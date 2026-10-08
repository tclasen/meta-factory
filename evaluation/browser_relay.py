"""Trusted Unix-to-TCP relay, gated by the parent's short-lived peer lease."""

import argparse
import json
from pathlib import Path
import threading
import time

from .evidence import atomic_json
from .http_relay import RelayServer


def serve(config, lease_directory, output):
    lease_directory, output = Path(lease_directory), Path(output)
    server = thread = None
    result = {'closed': False, 'transport': {}}
    phase = 'initial_lease'
    def check():
        # Host-shared filesystems can briefly hide an atomically replaced file.
        # Wait for a current receipt; never forward using a cached lease.
        read_deadline = time.monotonic() + .1
        while True:
            try:
                lease = json.loads((lease_directory / 'lease.json').read_text())
                break
            except FileNotFoundError:
                if time.monotonic() >= read_deadline:
                    raise
                time.sleep(min(.01, max(0, read_deadline - time.monotonic())))
        now = time.time()
        if (lease.get('nonce') != config['nonce'] or not now < lease['expires_at'] <= now + 5
                or now >= config['wall_deadline']):
            raise RuntimeError('Browser peer lease unavailable')
    try:
        check()
        phase = 'transport_setup'
        server = RelayServer('/channel/app.sock', config['upstream'], config['authority'], check=check,
                             request_seconds=min(30, max(.01, config['wall_deadline'] - time.time())))
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}, daemon=True)
        thread.start()
        atomic_json(output / 'ready.json', {'nonce': config['nonce']})
        phase = 'lease_monitor'
        while True:
            check()
            phase = 'stop_identity'
            stop = lease_directory / 'stop.json'
            if stop.exists():
                if json.loads(stop.read_text()).get('nonce') != config['nonce']:
                    raise RuntimeError('Invalid relay stop identity')
                break
            phase = 'lease_monitor'
            time.sleep(.05)
    except Exception as error:
        result['reason'] = 'relay_incomplete'
        result['failure_phase'] = phase
        result['failure_kind'] = ('permission' if isinstance(error, PermissionError) else
                                  'missing_file' if isinstance(error, FileNotFoundError) else
                                  'invalid_json' if isinstance(error, json.JSONDecodeError) else
                                  'invalid_field' if isinstance(error, (KeyError, TypeError, ValueError)) else
                                  'exception')
    finally:
        if server is not None:
            try:
                if thread is not None and thread.is_alive():
                    server.shutdown()
                    thread.join(2)
                server.server_close()
                result['closed'] = not (thread and thread.is_alive()) and 'reason' not in result
            except Exception:
                result['reason'] = 'relay_cleanup_incomplete'
            result['transport'] = server.observation()
        atomic_json(output / 'result.json', result)
    return 0 if result['closed'] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--lease', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    return serve(json.loads(Path(args.config).read_text()), args.lease, args.output)


if __name__ == '__main__':
    raise SystemExit(main())
