"""Independent, bounded stop watchdog; never resumes or executes in a sandbox."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid

from .evidence import Attempt, atomic_json, collect, positive, utc_now
from .sandbox import stopped_from_listing


NAME = re.compile(r"factory-eval-(builder|grader)-[0-9a-f]{16}")


def validate_config(config):
    if config.get('schema_version') != 1 or not NAME.fullmatch(config.get('sandbox', '')):
        raise ValueError('Invalid watchdog resource')
    if type(config.get('owner_pid')) is not int or config['owner_pid'] <= 1:
        raise ValueError('Invalid watchdog owner')
    if not re.fullmatch(r'[0-9a-f]{32}', config.get('nonce', '')):
        raise ValueError('Invalid watchdog identity')
    positive(config.get('max_seconds'), 'watchdog lifetime')
    if config['max_seconds'] > 26 * 3600:
        raise ValueError('Watchdog lifetime exceeds first-test envelope')
    positive(config.get('expires_at'), 'watchdog wall deadline')


def stop_and_verify(attempt, sandbox, sbx, *, command_timeout=30):
    """One stop + independent listing; unsuccessful cleanup is retained, not hidden."""
    stop = collect(attempt, 'stop', [sbx, 'stop', sandbox], cwd=attempt.directory, timeout=command_timeout)
    listing = collect(attempt, 'verify-stopped', [sbx, 'ls'], cwd=attempt.directory, timeout=command_timeout)
    output = (attempt.directory / 'verify-stopped/stdout.log').read_text()
    stopped = (stop['outcome'] == 'passed' and listing['outcome'] == 'passed'
               and stopped_from_listing(output, sandbox))
    return {'remote_termination_verified': stopped, 'stop': stop, 'listing': listing,
            'manual_stop': [sbx, 'stop', sandbox]}


def monitor(config_path, *, sbx='sbx', poll_seconds=0.25, command_timeout=30):
    config_path = Path(config_path).resolve(strict=True)
    config = json.loads(config_path.read_text())
    validate_config(config)
    positive(poll_seconds, 'poll interval')
    positive(command_timeout, 'command timeout')
    base = config_path.parent
    start = time.monotonic()
    wall_start = time.time()
    outcome = {'outcome': 'watchdog_error', 'remote_termination_verified': False}
    with Attempt(base / 'evidence', {'kind': 'stop_watchdog', 'sandbox': config['sandbox'],
                                    'owner_pid': config['owner_pid'], 'expires_at': config['expires_at']}) as attempt:
        attempt.transition('preflight')
        atomic_json(base / 'ready.json', {'nonce': config['nonce'], 'pid': os.getpid(), 'ready_at': utc_now()})
        try:
            while True:
                # Parent identity cannot be confused with a recycled PID after reparenting.
                if os.getppid() != config['owner_pid']:
                    reason = 'owner_exited'; break
                if time.monotonic() - start >= config['max_seconds'] or time.time() >= config['expires_at']:
                    reason = 'deadline'; break
                if abs((time.time() - wall_start) - (time.monotonic() - start)) > 5:
                    reason = 'clock_discontinuity'; break
                release = base / 'release.json'
                if release.exists():
                    value = json.loads(release.read_text())
                    if value.get('nonce') != config['nonce']:
                        raise ValueError('Invalid release identity')
                    # Release is only a request to stop verifying, never evidence of stop.
                    reason = 'owner_release'; break
                time.sleep(poll_seconds)
            attempt.emit('controller', 'watchdog.triggered', {'reason': reason})
            stopped = stop_and_verify(attempt, config['sandbox'], sbx, command_timeout=command_timeout)
            outcome = {'outcome': 'stopped' if stopped['remote_termination_verified'] else 'cleanup_incomplete',
                       'reason': reason, **stopped}
        except BaseException as error:
            outcome = {'outcome': 'watchdog_error', 'error_type': type(error).__name__,
                       'remote_termination_verified': False, 'manual_stop': [sbx, 'stop', config['sandbox']]}
            # A corrupt release request or termination signal must not disable stop.
            if not (attempt.directory / 'stop').exists():
                try:
                    outcome.update(stop_and_verify(attempt, config['sandbox'], sbx, command_timeout=command_timeout))
                except BaseException:
                    pass
        finally:
            # The guard is a cleanup attempt, not a builder/grading lifecycle.
            attempt.transition('failed')
            attempt.finish(outcome)
            atomic_json(base / 'result.json', outcome)
    return 0 if outcome['remote_termination_verified'] else 1


class Guard:
    def __init__(self, directory, sandbox, *, max_seconds, sbx='sbx'):
        positive(max_seconds, 'watchdog lifetime')
        config = {'schema_version': 1, 'sandbox': sandbox, 'owner_pid': os.getpid(),
                  'nonce': uuid.uuid4().hex, 'max_seconds': max_seconds,
                  'expires_at': time.time() + max_seconds}
        validate_config(config)
        self.directory = Path(directory)
        self.directory.mkdir(mode=0o700)
        self.nonce = config['nonce']
        atomic_json(self.directory / 'config.json', config)
        # Dedicated session survives controller process-group termination. No credentials.
        with (self.directory / 'transport.log').open('xb') as log:
            os.chmod(self.directory / 'transport.log', 0o600)
            self.process = subprocess.Popen([sys.executable, '-m', 'evaluation.watchdog',
                '--config', str((self.directory / 'config.json').resolve()), '--sbx', sbx],
                cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 10
        while not (self.directory / 'ready.json').exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                # Never begin protected work if the guard did not confirm readiness.
                raise RuntimeError('Stop watchdog failed to arm; inspect transport log')
            time.sleep(0.02)
        if json.loads((self.directory / 'ready.json').read_text())['nonce'] != self.nonce:
            raise RuntimeError('Stop watchdog identity mismatch')

    def release(self, *, timeout=70):
        positive(timeout, 'guard join timeout')
        atomic_json(self.directory / 'release.json', {'nonce': self.nonce})
        self.process.wait(timeout=timeout)
        result = json.loads((self.directory / 'result.json').read_text())
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--sbx', default='sbx')
    args = parser.parse_args()
    return monitor(args.config, sbx=args.sbx)


if __name__ == '__main__':
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
