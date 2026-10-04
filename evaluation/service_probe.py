"""Sandbox-side HTTP connectivity observations from an operator-selected peer."""

import argparse
import ipaddress
import json
import re
import subprocess
import time
from urllib.parse import urlsplit


HTTP_STATUS = re.compile(r'^\s*HTTP/\d(?:\.\d)?\s+[1-5]\d\d(?:\s|$)', re.MULTILINE)
NETWORK_FAILURE = re.compile(r'wget:.*(?:connection refused|timed out|no route to host|network is unreachable)', re.IGNORECASE)


def endpoint(value):
    parsed = urlsplit(value)
    address = ipaddress.ip_address(parsed.hostname or '')
    if (parsed.scheme != 'http' or not address.is_private or parsed.username or parsed.password
            or parsed.path not in ('', '/') or parsed.query or parsed.fragment
            or parsed.port is None or not 1 <= parsed.port <= 65535):
        raise ValueError('Probe endpoint must be an operator-selected private HTTP IP and port')
    return value


def classify(returncode, stderr):
    # An HTTP response, including 403 from a private S3 bucket, proves a connection.
    # Tool startup, exec and unrelated protocol failures cannot prove an outage.
    if HTTP_STATUS.search(stderr):
        return 'reachable'
    if returncode != 0 and NETWORK_FAILURE.search(stderr):
        return 'unreachable'
    return 'inconclusive'


def observe(check, target, control, mode):
    records = []
    def run(label, url):
        value = check(url)
        records.append(dict(value, check=label))
        return value['connectivity']
    if run('control-before', control) != 'reachable':
        return {'outcome': 'service_probe_incomplete', 'checks': records}
    expected = 'unreachable' if mode == 'unavailable' else 'reachable'
    for index in range(3 if mode == 'unavailable' else 1):
        if run('target-' + str(index), target) != expected:
            return {'outcome': 'service_probe_incomplete', 'checks': records}
    if run('control-after', control) != 'reachable':
        return {'outcome': 'service_probe_incomplete', 'checks': records}
    return {'outcome': 'service_' + mode + '_verified', 'checks': records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--peer-prefix', required=True)
    parser.add_argument('--target', required=True)
    parser.add_argument('--control', required=True)
    parser.add_argument('--mode', choices=('available', 'unavailable'), required=True)
    args = parser.parse_args()
    result = {'outcome': 'service_probe_incomplete'}
    deadline = time.monotonic() + 30
    try:
        prefix = json.loads(args.peer_prefix)
        if (not isinstance(prefix, list) or not 1 <= len(prefix) <= 24
                or not all(isinstance(a, str) and 0 < len(a) <= 1024 for a in prefix)):
            raise ValueError('Invalid trusted peer command prefix')
        target, control = endpoint(args.target), endpoint(args.control)
        if target == control:
            raise ValueError('Control must be independent of the fault target')
        def check(url):
            # Fixed trusted program; untrusted response bodies are discarded.
            script = ('unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy; '
                      'exec wget -T 3 -S -O /dev/null "$1"')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Service probe deadline')
            command = subprocess.run([*prefix, 'sh', '-c', script, 'service-probe', url],
                                     stdin=subprocess.DEVNULL, capture_output=True, timeout=min(5, remaining))
            if len(command.stdout) + len(command.stderr) > 65536:
                raise ValueError('Oversized service probe output')
            return {'exit_code': command.returncode,
                    'connectivity': classify(command.returncode, command.stderr.decode('utf-8', errors='replace'))}
        result = observe(check, target, control, args.mode)
    except Exception as error:
        result['error_type'] = type(error).__name__
    print(json.dumps(result, sort_keys=True))
    return 0 if result['outcome'] != 'service_probe_incomplete' else 1


if __name__ == '__main__':
    raise SystemExit(main())
