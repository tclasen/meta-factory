"""Independent cleanup of explicitly owned browser containers and socket volume."""

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


LABEL = 'factory.browser'


def validate(config):
    if (config.get('schema_version') != 1 or not re.fullmatch(r'[0-9a-f]{32}', config.get('nonce', ''))
            or type(config.get('owner_pid')) is not int or config['owner_pid'] <= 1):
        raise ValueError('Invalid browser guard identity')
    prefix = 'factory-browser-' + config['nonce'][:16]
    expected = {'browser': ['container', prefix + '-browser'],
                'relay': ['container', prefix + '-relay'], 'channel': ['volume', prefix + '-channel']}
    if config.get('resources') != expected:
        raise ValueError('Invalid browser guard resources')
    positive(config.get('max_seconds'), 'browser guard lifetime')
    positive(config.get('expires_at'), 'browser guard deadline')
    if config['max_seconds'] > 5400:
        raise ValueError('Browser guard exceeds grading envelope')


def cleanup(attempt, config, directory, *, docker='docker', command_timeout=10):
    """Inspect labels before removal; unknown daemon/creation state is incomplete.

    A missing receipt cannot prove a create operation has settled. Cleanup still
    removes matching owned resources, but retains that uncertainty in the result.
    """
    validate(config)
    results = {}
    for role in ('browser', 'relay', 'channel'):
        kind, name = config['resources'][role]
        result = {'name': name, 'cleanup_verified': False}
        try:
            receipt_path = directory / (role + '-creation.json')
            receipt = json.loads(receipt_path.read_text()) if receipt_path.is_file() else {}
            settled = (receipt.get('nonce') == config['nonce'] and receipt.get('name') == name
                       and receipt.get('settled') is True and type(receipt.get('created')) is bool)
            result['creation_settled'] = settled
            def command(suffix, argv):
                label = role + '-' + suffix
                checked = collect(attempt, label, [docker, *argv], cwd=directory, timeout=command_timeout)
                return checked, (attempt.directory / label / 'stdout.log').read_text().strip()
            def absent(suffix):
                args = (['container', 'ls', '--all', '--no-trunc', '--filter', 'name=^/' + name + '$', '--format', '{{.ID}}']
                        if kind == 'container' else ['volume', 'ls', '--filter', 'name=^' + name + '$', '--format', '{{.Name}}'])
                checked, output = command(suffix, args)
                if checked['outcome'] != 'passed':
                    raise RuntimeError('Browser cleanup listing unavailable')
                return not output
            if absent('before'):
                result.update(cleanup_verified=settled, reason='absent' if settled else 'creation_unsettled')
            else:
                label_path = '.Config.Labels' if kind == 'container' else '.Labels'
                identity = '.Id' if kind == 'container' else '.CreatedAt'
                projection = ('{"identity":{{json ' + identity + '}},"owner":{{json (index ' +
                              label_path + ' "' + LABEL + '")}}}')
                checked, output = command('identity', [kind, 'inspect', name, '--format', projection])
                if checked['outcome'] != 'passed':
                    raise RuntimeError('Browser cleanup identity unavailable')
                actual = json.loads(output)
                owned = actual.get('owner') == config['nonce'] and isinstance(actual.get('identity'), str) and bool(actual['identity'])
                if kind == 'container':
                    owned = owned and bool(re.fullmatch(r'[0-9a-f]{64}', actual['identity']))
                if settled:
                    owned = owned and receipt['created'] and receipt.get('identity') == actual['identity']
                if not owned:
                    result['reason'] = 'ownership_unverified'
                else:
                    # Container IDs avoid deleting a replacement with the same name.
                    resource = actual['identity'] if kind == 'container' else name
                    removed, _ = command('remove', [kind, 'rm', *(['--force'] if kind == 'container' else []), resource])
                    gone = absent('after')
                    result.update(cleanup_verified=settled and removed['outcome'] == 'passed' and gone,
                                  reason='removed' if settled else 'creation_unsettled')
        except Exception as error:
            result['error_type'] = type(error).__name__
        results[role] = result
        attempt.emit('controller', 'browser.cleanup', {'role': role, **result})
    return {'cleanup_verified': all(item['cleanup_verified'] for item in results.values()), 'resources': results}


def monitor(path, *, docker='docker', poll_seconds=.1):
    path = Path(path).resolve(strict=True)
    config = json.loads(path.read_text())
    validate(config)
    directory = path.parent
    started, wall_started = time.monotonic(), time.time()
    with Attempt(directory / 'evidence', {'kind': 'browser_watchdog', 'resources': config['resources']}) as attempt:
        atomic_json(directory / 'ready.json', {'nonce': config['nonce'], 'pid': os.getpid(), 'ready_at': utc_now()})
        reason = 'watchdog_error'
        try:
            while True:
                if os.getppid() != config['owner_pid']:
                    reason = 'owner_exited'; break
                if time.monotonic() - started >= config['max_seconds'] or time.time() >= config['expires_at']:
                    reason = 'deadline'; break
                if abs(time.time() - wall_started - (time.monotonic() - started)) > 5:
                    reason = 'clock_discontinuity'; break
                release = directory / 'release.json'
                if release.exists():
                    if json.loads(release.read_text()).get('nonce') != config['nonce']:
                        raise ValueError('Invalid browser guard release')
                    reason = 'owner_release'; break
                time.sleep(poll_seconds)
        except BaseException:
            reason = 'watchdog_error'
        atomic_json(directory / 'triggered.json', {'nonce': config['nonce'], 'reason': reason})
        result = dict(cleanup(attempt, config, directory, docker=docker), reason=reason)
        atomic_json(directory / 'result.json', result)
    return 0 if result['cleanup_verified'] else 1


class BrowserGuard:
    def __init__(self, directory, *, max_seconds, docker='docker'):
        nonce = uuid.uuid4().hex
        prefix = 'factory-browser-' + nonce[:16]
        self.config = {'schema_version': 1, 'nonce': nonce, 'owner_pid': os.getpid(),
                       'max_seconds': max_seconds, 'expires_at': time.time() + max_seconds,
                       'resources': {role: [kind, prefix + '-' + role] for role, kind in
                                     [('browser', 'container'), ('relay', 'container'), ('channel', 'volume')]}}
        validate(self.config)
        self.monotonic_deadline = time.monotonic() + max_seconds
        self.directory = Path(directory).resolve()
        self.directory.mkdir(mode=0o700)
        atomic_json(self.directory / 'config.json', self.config)
        with (self.directory / 'transport.log').open('xb') as log:
            os.chmod(self.directory / 'transport.log', 0o600)
            self.process = subprocess.Popen([sys.executable, '-m', 'evaluation.browser_guard',
                '--config', str(self.directory / 'config.json'), '--docker', docker],
                cwd=Path(__file__).resolve().parents[1], stdin=subprocess.DEVNULL,
                stdout=log, stderr=log, start_new_session=True)
        deadline = time.monotonic() + 10
        ready = self.directory / 'ready.json'
        while not ready.exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('Browser guard did not arm')
            time.sleep(.02)
        if json.loads(ready.read_text()).get('nonce') != nonce:
            raise RuntimeError('Browser guard identity changed')

    def check(self):
        if (self.process.poll() is not None or time.time() >= self.config['expires_at']
                or time.monotonic() >= self.monotonic_deadline or (self.directory / 'release.json').exists()):
            raise RuntimeError('Browser guard is not active')
        if (self.directory / 'triggered.json').exists():
            raise RuntimeError('Browser guard cleanup has started')

    def settled(self, role, *, created, identity=None):
        """Record only after the create command exited, never after a timeout."""
        if type(created) is not bool or role not in self.config['resources']:
            raise ValueError('Invalid browser creation receipt')
        if created and (not isinstance(identity, str) or not identity):
            raise ValueError('Created browser resource requires inspected identity')
        path = self.directory / (role + '-creation.json')
        if path.exists():
            raise ValueError('Browser creation already settled')
        atomic_json(path, {'nonce': self.config['nonce'], 'name': self.config['resources'][role][1],
                          'settled': True, 'created': created, 'identity': identity})

    def release(self, *, timeout=130):
        positive(timeout, 'browser guard join timeout')
        atomic_json(self.directory / 'release.json', {'nonce': self.config['nonce']})
        self.process.wait(timeout=timeout)
        return json.loads((self.directory / 'result.json').read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--docker', default='docker')
    args = parser.parse_args()
    return monitor(args.config, docker=args.docker)


if __name__ == '__main__':
    def interrupt(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
