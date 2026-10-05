"""Parent-owned Docker browser execution through guarded fixed-endpoint relays."""

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import shutil
import threading
import time
from urllib.parse import urlsplit

from .browser_guard import BrowserGuard, LABEL
from .evidence import Attempt, atomic_json, collect, positive
from .grading import contained_file, sha256


VOLUME_OPTIONS = {'type': 'tmpfs', 'device': 'tmpfs', 'o': 'size=1048576,uid=1000,gid=1000,mode=0700'}


def verify_volume(value, name, nonce):
    if (value.get('name') != name or value.get('owner') != nonce or value.get('driver') != 'local'
            or value.get('options') != VOLUME_OPTIONS or not isinstance(value.get('created'), str)
            or not value['created']):
        raise ValueError('Browser socket volume ownership or configuration differs')
    return value['created']


def shared_json(path, value):
    """Publish a readable lease atomically inside an otherwise private attempt."""
    staged = path.with_name('.' + path.name + '.next')
    atomic_json(staged, value)
    staged.chmod(0o444)
    os.replace(staged, path)


def verify_container(value, *, identifier, nonce, image, network, mounts, volume, browser, seccomp):
    """Verify only projected nonsecret Docker configuration before starting code."""
    if (value.get('id') != identifier or value.get('owner') != nonce or value.get('image') != image
            or value.get('user') != '1000:1000' or value.get('network') != network
            or value.get('readonly') is not True or value.get('privileged') is not False
            or value.get('cap_drop') != ['ALL'] or value.get('cap_add') not in (None, [])
            or value.get('pid_mode') != '' or value.get('init') is not True
            or value.get('ipc_mode') != 'private' or value.get('log_driver') != 'none'
            or value.get('memory') != 1024**3 or value.get('cpus') != 2000000000
            or value.get('pids') != 256 or value.get('shm') != 256*1024**2
            or not any(option in ('no-new-privileges', 'no-new-privileges=true') for option in value.get('security', []))):
        raise ValueError('Browser container isolation differs from request')
    policies = [item[8:] for item in value['security'] if item.startswith('seccomp=')]
    if len(policies) != 1 or json.loads(policies[0]) != seccomp:
        raise ValueError('Browser seccomp policy differs from request')
    observed = value.get('mounts', [])
    if len(observed) != len(mounts) + 1:
        raise ValueError('Unexpected browser container mount')
    expected = {destination: (str(source), destination == '/output') for source, destination in mounts}
    seen = set()
    for mount in observed:
        destination = mount['Destination']
        if destination in seen: raise ValueError('Duplicate browser mount')
        seen.add(destination)
        if destination == '/channel':
            if mount.get('Type') != 'volume' or mount.get('Name') != volume or mount.get('RW') is not (not browser):
                raise ValueError('Invalid browser socket mount')
        elif (destination not in expected or mount.get('Type') != 'bind'
              or (mount.get('Source'), mount.get('RW')) != expected[destination]):
            raise ValueError('Invalid browser protected mount')


class BrowserExecutor:
    """Trusted operator configuration; never derive these values from app output.

    peer_check must perform bounded identity/outer-sandbox-guard checks or raise.
    The relay gets a two-second lease refreshed only after those checks succeed.
    Network/image IDs are immutable Docker identities. No image builds/pulls occur.
    """
    def __init__(self, *, image, seccomp, seccomp_sha256, network, peer_host, peer_port, peer_check,
                 docker='docker'):
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image) or not re.fullmatch(r'[0-9a-f]{64}', network):
            raise ValueError('Browser requires immutable image and relay network identities')
        if not isinstance(peer_host, str):
            raise ValueError('Browser requires a numeric peer address')
        ipaddress.ip_address(peer_host)
        if type(peer_port) is not int or not 1 <= peer_port <= 65535 or not callable(peer_check):
            raise ValueError('Browser requires a guarded fixed peer')
        self.seccomp = Path(seccomp).resolve(strict=True)
        if not re.fullmatch(r'[0-9a-f]{64}', seccomp_sha256) or sha256(self.seccomp) != seccomp_sha256:
            raise ValueError('Browser seccomp policy identity changed')
        self.image, self.network = image, network
        self.peer = {'kind': 'tcp', 'host': peer_host, 'port': peer_port}
        self.peer_check, self.docker = peer_check, docker
        self.seccomp_digest = seccomp_sha256

    def __call__(self, parent, suite, case, target, *, timeout_seconds):
        positive(timeout_seconds, 'browser case timeout')
        result = {'case_id': case['id'], 'verdict': 'inconclusive',
                  'guard_verified': False, 'cleanup_verified': False}
        # Three resources can each require four bounded ten-second cleanup calls.
        # Reserve that time plus the guard join overhead inside the caller budget.
        if timeout_seconds <= 135:
            return dict(result, cleanup_verified=True, reason='browser_budget_unavailable')
        started = time.monotonic()
        deadline = started + timeout_seconds - 130
        wall_deadline = time.time() + timeout_seconds - 130
        origin = urlsplit(target['base_url'])
        if (origin.scheme != 'http' or origin.hostname != '127.0.0.1' or not origin.port
                or origin.netloc != f'127.0.0.1:{origin.port}' or origin.path or origin.query or origin.fragment):
            raise ValueError('Browser target must use the operator loopback origin')
        suite.verify()
        guard = None
        lease_thread = None
        lease_stop, lease_failed = threading.Event(), threading.Event()
        attempted = set()
        temporary_inputs = []
        directory = parent.directory / ('browser-' + case['id'])
        with Attempt(directory, {'kind': 'browser_executor', 'case_id': case['id'], 'suite_sha256': suite.digest,
                                  'image': self.image, 'network': self.network}) as attempt:
            def command(label, args, *, required=True):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('Browser execution budget exhausted')
                checked = collect(attempt, label, [self.docker, *args], cwd=directory, timeout=min(10, remaining))
                if required and checked['outcome'] != 'passed':
                    raise RuntimeError('Browser Docker operation incomplete')
                return checked
            def output(label):
                return (directory / label / 'stdout.log').read_text().strip()
            def read_result(path):
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 65536:
                    raise ValueError('Browser worker result unavailable')
                return json.loads(path.read_text())
            try:
                if sha256(self.seccomp) != self.seccomp_digest:
                    raise ValueError('Browser seccomp policy changed')
                self.peer_check()
                command('image', ['image', 'inspect', self.image, '--format', '{{.Id}}'])
                command('network', ['network', 'inspect', self.network, '--format',
                    '{"id":{{json .Id}},"driver":{{json .Driver}},"scope":{{json .Scope}}}'])
                if (output('image') != self.image or json.loads(output('network')) != {
                        'id': self.network, 'driver': 'bridge', 'scope': 'local'}):
                    raise ValueError('Browser Docker identities changed')
                protected, operator = directory / 'protected', directory / 'operator'
                protected.mkdir(); operator.mkdir()
                for relative in ['suite.json', *suite.manifest['files']]:
                    destination = protected / relative
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copyfile(contained_file(suite.root, relative), destination)
                for source in Path(__file__).parent.glob('*.py'):
                    package = operator / 'evaluation'; package.mkdir(exist_ok=True)
                    shutil.copyfile(source, package / source.name)
                for root in (protected, operator):
                    for path in root.rglob('*'): path.chmod(0o555 if path.is_dir() else 0o444)
                    root.chmod(0o555)
                policy = directory / 'seccomp.json'
                shutil.copyfile(self.seccomp, policy)
                if sha256(policy) != self.seccomp_digest:
                    raise ValueError('Browser seccomp copy changed')
                atomic_json(directory / 'identities.json', {str(p.relative_to(directory)): sha256(p)
                    for root in (protected, operator) for p in root.rglob('*') if p.is_file()})
                lease = directory / 'lease'; lease.mkdir(mode=0o755)
                browser_out, relay_out = directory / 'browser-output', directory / 'relay-output'
                for out in (browser_out, relay_out): out.mkdir(); out.chmod(0o777)
                target_path, relay_config = directory / 'target.json', directory / 'relay.json'
                temporary_inputs.append(target_path)
                atomic_json(target_path, target); target_path.chmod(0o444)
                guard = BrowserGuard(directory / 'guard', max_seconds=max(.01, deadline-time.monotonic()), docker=self.docker)
                nonce = guard.config['nonce']
                atomic_json(relay_config, {'nonce': nonce, 'authority': origin.netloc, 'upstream': self.peer,
                                          'wall_deadline': wall_deadline})
                relay_config.chmod(0o444)
                def refresh():
                    guard.check()
                    self.peer_check()
                    guard.check()
                    if time.monotonic() >= deadline:
                        raise TimeoutError('Browser peer lease expired')
                    shared_json(lease / 'lease.json', {'nonce': nonce, 'expires_at': min(wall_deadline, time.time()+2)})
                refresh()
                def maintain():
                    try:
                        while not lease_stop.wait(.25): refresh()
                    except Exception:
                        lease_failed.set()
                lease_thread = threading.Thread(target=maintain, daemon=True); lease_thread.start()
                volume = guard.config['resources']['channel'][1]
                attempted.add('channel')
                command('volume-create', ['volume', 'create', '--label', LABEL+'='+nonce, '--driver', 'local',
                    '--opt', 'type=tmpfs', '--opt', 'device=tmpfs', '--opt', 'o=size=1048576,uid=1000,gid=1000,mode=0700', volume])
                command('volume-identity', ['volume', 'inspect', volume, '--format',
                    '{"name":{{json .Name}},"owner":{{json (index .Labels "'+LABEL+'")}},'
                    '"driver":{{json .Driver}},"options":{{json .Options}},"created":{{json .CreatedAt}}}'])
                identity = verify_volume(json.loads(output('volume-identity')), volume, nonce)
                guard.settled('channel', created=True, identity=identity)
                def create(role):
                    out = browser_out if role == 'browser' else relay_out
                    name = guard.config['resources'][role][1]
                    args = ['container', 'create', '--name', name, '--label', LABEL+'='+nonce,
                        '--init', '--user', '1000:1000', '--network', 'none' if role=='browser' else self.network,
                        '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                        '--security-opt', 'seccomp='+str(policy), '--cpus', '2', '--memory', '1g',
                        '--shm-size', '256m', '--pids-limit', '256', '--log-driver', 'none',
                        '--tmpfs', '/tmp:rw,size=268435456', '--tmpfs', '/home/pwuser:rw,size=67108864,uid=1000,gid=1000',
                        '--env', 'PYTHONDONTWRITEBYTECODE=1', '--env', 'PYTHONPATH=/operator']
                    mounts = [(operator, '/operator'), (out, '/output')]
                    mounts += [(protected, '/protected'), (target_path, '/input/target.json')] if role=='browser' else [(lease, '/lease'), (relay_config, '/input/relay.json')]
                    for source, destination in mounts:
                        args += ['--mount', 'type=bind,src='+str(source)+',dst='+destination+('' if destination=='/output' else ',readonly')]
                    args += ['--mount', 'type=volume,src='+volume+',dst=/channel'+(',readonly' if role=='browser' else '')]
                    args += ['--entrypoint', 'timeout', self.image, '--signal=TERM', '--kill-after=2s',
                             str(max(1, math.ceil(deadline-time.monotonic())))+'s', 'python3', '-m']
                    if role=='browser':
                        args += ['evaluation.browser_worker', '--suite', '/protected', '--manifest-sha256', suite.digest,
                            '--case', case['id'], '--target', '/input/target.json', '--socket', '/channel/app.sock',
                            '--wall-deadline', str(wall_deadline), '--result', '/output/result.json']
                    else:
                        args += ['evaluation.browser_relay', '--config', '/input/relay.json', '--lease', '/lease', '--output', '/output']
                    attempted.add(role)
                    command(role+'-create', args)
                    identifier = output(role+'-create')
                    if not re.fullmatch(r'[0-9a-f]{64}', identifier):
                        raise ValueError('Browser container identity unavailable')
                    projection = '{' + ','.join('"'+key+'":{{json '+field+'}}' for key, field in {
                        'id': '.Id', 'owner': '(index .Config.Labels "'+LABEL+'")', 'image': '.Image',
                        'user': '.Config.User', 'network': '.HostConfig.NetworkMode', 'readonly': '.HostConfig.ReadonlyRootfs',
                        'privileged': '.HostConfig.Privileged', 'cap_drop': '.HostConfig.CapDrop', 'cap_add': '.HostConfig.CapAdd',
                        'pid_mode': '.HostConfig.PidMode', 'init': '.HostConfig.Init', 'security': '.HostConfig.SecurityOpt',
                        'ipc_mode': '.HostConfig.IpcMode', 'log_driver': '.HostConfig.LogConfig.Type',
                        'memory': '.HostConfig.Memory', 'cpus': '.HostConfig.NanoCpus', 'pids': '.HostConfig.PidsLimit',
                        'shm': '.HostConfig.ShmSize',
                        'mounts': '.Mounts'}.items()) + '}'
                    command(role+'-isolation', ['container', 'inspect', identifier, '--format', projection])
                    verify_container(json.loads(output(role+'-isolation')), identifier=identifier, nonce=nonce,
                        image=self.image, network='none' if role=='browser' else self.network,
                        mounts=mounts, volume=volume, browser=role=='browser', seccomp=json.loads(policy.read_text()))
                    # Record the inspected immutable ID before starting code.
                    guard.settled(role, created=True, identity=identifier)
                    command(role+'-start', ['container', 'start', identifier])
                    return identifier
                relay_id = create('relay')
                while not (relay_out / 'ready.json').exists():
                    guard.check()
                    if lease_failed.is_set() or time.monotonic() >= deadline:
                        raise RuntimeError('Browser relay readiness unavailable')
                    time.sleep(.05)
                if read_result(relay_out / 'ready.json').get('nonce') != nonce:
                    raise ValueError('Browser relay readiness identity changed')
                def wait_exit(role, identifier):
                    index = 0
                    while True:
                        guard.check()
                        if lease_failed.is_set(): raise RuntimeError('Browser peer lease failed')
                        label = role + '-state-' + str(index); index += 1
                        command(label, ['container', 'inspect', identifier, '--format', '{{json .State}}'])
                        state = json.loads(output(label))
                        if state.get('Status') == 'exited':
                            if state.get('ExitCode') != 0: raise RuntimeError('Browser process exit incomplete')
                            break
                        time.sleep(.1)
                browser_id = create('browser')
                wait_exit('browser', browser_id)
                worker = read_result(browser_out / 'result.json')
                shared_json(lease / 'stop.json', {'nonce': nonce})
                while not (relay_out / 'result.json').exists():
                    guard.check()
                    if lease_failed.is_set() or time.monotonic() >= deadline:
                        raise RuntimeError('Browser relay completion unavailable')
                    time.sleep(.05)
                upstream = read_result(relay_out / 'result.json')
                wait_exit('relay', relay_id)
                lease_stop.set(); lease_thread.join(2)
                if lease_thread.is_alive():
                    raise RuntimeError('Browser peer verifier did not settle')
                guard.check(); self.peer_check(); guard.check()
                if lease_failed.is_set() or not upstream.get('closed'):
                    raise RuntimeError('Browser transport lifetime uncertain')
                if worker.get('case_id') != case['id']:
                    raise ValueError('Browser worker identity changed')
                result.update(verdict=worker.get('verdict'), abort_suite=worker.get('abort_suite', False),
                    guard_verified=True, transport={'browser': worker.get('transport'), 'upstream': upstream.get('transport')})
                suite.verify()
            except Exception:
                result.update(verdict='inconclusive', reason='browser_execution_incomplete')
            finally:
                lease_stop.set()
                if lease_thread is not None:
                    lease_thread.join(2)
                    if lease_thread.is_alive(): result.update(guard_verified=False, abort_suite=True)
                if guard is not None:
                    try:
                        for role in guard.config['resources']:
                            if role not in attempted: guard.settled(role, created=False)
                        cleanup = guard.release(timeout=130)
                        result['cleanup_verified'] = cleanup['cleanup_verified']
                        if cleanup.get('reason') != 'owner_release': result['guard_verified'] = False
                    except Exception:
                        result.update(cleanup_verified=False, abort_suite=True)
                for path in temporary_inputs:
                    try: path.unlink(missing_ok=True)
                    except OSError: result.update(cleanup_verified=False, abort_suite=True)
                result['elapsed_seconds'] = time.monotonic() - started
                atomic_json(directory / 'result.json', result)
        return result
