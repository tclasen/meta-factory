"""Private, bounded native npm consistency collection on an owned install peer."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import time
import uuid

from .evidence import atomic_json, kill_group, positive, utc_now


BINDING_FIELDS = {'capture_sha256', 'manifest_sha256', 'lock_sha256',
                  'configuration_sha256', 'tool_context_sha256'}
SYNC_ERROR = (b'npm error `npm ci` can only install packages when your package.json and '
              b'package-lock.json or npm-shrinkwrap.json are in sync.')
KNOWN_CODES = {'EUSAGE', 'ENOTCACHED', 'ENOTFOUND', 'EAI_AGAIN', 'ETIMEDOUT',
               'ECONNREFUSED', 'ECONNRESET', 'EACCES', 'ENOENT', 'EINTEGRITY',
               'ERESOLVE', 'ETARGET', 'E404', 'E401', 'E403'}


def binding_record(value):
    if (not isinstance(value, dict) or set(value) != BINDING_FIELDS
            or any(not isinstance(v, str) or not re.fullmatch(r'[0-9a-f]{64}', v)
                   for v in value.values())):
        raise ValueError('Complete independently bound npm inputs required')
    return copy.deepcopy(value)


class NpmTransport:
    """Run npm 10.9.2 on an isolated, disposable, operator-owned install peer.

    Prefix executes trusted npm with a fixed cwd/configuration and exact peer ID;
    never execute this installer in the host checkout or an application peer.
    check(binding,reserve) returns exact True after independently verifying the
    complete captured manifest/lock, configuration, tool/image identity and
    active owner guard. It must reject NODE_OPTIONS, injected executable/config,
    dry-run/global/workspace modes and unsupported tree settings. The current
    profile requires ordinary nonworkspace registry locks and baseline npm
    configuration. Lifecycle scripts, audit and funding requests are disabled.

    cleanup() must bound and verify absence of all install processes on that
    exact owned peer, even if the client connection dies. Caller watchdog bounds
    both callbacks and remote resource lifetime. Successful ci is consistency
    under this profile, not source/build/runtime package consumption or an
    attestation of independently installed application packages.
    """
    def __init__(self, attempt, peer_prefix, binding, *, check, cleanup, cwd,
                 cache_only=True, max_output_bytes=1024*1024):
        if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 32
                or any(not isinstance(v, str) or not v or '\x00' in v or len(v) > 2048
                       for v in peer_prefix)):
            raise ValueError('Invalid trusted npm peer prefix')
        if not callable(check) or not callable(cleanup) or type(cache_only) is not bool:
            raise ValueError('Independent npm identity/lifetime/cleanup checks required')
        if type(max_output_bytes) is not int or not 1024 <= max_output_bytes <= 4*1024*1024:
            raise ValueError('Invalid npm output bound')
        self.attempt, self.prefix, self.binding = attempt, tuple(peer_prefix), binding_record(binding)
        self.check, self.cleanup, self.cwd = check, cleanup, Path(cwd)
        self.cache_only, self.max_output_bytes = cache_only, max_output_bytes

    def __call__(self, *, timeout=60):
        positive(timeout, 'npm collection timeout')
        if timeout > 120:
            raise ValueError('npm collection timeout exceeds bound')
        started, wall_started = time.monotonic(), time.time()
        selected = copy.deepcopy(self.binding)
        result = dict(started=utc_now(), outcome='npm_consistency_incomplete',
                      native_consistency=None, bindings_verified=False,
                      remote_install_absent_verified=False, client_groups_absent=True,
                      installed_environment_bound=False, artifact_integrity_verified=False,
                      build_consumption_verified=False, cache_only=self.cache_only,
                      binding_sha256=hashlib.sha256(json.dumps(selected, sort_keys=True).encode()).hexdigest(),
                      commands=[], limits='Native npm 10.9.2 ci under a bound baseline profile only; '
                      'not application image installation, artifact provenance or source/build/runtime use.')
        directory = self.attempt.directory / ('npm-' + uuid.uuid4().hex)
        directory.mkdir(mode=0o700)

        def elapsed():
            return max(time.monotonic()-started, time.time()-wall_started)

        def verify(reserve):
            if elapsed()+reserve > timeout+10 or self.check(copy.deepcopy(selected), reserve) is not True:
                raise RuntimeError('npm input/tool/lifetime binding unavailable')

        def command(arguments, bound):
            record = dict(exit_code=None, stdout_bytes=0, stderr_bytes=0, outcome='incomplete')
            result['commands'].append(record)
            output, diagnostics = bytearray(), bytearray()
            process = None
            command_started = time.monotonic()
            try:
                process = subprocess.Popen([*self.prefix, 'npm', *arguments], cwd=self.cwd,
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    start_new_session=True)
                with selectors.DefaultSelector() as selector:
                    for stream, kind in ((process.stdout, 'stdout'), (process.stderr, 'stderr')):
                        os.set_blocking(stream.fileno(), False)
                        selector.register(stream, selectors.EVENT_READ, kind)
                    while selector.get_map() or process.poll() is None:
                        remaining = min(bound-(time.monotonic()-command_started), timeout-elapsed())
                        if remaining <= 0:
                            record['outcome'] = 'timeout'
                            raise RuntimeError('npm command deadline')
                        for key, _ in selector.select(min(remaining, .1)):
                            data = os.read(key.fd, 65536)
                            if not data:
                                selector.unregister(key.fileobj)
                                continue
                            record[key.data+'_bytes'] += len(data)
                            if record['stdout_bytes']+record['stderr_bytes'] > self.max_output_bytes:
                                record['outcome'] = 'output_limit'
                                raise RuntimeError('npm response bound')
                            (output if key.data == 'stdout' else diagnostics).extend(data)
                    record['outcome'] = 'completed'
                    return process.returncode, bytes(output), bytes(diagnostics)
            finally:
                if process is not None:
                    try:
                        kill_group(process)
                    except BaseException:
                        result['client_groups_absent'] = False
                        raise
                    finally:
                        record['exit_code'] = process.returncode
                        for stream in (process.stdout, process.stderr):
                            stream.close()
                    try:
                        os.killpg(process.pid, 0)
                    except ProcessLookupError:
                        pass
                    else:
                        result['client_groups_absent'] = False
                record['elapsed_seconds'] = time.monotonic()-command_started

        try:
            verify(timeout+5)
            code, output, diagnostics = command(['--version'], 5)
            if code != 0 or output.strip() != b'10.9.2' or diagnostics:
                raise RuntimeError('Supported native npm version unavailable')
            result['npm_version'] = '10.9.2'
            arguments = ['ci', '--ignore-scripts', '--no-audit', '--no-fund']
            if self.cache_only:
                arguments.append('--offline')
            code, _, diagnostics = command(arguments, max(.001, timeout-elapsed()-5))
            codes = {v.decode('ascii') for v in re.findall(rb'^npm error code ([A-Z][A-Z0-9_]{0,31})\r?$', diagnostics, re.M)}
            result['native_error_codes'] = sorted(codes & KNOWN_CODES)
            if code == 0:
                observation = True
            elif code == 1 and codes == {'EUSAGE'} and any(
                    line.startswith(SYNC_ERROR) for line in diagnostics.splitlines()):
                observation = False
            else:
                observation = None
            code, output, diagnostics = command(['--version'], 5)
            if code != 0 or output.strip() != b'10.9.2' or diagnostics:
                raise RuntimeError('Native npm version changed')
            verify(5)
            result['bindings_verified'] = True
            result['native_consistency'] = observation
            result['outcome'] = 'npm_consistency_observed' if observation is not None else 'npm_native_unavailable'
        except BaseException as error:
            result['error_type'] = type(error).__name__
            if not isinstance(error, Exception):
                result['outcome'] = 'interrupted'
                raise
        finally:
            pending_interrupt = None
            try:
                result['remote_install_absent_verified'] = self.cleanup() is True
            except BaseException as error:
                result['cleanup_error_type'] = type(error).__name__
                if not isinstance(error, Exception):
                    result['outcome'] = 'interrupted'
                    pending_interrupt = error
            if not result['remote_install_absent_verified'] or not result['client_groups_absent']:
                result['native_consistency'] = None
                result['bindings_verified'] = False
                if result['outcome'] != 'interrupted':
                    result['outcome'] = 'npm_consistency_incomplete'
            elif result['bindings_verified']:
                try:
                    # Confirm quiescence before the final immutable-input check.
                    # A remote child must not rewrite inputs during cleanup and
                    # leave an earlier snapshot masquerading as the final state.
                    verify(0)
                except BaseException as error:
                    result.update(native_consistency=None, bindings_verified=False,
                                  outcome='npm_consistency_incomplete' if isinstance(error, Exception) else 'interrupted',
                                  final_check_error_type=type(error).__name__)
                    if not isinstance(error, Exception):
                        pending_interrupt = error
            result.update(ended=utc_now(), elapsed_seconds=elapsed())
            atomic_json(directory/'result.json', result)
            if pending_interrupt is not None:
                raise pending_interrupt
        return result
