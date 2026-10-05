"""Bounded trusted-psql transport; SQL and connection diagnostics are not logged."""
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
from .faults import FaultSetupError


class DatabaseTransport:
    """Use one operator-owned peer and two private libpq service aliases.

    check(reserve) must verify peer identity, immutable service configuration and
    active sandbox lifetime. Prefix must execute trusted psql with stdin preserved,
    using an exact peer identity rather than a reusable container name. Credentials
    belong in the peer's private service/password files, never argv or worker data.
    """
    def __init__(self, attempt, peer_prefix, services, *, check, cwd, max_output_bytes=65536):
        if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
                or any(not isinstance(a, str) or not a or '\x00' in a or len(a) > 1024 for a in peer_prefix)):
            raise ValueError('Invalid trusted database peer prefix')
        if (not isinstance(services, dict) or set(services) != {'runtime', 'operator'}
                or any(not isinstance(v, str) or not re.fullmatch(r'[a-zA-Z][a-zA-Z0-9_-]{0,63}', v) for v in services.values())):
            raise ValueError('Invalid database service aliases')
        if type(max_output_bytes) is not int or not 1 <= max_output_bytes <= 1024 * 1024:
            raise ValueError('Invalid database output bound')
        self.attempt, self.prefix, self.services = attempt, tuple(peer_prefix), dict(services)
        self.check, self.cwd, self.max_output_bytes = check, Path(cwd), max_output_bytes

    def __call__(self, identity, sql, *, timeout=15):
        if identity not in self.services:
            raise ValueError('Unreviewed database identity')
        positive(timeout, 'database command timeout')
        if timeout > 15:
            raise ValueError('Database command timeout exceeds bound')
        if not isinstance(sql, str) or '\x00' in sql:
            raise ValueError('Invalid database command')
        payload = sql.encode('utf-8')
        if not 1 <= len(payload) <= 256 * 1024:
            raise ValueError('Database input exceeds bound')
        record = {'identity': identity, 'started': utc_now(), 'outcome': 'incomplete',
                  'sql_sha256': hashlib.sha256(payload).hexdigest(), 'input_bytes': len(payload),
                  'stdout_bytes': 0, 'stderr_bytes': 0, 'exit_code': None,
                  'remote_termination_verified': False}
        label = 'database-' + uuid.uuid4().hex
        directory = self.attempt.directory / label
        directory.mkdir(mode=0o700)
        self.attempt.emit('controller', 'database.command.started', dict(record, label=label))
        process = None
        started = time.monotonic()
        output = bytearray()
        sent = 0
        value = None
        try:
            self.check(timeout + 5)
            argv = [*self.prefix, 'psql', '-X', '-q', '-A', '-t', '--no-password',
                    '--set=ON_ERROR_STOP=1', '--file=-', 'service=' + self.services[identity]]
            process = subprocess.Popen(argv, cwd=self.cwd, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
            with selectors.DefaultSelector() as selector:
                for stream, event, kind in ((process.stdin, selectors.EVENT_WRITE, 'stdin'),
                                            (process.stdout, selectors.EVENT_READ, 'stdout'),
                                            (process.stderr, selectors.EVENT_READ, 'stderr')):
                    os.set_blocking(stream.fileno(), False)
                    selector.register(stream, event, kind)
                while selector.get_map() or process.poll() is None:
                    remaining = timeout - (time.monotonic() - started)
                    if remaining <= 0:
                        record['outcome'] = 'timeout'
                        break
                    for key, _ in selector.select(min(remaining, .1)):
                        if key.data == 'stdin':
                            sent += os.write(key.fd, payload[sent:sent + 65536])
                            if sent == len(payload):
                                selector.unregister(key.fileobj)
                                process.stdin.close()
                            continue
                        data = os.read(key.fd, 65536)
                        if not data:
                            selector.unregister(key.fileobj)
                            continue
                        record[key.data + '_bytes'] += len(data)
                        if record['stdout_bytes'] + record['stderr_bytes'] > self.max_output_bytes:
                            record['outcome'] = 'output_limit'
                            break
                        if key.data == 'stdout':
                            output.extend(data)
                    if record['outcome'] == 'output_limit':
                        break
                else:
                    if process.returncode != 0 or sent != len(payload):
                        record['outcome'] = 'command_failed'
                    else:
                        def pairs(items):
                            result = {}
                            for key, item in items:
                                if key in result:
                                    raise ValueError('Duplicate observation key')
                                result[key] = item
                            return result
                        def invalid_constant(_):
                            raise ValueError('Nonfinite observation')
                        try:
                            value = json.loads(output.decode('utf-8'), object_pairs_hook=pairs,
                                               parse_constant=invalid_constant)
                            if not isinstance(value, dict):
                                raise ValueError('Observation must be an object')
                        except (ValueError, UnicodeError, RecursionError):
                            record['outcome'] = 'invalid_observation'
                        else:
                            self.check(5)
                            record['outcome'] = 'observed'
        except BaseException as error:
            record['outcome'] = 'interrupted' if not isinstance(error, Exception) else 'transport_incomplete'
            record['error_type'] = type(error).__name__
            if not isinstance(error, Exception):
                raise
        finally:
            if process is not None:
                kill_group(process)
                record['exit_code'] = process.returncode
                for stream in (process.stdin, process.stdout, process.stderr):
                    stream.close()
            record.update(ended=utc_now(), elapsed_seconds=time.monotonic() - started)
            atomic_json(directory / 'result.json', record)
            self.attempt.emit('controller', 'database.command.finished', dict(record, label=label))
        if record['outcome'] != 'observed':
            raise FaultSetupError('Database transport incomplete: ' + record['outcome'])
        return value
