"""Private selected startup-environment comparison; never emit environment values.

/proc/PID/environ represents the exec startup environment, not necessarily
current settings: https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html
The caller independently establishes application setting names/source semantics.
"""
import hashlib
import json
from pathlib import Path
import re
import sys


FIELDS = {'endpoint', 'bucket', 'region', 'access_key', 'secret_key', 'session_token'}


def mapping(value):
    if (not isinstance(value, dict) or set(value) != FIELDS
            or any(not isinstance(v, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', v)
                   for k, v in value.items() if k != 'session_token')
            or value['session_token'] is not None and (not isinstance(value['session_token'], str)
                or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,127}', value['session_token']))):
        raise ValueError('Explicit bounded storage environment mapping required')
    names = [v for v in value.values() if v is not None]
    if len(set(names)) != len(names):raise ValueError('Distinct setting names required')
    return value


def selected_environment(path, names):
    with path.open('rb') as stream:raw = stream.read(65537)
    if len(raw) > 65536:raise ValueError('Environment read limit')
    entries = raw.split(b'\0')
    if entries[-1] == b'':entries.pop()
    if len(entries) > 2048:raise ValueError('Environment entry limit')
    wanted = {name.encode('ascii') for name in names if name is not None}
    values = {}
    for entry in entries:
        key, separator, value = entry.partition(b'=')
        if not separator or not key:raise ValueError('Environment layout unavailable')
        if key not in wanted:continue
        if key in values or len(value) > 4096:raise ValueError('Selected environment unavailable')
        values[key] = value
    return values


def observe(config, selected, pid, start_ticks, executable_sha256, address, port,
            identity, *, proc=Path('/proc')):
    selected = mapping(selected)
    # identity must be the trusted bounded Linux executable/listener observer.
    first = identity(pid, start_ticks, executable_sha256, address, port, proc=proc)
    def read():return selected_environment(proc / str(pid) / 'environ', selected.values())
    before = read()
    for field, name in selected.items():
        if name is None:
            if config[field] is not None:raise ValueError('Unmapped selected credential setting')
            continue
        expected = config[field]
        actual = before.get(name.encode('ascii'))
        if expected is None:
            if actual is not None:raise ValueError('Unexpected selected session setting')
        elif actual != expected.encode('ascii'):
            raise ValueError('Selected startup setting mismatch')
    last = identity(pid, start_ticks, executable_sha256, address, port, proc=proc)
    after = read()
    if first != last or before != after:raise ValueError('Selected process or startup settings changed')
    public = {key:config[key] for key in ('endpoint', 'bucket', 'region')}
    return dict(outcome='storage_startup_configuration_observed', snapshot_stable=True,
                selected_credentials_matched=True, application_use_verified=False,
                current_configuration_verified=False, deployment_attribution_verified=False,
                pid=pid, process_start_ticks=start_ticks, executable_sha256=executable_sha256,
                configuration_sha256=hashlib.sha256(json.dumps(public, sort_keys=True).encode()).hexdigest(),
                process_identity_sha256=hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest())


def main(signing, identity):
    report = dict(outcome='storage_startup_configuration_incomplete', snapshot_stable=False,
                  selected_credentials_matched=False, application_use_verified=False,
                  current_configuration_verified=False, deployment_attribution_verified=False)
    try:
        config = signing['private_binding'](sys.argv[1])
        selected = json.loads(sys.argv[2])
        value = observe(config, selected, int(sys.argv[3]), sys.argv[4], sys.argv[5], sys.argv[6],
                        int(sys.argv[7]), identity['observe'])
        if config != signing['private_binding'](sys.argv[1]):raise ValueError('Private configuration changed')
        report.update(value)
    except BaseException as error:report['error_type'] = type(error).__name__
    print(json.dumps(report, allow_nan=False))
