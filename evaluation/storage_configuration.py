"""Guarded, sanitized startup configuration binding for an operator-selected app process."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .storage_configuration_probe import mapping
from .verdicts import Inconclusive


def probe_source():
    directory = Path(__file__).parent
    parts = []
    for namespace, name in [('signing', 'storage_canary_probe.py'), ('identity', 'listener_identity_probe.py'),
                            ('probe', 'storage_configuration_probe.py')]:
        parts.append(namespace+'={"__name__":"trusted_configuration_'+namespace+'"}\n'
                     'exec(compile('+repr((directory/name).read_text())+',"trusted-'+namespace+'","exec"),'+namespace+')\n')
    return ''.join(parts)+'probe["main"](signing,identity)\n'


def capture_storage_configuration(attempt, *, peer_prefix, private_binding_path, selected,
                                  pid, start_ticks, executable_sha256, address, port,
                                  lifetime_check, label='foundation-storage-configuration'):
    selected = mapping(json.loads(json.dumps(selected, allow_nan=False)))
    if (not isinstance(peer_prefix, (tuple, list)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v for v in peer_prefix)
            or not isinstance(private_binding_path, str) or not private_binding_path.startswith('/')
            or len(private_binding_path) > 4096 or '\x00' in private_binding_path
            or type(pid) is not int or not 1 <= pid <= 2147483647
            or not isinstance(start_ticks, str) or not re.fullmatch(r'[0-9]{1,24}', start_ticks)
            or not isinstance(executable_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', executable_sha256)
            or type(port) is not int or not 1 <= port <= 65535 or not callable(lifetime_check)
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Independent bounded application process configuration required')
    requested = ipaddress.ip_address(address)
    if not (requested.is_private or requested.is_loopback) or requested.is_link_local or requested.is_multicast or requested.is_unspecified:
        raise ValueError('Selected internal application listener required')
    if lifetime_check(95) is not True:raise Inconclusive('Application configuration lifetime unavailable')
    source = probe_source()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', source, private_binding_path,
                      json.dumps(selected), str(pid), start_ticks, executable_sha256, str(requested), str(port)],
                      cwd=Path(__file__).resolve().parents[1], timeout=90, max_output_bytes=4096)
    report = dict(outcome='storage_startup_configuration_incomplete', snapshot_stable=False,
                  selected_credentials_matched=False, application_use_verified=False,
                  current_configuration_verified=False, deployment_attribution_verified=False,
                  command=command, probe_sha256=hashlib.sha256(source.encode()).hexdigest(),
                  limits='Selected exec startup environment only; source setting semantics, actual use, '
                         'current configuration, Kubernetes attribution, endpoint route and storage privacy remain separate.')
    try:
        value = json.loads((attempt.directory/label/'stdout.log').read_text(), object_pairs_hook=unique_pairs)
        fields = {'outcome', 'snapshot_stable', 'selected_credentials_matched', 'application_use_verified',
                  'current_configuration_verified', 'deployment_attribution_verified', 'pid',
                  'process_start_ticks', 'executable_sha256', 'configuration_sha256', 'process_identity_sha256'}
        if (not isinstance(value, dict) or set(value) != fields
                or value['outcome'] != 'storage_startup_configuration_observed'
                or type(value['pid']) is not int or value['pid'] != pid or value['process_start_ticks'] != start_ticks
                or value['executable_sha256'] != executable_sha256
                or value['snapshot_stable'] is not True or value['selected_credentials_matched'] is not True
                or any(value[key] is not False for key in ('application_use_verified', 'current_configuration_verified',
                                                          'deployment_attribution_verified'))
                or any(not isinstance(value[key], str) or not re.fullmatch(r'[0-9a-f]{64}', value[key])
                       for key in ('configuration_sha256', 'process_identity_sha256'))):
            raise ValueError('Incomplete startup configuration projection')
        if command['outcome'] == 'passed':report.update(value)
    except (OSError, ValueError, TypeError, KeyError):pass
    try:verified = lifetime_check(0) is True
    except Exception as error:
        verified = False;report['lifetime_error_type'] = type(error).__name__
    if not verified:
        report.update(outcome='storage_startup_configuration_incomplete', snapshot_stable=False,
                      selected_credentials_matched=False)
    atomic_json(attempt.directory/(label+'.json'), report)
    return report
