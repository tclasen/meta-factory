"""Guarded executable/listener identity capture, independent of provider/version headers."""
import hashlib
import ipaddress
import json
from pathlib import Path
import re

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .verdicts import Inconclusive


def capture_listener_identity(attempt, *, peer_prefix, pid, start_ticks, executable_sha256,
                              address, port, lifetime_check, label='foundation-storage-peer'):
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v for v in peer_prefix)
            or type(pid) is not int or not 1 <= pid <= 2147483647
            or not isinstance(start_ticks, str) or not re.fullmatch(r'[0-9]{1,24}', start_ticks)
            or not isinstance(executable_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', executable_sha256)
            or type(port) is not int or not 1 <= port <= 65535 or not callable(lifetime_check)
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Bounded independent listener identity required')
    requested = ipaddress.ip_address(address)
    if isinstance(requested, ipaddress.IPv6Address) and requested.ipv4_mapped:requested = requested.ipv4_mapped
    if not (requested.is_private or requested.is_loopback) or requested.is_link_local or requested.is_multicast or requested.is_unspecified:
        raise ValueError('Selected internal listener required')
    if lifetime_check(45) is not True:raise Inconclusive('Listener peer lifetime unavailable')
    source = Path(__file__).with_name('listener_identity_probe.py').read_text()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', source, str(pid), start_ticks,
                      executable_sha256, str(requested), str(port)],
                      cwd=Path(__file__).resolve().parents[1], timeout=40, max_output_bytes=8192)
    report = dict(outcome='listener_identity_incomplete', snapshot_stable=False, command=command,
                  probe_sha256=hashlib.sha256(source.encode()).hexdigest(), provider_semantics_verified=False,
                  response_route_verified=False, runtime_memory_verified=False,
                  limits='Selected executable file and exclusive listener owner snapshots only. '
                         'Provider build provenance, process memory/libraries/configuration, '
                         'request routing, unseen concurrent changes and effective authorization '
                         'remain separate. No private-storage or AC-001 acceptance verdict.')
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text(), object_pairs_hook=unique_pairs)
        fields = {'pid', 'process_start_ticks', 'boot_id_sha256', 'net_namespace_device', 'net_namespace_inode',
                  'listener_rows', 'same_network_namespace', 'outcome', 'executable_sha256',
                  'exclusive_owner_snapshots', 'snapshot_stable', 'provider_semantics_verified',
                  'response_route_verified', 'runtime_memory_verified'}
        if (not isinstance(value, dict) or set(value) != fields or value['outcome'] != 'listener_identity_observed'
                or type(value['pid']) is not int or value['pid'] != pid or value['process_start_ticks'] != start_ticks
                or value['executable_sha256'] != executable_sha256
                or not isinstance(value['boot_id_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', value['boot_id_sha256'])
                or any(type(value[k]) is not int or value[k] < 0 for k in ('net_namespace_device', 'net_namespace_inode'))
                or type(value['same_network_namespace']) is not bool
                or any(value[k] is not True for k in ('exclusive_owner_snapshots', 'snapshot_stable'))
                or any(value[k] is not False for k in ('provider_semantics_verified', 'response_route_verified', 'runtime_memory_verified'))
                or not isinstance(value['listener_rows'], list) or not 1 <= len(value['listener_rows']) <= 16):
            raise ValueError('Incomplete listener projection')
        for row in value['listener_rows']:
            if (not isinstance(row, list) or len(row) != 3 or not isinstance(row[0], str)
                    or type(row[1]) is not int or row[1] <= 0 or type(row[2]) is not int or row[2] < 0):
                raise ValueError('Incomplete listener socket identity')
            ipaddress.ip_address(row[0])
        if command['outcome'] == 'passed':report.update(value)
    except (OSError, ValueError, TypeError, KeyError):pass
    try:verified = lifetime_check(0) is True
    except Exception as error:
        verified = False;report['lifetime_error_type'] = type(error).__name__
    if not verified:report.update(outcome='listener_identity_incomplete', snapshot_stable=False)
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
