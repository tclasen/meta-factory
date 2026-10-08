"""Guarded provider-specific anonymous storage observations, not full AC-001 acceptance."""
import hashlib
import json
from pathlib import Path
import re

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .job_storage import bucket_name
from .minio_storage_probe import EXECUTABLE, PROFILE, SOURCE_ARCHIVE
from .verdicts import Inconclusive


def probe_source():
    directory = Path(__file__).parent
    parts = []
    for namespace, filename in [('signing', 'storage_canary_probe.py'), ('policy', 'storage_policy_semantics.py'),
                                ('listener', 'listener_identity_probe.py'), ('route', 'storage_route_probe.py'),
                                ('probe', 'minio_storage_probe.py')]:
        source = (directory / filename).read_text()
        parts.append(namespace + '={"__name__":"trusted_minio_' + namespace + '"}\n'
                     'exec(compile(' + repr(source) + ',"trusted-' + namespace + '","exec"),' + namespace + ')\n')
    return ''.join(parts) + 'probe["main"](signing,policy,listener,route)\n'


def capture_minio_storage(attempt, *, peer_prefix, private_binding_path, provider_profile,
                          pid, start_ticks, lifetime_check, label='foundation-minio-storage'):
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v for v in peer_prefix)
            or not isinstance(private_binding_path, str) or not private_binding_path.startswith('/')
            or len(private_binding_path) > 4096 or '\x00' in private_binding_path
            or not isinstance(provider_profile, str) or not re.fullmatch(r'[a-z0-9-]{1,80}', provider_profile)
            or type(pid) is not int or not 1 <= pid <= 2147483647
            or not isinstance(start_ticks, str) or not re.fullmatch(r'[0-9]{1,24}', start_ticks)
            or not callable(lifetime_check) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Bounded independently verified MinIO provider required')
    if lifetime_check(185) is not True:raise Inconclusive('MinIO observation lifetime unavailable')
    source = probe_source()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', source, private_binding_path,
                      provider_profile, str(pid), start_ticks], cwd=Path(__file__).resolve().parents[1],
                      timeout=180, max_output_bytes=8192)
    report = dict(outcome='storage_observation_incomplete', private_anonymous_verified=None,
                  read_write_checked=False, cleanup_verified=None, abort_suite=True,
                  provider_snapshot_stable=False, policy_snapshot_stable=False, direct_route_verified=False,
                  atomic_snapshot_verified=False, credential_exposure_verified=False, future_changes_verified=False,
                  probe_sha256=hashlib.sha256(source.encode()).hexdigest(), command=command,
                  limits='Explicit operator-built provider only. Anonymous bucket-policy configuration '
                         'and owned-canary access at repeated snapshots; no credential leak, signed-link, '
                         'application bucket identity, future-change, atomicity or AC-001 acceptance proof.')
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text(), object_pairs_hook=unique_pairs)
        # Preserve safe owned-resource recovery fields even if later identity,
        # policy or routing checks fail. These are historical, not proof of cleanup.
        if (isinstance(value, dict) and isinstance(value.get('canary_key'), str)
                and re.fullmatch(r'factory-evaluation-canary/[0-9a-f]{32}', value['canary_key'])
                and isinstance(value.get('canary_versions'), list) and len(value['canary_versions']) <= 2
                and all(isinstance(v, str) and v and len(v) <= 1024 and all(ord(c) >= 32 for c in v)
                        for v in value['canary_versions'])):
            report.update(canary_key=value['canary_key'], canary_versions=value['canary_versions'])
            if type(value.get('cleanup_verified')) is bool:
                report['reported_cleanup_verified'] = value['cleanup_verified']
        base = {'outcome', 'private_anonymous_verified', 'read_write_checked', 'cleanup_verified', 'abort_suite',
                'provider_snapshot_stable', 'policy_snapshot_stable', 'direct_route_verified', 'atomic_snapshot_verified',
                'credential_exposure_verified', 'future_changes_verified', 'canary_outcome', 'canary_key', 'canary_versions',
                'bucket', 'provider_profile', 'executable_sha256', 'source_archive_sha256', 'policy_classification',
                'policy_sha256', 'provider_identity_sha256'}
        flags = ('read_write_checked', 'cleanup_verified', 'abort_suite', 'provider_snapshot_stable',
                 'policy_snapshot_stable', 'direct_route_verified', 'atomic_snapshot_verified',
                 'credential_exposure_verified', 'future_changes_verified')
        if (not isinstance(value, dict) or set(value) != base
                or value['outcome'] not in ('storage_observation_incomplete', 'storage_provider_observed')
                or value['private_anonymous_verified'] is not None and type(value['private_anonymous_verified']) is not bool
                or any(type(value[k]) is not bool for k in flags)
                or any(value[k] is not False for k in ('atomic_snapshot_verified', 'credential_exposure_verified', 'future_changes_verified'))
                or value['provider_profile'] != PROFILE or provider_profile != PROFILE
                or value['executable_sha256'] != EXECUTABLE or value['source_archive_sha256'] != SOURCE_ARCHIVE
                or value['canary_outcome'] not in ('pass', 'fail', 'inconclusive', 'cleanup_incomplete')
                or not isinstance(value['canary_key'], str) or not re.fullmatch(r'factory-evaluation-canary/[0-9a-f]{32}', value['canary_key'])
                or not isinstance(value['canary_versions'], list) or len(value['canary_versions']) > 2
                or any(not isinstance(v, str) or not v or len(v) > 1024 or any(ord(c) < 32 for c in v) for v in value['canary_versions'])
                or value['policy_classification'] not in ('inconclusive', 'bucket_policy_absent',
                    'no_broad_grant_in_supported_policy', 'unconditional_broad_grant_observed')
                or any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                       for k in ('policy_sha256', 'provider_identity_sha256'))):
            raise ValueError('Incomplete MinIO provider projection')
        bucket_name(value['bucket'])
        if value['outcome'] == 'storage_provider_observed':
            if (type(value['private_anonymous_verified']) is not bool or not all(value[k] for k in (
                    'provider_snapshot_stable', 'policy_snapshot_stable', 'direct_route_verified', 'cleanup_verified'))
                    or value['abort_suite'] != (not (value['private_anonymous_verified'] and
                        value['canary_outcome'] == 'pass' and value['read_write_checked']))):
                raise ValueError('Unsupported MinIO provider result')
        elif value['private_anonymous_verified'] is not None or value['abort_suite'] is not True:
            raise ValueError('Incomplete result must remain unknown')
        if command['outcome'] == 'passed':report.update(value)
    except (OSError, ValueError, TypeError, KeyError):pass
    try:verified = lifetime_check(0) is True
    except Exception as error:
        verified = False;report['lifetime_error_type'] = type(error).__name__
    if not verified:
        report.update(outcome='storage_observation_incomplete', private_anonymous_verified=None,
                      read_write_checked=False, cleanup_verified=None, abort_suite=True, provider_snapshot_stable=False,
                      policy_snapshot_stable=False, direct_route_verified=False)
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
