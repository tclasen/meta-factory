"""Operator-side guarded invocation of the trusted private-storage probe."""
import hashlib
import json
from pathlib import Path
import re

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .job_storage import bucket_name
from .verdicts import Inconclusive


def capture_storage_canary(attempt, *, peer_prefix, private_binding_path,
                           lifetime_check, label='foundation-storage'):
    """Prefix runs trusted python in the owned grading peer, not on the host.

    lifetime_check must bind the peer UID, internal endpoint, immutable private
    config, deployment/source and watchdog deadlines. This function does not
    discover application credentials or supply application storage services.
    """
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v
                   for v in peer_prefix) or not callable(lifetime_check)
            or not isinstance(private_binding_path, str) or not private_binding_path.startswith('/')
            or len(private_binding_path) > 4096 or '\x00' in private_binding_path
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Bounded independently verified storage peer required')
    if lifetime_check(85) is not True:
        raise Inconclusive('Storage peer/deployment lifetime unavailable')
    probe = Path(__file__).with_name('storage_canary_probe.py').read_text()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', probe, private_binding_path],
                      cwd=Path(__file__).resolve().parents[1], timeout=80, max_output_bytes=16384)
    report = dict(outcome='inconclusive', abort_suite=True, cleanup_verified=False,
                  command=command, probe_sha256=hashlib.sha256(probe.encode()).hexdigest(),
                  limits='Only one owned object and disclosed write versions; no whole-bucket ACL/history '
                         'or AC-001 acceptance claim. Caller must bind actual peer/config/source identities.')
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text(),
                           object_pairs_hook=unique_pairs)
        fields = {'outcome', 'bucket', 'key', 'read_write_checked', 'anonymous_read_denied',
                  'anonymous_write_denied', 'cleanup_verified', 'versions', 'abort_suite'}
        if (not isinstance(value, dict) or not fields <= set(value)
                or not set(value) <= fields | {'error_type', 'cleanup_error_type'}
                or value['outcome'] not in ('pass', 'fail', 'inconclusive', 'cleanup_incomplete')
                or any(type(value[k]) is not bool for k in ('read_write_checked',
                    'anonymous_read_denied', 'anonymous_write_denied', 'cleanup_verified', 'abort_suite'))
                or not re.fullmatch(r'factory-evaluation-canary/[0-9a-f]{32}', value['key'])
                or not isinstance(value['versions'], list) or len(value['versions']) > 2
                or any(not isinstance(v, str) or not v or len(v) > 1024 for v in value['versions'])
                or value['abort_suite'] != (value['outcome'] != 'pass')):
            raise ValueError('Incomplete bounded storage observation')
        bucket_name(value['bucket'])
        if value['outcome'] == 'pass' and not all(value[k] for k in (
                'read_write_checked', 'anonymous_read_denied', 'anonymous_write_denied', 'cleanup_verified')):
            raise ValueError('Unsupported storage success')
        if command['outcome'] == 'passed':report.update(value)
    except (OSError, ValueError, TypeError, KeyError):
        pass
    try:
        verified = lifetime_check(0) is True
    except Exception as error:
        verified = False
        report['lifetime_error_type'] = type(error).__name__
    if not verified:
        report.update(outcome='inconclusive', abort_suite=True,
                      reported_cleanup_verified=report['cleanup_verified'], cleanup_verified=False,
                      lifetime_outcome='peer_deployment_or_source_changed')
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
