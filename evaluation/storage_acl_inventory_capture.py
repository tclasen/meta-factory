"""Guarded complete declared-ACL capture over an independently verified inventory."""
import hashlib
import json
import os
from pathlib import Path
import re

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .job_storage import bucket_name
from .verdicts import Inconclusive


def probe_source():
    directory = Path(__file__).parent
    modules = [('support', 'storage_canary_probe.py'), ('inventory', 'storage_inventory.py'),
               ('private_files', 'storage_inventory_probe.py'), ('semantics', 'storage_acl_semantics.py'),
               ('core', 'storage_acl_inventory.py'), ('probe', 'storage_acl_inventory_probe.py')]
    parts = []
    for namespace, filename in modules:
        source = (directory / filename).read_text()
        parts.append(namespace + '={"__name__":"trusted_acl_inventory_' + namespace + '"}\n'
                     'exec(compile(' + repr(source) + ',"trusted-' + namespace + '","exec"),' + namespace + ')\n')
    return ''.join(parts) + 'probe["main"](support,inventory,private_files,semantics,core)\n'


def capture_acl_inventory(attempt, *, peer_prefix, private_binding_path, private_manifest_path,
                          inventory_manifest_sha256, lifetime_check, page_size=100,
                          label='foundation-storage-acl-inventory'):
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v for v in peer_prefix)
            or any(not isinstance(v, str) or not v.startswith('/') or len(v) > 4096 or '\x00' in v
                   for v in (private_binding_path, private_manifest_path))
            or not isinstance(inventory_manifest_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', inventory_manifest_sha256)
            or type(page_size) is not int or not 1 <= page_size <= 1000 or not callable(lifetime_check)
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Bounded independently verified ACL inventory peer required')
    destination = Path(os.path.normpath(private_manifest_path))
    if destination == attempt.directory or attempt.directory in destination.parents:
        raise ValueError('Private inventory must remain outside evidence')
    if lifetime_check(65) is not True:raise Inconclusive('ACL inventory peer lifetime unavailable')
    source = probe_source()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', source, private_binding_path,
                      private_manifest_path, inventory_manifest_sha256, str(page_size)],
                      cwd=Path(__file__).resolve().parents[1], timeout=60, max_output_bytes=8192)
    report = dict(outcome='acl_inventory_observation_incomplete', classification='inconclusive',
                  scope_visited_complete=False, acl_schema_coverage_complete=False, snapshot_stable=False,
                  manifest_stable=False, inventory_rechecks_passed=False, privacy_verified=None,
                  atomic_snapshot_verified=False, command=command,
                  probe_sha256=hashlib.sha256(source.encode()).hexdigest(),
                  limits='Declared bucket/current-object/retained-version ACLs only; delete markers counted '
                         'separately. Inventory consistency is not atomicity or a writer fence. '
                         'Effective policy, other authorization and application bucket binding remain unverified. '
                         'No whole-bucket privacy or AC-001 acceptance verdict.')
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text(), object_pairs_hook=unique_pairs)
        counts = ('expected_target_count', 'visited_target_count', 'supported_target_count',
                  'inconclusive_target_count', 'unstable_target_count', 'unavailable_target_count',
                  'broad_acl_target_count', 'current_object_target_count', 'retained_version_target_count',
                  'delete_marker_count')
        flags = ('scope_visited_complete', 'acl_schema_coverage_complete', 'inventory_rechecks_passed',
                 'snapshot_stable', 'manifest_stable')
        fields = {*counts, *flags, 'outcome', 'classification', 'observation_sha256', 'privacy_verified',
                  'atomic_snapshot_verified', 'bucket', 'inventory_manifest_sha256'}
        if (not isinstance(value, dict) or set(value) != fields or value['outcome'] != 'acl_inventory_observed'
                or value['classification'] not in ('inconclusive', 'broad_acl_grant_observed',
                                                   'no_broad_grant_in_supported_acl_inventory')
                or any(type(value[k]) is not int or not 0 <= value[k] <= 2001 for k in counts)
                or any(value[k] > 1000 for k in ('current_object_target_count', 'retained_version_target_count', 'delete_marker_count'))
                or value['retained_version_target_count'] + value['delete_marker_count'] > 1000
                or value['current_object_target_count'] > value['retained_version_target_count']
                or any(type(value[k]) is not bool for k in flags)
                or any(value[k] is not True for k in ('scope_visited_complete', 'inventory_rechecks_passed', 'manifest_stable'))
                or value['privacy_verified'] is not None or value['atomic_snapshot_verified'] is not False
                or value['inventory_manifest_sha256'] != inventory_manifest_sha256
                or not isinstance(value['observation_sha256'], str)
                or not re.fullmatch(r'[0-9a-f]{64}', value['observation_sha256'])
                or value['expected_target_count'] != 1 + value['current_object_target_count'] + value['retained_version_target_count']
                or value['visited_target_count'] != value['expected_target_count']
                or value['supported_target_count'] + value['inconclusive_target_count'] != value['expected_target_count']
                or value['broad_acl_target_count'] > value['supported_target_count']
                or value['unstable_target_count'] > value['inconclusive_target_count']
                or value['unavailable_target_count'] > value['inconclusive_target_count']
                or value['acl_schema_coverage_complete'] != (value['inconclusive_target_count'] == 0)
                or value['snapshot_stable'] != (value['unstable_target_count'] == 0)
                or (value['classification'] != 'inconclusive') != value['acl_schema_coverage_complete']
                or value['classification'] == 'broad_acl_grant_observed' and not value['broad_acl_target_count']
                or value['classification'] == 'no_broad_grant_in_supported_acl_inventory' and value['broad_acl_target_count']):
            raise ValueError('Incomplete ACL inventory projection')
        bucket_name(value['bucket'])
        if command['outcome'] == 'passed':report.update(value)
    except (OSError, ValueError, TypeError, KeyError):pass
    try:verified = lifetime_check(0) is True
    except Exception as error:
        verified = False;report['lifetime_error_type'] = type(error).__name__
    if not verified:
        report.update(outcome='acl_inventory_observation_incomplete', classification='inconclusive',
                      scope_visited_complete=False, acl_schema_coverage_complete=False, snapshot_stable=False,
                      manifest_stable=False, inventory_rechecks_passed=False)
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
