"""Guarded full-bucket inventory transport with an operator-private manifest handoff."""
import hashlib
import json
from pathlib import Path
import re
import os
import stat

from .evidence import atomic_json, collect
from .identity_observer import unique_pairs
from .job_storage import bucket_name
from .verdicts import Inconclusive
from .storage_inventory_probe import private_parent


def verify_private_manifest(path, expected_sha256):
    """Verify a privately accessible ordinary manifest without returning its contents."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(r'[0-9a-f]{64}', expected_sha256):
        return False
    parent = None
    try:
        parent, name, identity = private_parent(path)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(descriptor, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o077
                    or before.st_size > 8 * 1024 * 1024):return False
            raw = stream.read(8 * 1024 * 1024 + 1)
            after = os.fstat(stream.fileno())
            if (len(raw) > 8 * 1024 * 1024 or any(getattr(before, key) != getattr(after, key) for key in
                    ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))):
                return False
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if any(getattr(after, key) != getattr(named, key) for key in
               ('st_dev', 'st_ino', 'st_uid', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')):
            return False
        reopened, _, after_identity = private_parent(path)
        os.close(reopened)
        return identity == after_identity and hashlib.sha256(raw).hexdigest() == expected_sha256
    except (OSError, ValueError, TypeError):return False
    finally:
        if parent is not None:os.close(parent)


def probe_source():
    directory = Path(__file__).parent
    namespaces = [('support', 'storage_canary_probe.py'), ('inventory', 'storage_inventory.py'),
                  ('probe', 'storage_inventory_probe.py')]
    parts = []
    for namespace, filename in namespaces:
        source = (directory / filename).read_text()
        parts.append(namespace + '={"__name__":"trusted_inventory_' + namespace + '"}\n'
                     'exec(compile(' + repr(source) + ',"trusted-' + namespace + '","exec"),' + namespace + ')\n')
    return ''.join(parts) + 'probe["main"](support,inventory)\n'


def capture_inventory(attempt, *, peer_prefix, private_binding_path, private_manifest_path,
                      lifetime_check, manifest_check, page_size=100, label='foundation-storage-inventory'):
    """The caller binds endpoint/source/files and privately verifies manifest after capture."""
    if (not isinstance(peer_prefix, (list, tuple)) or not 1 <= len(peer_prefix) <= 24
            or any(not isinstance(v, str) or not v or len(v) > 1024 or '\x00' in v for v in peer_prefix)
            or any(not isinstance(v, str) or not v.startswith('/') or len(v) > 4096 or '\x00' in v
                   for v in (private_binding_path, private_manifest_path))
            or type(page_size) is not int or not 1 <= page_size <= 1000
            or not callable(lifetime_check) or not callable(manifest_check)
            or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', label)):
        raise ValueError('Bounded independently verified inventory peer required')
    destination = Path(os.path.normpath(private_manifest_path))
    if destination == attempt.directory or attempt.directory in destination.parents:
        raise ValueError('Private inventory manifest must remain outside evidence')
    if lifetime_check(65) is not True:
        raise Inconclusive('Inventory peer lifetime unavailable')
    source = probe_source()
    command = collect(attempt, label, [*peer_prefix, 'python3', '-c', source, private_binding_path,
                                     private_manifest_path, str(page_size)],
                      cwd=Path(__file__).resolve().parents[1], timeout=60, max_output_bytes=8192)
    report = dict(outcome='inventory_observation_incomplete', snapshot_stable=False,
                  listing_complete=False, private_manifest_written=False, privacy_verified=None,
                  private_manifest_verified=False,
                  atomic_snapshot_verified=False, command=command,
                  probe_sha256=hashlib.sha256(source.encode()).hexdigest(),
                  limits='Bounded repeated current/history listings only. Private manifest must be '
                         'verified separately and kept outside builder mounts/evidence. ACLs, application '
                         'bucket identity, other authorization and writer fencing remain unverified. '
                         'No whole-bucket privacy or AC-001 acceptance verdict.')
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text(), object_pairs_hook=unique_pairs)
        fields = {'outcome', 'snapshot_stable', 'private_manifest_written', 'bucket', 'private_manifest_sha256',
                  'current_object_count', 'retained_version_count', 'delete_marker_count', 'current_sha256',
                  'history_sha256', 'current_page_count', 'history_page_count', 'listing_complete',
                  'current_history_consistent', 'privacy_verified', 'atomic_snapshot_verified'}
        if (not isinstance(value, dict) or set(value) != fields or value['outcome'] != 'inventory_observed'
                or any(value[k] is not True for k in ('snapshot_stable', 'private_manifest_written',
                    'listing_complete', 'current_history_consistent'))
                or value['privacy_verified'] is not None or value['atomic_snapshot_verified'] is not False
                or any(type(value[k]) is not int or not 0 <= value[k] <= 1000
                       for k in ('current_object_count', 'retained_version_count', 'delete_marker_count'))
                or value['retained_version_count'] + value['delete_marker_count'] > 1000
                or value['current_object_count'] > value['retained_version_count']
                or any(type(value[k]) is not int or not 1 <= value[k] <= 20
                       for k in ('current_page_count', 'history_page_count'))
                or any(not isinstance(value[k], str) or not re.fullmatch(r'[0-9a-f]{64}', value[k])
                       for k in ('current_sha256', 'history_sha256', 'private_manifest_sha256'))):
            raise ValueError('Incomplete inventory projection')
        bucket_name(value['bucket'])
        if command['outcome'] == 'passed':
            report.update(value)
            try:manifest_verified = manifest_check(dict(value)) is True
            except Exception as error:
                manifest_verified = False;report['manifest_error_type'] = type(error).__name__
            report['private_manifest_verified'] = manifest_verified
            if not manifest_verified:
                report.update(outcome='inventory_observation_incomplete', listing_complete=False, snapshot_stable=False)
    except (OSError, ValueError, TypeError, KeyError):
        pass
    try:verified = lifetime_check(0) is True
    except Exception as error:
        verified = False;report['lifetime_error_type'] = type(error).__name__
    if not verified:
        report.update(outcome='inventory_observation_incomplete', snapshot_stable=False,
                      listing_complete=False, private_manifest_verified=False)
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
