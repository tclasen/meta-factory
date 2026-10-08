"""Complete declared-ACL inventory scans; no effective privacy or atomicity verdict."""
import hashlib
import json
import re
import time


class AclScanIncomplete(Exception):
    pass


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode()


def manifest_targets(manifest):
    """Validate the private handoff and include every applicable retained version."""
    if (not isinstance(manifest, dict) or set(manifest) != {'bucket', 'current', 'history'}
            or not isinstance(manifest['bucket'], str)):
        raise AclScanIncomplete('Exact private inventory manifest required')
    targets = [('bucket', None, None)]
    visible, retained_visible, latest = set(), set(), {}
    deleted = 0
    for kind in ('current', 'history'):
        view = manifest[kind]
        if (not isinstance(view, dict) or set(view) != {'kind', 'items', 'page_count', 'complete', 'sha256'}
                or view['kind'] != kind or view['complete'] is not True
                or type(view['page_count']) is not int or not 1 <= view['page_count'] <= 20
                or not isinstance(view['items'], list) or len(view['items']) > 1000
                or not isinstance(view['sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', view['sha256'])
                or hashlib.sha256(encoded(view['items'])).hexdigest() != view['sha256']):
            raise AclScanIncomplete('Complete hash-bound private inventory required')
        seen = set()
        for item in view['items']:
            if not isinstance(item, dict) or set(item) != {'key', 'version_id', 'latest', 'delete_marker'}:
                raise AclScanIncomplete('Exact inventory identity required')
            key, version = item['key'], item['version_id']
            for value in (key, version):
                if value is not None and (not isinstance(value, str) or not 1 <= len(value.encode('utf-8')) <= 1024
                        or any(ord(char) < 32 or ord(char) == 127 for char in value)):
                    raise AclScanIncomplete('Unsupported bounded ACL identity')
            if (key is None or any(part in ('.', '..') for part in key.split('/'))
                    or type(item['latest']) is not bool or type(item['delete_marker']) is not bool
                    or (key, version) in seen):
                raise AclScanIncomplete('Ambiguous ACL inventory identity')
            seen.add((key, version))
            if kind == 'current':
                if version is not None or item['latest'] is not True or item['delete_marker'] is not False:
                    raise AclScanIncomplete('Invalid current inventory identity')
                visible.add(key);targets.append(('object', key, None))
            else:
                if version is None:
                    raise AclScanIncomplete('Retained version identity required')
                latest[key] = latest.get(key, 0) + int(item['latest'])
                if item['latest'] and not item['delete_marker']:retained_visible.add(key)
                if item['delete_marker']:deleted += 1
                else:targets.append(('version', key, version))
    if visible != retained_visible or any(value != 1 for value in latest.values()):
        raise AclScanIncomplete('Current and retained inventories disagree')
    return targets, deleted


def scan_acl_inventory(manifest, *, fetch_acl, inventory_check, classify_acl, timeout=55):
    """The transport binds the peer and request deadlines; every target is visited twice."""
    if (not callable(fetch_acl) or not callable(inventory_check) or not callable(classify_acl)
            or type(timeout) not in (int, float) or not 0 < timeout <= 55):
        raise ValueError('Bounded independently verified ACL scan required')
    targets, deleted = manifest_targets(manifest)
    started, wall_started = time.monotonic(), time.time()
    def deadline():
        if max(time.monotonic() - started, time.time() - wall_started) >= timeout:
            raise AclScanIncomplete('Complete ACL scan deadline')
    deadline()
    if inventory_check(manifest) is not True:
        raise AclScanIncomplete('Inventory changed before ACL scan')
    deadline()
    counts = dict(expected_target_count=len(targets), visited_target_count=0, supported_target_count=0,
                  inconclusive_target_count=0, unstable_target_count=0, unavailable_target_count=0,
                  broad_acl_target_count=0, current_object_target_count=sum(t[0] == 'object' for t in targets),
                  retained_version_target_count=sum(t[0] == 'version' for t in targets), delete_marker_count=deleted)
    identities = []
    for target in targets:
        observations = []
        for _ in range(2):
            deadline()
            status, raw = fetch_acl(*target)
            deadline()
            if (type(status) is not int or not 100 <= status <= 599
                    or not isinstance(raw, bytes) or len(raw) > 65536):
                raise AclScanIncomplete('Bounded ACL response unavailable')
            observations.append((status, hashlib.sha256(raw).hexdigest(), classify_acl(status, raw)))
        first, second = observations
        counts['visited_target_count'] += 1
        stable = first == second
        unavailable = first[0] != 200 or second[0] != 200
        supported = (stable and not unavailable and first[2]['classification'] in
                     ('broad_acl_grant_observed', 'no_broad_grant_in_supported_acl'))
        counts['unstable_target_count'] += int(not stable)
        counts['unavailable_target_count'] += int(unavailable)
        counts['supported_target_count'] += int(supported)
        counts['inconclusive_target_count'] += int(not supported)
        counts['broad_acl_target_count'] += int(supported and first[2]['classification'] == 'broad_acl_grant_observed')
        identities.append((hashlib.sha256(encoded(target)).hexdigest(), observations))
    if inventory_check(manifest) is not True:
        raise AclScanIncomplete('Inventory changed after ACL scan')
    deadline()
    classification = 'inconclusive'
    if not counts['inconclusive_target_count']:
        classification = ('broad_acl_grant_observed' if counts['broad_acl_target_count']
                          else 'no_broad_grant_in_supported_acl_inventory')
    return dict(counts, classification=classification, scope_visited_complete=True,
                acl_schema_coverage_complete=not counts['inconclusive_target_count'],
                inventory_rechecks_passed=True, snapshot_stable=not counts['unstable_target_count'],
                observation_sha256=hashlib.sha256(encoded(identities)).hexdigest(),
                privacy_verified=None, atomic_snapshot_verified=False)
