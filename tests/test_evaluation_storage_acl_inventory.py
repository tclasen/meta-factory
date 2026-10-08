"""Complete ACL coverage includes old versions and objects behind latest delete markers."""
import copy
import hashlib
import unittest
from unittest.mock import patch

from evaluation.storage_acl_inventory import AclScanIncomplete, encoded, manifest_targets, scan_acl_inventory
from evaluation.storage_acl_semantics import classify_acl
from test_evaluation_storage_acl import acl, grant


def manifest():
    current = [dict(key='sensitive-current-object', version_id=None, latest=True, delete_marker=False)]
    history = [dict(key='sensitive-current-object', version_id='latest', latest=True, delete_marker=False),
               dict(key='sensitive-current-object', version_id='old', latest=False, delete_marker=False),
               dict(key='sensitive-deleted-object', version_id='delete', latest=True, delete_marker=True),
               dict(key='sensitive-deleted-object', version_id='retained', latest=False, delete_marker=False)]
    return dict(bucket='fixture-bucket', **{kind:dict(kind=kind, items=items, page_count=1,
        complete=True, sha256=hashlib.sha256(encoded(items)).hexdigest())
        for kind, items in [('current', current), ('history', history)]})


class StorageAclInventoryTest(unittest.TestCase):
    def scan(self, *, fetch=None, check=None, value=None):
        calls = []
        def read(*target):
            calls.append(target)
            return fetch(target, len(calls)) if fetch else (200, acl(grant()))
        result = scan_acl_inventory(value or manifest(), fetch_acl=read,
                                    inventory_check=check or (lambda _:True), classify_acl=classify_acl)
        return result, calls

    def test_every_current_and_retained_version_is_read_twice(self):
        result, calls = self.scan()
        self.assertEqual(result['expected_target_count'], 5)
        self.assertEqual(result['visited_target_count'], 5)
        self.assertEqual(result['current_object_target_count'], 1)
        self.assertEqual(result['retained_version_target_count'], 3)
        self.assertEqual(result['delete_marker_count'], 1)
        self.assertEqual(len(calls), 10)
        self.assertEqual(calls.count(('version', 'sensitive-deleted-object', 'retained')), 2)
        self.assertNotIn(('version', 'sensitive-deleted-object', 'delete'), calls)
        self.assertTrue(result['acl_schema_coverage_complete'])
        self.assertEqual(result['classification'], 'no_broad_grant_in_supported_acl_inventory')
        self.assertIsNone(result['privacy_verified'])
        self.assertFalse(result['atomic_snapshot_verified'])
        self.assertNotIn('sensitive-', str(result))

    def test_public_old_version_of_deleted_object_is_observed(self):
        def read(target, _):
            entry = grant('Group', 'http://acs.amazonaws.com/groups/global/AllUsers', 'READ')
            return 200, acl(grant(), entry) if target == ('version', 'sensitive-deleted-object', 'retained') else acl(grant())
        result, _ = self.scan(fetch=read)
        self.assertEqual(result['classification'], 'broad_acl_grant_observed')
        self.assertEqual(result['broad_acl_target_count'], 1)
        self.assertTrue(result['scope_visited_complete'])

    def test_unknown_denied_and_drifting_targets_never_get_complete_schema_coverage(self):
        for response in ('unsupported', 'denied', 'drift'):
            def read(target, count):
                if target[0] != 'bucket':return 200, acl(grant())
                if response == 'unsupported':return 200, b'<unsupported/>'
                if response == 'denied':return 403, b'<Error/>'
                return 200, acl(grant()) if count == 1 else acl(grant(permission='READ'))
            with self.subTest(response=response):
                result, calls = self.scan(fetch=read)
                self.assertEqual(len(calls), 10)
                self.assertEqual(result['classification'], 'inconclusive')
                self.assertEqual(result['inconclusive_target_count'], 1)
                self.assertFalse(result['acl_schema_coverage_complete'])
                self.assertTrue(result['scope_visited_complete'])

    def test_changed_inventory_before_or_after_scan_never_returns_complete_scope(self):
        for wanted in ([False], [True, False]):
            checks = iter(wanted)
            with self.assertRaises(AclScanIncomplete):self.scan(check=lambda _:next(checks))

    def test_unavailable_old_version_with_changing_error_bytes_remains_inconclusive(self):
        def read(target, count):
            if target == ('version', 'sensitive-deleted-object', 'retained'):
                return 404, ('<Error><Code>NoSuchKey</Code><RequestId>' + str(count) + '</RequestId></Error>').encode()
            return 200, acl(grant())
        result, calls = self.scan(fetch=read)
        self.assertEqual(len(calls), 10)
        self.assertTrue(result['scope_visited_complete'])
        self.assertEqual(result['unavailable_target_count'], 1)
        self.assertEqual(result['unstable_target_count'], 1)
        self.assertFalse(result['snapshot_stable'])
        self.assertFalse(result['acl_schema_coverage_complete'])
        self.assertEqual(result['classification'], 'inconclusive')

    def test_bad_hash_partial_ambiguous_and_filtered_manifests_are_refused(self):
        changes = []
        value = manifest();value['current']['complete'] = False;changes.append(value)
        value = manifest();value['history']['sha256'] = '0' * 64;changes.append(value)
        value = manifest();value['history']['items'][0]['latest'] = False
        value['history']['sha256'] = hashlib.sha256(encoded(value['history']['items'])).hexdigest();changes.append(value)
        value = manifest();value['history']['items'].append(copy.deepcopy(value['history']['items'][0]))
        value['history']['sha256'] = hashlib.sha256(encoded(value['history']['items'])).hexdigest();changes.append(value)
        value = manifest();value['current']['Prefix'] = 'subset';changes.append(value)
        value = manifest();value['current']['items'][0]['key'] = '../outside'
        value['current']['sha256'] = hashlib.sha256(encoded(value['current']['items'])).hexdigest();changes.append(value)
        for value in changes:
            with self.assertRaises(AclScanIncomplete):manifest_targets(value)

    def test_oversized_response_and_clock_overruns_never_return_partial_success(self):
        with self.assertRaises(AclScanIncomplete):self.scan(fetch=lambda *_:(200, b'x' * 65537))
        with patch('evaluation.storage_acl_inventory.time.monotonic', side_effect=[0, 0, 56]):
            with self.assertRaises(AclScanIncomplete):self.scan()
        with patch('evaluation.storage_acl_inventory.time.time', side_effect=[0, 0, 56]):
            with self.assertRaises(AclScanIncomplete):self.scan()


if __name__ == '__main__':
    unittest.main()
