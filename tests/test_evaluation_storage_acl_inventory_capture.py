"""Real-child full ACL scans with private inventory and signed HTTP fixtures."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlsplit
import uuid

from evaluation.evidence import Attempt
from evaluation.storage_acl_inventory import encoded
from evaluation.storage_acl_inventory_capture import capture_acl_inventory
from test_evaluation_storage_acl import acl, grant
from test_evaluation_storage_acl_inventory import manifest
from test_evaluation_storage_inventory import page


class StorageAclInventoryCaptureTest(unittest.TestCase):
    def observe(self, *, public=False, stale=False, drift=False, denied=False, corrupt=False, lifetime=None):
        value = manifest();versions = {}
        for item in value['history']['items']:
            versions[item['version_id']] = 'sensitive-version-' + uuid.uuid4().hex
            item['version_id'] = versions[item['version_id']]
        value['history']['items'].sort(key=lambda item:(item['key'].encode(), item['version_id'], item['delete_marker']))
        value['history']['sha256'] = hashlib.sha256(encoded(value['history']['items'])).hexdigest()
        calls, reads = [], [0]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):pass
            def do_GET(self):
                calls.append((self.command, self.path, bool(self.headers.get('Authorization'))))
                query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                if 'acl' in query:
                    reads[0] += 1
                    body = acl(grant())
                    if public and query.get('versionId') == [versions['retained']]:
                        body = acl(grant(), grant('Group', 'http://acs.amazonaws.com/groups/global/AllUsers', 'READ'))
                    status = 403 if denied and query.get('versionId') == [versions['old']] else 200
                else:
                    kind = 'history' if 'versions' in query else 'current'
                    entries = [(item['key'], item['version_id'], item['latest'], item['delete_marker'])
                               for item in value[kind]['items']]
                    if stale or drift and reads[0] > 0:
                        entries = []
                    body = page(kind, entries, size=100);status = 200
                self.send_response(status);self.send_header('Content-Length', str(len(body)))
                self.end_headers();self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve();private = root / 'private';private.mkdir(mode=0o700)
                target = private / 'inventory.json';binding = root / 'binding.json'
                raw = encoded(value);digest = hashlib.sha256(raw).hexdigest()
                target.write_bytes(raw + (b'changed' if corrupt else b''));target.chmod(0o600)
                config = dict(endpoint='http://127.0.0.1:' + str(server.server_port), bucket='fixture-bucket',
                              region='us-east-1', access_key=uuid.uuid4().hex,
                              secret_key=uuid.uuid4().hex, session_token=None)
                binding.write_text(json.dumps(config));binding.chmod(0o600)
                prefix = [sys.executable, '-c',
                          'import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])']
                with Attempt(root / 'attempt', {}) as attempt:
                    result = capture_acl_inventory(attempt, peer_prefix=prefix, private_binding_path=str(binding),
                        private_manifest_path=str(target), inventory_manifest_sha256=digest,
                        lifetime_check=lifetime or (lambda _:True))
                    self.assertIsNone(result['privacy_verified'])
                    self.assertFalse(result['atomic_snapshot_verified'])
                    for path in attempt.directory.rglob('*'):
                        if path.is_file():
                            text = path.read_text()
                            if any(secret in text for secret in (config['access_key'], config['secret_key'],
                                'sensitive-current-object', 'sensitive-deleted-object', *versions.values())):
                                raise AssertionError('Private fixture data entered evidence')
                return result, calls, reads[0]
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_full_signed_private_scan_checks_old_versions_and_inventory(self):
        result, calls, reads = self.observe()
        self.assertEqual(result['outcome'], 'acl_inventory_observed')
        self.assertTrue(result['scope_visited_complete'])
        self.assertTrue(result['acl_schema_coverage_complete'])
        self.assertEqual(result['visited_target_count'], 5)
        self.assertEqual(reads, 10)
        self.assertEqual(len(calls), 14)
        self.assertTrue(all(method == 'GET' and signed for method, _, signed in calls))

    def test_public_retained_version_is_observed_and_denied_version_is_inconclusive(self):
        result, _, _ = self.observe(public=True)
        self.assertEqual(result['classification'], 'broad_acl_grant_observed')
        self.assertEqual(result['broad_acl_target_count'], 1)
        result, _, reads = self.observe(denied=True)
        self.assertEqual(result['classification'], 'inconclusive')
        self.assertFalse(result['acl_schema_coverage_complete'])
        self.assertTrue(result['scope_visited_complete'])
        self.assertEqual(reads, 10)

    def test_stale_or_changed_inventory_and_corrupt_manifest_never_complete(self):
        for options in ({'stale':True}, {'drift':True}, {'corrupt':True}):
            result, calls, reads = self.observe(**options)
            self.assertEqual(result['outcome'], 'acl_inventory_observation_incomplete')
            self.assertFalse(result['scope_visited_complete'])
            if options.get('corrupt'):self.assertEqual(calls, [])
            if options.get('stale'):self.assertEqual(reads, 0)

    def test_failed_final_peer_recheck_invalidates_scope(self):
        result, _, reads = self.observe(lifetime=lambda seconds:seconds > 0)
        self.assertEqual(reads, 10)
        self.assertEqual(result['outcome'], 'acl_inventory_observation_incomplete')
        self.assertFalse(result['scope_visited_complete'])
        self.assertFalse(result['acl_schema_coverage_complete'])


if __name__ == '__main__':
    unittest.main()
