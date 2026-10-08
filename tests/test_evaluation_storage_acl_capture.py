"""Real-child ACL transport checks with private HTTP fixtures, never model calls."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import uuid

from evaluation.evidence import Attempt
from evaluation.storage_acl import capture_acl
from test_evaluation_storage_acl import acl, grant


class StorageAclCaptureTest(unittest.TestCase):
    def observe(self, responses, target, *, lifetime=None, target_mode=0o600):
        calls = []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):pass
            def do_GET(self):
                calls.append((self.command, self.path, bool(self.headers.get('Authorization'))))
                status, body = responses[min(len(calls) - 1, len(responses) - 1)]
                self.send_response(status)
                if status == 307:
                    self.send_header('Location', '/should-not-follow')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve()
                binding = root / 'private.json'
                selection = root / 'target.json'
                config = dict(endpoint='http://127.0.0.1:' + str(server.server_port), bucket='fixture-bucket',
                              region='us-east-1', access_key=uuid.uuid4().hex,
                              secret_key=uuid.uuid4().hex, session_token=None)
                binding.write_text(json.dumps(config));binding.chmod(0o600)
                selection.write_text(json.dumps(target));selection.chmod(target_mode)
                prefix = [sys.executable, '-c',
                          'import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])']
                with Attempt(root / 'attempt', {}) as attempt:
                    result = capture_acl(attempt, peer_prefix=prefix, private_binding_path=str(binding),
                                         private_target_path=str(selection), lifetime_check=lifetime or (lambda _:True))
                    self.assertIsNone(result['privacy_verified'])
                    self.assertFalse(result['inventory_complete'])
                    for path in attempt.directory.rglob('*'):
                        if path.is_file():
                            text = path.read_text()
                            for secret in (config['access_key'], config['secret_key'],
                                           'private response must not enter evidence',
                                           'sensitive-object', 'sensitive-version'):
                                self.assertNotIn(secret, text)
                return result, calls
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_bucket_object_version_paths_are_signed_and_encoded(self):
        body = acl(grant())
        targets = [({'key':None, 'version_id':None}, 'bucket', '/fixture-bucket?acl='),
                   ({'key':'sensitive-object/a?b+% ü', 'version_id':None}, 'object',
                    '/fixture-bucket/sensitive-object/a%3Fb%2B%25%20%C3%BC?acl='),
                   ({'key':'sensitive-object', 'version_id':'sensitive-version/+?='}, 'version',
                    '/fixture-bucket/sensitive-object?acl=&versionId=sensitive-version%2F%2B%3F%3D')]
        for target, scope, path in targets:
            with self.subTest(scope=scope):
                result, calls = self.observe([(200, body)], target)
                self.assertEqual(result['classification'], 'no_broad_grant_in_supported_acl')
                self.assertEqual(result['outcome'], 'selected_acl_observed')
                self.assertEqual(result['scope'], scope)
                self.assertTrue(result['snapshot_stable'])
                self.assertEqual(calls, [('GET', path, True)] * 2)

    def test_public_acl_and_drift_are_distinct(self):
        private = acl(grant())
        public = acl(grant(), grant('Group', 'http://acs.amazonaws.com/groups/global/AllUsers', 'READ'))
        for responses, classification, stable in (
                ([(200, public)], 'broad_acl_grant_observed', True),
                ([(200, private), (200, public)], 'inconclusive', False)):
            result, calls = self.observe(responses, {'key':None, 'version_id':None})
            self.assertEqual(result['classification'], classification)
            self.assertEqual(result['snapshot_stable'], stable)
            self.assertEqual(len(calls), 2)

    def test_denied_missing_malformed_and_oversized_are_not_private(self):
        for status, body in ((403, b'private response must not enter evidence'),
                             (404, b'<Error><Code>NoSuchKey</Code></Error>'),
                             (307, b'redirect must not be followed'),
                             (200, b'not an ACL'), (200, b'x' * 65537)):
            result, calls = self.observe([(status, body)], {'key':None, 'version_id':None})
            self.assertEqual(result['classification'], 'inconclusive')
            self.assertEqual(calls, [('GET', '/fixture-bucket?acl=', True)] * 2)
            if status != 200:
                self.assertEqual(result['outcome'], 'acl_observation_incomplete')

    def test_failed_peer_recheck_invalidates_observation(self):
        for lifetime in (lambda seconds:seconds > 0,
                         lambda seconds:True if seconds else (_ for _ in ()).throw(RuntimeError('private'))):
            result, _ = self.observe([(200, acl(grant()))], {'key':None, 'version_id':None}, lifetime=lifetime)
            self.assertEqual(result['outcome'], 'acl_observation_incomplete')
            self.assertEqual(result['classification'], 'inconclusive')
            self.assertFalse(result['snapshot_stable'])

    def test_invalid_private_targets_make_no_http_requests(self):
        for target in ({'key':None, 'version_id':'sensitive-version'},
                       {'key':'../unrelated', 'version_id':None},
                       {'key':'sensitive-object\n', 'version_id':None},
                       {'key':'sensitive-object'}, {'key':'x' * 1025, 'version_id':None}):
            result, calls = self.observe([(200, acl(grant()))], target)
            self.assertEqual(result['outcome'], 'acl_observation_incomplete')
            self.assertEqual(calls, [])
        result, calls = self.observe([(200, acl(grant()))], {'key':None, 'version_id':None}, target_mode=0o644)
        self.assertEqual(result['outcome'], 'acl_observation_incomplete')
        self.assertEqual(calls, [])


if __name__ == '__main__':
    unittest.main()
