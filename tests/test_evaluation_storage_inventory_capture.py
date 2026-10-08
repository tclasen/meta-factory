"""Private inventory handoff and signed transport controls using real child processes."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit
import uuid

from evaluation.evidence import Attempt
from evaluation.storage_inventory_capture import capture_inventory, verify_private_manifest
from test_evaluation_storage_inventory import page


class StorageInventoryCaptureTest(unittest.TestCase):
    def test_evidence_destination_is_refused_before_peer_or_file_operations(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve()
            with Attempt(root / 'attempt', {}) as attempt:
                with self.assertRaises(ValueError):
                    capture_inventory(attempt, peer_prefix=['owned-peer'], private_binding_path='/private/binding',
                        private_manifest_path=str(attempt.directory / 'inventory.json'),
                        lifetime_check=lambda _:(_ for _ in ()).throw(AssertionError('Peer operation attempted')),
                        manifest_check=lambda _:True)

    def observe(self, *, drift=False, status=200, existing=False, public_parent=False,
                lifetime=None, manifest_check=None):
        calls = []
        key = 'sensitive-owned-object'
        version = 'sensitive-owned-version'
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):pass
            def do_GET(self):
                query = parse_qs(urlsplit(self.path).query, keep_blank_values=True)
                calls.append((self.command, self.path, bool(self.headers.get('Authorization'))))
                kind = 'history' if 'versions' in query else 'current'
                actual_key = 'second-sensitive-owned-object' if drift and len(calls) > 2 else key
                body = page(kind, [(actual_key, version, True, False)]) if status == 200 else b'private response'
                self.send_response(status)
                if status == 307:self.send_header('Location', '/should-not-follow')
                self.send_header('Content-Length', str(len(body)));self.end_headers();self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True);thread.start()
        try:
            with tempfile.TemporaryDirectory() as name:
                root = Path(name).resolve();private = root / 'private';private.mkdir(mode=0o700)
                if public_parent:private.chmod(0o755)
                output = private / 'inventory.json';binding = root / 'binding.json'
                config = dict(endpoint='http://127.0.0.1:' + str(server.server_port), bucket='fixture-bucket',
                              region='us-east-1', access_key=uuid.uuid4().hex,
                              secret_key=uuid.uuid4().hex, session_token=None)
                binding.write_text(json.dumps(config));binding.chmod(0o600)
                if existing:output.write_bytes(b'preserve');output.chmod(0o600)
                def verify(report):
                    if manifest_check is not None:return manifest_check(output, report)
                    return verify_private_manifest(output, report['private_manifest_sha256'])
                prefix = [sys.executable, '-c',
                          'import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])']
                with Attempt(root / 'attempt', {}) as attempt:
                    result = capture_inventory(attempt, peer_prefix=prefix, private_binding_path=str(binding),
                        private_manifest_path=str(output), lifetime_check=lifetime or (lambda _:True),
                        manifest_check=verify, page_size=2)
                    self.assertIsNone(result['privacy_verified'])
                    self.assertFalse(result['atomic_snapshot_verified'])
                    for path in attempt.directory.rglob('*'):
                        if path.is_file():
                            text = path.read_text()
                            if any(secret in text for secret in (config['access_key'], config['secret_key'],
                                                                 key, version, 'private response')):
                                raise AssertionError('Private fixture data entered evidence')
                raw = output.read_bytes() if output.exists() else None
                return result, calls, raw
        finally:
            server.shutdown();server.server_close();thread.join(timeout=2)

    def test_signed_repeated_views_create_verified_private_manifest(self):
        result, calls, raw = self.observe()
        self.assertEqual(result['outcome'], 'inventory_observed')
        self.assertTrue(result['private_manifest_verified'])
        self.assertTrue(result['listing_complete'])
        self.assertEqual(result['current_object_count'], 1)
        self.assertEqual(result['retained_version_count'], 1)
        self.assertEqual(result['private_manifest_sha256'], hashlib.sha256(raw).hexdigest())
        manifest = json.loads(raw)
        self.assertEqual(manifest['current']['items'][0]['key'], 'sensitive-owned-object')
        self.assertEqual(len(calls), 4)
        self.assertTrue(all(method == 'GET' and signed and path.startswith('/fixture-bucket?')
                            for method, path, signed in calls))

    def test_drift_denial_redirect_and_missing_api_cannot_create_handoff(self):
        for options in ({'drift':True}, {'status':403}, {'status':404}, {'status':307}):
            with self.subTest(options=options):
                result, calls, raw = self.observe(**options)
                self.assertEqual(result['outcome'], 'inventory_observation_incomplete')
                self.assertFalse(result['private_manifest_verified'])
                self.assertFalse(result['listing_complete'])
                self.assertIsNone(raw)
                self.assertTrue(all('/should-not-follow' not in path for _, path, _ in calls))

    def test_existing_manifest_and_public_directory_are_refused_before_requests(self):
        for options in ({'existing':True}, {'public_parent':True}):
            result, calls, raw = self.observe(**options)
            self.assertEqual(result['outcome'], 'inventory_observation_incomplete')
            self.assertEqual(calls, [])
            self.assertEqual(raw, b'preserve' if options.get('existing') else None)

    def test_failed_manifest_verification_and_peer_recheck_invalidate_saved_file(self):
        cases = ({'manifest_check':lambda path, report:False}, {'lifetime':lambda seconds:seconds > 0},
                 {'manifest_check':lambda path, report:(_ for _ in ()).throw(RuntimeError('private'))})
        for options in cases:
            result, _, raw = self.observe(**options)
            self.assertEqual(result['outcome'], 'inventory_observation_incomplete')
            self.assertFalse(result['private_manifest_verified'])
            self.assertFalse(result['listing_complete'])
            self.assertTrue(result['private_manifest_written'])
            self.assertIsNotNone(raw)

    def test_private_file_digest_permissions_hardlinks_and_symlinks(self):
        with tempfile.TemporaryDirectory() as name:
            root = Path(name).resolve();path = root / 'manifest.json'
            path.write_bytes(b'owned fixture');path.chmod(0o600)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertTrue(verify_private_manifest(path, digest))
            self.assertFalse(verify_private_manifest(path, '0' * 64))
            path.chmod(0o644);self.assertFalse(verify_private_manifest(path, digest));path.chmod(0o600)
            link = root / 'link';os.link(path, link)
            self.assertFalse(verify_private_manifest(path, digest));link.unlink()
            link.symlink_to(path)
            self.assertFalse(verify_private_manifest(link, digest))
            self.assertFalse(verify_private_manifest(root / 'absent', digest))
            directory_link = root / 'linked-directory';directory_link.symlink_to(root, target_is_directory=True)
            self.assertFalse(verify_private_manifest(directory_link / path.name, digest))

    def test_same_content_rewrite_with_restored_mtime_is_refused(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name).resolve() / 'manifest.json'
            path.write_bytes(b'owned fixture');path.chmod(0o600)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            original = os.fstat;changed = [False]
            def rewrite_after_first_file_stat(descriptor):
                info = original(descriptor)
                if info.st_ino == path.stat().st_ino and not changed[0]:
                    changed[0] = True
                    path.write_bytes(b'owned fixture')
                    os.utime(path, ns=(info.st_atime_ns, info.st_mtime_ns))
                return info
            with patch('evaluation.storage_inventory_capture.os.fstat', side_effect=rewrite_after_first_file_stat):
                self.assertFalse(verify_private_manifest(path, digest))
            self.assertTrue(changed[0])


if __name__ == '__main__':
    unittest.main()
