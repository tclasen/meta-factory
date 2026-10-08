"""Real loopback signed requests and hostile storage/cleanup controls, no sbx."""
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.parse
import uuid

from evaluation.evidence import Attempt
from evaluation.storage_canary import capture_storage_canary
from evaluation.storage_canary_probe import (
    ObservationIncomplete, Peer, observe, private_binding, signed_headers, validate_binding,
)


class Fixture:
    def __init__(self, mode='private'):
        self.mode, self.objects, self.calls = mode, {'unrelated': b'preserve'}, []
        self.versions, self.deletions = {}, []
        self.config = dict(endpoint='', bucket='fixture-bucket', region='us-east-1',
                           access_key=uuid.uuid4().hex, secret_key=uuid.uuid4().hex, session_token=None)
        fixture = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):pass

            def handle_request(self):
                size = int(self.headers.get('Content-Length', '0'))
                body = self.rfile.read(size)
                parsed = urllib.parse.urlsplit(self.path)
                key = parsed.path.removeprefix('/fixture-bucket/'); bucket = parsed.path=='/fixture-bucket'
                authorization = self.headers.get('Authorization')
                signed = authorization is not None
                if signed:
                    # Independent wire verification, plus published-vector test below.
                    prefix, fields = authorization.split(' ', 1)
                    attrs = dict(part.strip().split('=', 1) for part in fields.split(','))
                    names = attrs['SignedHeaders'].split(';')
                    canonical = '\n'.join((self.command, parsed.path, parsed.query,
                        ''.join(name + ':' + self.headers[name].strip() + '\n' for name in names),
                        ';'.join(names), hashlib.sha256(body).hexdigest()))
                    access, scope = attrs['Credential'].split('/', 1)
                    date, region, service, terminator = scope.split('/')
                    signing = ('AWS4' + fixture.config['secret_key']).encode()
                    for part in (date, region, service, terminator):
                        signing = hmac.new(signing, part.encode(), hashlib.sha256).digest()
                    message = '\n'.join((prefix, self.headers['x-amz-date'], scope,
                                          hashlib.sha256(canonical.encode()).hexdigest()))
                    expected = hmac.new(signing, message.encode(), hashlib.sha256).hexdigest()
                    valid = (prefix=='AWS4-HMAC-SHA256' and access==fixture.config['access_key']
                             and region=='us-east-1' and service=='s3' and terminator=='aws4_request'
                             and hmac.compare_digest(expected, attrs['Signature'])
                             and self.headers['x-amz-content-sha256']==hashlib.sha256(body).hexdigest())
                    if not valid:
                        self.send_response(403); self.end_headers(); return
                fixture.calls.append((self.command, key if not bucket else None, signed))
                status, content, version = 200, b'', None
                if not signed and fixture.mode=='redirect':
                    self.send_response(307);self.send_header('Location','http://127.0.0.1:1/');self.end_headers();return
                if not signed and fixture.mode=='denial-error':status=503
                elif not signed and self.command=='GET' and fixture.mode!='public-read':status=403
                elif not signed and self.command=='PUT' and fixture.mode!='public-write':
                    if fixture.mode=='denial-mutation':fixture.objects[key]=body
                    status=403
                elif self.command=='HEAD':status=200 if bucket or key in fixture.objects else 404
                elif self.command=='PUT':
                    if fixture.mode=='write-error':status=503
                    else:
                        fixture.objects[key]=body
                        if fixture.mode=='versioned':
                            version=uuid.uuid4().hex;fixture.versions[key]=version
                elif self.command=='GET':
                    if key not in fixture.objects:status=404
                    else:content=fixture.objects[key]
                    if signed and fixture.mode=='corrupt-read':content=b'wrong'
                    if signed and fixture.mode=='large-response':content=b'x'*5000
                elif self.command=='DELETE':
                    fixture.deletions.append(parsed.query)
                    if fixture.mode=='cleanup-error':status=500
                    elif fixture.mode=='lying-delete':status=204
                    elif fixture.mode=='versioned':
                        selected=urllib.parse.parse_qs(parsed.query).get('versionId',[None])[0]
                        if selected==fixture.versions.get(key):
                            fixture.objects.pop(key,None);fixture.versions.pop(key,None)
                        status=204
                    else:fixture.objects.pop(key,None);status=204
                self.send_response(status);self.send_header('Content-Length',str(len(content)))
                if version is not None:self.send_header('x-amz-version-id',version)
                self.end_headers()
                if self.command!='HEAD':self.wfile.write(content)
            do_HEAD=do_GET=do_PUT=do_DELETE=handle_request
        self.server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
        self.config['endpoint']='http://127.0.0.1:'+str(self.server.server_port)
        self.thread=threading.Thread(target=self.server.serve_forever,daemon=True);self.thread.start()

    def close(self):
        self.server.shutdown();self.server.server_close();self.thread.join(timeout=2)


class StorageCanaryTest(unittest.TestCase):
    def fixture(self, mode='private'):
        fixture=Fixture(mode);self.addCleanup(fixture.close);return fixture

    def test_published_aws_list_objects_signature_vector(self):
        # Public AWS documentation example credentials, never real account access.
        config=dict(endpoint='https://examplebucket.s3.amazonaws.com',region='us-east-1',
                    access_key='AKIAIOSFODNN7EXAMPLE',
                    secret_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',session_token=None)
        headers=signed_headers(config,'GET','/','max-keys=2&prefix=J',b'','20130524T000000Z')
        self.assertTrue(headers['authorization'].endswith(
            'Signature=34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7'))

    def test_actual_private_read_write_denials_and_exact_cleanup(self):
        fixture=self.fixture();report=observe(fixture.config)
        self.assertEqual(report['outcome'],'pass')
        self.assertTrue(report['cleanup_verified']);self.assertFalse(report['abort_suite'])
        self.assertEqual(fixture.objects,{'unrelated':b'preserve'})
        self.assertTrue(all(key is None or key==report['key'] for _,key,_ in fixture.calls))
        self.assertNotIn(fixture.config['secret_key'],json.dumps(report))

    def test_public_access_and_denied_write_mutation_are_failures_with_cleanup(self):
        for mode in ('public-read','public-write','denial-mutation','corrupt-read'):
            with self.subTest(mode=mode):
                fixture=self.fixture(mode);report=observe(fixture.config)
                self.assertEqual(report['outcome'],'fail')
                self.assertTrue(report['abort_suite']);self.assertTrue(report['cleanup_verified'])
                self.assertEqual(fixture.objects,{'unrelated':b'preserve'})

    def test_disclosed_version_is_removed_without_creating_a_delete_marker(self):
        fixture=self.fixture('versioned');report=observe(fixture.config)
        self.assertEqual(report['outcome'],'pass');self.assertTrue(report['cleanup_verified'])
        self.assertEqual(len(report['versions']),1)
        self.assertEqual(fixture.deletions,['versionId='+report['versions'][0]])
        self.assertEqual(fixture.versions,{})
        self.assertEqual(fixture.objects,{'unrelated':b'preserve'})

    def test_service_errors_redirects_and_oversized_responses_are_inconclusive(self):
        for mode in ('write-error','denial-error','redirect','large-response'):
            with self.subTest(mode=mode):
                fixture=self.fixture(mode);report=observe(fixture.config)
                self.assertEqual(report['outcome'],'inconclusive')
                self.assertTrue(report['abort_suite']);self.assertTrue(report['cleanup_verified'])

    def test_failed_or_lying_cleanup_cannot_leave_a_pass(self):
        for mode in ('cleanup-error','lying-delete'):
            with self.subTest(mode=mode):
                report=observe(self.fixture(mode).config)
                self.assertEqual(report['outcome'],'cleanup_incomplete')
                self.assertFalse(report['cleanup_verified']);self.assertTrue(report['abort_suite'])

    def test_existing_key_is_never_overwritten_or_deleted(self):
        fixture=self.fixture();identity=uuid.uuid4();key='factory-evaluation-canary/'+identity.hex
        fixture.objects[key]=b'existing'
        with patch('evaluation.storage_canary_probe.uuid.uuid4',return_value=identity):report=observe(fixture.config)
        self.assertEqual(report['outcome'],'inconclusive')
        self.assertEqual(fixture.objects[key],b'existing')
        self.assertFalse(any(method in ('PUT','DELETE') for method,_,_ in fixture.calls))

    def test_external_metadata_and_redirect_capable_origins_refused(self):
        fixture=self.fixture()
        for origin in ('https://s3.amazonaws.com:443','http://169.254.169.254:80',
                       'http://[::ffff:169.254.169.254]:80',
                       'http://127.0.0.1:1/path','http://user:password@127.0.0.1:1',
                       'http://127.0.0.1:1?query','http://0.0.0.0:1',
                       'http://127.0.0.1:1#','http://127.0.0.1:1?'):
            with self.subTest(origin=origin),self.assertRaises(ObservationIncomplete):
                validate_binding(dict(fixture.config,endpoint=origin))

    def test_bucket_mutations_and_unrelated_object_requests_are_refused(self):
        fixture=self.fixture();peer=Peer(fixture.config)
        for method,key in (('DELETE',None),('PUT',None),('GET','unrelated'),('DELETE','unrelated')):
            with self.subTest(method=method,key=key),self.assertRaises(ObservationIncomplete):
                peer.request(method,key)
        self.assertEqual(fixture.calls,[])

    def test_private_binding_refuses_symlinks_and_shared_permissions(self):
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();binding=root/'binding.json'
            binding.write_text(json.dumps(self.fixture().config));binding.chmod(0o600)
            self.assertEqual(private_binding(binding)['bucket'],'fixture-bucket')
            binding.chmod(0o644)
            with self.assertRaises(ObservationIncomplete):private_binding(binding)
            binding.chmod(0o600);link=root/'link';link.symlink_to(binding)
            with self.assertRaises(OSError):private_binding(link)

    def test_real_peer_child_handoff_and_sanitized_evidence(self):
        fixture=self.fixture()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();binding=root/'binding.json'
            binding.write_text(json.dumps(fixture.config));binding.chmod(0o600)
            prefix=[sys.executable,'-c',"import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])"]
            with Attempt(root/'attempt',{}) as attempt:
                checked=capture_storage_canary(attempt,peer_prefix=prefix,
                    private_binding_path=str(binding),lifetime_check=lambda _:True)
                self.assertEqual(checked['outcome'],'pass')
                for path in attempt.directory.rglob('*'):
                    if path.is_file():
                        text=path.read_text()
                        self.assertNotIn(fixture.config['secret_key'],text)
                        self.assertNotIn(fixture.config['access_key'],text)

    def test_lifetime_change_cannot_be_reported_as_success(self):
        fixture=self.fixture()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();binding=root/'binding.json'
            binding.write_text(json.dumps(fixture.config));binding.chmod(0o600)
            prefix=[sys.executable,'-c',"import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])"]
            with Attempt(root/'attempt',{}) as attempt:
                checked=capture_storage_canary(attempt,peer_prefix=prefix,
                    private_binding_path=str(binding),lifetime_check=lambda reserve:reserve>0)
                self.assertEqual(checked['outcome'],'inconclusive');self.assertTrue(checked['abort_suite'])

    def test_failed_final_peer_check_retains_an_inconclusive_sanitized_report(self):
        fixture=self.fixture()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name).resolve();binding=root/'binding.json'
            binding.write_text(json.dumps(fixture.config));binding.chmod(0o600)
            prefix=[sys.executable,'-c',"import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])"]
            def lifetime(reserve):
                if reserve==0:raise RuntimeError('private diagnostic must not enter evidence')
                return True
            with Attempt(root/'attempt',{}) as attempt:
                checked=capture_storage_canary(attempt,peer_prefix=prefix,
                    private_binding_path=str(binding),lifetime_check=lifetime)
                self.assertEqual(checked['outcome'],'inconclusive');self.assertTrue(checked['abort_suite'])
                self.assertFalse(checked['cleanup_verified'])
                self.assertTrue(checked['reported_cleanup_verified'])
                self.assertNotIn('private diagnostic',json.dumps(checked))
                self.assertEqual(json.loads((attempt.directory/'foundation-storage.json').read_text()),checked)

    def test_expired_peer_lifetime_prevents_any_request(self):
        fixture=self.fixture();peer=Peer(fixture.config)
        with patch('evaluation.storage_canary_probe.time.monotonic',return_value=peer.started+71), \
             patch('evaluation.storage_canary_probe.time.time',return_value=peer.wall_started+71):
            with self.assertRaises(ObservationIncomplete):peer.request('HEAD')
        self.assertEqual(fixture.calls,[])


if __name__=='__main__':unittest.main()
