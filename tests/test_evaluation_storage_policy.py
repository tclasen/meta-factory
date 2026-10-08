"""Whole-policy structure controls, deliberately no privacy/acceptance inference."""
import copy
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import tempfile
import threading
import unittest
import uuid

from evaluation.evidence import Attempt
from evaluation.storage_policy import capture_bucket_policy
from evaluation.storage_policy_semantics import classify_policy, classify_response


def statement(principal='*', effect='Allow', prefix='evidence/*'):
    return dict(Effect=effect, Principal=principal, Action='s3:GetObject',
                Resource='arn:aws:s3:::fixture-bucket/' + prefix)


def policy(*statements):
    return dict(Version='2012-10-17', Statement=list(statements))


class StoragePolicyTest(unittest.TestCase):
    def classify(self, value):return classify_policy(value, 'fixture-bucket')

    def test_public_grant_outside_canary_prefix_is_observed(self):
        for who in ('*', {'AWS':'*'}, {'AWS':['*','123456789012']}):
            with self.subTest(who=who):
                result=self.classify(policy(statement(who)))
                self.assertEqual(result['classification'],'unconditional_broad_grant_observed')
                self.assertEqual(result['public_grant_count'],1)

    def test_fixed_named_principals_have_no_broad_grant_without_privacy_claim(self):
        for who in ({'AWS':'123456789012'}, {'AWS':['arn:aws:iam::123456789012:role/service']},
                    {'CanonicalUser':'a'*64}):
            with self.subTest(who=who):
                result=self.classify(policy(statement(who)))
                self.assertEqual(result['classification'],'no_broad_grant_in_supported_policy')
                self.assertNotIn('private',result)

    def test_explicit_deny_or_conditions_do_not_produce_false_public_verdict(self):
        conditional=statement();conditional['Condition']={'IpAddress':{'aws:SourceIp':'10.0.0.0/8'}}
        for value in (policy(statement(),statement(effect='Deny')),policy(conditional)):
            with self.subTest(value=value):self.assertEqual(self.classify(value)['classification'],'inconclusive')

    def test_not_principal_not_action_other_bucket_and_unknown_principals_refused(self):
        changes=({'NotPrincipal':'*'},{'NotAction':'s3:GetObject'},{'Condition':{}},
                 {'Principal':{'AWS':'arn:aws:iam::*:root'}},{'Principal':{'Service':'unknown'}},
                 {'Resource':'arn:aws:s3:::unrelated/*'},{'Resource':'*'},{'Action':'other:Read'})
        for changeset in changes:
            with self.subTest(changes=changeset):
                changed=statement();changed.update(changeset)
                self.assertEqual(self.classify(policy(changed))['classification'],'inconclusive')

    def test_absence_requires_exact_authenticated_s3_error_code(self):
        result=classify_response(404,b'<Error><Code>NoSuchBucketPolicy</Code><RequestId>dynamic</RequestId></Error>',
                                 'fixture-bucket')
        self.assertEqual(result['classification'],'bucket_policy_absent')
        for code in ('NoSuchBucket','AccessDenied','Unknown'):
            with self.subTest(code=code),self.assertRaises(ValueError):
                classify_response(404,('<Error><Code>'+code+'</Code></Error>').encode(),'fixture-bucket')
        for status in (403,500,307):
            with self.subTest(status=status),self.assertRaises(ValueError):
                classify_response(status,b'{}','fixture-bucket')

    def test_duplicate_keys_xml_entities_and_bounds_are_refused(self):
        for status,raw in ((200,b'{"Version":"2012-10-17","Version":"2008-10-17"}'),
                           (404,b'<!DOCTYPE Error [<!ENTITY x "NoSuchBucketPolicy">]><Error><Code>&x;</Code></Error>'),
                           (404,'<!DOCTYPE Error [<!ENTITY x "NoSuchBucketPolicy">]><Error><Code>&x;</Code></Error>'.encode('utf-16')),
                           (200,b' '*65537)):
            with self.subTest(status=status),self.assertRaises(ValueError):
                classify_response(status,raw,'fixture-bucket')
        value=policy(*[statement() for _ in range(65)])
        self.assertEqual(self.classify(value)['classification'],'inconclusive')

    def test_structural_reading_does_not_mutate_the_policy_or_publish_fields(self):
        value=policy(statement());before=copy.deepcopy(value)
        result=classify_response(200,json.dumps(value).encode(),'fixture-bucket')
        self.assertEqual(value,before)
        for name in ('Principal','Resource','Action','evidence/'):
            self.assertNotIn(name,json.dumps(result))

    def test_real_child_policy_reads_and_changed_or_failed_snapshots(self):
        present=json.dumps(policy(statement())).encode()
        absent=b'<Error><Code>NoSuchBucketPolicy</Code></Error>'
        cases=[([(200,present),(200,present)],'unconditional_broad_grant_observed',True),
               ([(200,present),(404,absent)],'inconclusive',False),
               ([(403,b'private response must not enter evidence')],'inconclusive',False)]
        for responses,wanted,stable in cases:
            with self.subTest(wanted=wanted,stable=stable):
                calls=[]
                class Handler(BaseHTTPRequestHandler):
                    def log_message(self,*args):pass
                    def do_GET(self):
                        calls.append((self.command,self.path,bool(self.headers.get('Authorization'))))
                        status,body=responses[min(len(calls)-1,len(responses)-1)]
                        self.send_response(status);self.send_header('Content-Length',str(len(body)))
                        self.end_headers();self.wfile.write(body)
                server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
                thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
                try:
                    with tempfile.TemporaryDirectory() as name:
                        root=Path(name).resolve();binding=root/'private.json'
                        config=dict(endpoint='http://127.0.0.1:'+str(server.server_port),bucket='fixture-bucket',
                                    region='us-east-1',access_key=uuid.uuid4().hex,secret_key=uuid.uuid4().hex,session_token=None)
                        binding.write_text(json.dumps(config));binding.chmod(0o600)
                        prefix=[sys.executable,'-c',"import os,sys;os.execv(sys.executable,[sys.executable]+sys.argv[2:])"]
                        with Attempt(root/'attempt',{}) as attempt:
                            observed=capture_bucket_policy(attempt,peer_prefix=prefix,
                                private_binding_path=str(binding),lifetime_check=lambda _:True)
                            self.assertEqual(observed['classification'],wanted)
                            self.assertEqual(observed['snapshot_stable'],stable)
                            self.assertIsNone(observed['privacy_verified'])
                            self.assertTrue(all(method=='GET' and path=='/fixture-bucket?policy=' and signed
                                                for method,path,signed in calls))
                            for path in attempt.directory.rglob('*'):
                                if path.is_file():
                                    text=path.read_text()
                                    self.assertNotIn(config['secret_key'],text)
                                    self.assertNotIn('private response must not enter evidence',text)
                finally:
                    server.shutdown();server.server_close();thread.join(timeout=2)
