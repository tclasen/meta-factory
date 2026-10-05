"""Physical listing scope, pagination and bounded private subprocess controls."""
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest

from evaluation.evidence import Attempt
from evaluation.job_broker import JobObservationError
from evaluation.job_storage import S3ArtifactCounter, S3ListTransport

IDENTITY='00000000-0000-0000-0000-000000000001'
PREFIX='exports/'+IDENTITY+'/'


def page(keys=(), *, truncated=False, token=None):
    value=dict(Name='fixture-bucket',Prefix=PREFIX,IsTruncated=truncated,
               KeyCount=len(keys),Contents=[{'Key':PREFIX+key} for key in keys])
    if token is not None:value['NextContinuationToken']=token
    return value


class ArtifactCounterTest(unittest.TestCase):
    def counter(self,pages,**kwargs):
        self.calls=[];self.checks=[]
        def transport(bucket,prefix,token,*,timeout):
            self.calls.append((bucket,prefix,token,timeout))
            return pages.pop(0)
        return S3ArtifactCounter(transport,'fixture-bucket',lambda identity:PREFIX,
                                 check=self.checks.append,**kwargs)

    def test_all_physical_pages_count_duplicates_as_distinct_keys(self):
        counter=self.counter([page(['one.zip'],truncated=True,token='next'),page(['two.zip'])])
        self.assertEqual(counter(IDENTITY,timeout=15),2)
        self.assertEqual([call[2] for call in self.calls],[None,'next'])
        self.assertTrue(all(0<call[3]<=15 for call in self.calls))

    def test_empty_scope_is_zero(self):
        self.assertEqual(self.counter([page()])(IDENTITY,timeout=15),0)

    def test_wrong_peer_scope_counts_or_keys_refused(self):
        for changed in (dict(Name='other-bucket'),dict(Prefix='other/'),dict(KeyCount=True),
                        dict(KeyCount=2),dict(IsTruncated=1),dict(Contents=[{'Key':'outside'}])):
            with self.subTest(changed=changed):
                value=page(['one.zip']);value.update(changed)
                with self.assertRaises(JobObservationError):self.counter([value])(IDENTITY,timeout=15)

    def test_repeated_keys_tokens_and_exhaustion_are_inconclusive(self):
        cases=[([page(['one.zip'],truncated=True,token='a'),page(['one.zip'])],{}),
               ([page(truncated=True,token='a'),page(truncated=True,token='a')],{}),
               ([page(truncated=True)],{}),([page(token='unexpected')],{}),
               ([page(truncated=True,token='a')],dict(max_pages=1))]
        for pages,kwargs in cases:
            with self.subTest(pages=pages),self.assertRaises(JobObservationError):
                self.counter(pages,**kwargs)(IDENTITY,timeout=15)

    def test_late_page_and_unverified_peer_cannot_return_success(self):
        now=[0]
        def transport(*args,**kwargs):now[0]=16;return page(['one.zip'])
        counter=S3ArtifactCounter(transport,'fixture-bucket',lambda _:PREFIX,check=lambda _:None,monotonic=lambda:now[0])
        with self.assertRaises(JobObservationError):counter(IDENTITY,timeout=15)
        def refused(_):raise RuntimeError('peer replaced')
        counter=S3ArtifactCounter(lambda *a,**k:self.fail('Unverified peer read'),
            'fixture-bucket',lambda _:PREFIX,check=refused)
        with self.assertRaises(RuntimeError):counter(IDENTITY,timeout=15)

    def test_unrelated_export_scope_is_refused_before_read(self):
        counter=S3ArtifactCounter(lambda *a,**k:self.fail('Unbound scope read'),
            'fixture-bucket',lambda _:'all-exports/',check=lambda _:None)
        with self.assertRaises(JobObservationError):counter(IDENTITY,timeout=15)


class StorageTransportTest(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)

    def transport(self,attempt,source,**kwargs):
        client=self.root/'client.py';client.write_text(source)
        return S3ListTransport(attempt,[sys.executable,str(client)],check=kwargs.pop('check',lambda _:None),cwd=self.root,**kwargs)

    def test_real_child_fixed_command_and_redacted_outputs(self):
        # The child verifies actual arguments/environment before sending keys.
        source='''import json,os,sys
assert sys.argv[1:3]==['s3api','list-objects-v2']
assert sys.argv[sys.argv.index('--bucket')+1]=='fixture-bucket'
assert sys.argv[sys.argv.index('--continuation-token')+1]=='private-token-canary'
assert '--no-paginate' in sys.argv
assert os.environ['AWS_MAX_ATTEMPTS']=='1'
print(json.dumps({'private-key-canary':'value'}))
print('private-credential-canary',file=sys.stderr)
'''
        with Attempt(self.root/'observed',{}) as attempt:
            transport=self.transport(attempt,source)
            self.assertEqual(transport('fixture-bucket',PREFIX,'private-token-canary',timeout=2),{'private-key-canary':'value'})
        for path in (self.root/'observed').rglob('*'):
            if path.is_file():
                for private in ('private-key-canary','private-credential-canary','private-token-canary',IDENTITY):
                    self.assertNotIn(private,path.read_text())

    def test_actual_timeout_output_limit_and_failed_child_are_inconclusive(self):
        controls=[('timeout','import time;time.sleep(10)',.1,{}),
                  ('output_limit',"print('x'*4096)",2,dict(max_output_bytes=1024)),
                  ('command_failed','import sys;sys.exit(3)',2,{})]
        for outcome,source,timeout,kwargs in controls:
            with self.subTest(outcome=outcome),Attempt(self.root/outcome,{}) as attempt:
                transport=self.transport(attempt,source,**kwargs)
                with self.assertRaises(JobObservationError):transport('fixture-bucket',PREFIX,None,timeout=timeout)
                record=json.loads(next(attempt.directory.glob('storage-*/result.json')).read_text())
                self.assertEqual(record['outcome'],outcome)
                self.assertIsInstance(record['exit_code'],int)

    def test_hostile_json_is_refused_and_private_error_redacted(self):
        for index,payload in enumerate(('{"x":1,"x":2}','{"x":NaN}','[]')):
            with Attempt(self.root/('json-'+str(index)),{}) as attempt:
                transport=self.transport(attempt,'print('+repr(payload)+')')
                with self.assertRaises(JobObservationError):transport('fixture-bucket',PREFIX,None,timeout=2)

    def test_post_command_revocation_suppresses_result(self):
        calls=[]
        def check(_):
            calls.append(1)
            if len(calls)>1:raise RuntimeError('private-credential-canary')
        with Attempt(self.root/'revoked',{}) as attempt:
            transport=self.transport(attempt,'print("{}")',check=check)
            with self.assertRaises(JobObservationError):transport('fixture-bucket',PREFIX,None,timeout=2)
            self.assertNotIn('private-credential-canary',next(attempt.directory.glob('storage-*/result.json')).read_text())
