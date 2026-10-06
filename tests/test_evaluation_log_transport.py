"""Fixed private log snapshots require source/guard continuity and complete output."""
import base64
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.log_transport import LogTransport


CANARY='Private-log-canary-2026!'
SOURCE=dict(namespace='incident-app',pod_name='worker.fixture-1',pod_uid='pod-uid-1',
            container_name='worker',container_id='containerd://fixture-1',previous=False)
CLIENT=r'''import json,signal,sys,time
signal.alarm(5)
mode=sys.argv[1]
if mode=='flags':
 assert sys.argv[2:]==['logs','--namespace=incident-app','worker.fixture-1','--container=worker','--timestamps=false','--tail=-1','--previous=false','--request-timeout=1s']
 print('ordinary log')
if mode in ('leak','failed-leak'):print('Private-log-canary-2026!')
if mode in ('binary','binary-diagnostics'):
 destination=sys.stderr.buffer if mode=='binary-diagnostics' else sys.stdout.buffer
 raw=b'PK\x03\x04\x00\xffprivate\nlog-binary'
 if '--timestamps=true' in sys.argv:raw=b'2026-10-06T00:00:00Z '+raw.replace(b'\n',b'\n2026-10-06T00:00:00Z ')
 destination.write(raw)
if mode=='large':print('x'*8192)
if mode=='diagnostics':print('Private-log-canary-2026!',file=sys.stderr)
if mode=='diagnostic-limit':print('x'*131072,file=sys.stderr)
if mode in ('failed','failed-leak'):sys.exit(7)
if mode=='hang':time.sleep(5)
'''


class LogTransportTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.attempt=Attempt(self.root/'attempt',{'purpose':'log transport fixture'})
        self.addCleanup(self.attempt.close);self.calls=[];self.allow=True

    def check(self,source,reserve):
        self.calls.append((copy.deepcopy(source),reserve));return self.allow

    def reader(self,mode,**kwargs):
        return LogTransport(self.attempt,[sys.executable,'-c',CLIENT,mode],SOURCE,check=self.check,cwd=self.root,**kwargs)

    def assert_private(self):
        for path in self.attempt.directory.rglob('*'):
            if path.is_file():self.assertNotIn(CANARY.encode(),path.read_bytes())

    def test_exact_flags_and_source_copy_guarded_before_and_after(self):
        selected=dict(SOURCE)
        reader=LogTransport(self.attempt,[sys.executable,'-c',CLIENT,'flags'],selected,check=self.check,cwd=self.root)
        selected['pod_uid']='changed'
        result=reader([CANARY],timeout=1)
        self.assertEqual(result['outcome'],'observed_clean')
        self.assertTrue(result['client_group_absent'])
        self.assertEqual(self.calls,[(SOURCE,6),(SOURCE,5)])
        self.assert_private()

    def test_binary_stream_and_diagnostics_stay_private(self):
        raw=b'PK\x03\x04\x00\xffprivate\nlog-binary'
        for mode,expected in [('binary','canary_detected'),('binary-diagnostics','observed_clean')]:
            result=self.reader(mode)(binary_values=[raw],timeout=1)
            self.assertEqual(result['outcome'],expected)
            self.assertTrue(result['source_verified_before'] and result['source_verified_after'])
            self.assertTrue(result['client_group_absent'])
        for path in self.attempt.directory.rglob('*'):
            if path.is_file():
                for secret in (raw,base64.b64encode(raw),raw.hex().encode()):self.assertNotIn(secret,path.read_bytes())

    def test_invalid_binary_controls_refused_before_client(self):
        before=set(self.attempt.directory.iterdir())
        for values in ([],['private-string'],[b'short'],[b'x'*65537]):
            with self.assertRaises(ValueError):self.reader('binary')(binary_values=values,timeout=1)
        self.assertEqual(self.calls,[])
        self.assertEqual(before,set(self.attempt.directory.iterdir()))

    def test_raw_leak_is_only_reported_as_sanitized_receipt(self):
        result=self.reader('leak')([CANARY],timeout=1)
        self.assertEqual(result['outcome'],'canary_detected')
        self.assertTrue(result['scan']['canary_present'])
        self.assertTrue(result['client_group_absent'])
        self.assert_private()

    def test_failed_client_cannot_establish_absence_but_does_not_erase_leak(self):
        for mode,expected in [('failed','incomplete'),('failed-leak','canary_detected')]:
            result=self.reader(mode)([CANARY],timeout=1)
            self.assertEqual(result['outcome'],expected)
            self.assertEqual(result['exit_code'],7)
            self.assertFalse(result['scan']['complete'])
            self.assertTrue(result['client_group_absent'])
        self.assert_private()

    def test_timeout_byte_and_diagnostic_limits_are_incomplete(self):
        for mode,limit in [('hang',4096),('large',32),('diagnostic-limit',4096)]:
            result=self.reader(mode,max_output_bytes=limit)([CANARY],timeout=.15)
            self.assertEqual(result['outcome'],'incomplete')
            self.assertFalse(result['scan']['complete'])
            self.assertTrue(result['client_group_absent'])
        self.assert_private()

    def test_private_client_diagnostics_are_not_application_logs(self):
        result=self.reader('diagnostics')([CANARY],timeout=1)
        self.assertEqual(result['outcome'],'observed_clean')
        self.assertGreater(result['stderr_bytes'],0)
        self.assertEqual(result['stdout_bytes'],0)
        self.assert_private()

    def test_precondition_failure_starts_no_client(self):
        self.allow=False
        result=self.reader('leak')([CANARY],timeout=1)
        self.assertEqual(result['outcome'],'incomplete')
        self.assertNotIn('client_group',result)
        self.assert_private()

    def test_changed_source_after_read_cannot_establish_absence(self):
        def check(source,reserve):return reserve!=5
        reader=LogTransport(self.attempt,[sys.executable,'-c',CLIENT,'flags'],SOURCE,check=check,cwd=self.root)
        result=reader([CANARY],timeout=1)
        self.assertEqual(result['outcome'],'incomplete')
        self.assertFalse(result['source_verified_after'])
        self.assertTrue(result['client_group_absent'])

    def test_post_read_identity_loss_retains_observed_leak(self):
        def check(source,reserve):return reserve!=5
        reader=LogTransport(self.attempt,[sys.executable,'-c',CLIENT,'leak'],SOURCE,check=check,cwd=self.root)
        result=reader([CANARY],timeout=1)
        self.assertEqual(result['outcome'],'incomplete')
        self.assertTrue(result['scan']['canary_present'])
        self.assertFalse(result['source_verified_after'])

    def test_bad_sources_prefixes_controls_and_timeouts_refused(self):
        for change in (dict(namespace='bad;command'),dict(pod_name='--other'),dict(container_name='bad/other'),
                       dict(pod_uid=''),dict(container_id=None),dict(previous=1),dict(extra='secret')):
            selected=dict(SOURCE,**change)
            with self.assertRaises(ValueError):LogTransport(self.attempt,['kubectl'],selected,check=self.check,cwd=self.root)
        for prefix in ([],[''],['x\x00']):
            with self.assertRaises(ValueError):LogTransport(self.attempt,prefix,SOURCE,check=self.check,cwd=self.root)
        reader=self.reader('leak')
        for controls,timeout in [([],1),([CANARY],True),([CANARY],0),([CANARY],31)]:
            with self.assertRaises(ValueError):reader(controls,timeout=timeout)
        self.assertEqual(self.calls,[])


if __name__=='__main__':unittest.main()
