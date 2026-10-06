"""Private security observation requires owned peer/guard/deadline continuity."""
import base64
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evaluation.security_broker import SecurityObservationError,read_security
from evaluation.security_runtime import SecurityRuntime


CANARY='Private-runtime-canary-2026'
PASS=dict(verdict='pass',reason='verified',observations_checked=2)


class SecurityRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temporary=tempfile.TemporaryDirectory();self.addCleanup(self.temporary.cleanup)
        self.root=Path(self.temporary.name);self.guard_directory=self.root/'guard';self.guard_directory.mkdir()
        self.status=None;self.clock=10;self.calls=[];self.peers=[]
        self.box=SimpleNamespace(name='security-fixture',stopped=False)
        self.guard=SimpleNamespace(directory=self.guard_directory,process=SimpleNamespace(poll=lambda:self.status))

    def inspect(self,canaries,*,timeout):
        self.calls.append((canaries,timeout));return dict(PASS,raw_hash=CANARY,raw_logs=CANARY)

    def peer(self,operation,*,timeout):
        self.peers.append((operation,timeout));return True

    def runtime(self,**kwargs):
        values=dict(inspections={'password_storage':self.inspect,'log_canaries':self.inspect},peer_check=self.peer,
            monotonic_deadline=100,wall_deadline=100,monotonic=lambda:self.clock,wall=lambda:self.clock)
        values.update(kwargs)
        result=SecurityRuntime(self.root/('runtime-'+str(len(list(self.root.iterdir())))),self.box,self.guard,**values)
        self.addCleanup(result.close);return result

    def test_bounded_parent_inspection_and_sanitized_evidence(self):
        runtime=self.runtime()
        self.assertEqual(read_security(runtime.broker.configuration,'log_canaries',canaries=[CANARY]),PASS)
        self.assertEqual(self.calls,[([CANARY],30)])
        self.assertEqual(self.peers,[('log_canaries',1),('log_canaries',1)])
        for path in runtime.directory.rglob('*'):
            if path.is_file():self.assertNotIn(CANARY.encode(),path.read_bytes())

    def test_binary_grant_delivers_bytes_and_sanitizes_parent_evidence(self):
        raw=b'PK\x03\x04\x00\xffprivate-binary-runtime'
        def reader(values,*,timeout):
            self.calls.append((values,timeout));return dict(PASS,raw_binary=raw)
        runtime=self.runtime(inspections={'log_binary_canaries':reader})
        self.assertEqual(read_security(runtime.broker.configuration,'log_binary_canaries',canaries=[raw]),PASS)
        self.assertEqual(self.calls,[([raw],30)])
        self.assertEqual(self.peers,[('log_binary_canaries',1),('log_binary_canaries',1)])
        for path in runtime.directory.rglob('*'):
            if path.is_file():
                for secret in (raw,base64.b64encode(raw),raw.hex().encode()):
                    self.assertNotIn(secret,path.read_bytes())

    def test_binary_requires_separate_grant(self):
        runtime=self.runtime()
        with self.assertRaises(SecurityObservationError):
            read_security(runtime.broker.configuration,'log_binary_canaries',canaries=[b'private-binary'])
        self.assertEqual(self.calls,[]);self.assertEqual(self.peers,[])

    def test_binary_lost_guard_suppresses_callback_receipt(self):
        def reader(values,*,timeout):
            self.status=0;return PASS
        runtime=self.runtime(inspections={'log_binary_canaries':reader})
        with self.assertRaises(SecurityObservationError):
            read_security(runtime.broker.configuration,'log_binary_canaries',canaries=[b'private-binary'])
        self.assertEqual(len(self.peers),1)

    def test_password_inspection_receives_no_worker_scope(self):
        runtime=self.runtime()
        self.assertEqual(read_security(runtime.broker.configuration,'password_storage'),PASS)
        self.assertEqual(self.calls,[(None,30)])

    def test_ungranted_operation_never_calls_reader_or_peer(self):
        runtime=self.runtime(inspections={'log_canaries':self.inspect})
        with self.assertRaises(SecurityObservationError):read_security(runtime.broker.configuration,'password_storage')
        self.assertEqual(self.calls,[]);self.assertEqual(self.peers,[])

    def test_changed_guard_sandbox_clock_owner_or_release_refuses_before_reader(self):
        for mode in ('guard','box','monotonic','wall','owner','release','result'):
            runtime=self.runtime()
            if mode=='guard':self.status=0
            if mode=='box':self.box.stopped=True
            if mode=='monotonic':runtime.monotonic=lambda:61
            if mode=='wall':runtime.wall=lambda:61
            if mode=='owner':runtime.owner_pid=-1
            if mode in ('release','result'):(self.guard_directory/(mode+'.json')).write_text('{}')
            with self.subTest(mode=mode),self.assertRaises(SecurityObservationError):
                read_security(runtime.broker.configuration,'password_storage')
            self.assertEqual(self.calls,[])
            runtime.close();self.status=None;self.box.stopped=False
            for path in self.guard_directory.iterdir():path.unlink()

    def test_bad_peer_refuses_before_reader(self):
        for value in (False,None,1):
            runtime=self.runtime(peer_check=lambda *args,**kwargs:value)
            with self.assertRaises(SecurityObservationError):read_security(runtime.broker.configuration,'password_storage')
            self.assertEqual(self.calls,[]);runtime.close()

    def test_peer_or_guard_loss_after_callback_suppresses_receipt(self):
        def reader(canaries,*,timeout):self.status=0;return PASS
        runtime=self.runtime(inspections={'password_storage':reader})
        with self.assertRaises(SecurityObservationError):read_security(runtime.broker.configuration,'password_storage')
        self.assertEqual(len(self.peers),1)

    def test_late_callback_cannot_extend_deadline(self):
        def reader(canaries,*,timeout):self.clock=96;return PASS
        runtime=self.runtime(inspections={'password_storage':reader})
        with self.assertRaises(SecurityObservationError):read_security(runtime.broker.configuration,'password_storage')
        self.assertEqual(runtime.monotonic_deadline,100);self.assertEqual(runtime.wall_deadline,100)

    def test_private_callback_exception_never_enters_evidence(self):
        def reader(*args,**kwargs):raise RuntimeError(CANARY)
        runtime=self.runtime(inspections={'password_storage':reader})
        with self.assertRaisesRegex(SecurityObservationError,'^Security inspection unavailable$'):
            read_security(runtime.broker.configuration,'password_storage')
        for path in runtime.directory.rglob('*'):
            if path.is_file():self.assertNotIn(CANARY.encode(),path.read_bytes())

    def test_close_revokes_inflight_observation_and_removes_socket(self):
        entered=threading.Event();release=threading.Event();results=[]
        def reader(*args,**kwargs):entered.set();release.wait(2);return PASS
        runtime=self.runtime(inspections={'password_storage':reader})
        def request():
            try:read_security(runtime.broker.configuration,'password_storage')
            except SecurityObservationError:results.append('unavailable')
        client=threading.Thread(target=request);client.start();self.assertTrue(entered.wait(1))
        closer=threading.Thread(target=runtime.close);closer.start();self.assertTrue(runtime.revoked.wait(1));release.set()
        closer.join(2);client.join(2)
        self.assertFalse(closer.is_alive());self.assertFalse(client.is_alive());self.assertEqual(results,['unavailable'])
        self.assertFalse(runtime.broker.directory.exists())

    def test_deadline_and_guard_failures_refuse_constructor(self):
        for values in ({'monotonic_deadline':True},{'wall_deadline':float('nan')},{'monotonic_deadline':30},
                       {'inspections':{}},{'inspections':{'builder-command':self.inspect}},{'peer_check':None}):
            with self.assertRaises((ValueError,SecurityObservationError)):self.runtime(**values)
        self.status=0
        with self.assertRaises(SecurityObservationError):self.runtime()


if __name__=='__main__':unittest.main()
