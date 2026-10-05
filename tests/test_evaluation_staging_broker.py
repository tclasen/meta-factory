"""Real private sockets enforce staging order and restoration on client loss."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import unittest

from evaluation.fault_broker import send, receive
from evaluation.faults import FaultRestoreError, FaultSetupError
from evaluation.staging_broker import (StagingBroker, remote_staging, WORKER_RECEIPT,
                                       STORAGE_RECEIPT, RESTART_RECEIPT, StagingSession)


class StagingBrokerTest(unittest.TestCase):
    def setUp(self):
        self.events=[]; self.fail=None
        self.initial={field:True for field in WORKER_RECEIPT}
        self.handoff={field:True for field in STORAGE_RECEIPT}
        self.restart={field:True for field in RESTART_RECEIPT}

    @contextmanager
    def factory(self):
        self.events.append('worker-held')
        test=self
        class Handle:
            observations=dict(test.initial,secret='private')
            handed_off=False
            def verify(self):
                test.events.append('verify-hold')
                return test.handoff if self.handed_off else test.initial
            def handoff(self):
                self.handed_off=True
                test.events.extend(['storage-held','worker-restored'])
                if test.fail=='handoff':raise RuntimeError('private-detail')
                return dict(test.handoff,commands=['private'])
            def restart_worker(self):
                test.events.append('worker-restarted')
                return dict(test.restart,uid='private')
        try:yield Handle()
        finally:
            self.events.append('restore-all')
            if self.fail=='restore':raise FaultRestoreError('private-detail')

    def test_ordered_roundtrip_projects_only_fixed_receipts_and_cleans_endpoint(self):
        with StagingBroker(self.factory) as broker:
            self.assertEqual(os.stat(broker.path).st_mode&0o777,0o600)
            with remote_staging(broker.configuration) as session:
                self.assertEqual(session.observations,self.initial)
                self.assertEqual(session.handoff(),self.handoff)
                self.assertEqual(session.restart_worker(),self.restart)
            self.assertTrue(broker.wait_idle(2));self.assertFalse(broker.aborted)
        self.assertEqual(self.events,['worker-held','storage-held','worker-restored','worker-restarted','restore-all'])
        self.assertFalse(broker.path.exists())

    def test_body_failure_restores_in_both_phases(self):
        for handoff in (False,True):
            with self.subTest(handoff=handoff),StagingBroker(self.factory) as broker:
                with self.assertRaisesRegex(AssertionError,'application defect'):
                    with remote_staging(broker.configuration) as session:
                        if handoff:session.handoff()
                        raise AssertionError('application defect')
                self.assertEqual(self.events[-1],'restore-all')
                self.assertFalse(broker.aborted)

    def test_wrong_token_and_extra_commands_never_enter_factory(self):
        with StagingBroker(self.factory) as broker:
            for request in ({'token':'wrong','operation':'stage'},
                            {'token':broker.token,'operation':'stage','command':['sh']}):
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                    connection.connect(str(broker.path))
                    with connection.makefile('rwb') as stream:
                        send(stream,request);self.assertEqual(receive(stream),{'status':'refused'})
            self.assertEqual(self.events,[])

    def test_out_of_order_or_repeated_wire_actions_restore_and_abort(self):
        for operations in (['restart_worker'],['handoff','handoff'],['handoff','restart_worker','restart_worker'],['unknown']):
            with self.subTest(operations=operations),StagingBroker(self.factory) as broker:
                with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                    connection.connect(str(broker.path))
                    with connection.makefile('rwb') as stream:
                        send(stream,{'token':broker.token,'operation':'stage'})
                        self.assertEqual(receive(stream)['status'],'worker_held')
                        for operation in operations:
                            send(stream,{'operation':operation});response=receive(stream)
                        self.assertEqual(response,{'status':'inconclusive'})
                self.assertTrue(broker.wait_idle(2));self.assertTrue(broker.aborted)
                self.assertEqual(self.events[-1],'restore-all')

    def test_integer_or_missing_parent_receipts_are_fatal(self):
        for phase,field in (('initial','worker_suspended_verified'),('handoff','storage_outage_verified'),
                            ('restart','storage_hold_verified')):
            with self.subTest(phase=phase):
                original=getattr(self,phase)[field];getattr(self,phase)[field]=1
                with StagingBroker(self.factory) as broker:
                    with self.assertRaises((FaultRestoreError,FaultSetupError)):
                        with remote_staging(broker.configuration) as session:
                            session.handoff();session.restart_worker()
                    self.assertTrue(broker.wait_idle(2));self.assertTrue(broker.aborted)
                    self.assertEqual(self.events[-1],'restore-all')
                getattr(self,phase)[field]=original

    def test_partial_handoff_and_restore_failure_never_return_success(self):
        for phase in ('handoff','restore'):
            self.fail=phase
            with self.subTest(phase=phase),StagingBroker(self.factory) as broker:
                with self.assertRaises(FaultRestoreError):
                    with remote_staging(broker.configuration) as session:session.handoff()
                self.assertTrue(broker.wait_idle(2));self.assertTrue(broker.aborted)
                self.assertEqual(self.events[-1],'restore-all')

    def test_actual_child_death_restores_each_phase_and_refuses_reuse(self):
        for handoff in (False,True):
            with self.subTest(handoff=handoff),StagingBroker(self.factory) as broker:
                source=('import os,json,sys\nfrom evaluation.staging_broker import remote_staging\n'
                        'with remote_staging(json.loads(sys.argv[1])) as session:\n'
                        +('    session.handoff()\n' if handoff else '')+'    os._exit(7)\n')
                child=subprocess.run([sys.executable,'-c',source,json.dumps(broker.configuration)],
                                     cwd=Path(__file__).resolve().parents[1],capture_output=True,timeout=5)
                self.assertEqual(child.returncode,7)
                self.assertTrue(broker.wait_idle(2));self.assertTrue(broker.aborted)
                self.assertEqual(self.events[-1],'restore-all')
                with self.assertRaises(FaultRestoreError):
                    with remote_staging(broker.configuration):pass

    def test_idle_client_is_bounded_and_restored(self):
        with StagingBroker(self.factory,idle_seconds=.1) as broker:
            with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
                connection.connect(str(broker.path))
                with connection.makefile('rwb') as stream:
                    send(stream,{'token':broker.token,'operation':'stage'})
                    self.assertEqual(receive(stream)['status'],'worker_held')
                    self.assertTrue(broker.wait_idle(2))
            self.assertTrue(broker.aborted);self.assertEqual(self.events[-1],'restore-all')

    def test_client_rejects_extra_or_integer_receipts(self):
        from types import SimpleNamespace
        for value in ({**self.handoff,'extra':True},{**self.handoff,'worker_restored_verified':1}):
            data=json.dumps({'status':'storage_held','observations':value}).encode()+b'\n'
            stream=SimpleNamespace(write=lambda value:len(value),flush=lambda:None,readline=lambda limit:data)
            with self.assertRaises(FaultRestoreError):StagingSession(stream,self.initial).handoff()

    def test_current_hold_verification_uses_parent_phase_without_new_authority(self):
        with StagingBroker(self.factory) as broker:
            with remote_staging(broker.configuration) as session:
                self.assertEqual(session.verify(), self.initial)
                session.handoff()
                self.assertEqual(session.verify(), self.handoff)
                session.restart_worker()
                self.assertEqual(session.verify(), self.handoff)
            self.assertFalse(broker.aborted)
        self.assertEqual(self.events.count('verify-hold'), 3)

    def test_lost_verified_storage_hold_aborts_before_restart(self):
        with StagingBroker(self.factory) as broker:
            with self.assertRaises(FaultRestoreError):
                with remote_staging(broker.configuration) as session:
                    session.handoff()
                    self.handoff['storage_outage_verified'] = False
                    session.verify()
            self.assertTrue(broker.wait_idle(2));self.assertTrue(broker.aborted)
            self.assertNotIn('worker-restarted',self.events)
            self.assertEqual(self.events[-1],'restore-all')
