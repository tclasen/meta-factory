"""Concrete context ownership/order with synthetic workload/service observations."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from evaluation.fault_broker import remote_fault
from evaluation.fault_runtime import FaultRuntime
from evaluation.faults import FaultRestoreError, FaultSetupError
from evaluation.staging_broker import remote_staging
from evaluation.staging_runtime import StagingRuntime


class StagingRuntimeTest(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name)
        self.box=SimpleNamespace(name='test-grader',stopped=False,exec_argv=lambda argv:argv)
        self.guard=SimpleNamespace(directory=self.root,process=SimpleNamespace(poll=lambda:None))
        self.now=[0,0];self.events=[];self.fail=None
        self.resources={role:dict(namespace='incident-app',kind='deployment',name=role,uid=role+'-uid')
                        for role in ('api','worker','storage')}
        self.states={role:dict(resource,replicas=1,generation=1,observed_generation=1,
                               pods=[dict(ready=True,terminating=False)]) for role,resource in self.resources.items()}

    def operation(self,attempt,transport,**kwargs):
        transport.exec_argv(['trusted-probe'])
        role=kwargs['name'];state=self.states[role]
        if kwargs['replicas'] is not None:
            replicas=kwargs['replicas']
            self.events.append((role,replicas))
            if self.fail=='storage-suspend' and role=='storage' and replicas==0:
                state['replicas']=0;state['pods']=[]
                return {'outcome':'incomplete'}
            if self.fail=='worker-restore' and role=='worker' and replicas==1:
                return {'outcome':'incomplete'}
            state['replicas']=replicas;state['pods']=[] if replicas==0 else [dict(ready=True,terminating=False)]
        return {'outcome':'workload_observed' if kwargs['expected'] is None else 'workload_scaled',
                'observation':{'workload':copy.deepcopy(state)}}

    def service(self,attempt,transport,*,label,configuration,mode):
        role=configuration['role'];replicas=self.states[role]['replicas']
        expected='unavailable' if replicas==0 else 'available'
        self.events.append(('service',role,mode))
        if self.fail=='storage-outage' and role=='storage' and mode=='unavailable':
            return {'outcome':'incomplete'}
        return {'outcome':'service_'+mode+'_verified' if mode==expected else 'incomplete'}

    def runtime(self):
        faults=FaultRuntime(self.root/'faults',self.box,self.guard,self.resources,['kubectl'],
            monotonic_deadline=6000,wall_deadline=6000,monotonic=lambda:self.now[0],wall=lambda:self.now[1],
            operation=self.operation,service_probes={role:{'role':role} for role in ('api','storage')},
            service_runner=self.service,storage_worker_restart=True)
        self.addCleanup(faults.close)
        staging=StagingRuntime(self.root/'staging',faults);self.addCleanup(staging.close)
        return staging,faults

    def test_handoff_blocks_storage_before_worker_release_and_restarts_under_hold(self):
        staging,faults=self.runtime()
        with remote_staging(staging.broker.configuration) as session:
            self.assertEqual(self.states['worker']['replicas'],0)
            self.assertEqual(self.states['storage']['replicas'],1)
            self.assertTrue(session.verify()['api_available_verified'])
            session.handoff()
            self.assertEqual(self.states['storage']['replicas'],0)
            self.assertEqual(self.states['worker']['replicas'],1)
            session.restart_worker()
            self.assertTrue(session.verify()['storage_outage_verified'])
        self.assertEqual(self.states['worker']['replicas'],1)
        self.assertEqual(self.states['storage']['replicas'],1)
        changes=[event for event in self.events if len(event)==2]
        self.assertEqual(changes,[('worker',0),('storage',0),('worker',1),('worker',0),('worker',1),('storage',1)])
        self.assertEqual(faults.held_workloads,{})
        result=next(staging.directory.glob('stage-*/result.json'))
        self.assertEqual(json.loads(result.read_text())['outcome'],'staging_restored')

    def test_body_failure_restores_the_correct_owned_stack_in_each_phase(self):
        staging,_=self.runtime()
        for handoff in (False,True):
            with self.subTest(handoff=handoff),self.assertRaisesRegex(AssertionError,'application defect'):
                with remote_staging(staging.broker.configuration) as session:
                    if handoff:session.handoff()
                    raise AssertionError('application defect')
            self.assertEqual(self.states['worker']['replicas'],1)
            self.assertEqual(self.states['storage']['replicas'],1)
            self.assertFalse(staging.broker.aborted)

    def test_partial_storage_handoff_restores_storage_before_worker(self):
        for failure in ('storage-suspend','storage-outage'):
            with self.subTest(failure=failure):
                # A fresh fixture for each fatal broker failure.
                self.fail=failure
                if (self.root/'faults').exists():
                    (self.root/'faults').rename(self.root/('old-faults-'+failure))
                    (self.root/'staging').rename(self.root/('old-staging-'+failure))
                staging,_=self.runtime()
                with self.assertRaises(FaultRestoreError):
                    with remote_staging(staging.broker.configuration) as session:session.handoff()
                self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
                self.assertEqual(self.states['worker']['replicas'],1)
                self.assertEqual(self.states['storage']['replicas'],1)
                changes=[event for event in self.events if len(event)==2]
                self.assertEqual(changes[-2:],[('storage',1),('worker',1)])

    def test_worker_restore_failure_still_restores_storage_and_aborts(self):
        staging,_=self.runtime();self.fail='worker-restore'
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:session.handoff()
        self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
        self.assertEqual(self.states['storage']['replicas'],1)
        self.assertEqual(self.states['worker']['replicas'],0)

    def test_changed_hold_or_workload_identity_is_not_repaired_or_accepted(self):
        staging,_=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:
                session.handoff();self.states['worker']['uid']='replaced-uid';session.verify()
        self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
        self.assertEqual(self.states['storage']['replicas'],1)
        self.assertEqual(self.states['worker']['uid'],'replaced-uid')

    def test_each_clock_and_guard_loss_refuse_new_staging_without_mutation(self):
        modes=('monotonic','wall','guard','release','stopped','owner')
        for index,mode in enumerate(modes):
            with self.subTest(mode=mode):
                if index:
                    (self.root/'faults').rename(self.root/('old-faults-'+mode))
                    (self.root/'staging').rename(self.root/('old-staging-'+mode))
                staging,faults=self.runtime()
                if mode=='monotonic':self.now[0]=1600
                elif mode=='wall':self.now[1]=1600
                elif mode=='guard':self.guard.process.poll=lambda:0
                elif mode=='release':(self.root/'release.json').touch()
                elif mode=='stopped':self.box.stopped=True
                elif mode=='owner':faults.owner_pid=-1
                with self.assertRaises(FaultSetupError):
                    with remote_staging(staging.broker.configuration):pass
                self.now[:]=[0,0];self.guard.process.poll=lambda:None;self.box.stopped=False
                (self.root/'release.json').unlink(missing_ok=True)
                self.assertEqual([event for event in self.events if len(event)==2],[])

    def test_close_revokes_new_actions_but_existing_owned_context_restores(self):
        import socket
        from evaluation.fault_broker import send,receive
        staging,_=self.runtime()
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
            connection.connect(str(staging.broker.path))
            with connection.makefile('rwb') as stream:
                send(stream,dict(token=staging.broker.token,operation='stage'))
                self.assertEqual(receive(stream)['status'],'worker_held')
                staging.close()
        self.assertEqual(self.states['worker']['replicas'],1)

    def test_another_broker_cannot_mutate_during_owned_staging(self):
        staging,faults=self.runtime()
        with remote_staging(staging.broker.configuration):
            with self.assertRaises(FaultSetupError):
                with remote_fault(faults.broker.configuration,'api'):pass
            self.assertEqual(self.states['api']['replicas'],1)
            self.assertEqual(self.states['worker']['replicas'],0)
        self.assertEqual(self.states['worker']['replicas'],1)

    def test_alias_bindings_are_refused_before_staging_endpoint(self):
        staging,faults=self.runtime();staging.close()
        faults.workloads['api']=copy.deepcopy(faults.workloads['worker'])
        with self.assertRaises(ValueError):StagingRuntime(self.root/'invalid',faults)
        self.assertFalse((self.root/'invalid').exists())

    def test_changed_parent_binding_is_refused_without_following_new_identity(self):
        staging,faults=self.runtime()
        faults.workloads['worker']['uid']='new-operator-binding'
        with self.assertRaises(FaultSetupError):
            with remote_staging(staging.broker.configuration):pass
        self.assertEqual(self.events,[])
        self.assertEqual(self.states['worker']['replicas'],1)

    def test_expired_guard_during_hold_reports_uncertain_restoration(self):
        staging,_=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:
                self.guard.process.poll=lambda:0
                session.verify()
        self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
        # Commands are forbidden after guard death; only outer sandbox termination
        # can resolve this deliberately unknown resource state.
        self.assertEqual(self.states['worker']['replicas'],0)

    def test_insufficient_initial_reserve_creates_no_staging_endpoint(self):
        staging,faults=self.runtime();staging.close()
        self.now[1]=1600
        with self.assertRaises(FaultSetupError):StagingRuntime(self.root/'insufficient',faults)
        self.assertFalse((self.root/'insufficient').exists())

    def test_restart_window_excludes_later_storage_verification_time(self):
        original_operation=self.operation;original_service=self.service
        restarting=[False]
        def timed_operation(*args,**kwargs):
            result=original_operation(*args,**kwargs)
            if restarting[0] and kwargs['name']=='worker' and kwargs['replicas'] is not None:
                self.now[0]=10 if kwargs['replicas']==0 else 20
            return result
        def timed_service(*args,**kwargs):
            result=original_service(*args,**kwargs)
            if restarting[0] and kwargs['label']=='held-service-after':self.now[0]=100
            return result
        self.operation=timed_operation;self.service=timed_service
        staging,_=self.runtime()
        with remote_staging(staging.broker.configuration) as session:
            session.handoff();restarting[0]=True
            observation=session.restart_worker()
            self.assertEqual(observation['restart_window'],{'earliest':0.0,'latest':20.0})
            self.assertEqual(self.now[0],100)
