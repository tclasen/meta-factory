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
                               pods=[dict(ready=True,running=True,terminating=False)]) for role,resource in self.resources.items()}

    def operation(self,attempt,transport,**kwargs):
        transport.exec_argv(['trusted-probe'])
        role=kwargs['name'];state=self.states[role]
        if kwargs['replicas'] is not None:
            replicas=kwargs['replicas']
            if state['replicas'] != replicas:self.events.append((role,replicas))
            if self.fail=='storage-suspend' and role=='storage' and replicas==0:
                state['replicas']=0;state['pods']=[]
                return {'outcome':'incomplete'}
            if self.fail=='worker-restore' and role=='worker' and replicas==1:
                return {'outcome':'incomplete'}
            state['replicas']=replicas;state['pods']=[] if replicas==0 else [dict(ready=True,running=True,terminating=False)]
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

    def bound_jobs(self,faults,reader):
        from evaluation.job_runtime import JobRuntime
        jobs=JobRuntime(self.root/'jobs',self.box,self.guard,database_read=reader,
            artifact_count=lambda *args,**kwargs:0,database_peer_check=lambda **kwargs:None,
            storage_peer_check=lambda **kwargs:None,monotonic_deadline=6000,wall_deadline=6000,
            monotonic=lambda:self.now[0],wall=lambda:self.now[1])
        self.addCleanup(jobs.close)
        return jobs

    def test_worker_dependency_readiness_can_fail_only_during_owned_storage_hold(self):
        base=self.operation
        def operation(attempt,transport,**kwargs):
            report=base(attempt,transport,**kwargs)
            if kwargs['name']=='worker' and self.states['storage']['replicas']==0:
                for pod in report['observation']['workload']['pods']:pod['ready']=False
                if kwargs['replicas']==1:self.assertEqual(kwargs.get('convergence'),'running')
            return report
        self.operation=operation
        staging,faults=self.runtime()
        with remote_staging(staging.broker.configuration) as session:
            session.handoff();session.verify();session.restart_worker()
        results=[json.loads(p.read_text()) for p in faults.directory.glob('fault-*/workload-result.json')]
        self.assertIn('running',[r['restore_convergence'] for r in results])
        self.assertEqual(self.states['storage']['replicas'],1)
        self.assertTrue(any(json.loads(p.read_text())['outcome']=='staging_restored' for p in staging.directory.glob('stage-*/result.json')))

    def test_waiting_worker_never_counts_as_running_under_storage_hold(self):
        base=self.operation
        def operation(attempt,transport,**kwargs):
            report=base(attempt,transport,**kwargs)
            if kwargs['name']=='worker' and self.states['storage']['replicas']==0:
                for pod in report['observation']['workload']['pods']:pod['running']=False
            return report
        self.operation=operation
        staging,_=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:session.handoff()
        self.assertTrue(staging.broker.wait_idle(2))
        self.assertEqual(self.states['storage']['replicas'],1)

    def test_worker_must_regain_readiness_after_storage_restoration(self):
        base=self.operation
        def operation(attempt,transport,**kwargs):
            report=base(attempt,transport,**kwargs)
            if kwargs['label']=='worker-ready-after-storage':
                report['observation']['workload']['pods'][0]['ready']=False
            return report
        self.operation=operation
        staging,_=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:session.handoff()
        self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
        self.assertEqual(self.states['storage']['replicas'],1)

    def test_requested_job_is_observed_after_worker_zero_before_restore(self):
        import uuid
        identity=str(uuid.uuid4());staging,faults=self.runtime();staging.close()
        def read(export_id,*,timeout):
            self.assertEqual(export_id,identity);self.assertEqual(timeout,15)
            self.assertEqual(self.states['worker']['replicas'],0)
            self.assertEqual(self.states['storage']['replicas'],0)
            self.events.append(('paused-read',export_id))
            return dict(export_id=export_id,status='running',processing_attempts=2,active_lease=True,
                        lease_fingerprint='b'*64,completion_events=0,password='private',published_artifacts=999)
        jobs=self.bound_jobs(faults,read)
        staging=StagingRuntime(self.root/'observed-staging',faults,job_runtime=jobs);self.addCleanup(staging.close)
        with remote_staging(staging.broker.configuration) as session:
            session.handoff();value=session.restart_worker(identity)
            self.assertEqual(value['paused_job']['lease_fingerprint'],'b'*64)
            self.assertNotIn('password',value['paused_job']);self.assertNotIn('published_artifacts',value['paused_job'])
        changes=[event for event in self.events if len(event)==2]
        index=changes.index(('paused-read',identity))
        self.assertEqual(changes[index-1],('worker',0));self.assertEqual(changes[index+1],('worker',1))

    def test_paused_reader_failure_still_restores_worker_and_storage(self):
        import uuid
        staging,faults=self.runtime();staging.close()
        def read(*args,**kwargs):raise RuntimeError('private-database-credential')
        jobs=self.bound_jobs(faults,read)
        staging=StagingRuntime(self.root/'broken-read-staging',faults,job_runtime=jobs);self.addCleanup(staging.close)
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:
                session.handoff();session.restart_worker(str(uuid.uuid4()))
        self.assertTrue(staging.broker.wait_idle(2))
        self.assertEqual(self.states['worker']['replicas'],1);self.assertEqual(self.states['storage']['replicas'],1)
        for path in jobs.directory.rglob('*.json'):
            self.assertNotIn('private-database-credential',path.read_text())

    def test_foreign_outer_job_guard_is_rejected_before_endpoint_creation(self):
        staging,faults=self.runtime();staging.close()
        jobs=self.bound_jobs(faults,lambda *args,**kwargs:{})
        jobs.guard=SimpleNamespace(directory=self.root,process=SimpleNamespace(poll=lambda:None))
        with self.assertRaises(ValueError):StagingRuntime(self.root/'foreign-staging',faults,job_runtime=jobs)
        self.assertFalse((self.root/'foreign-staging').exists())

    def test_worker_spec_change_during_paused_read_never_yields_an_interruption_receipt(self):
        import uuid
        staging,faults=self.runtime();staging.close()
        def read(export_id,*,timeout):
            self.states['worker']['generation']+=2
            self.states['worker']['observed_generation']=self.states['worker']['generation']
            return dict(export_id=export_id,status='running',processing_attempts=1,active_lease=True,
                        lease_fingerprint='a'*64,completion_events=0)
        jobs=self.bound_jobs(faults,read)
        staging=StagingRuntime(self.root/'changed-hold-staging',faults,job_runtime=jobs);self.addCleanup(staging.close)
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:
                session.handoff();session.restart_worker(str(uuid.uuid4()))
        self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
        self.assertEqual(self.states['worker']['replicas'],1);self.assertEqual(self.states['storage']['replicas'],1)

    def test_competing_fault_is_refused_until_post_storage_readiness_finishes(self):
        base=self.operation;holder={};checked=[]
        def operation(attempt,transport,**kwargs):
            if kwargs['label']=='worker-ready-after-storage':
                with self.assertRaises(FaultSetupError):
                    with remote_fault(holder['faults'].broker.configuration,'api'):pass
                checked.append(True)
            return base(attempt,transport,**kwargs)
        self.operation=operation
        staging,faults=self.runtime();holder['faults']=faults
        with remote_staging(staging.broker.configuration) as session:session.handoff()
        self.assertEqual(checked,[True])

    def test_post_restore_observations_have_exclusive_command_directories(self):
        base=self.operation
        def operation(attempt,transport,**kwargs):
            (attempt.directory/kwargs['label']).mkdir()
            return base(attempt,transport,**kwargs)
        self.operation=operation
        staging,_=self.runtime()
        with remote_staging(staging.broker.configuration) as session:
            session.handoff();session.restart_worker()
        self.assertFalse(staging.broker.aborted)

    def test_parent_running_clock_uses_fresh_api_worker_process_identities(self):
        base=self.operation
        def operation(attempt,transport,**kwargs):
            report=base(attempt,transport,**kwargs)
            role=kwargs['name']
            for pod in report['observation']['workload']['pods']:
                pod.update(name=role+'-pod',uid=role+'-pod-uid',process_fingerprint='a'*64)
                if self.states['storage']['replicas']==0:pod['ready']=False
            return report
        self.operation=operation
        staging,_=self.runtime()
        with remote_staging(staging.broker.configuration) as session:
            session.handoff()
            self.assertEqual(session.observe_running(),{'minimum':0,'maximum':0})
            self.now[:]=[10,10]
            self.assertEqual(session.observe_running(),{'minimum':10,'maximum':10})
            with self.assertRaises(FaultSetupError):session.restart_worker()
        self.assertFalse(staging.broker.aborted)

    def test_missing_continuity_metadata_aborts_timing_and_restores(self):
        staging,_=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:
                session.handoff();session.observe_running()
        self.assertTrue(staging.broker.wait_idle(2));self.assertTrue(staging.broker.aborted)
        self.assertEqual(self.states['storage']['replicas'],1)

    def test_storage_generation_change_during_timing_suppresses_receipt(self):
        base=self.operation;changed=[]
        def operation(attempt,transport,**kwargs):
            report=base(attempt,transport,**kwargs)
            role=kwargs['name']
            for pod in report['observation']['workload']['pods']:
                pod.update(name=role+'-pod',uid=role+'-pod-uid',process_fingerprint='a'*64)
            if attempt.directory.name.startswith('running-') and role=='worker' and not changed:
                self.states['storage']['generation']+=1
                self.states['storage']['observed_generation']+=1
                changed.append(True)
            return report
        self.operation=operation
        staging,_=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_staging(staging.broker.configuration) as session:
                session.handoff();session.observe_running()
        self.assertEqual(changed,[True]);self.assertTrue(staging.broker.wait_idle(2))
        self.assertTrue(staging.broker.aborted)
