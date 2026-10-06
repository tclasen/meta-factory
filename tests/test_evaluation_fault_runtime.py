"""Fault lifetime must end before sandbox cleanup and never follow new identities."""

import copy
import json
from pathlib import Path
import re
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from evaluation.fault_broker import remote_fault
from evaluation.fault_runtime import FaultRuntime
from evaluation.faults import FaultSetupError, FaultRestoreError


class FaultRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.commands = []
        self.box = SimpleNamespace(name='factory-eval-grader-0123456789abcdef', stopped=False,
                                   exec_argv=lambda argv: self.commands.append(argv) or ['sbx', 'exec', 'exact', *argv])
        self.guard_status = None
        self.guard = SimpleNamespace(directory=self.root,
                    process=SimpleNamespace(poll=lambda: self.guard_status))
        self.clock = 0; self.wall = 0
        self.resource = {'namespace': 'incident-app', 'kind': 'statefulset', 'name': 'storage', 'uid': 'storage-uid'}
        self.state = dict(self.resource, replicas=1, generation=1, observed_generation=1,
                          pods=[{'ready': True, 'running': True, 'terminating': False}])
        self.called = []

    def operation(self, attempt, transport, **kwargs):
        transport.exec_argv(['trusted-probe'])
        self.called.append(kwargs['label'])
        if kwargs['replicas'] is not None:
            self.state['replicas'] = kwargs['replicas']
            self.state['pods'] = [] if kwargs['replicas'] == 0 else [{'ready': True, 'running': True, 'terminating': False}]
        return {'outcome': 'workload_observed' if kwargs['expected'] is None else 'workload_scaled',
                'observation': {'workload': copy.deepcopy(self.state)}}

    def runtime(self, **kwargs):
        runtime = FaultRuntime(self.root / 'faults', self.box, self.guard, {'storage': self.resource},
                               ['kubectl'], monotonic_deadline=1000, wall_deadline=1000,
                               monotonic=lambda: self.clock, wall=lambda: self.wall, operation=self.operation, **kwargs)
        self.addCleanup(runtime.close)
        return runtime

    def test_scoped_context_uses_separate_evidence_and_restores(self):
        runtime = self.runtime()
        with remote_fault(runtime.broker.configuration, 'storage') as observations:
            self.assertEqual(self.state['replicas'], 0)
            self.assertEqual(observations, {'service_outage_verified': False,
                                            'workload_suspended_verified': True})
        self.assertTrue(runtime.broker.wait_idle(2))
        self.assertEqual(self.state['replicas'], 1)
        self.assertEqual(len(list((self.root / 'faults').glob('fault-*/result.json'))), 1)
        self.assertEqual(len(self.called), 4)

    def test_insufficient_total_budget_refuses_new_fault(self):
        runtime = self.runtime(); self.clock = 400
        with self.assertRaises(FaultSetupError):
            with remote_fault(runtime.broker.configuration, 'storage'): pass
        self.assertEqual(self.commands, [])

    def test_command_reserve_checked_again_for_both_clocks(self):
        runtime = self.runtime()
        for clock, wall in [(851, 0), (0, 851)]:
            self.clock, self.wall = clock, wall
            with self.assertRaises(FaultSetupError): runtime.exec_argv(['probe'])
        self.assertEqual(self.commands, [])

    def test_guard_exit_release_and_sandbox_stop_refuse_commands(self):
        runtime = self.runtime()
        self.guard_status = 0
        with self.assertRaises(FaultSetupError): runtime.exec_argv(['probe'])
        self.guard_status = None
        (self.root / 'release.json').write_text('{}')
        with self.assertRaises(FaultSetupError): runtime.exec_argv(['probe'])
        (self.root / 'release.json').unlink(); self.box.stopped = True
        with self.assertRaises(FaultSetupError): runtime.exec_argv(['probe'])
        self.assertEqual(self.commands, [])

    def test_revocation_refuses_subsequent_commands(self):
        runtime = self.runtime(); runtime.revoked.set()
        with self.assertRaises(FaultSetupError): runtime.exec_argv(['probe'])
        self.assertEqual(self.commands, [])

    def test_replaced_operator_identity_never_reaches_suspension(self):
        runtime = self.runtime(); self.state['uid'] = 'replaced'
        with self.assertRaises(FaultSetupError):
            with remote_fault(runtime.broker.configuration, 'storage'): pass
        self.assertEqual(self.called, ['workload-baseline'])
        self.assertEqual(self.state['replicas'], 1)

    def test_service_evidence_requires_all_three_phases(self):
        phases = []
        def probe(attempt, transport, *, label, configuration, mode):
            phases.append((label, mode))
            return {'outcome': 'service_' + mode + '_verified'}
        runtime = self.runtime(service_probes={'storage': {}}, service_runner=probe)
        with remote_fault(runtime.broker.configuration, 'storage') as observed:
            self.assertTrue(observed['service_outage_verified'])
        self.assertEqual(phases, [('service-baseline', 'available'), ('service-outage', 'unavailable'), ('service-recovery', 'available')])

    def test_unverified_outage_is_restored_and_never_forwarded(self):
        def probe(attempt, transport, *, label, configuration, mode):
            return {'outcome': 'service_available_verified' if mode == 'available' else 'service_probe_incomplete'}
        runtime = self.runtime(service_probes={'storage': {}}, service_runner=probe)
        with self.assertRaises(FaultSetupError):
            with remote_fault(runtime.broker.configuration, 'storage'): self.fail('Unverified outage exposed')
        self.assertEqual(self.state['replicas'], 1)
        self.assertTrue(runtime.broker.aborted)

    def test_service_recovery_failure_aborts_after_workload_restoration(self):
        from evaluation.faults import FaultRestoreError
        def probe(attempt, transport, *, label, configuration, mode):
            return {'outcome': 'service_probe_incomplete' if label == 'service-recovery' else 'service_' + mode + '_verified'}
        runtime = self.runtime(service_probes={'storage': {}}, service_runner=probe)
        with self.assertRaises(FaultRestoreError):
            with remote_fault(runtime.broker.configuration, 'storage'): pass
        self.assertEqual(self.state['replicas'], 1)
        self.assertTrue(runtime.broker.aborted)

    def audit_options(self):
        self.audit_calls = []; self.audit_gate = None; self.peer_ok = True
        self.peer_checks = []
        def peer_check(allowance):
            self.peer_checks.append(allowance)
            if not self.peer_ok:raise FaultSetupError('Peer identity changed')
        return dict(audit_binding=dict(schema='public', table='events', table_oid=123,
            database_name='fixture', runtime_user='app', session_user='app',
            operator_user='migration', operator_session_user='migration',
            canary={'message':'private canary'}),
            database_peer={'prefix':['trusted-psql-peer'], 'services':{'runtime':'app','operator':'migration'}, 'cwd':self.root},
            database_peer_check=peer_check)

    def transport(self, attempt, prefix, services, *, check, cwd):
        self.assertEqual(prefix, ['trusted-psql-peer'])
        self.assertEqual(services, {'runtime':'app','operator':'migration'})
        self.assertEqual(cwd, self.root)
        def execute(identity, sql, *, timeout):
            check(20)
            self.audit_calls.append(identity)
            role = 'app' if identity == 'runtime' else 'migration'
            common = {'current_user':role,'session_user':role,'database_name':'fixture'}
            if 'ADD CONSTRAINT' in sql:
                self.audit_gate = re.search(r'factory_audit_fault_[0-9a-f]{32}', sql)[0]
                return {'outcome':'audit_gate_installed','table_oid':123,'constraint_oid':456,'constraint_name':self.audit_gate}
            if 'DROP CONSTRAINT' in sql:
                self.audit_gate = None
                return {'outcome':'audit_gate_removed','table_oid':123}
            if 'factory.audit_canary' in sql:
                if self.audit_gate:
                    return dict(common,outcome='insert_rejected',sqlstate='23514',constraint_name=self.audit_gate,schema='public',table='events')
                return dict(common,outcome='insert_executed',rows=1)
            return dict(common,relation_found=True,relation_oid=123,relation_kind='r')
        return execute

    def test_audit_and_workload_roles_share_private_broker_and_restore(self):
        options = self.audit_options()
        runtime = self.runtime(**options)
        # Caller changes cannot retarget an existing capability.
        options['audit_binding']['table'] = 'unrelated'
        options['database_peer']['prefix'] = ['untrusted']
        with patch('evaluation.fault_runtime.DatabaseTransport', side_effect=self.transport):
            with remote_fault(runtime.broker.configuration, 'audit') as observation:
                self.assertEqual(observation, {'service_outage_verified':False,'audit_insert_failure_verified':True,
                    'audit_constraint_canary':self.audit_gate})
                self.assertIsNotNone(self.audit_gate)
        self.assertIsNone(self.audit_gate)
        self.assertEqual(len(self.audit_calls), 8)
        self.assertEqual(self.called, [])
        with remote_fault(runtime.broker.configuration, 'storage'):pass
        reports = [json.loads(p.read_text()) for p in (self.root/'faults').glob('fault-*/result.json')]
        self.assertEqual([r['outcome'] for r in reports], ['fault_restored'] * 2)
        self.assertNotIn('private canary', (self.root/'faults/scope.json').read_text())

    def test_audit_peer_mismatch_prevents_database_commands(self):
        runtime = self.runtime(**self.audit_options()); self.peer_ok = False
        with patch('evaluation.fault_runtime.DatabaseTransport', side_effect=self.transport):
            with self.assertRaises(FaultSetupError):
                with remote_fault(runtime.broker.configuration, 'audit'):self.fail('Unverified peer exposed')
        self.assertEqual(self.audit_calls, [])

    def test_audit_guard_revocation_aborts_without_unbounded_restoration(self):
        runtime = self.runtime(**self.audit_options())
        with patch('evaluation.fault_runtime.DatabaseTransport', side_effect=self.transport):
            with self.assertRaises(FaultRestoreError):
                with remote_fault(runtime.broker.configuration, 'audit'):runtime.revoked.set()
        self.assertIsNotNone(self.audit_gate)
        self.assertTrue(runtime.broker.aborted)

    def test_peer_check_cannot_use_up_guard_reserve(self):
        options = self.audit_options()
        options['database_peer_check'] = lambda allowance: setattr(self, 'clock', 900)
        runtime = self.runtime(**options)
        with patch('evaluation.fault_runtime.DatabaseTransport', side_effect=self.transport):
            with self.assertRaises(FaultSetupError):
                with remote_fault(runtime.broker.configuration, 'audit'):pass
        self.assertEqual(self.audit_calls, [])

    def test_audit_only_runtime_uses_audit_reserve(self):
        runtime = FaultRuntime(self.root/'faults',self.box,self.guard,{},['kubectl'],
            monotonic_deadline=300,wall_deadline=300,monotonic=lambda:0,wall=lambda:0,**self.audit_options())
        self.addCleanup(runtime.close)
        with patch('evaluation.fault_runtime.DatabaseTransport', side_effect=self.transport):
            with remote_fault(runtime.broker.configuration, 'audit'):pass
        self.assertIsNone(self.audit_gate)

    def test_incomplete_or_ambiguous_database_configuration_refused(self):
        for options in ({'audit_binding':{}}, {'database_peer':{}}, {'database_peer_check':lambda _:None}):
            with self.subTest(options=list(options)), self.assertRaises(ValueError):self.runtime(**options)
        with self.assertRaises(ValueError):
            FaultRuntime(self.root/'faults',self.box,self.guard,{'audit':self.resource},['kubectl'],
                monotonic_deadline=1000,wall_deadline=1000,**self.audit_options())


class CompoundFaultRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.calls = []; self.services = []; self.variant = None
        self.clock = 0
        self.box = SimpleNamespace(name='factory-eval-grader-0123456789abcdef', stopped=False,
                                   exec_argv=lambda argv: argv)
        self.guard = SimpleNamespace(directory=self.root, process=SimpleNamespace(poll=lambda: None))
        self.resources = {role:dict(namespace='incident-app', kind='deployment', name=role, uid=role+'-uid')
                          for role in ('storage','worker')}
        self.states = {role:dict(resource, replicas=1, generation=1, observed_generation=1,
                                pods=[{'ready':True,'running':True,'terminating':False}])
                       for role,resource in self.resources.items()}

    def operation(self, attempt, transport, **kwargs):
        transport.exec_argv(['trusted-probe'])
        role=kwargs['name']; state=self.states[role]; label=kwargs['label']; self.calls.append((role,label))
        if role=='worker' and self.variant=='worker-replaced':state['uid']='different-uid'
        if role=='worker' and label=='workload-restore' and self.variant=='restore-fails':
            return {'outcome':'incomplete'}
        if kwargs['replicas'] is not None:
            state['replicas']=kwargs['replicas'];state['pods']=[] if kwargs['replicas']==0 else [{'ready':True,'running':True,'terminating':False}]
        if role=='worker' and label=='workload-restore' and self.variant=='hold-lost':
            self.states['storage']['replicas']=1
            self.states['storage']['pods']=[{'ready':True,'running':True,'terminating':False}]
        return {'outcome':'workload_observed' if kwargs['expected'] is None else 'workload_scaled',
                'observation':{'workload':copy.deepcopy(state)}}

    def service(self, attempt, transport, *, label, configuration, mode):
        self.services.append((label,mode))
        if self.variant=='service-restored' and label=='held-service-after':
            return {'outcome':'service_available_verified'}
        return {'outcome':'service_'+mode+'_verified'}

    def runtime(self, **kwargs):
        runtime=FaultRuntime(self.root/'faults',self.box,self.guard,self.resources,['kubectl'],
            monotonic_deadline=5000,wall_deadline=5000,monotonic=lambda:self.clock,wall=lambda:self.clock,
            operation=self.operation,service_probes={'storage':{}},service_runner=self.service,
            storage_worker_restart=True,**kwargs)
        self.addCleanup(runtime.close);return runtime

    def test_worker_restart_preserves_storage_hold_and_restores_both(self):
        from evaluation.fault_broker import remote_fault_session
        runtime=self.runtime()
        with remote_fault_session(runtime.broker.configuration,'storage') as session:
            self.assertEqual(self.states['storage']['replicas'],0)
            self.assertTrue(session.restart('worker')['held_fault_verified'])
            self.assertEqual(self.states['worker']['replicas'],1)
            self.assertEqual(self.states['storage']['replicas'],0)
        self.assertEqual(self.states['storage']['replicas'],1)
        self.assertFalse(runtime.held_workloads)
        self.assertEqual([name for name,mode in self.services if mode=='unavailable'],
                         ['service-outage','held-service-before','held-service-after'])

    def test_changed_worker_or_outer_hold_and_failed_restore_abort(self):
        from evaluation.fault_broker import remote_fault_session
        for variant in ('worker-replaced','hold-lost','restore-fails','service-restored'):
            with self.subTest(variant=variant):
                # Each lifecycle uses a separate exact runtime/evidence directory.
                self.variant=variant
                self.root=Path(self.temp.name)/variant;self.root.mkdir()
                runtime=self.runtime()
                with self.assertRaises(FaultRestoreError):
                    with remote_fault_session(runtime.broker.configuration,'storage') as session:
                        session.restart('worker')
                self.assertTrue(runtime.broker.wait_idle(2))
                self.assertTrue(runtime.broker.aborted)
                self.assertEqual(self.states['storage']['replicas'],1)
                self.assertFalse(runtime.held_workloads)
                self.states['worker']['uid']='worker-uid';self.states['worker']['replicas']=1
                self.states['worker']['pods']=[{'ready':True,'running':True,'terminating':False}]
                self.root=Path(self.temp.name)

    def test_insufficient_restart_reserve_prevents_worker_commands(self):
        from evaluation.fault_broker import remote_fault_session
        runtime=self.runtime()
        with self.assertRaises(FaultRestoreError):
            with remote_fault_session(runtime.broker.configuration,'storage') as session:
                self.clock=3500
                session.restart('worker')
        self.assertFalse(any(role=='worker' for role,label in self.calls))
        self.assertEqual(self.states['storage']['replicas'],1)

    def test_configuration_requires_storage_probe_and_distinct_identities(self):
        with self.assertRaises(ValueError):
            FaultRuntime(self.root/'invalid',self.box,self.guard,self.resources,['kubectl'],
                         monotonic_deadline=5000,wall_deadline=5000,
                         service_probes={},storage_worker_restart=True)
        self.resources['worker']['uid']='storage-uid'
        with self.assertRaises(ValueError):self.runtime()
