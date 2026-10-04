"""Fault lifetime must end before sandbox cleanup and never follow new identities."""

import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

from evaluation.fault_broker import remote_fault
from evaluation.fault_runtime import FaultRuntime
from evaluation.faults import FaultSetupError


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
                          pods=[{'ready': True, 'terminating': False}])
        self.called = []

    def operation(self, attempt, transport, **kwargs):
        transport.exec_argv(['trusted-probe'])
        self.called.append(kwargs['label'])
        if kwargs['replicas'] is not None:
            self.state['replicas'] = kwargs['replicas']
            self.state['pods'] = [] if kwargs['replicas'] == 0 else [{'ready': True, 'terminating': False}]
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
        with remote_fault(runtime.broker.configuration, 'storage'):
            self.assertEqual(self.state['replicas'], 0)
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
