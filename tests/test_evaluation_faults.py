"""Uncertain fault cleanup cannot contaminate later acceptance observations."""

import copy
import json
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.faults import FaultRestoreError, FaultSetupError, suspended_workload


class FaultTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.attempt = Attempt(Path(self.temp.name) / 'attempt', {})
        self.addCleanup(self.attempt.close)
        self.state = {'namespace': 'incident-app', 'kind': 'deployment', 'name': 'worker',
                      'uid': 'worker-uid', 'replicas': 1, 'generation': 1, 'observed_generation': 1,
                      'pods': [{'name': 'worker-pod', 'ready': True, 'terminating': False}]}
        self.calls = []; self.mode = 'good'

    def operation(self, attempt, sandbox, **kwargs):
        phase = kwargs['label'].removeprefix('test-'); self.calls.append(phase)
        if phase == 'before-restore':
            if self.mode == 'replacement': self.state['uid'] = 'new-workload'
            if self.mode == 'concurrent-scale': self.state['replicas'] = 3
        if kwargs['expected'] is not None:
            if phase == 'restore' and self.mode == 'restore-fails':
                return {'outcome': 'workload_operation_incomplete'}
            self.state['replicas'] = kwargs['replicas']
            self.state['pods'] = [] if kwargs['replicas'] == 0 else [{'name': 'new-pod', 'ready': True, 'terminating': False}]
            if phase == 'suspend' and self.mode == 'failed-after-mutation':
                return {'outcome': 'workload_operation_incomplete'}
        return {'outcome': 'workload_observed' if kwargs['expected'] is None else 'workload_scaled',
                'observation': {'workload': copy.deepcopy(self.state)}}

    def fault(self):
        return suspended_workload(self.attempt, object(), label='test', kubectl_prefix=['kubectl'],
                                  namespace='incident-app', kind='deployment', name='worker', operation=self.operation)

    def result(self):
        return json.loads((self.attempt.directory / 'test-result.json').read_text())

    def test_normal_body_and_assertion_restore_original_replicas(self):
        with self.assertRaisesRegex(AssertionError, 'application failure'):
            with self.fault():
                self.assertEqual(self.state['replicas'], 0)
                self.assertTrue((self.attempt.directory / 'test-restoration-plan.json').is_file())
                raise AssertionError('application failure')
        self.assertEqual(self.state['replicas'], 1)
        self.assertTrue(self.result()['restoration_verified'])
        self.assertEqual(self.result()['body_error_type'], 'AssertionError')

    def test_successful_context_restores(self):
        with self.fault(): self.assertEqual(self.state['pods'], [])
        self.assertTrue(self.result()['fault_established'])
        self.assertTrue(self.result()['restoration_verified'])

    def test_failed_suspend_can_have_mutated_and_is_restored(self):
        self.mode = 'failed-after-mutation'
        with self.assertRaises(FaultSetupError):
            with self.fault(): self.fail('Unverified fault body ran')
        self.assertEqual(self.state['replicas'], 1)
        self.assertTrue(self.result()['restoration_verified'])

    def test_interruption_executes_restoration(self):
        with self.assertRaises(KeyboardInterrupt):
            with self.fault(): raise KeyboardInterrupt
        self.assertTrue(self.result()['restoration_verified'])

    def test_replaced_or_independently_scaled_workload_is_not_overwritten(self):
        self.mode = 'replacement'
        with self.assertRaises(FaultRestoreError):
            with self.fault(): pass
        self.assertNotIn('restore', self.calls)
        self.assertFalse(self.result()['restoration_verified'])

    def test_concurrent_scale_refuses_restoration(self):
        self.mode = 'concurrent-scale'
        with self.assertRaises(FaultRestoreError):
            with self.fault(): pass
        self.assertNotIn('restore', self.calls)
        self.assertEqual(self.state['replicas'], 3)

    def test_restoration_failure_overrides_body_assertion_without_losing_evidence(self):
        self.mode = 'restore-fails'
        with self.assertRaises(FaultRestoreError):
            with self.fault(): raise AssertionError('original assertion')
        self.assertEqual(self.result()['body_error_type'], 'AssertionError')
        self.assertFalse(self.result()['restoration_verified'])

    def test_unready_baseline_does_not_mutate(self):
        self.state['pods'][0]['ready'] = False
        with self.assertRaises(FaultSetupError):
            with self.fault(): self.fail('Unready body ran')
        self.assertEqual(self.calls, ['baseline'])
