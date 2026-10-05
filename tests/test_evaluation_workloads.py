"""Faults must target exact owner chains, preserve secrets and reject stale writes."""

import copy
import json
import subprocess
import sys
import unittest

from evaluation.workload_probe import project, scale_patch, converged, pod_running


class WorkloadTest(unittest.TestCase):
    def setUp(self):
        self.workload = {'kind': 'Deployment', 'metadata': {'name': 'worker', 'namespace': 'incident-app',
                         'uid': 'deployment-uid', 'resourceVersion': '4', 'generation': 2},
                         'spec': {'replicas': 1, 'secret': 'must-not-log'},
                         'status': {'observedGeneration': 2}}
        self.rs = {'metadata': {'namespace': 'incident-app', 'uid': 'rs-uid',
                   'ownerReferences': [{'controller': True, 'kind': 'Deployment', 'uid': 'deployment-uid'}]}}
        self.pod = {'metadata': {'namespace': 'incident-app', 'name': 'worker-pod', 'uid': 'pod-uid',
                    'ownerReferences': [{'controller': True, 'kind': 'ReplicaSet', 'uid': 'rs-uid'}]},
                    'spec': {'secret': 'must-not-log'},
                    'status': {'conditions': [{'type': 'Ready', 'status': 'True'}]}}

    def snapshot(self):
        return project(self.workload, [self.rs], [self.pod], 'incident-app', 'deployment', 'worker')

    def test_exact_owner_chain_and_sanitized_projection(self):
        snapshot = self.snapshot()
        self.assertEqual(len(snapshot['pods']), 1)
        self.assertNotIn('must-not-log', json.dumps(snapshot))
        self.rs['metadata']['ownerReferences'][0]['uid'] = 'unrelated'
        self.assertEqual(self.snapshot()['pods'], [])

    def test_statefulset_direct_owner_and_terminating_pods(self):
        self.workload['kind'] = 'StatefulSet'
        self.pod['metadata']['ownerReferences'] = [{'controller': True, 'kind': 'StatefulSet', 'uid': 'deployment-uid'}]
        self.pod['metadata']['deletionTimestamp'] = '2026-01-01T00:00:00Z'
        snapshot = project(self.workload, [], [self.pod], 'incident-app', 'statefulset', 'worker')
        self.assertFalse(converged(snapshot, 'deployment-uid', 1))
        snapshot['replicas'] = 0
        self.assertFalse(converged(snapshot, 'deployment-uid', 0))
        snapshot['pods'] = []
        self.assertTrue(converged(snapshot, 'deployment-uid', 0))

    def test_conditional_patch_rejects_replacement_and_concurrent_scale(self):
        snapshot = self.snapshot()
        patch = scale_patch(snapshot, 'deployment-uid', 1, 0)
        self.assertEqual(patch[:3], [
            {'op': 'test', 'path': '/metadata/uid', 'value': 'deployment-uid'},
            {'op': 'test', 'path': '/metadata/resourceVersion', 'value': '4'},
            {'op': 'test', 'path': '/spec/replicas', 'value': 1}])
        for uid, replicas in [('replaced', 1), ('deployment-uid', 2)]:
            with self.assertRaises(ValueError): scale_patch(snapshot, uid, replicas, 0)
        with self.assertRaises(ValueError): scale_patch(snapshot, 'deployment-uid', 1, True)

    def test_readiness_requires_observed_generation_and_matching_target(self):
        snapshot = self.snapshot()
        self.assertTrue(converged(snapshot, 'deployment-uid', 1))
        snapshot['observed_generation'] = 1
        self.assertFalse(converged(snapshot, 'deployment-uid', 1))
        with self.assertRaises(ValueError): converged(snapshot, 'replacement', 1)
        with self.assertRaises(ValueError): converged(snapshot, 'deployment-uid', 0)

    def running_pod(self):
        self.pod['spec']['containers'] = [{'name': 'worker', 'env': ['must-not-log']}]
        self.pod['status'].update(phase='Running', conditions=[{'type': 'Ready', 'status': 'False'}],
            containerStatuses=[{'name': 'worker', 'state': {'running': {'startedAt': '2026-01-01T00:00:00Z'}}, 'ready': False}])

    def test_running_process_does_not_require_dependency_readiness(self):
        self.running_pod()
        snapshot = self.snapshot()
        self.assertFalse(converged(snapshot, 'deployment-uid', 1))
        self.assertTrue(converged(snapshot, 'deployment-uid', 1, convergence='running'))
        self.assertNotIn('must-not-log', json.dumps(snapshot))
        snapshot['observed_generation'] = 1
        self.assertFalse(converged(snapshot, 'deployment-uid', 1, convergence='running'))
        with self.assertRaises(ValueError): converged(snapshot, 'different', 1, convergence='running')

    def test_running_requires_complete_unique_container_states(self):
        self.running_pod()
        original = copy.deepcopy(self.pod)
        for change in (lambda p:p['status'].update(phase='Pending'),
                       lambda p:p['status'].update(containerStatuses=[]),
                       lambda p:p['status']['containerStatuses'][0].update(name='replacement'),
                       lambda p:p['status']['containerStatuses'].append(copy.deepcopy(p['status']['containerStatuses'][0])),
                       lambda p:p['status']['containerStatuses'][0].update(state={'waiting': {}}),
                       lambda p:p['status']['containerStatuses'][0].update(state={'terminated': {}}),
                       lambda p:p['status']['containerStatuses'][0].update(state={'running': {}})):
            value = copy.deepcopy(original); change(value)
            self.assertFalse(pod_running(value))
        snapshot = self.snapshot(); snapshot['pods'][0]['terminating'] = True
        self.assertFalse(converged(snapshot, 'deployment-uid', 1, convergence='running'))

    def test_restartable_init_sidecars_must_also_be_running(self):
        self.running_pod()
        self.pod['spec']['initContainers'] = [{'name': 'sidecar', 'restartPolicy': 'Always'}, {'name': 'migration'}]
        self.pod['status']['initContainerStatuses'] = [
            {'name': 'sidecar', 'state': {'running': {'startedAt': '2026-01-01T00:00:00Z'}}},
            {'name': 'migration', 'state': {'terminated': {'exitCode': 0}}}]
        self.assertTrue(pod_running(self.pod))
        self.pod['status']['initContainerStatuses'][0]['state'] = {'waiting': {}}
        self.assertFalse(pod_running(self.pod))

    def test_running_scale_mode_through_bounded_transport(self):
        import tempfile
        from pathlib import Path
        from types import SimpleNamespace
        from evaluation.evidence import Attempt
        from evaluation.workloads import workload_operation
        self.running_pod()
        fixtures = {'deployment': self.workload, 'replicasets': {'items': [self.rs]}, 'pods': {'items': [self.pod]}}
        program = 'import json,sys; data=json.loads(' + repr(json.dumps(fixtures)) + '); print(json.dumps(data[sys.argv[4]]))'
        with tempfile.TemporaryDirectory() as temporary, Attempt(Path(temporary)/'attempt', {}) as attempt:
            box = SimpleNamespace(exec_argv=lambda argv:[sys.executable, *argv[1:]])
            result = workload_operation(attempt, box, label='running-scale',
                kubectl_prefix=[sys.executable, '-c', program], namespace='incident-app', kind='deployment', name='worker',
                expected=self.snapshot(), replicas=1, convergence='running')
            self.assertEqual(result['outcome'], 'workload_scaled')
            self.assertFalse(result['observation']['workload']['pods'][0]['ready'])
            self.assertTrue(result['observation']['workload']['pods'][0]['running'])
            with self.assertRaises(ValueError):
                workload_operation(attempt, box, label='invalid', kubectl_prefix=[], namespace='incident-app', kind='deployment', name='worker', convergence='arbitrary')

    def test_failed_command_status_preserved_without_secret_output(self):
        result = subprocess.run([sys.executable, '-m', 'evaluation.workload_probe', '--kubectl-prefix',
                                 json.dumps([sys.executable, '-c', 'import sys; print("secret"); sys.exit(7)']),
                                 '--namespace', 'incident-app', '--kind', 'deployment', '--name', 'worker',
                                 '--operation', 'inspect'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['query_exit_codes'], [7])
        self.assertNotIn('secret', result.stdout + result.stderr)

    def test_deleted_or_wrong_identity_refused(self):
        self.workload['metadata']['deletionTimestamp'] = '2026-01-01T00:00:00Z'
        with self.assertRaises(ValueError): self.snapshot()
        del self.workload['metadata']['deletionTimestamp']
        self.workload['metadata']['namespace'] = 'other'
        with self.assertRaises(ValueError): self.snapshot()
