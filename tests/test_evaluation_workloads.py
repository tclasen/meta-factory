"""Faults must target exact owner chains, preserve secrets and reject stale writes."""

import copy
import json
import subprocess
import sys
import unittest

from evaluation.workload_probe import project, scale_patch, converged


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
