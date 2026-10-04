"""Image observations must be complete and must never print raw Pod secrets."""

import copy
import json
import subprocess
import sys
import unittest

from evaluation.image_probe import inventory


class ImagesTest(unittest.TestCase):
    def setUp(self):
        self.digest = 'sha256:' + 'a' * 64
        self.pod = {'metadata': {'namespace': 'incident-app', 'name': 'api-pod'},
                    'spec': {'containers': [{'name': 'api', 'image': 'example/api:1.0',
                                             'env': [{'name': 'PASSWORD', 'value': 'secret-fixture-do-not-log'}]}]},
                    'status': {'containerStatuses': [{'name': 'api', 'imageID': 'containerd://' + self.digest}]}}

    def test_named_status_matching_and_init_images(self):
        self.pod['spec']['initContainers'] = [{'name': 'migration', 'image': 'example/migration@' + self.digest}]
        self.pod['status']['initContainerStatuses'] = [{'name': 'migration', 'imageID': 'docker-pullable://example/migration@' + self.digest}]
        result = inventory({'items': [self.pod]})
        self.assertEqual(len(result), 2)
        self.assertFalse(result[0]['reference_uses_digest'])
        self.assertTrue(result[1]['reference_uses_digest'])
        self.assertNotIn('secret-fixture', json.dumps(result))
        self.assertTrue(all(record['runtime_digest'] == self.digest for record in result))

    def test_missing_image_identity_and_duplicate_status_are_incomplete(self):
        for statuses in ([], [{'name': 'api', 'imageID': ''}], self.pod['status']['containerStatuses'] * 2):
            pod = copy.deepcopy(self.pod); pod['status']['containerStatuses'] = statuses
            with self.assertRaises(ValueError): inventory({'items': [pod]})
        with self.assertRaises(ValueError): inventory({'items': []})

    def test_malformed_or_credential_bearing_references_refused(self):
        for value in ('https://user:password@example/image', 'user:password@example/image', 'image?token=secret'):
            pod = copy.deepcopy(self.pod); pod['spec']['containers'][0]['image'] = value
            with self.assertRaises(ValueError): inventory({'items': [pod]})
        self.pod['status']['containerStatuses'][0]['imageID'] = 'containerd://docker://' + self.digest
        with self.assertRaises(ValueError): inventory({'items': [self.pod]})

    def probe(self, source):
        return subprocess.run([sys.executable, '-m', 'evaluation.image_probe', '--namespace', 'incident-app',
                               '--kubectl-prefix', json.dumps([sys.executable, '-c', source])],
                              capture_output=True, text=True, timeout=5)

    def test_probe_prints_only_sanitized_projection(self):
        response = json.dumps({'items': [self.pod]})
        result = self.probe('import sys; print(' + repr(response) + '); print("secret-stderr",file=sys.stderr)')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)['outcome'], 'image_identities_observed')
        self.assertNotIn('secret', result.stdout + result.stderr)

    def test_failed_query_retains_status_without_diagnostic_secret(self):
        result = self.probe('import sys; print("secret-token"); print("secret-error",file=sys.stderr); sys.exit(7)')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stdout)['query_exit_code'], 7)
        self.assertNotIn('secret', result.stdout + result.stderr)
