"""Network faults require working controls, never mere command failure."""

import json
import subprocess
import sys
import unittest
from evaluation.service_probe import classify, endpoint, observe


class ServicesTest(unittest.TestCase):
    def test_http_authorization_failure_still_proves_connectivity(self):
        self.assertEqual(classify(1, '  HTTP/1.1 403 Forbidden\nsecret-header'), 'reachable')
        self.assertEqual(classify(0, '  HTTP/1.1 200 OK'), 'reachable')

    def test_only_specific_network_failures_prove_unreachability(self):
        for message in ('wget: connection refused', 'wget: download timed out', 'wget: no route to host'):
            self.assertEqual(classify(1, message), 'unreachable')
        for message in ('sh: wget: not found', 'error: pod not found', 'Unauthorized', 'unexpected failure'):
            self.assertEqual(classify(1, message), 'inconclusive')
        self.assertEqual(classify(0, 'wget: connection refused'), 'inconclusive')

    def test_gnu_wget_connect_diagnostics_and_ambiguous_failures(self):
        for reason in ('Connection refused', 'Connection timed out', 'No route to host', 'Network is unreachable'):
            message = '--2026-10-04-- http://127.0.0.1:9000/\nConnecting to 127.0.0.1:9000... failed: ' + reason + '.\n'
            self.assertEqual(classify(4, message), 'unreachable')
            self.assertEqual(classify(0, message), 'inconclusive')
            self.assertEqual(classify(4, message + '  HTTP/1.1 503 Unavailable\n'), 'reachable')
        for message in ('failed: Connection refused.', 'Connecting to 127.0.0.1:9000... failed: unknown.',
                        'Connecting to 127.0.0.1:9000... connected.\nRead error: Connection timed out.'):
            self.assertEqual(classify(4, message), 'inconclusive')

    def test_failed_controls_cannot_establish_outage(self):
        for values in (['unreachable'], ['reachable', 'unreachable', 'unreachable', 'unreachable', 'inconclusive'],
                       ['reachable', 'reachable']):
            responses = iter(values)
            result = observe(lambda url: {'connectivity': next(responses), 'exit_code': 1}, 'target', 'control', 'unavailable')
            self.assertEqual(result['outcome'], 'service_probe_incomplete')

    def test_three_negative_observations_and_two_positive_controls(self):
        states = iter(['reachable', 'unreachable', 'unreachable', 'unreachable', 'reachable'])
        result = observe(lambda url: {'connectivity': next(states), 'exit_code': 1}, 'target', 'control', 'unavailable')
        self.assertEqual(result['outcome'], 'service_unavailable_verified')
        self.assertEqual(len(result['checks']), 5)

    def test_endpoint_rejects_credentials_public_hosts_and_paths(self):
        self.assertEqual(endpoint('http://10.43.1.2:9000/'), 'http://10.43.1.2:9000/')
        for value in ('http://user:secret@10.43.1.2:9000', 'http://example.com:80', 'http://8.8.8.8:80',
                      'http://10.43.1.2:80/private', 'http://10.43.1.2:80?token=secret'):
            with self.assertRaises(ValueError): endpoint(value)

    def test_probe_never_prints_raw_headers_or_diagnostics(self):
        prefix = [sys.executable, '-c', 'import sys; print("  HTTP/1.1 403 Forbidden\\nAuthorization: secret",file=sys.stderr); sys.exit(1)']
        result = subprocess.run([sys.executable, '-m', 'evaluation.service_probe', '--peer-prefix', json.dumps(prefix),
                                 '--target', 'http://10.43.1.2:9000/', '--control', 'http://10.43.1.3:8080/',
                                 '--mode', 'available'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('secret', result.stdout + result.stderr)
        self.assertTrue(all(item['exit_code'] == 1 for item in json.loads(result.stdout)['checks']))
