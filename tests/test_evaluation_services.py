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

    def test_delayed_service_recovery_is_bracketed_by_live_controls(self):
        clock=[0.0];responses=iter(['reachable','unreachable','reachable',
                                 'reachable','reachable','reachable'])
        result=observe(lambda url:{'connectivity':next(responses),'exit_code':1},
            'target','control','available',deadline=2,monotonic=lambda:clock[0],
            sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds))
        self.assertEqual(result['outcome'],'service_available_verified')
        self.assertEqual(len(result['checks']),6)
        self.assertGreater(clock[0],0)

    def test_recovery_refuses_unknown_failure_or_lost_control(self):
        for values in (['reachable','inconclusive'],
                       ['reachable','unreachable','reachable','reachable','reachable','unreachable']):
            responses=iter(values)
            result=observe(lambda url:{'connectivity':next(responses),'exit_code':1},
                'target','control','available',deadline=100,monotonic=lambda:0,
                sleep=lambda seconds:None)
            self.assertEqual(result['outcome'],'service_probe_incomplete')
            self.assertEqual(len(result['checks']),len(values))

    def test_service_still_unavailable_at_deadline_cannot_recover(self):
        clock=[0.0]
        result=observe(lambda url:{'connectivity':'unreachable' if url=='target' else 'reachable','exit_code':1},
            'target','control','available',deadline=.5,monotonic=lambda:clock[0],
            sleep=lambda seconds:clock.__setitem__(0,clock[0]+seconds))
        self.assertEqual(result['outcome'],'service_probe_incomplete')
        self.assertEqual(clock[0],.5)
        self.assertEqual(len(result['checks']),6)

    def test_late_control_response_prevents_new_probe_commands(self):
        clock=[0.0];calls=[]
        def check(url):
            calls.append(url);clock[0]=2
            return {'connectivity':'reachable','exit_code':0}
        result=observe(check,'target','control','available',deadline=1,
                       monotonic=lambda:clock[0],sleep=lambda seconds:self.fail('No late sleep'))
        self.assertEqual(calls,['control'])
        self.assertEqual(result['outcome'],'service_probe_incomplete')

    def test_probe_exception_retains_prior_observations_without_private_diagnostic(self):
        calls=[]
        def check(url):
            calls.append(url)
            if url=='target':raise TimeoutError('private-header-and-secret-canary')
            return {'connectivity':'reachable','exit_code':0}
        result=observe(check,'target','control','available',deadline=10,
                       monotonic=lambda:0,sleep=lambda seconds:self.fail('No retry of unknown error'))
        self.assertEqual(calls,['control','target'])
        self.assertEqual(result['outcome'],'service_probe_incomplete')
        self.assertEqual(len(result['checks']),2)
        self.assertEqual(result['checks'][1]['error_type'],'TimeoutError')
        self.assertIsNone(result['checks'][1]['exit_code'])
        self.assertNotIn('private-header-and-secret-canary',json.dumps(result))

    def test_probe_never_prints_raw_headers_or_diagnostics(self):
        prefix = [sys.executable, '-c', 'import sys; print("  HTTP/1.1 403 Forbidden\\nAuthorization: secret",file=sys.stderr); sys.exit(1)']
        result = subprocess.run([sys.executable, '-m', 'evaluation.service_probe', '--peer-prefix', json.dumps(prefix),
                                 '--target', 'http://10.43.1.2:9000/', '--control', 'http://10.43.1.3:8080/',
                                 '--mode', 'available'], capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0)
        self.assertNotIn('secret', result.stdout + result.stderr)
        self.assertTrue(all(item['exit_code'] == 1 for item in json.loads(result.stdout)['checks']))
