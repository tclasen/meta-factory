"""Browser transport uncertainty must never become application acceptance."""

import json
import unittest
from unittest.mock import patch

import test_evaluation_grading as grading_fixtures
from evaluation.grading import Suite, run_suite
from evaluation.evidence import Attempt


class BrowserGradingTest(unittest.TestCase):
    save = grading_fixtures.GradingTest.save

    def setUp(self):
        grading_fixtures.GradingTest.setUp(self)
        self.manifest['cases'][0]['browser'] = 'page'
        self.manifest['cases'].append(dict(id='second', source='cases.py', function='good',
            criteria=['AC-002'], timeout_seconds=2))
        self.save()
        self.sequence = 0

    def execute(self, executor=None):
        self.sequence += 1
        with Attempt(self.root / ('browser-' + str(self.sequence)), {}) as attempt:
            return run_suite(attempt, Suite(self.suite, self.packages),
                {'value': 1, '_audit_control': {'token': 'forged'}, '_fault_control': {}},
                deadline_seconds=5, development=True, browser_executor=executor)

    def evidence(self, **changes):
        return dict(dict(case_id='first', verdict='pass', cleanup_verified=True, guard_verified=True,
                    transport={'browser': {'completed': 2}, 'upstream': {'completed': 2}}), **changes)

    def test_browser_unavailable_never_falls_back_to_host_worker(self):
        report = self.execute()
        self.assertEqual(report['case_results']['first']['reason'], 'browser_executor_unavailable')
        self.assertEqual(report['case_results']['second']['verdict'], 'pass')
        self.assertFalse(report['project_success'])

    def test_browser_dispatch_scopes_configuration_and_bounds(self):
        def executor(attempt, suite, case, target, *, timeout_seconds):
            self.assertEqual(case['browser'], 'page')
            self.assertEqual(target, {'value': 1})
            self.assertGreater(timeout_seconds, 0)
            self.assertLessEqual(timeout_seconds, 2)
            return self.evidence(reason='secret', observation={'password': 'secret'})
        report = self.execute(executor)
        self.assertEqual(report['case_results']['first']['verdict'], 'pass')
        self.assertNotIn('secret', json.dumps(report))
        self.assertFalse(report['project_success'])

    def test_browser_both_transport_hops_must_be_verified(self):
        invalid = [None, {}, {'browser': {'completed': 1}},
                   {'browser': {'completed': True}, 'upstream': {'completed': 1}}]
        for counter in ('refused', 'upstream_error', 'request_limit', 'response_limit',
                        'deadline', 'client_disconnect', 'handler_error', 'unknown'):
            invalid.append({'browser': {'completed': 2}, 'upstream': {'completed': 2, counter: 1}})
        for transport in invalid:
            for verdict in ('pass', 'fail'):
                with self.subTest(transport=transport, verdict=verdict):
                    report = self.execute(lambda *a, **k: self.evidence(transport=transport, verdict=verdict))
                    self.assertEqual(report['case_results']['first']['verdict'], 'inconclusive')

    def test_browser_lifetime_and_malformed_evidence_abort(self):
        for value in (None, self.evidence(case_id='wrong'), self.evidence(guard_verified=False),
                      self.evidence(cleanup_verified=False), self.evidence(abort_suite=True),
                      self.evidence(abort_suite='false'), self.evidence(verdict='invented')):
            report = self.execute(lambda *a, **k: value)
            self.assertTrue(report['aborted'])
            self.assertNotIn('second', report['case_results'])

    def test_browser_callback_exception_is_redacted_and_aborts(self):
        def executor(*a, **k):
            raise RuntimeError('private credential')
        report = self.execute(executor)
        self.assertTrue(report['aborted'])
        self.assertNotIn('private credential', json.dumps(report))

    def test_browser_clean_failure_and_untested_remain_distinct(self):
        for verdict in ('fail', 'untested', 'inconclusive'):
            report = self.execute(lambda *a, **k: self.evidence(verdict=verdict))
            self.assertEqual(report['case_results']['first']['verdict'], verdict)
            self.assertFalse(report['aborted'])

    def test_browser_uncertain_shared_state_stops_following_case(self):
        self.manifest['cases'][0]['mutates_shared_state'] = True
        self.save()
        report = self.execute(lambda *a, **k: self.evidence(verdict='fail'))
        self.assertTrue(report['aborted'])
        self.assertNotIn('second', report['case_results'])

    def test_browser_elapsed_time_cannot_be_ignored(self):
        with patch('evaluation.browser.time.monotonic', side_effect=[0, 3]):
            # Direct boundary call keeps the suite's own monotonic clock separate.
            from evaluation.browser import run_browser_case
            result = run_browser_case(lambda *a, **k: self.evidence(), None, None,
                                      {'id': 'first'}, {}, 2)
        self.assertEqual(result['reason'], 'browser_deadline_exceeded')

    def test_browser_declaration_validation(self):
        for mode in (True, {}, 'unknown', None):
            self.manifest['cases'][0]['browser'] = mode; self.save()
            with self.assertRaises(ValueError):
                Suite(self.suite, self.packages)
        for capability in ('reads_audit', 'mutates_runtime'):
            self.manifest['cases'][0] = dict(self.manifest['cases'][0], browser='page', **{capability: True})
            self.save()
            with self.assertRaises(ValueError):
                Suite(self.suite, self.packages)
            del self.manifest['cases'][0][capability]
