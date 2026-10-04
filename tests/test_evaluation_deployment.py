"""Redeployment never executes captured application scripts on the operator host."""

from pathlib import Path
import tempfile
import unittest

from evaluation.deployment import grade_capture, verify_capture
from evaluation.evidence import Attempt
from evaluation.sandbox import capture_tree


class FakeSuite:
    approved = False
    def __init__(self, root): self.root = root
    def verify(self): pass


class FakeSandbox:
    instances = []
    def __init__(self, *args, **kwargs):
        self.name = 'factory-eval-grader-0123456789abcdef'
        self.creation_attempted = False
        self.stopped = False
        self.instances.append(self)
    def create(self):
        self.creation_attempted = True
        return {'outcome': 'passed'}
    def exec_argv(self, args): return ['sbx', 'exec', self.name] + args
    def stop(self): self.stopped = True; return True


class FakeGuard:
    stopped = True
    def __init__(self, *args, **kwargs): pass
    def release(self): return {'remote_termination_verified': self.stopped}


class DeploymentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        source = self.root/'source';(source/'ops').mkdir(parents=True)
        (source/'ops/bootstrap.sh').write_text('#!/bin/sh\nexit 0\n')
        (source/'ops/bootstrap.sh').chmod(0o700)
        self.capture = self.root/'capture'
        self.inventory = capture_tree(source, self.capture, termination_verified=True)
        self.spec = self.root/'spec';self.spec.mkdir()
        self.suite = FakeSuite(self.root/'suite');self.suite.root.mkdir()
        self.commands = []
        FakeGuard.stopped = True

    def run_grade(self, attempt, *, bootstrap='passed', runner=None):
        def command(attempt, label, argv, **kwargs):
            self.commands.append(argv)
            return {'outcome': bootstrap, 'exit_code': 0 if bootstrap == 'passed' else 7}
        def default_suite(attempt, suite, target, **kwargs):
            self.assertEqual(target['base_url'], 'http://127.0.0.1:18080')
            return {'criteria': {'AC-001': {'verdict': 'pass'}}, 'project_success': True,
                    'accepted_packages': ['WP-001']}
        return grade_capture(attempt, self.capture, self.inventory, self.spec, self.root/'project',
                             self.suite, {'base_url': 'https://untrusted.invalid'}, port=18080,
                             development=True, sandbox_factory=FakeSandbox, guard_factory=FakeGuard,
                             command_runner=command, suite_runner=runner or default_suite)

    def test_capture_tampering_refused(self):
        (self.capture/'ops/bootstrap.sh').write_text('modified')
        with self.assertRaises(ValueError):verify_capture(self.capture, self.inventory)

    def test_bootstrap_only_inside_sbx_and_unapproved_suite_never_accepts(self):
        with Attempt(self.root/'logs', {}) as attempt:
            result = self.run_grade(attempt)
        self.assertEqual(self.commands[0], ['sbx', 'exec', FakeSandbox.instances[-1].name, './ops/bootstrap.sh'])
        self.assertFalse(result['project_success'])
        self.assertEqual(result['accepted_packages'], [])
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_failed_bootstrap_still_cleans_up_without_grading(self):
        def unexpected(*args, **kwargs):raise AssertionError('Must not grade failed deployment')
        with Attempt(self.root/'logs', {}) as attempt:
            result = self.run_grade(attempt, bootstrap='failed', runner=unexpected)
        self.assertEqual(result['reason'], 'bootstrap_failed')
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_guard_failure_uses_scoped_fallback_stop(self):
        FakeGuard.stopped = False
        with Attempt(self.root/'logs', {}) as attempt:
            result = self.run_grade(attempt)
        self.assertTrue(result['cleanup']['fallback_remote_termination_verified'])
        self.assertTrue(FakeSandbox.instances[-1].stopped)
