"""Redeployment never executes captured application scripts on the operator host."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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

    def run_grade(self, attempt, *, bootstrap='passed', runner=None, **extras):
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
                             command_runner=command, suite_runner=runner or default_suite, **extras)

    def test_capture_tampering_refused(self):
        (self.capture/'ops/bootstrap.sh').write_text('modified')
        with self.assertRaises(ValueError):verify_capture(self.capture, self.inventory)

    def test_link_identity_and_relocation_verified(self):
        source = self.root / 'linked-source'; source.mkdir()
        (source / 'real').write_text('content')
        (source / 'alias').symlink_to('real')
        captured = self.root / 'linked-capture'
        inventory = capture_tree(source, captured, termination_verified=True)
        verify_capture(captured, inventory)
        relocated = self.root / 'linked-relocated'
        copied = capture_tree(captured, relocated, termination_verified=True)
        self.assertEqual(inventory['files'], copied['files'])
        self.assertEqual((relocated / 'alias').read_text(), 'content')
        (captured / 'alias').unlink()
        (captured / 'alias').write_text('real')
        with self.assertRaises(ValueError): verify_capture(captured, inventory)

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

    def test_fault_transport_closes_before_sandbox_guard_release(self):
        events = []; broker = object()
        class Runtime:
            def __init__(inner, directory, box, guard, workloads, prefix, **kwargs):
                inner.broker = broker
                self.assertEqual(workloads, {'storage': 'operator selection'})
                self.assertGreater(kwargs['wall_deadline'], 0)
            def close(inner): events.append('broker-close')
        def runner(attempt, suite, target, **kwargs):
            self.assertIs(kwargs['fault_broker'], broker)
            events.append('grade')
            return {'criteria': {'AC-001': {'verdict': 'pass'}}, 'project_success': False, 'accepted_packages': []}
        def release(guard):
            events.append('guard-release')
            return {'remote_termination_verified': True}
        with patch.object(FakeGuard, 'release', release), Attempt(self.root/'fault-run', {}) as attempt:
            report = self.run_grade(attempt, runner=runner, fault_runtime_factory=Runtime,
                                    fault_workloads=lambda box: {'storage': 'operator selection'} if box.creation_attempted else {},
                                    kubectl_prefix=['kubectl'])
        self.assertEqual(events, ['grade', 'broker-close', 'guard-release'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_fault_initialization_failure_still_stops_sandbox(self):
        def broken(*args, **kwargs): raise RuntimeError('fixture fault admission')
        with Attempt(self.root/'fault-broken', {}) as attempt:
            report = self.run_grade(attempt, fault_runtime_factory=broken,
                                    fault_workloads={'storage': 'operator selection'}, kubectl_prefix=['kubectl'])
        self.assertEqual(report['outcome'], 'grading_incomplete')
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_fault_close_failure_still_releases_guard_and_cannot_accept(self):
        class Runtime:
            def __init__(self, *args, **kwargs): self.broker = object()
            def close(self): raise RuntimeError('fixture broker close')
        self.suite.approved = True
        with Attempt(self.root/'fault-close-broken', {}) as attempt:
            report = self.run_grade(attempt, fault_runtime_factory=Runtime,
                                    fault_workloads={'storage': 'operator selection'}, kubectl_prefix=['kubectl'])
        self.assertEqual(report['outcome'], 'grading_incomplete')
        self.assertFalse(report['project_success'])
        self.assertEqual(report['accepted_packages'], [])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_audit_resolves_after_bootstrap_and_stays_out_of_worker_target(self):
        events = []; broker = object(); peer_check = lambda _: None
        binding = {'canary': {'message': 'private fixture'}}
        peer = {'prefix': ['trusted-peer'], 'services': {}, 'cwd': self.root}
        def resolve(box):
            self.assertTrue(box.creation_attempted)
            self.assertEqual(len(self.commands), 1)
            events.append('resolve')
            return dict(audit_binding=binding, database_peer=peer, database_peer_check=peer_check)
        class Runtime:
            def __init__(inner, directory, box, guard, workloads, prefix, **kwargs):
                self.assertEqual(workloads, {})
                self.assertEqual(prefix, ['kubectl'])
                self.assertIs(kwargs['audit_binding'], binding)
                self.assertIs(kwargs['database_peer'], peer)
                self.assertIs(kwargs['database_peer_check'], peer_check)
                events.append('runtime'); inner.broker = broker
            def close(inner):events.append('close')
        def runner(attempt, suite, target, **kwargs):
            self.assertEqual(set(target), {'base_url'})
            self.assertIs(kwargs['fault_broker'], broker)
            events.append('grade')
            return {'criteria': {'AC-018': {'verdict':'pass'}}, 'project_success':False, 'accepted_packages':[]}
        with Attempt(self.root/'audit', {}) as attempt:
            report = self.run_grade(attempt, runner=runner, fault_audit=resolve, fault_runtime_factory=Runtime)
        self.assertEqual(events, ['resolve','runtime','grade','close'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertFalse(report['project_success'])

    def test_failed_bootstrap_does_not_resolve_audit_credentials(self):
        def unexpected(*args):self.fail('Resolver ran before successful bootstrap')
        with Attempt(self.root/'audit-no-bootstrap', {}) as attempt:
            report = self.run_grade(attempt, bootstrap='failed', fault_audit=unexpected)
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_audit_resolver_failure_disposes_environment_without_grading(self):
        def broken(box):raise RuntimeError('private credential diagnostic')
        def unexpected(*args, **kwargs):self.fail('Unbound database reached grader')
        with Attempt(self.root/'audit-broken', {}) as attempt:
            report = self.run_grade(attempt, fault_audit=broken, runner=unexpected)
        self.assertEqual(report['error_type'], 'RuntimeError')
        self.assertNotIn('private credential diagnostic', str(report))
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_incomplete_audit_resolution_never_constructs_runtime(self):
        def unexpected(*args, **kwargs):self.fail('Incomplete mapping reached runtime')
        for index, value in enumerate((None, {}, {'unexpected':True},
                {'audit_binding':None,'database_peer':{},'database_peer_check':lambda _:None})):
            with self.subTest(value=value), Attempt(self.root/('audit-missing-'+str(index)), {}) as attempt:
                # Each run needs a fresh copied project directory.
                if (self.root/'project').exists():
                    import shutil
                    shutil.rmtree(self.root/'project')
                report = self.run_grade(attempt, fault_audit=lambda box:value, fault_runtime_factory=unexpected)
                self.assertEqual(report['error_type'], 'ValueError')
                self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_static_audit_configuration_rejected_before_sandbox_creation(self):
        count = len(FakeSandbox.instances)
        with Attempt(self.root/'audit-static', {}) as attempt, self.assertRaises(ValueError):
            self.run_grade(attempt, fault_audit={})
        self.assertEqual(len(FakeSandbox.instances), count)

    def test_audit_observer_resolves_after_bootstrap_and_closes_before_guard(self):
        events = []
        broker = object()
        binding = {'private': 'binding'}
        def resolve(box):
            self.assertEqual(len(self.commands), 1)
            events.append('resolve')
            return dict(audit_binding=binding, database_peer={}, database_peer_check=lambda _:None)
        class Runtime:
            def __init__(inner, directory, box, guard, **kwargs):
                self.assertIs(kwargs['audit_binding'], binding)
                self.assertGreater(kwargs['wall_deadline'], 0)
                inner.broker = broker
            def close(inner): events.append('close')
        def runner(attempt, suite, target, **kwargs):
            self.assertEqual(set(target), {'base_url'})
            self.assertIs(kwargs['audit_broker'], broker)
            events.append('grade')
            return {'criteria': {'AC-016': {'verdict':'pass'}}, 'project_success':False}
        def release(guard):
            events.append('guard-release')
            return {'remote_termination_verified': True}
        with patch.object(FakeGuard, 'release', release), Attempt(self.root/'observer', {}) as attempt:
            report = self.run_grade(attempt, runner=runner, audit_observer=resolve, audit_runtime_factory=Runtime)
        self.assertEqual(events, ['resolve', 'grade', 'close', 'guard-release'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_audit_observer_close_error_prevents_acceptance_but_releases_guard(self):
        class Runtime:
            def __init__(self, *args, **kwargs): self.broker = object()
            def close(self): raise RuntimeError('private diagnostic')
        self.suite.approved = True
        with Attempt(self.root/'observer-close', {}) as attempt:
            report = self.run_grade(attempt, audit_runtime_factory=Runtime, audit_observer=lambda box:
                dict(audit_binding={}, database_peer={}, database_peer_check=lambda _:None))
        self.assertEqual(report['outcome'], 'grading_incomplete')
        self.assertEqual(report['audit_cleanup_error'], 'RuntimeError')
        self.assertFalse(report['project_success'])
        self.assertEqual(report['accepted_packages'], [])
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private diagnostic', str(report))

    def test_observer_is_not_resolved_after_failed_bootstrap(self):
        def unexpected(*args): self.fail('Resolver ran before bootstrap succeeded')
        with Attempt(self.root/'observer-bootstrap', {}) as attempt:
            report = self.run_grade(attempt, bootstrap='failed', audit_observer=unexpected)
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_static_observer_refused_and_missing_binding_disposes_environment(self):
        with Attempt(self.root/'observer-static', {}) as attempt, self.assertRaises(ValueError):
            self.run_grade(attempt, audit_observer={})
        with Attempt(self.root/'observer-missing', {}) as attempt:
            report = self.run_grade(attempt, audit_observer=lambda _: {})
        self.assertEqual(report['error_type'], 'ValueError')
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_observer_resolver_failure_closes_existing_fault_runtime(self):
        closed = []
        class Runtime:
            def __init__(self, *args, **kwargs): self.broker = object()
            def close(self): closed.append(True)
        def broken(box): raise RuntimeError('private diagnostic')
        with Attempt(self.root/'observer-failure', {}) as attempt:
            report = self.run_grade(attempt, fault_runtime_factory=Runtime, fault_workloads={},
                                    audit_observer=broken)
        self.assertEqual(closed, [True])
        self.assertEqual(report['outcome'], 'grading_incomplete')
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private diagnostic', str(report))
