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

    def test_browser_resolves_only_after_bootstrap_and_closes_before_outer_guard(self):
        events=[];configuration={'private':'browser configuration'}
        def resolve(box):
            self.assertTrue(box.creation_attempted)
            self.assertEqual(len(self.commands),1)
            events.append('resolve');return configuration
        class Binding:
            def __init__(inner,box,guard,config,**kwargs):
                self.assertIs(config,configuration)
                self.assertEqual(kwargs['base_url'],'http://127.0.0.1:18080')
                self.assertGreater(kwargs['monotonic_deadline'],0)
                events.append('bind')
            def close(inner):events.append('close')
        def runner(attempt,suite,target,**kwargs):
            self.assertIsInstance(kwargs['browser_executor'],Binding)
            self.assertEqual(target,{'base_url':'http://127.0.0.1:18080'})
            events.append('grade')
            return {'criteria':{'AC-025':{'verdict':'pass'}},'project_success':True,'accepted_packages':['WP-009']}
        def release(guard):
            events.append('guard-release');return {'remote_termination_verified':True}
        with patch.object(FakeGuard,'release',release),Attempt(self.root/'browser',{}) as attempt:
            report=self.run_grade(attempt,runner=runner,browser_resolver=resolve,browser_binding_factory=Binding)
        self.assertEqual(events,['resolve','bind','grade','close','guard-release'])
        self.assertFalse(report['project_success'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_failed_bootstrap_does_not_resolve_browser(self):
        def unexpected(*args):self.fail('Browser resolved before successful bootstrap')
        with Attempt(self.root/'browser-no-bootstrap',{}) as attempt:
            report=self.run_grade(attempt,bootstrap='failed',browser_resolver=unexpected)
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_browser_resolution_failure_cleans_sandbox_and_redacts_exception(self):
        def broken(box):raise RuntimeError('private-browser-credential')
        with Attempt(self.root/'browser-broken',{}) as attempt:
            report=self.run_grade(attempt,browser_resolver=broken)
        self.assertEqual(report['outcome'],'grading_incomplete')
        self.assertNotIn('private-browser-credential',str(report))
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_static_browser_configuration_rejected_before_sandbox_creation(self):
        count=len(FakeSandbox.instances)
        with Attempt(self.root/'browser-static',{}) as attempt,self.assertRaises(ValueError):
            self.run_grade(attempt,browser_resolver={})
        self.assertEqual(len(FakeSandbox.instances),count)

    def test_browser_close_failure_cannot_accept_and_still_stops_outer_sandbox(self):
        class Binding:
            def __init__(self,*args,**kwargs):pass
            def close(self):raise RuntimeError('private-browser-cleanup')
        self.suite.approved=True
        with Attempt(self.root/'browser-close-broken',{}) as attempt:
            report=self.run_grade(attempt,browser_resolver=lambda box:{},browser_binding_factory=Binding)
        self.assertFalse(report['project_success'])
        self.assertEqual(report['accepted_packages'],[])
        self.assertEqual(report['browser_cleanup_error'],'RuntimeError')
        self.assertNotIn('private-browser-cleanup',str(report))
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_compound_faults_resolve_fresh_and_close_before_guard(self):
        events=[]; broker=object()
        def workloads(box):
            self.assertTrue(self.commands and box.creation_attempted)
            events.append('workloads');return {'storage':'fresh-storage','worker':'fresh-worker'}
        def services(box):
            self.assertTrue(self.commands);events.append('services');return {'storage':'fresh-probe'}
        class Runtime:
            def __init__(inner,directory,box,guard,mapping,prefix,**kwargs):
                self.assertEqual(mapping,{'storage':'fresh-storage','worker':'fresh-worker'})
                self.assertEqual(kwargs['service_probes'],{'storage':'fresh-probe'})
                self.assertIs(kwargs['storage_worker_restart'],True)
                self.assertGreater(kwargs['monotonic_deadline'],0)
                inner.broker=broker;events.append('runtime')
            def close(inner):events.append('close')
        def runner(attempt,suite,target,**kwargs):
            self.assertIs(kwargs['fault_broker'],broker)
            self.assertNotIn('storage_worker_restart',target)
            events.append('grade');return {'criteria':{},'project_success':False,'accepted_packages':[]}
        def release(guard):events.append('release');return {'remote_termination_verified':True}
        with patch.object(FakeGuard,'release',release), Attempt(self.root/'compound',{}) as attempt:
            report=self.run_grade(attempt,runner=runner,fault_workloads=workloads,fault_service_probes=services,
                fault_runtime_factory=Runtime,kubectl_prefix=['kubectl'],fault_storage_worker_restart=True)
        self.assertEqual(events,['workloads','services','runtime','grade','close','release'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_compound_static_or_malformed_selection_refused_before_creation(self):
        cases=[dict(fault_storage_worker_restart='true'),dict(fault_storage_worker_restart=True),
               dict(fault_storage_worker_restart=True,fault_workloads={},fault_service_probes=lambda box:{}),
               dict(fault_storage_worker_restart=True,fault_workloads=lambda box:{},fault_service_probes={})]
        before=len(FakeSandbox.instances)
        for index,extras in enumerate(cases):
            with self.subTest(index=index), Attempt(self.root/('invalid-compound-'+str(index)),{}) as attempt:
                with self.assertRaises(ValueError):self.run_grade(attempt,**extras)
        self.assertEqual(len(FakeSandbox.instances),before)
        self.assertEqual(self.commands,[])

    def test_failed_bootstrap_never_resolves_compound_resources(self):
        def unexpected(box):raise AssertionError('Failed bootstrap resolved fault resources')
        with Attempt(self.root/'compound-bootstrap-failed',{}) as attempt:
            report=self.run_grade(attempt,bootstrap='failed',fault_storage_worker_restart=True,
                fault_workloads=unexpected,fault_service_probes=unexpected,kubectl_prefix=['kubectl'])
        self.assertEqual(report['outcome'],'grading_incomplete')
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def job_options(self):
        return {key: lambda *args, **kwargs: None for key in (
            'database_read', 'artifact_count', 'database_peer_check', 'storage_peer_check')}

    def test_jobs_resolve_after_bootstrap_and_close_before_outer_guard(self):
        events = []; broker = object(); configuration = self.job_options()
        def resolve(box):
            self.assertEqual(len(self.commands), 1)
            events.append('resolve')
            return configuration
        class Runtime:
            def __init__(inner, directory, box, guard, **kwargs):
                self.assertIs(kwargs['database_read'], configuration['database_read'])
                self.assertGreater(kwargs['monotonic_deadline'], 0)
                self.assertGreater(kwargs['wall_deadline'], 0)
                inner.broker = broker
            def close(inner): events.append('close')
        def runner(attempt, suite, target, **kwargs):
            self.assertEqual(set(target), {'base_url'})
            self.assertIs(kwargs['job_broker'], broker)
            events.append('grade')
            return {'criteria': {'AC-025': {'verdict': 'pass'}}, 'project_success': False}
        def release(guard):
            events.append('release')
            return {'remote_termination_verified': True}
        with patch.object(FakeGuard, 'release', release), Attempt(self.root/'jobs', {}) as attempt:
            report = self.run_grade(attempt, runner=runner, job_observer=resolve, job_runtime_factory=Runtime)
        self.assertEqual(events, ['resolve', 'grade', 'close', 'release'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_failed_bootstrap_never_resolves_jobs(self):
        def unexpected(*args): self.fail('Job resolver called without deployment')
        with Attempt(self.root/'jobs-no-bootstrap', {}) as attempt:
            report = self.run_grade(attempt, bootstrap='failed', job_observer=unexpected)
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_static_job_configuration_rejected_before_creation(self):
        count = len(FakeSandbox.instances)
        with Attempt(self.root/'jobs-static', {}) as attempt, self.assertRaises(ValueError):
            self.run_grade(attempt, job_observer={})
        self.assertEqual(len(FakeSandbox.instances), count)

    def test_malformed_job_binding_never_constructs_runtime_or_grades(self):
        # One redeployment per isolated fixture: use separate project directories.
        configurations = [{}, dict(self.job_options(), artifact_count=None),
                          dict(self.job_options(), credentials='private')]
        for index, configuration in enumerate(configurations):
            if index: (self.root/'project').rename(self.root/('previous-project-'+str(index)))
            def unexpected(*args, **kwargs): self.fail('Invalid job binding was used')
            with Attempt(self.root/('jobs-malformed-'+str(index)), {}) as attempt:
                report = self.run_grade(attempt, job_observer=lambda box:configuration,
                                        job_runtime_factory=unexpected, runner=unexpected)
            self.assertEqual(report['error_type'], 'ValueError')
            self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_job_close_failure_revokes_acceptance_and_releases_guard(self):
        class Runtime:
            def __init__(self, *args, **kwargs): self.broker = object()
            def close(self): raise RuntimeError('private-job-credential')
        self.suite.approved = True
        with Attempt(self.root/'jobs-close-broken', {}) as attempt:
            report = self.run_grade(attempt, job_observer=lambda box:self.job_options(), job_runtime_factory=Runtime)
        self.assertFalse(report['project_success'])
        self.assertEqual(report['accepted_packages'], [])
        self.assertEqual(report['job_cleanup_error'], 'RuntimeError')
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-job-credential', str(report))

    def test_later_resolver_failure_closes_job_capability(self):
        closed = []
        class Runtime:
            def __init__(self, *args, **kwargs): self.broker = object()
            def close(self): closed.append(True)
        def broken(box): raise RuntimeError('private-browser-credential')
        with Attempt(self.root/'jobs-later-failure', {}) as attempt:
            report = self.run_grade(attempt, job_observer=lambda box:self.job_options(),
                                    job_runtime_factory=Runtime, browser_resolver=broken)
        self.assertEqual(closed, [True])
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-browser-credential', str(report))
