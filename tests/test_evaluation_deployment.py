"""Redeployment never executes captured application scripts on the operator host."""

from pathlib import Path
import tempfile
import shutil
import unittest
import os
import time
from types import SimpleNamespace
from unittest.mock import patch

from evaluation.deployment import grade_capture, verify_capture
from evaluation.evidence import Attempt
from evaluation.sandbox import capture_tree


class FakeSuite:
    approved = False
    def __init__(self, root): self.root = root
    def verify(self): pass
    def aggregate(self, results):
        assert not results
        return dict(criteria={'AC-001':dict(verdict='untested')},
                    accepted_packages=[], development_passing_packages=[],
                    project_success=False, suite_approved=self.approved)


class FakeSandbox:
    instances = []
    def __init__(self, *args, **kwargs):
        self.name = 'factory-eval-grader-0123456789abcdef'
        self.project, self.specification = args[1], args[2]
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
    def __init__(self, *args, **kwargs):
        self.directory = Path(args[0])
        self.process = SimpleNamespace(poll=lambda: None)
        self.nonce = '0'*32
        self.directory.mkdir(mode=0o700)
        from evaluation.evidence import atomic_json
        atomic_json(self.directory/'config.json',dict(schema_version=1,sandbox=args[1],owner_pid=os.getpid(),nonce=self.nonce,max_seconds=6000,expires_at=time.time()+6000))
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

    def test_bridge_precedes_fixture_loading_and_closes_before_guard(self):
        calls=[]
        class Bridge:
            def __init__(self,*args,**kwargs):
                self.check=kwargs['lifetime_check']
                calls.append('construct')
            def start(self):self.check(1);calls.append('start')
            def close(self):calls.append('close')
        def loader(box,**kwargs):
            self.assertEqual(calls,['construct','start'])
            calls.append('fixture')
            return {'tenants':{'alpha':'fixture'}}
        with Attempt(self.root/'logs',{}) as attempt:
            report=self.run_grade(attempt,loopback_bridge=True,loopback_bridge_factory=Bridge,
                                  fixture_loader=loader)
        self.assertEqual(calls,['construct','start','fixture','close'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_bridge_startup_failure_skips_fixture_and_grading_and_still_closes(self):
        closed=[]
        class Bridge:
            def __init__(self,*args,**kwargs):pass
            def start(self):raise RuntimeError('private startup diagnostic')
            def close(self):closed.append(True)
        def forbidden(*args,**kwargs):raise AssertionError('Incomplete bridge must not grade')
        with Attempt(self.root/'logs',{}) as attempt:
            report=self.run_grade(attempt,loopback_bridge=True,loopback_bridge_factory=Bridge,
                                  fixture_loader=forbidden,runner=forbidden)
        self.assertEqual(closed,[True])
        self.assertEqual(report['reason'],'grading_unavailable')
        self.assertFalse(report['project_success'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private startup diagnostic',str(report))

    def test_bridge_cleanup_failure_clears_passed_package_acceptance(self):
        class Bridge:
            def __init__(self,*args,**kwargs):pass
            def start(self):pass
            def close(self):raise RuntimeError('private cleanup diagnostic')
        with Attempt(self.root/'logs',{}) as attempt:
            report=self.run_grade(attempt,loopback_bridge=True,loopback_bridge_factory=Bridge)
        self.assertEqual(report['bridge_cleanup_error'],'RuntimeError')
        self.assertEqual(report['accepted_packages'],[])
        self.assertFalse(report['project_success'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_capture_tampering_refused(self):
        (self.capture/'ops/bootstrap.sh').write_text('modified')
        with self.assertRaises(ValueError):verify_capture(self.capture, self.inventory)

    def test_legacy_missing_mode_metadata_stops_before_sandbox_creation(self):
        self.inventory.pop('unix_modes')
        previous = len(FakeSandbox.instances)
        with Attempt(self.root/'logs', {}) as attempt:
            result = self.run_grade(attempt)
        self.assertEqual(result['reason'], 'source_permission_metadata_missing')
        self.assertEqual(len(FakeSandbox.instances), previous)
        self.assertEqual(self.commands, [])
        self.assertFalse(result['project_success'])

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

    def staging_extras(self, events):
        owner=self;fault_broker=object();job_broker=object();stage_broker=object()
        class Faults:
            def __init__(inner,*args,**kwargs):
                owner.assertTrue(kwargs['storage_worker_restart']);inner.broker=fault_broker
                events.append('fault-bind')
            def close(inner):events.append('fault-close')
        class Jobs:
            def __init__(inner,*args,**kwargs):inner.broker=job_broker;events.append('job-bind')
            def close(inner):events.append('job-close')
        class Staging:
            def __init__(inner,directory,faults,**kwargs):
                owner.assertIsInstance(faults,Faults);owner.assertIsInstance(kwargs['job_runtime'],Jobs);inner.broker=stage_broker;events.append('stage-bind')
            def close(inner):events.append('stage-close')
        def workloads(box):
            owner.assertEqual(len(owner.commands),1);events.append('workloads');return {}
        return dict(job_staging=True,fault_workloads=workloads,fault_service_probes=lambda box:{},
                    job_observer=lambda box:owner.job_options(),kubectl_prefix=['kubectl'],
                    fault_runtime_factory=Faults,job_runtime_factory=Jobs,staging_runtime_factory=Staging)

    def test_staging_opt_in_binds_after_bootstrap_and_closes_before_jobs_faults_guard(self):
        events=[];extras=self.staging_extras(events)
        def runner(attempt,suite,target,**kwargs):
            self.assertIn('staging_broker',kwargs);self.assertIn('job_broker',kwargs)
            self.assertEqual(set(target),{'base_url'});events.append('grade')
            return {'criteria':{'AC-024':{'verdict':'pass'}},'project_success':False}
        def release(guard):events.append('guard-release');return {'remote_termination_verified':True}
        with patch.object(FakeGuard,'release',release),Attempt(self.root/'staging-bound',{}) as attempt:
            report=self.run_grade(attempt,runner=runner,**extras)
        self.assertEqual(events,['workloads','fault-bind','job-bind','stage-bind','grade','stage-close','job-close','fault-close','guard-release'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def security_options(self):
        return dict(inspections={'password_storage':lambda *a,**k:None},peer_check=lambda *a,**k:True)

    def test_security_resolves_after_bootstrap_with_owned_guard_and_deadlines(self):
        events=[];context={};broker=object();configuration=self.security_options()
        def resolver(box,**kwargs):
            self.assertTrue(box.creation_attempted);self.assertEqual(len(self.commands),1)
            self.assertIsInstance(kwargs['guard'],FakeGuard);context.update(kwargs)
            events.append('resolve');return configuration
        class Runtime:
            def __init__(inner,directory,box,guard,**kwargs):
                self.assertIs(guard,context['guard'])
                self.assertIs(kwargs['inspections'],configuration['inspections'])
                self.assertEqual(kwargs['monotonic_deadline'],context['monotonic_deadline'])
                self.assertEqual(kwargs['wall_deadline'],context['wall_deadline'])
                inner.broker=broker
            def close(inner):events.append('security-close')
        def runner(attempt,suite,target,**kwargs):
            self.assertEqual(set(target),{'base_url'});self.assertIs(kwargs['security_broker'],broker)
            events.append('grade');return {'criteria':{'AC-004':{'verdict':'pass'}},'project_success':False}
        def release(guard):events.append('guard-release');return {'remote_termination_verified':True}
        with patch.object(FakeGuard,'release',release),Attempt(self.root/'security-bound',{}) as attempt:
            report=self.run_grade(attempt,runner=runner,security_observer=resolver,security_runtime_factory=Runtime)
        self.assertEqual(events,['resolve','grade','security-close','guard-release'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_security_closes_before_other_parent_resources_and_guard(self):
        events=[]
        class Security:
            def __init__(inner,*a,**k):inner.broker=object()
            def close(inner):events.append('security-close')
        class Jobs:
            def __init__(inner,*a,**k):inner.broker=object()
            def close(inner):events.append('job-close')
        def release(guard):events.append('guard-release');return {'remote_termination_verified':True}
        with patch.object(FakeGuard,'release',release),Attempt(self.root/'security-order',{}) as attempt:
            self.run_grade(attempt,security_observer=lambda *a,**k:self.security_options(),security_runtime_factory=Security,
                job_observer=lambda box:self.job_options(),job_runtime_factory=Jobs)
        self.assertEqual(events,['security-close','job-close','guard-release'])

    def test_later_resolver_failure_closes_security_before_guard(self):
        events=[]
        class Security:
            def __init__(inner,*a,**k):inner.broker=object()
            def close(inner):events.append('security-close')
        def broken(box):raise RuntimeError('private-later-security-secret')
        def release(guard):events.append('guard-release');return {'remote_termination_verified':True}
        with patch.object(FakeGuard,'release',release),Attempt(self.root/'security-later-failure',{}) as attempt:
            result=self.run_grade(attempt,security_observer=lambda *a,**k:self.security_options(),security_runtime_factory=Security,
                browser_resolver=broken)
        self.assertEqual(events,['security-close','guard-release'])
        self.assertTrue(result['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-later-security-secret',str(result))

    def test_security_default_constructs_no_capability(self):
        def unexpected(*args,**kwargs):self.fail('Default created security runtime')
        with Attempt(self.root/'security-default',{}) as attempt:
            self.run_grade(attempt,security_runtime_factory=unexpected)

    def test_static_security_configuration_refused_before_sandbox_creation(self):
        count=len(FakeSandbox.instances)
        with Attempt(self.root/'security-static',{}) as attempt,self.assertRaises(ValueError):
            self.run_grade(attempt,security_observer={})
        self.assertEqual(len(FakeSandbox.instances),count)

    def test_failed_bootstrap_never_resolves_security(self):
        def unexpected(*args,**kwargs):self.fail('Security resolver called without bootstrap')
        with Attempt(self.root/'security-bootstrap-failed',{}) as attempt:
            result=self.run_grade(attempt,bootstrap='failed',security_observer=unexpected)
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_malformed_security_configuration_disposes_sandbox_without_grading(self):
        configurations=[{},dict(self.security_options(),inspections={}),dict(self.security_options(),peer_check=None),
                        dict(self.security_options(),inspections={'builder-command':lambda:None}),
                        dict(self.security_options(),inspections={'password_storage':None}),dict(self.security_options(),credentials='private')]
        for index,configuration in enumerate(configurations):
            if index:(self.root/'project').rename(self.root/('security-old-project-'+str(index)))
            def unexpected(*args,**kwargs):self.fail('Malformed security scope used')
            with Attempt(self.root/('security-malformed-'+str(index)),{}) as attempt:
                result=self.run_grade(attempt,runner=unexpected,security_observer=lambda *a,**k:configuration,security_runtime_factory=unexpected)
            self.assertEqual(result['error_type'],'ValueError')
            self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_security_close_failure_cannot_accept_and_still_releases_guard(self):
        class Runtime:
            def __init__(inner,*a,**k):inner.broker=object()
            def close(inner):raise RuntimeError('private-security-credential')
        self.suite.approved=True
        with Attempt(self.root/'security-close-broken',{}) as attempt:
            result=self.run_grade(attempt,security_observer=lambda *a,**k:self.security_options(),security_runtime_factory=Runtime)
        self.assertFalse(result['project_success']);self.assertEqual(result['accepted_packages'],[])
        self.assertEqual(result['security_cleanup_error'],'RuntimeError')
        self.assertTrue(result['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-security-credential',str(result))

    def test_security_initialization_failure_still_disposes_sandbox(self):
        def broken(*args,**kwargs):raise ValueError('private-security-binding')
        with Attempt(self.root/'security-binding-failed',{}) as attempt:
            result=self.run_grade(attempt,security_observer=lambda *a,**k:self.security_options(),security_runtime_factory=broken)
        self.assertEqual(result['outcome'],'grading_incomplete')
        self.assertTrue(result['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-security-binding',str(result))

    def test_staging_default_does_not_construct_capability(self):
        def unexpected(*args,**kwargs):self.fail('Default created staging capability')
        with Attempt(self.root/'staging-default',{}) as attempt:
            report=self.run_grade(attempt,staging_runtime_factory=unexpected)
        self.assertEqual(report['outcome'],'graded')

    def test_staging_requires_boolean_and_all_trusted_resolvers_before_creation(self):
        count=len(FakeSandbox.instances)
        for index,extras in enumerate((dict(job_staging=1),dict(job_staging=True),
                                      dict(job_staging=True,fault_workloads={},fault_service_probes=lambda box:{},job_observer=lambda box:{}))):
            with Attempt(self.root/('staging-invalid-'+str(index)),{}) as attempt,self.assertRaises(ValueError):
                self.run_grade(attempt,**extras)
        self.assertEqual(len(FakeSandbox.instances),count)

    def test_failed_bootstrap_never_resolves_staging_inputs(self):
        def unexpected(*args,**kwargs):self.fail('Staging prepared without successful bootstrap')
        with Attempt(self.root/'staging-no-bootstrap',{}) as attempt:
            report=self.run_grade(attempt,bootstrap='failed',job_staging=True,fault_workloads=unexpected,
                fault_service_probes=unexpected,job_observer=unexpected,staging_runtime_factory=unexpected)
        self.assertTrue(report['cleanup']['remote_termination_verified'])

    def test_staging_close_failure_revokes_acceptance_without_skipping_parent_cleanup(self):
        events=[];extras=self.staging_extras(events)
        class Broken:
            def __init__(inner,*args,**kwargs):inner.broker=object()
            def close(inner):events.append('stage-close');raise RuntimeError('private-staging-credential')
        extras['staging_runtime_factory']=Broken;self.suite.approved=True
        with Attempt(self.root/'staging-close-broken',{}) as attempt:
            report=self.run_grade(attempt,**extras)
        self.assertEqual(events[-3:],['stage-close','job-close','fault-close'])
        self.assertEqual(report['staging_cleanup_error'],'RuntimeError')
        self.assertFalse(report['project_success']);self.assertEqual(report['accepted_packages'],[])
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-staging-credential',str(report))

    def test_staging_binding_failure_disposes_already_bound_parent_capabilities(self):
        events=[];extras=self.staging_extras(events)
        def broken(*args,**kwargs):raise ValueError('private-staging-binding')
        extras['staging_runtime_factory']=broken
        with Attempt(self.root/'staging-bind-broken',{}) as attempt:
            report=self.run_grade(attempt,**extras)
        self.assertEqual(events[-2:],['job-close','fault-close'])
        self.assertTrue(report['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-staging-binding',str(report))


    def test_post_bootstrap_fixture_loader_receives_guard_and_fixed_origin(self):
        observations=[]
        fixture={'accounts':{'analyst':{'username':'independent','password':'synthetic'}},
                 'twenty_export_fixture':{'case':{'title':'independently seeded'},'patterns':{'synthetic-id':'synthetic bytes'}},
                 'integrated_fixture':{'identities':{'users':[{'username':'independent journey actor'}]},
                                       'actors':{'alpha':{'analyst':'independent actor identity'}}},
                 'network_fixture':{'cluster':{'uid':'independently observed cluster'},
                                    'roles':{'api':{'pods':['independent api pod']}}},
                 'foundation_fixture':{'cluster':{'uid':'independent foundation cluster'},
                                       'components':{'database':{'image':'locked digest'}}},
                 'documentation_fixture':{'documents':{'operations':{'sha256':'a'*64}},
                                          'checks':{'bootstrap':{'exit_code':0}}},
                 'attestation_fixture':{'source':{'sha256':'b'*64},
                                        'runtime':{'cluster_uid':'independent runtime'}},
                 'disposal_fixture':{'verdict':'pass','abort_suite':False},
                 'authentication_fixture':{'documented_local_http':True}}
        def loader(box, **context):
            self.assertEqual(len(self.commands),1)
            self.assertIsInstance(context['guard'],FakeGuard)
            self.assertEqual(context['base_url'],'http://127.0.0.1:18080')
            self.assertGreater(context['monotonic_deadline'],0)
            self.assertGreater(context['wall_deadline'],0)
            self.assertTrue(context['lifetime_check'](10))
            observations.append(box.name)
            return fixture
        def runner(attempt,suite,target,**kwargs):
            self.assertEqual(target['accounts'],fixture['accounts'])
            self.assertIsNot(target['accounts'],fixture['accounts'])
            self.assertEqual(target['twenty_export_fixture'],fixture['twenty_export_fixture'])
            target['twenty_export_fixture']['case']['title']='worker-side change'
            self.assertEqual(fixture['twenty_export_fixture']['case']['title'],'independently seeded')
            self.assertEqual(target['integrated_fixture'],fixture['integrated_fixture'])
            target['integrated_fixture']['identities']['users'][0]['username']='worker-side change'
            self.assertEqual(fixture['integrated_fixture']['identities']['users'][0]['username'],
                             'independent journey actor')
            self.assertEqual(target['network_fixture'],fixture['network_fixture'])
            target['network_fixture']['roles']['api']['pods'].append('worker-side pod')
            self.assertEqual(fixture['network_fixture']['roles']['api']['pods'],
                             ['independent api pod'])
            self.assertEqual(target['foundation_fixture'],fixture['foundation_fixture'])
            target['foundation_fixture']['components']['database']['image']='worker-side digest'
            self.assertEqual(fixture['foundation_fixture']['components']['database']['image'],
                             'locked digest')
            self.assertEqual(target['documentation_fixture'],fixture['documentation_fixture'])
            target['documentation_fixture']['checks']['bootstrap']['exit_code']=1
            self.assertEqual(fixture['documentation_fixture']['checks']['bootstrap']['exit_code'],0)
            self.assertEqual(target['attestation_fixture'],fixture['attestation_fixture'])
            target['attestation_fixture']['source']['sha256']='c'*64
            self.assertEqual(fixture['attestation_fixture']['source']['sha256'],'b'*64)
            self.assertEqual(target['disposal_fixture'],fixture['disposal_fixture'])
            target['disposal_fixture']['verdict']='fail'
            self.assertEqual(fixture['disposal_fixture']['verdict'],'pass')
            self.assertEqual(target['authentication_fixture'],fixture['authentication_fixture'])
            target['authentication_fixture']['documented_local_http']=False
            self.assertIs(fixture['authentication_fixture']['documented_local_http'],True)
            self.assertEqual(target['base_url'],'http://127.0.0.1:18080')
            return {'criteria':{},'project_success':False,'accepted_packages':[]}
        with Attempt(self.root/'fixtures',{}) as attempt:
            result=self.run_grade(attempt,fixture_loader=loader,runner=runner)
        self.assertEqual(len(observations),1)
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_fixture_loader_accepts_boolean_isolated_membership_declaration(self):
        for index,flag in enumerate((True,False)):
            def runner(attempt,suite,target,**kwargs):
                self.assertIs(target['isolated_membership_fixture'],flag)
                return {'criteria':{},'accepted_packages':[],'project_success':False,'case_results':{}}
            with Attempt(self.root/('membership-flag-'+str(index)),{}) as attempt:
                report=self.run_grade(attempt,fixture_loader=lambda *args,**kwargs:
                    {'isolated_membership_fixture':flag},runner=runner)
            self.assertNotEqual(report.get('reason'),'grading_unavailable')
            self.assertTrue(report['cleanup']['remote_termination_verified'])
            shutil.rmtree(self.root/'project')

    def test_fixture_loader_refuses_malformed_isolated_membership_declaration(self):
        def forbidden(*args,**kwargs):raise AssertionError('Malformed declaration must not grade')
        for index,flag in enumerate((1,'true',None,{},[])):
            with Attempt(self.root/('invalid-membership-flag-'+str(index)),{}) as attempt:
                report=self.run_grade(attempt,fixture_loader=lambda *args,**kwargs:
                    {'isolated_membership_fixture':flag},runner=forbidden)
            self.assertEqual(report['reason'],'grading_unavailable')
            self.assertTrue(report['cleanup']['remote_termination_verified'])
            shutil.rmtree(self.root/'project')

    def test_fixture_loader_not_called_after_failed_bootstrap(self):
        def loader(*args,**kwargs):self.fail('Fixture loader ran after failed bootstrap')
        with Attempt(self.root/'fixtures-no-bootstrap',{}) as attempt:
            result=self.run_grade(attempt,bootstrap='failed',fixture_loader=loader)
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_invalid_fixture_loader_refused_before_sandbox_creation(self):
        count=len(FakeSandbox.instances)
        with Attempt(self.root/'fixtures-invalid-callback',{}) as attempt,self.assertRaises(ValueError):
            self.run_grade(attempt,fixture_loader={})
        self.assertEqual(len(FakeSandbox.instances),count)

    def test_fixture_loader_cannot_redirect_or_inject_capabilities(self):
        for index,value in enumerate(({},None,{'base_url':'https://elsewhere.invalid'},
                                      {'job_broker':{}},{'accounts':[]},
                                      {'accounts':{},'browser_executor':{}})):
            def runner(*args,**kwargs):self.fail('Invalid fixture configuration reached grader')
            with Attempt(self.root/('fixtures-invalid-'+str(index)),{}) as attempt:
                result=self.run_grade(attempt,fixture_loader=lambda *args,**kwargs:value,runner=runner)
            self.assertEqual(result['outcome'],'grading_incomplete')
            self.assertTrue(result['cleanup']['remote_termination_verified'])
            shutil.rmtree(self.root/'project')

    def test_fixture_loader_error_is_sanitized_and_cleanup_runs(self):
        def loader(*args,**kwargs):raise RuntimeError('private-fixture-credential')
        def runner(*args,**kwargs):self.fail('Grading ran without fixture preparation')
        with Attempt(self.root/'fixtures-error',{}) as attempt:
            result=self.run_grade(attempt,fixture_loader=loader,runner=runner)
        self.assertTrue(result['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-fixture-credential',str(result))


    def test_fixture_preparation_consumes_existing_grading_deadline(self):
        with patch('evaluation.deployment.time.monotonic',return_value=10) as clock:
            def loader(*args,**kwargs):
                clock.return_value=6000
                return {'accounts':{}}
            def runner(*args,**kwargs):self.fail('Grading ran after fixture preparation exhausted budget')
            with Attempt(self.root/'fixtures-budget',{}) as attempt:
                result=self.run_grade(attempt,fixture_loader=loader,runner=runner)
        self.assertEqual(result['outcome'],'grading_incomplete')
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_fixture_lifetime_loss_refuses_grading_and_restores_cleanup_scope(self):
        mutations = ('name', 'project', 'specification', 'creation_attempted',
                     'directory', 'process', 'nonce', 'config', 'release', 'result', 'exit')
        for index, mutation in enumerate(mutations):
            with self.subTest(mutation=mutation):
                originals = {}
                def loader(box, **context):
                    guard = context['guard']
                    originals.update(name=box.name, project=box.project,
                                     specification=box.specification, directory=guard.directory,
                                     process=guard.process, nonce=guard.nonce)
                    if mutation in ('name', 'project', 'specification'):
                        setattr(box, mutation, 'unowned-resource')
                    elif mutation == 'creation_attempted':
                        box.creation_attempted = False
                    elif mutation == 'directory':
                        guard.directory = self.root / 'unowned-guard'
                    elif mutation == 'process':
                        guard.process = SimpleNamespace(poll=lambda: None)
                    elif mutation == 'nonce':
                        guard.nonce = '1' * 32
                    elif mutation == 'config':
                        (guard.directory / 'config.json').write_text('{}')
                    elif mutation in ('release', 'result'):
                        (guard.directory / (mutation + '.json')).write_text('{}')
                    else:
                        guard.process.poll = lambda: 0
                    return {'accounts': {}}
                def runner(*args, **kwargs):
                    self.fail('Grading ran after fixture lifetime loss')
                with Attempt(self.root / ('lifetime-' + str(index)), {}) as attempt:
                    result = self.run_grade(attempt, fixture_loader=loader, runner=runner)
                box = FakeSandbox.instances[-1]
                for key in ('name', 'project', 'specification'):
                    self.assertEqual(getattr(box, key), originals[key])
                self.assertTrue(box.creation_attempted)
                self.assertEqual(result['outcome'], 'grading_incomplete')
                self.assertTrue(result['cleanup']['remote_termination_verified'])
                shutil.rmtree(self.root / 'project')

    def test_fixture_checker_reserves_owner_and_watchdog_expiry(self):
        from evaluation.fixture_lifetime import FixtureLifetime
        from evaluation.verdicts import Inconclusive
        from evaluation.evidence import atomic_json
        import json
        box = FakeSandbox('unused', self.root / 'project', self.spec)
        box.create()
        guard = FakeGuard(self.root / 'direct-guard', box.name)
        config = json.loads((guard.directory / 'config.json').read_text())
        config['expires_at'] = 150
        atomic_json(guard.directory / 'config.json', config)
        lifetime = FixtureLifetime(box, guard, monotonic_deadline=200,
                                   wall_deadline=200, monotonic=lambda: 100,
                                   wall=lambda: 100)
        self.assertIs(lifetime.check(49), True)
        with self.assertRaises(Inconclusive):
            lifetime.check(50)
        for reserve in (True, -1, float('nan'), float('inf'), '1'):
            with self.subTest(reserve=reserve), self.assertRaises(ValueError):
                lifetime.check(reserve)
        with patch('evaluation.fixture_lifetime.os.getpid', return_value=os.getpid()+1):
            with self.assertRaises(Inconclusive):
                lifetime.check()
        for invalid in (float('nan'), float('inf'), True):
            for clock in ('monotonic', 'wall'):
                original_clock = getattr(lifetime, clock)
                setattr(lifetime, clock, lambda: invalid)
                with self.subTest(clock=clock, invalid=invalid), self.assertRaises(Inconclusive):
                    lifetime.check()
                setattr(lifetime, clock, original_clock)
        box.stopped = True
        with self.assertRaises(Inconclusive):
            lifetime.check()
        lifetime.restore_scope()
        self.assertTrue(box.stopped)

    def test_fixture_callback_error_restores_owned_scope(self):
        original = {}
        def loader(box, **context):
            original['name'] = box.name
            box.name = 'unowned-resource'
            context['guard'].directory = self.root / 'unowned-guard'
            raise RuntimeError('private-callback-error')
        with Attempt(self.root / 'fixture-error-scope', {}) as attempt:
            result = self.run_grade(attempt, fixture_loader=loader)
        self.assertEqual(FakeSandbox.instances[-1].name, original['name'])
        self.assertTrue(result['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-callback-error', str(result))

    def test_fixture_wall_deadline_expires_without_monotonic_expiry(self):
        with patch('evaluation.deployment.time.time', return_value=100) as clock:
            def loader(*args, **kwargs):
                clock.return_value = 10000
                return {'accounts': {}}
            def runner(*args, **kwargs):
                self.fail('Grading ran after wall deadline')
            with Attempt(self.root / 'fixture-wall-expiry', {}) as attempt:
                result = self.run_grade(attempt, fixture_loader=loader, runner=runner)
        self.assertEqual(result['outcome'], 'grading_incomplete')
        self.assertTrue(result['cleanup']['remote_termination_verified'])

    def test_operations_bound_after_bootstrap_and_closed_before_guard(self):
        order=[]
        class Runtime:
            broker=object()
            def __init__(inner,*args,**kwargs):
                order.append('bound')
                self.assertEqual(len(self.commands),1)
            def close(inner):order.append('closed')
        def resolver(box,**kwargs):
            self.assertEqual(kwargs['base_url'],'http://127.0.0.1:18080')
            return dict(observe=lambda:None,verify=lambda:None,expected_case={'id':'independent'},source_check=lambda:True)
        def runner(*args,**kwargs):
            self.assertIs(kwargs['ops_broker'],Runtime.broker)
            order.append('graded')
            return dict(criteria={},project_success=True,accepted_packages=[])
        with patch.object(FakeGuard,'release',side_effect=lambda:order.append('released') or {'remote_termination_verified':True}):
            with Attempt(self.root/'logs',{}) as attempt:
                self.run_grade(attempt,runner=runner,ops_resolver=resolver,ops_runtime_factory=Runtime)
        self.assertEqual(order,['bound','graded','closed','released'])

    def test_operations_cleanup_failure_revokes_acceptance_and_still_disposes(self):
        class Runtime:
            broker=object()
            def __init__(self,*args,**kwargs):pass
            def close(self):raise RuntimeError('private detail')
        config=dict(observe=lambda:None,verify=lambda:None,expected_case={'id':'x'},source_check=lambda:True)
        with Attempt(self.root/'logs',{}) as attempt:
            result=self.run_grade(attempt,ops_resolver=lambda *args,**kwargs:config,ops_runtime_factory=Runtime)
        self.assertEqual(result['outcome'],'grading_incomplete')
        self.assertFalse(result['project_success'])
        self.assertEqual(result['accepted_packages'],[])
        self.assertEqual(result['ops_cleanup_error'],'RuntimeError')
        self.assertTrue(result['cleanup']['remote_termination_verified'])


class DeploymentDenominatorTest(unittest.TestCase):
    setUp = DeploymentTest.setUp
    run_grade = DeploymentTest.run_grade
    def test_actual_registry_denominators_survive_preparation_failure(self):
        import hashlib
        import json
        from evaluation.evidence import atomic_json
        from evaluation.grading import Suite
        packages=[dict(id='WP-001',criteria=['AC-001']),
                  dict(id='WP-002',criteria=['AC-004'])]
        source='def check(target): pass\n'
        (self.suite.root/'check.py').write_text(source)
        atomic_json(self.suite.root/'suite.json',dict(schema_version=1,
            packages_sha256=hashlib.sha256(json.dumps(packages,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
            files={'check.py':hashlib.sha256(source.encode()).hexdigest()},
            cases=[dict(id='foundation',source='check.py',function='check',criteria=['AC-001'],timeout_seconds=10),
                   dict(id='session',source='check.py',function='check',criteria=['AC-004'],timeout_seconds=10)],
            coverage_complete=['AC-001','AC-004']))
        self.suite=Suite(self.suite.root,packages)
        def loader(*args,**kwargs):raise RuntimeError('private-canary-credential')
        def runner(*args,**kwargs):self.fail('Protected worker ran after preparation failure')
        with Attempt(self.root/'denominator-logs',{}) as attempt:
            result=self.run_grade(attempt,fixture_loader=loader,runner=runner)
            persisted=json.loads((attempt.directory/'deployment-result.json').read_text())
        self.assertEqual(result,persisted)
        self.assertEqual(set(result['criteria']),{'AC-001','AC-004'})
        self.assertEqual({r['verdict'] for r in result['criteria'].values()},{'untested'})
        self.assertEqual(result['case_results'],{})
        self.assertEqual(result['accepted_packages'],[])
        self.assertEqual(result['development_passing_packages'],[])
        self.assertTrue(result['aborted'])
        self.assertEqual(result['reason'],'grading_unavailable')
        self.assertTrue(result['cleanup']['remote_termination_verified'])
        self.assertNotIn('private-canary-credential',str(result))

    def test_cleanup_loss_cannot_retain_accepted_packages(self):
        self.suite.approved=True
        FakeGuard.stopped=False
        with patch.object(FakeSandbox,'stop',return_value=False), Attempt(self.root/'denominator-cleanup',{}) as attempt:
            result=self.run_grade(attempt)
        self.assertEqual(result['outcome'],'cleanup_incomplete')
        self.assertEqual(result['accepted_packages'],[])
        self.assertFalse(result['project_success'])
        self.assertTrue(result['aborted'])
