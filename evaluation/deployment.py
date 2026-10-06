"""Redeploy captured source only inside a guarded, disposable grading sandbox."""

from pathlib import Path
import copy
import time

from .evidence import atomic_json, collect, positive
from .fault_runtime import FaultRuntime
from .fixture_lifetime import FixtureLifetime
from .audit_runtime import AuditRuntime
from .job_runtime import JobRuntime
from .staging_runtime import StagingRuntime
from .security_runtime import SecurityRuntime
from .ops_runtime import OpsRuntime
from .security_broker import OPERATIONS as SECURITY_OPERATIONS
from .browser_binding import BrowserBinding
from .grading import run_suite, sha256
from .sandbox import Sandbox, capture_tree, disjoint, symlink_record
from .watchdog import Guard


def verify_capture(source, inventory):
    source = Path(source).resolve(strict=True)
    if inventory.get('outcome') != 'captured' or not isinstance(inventory.get('files'), dict):
        raise ValueError('A completed source inventory is required')
    actual = set()
    for path in source.rglob('*'):
        if path.is_symlink():
            relative = str(path.relative_to(source))
            actual.add(relative)
            if symlink_record(source, path) != inventory['files'].get(relative):
                raise ValueError('Captured link changed')
            continue
        if not path.is_dir() and not path.is_file():
            raise ValueError('Unsafe captured artifact')
        if path.is_file():
            relative = str(path.relative_to(source))
            actual.add(relative)
            expected = inventory['files'].get(relative)
            if (not expected or expected.get('kind', 'file') != 'file'
                    or sha256(path) != expected['sha256'] or path.stat().st_size != expected['size']
                    or bool(path.stat().st_mode & 0o111) != expected['executable']):
                raise ValueError('Captured artifact changed')
    if actual != set(inventory['files']):
        raise ValueError('Captured files missing')


def grade_capture(attempt, source, inventory, specification, project, suite, target, *,
                  port, bootstrap_seconds=1800, grading_seconds=5400, development=False,
                  sandbox_factory=Sandbox, guard_factory=Guard, command_runner=collect,
                  suite_runner=run_suite, fault_workloads=None, kubectl_prefix=None,
                  fault_runtime_factory=FaultRuntime, fault_service_probes=None,
                  fault_audit=None, audit_observer=None, audit_runtime_factory=AuditRuntime,
                  browser_resolver=None, browser_binding_factory=BrowserBinding,
                  fault_storage_worker_restart=False, job_observer=None,
                  job_runtime_factory=JobRuntime, job_staging=False, staging_runtime_factory=StagingRuntime,
                  security_observer=None, security_runtime_factory=SecurityRuntime, fixture_loader=None,
                  ops_resolver=None, ops_runtime_factory=OpsRuntime):
    """No model execution. Application scripts run only in the named grading sbx.

    The source must already have been captured after builder termination. Callers
    freeze deadlines and approve the suite before final grading. Development mode
    never grants acceptance and is for synthetic preflights or grader development.
    Factory injection supports deterministic lifecycle/failure tests, not CLI bypasses.
    """
    if ops_resolver is not None and not callable(ops_resolver):
        raise ValueError("Operations require a trusted post-bootstrap resolver")
    if fixture_loader is not None and not callable(fixture_loader):
        raise ValueError('Fixture loading requires a trusted post-bootstrap callback')
    if type(job_staging) is not bool:
        raise ValueError('Job staging selection must be a boolean')
    if job_staging and not all(callable(callback) for callback in (fault_workloads, fault_service_probes, job_observer)):
        raise ValueError('Job staging requires trusted post-bootstrap workload, service and job resolvers')
    if type(fault_storage_worker_restart) is not bool:
        raise ValueError('Compound fault selection must be a boolean')
    if fault_storage_worker_restart and (not callable(fault_workloads) or not callable(fault_service_probes)):
        raise ValueError('Compound faults require trusted post-bootstrap workload and service resolvers')
    positive(bootstrap_seconds, 'bootstrap timeout')
    positive(grading_seconds, 'grading timeout')
    if audit_observer is not None and not callable(audit_observer):
        raise ValueError('Audit observation requires a trusted post-bootstrap resolver')
    if job_observer is not None and not callable(job_observer):
        raise ValueError('Job observation requires a trusted post-bootstrap resolver')
    if security_observer is not None and not callable(security_observer):
        raise ValueError('Security inspection requires a trusted post-bootstrap resolver')
    if browser_resolver is not None and not callable(browser_resolver):
        raise ValueError('Browser configuration requires a trusted post-bootstrap resolver')
    if fault_audit is not None and not callable(fault_audit):
        raise ValueError('Audit configuration requires a trusted post-bootstrap resolver')
    grading_started = time.monotonic()
    grading_wall_started = time.time()
    lifetime = grading_seconds + 120
    if lifetime > 26 * 3600:
        raise ValueError('Grading lifetime exceeds watchdog envelope')
    if not suite.approved and not development:
        raise ValueError('Protected suite review is required')
    suite.verify()
    source, specification = Path(source).resolve(strict=True), Path(specification).resolve(strict=True)
    project = Path(project).resolve()
    repository = Path(__file__).resolve().parents[1]
    # Suite and evidence must not be visible through either app mount.
    for mount in (project, specification):
        for protected in (suite.root, attempt.directory, repository):
            disjoint(mount, protected)
    verify_capture(source, inventory)
    copied = capture_tree(source, project, termination_verified=True)
    if copied['files'] != inventory['files']:
        raise ValueError('Redeployment copy differs from frozen capture')
    atomic_json(attempt.directory / 'redeployment-source.json', copied)
    box = sandbox_factory(attempt, project, specification, repository, port=port, role='grader')
    guard = None
    fault_runtime = None
    audit_runtime = None
    job_runtime = None
    staging_runtime = None
    ops_runtime = None
    security_runtime = None
    browser_binding = None
    report = {'outcome': 'grading_incomplete', 'project_success': False}
    cleanup = {'remote_termination_verified': False}
    try:
        created = box.create()
        if created['outcome'] != 'passed':
            raise RuntimeError('Grading sandbox creation failed')
        remaining = grading_seconds - (time.monotonic() - grading_started)
        if remaining <= 0:
            raise TimeoutError('Grading budget consumed before deployment')
        guard = guard_factory(attempt.directory / 'grading-guard', box.name, max_seconds=remaining + 120)
        command = box.exec_argv(['./ops/bootstrap.sh'])
        bootstrap = command_runner(attempt, 'grading-bootstrap', command, cwd=repository, timeout=min(bootstrap_seconds, remaining))
        atomic_json(attempt.directory / 'grading-bootstrap-result.json', bootstrap)
        if bootstrap['outcome'] != 'passed':
            report['reason'] = 'bootstrap_' + bootstrap['outcome']
            return report
        # Never accept a builder-supplied URL that sends grading fixtures elsewhere.
        target = dict(target, base_url=f'http://127.0.0.1:{port}')
        remaining = grading_seconds - (time.monotonic() - grading_started)
        if remaining <= 0:
            raise TimeoutError('Grading budget consumed by deployment')
        if fixture_loader is not None:
            # This operator callback owns bounded fixture creation and independent
            # expected resources. It never receives or selects an executable from
            # application output, and cannot redirect the HTTP grading origin.
            fixture_lifetime = FixtureLifetime(box, guard,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds,
                monotonic=time.monotonic, wall=time.time)
            try:
                fixture = fixture_loader(box, guard=guard, base_url=target['base_url'],
                    monotonic_deadline=grading_started + grading_seconds,
                    wall_deadline=grading_wall_started + grading_seconds,
                    lifetime_check=fixture_lifetime.check)
                fixture_lifetime.check()
            finally:
                fixture_lifetime.restore_scope()
            allowed = {'tenants', 'accounts', 'scale_cases', 'performance_fixture',
                       'twenty_export_fixture', 'integrated_fixture', 'network_fixture',
                       'foundation_fixture', 'documentation_fixture',
                       'attestation_fixture', 'disposal_fixture'}
            if (not isinstance(fixture, dict) or not fixture
                    or not set(fixture) <= allowed
                    or not all(isinstance(value, dict) for value in fixture.values())):
                raise ValueError('Incomplete post-bootstrap fixture configuration')
            target = dict(target, **copy.deepcopy(fixture))
            remaining = grading_seconds - (time.monotonic() - grading_started)
            if remaining <= 0:
                raise TimeoutError('Grading budget consumed by fixture preparation')
        options = {}
        if ops_resolver is not None:
            ops_options = ops_resolver(box, guard=guard, base_url=target['base_url'],
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds)
            required = {'observe', 'verify', 'expected_case', 'source_check'}
            if (not isinstance(ops_options, dict) or not required <= set(ops_options)
                    or not set(ops_options) <= required | {'timeout'}):
                raise ValueError('Incomplete post-bootstrap operations configuration')
            ops_runtime = ops_runtime_factory(attempt.directory / 'operations', box, guard,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds, **ops_options)
            options['ops_broker'] = ops_runtime.broker
        if fault_workloads is not None or fault_audit is not None:
            # Fresh workload UIDs exist only after bootstrap. An operator-owned
            # resolver may inspect the live deployment here; never use app output
            # as executable configuration or as an authoritative role mapping.
            selected_workloads = fault_workloads(box) if callable(fault_workloads) else fault_workloads
            if selected_workloads is None:
                selected_workloads = {}
            service_probes = fault_service_probes(box) if callable(fault_service_probes) else fault_service_probes
            audit_options = {} if fault_audit is None else fault_audit(box)
            if (not isinstance(audit_options, dict)
                    or fault_audit is not None and set(audit_options) != {
                        'audit_binding', 'database_peer', 'database_peer_check'}):
                raise ValueError('Incomplete post-bootstrap audit configuration')
            if fault_audit is not None and audit_options['audit_binding'] is None:
                raise ValueError('Post-bootstrap audit binding unavailable')
            prefix = ['kubectl'] if kubectl_prefix is None and fault_workloads is None else kubectl_prefix
            fault_runtime = fault_runtime_factory(attempt.directory / 'faults', box, guard,
                selected_workloads, prefix,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds, service_probes=service_probes,
                **audit_options, **({'storage_worker_restart': True} if fault_storage_worker_restart or job_staging else {}))
            options['fault_broker'] = fault_runtime.broker
        if audit_observer is not None:
            audit_options = audit_observer(box)
            if (not isinstance(audit_options, dict) or set(audit_options) != {
                    'audit_binding', 'database_peer', 'database_peer_check'}
                    or audit_options['audit_binding'] is None):
                raise ValueError('Incomplete post-bootstrap audit observation configuration')
            audit_runtime = audit_runtime_factory(attempt.directory / 'audit-observations', box, guard,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds, **audit_options)
            options['audit_broker'] = audit_runtime.broker
        if job_observer is not None:
            job_options = job_observer(box)
            required = {'database_read', 'artifact_count', 'database_peer_check', 'storage_peer_check'}
            if (not isinstance(job_options, dict) or set(job_options) != required
                    or not all(callable(job_options[key]) for key in required)):
                raise ValueError('Incomplete post-bootstrap job observation configuration')
            job_runtime = job_runtime_factory(attempt.directory / 'job-observations', box, guard,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds, **job_options)
            options['job_broker'] = job_runtime.broker
        if job_staging:
            staging_runtime = staging_runtime_factory(attempt.directory / 'job-staging', fault_runtime, job_runtime=job_runtime)
            options['staging_broker'] = staging_runtime.broker
        if security_observer is not None:
            security_options = security_observer(box, guard=guard,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds)
            if (not isinstance(security_options, dict) or set(security_options) != {'inspections', 'peer_check'}
                    or not isinstance(security_options['inspections'], dict) or not security_options['inspections']
                    or not set(security_options['inspections']) <= SECURITY_OPERATIONS
                    or not all(callable(reader) for reader in security_options['inspections'].values())
                    or not callable(security_options['peer_check'])):
                raise ValueError('Incomplete post-bootstrap security inspection configuration')
            security_runtime = security_runtime_factory(attempt.directory / 'security-observations', box, guard,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds, **security_options)
            options['security_broker'] = security_runtime.broker
        if browser_resolver is not None:
            browser_configuration = browser_resolver(box)
            browser_binding = browser_binding_factory(box, guard, browser_configuration,
                base_url=target['base_url'], monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds)
            options['browser_executor'] = browser_binding
        remaining = grading_seconds - (time.monotonic() - grading_started)
        if remaining <= 0:
            raise TimeoutError('Grading budget consumed by capability preparation')
        report = suite_runner(attempt, suite, target, deadline_seconds=remaining,
                              development=development, **options)
        report['outcome'] = ('graded' if all(c['verdict'] in ('pass', 'fail') for c in report['criteria'].values())
                             else 'grading_incomplete')
        if not suite.approved:
            report['project_success'] = False
            report['accepted_packages'] = []
    except Exception as error:
        report.update(outcome='grading_incomplete', project_success=False, error_type=type(error).__name__)
    finally:
        if ops_runtime is not None:
            try:
                ops_runtime.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[], ops_cleanup_error=type(error).__name__)
        if security_runtime is not None:
            try:
                security_runtime.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[], security_cleanup_error=type(error).__name__)
        if browser_binding is not None:
            try:
                browser_binding.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[], browser_cleanup_error=type(error).__name__)
        if staging_runtime is not None:
            try:
                staging_runtime.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[], staging_cleanup_error=type(error).__name__)
        if job_runtime is not None:
            try:
                job_runtime.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[], job_cleanup_error=type(error).__name__)
        if audit_runtime is not None:
            try:
                audit_runtime.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[], audit_cleanup_error=type(error).__name__)
        if fault_runtime is not None:
            try:
                fault_runtime.close()
            except Exception as error:
                report.update(outcome='grading_incomplete', project_success=False,
                              accepted_packages=[],
                              fault_cleanup_error=type(error).__name__)
        if guard is not None:
            try:
                cleanup = guard.release()
                box.stopped = cleanup.get('remote_termination_verified') is True
            except Exception as error:
                cleanup = {'remote_termination_verified': False, 'error_type': type(error).__name__}
        if box.creation_attempted and not box.stopped:
            try:
                verified = box.stop()
                cleanup['fallback_remote_termination_verified'] = verified
                cleanup['remote_termination_verified'] = verified
            except Exception as error:
                cleanup['fallback_error_type'] = type(error).__name__
        if not cleanup.get('remote_termination_verified'):
            report.update(outcome='cleanup_incomplete', project_success=False)
        report['cleanup'] = cleanup
        report['manual_stop'] = ['sbx', 'stop', box.name]
        atomic_json(attempt.directory / 'deployment-result.json', report)
    return report
