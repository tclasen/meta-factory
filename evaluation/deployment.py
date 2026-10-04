"""Redeploy captured source only inside a guarded, disposable grading sandbox."""

from pathlib import Path
import time

from .evidence import atomic_json, collect, positive
from .fault_runtime import FaultRuntime
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
                  fault_runtime_factory=FaultRuntime):
    """No model execution. Application scripts run only in the named grading sbx.

    The source must already have been captured after builder termination. Callers
    freeze deadlines and approve the suite before final grading. Development mode
    never grants acceptance and is for synthetic preflights or grader development.
    Factory injection supports deterministic lifecycle/failure tests, not CLI bypasses.
    """
    positive(bootstrap_seconds, 'bootstrap timeout')
    positive(grading_seconds, 'grading timeout')
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
        options = {}
        if fault_workloads is not None:
            # Fresh workload UIDs exist only after bootstrap. An operator-owned
            # resolver may inspect the live deployment here; never use app output
            # as executable configuration or as an authoritative role mapping.
            selected_workloads = fault_workloads(box) if callable(fault_workloads) else fault_workloads
            fault_runtime = fault_runtime_factory(attempt.directory / 'faults', box, guard,
                selected_workloads, kubectl_prefix,
                monotonic_deadline=grading_started + grading_seconds,
                wall_deadline=grading_wall_started + grading_seconds)
            options['fault_broker'] = fault_runtime.broker
        remaining = grading_seconds - (time.monotonic() - grading_started)
        if remaining <= 0:
            raise TimeoutError('Grading budget consumed by fault preparation')
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
