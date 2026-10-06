"""Acquire a planned local workspace without provisioning or launch authority."""
import hashlib
import json
import os
from pathlib import Path
import re
import time

from .evidence import atomic_json, positive, private_file
from .plan import controller_identities
from .preparation import prepare_specification, read_regular
from .readiness import audit
from .sandbox import disjoint, sandbox_create_argv


def prepare_workspace(attempt, plan, workload, suite_root, *, monotonic_deadline,
                      wall_deadline, suite_approval=None, host_attempt=None,
                      monotonic=time.monotonic, wall=time.time):
    """One exclusive local acquisition per attempt; retained partial copies.

    Preparation may inspect an incomplete readiness plan, but never changes its
    gates or creates a sandbox. Filesystem I/O needs an outer deadline owner.
    Revalidate again before any subsequent mounting or execution.
    """
    for value in (monotonic_deadline, wall_deadline):
        positive(value, 'workspace deadline')
    encoded = json.dumps(plan, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()
    if len(encoded) > 1024 * 1024:
        raise ValueError('Workspace plan exceeds inspection bound')
    # Detach from mutable caller data for all later checks and receipts.
    plan = json.loads(encoded)
    repository = Path(__file__).resolve().parents[1]
    workload = Path(workload).resolve(strict=True)
    suite_root = Path(suite_root).resolve(strict=True)
    owner = os.getpid()

    def check():
        if os.getpid() != owner or min(monotonic_deadline - monotonic(), wall_deadline - wall()) <= 0:
            raise TimeoutError('Workspace preparation lifetime unavailable')

    if (plan.get('schema_version') != 1 or plan.get('outcome') != 'planned_not_ready'
            or plan.get('launch_enabled') is not False):
        raise ValueError('Nonlaunching resource plan required')
    workspace = Path(plan['workspace'])
    if (not workspace.is_absolute() or workspace != workspace.resolve()
            or not re.fullmatch('factory-eval-[0-9a-f]{16}', workspace.name)):
        raise ValueError('Canonical planned workspace identity required')
    token = workspace.name.removeprefix('factory-eval-')
    paths = {name: workspace / name for name in
             ('builder-project', 'grader-project', 'specification', 'capture')}
    if plan['paths'] != {name: str(path) for name, path in paths.items()}:
        raise ValueError('Workspace paths differ from resource plan')
    old_evidence = Path(plan['evidence']).resolve(strict=True)
    for protected in (repository, workload, suite_root, old_evidence, attempt.directory):
        disjoint(workspace, protected)
    resources = plan['resources']
    if set(resources) != {'builder', 'grader'}:
        raise ValueError('Exact builder and grader resource plan required')
    for role, resource in resources.items():
        name = 'factory-eval-' + role + '-' + token
        expected = dict(name=name, project=str(paths[role + '-project']),
                        specification=str(paths['specification']),
                        create_argv=sandbox_create_argv(paths[role + '-project'],
                            paths['specification'], name=name, port=resource['host_port'], role=role),
                        manual_stop=['sbx', 'stop', name], cpus=8, memory_gib=16,
                        host_port=resource['host_port'], created=False, termination_verified=False)
        if json.dumps(resource, sort_keys=True) != json.dumps(expected, sort_keys=True):
            raise ValueError('Resource identity or effects differ from inspected plan')
    if resources['builder']['host_port'] != resources['grader']['host_port']:
        raise ValueError('Sequential planned origin required')

    def verify_sources():
        check()
        identities = plan['source_identities']
        observed = audit(workload, suite_root, repository=repository,
                         suite_approval=suite_approval, host_attempt=host_attempt)
        approval = read_regular(workload / 'review/WORKLOAD-APPROVAL.json', 65536, check)
        if (json.dumps(observed, sort_keys=True) != json.dumps(plan['readiness'], sort_keys=True)
                or observed['details']['reviewed_workload_unchanged'] is not True
                or observed['details']['suite_sha256'] != identities['suite_sha256']
                or hashlib.sha256(approval).hexdigest() != identities['workload_approval_sha256']
                or json.loads(approval)['workload_sha256'] != identities['workload']
                or controller_identities(repository) != identities['controller']):
            raise ValueError('Inspected workspace source identities changed')
        review = json.loads(approval)
        if (review.get('schema_version') != 1
                or review.get('approval_type') != 'workload_and_envelope_review_not_suite_freeze'
                or not {'24-hour builder wall-clock ceiling', '8-vCPU and 16-GiB sandbox allocation'}
                    <= set(review.get('approved_scope', []))):
            raise ValueError('Reviewed first-test workload and envelope required')
        check()

    with private_file(attempt.directory / 'workspace-preparation.lock'):
        pass
    receipt = attempt.directory / 'workspace-preparation.json'
    report = dict(outcome='workspace_preparation_incomplete', workspace=str(workspace),
                  workspace_created=False, workspace_creation_attempted=False,
                  plan_sha256=hashlib.sha256(encoded).hexdigest(),
                  sandboxes_created=False, model_calls=0, launch_enabled=False)
    try:
        verify_sources()
        # Record exact intent before the first filesystem side effect. Death
        # between mkdir and confirmation leaves an inspectable uncertain claim.
        report['workspace_creation_attempted'] = True
        atomic_json(receipt, report)
        check()
        workspace.mkdir(mode=0o700)
        report['workspace_created'] = True
        owned = workspace.stat()
        report['workspace_identity'] = dict(device=owned.st_dev, inode=owned.st_ino)
        atomic_json(receipt, report)
        check()
        paths['builder-project'].mkdir(mode=0o700)
        project = paths['builder-project'].stat()
        prepared = prepare_specification(attempt, workload, paths['specification'],
            monotonic_deadline=monotonic_deadline, wall_deadline=wall_deadline,
            monotonic=monotonic, wall=wall)
        verify_sources()
        for path, identity in ((workspace, owned), (paths['builder-project'], project)):
            current = path.lstat()
            if (current.st_dev, current.st_ino, current.st_mode) != (identity.st_dev, identity.st_ino, identity.st_mode):
                raise ValueError('Owned workspace directory replaced')
        if (list(paths['builder-project'].iterdir()) or paths['capture'].exists()
                or paths['grader-project'].exists()):
            raise ValueError('Unexpected application or capture content during preparation')
        if set(path.name for path in workspace.iterdir()) != {'builder-project', 'specification'}:
            raise ValueError('Unexpected prepared workspace content')
        report.update(outcome='workspace_prepared', paths=plan['paths'],
                      specification=prepared, readiness_outcome=plan['readiness']['outcome'],
                      limits='Owned local workspace and reviewed byte copy only; no readiness, mount, runtime, suite approval or launch evidence.')
        check(); atomic_json(receipt, report); check()
        return report
    except BaseException as error:
        report.update(outcome='workspace_preparation_incomplete', error_type=type(error).__name__)
        if report['workspace_created']:
            report['retained_workspace'] = str(workspace)
        atomic_json(receipt, report)
        raise
