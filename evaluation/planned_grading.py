"""Bind an inspected staged plan to its owned workspace and operator adapters."""
import copy
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import time

from .deployment import verify_capture
from .evidence import atomic_json, positive
from .grading import Suite
from .grading_stages import grade_stages, suite_identity
from .preparation import read_regular, snapshot
from .source_binding import open_directory
from .verdicts import Inconclusive
from .workspace import validate_workspace_resources, verify_plan_sources


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def grade_planned_stages(attempt, preparation_attempt, plan, workload, suite,
                        configurations, inventory, *, termination_verified,
                        monotonic_deadline, wall_deadline, suite_approval=None,
                        host_attempt=None, monotonic=time.monotonic, wall=time.time,
                        **grading_options):
    """Operator-only handoff; no launch/readiness or termination authority.

    The caller must independently verify builder termination before capture and
    bound callbacks/IO with an outer owner. Preparation receipts prove local
    directory/byte ownership only. Protected targets and callable adapters remain
    separate from the inspected plan and must receive independent review.
    """
    if termination_verified is not True:
        raise ValueError('Independent builder termination required before planned grading')
    for value in (monotonic_deadline, wall_deadline):
        positive(value, 'planned grading outer deadline')
    if not callable(monotonic) or not callable(wall):
        raise ValueError('Trusted outer clocks required')
    if set(grading_options) & {'port', 'grading_seconds', 'sequence_check'}:
        raise ValueError('Planned origin, grading budget and identity check cannot be overridden')
    raw_plan = encoded(plan)
    if len(raw_plan) > 1024 * 1024:
        raise ValueError('Bounded inspected grading plan required')
    plan = json.loads(raw_plan)
    if (plan.get('schema_version') != 1 or plan.get('outcome') != 'planned_not_ready'
            or plan.get('launch_enabled') is not False or 'grading_stages' not in plan):
        raise ValueError('Inspected nonlaunching staged plan required')
    workload = Path(workload).resolve(strict=True)
    repository = Path(__file__).resolve().parents[1]
    workspace = Path(plan['workspace'])
    owner = os.getpid()
    previous = None

    def lifetime():
        nonlocal previous
        clocks = monotonic(), wall()
        if (os.getpid() != owner or any(type(value) not in (int, float)
                or not math.isfinite(value) for value in clocks)
                or previous is not None and any(value < before for value, before in zip(clocks, previous))
                or min(monotonic_deadline-clocks[0], wall_deadline-clocks[1]) <= 0):
            raise Inconclusive('Planned grading outer lifetime unavailable')
        previous = clocks

    paths = validate_workspace_resources(plan, workload, suite.root, suite_approval)
    suite.verify()
    expected_suite = suite_identity(suite)
    independently_loaded = Suite(suite.root, suite.packages, approval=suite_approval)
    if (suite.digest != plan['source_identities']['suite_sha256']
            or suite_identity(independently_loaded) != expected_suite):
        raise ValueError('Grading suite differs from inspected plan')
    preparation_path = preparation_attempt.directory / 'workspace-preparation.json'
    verification_path = preparation_attempt.directory / 'workspace-verification.json'
    raw_preparation = read_regular(preparation_path, 1024 * 1024, lifetime)
    raw_verification = read_regular(verification_path, 1024 * 1024, lifetime)
    prepared = json.loads(raw_preparation)
    verified = json.loads(raw_verification)
    if (prepared.get('outcome') != 'workspace_prepared'
            or prepared.get('workspace_created') is not True
            or prepared.get('launch_enabled') is not False
            or prepared.get('plan_sha256') != digest(raw_plan)
            or prepared.get('workspace') != str(workspace)
            or prepared.get('paths') != plan['paths']
            or verified.get('outcome') != 'workspace_verified_for_inspection'
            or verified.get('launch_enabled') is not False
            or verified.get('workspace') != str(workspace)
            or verified.get('plan_sha256') != digest(raw_plan)
            or verified.get('preparation_sha256') != digest(raw_preparation)):
        raise ValueError('Matching successful owned preparation and reinspection required')
    expected_files = {name.removeprefix('builder/'): value
                      for name, value in plan['source_identities']['workload'].items()}
    if (prepared['specification'].get('outcome') != 'specification_prepared'
            or prepared['specification'].get('destination') != str(paths['specification'])
            or prepared['specification'].get('files') != expected_files
            or verified.get('files') != expected_files):
        raise ValueError('Prepared reviewed specification differs from plan')
    declarations = plan['grading_stages']
    if (not isinstance(configurations, (list, tuple))
            or len(configurations) != len(declarations)):
        raise ValueError('Exact operator configuration for every planned stage required')
    stages = []
    for declaration, configuration in zip(declarations, configurations):
        if (not isinstance(configuration, dict)
                or not {'id', 'target'} <= set(configuration)
                or not set(configuration) <= {'id', 'target', 'options'}
                or configuration['id'] != declaration['id']
                or not isinstance(configuration['target'], dict)
                or not isinstance(configuration.get('options', {}), dict)):
            raise ValueError('Ordered independent stage targets/options required; resource overrides forbidden')
        resource = plan['resources'][declaration['resource']]
        stages.append(dict(id=declaration['id'], name=resource['name'],
            project=resource['project'], case_ids=copy.deepcopy(declaration['case_ids']),
            target=copy.deepcopy(configuration['target']), options=dict(configuration.get('options', {}))))
    inventory = copy.deepcopy(inventory)
    allowed_contents = {path.name for path in paths.values()}
    descriptor = open_directory(paths['capture'])
    try:
        metadata = os.fstat(descriptor)
        capture_identity = (metadata.st_dev, metadata.st_ino)
    finally:
        os.close(descriptor)

    def check():
        lifetime()
        if (read_regular(preparation_path, 1024 * 1024, lifetime) != raw_preparation
                or read_regular(verification_path, 1024 * 1024, lifetime) != raw_verification):
            raise Inconclusive('Original workspace ownership receipts changed')
        for path, key, mode in ((workspace, 'workspace_identity', 0o700),
                (paths['builder-project'], 'builder_project_identity', 0o700),
                (paths['specification'], 'specification_identity', 0o555)):
            descriptor = open_directory(path)
            try:
                metadata = os.fstat(descriptor)
                if (stat.S_IMODE(metadata.st_mode) != mode
                        or prepared[key] != dict(device=metadata.st_dev, inode=metadata.st_ino)):
                    raise Inconclusive('Original owned workspace directories changed')
            finally:
                os.close(descriptor)
        if not {path.name for path in workspace.iterdir()} <= allowed_contents:
            raise Inconclusive('Unplanned workspace content appeared')
        verify_plan_sources(plan, workload, suite.root, repository, lifetime,
                            suite_approval=suite_approval, host_attempt=host_attempt)
        suite.verify()
        if suite_identity(suite) != expected_suite:
            raise Inconclusive('Planned protected registry cache changed')
        _, copied_bytes = snapshot(paths['specification'], expected_files, 64 * 1024**2, 256, lifetime)
        if copied_bytes != prepared['specification']['copied_bytes'] or copied_bytes != verified['copied_bytes']:
            raise Inconclusive('Original reviewed specification byte count changed')
        for path in paths['specification'].rglob('*'):
            metadata = path.lstat()
            if stat.S_IMODE(metadata.st_mode) != (0o555 if stat.S_ISDIR(metadata.st_mode) else 0o444):
                raise Inconclusive('Original reviewed specification permissions changed')
            lifetime()
        verify_capture(paths['capture'], inventory)
        descriptor = open_directory(paths['capture'])
        try:
            metadata = os.fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) != capture_identity:
                raise Inconclusive('Original planned capture directory changed')
        finally:
            os.close(descriptor)
        lifetime()
        return True

    check()
    atomic_json(attempt.directory / 'planned-grading-binding.json', dict(schema_version=1,
        plan_sha256=digest(raw_plan), preparation_sha256=digest(raw_preparation),
        verification_sha256=digest(raw_verification), suite_sha256=suite.digest,
        workspace=str(workspace), stage_ids=[stage['id'] for stage in stages],
        limits='Owned local receipts, exact inspected stages and current bytes only; caller supplies verified builder termination, native adapters and outer interruption. No readiness, launch, suite approval or source/image/runtime proof.'))
    return grade_stages(attempt, paths['capture'], inventory, paths['specification'], suite,
        stages, port=plan['resources']['builder']['host_port'],
        grading_seconds=plan['limits']['grading_seconds']['value'], sequence_check=check,
        monotonic=monotonic, wall=wall, **grading_options)
