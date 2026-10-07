"""REQ-007: review-only, hash-bound inputs for three native state treatments.

Operator artifact preparation, not a task API, state service, or launch gate.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import unicodedata

from .git_state import TRACKER_PATH, _unique_pairs, render_git_seed
from .preparation import read_regular, snapshot


ARMS = ('conversation', 'git-file', 'github-projects')
CONTROL_DIGESTS = ('factory_revision', 'toolchain_sha256', 'limits_sha256',
                   'context_configuration_sha256', 'network_policy_sha256', 'grading_suite_sha256')
RESOURCE_PATH = '.factory/project/task-state-resource.json'
BOUNDARY_FILES = ('docs/task-state-workflows.md', 'evaluation/instructions/state-common.md',
                  *(f'evaluation/instructions/state-{arm}.md' for arm in ARMS))


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode()


def _projects_descriptor(value):
    if (not isinstance(value, dict) or set(value) != {'owner', 'project_number', 'project_id', 'fields', 'status_options'}
            or not isinstance(value['owner'], str)
            or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9-]{0,38}', value['owner'])
            or type(value['project_number']) is not int or value['project_number'] <= 0):
        raise ValueError('Exact assigned Projects resource descriptor required')
    for key, names in (('fields', {'Work package', 'Status', 'Progress', 'Next action'}),
                       ('status_options', {'Todo', 'In progress', 'Blocked', 'Done'})):
        if not isinstance(value[key], dict) or set(value[key]) != names:
            raise ValueError('Exact native Projects fields and status options required')
        ids = list(value[key].values())
        if any(not isinstance(item, str) or not re.fullmatch('[A-Za-z0-9_-]{1,256}', item) for item in ids):
            raise ValueError('Ordinary native Projects identifiers required')
        if len(set(ids)) != len(ids):
            raise ValueError('Distinct native Projects identifiers required')
    if (not isinstance(value['project_id'], str)
            or not re.fullmatch('[A-Za-z0-9_-]{1,256}', value['project_id'])):
        raise ValueError('Ordinary native project node ID required')
    return json.loads(_canonical(value))


def prepare_state_inputs(specification, expected_files, controls, *, projects=None):
    """Return draft operator data; make no filesystem/network/model changes.

    expected_files must come from the reviewed specification hash record, with
    paths relative to /spec. Controls are explicit shared identities, not inferred
    from whichever runtime happens to be installed. A descriptor records resource
    IDs, not credentials or mutable item state. Matching hashes does not establish
    protocol approval, frozen grading, mount isolation, or launch authorization.
    """
    if (not isinstance(specification, dict) or not isinstance(expected_files, dict)
            or not 1 <= len(specification) <= 256 or set(specification) != set(expected_files)):
        raise ValueError('Complete exact reviewed specification file set required')
    expected = dict(expected_files); data = dict(specification)
    total = 0
    for name, content in data.items():
        if (not isinstance(name, str) or not name or '\\' in name
                or any(unicodedata.category(character).startswith('C') for character in name)
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or str(PurePosixPath(name)) != name or name == '.'
                or not isinstance(content, bytes) or not isinstance(expected[name], str)
                or not re.fullmatch('[0-9a-f]{64}', expected[name])
                or _digest(content) != expected[name]):
            raise ValueError('Canonical reviewed specification bytes required')
        total += len(content)
        if total > 64 * 1024 ** 2:
            raise ValueError('Specification byte bound exceeded')
    if 'packages.json' not in data:
        raise ValueError('Reviewed frozen-package manifest required')
    seed = render_git_seed(data['packages.json'], expected['packages.json']).decode()
    if (not isinstance(controls, dict)
            or set(controls) != {'model', 'reasoning_effort', 'runtime_version', *CONTROL_DIGESTS}
            or controls['model'] != 'gpt-6-luna' or controls['reasoning_effort'] != 'medium'
            or controls['runtime_version'] != '0.160.0'):
        raise ValueError('Exact shared first-study controls required')
    controls = dict(controls)
    for name in CONTROL_DIGESTS:
        length = 40 if name == 'factory_revision' else 64
        if not isinstance(controls[name], str) or not re.fullmatch('[0-9a-f]{' + str(length) + '}', controls[name]):
            raise ValueError('Explicit immutable shared control identity required')
    descriptor = None if projects is None else _projects_descriptor(projects)
    root = Path(__file__).parent / 'instructions'
    names = ['state-common.md'] + ['state-' + arm + '.md' for arm in ARMS]
    instructions = {name: read_regular(root / name, 16384, lambda: None) for name in names}
    common = instructions['state-common.md'].decode('utf-8')
    shared = dict(specification_files=expected, specification_bytes=total,
                  common_instructions_sha256=_digest(instructions['state-common.md']), controls=controls)
    identity = _digest(_canonical(shared))
    arms = {}
    for arm in ARMS:
        prompt = common + '\n' + instructions['state-' + arm + '.md'].decode('utf-8')
        files = {}
        if arm == 'git-file':
            files[TRACKER_PATH] = seed
        if arm == 'github-projects' and descriptor is not None:
            files[RESOURCE_PATH] = json.dumps(descriptor, sort_keys=True, indent=2) + '\n'
            prompt += f'\nRead your immutable resource descriptor at {RESOURCE_PATH}.\n'
        arms[arm] = dict(shared_identity=identity, prompt=prompt, prompt_sha256=_digest(prompt.encode()),
                         initial_files=files, initial_file_sha256={name: _digest(value.encode()) for name, value in files.items()},
                         launch_enabled=False)
    # Reject a source edit during preparation rather than publishing mixed text.
    if any(read_regular(root / name, 16384, lambda: None) != value for name, value in instructions.items()):
        raise ValueError('Treatment instructions changed during preparation')
    return dict(schema_version=1, outcome='state_inputs_prepared_for_review', launch_enabled=False,
        shared=shared, shared_identity=identity, arms=arms,
        instruction_files={name: _digest(value) for name, value in instructions.items()},
        projects_resource_assigned=descriptor is not None,
        overhead_policy='Retain whole-attempt runtime usage and elapsed time, including native state operations; report setup and final capture separately.',
        limits='Draft inputs only; human boundary review, specification/protocol freeze, native resource verification and separate launch authority remain required.')


def prepare_reviewed_state_inputs(workload, controls_path, *, projects_path=None,
                                 boundary_approval_path=None, check=lambda: None):
    """Inspect approved workload bytes and explicit operator files; publish no state.

    Retain input hashes rather than assuming filenames identify frozen content.
    A caller owns the overall deadline; regular-file reads are bounded, but
    filesystem I/O itself is not interruptible by this function.
    """
    workload = Path(workload).resolve(strict=True)
    approval_path = workload / 'review/WORKLOAD-APPROVAL.json'
    approval_bytes = read_regular(approval_path, 65536, check)
    approval = json.loads(approval_bytes, object_pairs_hook=_unique_pairs)
    if (not isinstance(approval, dict) or type(approval.get('schema_version')) is not int
            or approval['schema_version'] != 1
            or approval.get('approval_type') != 'workload_and_envelope_review_not_suite_freeze'
            or not isinstance(approval.get('workload_sha256'), dict)
            or not approval['workload_sha256']):
        raise ValueError('Explicit reviewed workload hash record required')
    expected = {}
    for name, digest in approval['workload_sha256'].items():
        if (not isinstance(name, str) or '\\' in name or str(PurePosixPath(name)) != name
                or PurePosixPath(name).is_absolute() or '..' in PurePosixPath(name).parts
                or len(PurePosixPath(name).parts) < 2 or PurePosixPath(name).parts[0] != 'builder'
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise ValueError('Canonical reviewed builder-file identities required')
        expected[name.removeprefix('builder/')] = digest
    data, _ = snapshot(workload / 'builder', expected, 64 * 1024 ** 2, 256, check)
    inputs = {'controls': Path(controls_path)}
    if projects_path is not None:
        inputs['projects_resource'] = Path(projects_path)
    if boundary_approval_path is not None:
        inputs['boundary_approval'] = Path(boundary_approval_path)
    raw = {name: read_regular(path, 65536, check) for name, path in inputs.items()}
    values = {name: json.loads(content, object_pairs_hook=_unique_pairs) for name, content in raw.items()}
    report = prepare_state_inputs(data, expected, values['controls'], projects=values.get('projects_resource'))
    boundary_sources = {}
    if boundary_approval_path is not None:
        boundary = values['boundary_approval']
        if (not isinstance(boundary, dict) or type(boundary.get('schema_version')) is not int
                or boundary['schema_version'] != 1
                or boundary.get('approval_type') != 'native_task_state_boundaries_not_suite_or_launch'
                or not isinstance(boundary.get('reviewer'), str) or not boundary['reviewer'].strip()
                or not isinstance(boundary.get('recorded_utc'), str) or not boundary['recorded_utc'].strip()
                or boundary.get('launch_enabled') is not False
                or boundary.get('workload_approval_sha256') != _digest(approval_bytes)
                or not isinstance(boundary.get('artifact_sha256'), dict)
                or set(boundary['artifact_sha256']) != set(BOUNDARY_FILES)):
            raise ValueError('Explicit matching human boundary approval required')
        repository = Path(__file__).resolve().parents[1]
        for name in BOUNDARY_FILES:
            content = read_regular(repository / name, 65536, check)
            digest = _digest(content)
            if boundary['artifact_sha256'][name] != digest:
                raise ValueError('Approved boundary artifact changed')
            if name.startswith('evaluation/instructions/') and report['instruction_files'][Path(name).name] != digest:
                raise ValueError('Prepared prompt differs from approved boundary instructions')
            boundary_sources[repository / name] = content
    snapshot(workload / 'builder', expected, 64 * 1024 ** 2, 256, check)
    if (read_regular(approval_path, 65536, check) != approval_bytes
            or any(read_regular(inputs[name], 65536, check) != content for name, content in raw.items())
            or any(read_regular(path, 65536, check) != content for path, content in boundary_sources.items())):
        raise ValueError('Reviewed state-input sources changed during inspection')
    check()
    report['operator_source_sha256'] = dict(workload_approval=_digest(approval_bytes),
                                          **{name: _digest(content) for name, content in raw.items()})
    report['boundary_review_verified'] = boundary_approval_path is not None
    return report
