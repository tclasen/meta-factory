"""Reviewable first-test resource plan; no provisioning or experiment execution."""
from pathlib import Path
import copy
import re
import json
import hashlib
import uuid

from .grading import Suite, select_cases, sha256
from .readiness import audit
from .sandbox import disjoint, sandbox_create_argv, local_template_binding


def controller_identities(repository):
    paths=[path for path in (repository/'evaluation').rglob('*')
           if path.is_file() and path.suffix in ('.py','.json','.md') and '__pycache__' not in path.parts]
    paths += [repository/'pyproject.toml',repository/'uv.lock']
    return {str(path.relative_to(repository)):sha256(path) for path in paths}


def normalize_stage_assignments(assignments, suite):
    """Exact operator case partition and explicit parallel-lane assignment."""
    if not isinstance(assignments, (list, tuple)) or not assignments:
        raise ValueError('Nonempty grading stage assignments required')
    stages = []; identifiers = set(); assigned = []
    for item in assignments:
        if (not isinstance(item, dict) or not {'id', 'case_ids'} <= set(item)
                or not set(item) <= {'id', 'case_ids', 'lane'}):
            raise ValueError('Stage assignment requires id, case_ids and optional lane')
        identifier = item['id']
        if (not isinstance(identifier, str)
                or not re.fullmatch('[a-z][a-z0-9-]{0,57}', identifier)
                or identifier in identifiers):
            raise ValueError('Unique grading stage identifiers required')
        lane = item.get('lane', 0)
        if type(lane) is not int or not 0 <= lane <= 31:
            raise ValueError('Stage lane must be an integer from 0 through 31')
        selected = [case['id'] for case in select_cases(suite, item['case_ids'])]
        stages.append(dict(id=identifier, case_ids=selected, lane=lane))
        identifiers.add(identifier); assigned.extend(selected)
    if len(set(assigned)) != len(assigned) or set(assigned) != {case['id'] for case in suite.cases}:
        raise ValueError('Grading stages must partition the full registry exactly once')
    return stages


def planned_stage_resources(workspace, assignments, port, *, template=None):
    """Derive distinct names/projects/argv from the inspected workspace identity."""
    resources = {}; stages = []
    token = workspace.name.removeprefix('factory-eval-')
    for stage in assignments:
        key = 'grader-' + stage['id']
        suffix = hashlib.sha256((token + ':' + stage['id']).encode()).hexdigest()[:16]
        name = 'factory-eval-grader-' + suffix
        project = workspace / (key + '-project')
        specification = workspace / 'specification'
        host_port = port + stage['lane']
        if host_port > 65535:
            raise ValueError('Planned grading lane exceeds available host ports')
        resources[key] = dict(name=name, project=str(project), specification=str(specification),
            create_argv=sandbox_create_argv(project, specification, name=name, port=host_port, role='grader', template=template),
            manual_stop=['sbx', 'stop', name], cpus=8, memory_gib=16, host_port=host_port,
            created=False, termination_verified=False)
        stages.append(dict(id=stage['id'], case_ids=stage['case_ids'], resource=key, lane=stage['lane']))
    if len({value['name'] for value in resources.values()}) != len(resources):
        raise ValueError('Planned grading name collision')
    return resources, stages


def build_plan(workload, suite_root, workspace_parent, evidence, *, port,
               repository=None, suite_approval=None, host_attempt=None, stage_assignments=None, templates=None):
    """Resolve and hash operator inputs; reserve no resource and run no command.

    A plan is not permission to launch. Its paths are proposals, not created or
    owned directories. A future executor must revalidate all identities, acquire
    exclusive ownership and satisfy the independently reviewed readiness gates.
    """
    if templates is not None:
        if not isinstance(templates, dict) or set(templates) != {'builder', 'grader'}:
            raise ValueError('Exact builder and grader template bindings required')
        templates = {role: local_template_binding(templates[role], role) for role in ('builder', 'grader')}
        if any(value is None for value in templates.values()):
            raise ValueError('Both local template bindings required')
    repository=Path(repository or Path(__file__).resolve().parents[1]).resolve(strict=True)
    workload=Path(workload).resolve(strict=True);suite_root=Path(suite_root).resolve(strict=True)
    parent=Path(workspace_parent).resolve(strict=True);evidence=Path(evidence).resolve(strict=True)
    if not parent.is_dir() or not evidence.is_dir():raise ValueError('Existing operator workspace parent and evidence required')
    approval_path=workload/'review/WORKLOAD-APPROVAL.json'
    approval_bytes=approval_path.read_bytes()
    approval=json.loads(approval_bytes)
    approval_digest=hashlib.sha256(approval_bytes).hexdigest()
    if (approval.get('schema_version')!=1
            or approval.get('approval_type')!='workload_and_envelope_review_not_suite_freeze'
            or not {'24-hour builder wall-clock ceiling','8-vCPU and 16-GiB sandbox allocation'} <= set(approval.get('approved_scope',[]))):
        raise ValueError('First-test workload/envelope approval record required')
    readiness=audit(workload,suite_root,suite_approval=suite_approval,host_attempt=host_attempt,repository=repository)
    if readiness['details']['reviewed_workload_unchanged'] is not True:
        raise ValueError('Reviewed workload identity changed')
    assignments = None
    if stage_assignments is not None:
        packages = json.loads((workload/'builder/packages.json').read_text())['packages']
        registry = Suite(suite_root, packages, approval=suite_approval)
        assignments = normalize_stage_assignments(copy.deepcopy(stage_assignments), registry)
        if registry.digest != readiness['details']['suite_sha256']:
            raise ValueError('Stage registry differs from inspected readiness')
    token=uuid.uuid4().hex[:16]
    workspace=parent/('factory-eval-'+token)
    if workspace.exists() or workspace.is_symlink():raise ValueError('Proposed workspace already exists')
    for protected in (repository,workload,suite_root,evidence):disjoint(workspace,protected)
    paths={key:workspace/key for key in ('builder-project','grader-project','specification','capture')}
    disjoint(*paths.values())
    resources={}
    for role in ('builder','grader'):
        name='factory-eval-'+role+'-'+token
        project=paths[role+'-project']
        resources[role]=dict(name=name,project=str(project),specification=str(paths['specification']),
            create_argv=sandbox_create_argv(project,paths['specification'],name=name,port=port,role=role,
                template=templates[role] if templates is not None else None),
            manual_stop=['sbx','stop',name],cpus=8,memory_gib=16,host_port=port,
            created=False,termination_verified=False)
    stages = None
    if assignments is not None:
        del paths['grader-project']; del resources['grader']
        staged_resources, stages = planned_stage_resources(workspace, assignments, port,
            template=templates['grader'] if templates is not None else None)
        resources.update(staged_resources)
        paths.update({key+'-project':Path(value['project']) for key,value in staged_resources.items()})
        disjoint(*paths.values())
    identities=controller_identities(repository)
    report=dict(schema_version=1,outcome='planned_not_ready',launch_enabled=False,
        workspace=str(workspace),paths={key:str(value) for key,value in paths.items()},
        resources=resources,evidence=str(evidence),readiness=readiness,
        source_identities=dict(workload_approval_sha256=approval_digest,
            workload={str(path.relative_to(workload)):sha256(path) for path in (workload/'builder').rglob('*') if path.is_file()},
            suite_sha256=readiness['details']['suite_sha256'],controller=identities),
        limits=dict(builder_seconds=dict(value=86400,approval='D-048'),
            allocation=dict(cpus=8,memory_gib=16,approval='D-048'),
            preparation_seconds=dict(value=1800,approval='proposal'),
            capture_seconds=dict(value=600,approval='proposal'),
            grading_seconds=dict(value=5400,approval='proposal'),
            cleanup_seconds=dict(value=600,approval='proposal')),
        sequence=[
            'Revalidate source identities and reviewed readiness; obtain separate launch authorization',
            'Acquire exclusive workspace ownership and copy only reviewed builder specification',
            'Create builder sandbox with isolated project and read-only specification',
            'Start one bounded runtime thread/turn; no replacement thread or reminder',
            'Revoke builder and independently verify remote termination before capture',
            'Capture source as untrusted bytes; execute no captured script on the host',
            'Create fresh grader only after builder termination; reuse the forwarded port sequentially',
            'Bootstrap inside grader; bind independent fixtures and protected capabilities',
            'Run the reviewed protected suite outside both application mounts',
            'Close capabilities before watchdog release; verify remote cleanup and retain evidence'],
        changes_made=dict(evidence_only=True,workspace_created=False,sandboxes_created=False,
                          policy_changed=False,model_calls=0),
        limits_note='Planning evidence only. No workspace ownership, source copy, sandbox, port reservation, policy, model, suite approval or launch authority is established.')

    if templates is not None:
        report['template_bindings'] = copy.deepcopy(templates)
        report['source_identities']['template_bindings'] = copy.deepcopy(templates)

    if stages is not None:
        report['grading_stages'] = stages
        report['grading_lanes'] = [
            dict(lane=lane, host_port=port + lane,
                 stage_ids=[stage['id'] for stage in stages if stage['lane'] == lane])
            for lane in sorted({stage['lane'] for stage in stages})]
        report['sequence'][6:9] = [
            'After verified builder termination, grade every assigned stage against one frozen capture and registry',
            'Run stages sequentially within each lane; distinct lanes use distinct loopback ports and require independent owners',
            'Bootstrap and bind independent stage fixtures; aggregate the full registry within one shared grading budget']

    settled=audit(workload,suite_root,suite_approval=suite_approval,host_attempt=host_attempt,repository=repository)
    if (settled['details']!=readiness['details']
            or report['source_identities']['workload']!=approval['workload_sha256']
            or sha256(approval_path)!=report['source_identities']['workload_approval_sha256']
            or controller_identities(repository)!=identities):
        raise ValueError('Planning source identities changed during inspection')
    return report
