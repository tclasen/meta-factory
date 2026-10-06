"""Reviewable first-test resource plan; no provisioning or experiment execution."""
from pathlib import Path
import json
import uuid

from .grading import sha256
from .readiness import audit
from .sandbox import disjoint, sandbox_create_argv


def build_plan(workload, suite_root, workspace_parent, evidence, *, port,
               repository=None, suite_approval=None, host_attempt=None):
    """Resolve and hash operator inputs; reserve no resource and run no command.

    A plan is not permission to launch. Its paths are proposals, not created or
    owned directories. A future executor must revalidate all identities, acquire
    exclusive ownership and satisfy the independently reviewed readiness gates.
    """
    repository=Path(repository or Path(__file__).resolve().parents[1]).resolve(strict=True)
    workload=Path(workload).resolve(strict=True);suite_root=Path(suite_root).resolve(strict=True)
    parent=Path(workspace_parent).resolve(strict=True);evidence=Path(evidence).resolve(strict=True)
    if not parent.is_dir() or not evidence.is_dir():raise ValueError('Existing operator workspace parent and evidence required')
    approval_path=workload/'review/WORKLOAD-APPROVAL.json'
    approval=json.loads(approval_path.read_text())
    if (approval.get('schema_version')!=1
            or approval.get('approval_type')!='workload_and_envelope_review_not_suite_freeze'
            or not {'24-hour builder wall-clock ceiling','8-vCPU and 16-GiB sandbox allocation'} <= set(approval.get('approved_scope',[]))):
        raise ValueError('First-test workload/envelope approval record required')
    readiness=audit(workload,suite_root,suite_approval=suite_approval,host_attempt=host_attempt,repository=repository)
    if readiness['details']['reviewed_workload_unchanged'] is not True:
        raise ValueError('Reviewed workload identity changed')
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
            create_argv=sandbox_create_argv(project,paths['specification'],name=name,port=port,role=role),
            manual_stop=['sbx','stop',name],cpus=8,memory_gib=16,host_port=port,
            created=False,termination_verified=False)
    controller_paths=[path for path in (repository/'evaluation').rglob('*') if path.is_file() and path.suffix in ('.py','.json') and '__pycache__' not in path.parts]
    controller_paths += [repository/'pyproject.toml',repository/'uv.lock']
    identities={str(path.relative_to(repository)):sha256(path) for path in controller_paths}
    report=dict(schema_version=1,outcome='planned_not_ready',launch_enabled=False,
        workspace=str(workspace),paths={key:str(value) for key,value in paths.items()},
        resources=resources,evidence=str(evidence),readiness=readiness,
        source_identities=dict(workload_approval_sha256=sha256(workload/'review/WORKLOAD-APPROVAL.json'),
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

    settled=audit(workload,suite_root,suite_approval=suite_approval,host_attempt=host_attempt,repository=repository)
    if (settled['details']!=readiness['details']
            or report['source_identities']['workload']!=approval['workload_sha256']
            or sha256(approval_path)!=report['source_identities']['workload_approval_sha256']
            or any(sha256(repository/name)!=digest for name,digest in identities.items())):
        raise ValueError('Planning source identities changed during inspection')
    return report
