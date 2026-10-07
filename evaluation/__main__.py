"""Inspect evaluator readiness with durable local logs; no experiment launch."""

import argparse
import json
from pathlib import Path
import tempfile
import sys
import time

from .evidence import Attempt, atomic_json, collect
from .readiness import audit
from .plan import build_plan
from .preparation import read_regular
from .state_inputs import prepare_reviewed_state_inputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='Read-only readiness report, no model or sandbox operations')
    inspect.add_argument('--workload', type=Path, required=True)
    inspect.add_argument('--suite', type=Path, required=True)
    inspect.add_argument('--suite-approval', type=Path)
    inspect.add_argument('--host-attempt', type=Path)
    plan = commands.add_parser('plan', help='Record exact proposed resources and effects; never provision or launch')
    plan.add_argument('--workload', type=Path, required=True)
    plan.add_argument('--suite', type=Path, required=True)
    plan.add_argument('--suite-approval', type=Path)
    plan.add_argument('--host-attempt', type=Path)
    plan.add_argument('--workspace-parent', type=Path, required=True)
    plan.add_argument('--port', type=int, required=True)
    plan.add_argument('--stage-assignments', type=Path,
                      help='Protected JSON list of id/case_ids assignments; exact full-registry partition')
    state = commands.add_parser('state-inputs', help='Record reviewed three-arm inputs; never provision or launch')
    state.add_argument('--workload', type=Path, required=True)
    state.add_argument('--controls', type=Path, required=True, help='Explicit operator shared-control identities')
    state.add_argument('--projects-resource', type=Path, help='Assigned immutable native resource IDs, no credentials')
    state.add_argument('--boundary-approval', type=Path,
                       help='Human boundary approval bound to current instructions and reviewed workload; no launch authority')
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    log_names = {'plan': 'evaluation-plan-logs', 'inspect': 'evaluation-readiness-logs',
                 'state-inputs': 'state-input-review-logs'}
    base = repository / '.factory-planning' / log_names[args.command]
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
    directory.rmdir()
    print(f'Logs: {directory}', flush=True)
    print('Read-only audit; no model calls, sandbox creation, or host-policy changes.', flush=True)
    kinds = {'plan': 'resource_plan', 'inspect': 'readiness_inspection', 'state-inputs': 'state_input_review'}
    with Attempt(directory, {'kind': kinds[args.command]}) as attempt:
        attempt.transition('preflight')
        try:
            checks=[('revision', ['git', 'rev-parse', 'HEAD']), ('worktree', ['git', 'status', '--porcelain'])]
            if args.command in ('plan', 'state-inputs'):
                checks += [('python',[sys.executable,'--version']),('uv',['uv','--version'])]
            for label, command in checks:
                result = collect(attempt, label, command, cwd=repository, timeout=30)
                if result['outcome'] != 'passed':
                    raise RuntimeError('Repository inspection failed')
            if args.command == 'state-inputs':
                if (directory / 'worktree/stdout.log').read_text():
                    raise ValueError('Clean committed state-input sources required')
                deadline = time.monotonic() + 60
                def check():
                    if time.monotonic() >= deadline:
                        raise TimeoutError('State-input inspection deadline expired')
                report = prepare_reviewed_state_inputs(args.workload, args.controls,
                    projects_path=args.projects_resource, boundary_approval_path=args.boundary_approval, check=check)
                atomic_json(directory / 'state-inputs.json', report)
            elif args.command=='plan':
                assignments = None
                if args.stage_assignments is not None:
                    assignments = json.loads(read_regular(args.stage_assignments, 65536, lambda: None))
                report = build_plan(args.workload,args.suite,args.workspace_parent,attempt.directory,
                    port=args.port,suite_approval=args.suite_approval,host_attempt=args.host_attempt,repository=repository,
                    stage_assignments=assignments)
                atomic_json(directory/'plan.json',report)
            else:
                report = audit(args.workload, args.suite, suite_approval=args.suite_approval,
                               host_attempt=args.host_attempt, repository=repository)
        except Exception as error:
            report = {'outcome': 'inspection_error', 'launch_enabled': False, 'error_type': type(error).__name__}
        attempt.transition('failed')  # No READY transition until launch gates exist.
        attempt.finish(report)
        print('Outcome:', report['outcome'])
        for blocker in report.get('blockers', report.get('readiness', {}).get('blockers', [])):
            print('-', blocker)
        print(f'Logs: {directory}', flush=True)
    return 0 if report['outcome'] in ('ready','planned_not_ready', 'state_inputs_prepared_for_review') else 2


if __name__ == '__main__':
    raise SystemExit(main())
