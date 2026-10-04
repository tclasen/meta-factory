"""Inspect evaluator readiness with durable local logs; no experiment launch."""

import argparse
from pathlib import Path
import tempfile

from .evidence import Attempt, collect
from .readiness import audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    inspect = commands.add_parser('inspect', help='Read-only readiness report, no model or sandbox operations')
    inspect.add_argument('--workload', type=Path, required=True)
    inspect.add_argument('--suite', type=Path, required=True)
    inspect.add_argument('--suite-approval', type=Path)
    inspect.add_argument('--host-attempt', type=Path)
    args = parser.parse_args()
    repository = Path(__file__).resolve().parents[1]
    base = repository / '.factory-planning/evaluation-readiness-logs'
    base.mkdir(parents=True, exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
    directory.rmdir()
    print(f'Logs: {directory}', flush=True)
    print('Read-only audit; no model calls, sandbox creation, or host-policy changes.', flush=True)
    with Attempt(directory, {'kind': 'readiness_inspection'}) as attempt:
        attempt.transition('preflight')
        try:
            for label, command in [('revision', ['git', 'rev-parse', 'HEAD']), ('worktree', ['git', 'status', '--porcelain'])]:
                result = collect(attempt, label, command, cwd=repository, timeout=30)
                if result['outcome'] != 'passed':
                    raise RuntimeError('Repository inspection failed')
            report = audit(args.workload, args.suite, suite_approval=args.suite_approval,
                           host_attempt=args.host_attempt, repository=repository)
        except Exception as error:
            report = {'outcome': 'inspection_error', 'launch_enabled': False, 'error_type': type(error).__name__}
        attempt.transition('failed')  # No READY transition until launch gates exist.
        attempt.finish(report)
        print('Outcome:', report['outcome'])
        for blocker in report.get('blockers', []):
            print('-', blocker)
        print(f'Logs: {directory}', flush=True)
    return 0 if report['outcome'] == 'ready' else 2


if __name__ == '__main__':
    raise SystemExit(main())
