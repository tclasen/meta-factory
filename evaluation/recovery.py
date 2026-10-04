"""Explicit cleanup of resources recorded by an interrupted controller attempt."""

import hashlib
import json
from pathlib import Path
import argparse
import platform
import tempfile
import sys

from .evidence import Attempt, atomic_json, collect
from .sandbox import disjoint
from .watchdog import NAME


def resources(directory):
    """Read only protected controller records; never discover resources by prefix."""
    directory = Path(directory).resolve(strict=True)
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest.get('schema_version') != 1 or not manifest.get('attempt_id'):
        raise ValueError('Source must be a controller attempt directory')
    records = {}
    for path in directory.rglob('*-resource.json'):
        if len(records) >= 100:
            raise ValueError('Recovery resource bound exceeded')
        if any(part.is_symlink() for part in (path, *path.parents) if directory in part.parents):
            raise ValueError('Symlink in recovery evidence')
        if path.stat().st_size > 65536:
            raise ValueError('Oversized resource record')
        raw = path.read_bytes()
        record = json.loads(raw)
        name = record.get('name', '')
        if not NAME.fullmatch(name) or record.get('manual_stop') != ['sbx', 'stop', name]:
            raise ValueError('Invalid recovery resource identity')
        if name in records:
            raise ValueError('Duplicate recovery resource identity')
        # Require the matching creation command evidence, not merely a name file.
        role = name.split('-')[2]
        events = path.parent / 'events.jsonl'
        if events.stat().st_size > 64 * 1024 * 1024:
            raise ValueError('Oversized creation evidence')
        started = False
        with events.open() as stream:
            for line in stream:
                event = json.loads(line)
                payload = event.get('payload', {})
                argv = payload.get('argv', [])
                if (event.get('type') == 'command.start' and payload.get('check') == role + '-create'
                        and argv[:4] == ['sbx', 'create', '--name', name]):
                    started = True
        if not started:
            raise ValueError('Resource has no matching creation attempt')
        creation_result = path.parent / (role + '-create') / 'result.json'
        settled = False
        if creation_result.is_file() and not creation_result.is_symlink():
            result = json.loads(creation_result.read_text())
            settled = (result.get('outcome') in ('passed', 'failed')
                       and type(result.get('exit_code')) is int and bool(result.get('ended')))
        records[name] = {'record': str(path.relative_to(directory)),
                         'sha256': hashlib.sha256(raw).hexdigest(), 'creation_command_settled': settled}
    return records


def state_from_listing(output, name):
    lines = output.splitlines()
    if not lines or lines[0].split()[:3] != ['SANDBOX', 'AGENT', 'STATUS']:
        raise ValueError('Unknown sbx listing format')
    rows = [line.split() for line in lines[1:] if line.split() and line.split()[0] == name]
    if not rows:
        return 'absent'
    if len(rows) != 1 or len(rows[0]) < 3:
        raise ValueError('Ambiguous sbx resource identity')
    return rows[0][2]


def recover(attempt, source, *, command_runner=collect):
    """Bounded, explicitly invoked cleanup. Never resume a model or restart sbx.

    This can clean up after host/daemon recovery; it cannot stop anything while
    that host/daemon is unavailable. Operators must ensure the original controller
    has exited before invoking recovery. Original attempt evidence is unchanged.
    """
    source = Path(source).resolve(strict=True)
    disjoint(attempt.directory, source)
    selected = resources(source)
    atomic_json(attempt.directory / 'recovery-inputs.json', {'source': str(source), 'resources': selected})
    results = {}
    for index, name in enumerate(selected):
        result = {'remote_termination_verified': False, 'manual_stop': ['sbx', 'stop', name]}
        try:
            def listing(suffix):
                label = f'recovery-{index}-{suffix}'
                checked = command_runner(attempt, label, ['sbx', 'ls'], cwd=attempt.directory, timeout=30)
                if checked['outcome'] != 'passed':
                    raise RuntimeError('Recovery listing failed')
                return state_from_listing((attempt.directory / label / 'stdout.log').read_text(), name)
            before = listing('before')
            result['before'] = before
            if before not in ('stopped', 'absent'):
                stopped = command_runner(attempt, f'recovery-{index}-stop', ['sbx', 'stop', name],
                                         cwd=attempt.directory, timeout=60)
                result['stop'] = stopped
                after = listing('after')
                result['remote_termination_verified'] = stopped['outcome'] == 'passed' and after in ('stopped', 'absent')
            else:
                after = before
                # An orphaned create command might still be provisioning after
                # controller death. One absent listing cannot establish cleanup.
                result['remote_termination_verified'] = before == 'stopped' or selected[name]['creation_command_settled']
                if not result['remote_termination_verified']:
                    result['reason'] = 'absent_with_unsettled_creation'
            result['after'] = after
        except Exception as error:
            result['error_type'] = type(error).__name__
        results[name] = result
        attempt.emit('controller', 'recovery.resource', {'name': name, **result})
    report = {'outcome': 'cleanup_verified' if all(r['remote_termination_verified'] for r in results.values()) else 'cleanup_incomplete',
              'resources': results, 'resumed': False,
              'limits': 'Explicit cleanup after host availability returns; no reboot-surviving deadline enforcement or experiment continuation'}
    atomic_json(attempt.directory / 'recovery-result.json', report)
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--attempt', type=Path, required=True,
                        help='Protected evidence of an attempt whose controller has exited')
    args = parser.parse_args()
    if platform.system() != 'Darwin':
        parser.error('Run recovery on the host Mac after the original controller exits')
    repository = Path(__file__).resolve().parents[1]
    base = repository / '.factory-planning/evaluation-recovery-logs'
    base.mkdir(exist_ok=True)
    directory = Path(tempfile.mkdtemp(prefix='run-', dir=base))
    directory.rmdir()
    print('Logs:', directory, flush=True)
    print('Stops only exact resources recorded in the supplied attempt. No model, resume, sandbox creation or policy change.', flush=True)
    with Attempt(directory, {'kind': 'explicit_recovery', 'source': str(args.attempt.resolve())}) as attempt:
        attempt.transition('preflight')
        report = {'outcome': 'recovery_error', 'resumed': False}
        try:
            for label, argv in [('revision', ['git', 'rev-parse', 'HEAD']),
                                ('python', [sys.executable, '--version']), ('macos', ['sw_vers']),
                                ('sbx-version', ['sbx', 'version'])]:
                result = collect(attempt, label, argv, cwd=repository, timeout=30)
                if result['outcome'] != 'passed':
                    raise RuntimeError('Recovery preflight failed')
            if '0.46.0' not in (directory / 'sbx-version/stdout.log').read_text():
                raise ValueError('Unreviewed sbx version')
            report = recover(attempt, args.attempt)
        except BaseException as error:
            report['error_type'] = type(error).__name__
        finally:
            attempt.transition('failed')
            attempt.finish(report)
            print('Outcome:', report['outcome'], '\nLogs:', directory, flush=True)
    return 0 if report['outcome'] == 'cleanup_verified' else 1


if __name__ == '__main__':
    import signal
    def interrupt(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupt)
    raise SystemExit(main())
