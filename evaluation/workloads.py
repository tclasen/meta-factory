"""Operator-selected workload faults; application topology is never guessed."""

import hashlib
import json
from pathlib import Path

from .evidence import atomic_json, collect
from .workload_probe import KINDS, NAME


def workload_operation(attempt, sandbox, *, label, kubectl_prefix, namespace, kind,
                       name, expected=None, replicas=None, convergence='ready'):
    """Inspect, or conditionally scale and wait. Caller must arrange restoration.

    Persist the original observation before suspension. Even a failed scale may
    have mutated the target; cleanup must inspect the same UID and restore it or
    stop the disposable grading sandbox. Use only under its lifetime guard.
    """
    if convergence not in ('ready', 'running'):
        raise ValueError('Invalid workload convergence mode')
    if kind not in KINDS or not all(NAME.fullmatch(v) for v in (namespace, name)):
        raise ValueError('Invalid workload identity')
    if not isinstance(label, str) or not 1 <= len(label) <= 48 or not NAME.fullmatch(label):
        raise ValueError('Invalid workload evidence label')
    probe = Path(__file__).with_name('workload_probe.py').read_text()
    argv = ['python3', '-c', probe, '--kubectl-prefix', json.dumps(kubectl_prefix),
            '--namespace', namespace, '--kind', kind, '--name', name,
            '--operation', 'scale' if expected is not None else 'inspect']
    if convergence != 'ready':
        argv += ['--convergence', convergence]
    if expected is not None:
        if any(expected[key] != value for key, value in (('namespace', namespace), ('kind', kind), ('name', name))):
            raise ValueError('Observation belongs to a different workload')
        argv += ['--expected-uid', expected['uid'], '--expected-replicas', str(expected['replicas']),
                 '--replicas', str(replicas)]
    command = collect(attempt, label, sandbox.exec_argv(argv), cwd=Path(__file__).resolve().parents[1], timeout=135)
    report = {'outcome': 'workload_operation_incomplete', 'command': command,
              'probe_sha256': hashlib.sha256(probe.encode()).hexdigest()}
    output = attempt.directory / label / 'stdout.log'
    try:
        value = json.loads(output.read_text())
        if isinstance(value, dict):
            report['observation'] = value
            if command['outcome'] == 'passed' and value.get('outcome') in ('workload_observed', 'workload_scaled'):
                report['outcome'] = value['outcome']
    except (ValueError, OSError):
        pass
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
