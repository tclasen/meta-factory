"""Collect sanitized peer connectivity, independent of application health APIs."""

import hashlib
import json
from pathlib import Path
from .evidence import atomic_json, collect
from .service_probe import endpoint


def service_operation(attempt, sandbox, *, label, configuration, mode):
    if set(configuration) != {'peer_prefix', 'target', 'control'} or mode not in ('available', 'unavailable'):
        raise ValueError('Invalid operator service probe configuration')
    endpoint(configuration['target']); endpoint(configuration['control'])
    probe = Path(__file__).with_name('service_probe.py').read_text()
    argv = ['python3', '-c', probe, '--peer-prefix', json.dumps(configuration['peer_prefix']),
            '--target', configuration['target'], '--control', configuration['control'], '--mode', mode]
    command = collect(attempt, label, sandbox.exec_argv(argv), cwd=Path(__file__).resolve().parents[1], timeout=40)
    report = {'outcome': 'service_probe_incomplete', 'command': command,
              'probe_sha256': hashlib.sha256(probe.encode()).hexdigest()}
    try:
        value = json.loads((attempt.directory / label / 'stdout.log').read_text())
        report['observation'] = value
        if command['outcome'] == 'passed' and value.get('outcome') == 'service_' + mode + '_verified':
            report['outcome'] = value['outcome']
    except (ValueError, OSError, AttributeError):
        pass
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
