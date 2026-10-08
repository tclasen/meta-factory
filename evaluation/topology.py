"""Guarded operator transport for sanitized fresh Kubernetes topology reads."""
import hashlib
import json
from pathlib import Path

from .evidence import atomic_json, collect
from .topology_probe import mapping
from .verdicts import Inconclusive


def capture_topology(attempt, sandbox, *, kubectl_prefix, selected,
                     lifetime_check, label='foundation-topology'):
    """Only operator-selected commands/resources; no builder descriptor execution."""
    selected = mapping(json.loads(json.dumps(selected, allow_nan=False)))
    if (not callable(lifetime_check) or not isinstance(kubectl_prefix, list)
            or not 1 <= len(kubectl_prefix) <= 16
            or any(not isinstance(v, str) or not 0 < len(v) <= 1024 for v in kubectl_prefix)):
        raise ValueError('Trusted bounded topology configuration required')
    if lifetime_check(70) is not True:
        raise Inconclusive('Topology deployment/source lifetime unavailable')
    probe = Path(__file__).with_name('topology_probe.py').read_text()
    argv = sandbox.exec_argv(['python3', '-c', probe, '--kubectl-prefix', json.dumps(kubectl_prefix),
                             '--mapping', json.dumps(selected)])
    command = collect(attempt, label, argv, cwd=Path(__file__).resolve().parents[1], timeout=70)
    if lifetime_check(0) is not True:
        raise Inconclusive('Topology deployment/source lifetime unavailable')
    report = dict(outcome='topology_observation_incomplete', command=command,
                  probe_sha256=hashlib.sha256(probe.encode()).hexdigest())
    try:
        value = json.loads((attempt.directory/label/'stdout.log').read_text())
        if command['outcome'] == 'passed' and value.get('outcome') == 'stable_topology_observed':
            report.update(value)
    except (OSError, ValueError, AttributeError):
        pass
    atomic_json(attempt.directory/(label+'.json'), report)
    return report
