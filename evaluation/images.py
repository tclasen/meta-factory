"""Capture only sanitized runtime image identities from the grading sandbox."""

import hashlib
import json
from pathlib import Path

from .evidence import atomic_json, collect
from .image_probe import NAME


def capture_images(attempt, sandbox, *, kubectl_prefix, namespace='incident-app'):
    if not NAME.fullmatch(namespace):
        raise ValueError('Invalid image inventory namespace')
    probe = Path(__file__).with_name('image_probe.py').read_text()
    argv = sandbox.exec_argv(['python3', '-c', probe, '--kubectl-prefix', json.dumps(kubectl_prefix),
                             '--namespace', namespace])
    label = 'image-inventory-' + namespace
    if len(label) > 64:
        label = 'image-inventory-' + hashlib.sha256(namespace.encode()).hexdigest()[:12]
    # The trusted probe executes inside sbx; application code never executes here.
    command = collect(attempt, label, argv, cwd=Path(__file__).resolve().parents[1], timeout=45)
    report = {'outcome': 'image_inventory_incomplete', 'command': command,
              'namespace': namespace, 'probe_sha256': hashlib.sha256(probe.encode()).hexdigest()}
    if command['outcome'] == 'passed':
        value = json.loads((attempt.directory / label / 'stdout.log').read_text())
        if value.get('outcome') == 'image_identities_observed' and value.get('query_exit_code') == 0:
            report.update(value)
    atomic_json(attempt.directory / (label + '.json'), report)
    return report
