"""Read-only readiness audit. No configuration field can launch an experiment."""

import hashlib
import json
from pathlib import Path

from .grading import Suite, sha256


ADAPTER_FILES = ('evaluation/evidence.py', 'evaluation/runtime.py', 'evaluation/sandbox.py',
                 'evaluation/schema/codex-0.160.0.json', 'pyproject.toml', 'uv.lock')


def effective_tcp_policy(snapshot, sandbox_name, approved_destinations):
    """Conservative pinned-format check; observations and review are still required."""
    if not isinstance(snapshot.get('rules'), list) or not approved_destinations:
        return False
    destinations = set()
    for rule in snapshot['rules']:
        if rule.get('status') != 'active':
            continue
        if rule.get('resource_type') != 'network':
            continue
        if rule.get('scope') not in ('global', 'sandbox:' + sandbox_name):
            # The caller supplies an effective snapshot, not an all-sandbox dump.
            return False
        if rule.get('decision') == 'allow' and 'net:connect:tcp' in rule.get('actions', []):
            values = rule.get('resources')
            if not isinstance(values, list) or any(not isinstance(v, str) or '*' in v for v in values):
                return False
            destinations.update(values)
    return bool(destinations) and destinations == set(approved_destinations)


def audit(workload, suite_root, *, suite_approval=None, host_attempt=None, repository=None):
    """Describe remaining gates; never turn file presence into tested isolation."""
    workload = Path(workload).resolve(strict=True)
    blockers = []
    details = {}
    review = json.loads((workload / 'review/WORKLOAD-APPROVAL.json').read_text())
    actual = {str(p.relative_to(workload)): sha256(p) for p in (workload / 'builder').rglob('*') if p.is_file()}
    reviewed = actual == review.get('workload_sha256')
    details['reviewed_workload_unchanged'] = reviewed
    if not reviewed:
        blockers.append('Reviewed workload bytes changed')
    packages = json.loads((workload / 'builder/packages.json').read_text())['packages']
    suite = Suite(suite_root, packages, approval=suite_approval)
    details['suite_sha256'] = suite.digest
    details['complete_criteria'] = sorted(suite.complete)
    details['incomplete_criteria'] = sorted(suite.criteria - suite.complete)
    if suite.complete != suite.criteria:
        blockers.append('Acceptance-suite implementation/validation incomplete')
    if not suite.approved:
        blockers.append('Independent human acceptance-suite review pending')
    details['host_preflight_passed'] = False
    if host_attempt is not None and repository is not None:
        host = Path(host_attempt)
        result = json.loads((host / 'result.json').read_text())
        manifest = json.loads((host / 'manifest.json').read_text())['inputs']
        current = {name: sha256(Path(repository) / name) for name in ADAPTER_FILES}
        good = (result.get('outcome') == 'preflight_passed_pending_event_review'
                and result.get('cleanup') == {'builder': True, 'grader': True}
                and manifest.get('adapter_sha256') == current)
        details['host_preflight_passed'] = good
    if not details['host_preflight_passed']:
        blockers.append('Bounded Mac adapter preflight missing, stale, or failed')
    # These gates have no verified implementation/evidence yet. Do not expose
    # boolean overrides that make an unsafe launch look ready.
    blockers.extend([
        'Live preflight event review and protected grader transport validation pending',
        'Long-run effective default-deny policy and recovery arrangement pending',
        'Remote termination/watchdog behavior under operator interruption pending',
        'Full deployment/browser/fault/scale grading integration pending',
        'Final protocol limits, suite identities, and launch authorization pending',
    ])
    return {'outcome': 'not_ready', 'launch_enabled': False, 'details': details, 'blockers': blockers}
