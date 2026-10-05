"""The evaluator must never turn absent/invalid grading into acceptance."""

import hashlib
from contextlib import contextmanager
import json
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.fault_broker import FaultBroker
from evaluation.grading import Suite, run_suite


class GradingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.suite = self.root / "suite"; self.suite.mkdir()
        self.packages = [{"id": "WP-001", "criteria": ["AC-001", "AC-002"]}]
        self.source = self.suite / "cases.py"
        self.source.write_text('def good(target):\n    assert target["value"] == 1, "wrong value"\n\ndef bad(target):\n    raise RuntimeError("fixture infrastructure")\n')
        self.manifest = {"schema_version": 1, "packages_sha256": hashlib.sha256(json.dumps(self.packages, sort_keys=True, separators=(",", ":")).encode()).hexdigest(), "files": {"cases.py": hashlib.sha256(self.source.read_bytes()).hexdigest()},
                         "cases": [{"id": "first", "source": "cases.py", "function": "good",
                                    "criteria": ["AC-001", "AC-002"], "timeout_seconds": 2}],
                         "coverage_complete": ["AC-001", "AC-002"]}
        self.save()

    def save(self):
        (self.suite / "suite.json").write_text(json.dumps(self.manifest))

    def approval(self):
        path = self.root / "review.json"
        path.write_text(json.dumps({"suite_sha256": hashlib.sha256((self.suite / "suite.json").read_bytes()).hexdigest(),
                                    "decision": "approved", "reviewer": "fixture reviewer", "reviewed_at": "fixture"}))
        return path

    def test_no_missing_or_unapproved_acceptance(self):
        suite = Suite(self.suite, self.packages)
        result = suite.aggregate({})
        self.assertFalse(result["project_success"])
        result = suite.aggregate({"first": {"case_id": "first", "verdict": "pass"}})
        self.assertEqual(result["accepted_packages"], [])
        self.assertEqual(result["development_passing_packages"], ["WP-001"])

    def test_incomplete_coverage_is_not_pass_or_approvable(self):
        self.manifest["coverage_complete"] = ["AC-001"]; self.save()
        suite = Suite(self.suite, self.packages)
        result = suite.aggregate({"first": {"case_id": "first", "verdict": "pass"}})
        self.assertEqual(result["criteria"]["AC-002"]["verdict"], "untested")
        with self.assertRaises(ValueError):
            Suite(self.suite, self.packages, approval=self.approval())

    def test_changed_source_and_stale_approval_refused(self):
        approval = self.approval()
        suite = Suite(self.suite, self.packages, approval=approval)
        self.source.write_text("changed")
        with self.assertRaises(ValueError): suite.verify()
        self.manifest["files"]["cases.py"] = hashlib.sha256(self.source.read_bytes()).hexdigest(); self.save()
        with self.assertRaises(ValueError): Suite(self.suite, self.packages, approval=approval)

    def test_unmapped_or_forged_result_refused(self):
        suite = Suite(self.suite, self.packages)
        with self.assertRaises(ValueError): suite.aggregate({"invented": {"verdict": "pass"}})
        with self.assertRaises(ValueError): suite.aggregate({"first": {"case_id": "other", "verdict": "pass"}})
        self.manifest["cases"][0]["criteria"] = ["AC-999"]; self.save()
        with self.assertRaises(ValueError): Suite(self.suite, self.packages)

    def test_worker_distinguishes_pass_failure_and_grader_error(self):
        for value, verdict in [(1, "pass"), (2, "fail")]:
            with Attempt(self.root / f"run-{value}", {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages, approval=self.approval()),
                                   {"value": value}, deadline_seconds=5)
            self.assertEqual(report["criteria"]["AC-001"]["verdict"], verdict)
            self.assertEqual(report["project_success"], value == 1)
        self.manifest["cases"][0]["function"] = "bad"; self.save()
        with Attempt(self.root / "broken", {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {}, deadline_seconds=5, development=True)
        self.assertEqual(report["criteria"]["AC-001"]["verdict"], "inconclusive")

    def test_uncertain_runtime_fault_stops_following_cases(self):
        for mode in ('restore-error', 'timeout', 'exception'):
            source = {'restore-error': 'from evaluation.faults import FaultRestoreError\ndef first(target):\n    raise FaultRestoreError("fixture")\n',
                      'timeout': 'import time\ndef first(target):\n    time.sleep(10)\n',
                      'exception': 'def first(target):\n    raise RuntimeError("uncertain state")\n'}[mode]
            self.source.write_text(source + '\ndef second(target):\n    raise AssertionError("must not run")\n')
            self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
            self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'],
                                           timeout_seconds=0.2 if mode == 'timeout' else 2, mutates_runtime=True),
                                      dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
            self.save()
            with Attempt(self.root / mode, {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages), {}, deadline_seconds=5, development=True)
            self.assertTrue(report['aborted'])
            self.assertEqual(report['case_results']['first']['verdict'], 'inconclusive')
            self.assertNotIn('second', report['case_results'])
            self.assertEqual(report['criteria']['AC-002']['verdict'], 'untested')

    def test_worker_preserves_explicit_missing_evidence_verdicts(self):
        for exception, verdict in [('Inconclusive', 'inconclusive'), ('Untested', 'untested')]:
            with self.subTest(exception=exception):
                self.source.write_text(
                    f'from evaluation.grade_worker import {exception}\n'
                    f'def good(target):\n    raise {exception}("Required fixture unavailable")\n')
                self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
                self.save()
                with Attempt(self.root / exception, {}) as attempt:
                    report = run_suite(attempt, Suite(self.suite, self.packages), {},
                                       deadline_seconds=5, development=True)
                self.assertEqual(report['case_results']['first']['verdict'], verdict)
                self.assertEqual(report['case_results']['first']['reason'], 'Required fixture unavailable')
                self.assertFalse(report['project_success'])

    def test_mutation_declaration_requires_boolean(self):
        for declaration in ('mutates_runtime', 'mutates_shared_state', 'reads_audit'):
            self.manifest['cases'][0][declaration] = 'false'; self.save()
            with self.assertRaises(ValueError): Suite(self.suite, self.packages)
            del self.manifest['cases'][0][declaration]

    def test_shared_fixture_failure_aborts_without_runtime_capability(self):
        for mode, body, verdict in [
                ('pass', 'pass', 'pass'),
                ('assertion', 'raise AssertionError("Membership changed unexpectedly")', 'fail'),
                ('inconclusive', 'raise Inconclusive("Restoration unknown")', 'inconclusive'),
                ('untested', 'raise Untested("Missing observation")', 'untested'),
                ('timeout', 'time.sleep(10)', 'inconclusive')]:
            self.source.write_text(
                'import time\nfrom evaluation.verdicts import Inconclusive, Untested\n'
                'def first(target):\n    assert "_fault_control" not in target\n    ' + body + '\n'
                'def second(target):\n    pass\n')
            self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
            self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'],
                                           timeout_seconds=0.2 if mode == 'timeout' else 2, mutates_shared_state=True),
                                      dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
            self.save()
            @contextmanager
            def unexpected_fault(role):
                raise AssertionError('Shared state tests cannot request runtime faults')
                yield
            with FaultBroker(['storage'], unexpected_fault) as broker, Attempt(self.root / ('shared-' + mode), {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages), {'_fault_control': {'untrusted': True}},
                                   deadline_seconds=5, development=True, fault_broker=broker)
            self.assertEqual(report['case_results']['first']['verdict'], verdict)
            self.assertEqual(report['aborted'], mode != 'pass')
            self.assertEqual('second' in report['case_results'], mode == 'pass')

    def test_worker_fault_requests_execute_in_parent_and_strip_untrusted_capability(self):
        self.source.write_text('from evaluation.fault_broker import remote_fault\ndef first(target):\n    with remote_fault(target["_fault_control"], "storage"):\n        pass\n\ndef second(target):\n    assert "_fault_control" not in target\n')
        self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'], timeout_seconds=2, mutates_runtime=True),
                                  dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
        self.save(); events = []
        @contextmanager
        def factory(role):
            events.append(('suspend', role))
            try: yield
            finally: events.append(('restore', role))
        with FaultBroker(['storage'], factory) as broker, Attempt(self.root / 'broker', {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {'_fault_control': {'token': 'untrusted'}},
                               deadline_seconds=5, development=True, fault_broker=broker)
        self.assertEqual(events, [('suspend', 'storage'), ('restore', 'storage')])
        self.assertEqual([v['verdict'] for v in report['case_results'].values()], ['pass', 'pass'])
        self.assertFalse(report['aborted'])

    def test_audit_capability_is_injected_only_for_declared_cases(self):
        from evaluation.audit_broker import AuditBroker
        self.source.write_text(
            'from evaluation.audit_broker import read_audit\n'
            'def first(target):\n'
            '    value = read_audit(target["_audit_control"], ["00000000-0000-0000-0000-000000000001"])\n'
            '    assert value == {"events": [], "truncated": False}\n'
            '    assert "_fault_control" in target\n'
            'def second(target):\n'
            '    assert "_audit_control" not in target\n'
            '    assert "_fault_control" not in target\n')
        self.manifest['files']['cases.py'] = hashlib.sha256(self.source.read_bytes()).hexdigest()
        self.manifest['cases'] = [dict(id='first', source='cases.py', function='first', criteria=['AC-001'],
                                       timeout_seconds=2, reads_audit=True, mutates_runtime=True),
                                  dict(id='second', source='cases.py', function='second', criteria=['AC-002'], timeout_seconds=2)]
        self.save()
        @contextmanager
        def fault(role): yield
        with AuditBroker(lambda *_: {'events': [], 'truncated': False}) as audit, FaultBroker(['storage'], fault) as faults:
            with Attempt(self.root / 'audit', {}) as attempt:
                report = run_suite(attempt, Suite(self.suite, self.packages),
                    {'_audit_control': {'token': 'forged'}, '_fault_control': {'token': 'forged'}},
                    deadline_seconds=5, development=True, audit_broker=audit, fault_broker=faults)
        self.assertEqual([v['verdict'] for v in report['case_results'].values()], ['pass', 'pass'])
        self.assertEqual(json.loads((self.root / 'audit/grading-target.json').read_text()), {})

    def test_unsettled_audit_reader_aborts_following_cases(self):
        from types import SimpleNamespace
        self.manifest['cases'][0]['reads_audit'] = True
        self.manifest['cases'].append(dict(id='second', source='cases.py', function='good',
                                          criteria=['AC-002'], timeout_seconds=2))
        self.save()
        with Attempt(self.root / 'unsettled-audit', {}) as attempt:
            report = run_suite(attempt, Suite(self.suite, self.packages), {'value': 1},
                deadline_seconds=5, development=True,
                audit_broker=SimpleNamespace(configuration={}, wait_idle=lambda: False))
        self.assertTrue(report['aborted'])
        self.assertEqual(report['case_results']['first']['reason'], 'audit_reader_unsettled')
        self.assertNotIn('second', report['case_results'])
