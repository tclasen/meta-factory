"""The evaluator must never turn absent/invalid grading into acceptance."""

import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt
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
