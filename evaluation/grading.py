"""REQ-012/013: external protected suites and fail-closed acceptance aggregation."""

import hashlib
import json
from pathlib import Path
import re
import sys
import time

from .evidence import atomic_json, collect, positive


VERDICTS = {"pass", "fail", "untested", "inconclusive"}


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def contained_file(root, relative):
    path = Path(relative)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError("Invalid suite-relative path")
    full = root / path
    if any(part.is_symlink() for part in [full, *full.parents] if part != root.parent):
        raise ValueError("Suite paths must not be symlinks")
    if not full.is_file() or root not in full.resolve().parents:
        raise ValueError("Suite file missing or outside protected root")
    return full


class Suite:
    def __init__(self, root, packages, *, approval=None):
        self.root = Path(root).resolve(strict=True)
        self.path = self.root / "suite.json"
        self.digest = sha256(self.path)
        self.manifest = json.loads(self.path.read_text())
        self.packages = packages
        package_digest = hashlib.sha256(json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if self.manifest.get("packages_sha256") != package_digest:
            raise ValueError("Suite is bound to different acceptance packages")
        if len({p["id"] for p in packages}) != len(packages):
            raise ValueError("Duplicate package identity")
        self.criteria = {c for p in packages for c in p["criteria"]}
        if sum(len(p["criteria"]) for p in packages) != len(self.criteria):
            raise ValueError("Criterion ownership must be unique")
        if self.manifest.get("schema_version") != 1:
            raise ValueError("Unknown suite schema")
        if not isinstance(self.manifest.get("files"), dict) or not self.manifest["files"]:
            raise ValueError("Suite requires hashed files")
        self.cases = self.manifest["cases"]
        seen = set()
        for case in self.cases:
            identifier = case["id"]
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,57}", identifier) or identifier in seen:
                raise ValueError("Invalid or duplicate case ID")
            seen.add(identifier)
            if not case["criteria"] or not set(case["criteria"]) <= self.criteria:
                raise ValueError("Unmapped case criteria")
            if len(set(case["criteria"])) != len(case["criteria"]):
                raise ValueError("Duplicate criterion reference")
            positive(case["timeout_seconds"], "case timeout")
            if case["source"] not in self.manifest["files"] or not re.fullmatch(r"[a-z][a-z0-9_]*", case["function"]):
                raise ValueError("Unhashed source or invalid function")
        covered = set(self.manifest.get("coverage_complete", []))
        if not covered <= self.criteria:
            raise ValueError("Unknown coverage declaration")
        referenced = {c for case in self.cases for c in case["criteria"]}
        if not covered <= referenced:
            raise ValueError("Complete criterion has no test")
        self.complete = covered
        self.verify()
        self.approved = False
        if approval is not None:
            record = json.loads(Path(approval).read_text())
            if (record.get("suite_sha256") != self.digest or record.get("decision") != "approved"
                    or not record.get("reviewer") or not record.get("reviewed_at")):
                raise ValueError("Missing or stale independent suite approval")
            if self.complete != self.criteria:
                raise ValueError("Incomplete coverage cannot be approved for final acceptance")
            self.approved = True

    def verify(self):
        if sha256(self.path) != self.digest:
            raise ValueError("Suite manifest changed")
        for name, expected in self.manifest["files"].items():
            if sha256(contained_file(self.root, name)) != expected:
                raise ValueError("Protected suite file changed")

    def aggregate(self, results):
        known = {case["id"] for case in self.cases}
        if not set(results) <= known:
            raise ValueError("Results contain unknown cases")
        for identifier, result in results.items():
            if result.get("verdict") not in VERDICTS or result.get("case_id") != identifier:
                raise ValueError("Invalid result identity/verdict")
        criteria = {}
        for criterion in sorted(self.criteria):
            cases = [case["id"] for case in self.cases if criterion in case["criteria"]]
            verdicts = [results.get(identifier, {}).get("verdict", "untested") for identifier in cases]
            verdict = ("fail" if "fail" in verdicts else "inconclusive" if "inconclusive" in verdicts else
                       "untested" if criterion not in self.complete or not cases or "untested" in verdicts else "pass")
            criteria[criterion] = {"verdict": verdict, "cases": cases, "coverage_complete": criterion in self.complete}
        accepted = [p["id"] for p in self.packages if p["criteria"] and
                    all(criteria[c]["verdict"] == "pass" for c in p["criteria"])]
        return {"suite_sha256": self.digest, "suite_approved": self.approved, "criteria": criteria,
                "accepted_packages": accepted if self.approved else [],
                "development_passing_packages": accepted,
                "project_success": self.approved and len(accepted) == len(self.packages),
                "limits": "Unapproved or incomplete suites cannot establish acceptance"}


def run_suite(attempt, suite, target, *, deadline_seconds, development=False):
    """Run trusted hashed suite code only; target application remains untrusted.

    target is operator-created synthetic endpoint/fixture config, never builder
    stdout. No application build script or command is executed on the host here.
    """
    positive(deadline_seconds, "grading deadline")
    if not suite.approved and not development:
        raise ValueError("Independent human suite approval required")
    target_path = attempt.directory / "grading-target.json"
    atomic_json(target_path, target)
    results = {}
    started = time.monotonic()
    for case in suite.cases:
        suite.verify()
        remaining = deadline_seconds - (time.monotonic() - started)
        if remaining <= 0:
            break
        path = attempt.directory / (case["id"] + "-verdict.json")
        argv = [sys.executable, "-m", "evaluation.grade_worker", "--suite", str(suite.root),
                "--case", case["id"], "--target", str(target_path), "--result", str(path),
                "--manifest-sha256", suite.digest]
        command = collect(attempt, "grade-" + case["id"], argv, cwd=Path(__file__).resolve().parents[1],
                          timeout=min(remaining, case["timeout_seconds"]))
        suite.verify()
        if command["outcome"] != "passed" or not path.is_file():
            results[case["id"]] = {"case_id": case["id"], "verdict": "inconclusive",
                                   "reason": "grader_" + command["outcome"]}
        else:
            value = json.loads(path.read_text())
            if value.get("case_id") != case["id"] or value.get("verdict") not in VERDICTS:
                raise ValueError("Malformed grader result")
            results[case["id"]] = value
        attempt.emit("grader", "case.result", results[case["id"]])
    report = suite.aggregate(results)
    report["case_results"] = results
    report["elapsed_seconds"] = time.monotonic() - started
    atomic_json(attempt.directory / "grading.json", report)
    return report
