"""REQ-012/013: external protected suites and fail-closed acceptance aggregation."""

import hashlib
import json
from pathlib import Path
import re
import sys
import time

from .evidence import atomic_json, collect, positive
from .browser import BROWSER_MODES, run_browser_case


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
            if "browser" in case:
                if not isinstance(case["browser"], str) or case["browser"] not in BROWSER_MODES:
                    raise ValueError("Invalid browser invocation mode")
                if case.get("mutates_runtime", False) or case.get("reads_audit", False) or case.get("reads_jobs", False) or case.get("stages_jobs", False) or case.get("inspects_security", False) or case.get("runs_ops", False):
                    raise ValueError("Browser cases cannot receive host broker capabilities")
            for declaration in ("mutates_runtime", "mutates_shared_state", "reads_audit", "reads_jobs", "stages_jobs", "inspects_security", "runs_ops"):
                if type(case.get(declaration, False)) is not bool:
                    raise ValueError("Invalid case capability declaration: " + declaration)
            if case.get('runs_ops', False) and (not case.get('mutates_shared_state', False) or any(case.get(k,False) for k in ('mutates_runtime','reads_audit','reads_jobs','stages_jobs','inspects_security'))):
                raise ValueError('Operations cases require exclusive shared-state mutation')
            if case.get('stages_jobs', False) and not (case.get('mutates_runtime', False) and case.get('reads_jobs', False)):
                raise ValueError('Staged jobs require runtime mutation and independent job observations')
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


def run_suite(attempt, suite, target, *, deadline_seconds, development=False, fault_broker=None, audit_broker=None,
              browser_executor=None, job_broker=None, staging_broker=None, security_broker=None, ops_broker=None):
    """Run trusted hashed suite code only; target application remains untrusted.

    target is operator-created synthetic endpoint/fixture config, never builder
    stdout. No application build script or command is executed on the host here.
    """
    positive(deadline_seconds, "grading deadline")
    if not suite.approved and not development:
        raise ValueError("Independent human suite approval required")
    target = dict(target)
    target.pop('_fault_control', None)
    target.pop('_audit_control', None)
    target.pop('_job_control', None)
    target.pop('_staging_control', None)
    target.pop('_security_control', None)
    target.pop('_ops_control', None)
    target_path = attempt.directory / "grading-target.json"
    atomic_json(target_path, target)
    results = {}
    aborted = False
    started = time.monotonic()
    for case in suite.cases:
        suite.verify()
        remaining = deadline_seconds - (time.monotonic() - started)
        if remaining <= 0:
            break
        path = attempt.directory / (case["id"] + "-verdict.json")
        worker_path = attempt.directory / ("grade-" + case["id"]) / "worker-verdict.json"
        worker_target = target_path
        capabilities = {}
        if case.get('mutates_runtime', False) and not case.get('stages_jobs', False) and fault_broker is not None:
            capabilities['_fault_control'] = fault_broker.configuration
        if case.get('reads_audit', False) and audit_broker is not None:
            capabilities['_audit_control'] = audit_broker.configuration
        if case.get('reads_jobs', False) and job_broker is not None:
            capabilities['_job_control'] = job_broker.configuration
        if case.get('stages_jobs', False) and staging_broker is not None:
            capabilities['_staging_control'] = staging_broker.configuration
        if case.get('inspects_security', False) and security_broker is not None:
            capabilities['_security_control'] = security_broker.configuration
        ops_available = ops_broker is not None and not ops_broker.used
        if case.get('runs_ops', False) and ops_available:
            capabilities['_ops_control'] = ops_broker.configuration
        if capabilities:
            worker_target = attempt.directory / (case['id'] + '-target.json')
            atomic_json(worker_target, dict(target, **capabilities))
        if case.get('runs_ops', False) and not ops_available:
            results[case['id']] = {'case_id':case['id'],'verdict':'inconclusive','reason':'ops_capability_unavailable','abort_suite':True}
        elif case.get('stages_jobs', False) and (staging_broker is None or job_broker is None):
            results[case['id']] = {'case_id':case['id'], 'verdict':'inconclusive',
                                    'reason':'staging_capability_unavailable', 'abort_suite':True}
            atomic_json(path, results[case['id']])
        elif case.get('inspects_security', False) and security_broker is None:
            results[case['id']] = {'case_id':case['id'], 'verdict':'inconclusive',
                                    'reason':'security_capability_unavailable'}
            atomic_json(path, results[case['id']])
        elif "browser" in case:
            results[case["id"]] = run_browser_case(browser_executor, attempt, suite, case, target,
                                                  min(remaining, case["timeout_seconds"]))
            atomic_json(path, results[case["id"]])
        else:
            argv = [sys.executable, "-m", "evaluation.grade_worker", "--suite", str(suite.root),
                    "--case", case["id"], "--target", str(worker_target), "--result", str(worker_path),
                    "--manifest-sha256", suite.digest]
            command = collect(attempt, "grade-" + case["id"], argv, cwd=Path(__file__).resolve().parents[1],
                              timeout=min(remaining, case["timeout_seconds"]))
            if command["outcome"] != "passed" or not worker_path.is_file():
                results[case["id"]] = {"case_id": case["id"], "verdict": "inconclusive",
                                       "reason": "grader_" + command["outcome"]}
            else:
                value = json.loads(worker_path.read_text())
                if value.get("case_id") != case["id"] or value.get("verdict") not in VERDICTS:
                    raise ValueError("Malformed grader result")
                results[case["id"]] = value
        suite.verify()
        if case.get('mutates_runtime', False) and not case.get('stages_jobs', False) and fault_broker is not None:
            if not fault_broker.wait_idle() or fault_broker.aborted:
                results[case['id']] = {'case_id': case['id'], 'verdict': 'inconclusive',
                                       'reason': 'fault_control_aborted', 'abort_suite': True}
        if case.get('stages_jobs', False) and staging_broker is not None:
            if not staging_broker.wait_idle() or staging_broker.aborted:
                results[case['id']] = {'case_id':case['id'], 'verdict':'inconclusive',
                                        'reason':'staging_control_aborted', 'abort_suite':True}
        if case.get('reads_audit', False) and audit_broker is not None:
            if not audit_broker.wait_idle():
                results[case['id']] = {'case_id': case['id'], 'verdict': 'inconclusive',
                                       'reason': 'audit_reader_unsettled', 'abort_suite': True}
        if case.get('reads_jobs', False) and job_broker is not None:
            if not job_broker.wait_idle():
                results[case['id']] = {'case_id': case['id'], 'verdict': 'inconclusive',
                                       'reason': 'job_reader_unsettled', 'abort_suite': True}
        if case.get('inspects_security', False) and security_broker is not None:
            if not security_broker.wait_idle():
                results[case['id']] = {'case_id':case['id'], 'verdict':'inconclusive',
                                        'reason':'security_reader_unsettled', 'abort_suite':True}
        if case.get('runs_ops', False) and ops_available:
            settled = ops_broker.wait_idle()
            observed = ops_broker.result if settled else None
            valid = (isinstance(observed,dict) and set(observed)=={'verdict','abort_suite'}
                     and observed['verdict'] in VERDICTS-{'untested'} and type(observed['abort_suite']) is bool
                     and observed['abort_suite']==(observed['verdict']!='pass') and ops_broker.used)
            if not valid or observed['verdict'] == 'inconclusive':
                results[case['id']] = {'case_id':case['id'],'verdict':'inconclusive','reason':'ops_control_unsettled','abort_suite':True}
            elif observed.get('verdict') == 'fail':
                results[case['id']] = {'case_id':case['id'],'verdict':'fail','reason':'ops_preservation_mismatch','abort_suite':True}
        atomic_json(path, results[case["id"]])
        attempt.emit("grader", "case.result", results[case["id"]])
        shared_state_uncertain = (case.get("mutates_shared_state", False)
                                  and results[case["id"]]["verdict"] != "pass")
        if (results[case["id"]].get("abort_suite") is True
                or shared_state_uncertain
                or case.get("mutates_runtime", False) and results[case["id"]]["verdict"] == "inconclusive"):
            aborted = True
            attempt.emit("grader", "suite.aborted", {"case_id": case["id"],
                                                       "reason": ("shared_fixture_state_uncertain" if shared_state_uncertain
                                                                  else "runtime_state_uncertain")})
            break
    report = suite.aggregate(results)
    report["case_results"] = results
    report["aborted"] = aborted
    report["elapsed_seconds"] = time.monotonic() - started
    atomic_json(attempt.directory / "grading.json", report)
    return report
