import contextlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
SPEC = importlib.util.spec_from_file_location("isolation", SCRIPTS / "test_host_isolation.py")
ISOLATION = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(SCRIPTS))
try:
    SPEC.loader.exec_module(ISOLATION)
finally:
    sys.path.remove(str(SCRIPTS))


class IsolationScriptTest(unittest.TestCase):
    def exercise(self, fail_label, argv=None):
        calls = []

        def collect(directory, label, command, timeout):
            calls.append((label, command))
            return {"check": label, "outcome": "failed" if label == fail_label else "ok"}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Keep both retained fixture and evidence inside this test's disposable root.
            make_directory = tempfile.mkdtemp

            def temporary_directory(*args, **kwargs):
                kwargs.setdefault("dir", root)
                return make_directory(*args, **kwargs)

            with patch.object(ISOLATION, "REPO", root), \
                 patch.object(ISOLATION.platform, "system", return_value="Darwin"), \
                 patch.object(ISOLATION, "collect", side_effect=collect), \
                 patch.object(ISOLATION.tempfile, "mkdtemp", side_effect=temporary_directory), \
                 contextlib.redirect_stdout(io.StringIO()):
                status = ISOLATION.main(argv or [])
            summary_path = next(root.glob(".factory-planning/isolation-preflight-logs/run-*/summary.json"))
            summary = json.loads(summary_path.read_text())
        return status, summary, calls

    def test_cluster_failure_still_cleans_up_and_records_failure(self):
        status, summary, calls = self.exercise("k3s-ready")
        self.assertEqual(status, 1)
        self.assertEqual(summary["outcome"], "blocked_or_failed")
        self.assertEqual([label for label, _ in calls[-3:]],
                         ["cluster-events", "cluster-remove", "sandbox-stop"])
        self.assertEqual(calls[-1][1], ["sbx", "stop", summary["sandbox"]])

    def test_stop_failure_is_visible_and_returns_nonzero(self):
        status, summary, calls = self.exercise("sandbox-stop")
        self.assertEqual(status, 1)
        self.assertFalse(summary["cleanup_ok"])

    def test_diagnostic_failure_is_not_cleanup_failure(self):
        status, summary, calls = self.exercise("cluster-events")
        self.assertEqual(status, 0)
        self.assertTrue(summary["cleanup_ok"])
        self.assertEqual(summary["diagnostics"][-1]["outcome"], "failed")

    def test_success_scopes_denial_to_created_sandbox(self):
        status, summary, calls = self.exercise(None)
        self.assertEqual(status, 0)
        self.assertEqual(summary["outcome"], "checks_passed_pending_log_review")
        deny = next(command for label, command in calls if label == "deny-egress")
        self.assertEqual(deny, ["sbx", "policy", "deny", "network", "--sandbox", summary["sandbox"], "**"])

    def test_extended_observations_do_not_claim_isolation_pass(self):
        status, summary, calls = self.exercise(None, ["--egress"])
        self.assertEqual(status, 0)
        self.assertEqual(summary["outcome"], "observations_collected_pending_review")
        for stage in ("before", "denied", "after-allow"):
            self.assertIn("sandbox-egress-" + stage, [label for label, _ in calls])
            self.assertIn("pod-egress-" + stage, [label for label, _ in calls])
        allow = next(command for label, command in calls if label == "allow-registry")
        self.assertEqual(allow, ["sbx", "policy", "allow", "network", "--sandbox",
                                summary["sandbox"], "registry.npmjs.org:443"])
