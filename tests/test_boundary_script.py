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
SPEC = importlib.util.spec_from_file_location("boundaries", SCRIPTS / "test_host_boundaries.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(SCRIPTS))
try:
    SPEC.loader.exec_module(MODULE)
finally:
    sys.path.remove(str(SCRIPTS))


class BoundaryScriptTest(unittest.TestCase):
    def exercise(self, fail_label):
        calls = []

        def collect(directory, label, command, timeout):
            calls.append((label, command))
            return {"check": label, "outcome": "failed" if label == fail_label else "ok"}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = tempfile.mkdtemp

            def make_directory(*args, **kwargs):
                kwargs.setdefault("dir", root)
                return original(*args, **kwargs)

            with patch.object(MODULE, "REPO", root), \
                 patch.object(MODULE.platform, "system", return_value="Darwin"), \
                 patch.object(MODULE, "collect", side_effect=collect), \
                 patch.object(MODULE.tempfile, "mkdtemp", side_effect=make_directory), \
                 contextlib.redirect_stdout(io.StringIO()):
                code = MODULE.main()
            summary = json.loads(next(root.glob(
                ".factory-planning/boundary-preflight-logs/run-*/summary.json")).read_text())
        return code, summary, calls

    def test_mount_failure_does_not_hide_independent_service_results(self):
        code, summary, calls = self.exercise("spec-write-root")
        self.assertEqual(code, 1)
        names = [label for label, _ in calls]
        self.assertIn("host-http", names)
        self.assertEqual(names[-2:], ["cluster-remove", "sandbox-stop"])

    def test_http_failure_is_reported_and_resources_are_stopped(self):
        code, summary, calls = self.exercise("host-http")
        self.assertEqual(code, 1)
        self.assertEqual(calls[-1][1], ["sbx", "stop", summary["sandbox"]])

    def test_create_limits_host_exposure_and_mounts_spec_read_only(self):
        code, summary, calls = self.exercise(None)
        self.assertEqual(code, 0)
        command = next(command for label, command in calls if label == "create")
        self.assertEqual(command[command.index("--publish") + 1],
                         f"127.0.0.1:{summary['host_port']}:18080")
        self.assertTrue(command[-1].endswith("/spec:ro"))
        self.assertFalse(any("policy" in command for _, command in calls))
