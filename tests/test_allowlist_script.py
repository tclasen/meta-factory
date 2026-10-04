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
SPEC = importlib.util.spec_from_file_location("allowlist", SCRIPTS / "test_host_allowlist.py")
MODULE = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(SCRIPTS))
try:
    SPEC.loader.exec_module(MODULE)
finally:
    sys.path.remove(str(SCRIPTS))

BASELINE = {"rules": [{"id": "original", "scope": "global", "decision": "allow",
                       "resources": ["**"], "actions": ["net:connect:tcp"],
                       "editable": True, "status": "active", "policy_id": "local-policy"}]}


class AllowlistScriptTest(unittest.TestCase):
    def test_unfamiliar_global_policy_is_rejected(self):
        for snapshot in ({"rules": []}, {"rules": BASELINE["rules"] * 2},
                         {"rules": [{**BASELINE["rules"][0], "actions": ["net:connect:udp"]}]}):
            with self.assertRaises(ValueError):
                MODULE.global_allow_rule(snapshot)

    def test_failure_after_removal_restores_before_stopping_sandbox(self):
        calls = []

        def collect(directory, label, command, timeout):
            calls.append((label, command))
            if label in ("policy-before", "policy-recheck", "policy-after"):
                (directory / f"{label}.stdout.log").write_text(json.dumps(BASELINE))
            return {"check": label, "outcome": "failed" if label == "allowed-during" else "ok"}

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(MODULE, "REPO", Path(temporary)), \
                 patch.object(MODULE.platform, "system", return_value="Darwin"), \
                 patch.object(MODULE, "collect", side_effect=collect), \
                 patch.object(MODULE.subprocess, "Popen"), \
                 contextlib.redirect_stdout(io.StringIO()):
                result = MODULE.main(["--allow-temporary-global-policy-change"])
            summary = json.loads(next(Path(temporary).glob(
                ".factory-planning/allowlist-preflight-logs/run-*/summary.json")).read_text())
        self.assertEqual(result, 1)
        self.assertTrue(summary["restored"])
        names = [name for name, _ in calls]
        self.assertLess(names.index("restore-global-allow"), names.index("sandbox-stop"))
        self.assertIn(("restore-global-allow", MODULE.RESTORE), calls)

    def test_failed_restore_keeps_marker_for_watchdog(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "restoration-needed").write_text("test")
            with patch.object(MODULE, "collect", return_value={"outcome": "failed"}):
                self.assertFalse(MODULE.restore(directory, "restore"))
            self.assertTrue((directory / "restoration-needed").exists())
            with patch.object(MODULE, "collect", return_value={"outcome": "ok"}):
                self.assertTrue(MODULE.restore(directory, "retry"))
            self.assertFalse((directory / "restoration-needed").exists())
