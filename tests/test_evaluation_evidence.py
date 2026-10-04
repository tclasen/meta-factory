"""Deterministic evaluator fixtures; no model or benchmark calls."""

import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from evaluation.evidence import Attempt, atomic_json, collect


class EvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.attempt = Attempt(self.root / "attempt", {"fixture": True})
        self.addCleanup(self.attempt.close)

    def command(self, source, **options):
        return collect(self.attempt, "fixture", [sys.executable, "-c", source], cwd=self.root,
                       timeout=options.pop("timeout", 2), **options)

    def test_exclusive_ownership_and_private_permissions(self):
        with self.assertRaises(FileExistsError):
            Attempt(self.attempt.directory, {})
        self.assertEqual(self.attempt.directory.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.attempt.directory / "events.jsonl").stat().st_mode & 0o777, 0o600)

    def test_state_machine_and_durable_failure_finalization(self):
        with self.assertRaises(ValueError):
            self.attempt.transition("running")
        self.attempt.transition("preflight")
        self.attempt.transition("failed")
        self.attempt.finish({"outcome": "infrastructure_incomplete"})
        status = json.loads((self.attempt.directory / "status.json").read_text())
        self.assertEqual(status["phase"], "finalized")
        events = [json.loads(line) for line in (self.attempt.directory / "events.jsonl").read_text().splitlines()]
        self.assertEqual([e["sequence"] for e in events], list(range(1, len(events) + 1)))

    def test_failed_command_preserves_stdout_stderr_and_status(self):
        result = self.command("import sys; print('out'); print('err', file=sys.stderr); sys.exit(7)")
        self.assertEqual((result["outcome"], result["exit_code"]), ("failed", 7))
        self.assertEqual((self.attempt.directory / "fixture/stdout.log").read_text(), "out\n")
        self.assertEqual((self.attempt.directory / "fixture/stderr.log").read_text(), "err\n")
        with self.assertRaises(FileExistsError):
            self.command("pass")

    def test_timeout_also_bounds_descendant_held_pipes(self):
        start = time.monotonic()
        result = self.command("import subprocess,sys; subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])",
                              timeout=0.2)
        self.assertEqual(result["outcome"], "timeout")
        self.assertLess(time.monotonic() - start, 2)
        self.assertFalse(result["remote_termination_verified"])

    def test_output_bound_is_failure_even_when_process_exits_zero(self):
        result = self.command("print('x'*10000)", max_output_bytes=100)
        self.assertEqual(result["outcome"], "output_limit")
        self.assertEqual((self.attempt.directory / "fixture/stdout.log").stat().st_size, 100)

    def test_failed_snapshot_write_preserves_original(self):
        path = self.root / "snapshot.json"
        atomic_json(path, {"old": True})
        with patch("evaluation.evidence.os.replace", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                atomic_json(path, {"new": True})
        self.assertEqual(json.loads(path.read_text()), {"old": True})
        self.assertFalse(list(self.root.glob(".snapshot-*")))

    def test_failed_event_write_prevents_transition(self):
        with patch.object(self.attempt, "emit", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                self.attempt.transition("preflight")
        self.assertEqual(self.attempt.phase, "created")

    def test_nonfinite_limits_and_path_traversal_rejected(self):
        for value in (float("nan"), float("inf"), -1, 0, True):
            with self.assertRaises(ValueError):
                self.command("pass", timeout=value)
        with self.assertRaises(ValueError):
            collect(self.attempt, "../escape", ["true"], cwd=self.root, timeout=1)
