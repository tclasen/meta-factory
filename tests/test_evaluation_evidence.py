"""Deterministic evaluator fixtures; no model or benchmark calls."""

import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import time
import unittest
from unittest.mock import Mock, patch

from evaluation.evidence import Attempt, atomic_json, collect, kill_group


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

    def test_exited_leader_cleanup_reaps_and_still_signals_descendants(self):
        child = Mock(pid=123, poll=Mock(return_value=0))
        for retry in (None, ProcessLookupError()):
            with self.subTest(retry=type(retry).__name__):
                child.reset_mock()
                with patch('evaluation.evidence.os.killpg',
                           side_effect=[PermissionError(), retry]) as signal_group:
                    kill_group(child)
                self.assertEqual(signal_group.call_count, 2)
                child.poll.assert_called_once_with()
                child.wait.assert_called_once_with(timeout=5)

    def test_live_or_persistent_cleanup_denial_is_not_suppressed(self):
        for status, failures, count in ((None, [PermissionError()], 1),
                                        (0, [PermissionError(), PermissionError()], 2)):
            with self.subTest(status=status):
                child = Mock(pid=123, poll=Mock(return_value=status))
                with patch('evaluation.evidence.os.killpg', side_effect=failures) as signal_group:
                    with self.assertRaises(PermissionError):
                        kill_group(child)
                self.assertEqual(signal_group.call_count, count)
                child.wait.assert_not_called()

    def test_real_exited_local_child_is_reaped(self):
        child = subprocess.Popen([sys.executable, '-c', 'pass'], start_new_session=True)
        try:
            time.sleep(0.05)
            kill_group(child)
            self.assertIsNotNone(child.returncode)
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=5)

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

    def test_cleanup_failure_retains_original_failure_and_final_evidence(self):
        with patch("evaluation.evidence.kill_group", side_effect=OSError("private error")):
            result = self.command("import sys; sys.exit(7)")
        self.assertEqual((result["outcome"], result["command_outcome"], result["exit_code"]),
                         ("cleanup_error", "failed", 7))
        self.assertEqual(result["cleanup_error_type"], "OSError")
        self.assertIn("ended", result)
        saved = json.loads((self.attempt.directory / "fixture/result.json").read_text())
        self.assertEqual(saved, result)
        events = [json.loads(line) for line in (self.attempt.directory / "events.jsonl").read_text().splitlines()]
        self.assertEqual(events[-1]["type"], "command.end")
        self.assertEqual(events[-1]["payload"], result)
        self.assertNotIn("private error", json.dumps(result))

    def test_cleanup_timeout_cannot_turn_success_into_pass(self):
        with patch("evaluation.evidence.kill_group", side_effect=subprocess.TimeoutExpired("private", 5)):
            result = self.command("pass")
        self.assertEqual((result["outcome"], result["command_outcome"], result["exit_code"]),
                         ("cleanup_error", "passed", 0))
        self.assertEqual(result["cleanup_error_type"], "TimeoutExpired")

    def test_cleanup_interrupt_is_logged_before_propagation(self):
        with patch("evaluation.evidence.kill_group", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.command("pass")
        saved = json.loads((self.attempt.directory / "fixture/result.json").read_text())
        self.assertEqual(saved["outcome"], "cleanup_error")
        self.assertEqual(saved["cleanup_error_type"], "KeyboardInterrupt")
        self.assertIn("ended", saved)

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
