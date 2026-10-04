"""Resource boundaries and untrusted-source capture fixtures."""

import os
from pathlib import Path
import tempfile
import unittest

from evaluation.evidence import Attempt
from evaluation.sandbox import Sandbox, capture_tree, disjoint, stopped_from_listing


class SandboxTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.project = self.root / "project"
        self.project.mkdir()

    def capture(self, **kwargs):
        return capture_tree(self.project, self.root / "capture", termination_verified=True, **kwargs)

    def test_mount_ancestor_overlap_rejected(self):
        with self.assertRaises(ValueError):
            disjoint(self.project, self.project / "evidence")

    def test_no_capture_before_remote_stop(self):
        with self.assertRaises(ValueError):
            capture_tree(self.project, self.root / "capture", termination_verified=False)
        self.assertFalse((self.root / "capture").exists())

    def test_capture_hashes_and_preserves_executable_without_running(self):
        script = self.project / "danger.sh"
        script.write_text("#!/bin/sh\nexit 9\n")
        script.chmod(0o755)
        result = self.capture()
        self.assertEqual(result["outcome"], "captured")
        self.assertTrue(result["files"]["danger.sh"]["executable"])
        self.assertEqual((self.root / "capture/danger.sh").read_bytes(), script.read_bytes())

    def test_symlink_escape_rejected_without_reading(self):
        (self.root / "secret").write_text("private")
        (self.project / "escape").symlink_to(self.root / "secret")
        with self.assertRaises(ValueError):
            self.capture()
        self.assertFalse((self.root / "capture/escape").exists())

    def test_hardlinks_and_size_limit_rejected(self):
        (self.project / "file").write_text("12345")
        with self.assertRaises(ValueError):
            self.capture(max_bytes=4)
        os.link(self.project / "file", self.project / "link")
        with self.assertRaises(ValueError):
            capture_tree(self.project, self.root / "second", termination_verified=True)

    def test_exact_stopped_identity_required(self):
        text = "SANDBOX AGENT STATUS PORTS WORKSPACE\nother codex stopped\nours codex running\n"
        self.assertFalse(stopped_from_listing(text, "ours"))
        self.assertTrue(stopped_from_listing(text.replace("ours codex running", "ours codex stopped"), "ours"))
        self.assertFalse(stopped_from_listing(text, "missing"))
        self.assertFalse(stopped_from_listing("unknown format", "ours"))

    def test_scoped_create_plan_and_no_exec_after_stop(self):
        spec = self.root / "spec"; spec.mkdir()
        control = self.root / "control"; control.mkdir()
        with Attempt(control / "logs", {}) as attempt:
            box = Sandbox(attempt, self.project, spec, control, port=18080)
            argv = box.create_argv()
            self.assertIn("127.0.0.1:18080:8080", argv)
            self.assertIn(str(spec) + ":ro", argv)
            self.assertNotIn("--cloud", argv)
            self.assertIn("-i", box.exec_argv(["codex", "app-server"], interactive=True))
            scratch = self.root / 'scratch'; scratch.mkdir()
            with self.assertRaises(ValueError):
                Sandbox(attempt, self.project, spec, control, port=18081,
                        role="grader", project_readonly=True)
            inspector = Sandbox(attempt, self.project, spec, control, port=18081,
                                role="grader", project_readonly=True, primary_workspace=scratch)
            self.assertIn(str(self.project) + ":ro", inspector.create_argv())
            self.assertEqual(inspector.create_argv()[-3:],
                             [str(scratch), str(self.project) + ":ro", str(spec) + ":ro"])
            with self.assertRaises(ValueError):
                box.stop()
            box.stopped = True
            with self.assertRaises(ValueError):
                box.exec_argv(["true"])
