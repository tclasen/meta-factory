"""Runtime smoke preparation and fixed acceptance; no sandbox or model launch."""

import importlib.util
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

import yaml


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prepare_smoke", REPO / "scripts/prepare_smoke.py")
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


class SmokeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        shutil.copy(REPO / "copier.yml", self.source)
        shutil.copytree(REPO / "template", self.source / "template",
                        ignore=shutil.ignore_patterns("__pycache__"))
        smoke.git(self.source, "init", "--initial-branch=main")
        smoke.git(self.source, "config", "user.name", "Fixture")
        smoke.git(self.source, "config", "user.email", "fixture@example.invalid")
        smoke.git(self.source, "add", ".")
        smoke.git(self.source, "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false",
                  "commit", "-m", "template fixture")
        self.commit = smoke.git(self.source, "rev-parse", "HEAD")
        smoke.git(self.source, "tag", "smoke-template")
        self.target = self.base / "project with spaces"

    def command(self, *args):
        return subprocess.run(args, cwd=self.target, capture_output=True, text=True)

    def test_existing_destinations_are_untouched(self):
        self.target.mkdir()
        sentinel = self.target / "keep.txt"
        sentinel.write_text("keep me\n")
        with self.assertRaisesRegex(ValueError, "must not exist"):
            smoke.prepare(self.source, self.target, "smoke-template")
        self.assertEqual(list(self.target.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(), "keep me\n")
        link = self.base / "broken-link"
        link.symlink_to(self.base / "missing")
        with self.assertRaisesRegex(ValueError, "must not exist"):
            smoke.prepare(self.source, link, "smoke-template")
        self.assertTrue(link.is_symlink())

    def test_invalid_revision_does_not_create_destination(self):
        with self.assertRaises(subprocess.CalledProcessError):
            smoke.prepare(self.source, self.target, "missing-revision")
        self.assertFalse(self.target.exists())

    def test_pinned_clean_fixture_and_known_correction(self):
        self.assertEqual(smoke.prepare(self.source, self.target, "smoke-template"), self.commit)
        answers = yaml.safe_load((self.target / ".factory-answers.yml").read_text())
        self.assertEqual(answers["_commit"], self.commit)
        self.assertEqual(smoke.git(self.target, "status", "--porcelain"), "")
        initial = smoke.git(self.target, "rev-parse", "HEAD")
        integration = self.command(sys.executable, ".factory/core/tools/integrate.py", "--check")
        self.assertEqual(integration.returncode, 0, integration.stderr)
        before = self.command(sys.executable, ".factory/core/tools/check.py", "verify")
        self.assertEqual(before.returncode, 1, before.stderr)
        self.assertIn("FAIL: test_surrounding_whitespace", before.stderr)
        self.assertIn("Ran 4 tests", before.stderr)
        self.assertIn("FAILED (failures=1)", before.stderr)
        self.assertEqual(smoke.git(self.target, "status", "--porcelain"), "")

        implementation = self.target / "normalizer.py"
        implementation.write_text(implementation.read_text().replace("value.lower()", "value.strip().lower()"))
        after = self.command(sys.executable, ".factory/core/tools/check.py", "verify")
        self.assertEqual(after.returncode, 0, after.stderr)
        self.assertEqual(smoke.git(self.target, "diff", "--name-only"), "normalizer.py")
        smoke.git(self.target, "add", "normalizer.py")
        hook = self.command(str(self.target / ".git/hooks/pre-commit"))
        self.assertEqual(hook.returncode, 0, hook.stderr)
        self.assertEqual(smoke.git(self.target, "rev-parse", "HEAD"), initial)

        # Confirm the installed hook rejects an actual staged whitespace error.
        implementation.write_text(implementation.read_text() + "# trailing whitespace  \n")
        smoke.git(self.target, "add", "normalizer.py")
        hook = self.command(str(self.target / ".git/hooks/pre-commit"))
        self.assertNotEqual(hook.returncode, 0)
        self.assertIn("trailing whitespace", hook.stdout + hook.stderr)


if __name__ == "__main__":
    unittest.main()
