"""Behavioral fixtures for template generation and explicit project checks."""

import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from copier import run_copy


REPO = Path(__file__).resolve().parents[1]


class TemplateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / "source"
        self.source.mkdir()
        shutil.copy(REPO / "copier.yml", self.source)
        shutil.copytree(REPO / "template", self.source / "template")
        self.target = self.base / "project"
        run_copy(str(self.source), self.target, defaults=True, quiet=True)

    def config(self, **changes):
        path = self.target / ".factory/project/config.json"
        config = json.loads(path.read_text())
        config.update(changes)
        path.write_text(json.dumps(config))

    def check(self, phase):
        return subprocess.run(
            [sys.executable, str(self.target / ".factory/core/tools/check.py"), phase],
            cwd=self.base, capture_output=True, text=True,
        )

    def test_generation_and_native_skill_discovery(self):
        self.assertTrue((self.target / ".factory-answers.yml").exists())
        skills = self.target / ".agents/skills"
        self.assertEqual(
            {p.name for p in skills.iterdir()},
            {"factory-plan", "factory-implement", "factory-verify", "factory-review"},
        )
        for path in skills.glob("*/SKILL.md"):
            self.assertIn(f"name: {path.parent.name}\n", path.read_text())
        self.assertEqual(self.check("config").returncode, 0)
        result = self.check("verify")
        self.assertEqual(result.returncode, 2)
        self.assertIn("unconfigured", result.stderr)

    def test_explicit_override_runs_at_root_without_shell(self):
        self.config(verification_commands=[[
            sys.executable, "-c",
            "from pathlib import Path; import sys; "
            "assert Path('.factory').is_dir(); "
            "assert sys.argv[1] == '$(touch unexpected)'",
            "$(touch unexpected)",
        ]])
        self.assertEqual(self.check("verify").returncode, 0)
        self.assertFalse((self.target / "unexpected").exists())

    def test_failure_stops_following_commands(self):
        self.config(verification_commands=[
            [sys.executable, "-c", "raise SystemExit(7)"],
            [sys.executable, "-c", "from pathlib import Path; Path('ran').touch()"],
        ])
        self.assertEqual(self.check("verify").returncode, 7)
        self.assertFalse((self.target / "ran").exists())

    def test_invalid_overrides_fail_closed(self):
        for change in [
            {"schema_version": 2}, {"schema_version": True},
            {"verification_commands": ["echo passed"]},
            {"verification_commands": [[]]}, {"disable_required_checks": True},
        ]:
            with self.subTest(change=change):
                (self.target / ".factory/project/config.json").write_text(json.dumps({
                    "schema_version": 1, "verification_commands": [], "pre_commit_commands": [],
                }))
                self.config(**change)
                self.assertEqual(self.check("config").returncode, 2)

    def test_project_check_failure_blocks_pre_commit(self):
        self.config(pre_commit_commands=[[sys.executable, "-c", "raise SystemExit(8)"]])
        self.assertEqual(self.check("pre-commit").returncode, 8)


if __name__ == "__main__":
    unittest.main()
