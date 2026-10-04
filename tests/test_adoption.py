"""REQ-001/005/006: adoption, hook composition, and two-version update fixtures."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from copier import run_update


REPO = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("adoption", REPO / "scripts/adopt.py")
adoption = importlib.util.module_from_spec(spec)
spec.loader.exec_module(adoption)


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True,
    ).stdout.strip()


def init(root):
    root.mkdir(parents=True, exist_ok=True)
    git(root, "init", "--initial-branch=main")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture@example.invalid")


def commit(root, message):
    git(root, "add", ".")
    git(root, "-c", "core.hooksPath=/dev/null", "commit", "--allow-empty", "-m", message)


class AdoptionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        # macOS aliases /var to /private/var; Git and adoption resolve that alias.
        # Copier updates and injected write failures must use the same spelling.
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / "source"
        init(self.source)
        shutil.copy(REPO / "copier.yml", self.source)
        shutil.copytree(REPO / "template", self.source / "template", ignore=shutil.ignore_patterns("__pycache__"))
        commit(self.source, "first template")
        git(self.source, "tag", "v0.1.0")
        self.target = self.base / "project with spaces"
        init(self.target)
        (self.target / "AGENTS.md").write_bytes(b"# Existing guidance\r\n\r\nPreserve me.\r\n")
        (self.target / "app.txt").write_text("existing application\n")
        skill = self.target / ".agents/skills/project-skill"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text("project skill\n")
        commit(self.target, "existing project")

    def adopt(self, hooks="auto"):
        adoption.adopt(self.source, self.target, "v0.1.0", hooks)

    def integrate(self, *args):
        return subprocess.run(
            [sys.executable, str(self.target / ".factory/core/tools/integrate.py"), *args],
            capture_output=True, text=True,
        )

    def hook(self):
        return self.target / ".git/hooks/pre-commit"

    def new_version(self):
        core = self.source / "template/.factory/core"
        with (core / "instructions.md").open("a") as stream:
            stream.write("\nNew template guidance.\n")
        path = core / "agents-section.md"
        path.write_text(path.read_text().replace("## Factory workflow", "## Factory workflows"))
        commit(self.source, "second template")
        git(self.source, "tag", "v0.2.0")

    def update(self):
        run_update(
            self.target, answers_file=".factory-answers.yml", vcs_ref="v0.2.0",
            defaults=True, overwrite=True, quiet=True,
        )

    def test_adoption_preserves_content_and_is_idempotent(self):
        original = (self.target / "AGENTS.md").read_bytes()
        self.adopt()
        current = (self.target / "AGENTS.md").read_bytes()
        self.assertTrue(current.startswith(original))
        self.assertEqual(current.count(b"<!-- factory:begin -->"), 1)
        self.assertEqual((self.target / "app.txt").read_text(), "existing application\n")
        self.assertEqual((self.target / ".agents/skills/project-skill/SKILL.md").read_text(), "project skill\n")
        self.assertEqual(self.integrate("--check").returncode, 0)
        self.assertEqual(self.integrate().returncode, 0)
        self.assertEqual((self.target / "AGENTS.md").read_bytes(), current)
        self.assertTrue(os.access(self.hook(), os.X_OK))
        self.assertFalse(list((self.target / ".factory").rglob("__pycache__")))

    def test_documented_cli_copy_and_update_preserve_extensions(self):
        project = self.base / "new cli project"
        subprocess.run(
            [sys.executable, "-m", "copier", "copy", "--vcs-ref", "v0.1.0",
             "--defaults", str(self.source), str(project)],
            capture_output=True, text=True, check=True, timeout=30,
        )
        init(project)
        tool = project / ".factory/core/tools/integrate.py"
        subprocess.run([sys.executable, str(tool)], cwd=project, capture_output=True, check=True)
        policy = project / ".factory/project/policy.md"
        policy.write_text("Project-owned CLI lifecycle policy\n")
        config = project / ".factory/project/config.json"
        config_before = config.read_bytes()
        commit(project, "initialize CLI fixture")
        self.new_version()
        subprocess.run(
            [sys.executable, "-m", "copier", "update", "--answers-file", ".factory-answers.yml",
             "--vcs-ref", "v0.2.0", "--defaults"],
            cwd=project, capture_output=True, text=True, check=True, timeout=30,
        )
        self.assertIn("New template guidance.", (project / ".factory/core/instructions.md").read_text())
        self.assertEqual(policy.read_text(), "Project-owned CLI lifecycle policy\n")
        self.assertEqual(config.read_bytes(), config_before)
        subprocess.run([sys.executable, str(tool)], cwd=project, capture_output=True, check=True)
        subprocess.run([sys.executable, str(tool), "--check"], cwd=project, capture_output=True, check=True)
        self.assertIn("## Factory workflows", (project / "AGENTS.md").read_text())
        git(project, "diff", "--check")

    def test_existing_hook_runs_before_factory_and_failure_blocks_commit(self):
        original = b"#!/bin/sh\nprintf 'existing' > hook-ran\nexit 0\n"
        self.hook().write_bytes(original)
        self.hook().chmod(0o755)
        self.adopt()
        self.assertEqual(self.hook().with_name("pre-commit.factory-original").read_bytes(), original)
        config = self.target / ".factory/project/config.json"
        data = json.loads(config.read_text())
        data["pre_commit_commands"] = [[sys.executable, "-c", "raise SystemExit(9)"]]
        config.write_text(json.dumps(data))
        result = subprocess.run([str(self.hook())], cwd=self.target, capture_output=True)
        self.assertEqual(result.returncode, 9)
        self.assertEqual((self.target / "hook-ran").read_text(), "existing")
        # Original hook failures short-circuit the factory command as well.
        self.hook().with_name("pre-commit.factory-original").write_text("#!/bin/sh\nexit 6\n")
        self.assertEqual(subprocess.run([str(self.hook())], cwd=self.target).returncode, 6)

    def test_collision_refuses_without_mutating_project(self):
        collision = self.target / ".agents/skills/factory-plan"
        collision.mkdir()
        (collision / "SKILL.md").write_text("owned by project")
        commit(self.target, "colliding skill")
        with self.assertRaisesRegex(ValueError, "collision"):
            self.adopt()
        self.assertEqual(git(self.target, "status", "--porcelain"), "")
        self.assertFalse((self.target / ".factory").exists())
        self.assertFalse(self.hook().exists())

    def test_override_and_custom_hook_path_require_resolution(self):
        (self.target / "AGENTS.override.md").write_text("override")
        commit(self.target, "override")
        with self.assertRaisesRegex(ValueError, "suppresses"):
            self.adopt()
        self.assertFalse((self.target / ".factory").exists())
        (self.target / "AGENTS.override.md").unlink()
        commit(self.target, "resolve override")
        git(self.target, "config", "core.hooksPath", ".githooks")
        with self.assertRaisesRegex(ValueError, "hooksPath"):
            self.adopt()
        self.assertFalse((self.target / ".factory").exists())
        self.adopt(hooks="manual")
        self.assertFalse(self.hook().exists())
        self.assertEqual(git(self.target, "config", "--get", "core.hooksPath"), ".githooks")
        self.assertEqual(self.integrate("--hooks", "manual", "--check").returncode, 0)

    def test_duplicate_skill_metadata_is_a_collision(self):
        skill = self.target / ".agents/skills/project-skill/SKILL.md"
        skill.write_text("---\nname: factory-plan\ndescription: existing skill\n---\n")
        commit(self.target, "duplicate name")
        with self.assertRaisesRegex(ValueError, "reserved skill name"):
            self.adopt()
        self.assertFalse((self.target / ".factory").exists())

    def test_linked_worktree_requires_manual_hook_composition(self):
        main = self.target
        self.target = self.base / "linked"
        git(main, "worktree", "add", "-b", "fixture", str(self.target))
        with self.assertRaisesRegex(ValueError, "linked worktrees"):
            self.adopt()
        self.assertFalse((self.target / ".factory").exists())
        self.assertFalse((main / ".git/hooks/pre-commit").exists())

    def test_dirty_destination_is_untouched(self):
        (self.target / "untracked.txt").write_text("user work")
        with self.assertRaisesRegex(ValueError, "clean"):
            self.adopt()
        self.assertFalse((self.target / ".factory").exists())

    def test_new_repository_without_guidance(self):
        self.target = self.base / "empty repository"
        init(self.target)
        self.adopt()
        self.assertTrue((self.target / "AGENTS.md").read_text().startswith("<!-- factory:begin -->"))
        self.assertEqual(self.integrate("--check").returncode, 0)

    def test_existing_project_extensions_are_preserved_and_validated(self):
        extensions = self.target / ".factory/project"
        extensions.mkdir(parents=True)
        config = {"schema_version": 1, "verification_commands": [["git", "status", "--short"]],
                  "pre_commit_commands": []}
        (extensions / "config.json").write_text(json.dumps(config))
        (extensions / "policy.md").write_text("Project-owned policy")
        commit(self.target, "project extensions")
        self.adopt()
        self.assertEqual(json.loads((extensions / "config.json").read_text()), config)
        self.assertEqual((extensions / "policy.md").read_text(), "Project-owned policy")

    def test_write_failure_rolls_back_adoption(self):
        original = (self.target / "AGENTS.md").read_bytes()
        write_bytes = Path.write_bytes

        def fail_once(path, data):
            if path == self.hook():
                raise OSError("simulated hook write failure")
            return write_bytes(path, data)

        with patch.object(Path, "write_bytes", fail_once):
            with self.assertRaisesRegex(OSError, "simulated"):
                self.adopt()
        self.assertEqual((self.target / "AGENTS.md").read_bytes(), original)
        self.assertFalse((self.target / ".factory").exists())
        self.assertEqual(git(self.target, "status", "--porcelain"), "")

    def test_representative_change_uses_project_verification(self):
        self.adopt()
        # Acceptance: double(3) returns 6. Start with a failing implementation.
        (self.target / "example.py").write_text("def double(value):\n    return value\n")
        (self.target / "test_example.py").write_text(
            "import unittest\nfrom example import double\n"
            "class ExampleTest(unittest.TestCase):\n"
            "    def test_double(self):\n        self.assertEqual(double(3), 6)\n"
        )
        config = self.target / ".factory/project/config.json"
        data = json.loads(config.read_text())
        data["verification_commands"] = [[sys.executable, "-B", "-m", "unittest", "test_example"]]
        config.write_text(json.dumps(data))
        command = [sys.executable, str(self.target / ".factory/core/tools/check.py"), "verify"]
        self.assertNotEqual(subprocess.run(command, capture_output=True).returncode, 0)
        (self.target / "example.py").write_text("def double(value):\n    return value * 2\n")
        self.assertEqual(subprocess.run(command, capture_output=True).returncode, 0)
        self.assertIn("return value * 2", (self.target / "example.py").read_text())

    def test_symlink_destination_is_not_followed(self):
        outside = self.base / "outside"
        outside.mkdir()
        (self.target / ".factory").symlink_to(outside, target_is_directory=True)
        commit(self.target, "symlink")
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.adopt()
        self.assertEqual(list(outside.iterdir()), [])

    def test_update_preserves_extensions_and_refreshes_managed_section(self):
        self.adopt()
        policy = self.target / ".factory/project/policy.md"
        policy.write_text("My project policy\n")
        config = self.target / ".factory/project/config.json"
        custom = json.loads(config.read_text())
        custom["verification_commands"] = [[sys.executable, "-c", "pass"]]
        config.write_text(json.dumps(custom))
        agents = self.target / "AGENTS.md"
        with agents.open("ab") as stream:
            stream.write(b"\nAdditional project instructions.\n")
        commit(self.target, "adopt and customize")
        self.new_version()
        self.update()
        self.assertEqual(policy.read_text(), "My project policy\n")
        self.assertEqual(json.loads(config.read_text()), custom)
        self.assertIn("New template guidance.", (self.target / ".factory/core/instructions.md").read_text())
        self.assertNotEqual(self.integrate("--check").returncode, 0)
        self.assertEqual(self.integrate().returncode, 0)
        self.assertIn("## Factory workflows", agents.read_text())
        self.assertTrue(agents.read_bytes().endswith(b"Additional project instructions.\n"))
        self.assertEqual(self.integrate("--check").returncode, 0)

    def test_modified_section_is_not_overwritten(self):
        self.adopt()
        agents = self.target / "AGENTS.md"
        agents.write_text(agents.read_text().replace("## Factory workflow", "## Local edit"))
        before = agents.read_bytes()
        result = self.integrate()
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecorded edits", result.stderr)
        self.assertEqual(agents.read_bytes(), before)

    def test_managed_update_conflict_is_reviewable(self):
        self.adopt()
        instructions = self.target / ".factory/core/instructions.md"
        instructions.write_text(instructions.read_text().replace("# Factory working instructions", "# Local rules"))
        commit(self.target, "local managed edit")
        upstream = self.source / "template/.factory/core/instructions.md"
        upstream.write_text(upstream.read_text().replace("# Factory working instructions", "# Upstream rules"))
        commit(self.source, "conflicting managed edit")
        git(self.source, "tag", "v0.2.0")
        self.update()
        self.assertIn("<<<<<<<", instructions.read_text())
        self.assertIn("Local rules", instructions.read_text())
        self.assertIn("Upstream rules", instructions.read_text())


if __name__ == "__main__":
    unittest.main()
