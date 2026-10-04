#!/usr/bin/env python3
"""Render this Copier template, preflight an existing Git root, then adopt it."""

import argparse
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile

from copier import run_copy
import yaml


def adopt(source, destination, revision, hooks="auto"):
    destination = Path(destination).resolve()
    status = subprocess.run(
        ["git", "-C", str(destination), "status", "--porcelain", "--untracked-files=all"],
        capture_output=True, text=True, check=True,
    )
    if status.stdout:
        raise ValueError("destination worktree must be clean, including untracked files")
    with tempfile.TemporaryDirectory(prefix="factory-adopt-") as temp:
        rendered = Path(temp) / "rendered"
        run_copy(str(source), rendered, vcs_ref=revision, defaults=True, quiet=True)
        tools = rendered / ".factory/core/tools"
        # Load only this trusted template's focused integration helper.
        sys.path.insert(0, str(tools))
        previous_check = sys.modules.pop("check", None)
        try:
            spec = importlib.util.spec_from_file_location("factory_integration", tools / "integrate.py")
            integration = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(integration)
            for relative in [".factory/core", ".factory-answers.yml", ".factory/project/integration.json"]:
                path = integration.safe_path(destination, relative)
                if path.exists():
                    raise ValueError(f"adoption collision: {relative}; use the update procedure for an existing factory")
            skills = integration.safe_path(destination, ".agents/skills")
            if skills.exists() and any(skills.glob("factory-*")):
                raise ValueError("adoption collision: existing factory-* skill name")
            if skills.is_dir():
                for entry in skills.rglob("SKILL.md"):
                    integration.safe_path(destination, entry.relative_to(destination))
                    content = entry.read_text()
                    if content.startswith("---\n"):
                        frontmatter = content.split("---", 2)
                        if len(frontmatter) != 3:
                            raise ValueError(f"cannot check skill metadata: {entry}")
                        try:
                            metadata = yaml.safe_load(frontmatter[1])
                        except yaml.YAMLError as exc:
                            raise ValueError(f"cannot check skill metadata: {entry}") from exc
                        if isinstance(metadata, dict) and str(metadata.get("name", "")).startswith("factory-"):
                            raise ValueError(f"adoption collision: reserved skill name in {entry}")
            writes = []
            for source_path in sorted(rendered.rglob("*")):
                if "__pycache__" in source_path.parts:
                    continue
                if source_path.is_symlink():
                    raise ValueError(f"unexpected template symlink: {source_path}")
                if not source_path.is_file():
                    continue
                relative = source_path.relative_to(rendered)
                target = integration.safe_path(destination, relative)
                if target.exists():
                    if relative.parts[:2] == (".factory", "project") and target.is_file():
                        continue
                    raise ValueError(f"adoption collision: {relative}")
                for parent in target.parents:
                    if parent.exists() and not parent.is_dir():
                        raise ValueError(f"adoption parent is not a directory: {parent}")
                writes.append((target, source_path.read_bytes(), source_path.stat().st_mode & 0o777))
            config_path = destination / ".factory/project/config.json"
            integration.load_config(destination if config_path.exists() else rendered)
            writes.extend(integration.plan(destination, rendered / ".factory/core", hooks))
            integration.apply(writes)
        finally:
            sys.path.pop(0)
            sys.modules.pop("check", None)
            if previous_check is not None:
                sys.modules["check"] = previous_check


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="existing, clean Git repository root")
    parser.add_argument("--ref", default="HEAD", help="template Git tag or commit; default HEAD is experimental")
    parser.add_argument("--hooks", choices=["auto", "manual"], default="auto")
    args = parser.parse_args()
    try:
        adopt(Path(__file__).resolve().parents[1], args.destination, args.ref, args.hooks)
        print("Factory adopted. Review and commit the diff; configure project verification commands.")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Factory adoption: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
