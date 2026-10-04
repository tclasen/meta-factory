#!/usr/bin/env python3
"""Prepare a disposable factory runtime smoke project; never launch a runtime."""

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys

from copier import run_copy
import yaml


REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests/fixtures/runtime-smoke"


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=True,
    ).stdout.strip()


def prepare(source, destination, revision):
    destination = Path(destination).absolute()
    if destination.exists() or destination.is_symlink():
        raise ValueError("destination must not exist; choose a new disposable project path")
    if not destination.parent.is_dir():
        raise ValueError("destination parent must already be a directory")
    commit = git(source, "rev-parse", "--verify", "--end-of-options", f"{revision}^{{commit}}")
    # Reserve the destination before rendering so existing directories are never reused.
    destination.mkdir()
    run_copy(str(source), destination, vcs_ref=commit, defaults=True, quiet=True)
    # Copier may describe the resolved commit by a mutable tag. Store the exact
    # object ID and omit its extra final blank line for the staged whitespace check.
    answers = destination / ".factory-answers.yml"
    metadata = yaml.safe_load(answers.read_text())
    metadata["_commit"] = commit
    answers.write_text(yaml.safe_dump(metadata, sort_keys=False))
    shutil.copytree(FIXTURE, destination, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    config = {
        "schema_version": 1,
        "verification_commands": [["python3", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"]],
        "pre_commit_commands": [["git", "diff", "--cached", "--check"]],
    }
    (destination / ".factory/project/config.json").write_text(json.dumps(config, indent=2) + "\n")
    git(destination, "init", "--initial-branch=main")
    git(destination, "config", "user.name", "Factory Smoke Fixture")
    git(destination, "config", "user.email", "factory-smoke@example.invalid")
    git(destination, "config", "commit.gpgsign", "false")
    subprocess.run(
        [sys.executable, str(destination / ".factory/core/tools/integrate.py")],
        cwd=destination, check=True,
    )
    git(destination, "add", "--all")
    git(destination, "commit", "-m", "test(smoke): initialize runtime fixture")
    if git(destination, "status", "--porcelain", "--untracked-files=all"):
        raise ValueError("prepared fixture is unexpectedly dirty; inspect it before use")
    return commit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new disposable project path; parent must exist")
    parser.add_argument("--ref", required=True, help="trusted template Git tag or commit to resolve and pin")
    args = parser.parse_args()
    try:
        commit = prepare(REPO, args.destination, args.ref)
        print(f"Prepared {args.destination.absolute()} from template {commit}.")
        print("Initial verification intentionally fails the whitespace test. Follow docs/runtime-preflight.md.")
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Smoke preparation: {exc}", file=sys.stderr)
        if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
            print(exc.stderr, file=sys.stderr)
        print("If a partial destination was created, inspect it and use a new path; it is not removed automatically.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
