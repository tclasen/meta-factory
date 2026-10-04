#!/usr/bin/env python3
"""Integrate managed guidance and compose a repository's pre-commit hook."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
from check import load_config


BEGIN = b"<!-- factory:begin -->"
END = b"<!-- factory:end -->"
STATE = ".factory/project/integration.json"
BACKUP = "pre-commit.factory-original"
HOOK = b'''#!/bin/sh
# Factory pre-commit dispatcher v1. Re-run integrate.py in each clone.
hook_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd) || exit 1
if [ -x "$hook_dir/pre-commit.factory-original" ]; then
    "$hook_dir/pre-commit.factory-original" "$@" || exit "$?"
fi
root=$(git rev-parse --show-toplevel) || exit 1
exec python3 "$root/.factory/core/tools/check.py" pre-commit
'''


def git(root, *args):
    return subprocess.run(
        ["git", "-C", str(root), *args], check=True, capture_output=True, text=True,
    ).stdout.strip()


def safe_path(root, relative):
    """Reject symlinks, including broken links and symlinked parent directories."""
    path = root
    for component in Path(relative).parts:
        path /= component
        if path.is_symlink():
            raise ValueError(f"symlink integration path requires review: {path}")
    return path


def digest(content):
    return hashlib.sha256(content).hexdigest()


def guidance_plan(root, core):
    override = root / "AGENTS.override.md"
    if override.exists() or override.is_symlink():
        raise ValueError("root AGENTS.override.md suppresses AGENTS.md; reconcile discovery first")
    path = safe_path(root, "AGENTS.md")
    current = path.read_bytes() if path.exists() else b""
    desired = (core / "agents-section.md").read_bytes().rstrip(b"\n")
    state_path = safe_path(root, STATE)
    state = json.loads(state_path.read_text()) if state_path.exists() else None
    if state is not None and (
        not isinstance(state, dict) or set(state) != {"schema_version", "agents_sha256"}
        or type(state["schema_version"]) is not int or state["schema_version"] != 1
    ):
        raise ValueError("unsupported integration record; reconcile before updating")
    if current.count(BEGIN) != current.count(END) or current.count(BEGIN) > 1:
        raise ValueError("malformed or duplicate factory guidance markers")
    if BEGIN in current:
        start = current.index(BEGIN)
        end = current.index(END) + len(END)
        if end <= start:
            raise ValueError("reversed factory guidance markers")
        previous = current[start:end]
        if state is None or digest(previous) != state["agents_sha256"]:
            raise ValueError("factory guidance section has unrecorded edits; reconcile before updating")
        updated = current[:start] + desired + current[end:]
    else:
        if state is not None:
            raise ValueError("recorded factory guidance section is missing; reconcile before updating")
        separator = b"" if not current else (b"\n" if current.endswith(b"\n") else b"\n\n")
        updated = current + separator + desired + b"\n"
    record = {"schema_version": 1, "agents_sha256": digest(desired)}
    return [(path, updated, None), (state_path, (json.dumps(record, indent=2) + "\n").encode(), None)]


def hook_plan(root, mode):
    if mode == "manual":
        return []
    git_dir = Path(git(root, "rev-parse", "--absolute-git-dir")).resolve()
    common_dir = Path(git(root, "rev-parse", "--path-format=absolute", "--git-common-dir")).resolve()
    if git_dir != common_dir:
        raise ValueError("linked worktrees share hooks; use --hooks manual to review their integration")
    configured = subprocess.run(
        ["git", "-C", str(root), "config", "--get", "core.hooksPath"],
        capture_output=True, text=True, check=False,
    )
    if configured.returncode != 1:
        raise ValueError("core.hooksPath is configured; use --hooks manual and compose its workflow explicitly")
    # Git resolves this correctly for ordinary repositories and linked worktrees.
    hooks = Path(git(root, "rev-parse", "--path-format=absolute", "--git-path", "hooks"))
    for path in [hooks, *hooks.parents]:
        if path.is_symlink():
            raise ValueError(f"symlink hook directory requires manual integration: {path}")
    hook = safe_path(hooks, "pre-commit")
    backup = safe_path(hooks, BACKUP)
    current = hook.read_bytes() if hook.exists() else None
    if current == HOOK:
        if not os.access(hook, os.X_OK):
            raise ValueError("factory dispatcher is not executable; restore its executable permission")
        return []
    if backup.exists() or (current and b"Factory pre-commit dispatcher" in current):
        raise ValueError("existing factory hook integration conflicts; reconcile before installing")
    writes = []
    if current is not None:
        if not os.access(hook, os.X_OK):
            raise ValueError("existing pre-commit hook is not executable; resolve it before composing")
        writes.append((backup, current, hook.stat().st_mode & 0o777))
    writes.append((hook, HOOK, 0o755))
    return writes


def plan(root, core, mode="auto"):
    if Path(git(root, "rev-parse", "--show-toplevel")).resolve() != root:
        raise ValueError("destination must be the Git repository root")
    writes = guidance_plan(root, core) + hook_plan(root, mode)
    # Check every path before the first write, including non-directory parents.
    for path, _, _ in writes:
        if path.exists() and not path.is_file():
            raise ValueError(f"integration path is not a file: {path}")
        for parent in path.parents:
            if parent.exists() and not parent.is_dir():
                raise ValueError(f"integration parent is not a directory: {parent}")
    return writes


def apply(writes):
    """Apply a preflighted plan and restore original bytes on an I/O failure."""
    previous = []
    created_dirs = []
    try:
        for path, content, mode in writes:
            previous.append((path, path.read_bytes() if path.exists() else None,
                             path.stat().st_mode & 0o777 if path.exists() else None))
            missing = []
            parent = path.parent
            while not parent.exists():
                missing.append(parent)
                parent = parent.parent
            for directory in reversed(missing):
                directory.mkdir()
                created_dirs.append(directory)
            path.write_bytes(content)
            if mode is not None:
                path.chmod(mode)
    except OSError:
        for path, content, mode in reversed(previous):
            if content is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(content)
                path.chmod(mode)
        for directory in reversed(created_dirs):
            directory.rmdir()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hooks", choices=["auto", "manual"], default="auto")
    parser.add_argument("--check", action="store_true", help="check integration without writing")
    args = parser.parse_args()
    core = Path(__file__).resolve().parents[1]
    root = core.parents[1]
    try:
        load_config(root)
        writes = plan(root, core, args.hooks)
        if args.check:
            if any(not path.exists() or path.read_bytes() != content for path, content, _ in writes):
                raise ValueError("integration is missing or stale; run integrate.py after reviewing changes")
        else:
            apply(writes)
        print("Factory guidance integrated; " + (
            "hook composition is project-managed." if args.hooks == "manual" else "pre-commit dispatcher installed."
        ))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f"Factory integration: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
