# Adoption, hooks, and update conflicts

Start with the commands in the [user guide](../README.md).

## Adoption preflight

The adoption helper renders Copier into a temporary directory and checks all
destination paths before installing files. It preserves application content,
project skills, and existing project extensions. Existing managed core, reserved
skill names, answers metadata, symlinked integration paths, and a root
`AGENTS.override.md` are conflicts. Resolve them explicitly before retrying;
do not force-copy over an existing project. Ordinary write failures roll back
changes. Do not run adoption concurrently with other editors.

## Hook composition

On a plain Git hook setup, integration preserves an existing executable
`pre-commit` script as `pre-commit.factory-original` in the same hooks directory.
The dispatcher runs it first with the original arguments and environment; any
failure prevents factory checks. It then runs configured factory pre-commit
checks. Repeated integration is idempotent. Existing hooks that depend on their
exact filename, symlinks, hook managers, or `core.hooksPath` need manual composition.
Linked worktrees share Git hook storage and are rejected by automatic integration;
use manual composition for such setups.

For a hook manager or custom hook path, use `--hooks manual` during adoption and
integration. This leaves hooks untouched. Add the following command as a required
step in the existing pre-commit workflow, preserving its current commands:

```sh
python3 .factory/core/tools/check.py pre-commit
```

Manual mode checks guidance integration only; it does not claim to validate or
activate the project's hook manager. Neither mode installs Codex hooks. Python
3.11+ and Git must be available where these scripts run.

## Update conflicts

Use Copier `update`, not `recopy`, to retain the downstream change history.
Resolve inline conflict markers before running integration or verification.

The managed section in `AGENTS.md` is updated only when its content matches the
digest recorded by the previous integration. An edited or missing section is a
conflict. Reconcile the section against the last committed integration and move
project guidance outside the markers before retrying; do not delete the record
to bypass the check. Content outside the markers is preserved byte-for-byte.
Commit `.factory/project/integration.json` with the adoption and each integration
change so future updates can detect local edits.

Project extensions are skipped by Copier updates. Unknown configuration keys or
schema versions fail validation; migrate project configuration explicitly when a
future version requires it. Inspect answers metadata changes with the rest of the
diff. Submit downstream updates for project review; these commands do not merge,
release, or promote anything.
