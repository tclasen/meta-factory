# Knowledge-work factory

An experimental Copier template containing instructions, policies, skills, and
focused tools for an existing Codex agent. The factory is not an application,
central CLI, or service. A separate evaluation harness remains to be designed.

## Component contract

| Location in an adopting repository | Ownership |
| --- | --- |
| `.factory/core/` | Template-managed instructions, references, shared tools, and hooks. |
| `.factory/project/` | Project-owned configuration and policy extensions. |
| `.agents/skills/factory-*/` | Template-managed, natively discoverable workflow skills. |
| Root `AGENTS.md` | Project-owned, except a marked factory integration section. |

The initial workflow covers planning, implementation, verification, and review.
Keep always-loaded guidance small; load skills and references when needed. Use
scripts for deterministic checks rather than turning the factory into a program.

Projects customize named extension points. Updates preserve project extensions
and unrelated instructions, skills, and hooks. Conflicting edits and unsupported
integrations require review. Required checks cannot be silently disabled by prose;
changes to policy must be explicit. Protected evaluation and release gates remain
outside the builder's authority and are not included in generated repositories.

Git hooks compose with existing hooks. Codex hooks are added only when a concrete
requirement needs one and the selected Codex version supports it. Instructions
guide agents; local hooks are bypassable checks, not a security boundary.

This contract implements REQ-001, REQ-005, and REQ-006 and records the component
boundary decisions D-039 through D-044. Local planning records remain untracked.
Fixture results do not constitute benchmark evidence or stable catalog promotion.
This repository will consume its own template only after a stable release exists.

## Discovery references

- [Codex project instructions](https://developers.openai.com/codex/guides/agents-md)
- [Codex repository skills](https://developers.openai.com/codex/skills)

Factory skills use the native `.agents/skills` directory. Existing project and
user instructions still follow Codex's own instruction hierarchy; the factory
does not claim to override that hierarchy.

## Development

Install [uv](https://docs.astral.sh/uv/) and Python 3.11 or newer, then run:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
git diff --check
```

There is no application build or development server. `pyproject.toml` and
`uv.lock` pin template development tools (Copier 9.14.0); they do not define
a factory application or select the future harness's language. Focused scripts
use Python's standard library. Use four-space indentation, descriptive snake-case
names, and standard-library `unittest` for behavior fixtures. Keep skills concise
and maintain their YAML `name` and `description` fields.

The template's verification commands are deliberately unconfigured. Projects
select their actual commands in `.factory/project/config.json`; an empty list
does not count as passing verification. See the generated customization reference
for the full extension contract.

## Generate or adopt a repository

Run these commands from this template checkout after `uv sync --locked`:

```sh
uv run --locked python scripts/adopt.py /absolute/path/to/project --ref HEAD
```

The destination must already be a Git repository with a clean worktree, including
no untracked files. For a new project, create the directory and initialize Git
explicitly first; the adoption tool does not initialize repositories. `HEAD`
selects this checkout's committed experimental template. Once releases exist,
use an explicit reviewed tag or commit instead. Keep the source checkout available:
Copier records its location in `.factory-answers.yml` for subsequent updates.

Adoption renders into a temporary directory, checks all destination paths, then
installs the template and integrates guidance/hooks. It does not execute project
verification commands, create commits, or publish anything. Existing application
files, project skills, and project extensions are preserved. Existing factory core,
reserved skill names, answers metadata, symlinked integration paths, and a root
`AGENTS.override.md` are conflicts. Resolve them explicitly before retrying; do not
force-copy the template over an existing project. Changes are rolled back on
ordinary write failures; do not run adoption concurrently with other editors.

Review the generated diff, select actual verification commands in
`.factory/project/config.json`, and commit the adoption under project policy.
Restart Codex to load the new root guidance. The four skills live directly in
`.agents/skills/`. Local hooks are not tracked by Git; in each subsequent clone run:

```sh
python3 .factory/core/tools/integrate.py
python3 .factory/core/tools/integrate.py --check
python3 .factory/core/tools/check.py verify
```

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

## Update an adopted repository

Start with a clean, committed destination on the branch required by its own
policy. Run from the destination:

```sh
uv tool run --from copier==9.14.0 copier update --answers-file .factory-answers.yml --vcs-ref REVIEWED_REF --defaults
git diff --check
git diff
python3 .factory/core/tools/integrate.py
python3 .factory/core/tools/integrate.py --check
python3 .factory/core/tools/check.py verify
```

Replace `REVIEWED_REF` with the selected template tag or commit. Stop and resolve
Copier's inline conflict markers before integration or checks. Never use `recopy`
as an update shortcut. If the project uses manual hook composition, pass
`--hooks manual` to both integration commands.

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

## Validation limits

Fixtures exercise generation, adoption, hook composition, explicit overrides,
and updates between two temporary template tags, including conflicts. They check
Codex's documented discovery paths and instruction links, not an actual Codex
session or the effectiveness of the workflows. Live model discovery and workflow
evaluation remain runtime preflight and evaluation-harness work. No benchmark,
stable release, promotion, or downstream PR has been performed.

Local validation used Python 3.14.4, Git 2.53.0, and Copier 9.14.0 on Linux.
macOS execution and older supported Python versions have not yet been exercised.
