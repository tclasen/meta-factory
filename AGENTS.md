# Repository Guidelines

## Project Structure & Module Organization

This workspace contains an experimental Copier template for repository-contained agent workflows. The factory is instructions, policies, skills, and focused tools, not an application. A separate evaluation harness remains to be designed.

- `template/` and `copier.yml`: managed factory resources and Copier configuration.
- `tests/`: isolated generation, integration, and update fixtures.
- `scripts/adopt.py`: focused render/preflight/adoption helper; no central factory CLI.
- `README.md`: component ownership, setup, and usage.

- `.factory-planning/SPEC.md`: product scope, requirements, and open questions.
- `.factory-planning/DECISIONS.md`: confirmed decisions and unresolved choices.
- `.factory-planning/EVALUATION.md`: experimental protocol and evidence rules.
- `.gitignore`: excludes `/.factory-planning/` from version control.

Read these records before proposing implementation. Preserve identifiers such as `REQ-001` and `D-001` when referencing them. The planned TypeScript/React and Python/FastAPI stack belongs to the benchmark application; the factory implementation language remains undecided.

## Build, Test, and Development Commands

Use `uv sync --locked` for setup and `uv run --locked python -m unittest discover -s tests -v` for fixture tests. Run `git diff --check` before committing. There is no application build or development server. Copier is pinned in `pyproject.toml` and `uv.lock`.

Useful inspection commands from the workspace root:

- `ls -la`: inspect files, including hidden planning records.
- `cat .gitignore`: check excluded paths.
- `rg -n 'REQ-|Q-' .factory-planning/SPEC.md`: locate requirements and open questions.

When tooling is introduced, document exact setup, build, lint, and test commands alongside its configuration.

## Coding Style & Naming Conventions

Follow existing Markdown conventions: descriptive headings, short paragraphs, fenced command examples, and stable identifiers. Python tools use four-space indentation, descriptive snake-case names, and the standard library where practical. No formatter is configured.

## Testing Guidelines

Use standard-library `unittest` for template behavior fixtures. No coverage threshold is configured. Evaluation checks must trace to disclosed requirements. Keep authoritative grading independent of builder-written tests, protect holdout cases, and obtain human review before freezing acceptance suites. Fixture tests are not promotion evidence. Report pilot and inconclusive results with their evidence limits.

## Commit & Pull Request Guidelines

Work in the smallest independently verifiable units possible. Complete this workflow for each unit before starting the next:

1. Before changing any file, confirm the current branch is the repository's trunk branch (for example, `main` or `master`) using `git branch --show-current`. Determine the actual trunk branch from repository configuration; do not assume its name. Switch to trunk before proceeding.
2. Run `git status --porcelain` and require empty output, including no untracked files. If the workspace is dirty, stop and resolve ownership of existing changes; do not discard, stash, or commit unrelated work automatically.
3. Make one focused change directly on trunk. Avoid unrelated cleanup or combining separate tasks.
4. Verify completion locally with checks appropriate to the change, and inspect `git diff` for unintended edits. Fix failures before committing.
5. Stage only files belonging to that unit and create one atomic Conventional Commit: `<type>(<optional scope>): <description>`, for example, `docs(agents): require verified atomic changes` or `fix(template): preserve project extensions`.
6. Confirm the commit succeeded and the workspace is clean before beginning another unit.

If Git is unavailable or the directory is not a repository, report the blocker; do not initialize Git without authorization. PR descriptions should explain the change, reference relevant requirement or decision identifiers, and state local validation and unresolved questions.

## Planning & Configuration Boundaries

Keep `.factory-planning/` local; adding it to Git requires the owner's approval. The owner authorized implementation of the component/template plan (D-039 through D-044). Experiment execution, provisioning, purchasing, stable promotion, and implementing the separate evaluation harness remain outside this task. Keep unresolved recommendations distinct from confirmed requirements.
