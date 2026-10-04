# Repository Guidelines

## Project Structure & Module Organization

This workspace is in the planning stage for a knowledge-work factory: a template, evaluation, and release system for repository-contained agent workflows. No source, test, or asset directories exist yet.

- `.factory-planning/SPEC.md`: product scope, requirements, and open questions.
- `.factory-planning/DECISIONS.md`: confirmed decisions and unresolved choices.
- `.factory-planning/EVALUATION.md`: experimental protocol and evidence rules.
- `.gitignore`: excludes `/.factory-planning/` from version control.

Read these records before proposing implementation. Preserve identifiers such as `REQ-001` and `D-001` when referencing them. The planned TypeScript/React and Python/FastAPI stack belongs to the benchmark application; the factory implementation language remains undecided.

## Build, Test, and Development Commands

No build system, dependency manifest, development server, or executable test suite is configured. Do not assume commands such as `npm test` or `make build` work.

Useful inspection commands from the workspace root:

- `ls -la`: inspect files, including hidden planning records.
- `cat .gitignore`: check excluded paths.
- `rg -n 'REQ-|Q-' .factory-planning/SPEC.md`: locate requirements and open questions.

When tooling is introduced, document exact setup, build, lint, and test commands alongside its configuration.

## Coding Style & Naming Conventions

No language-specific indentation rules, formatter, or linter are established. Follow existing Markdown conventions: descriptive headings, short paragraphs, fenced command examples, and stable identifiers. When adding code under an authorized implementation task, establish formatting and naming rules with the selected toolchain.

## Testing Guidelines

No testing framework or coverage threshold is configured. Future evaluation checks must trace to disclosed requirements. Keep authoritative grading independent of builder-written tests, protect holdout cases, and obtain human review before freezing acceptance suites. Report pilot and inconclusive results with their evidence limits.

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

Keep `.factory-planning/` local; adding it to Git requires the owner's approval. This documentation task authorizes neither repository initialization nor implementation, experiment execution, provisioning, or purchasing. Keep unresolved recommendations distinct from confirmed requirements.
