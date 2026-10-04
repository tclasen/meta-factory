# Repository Guidelines

## Project Structure & Module Organization

This workspace contains an experimental Copier template for repository-contained agent workflows. The factory is instructions, policies, skills, and focused tools, not an application. A separate Python evaluation controller and protected grading suite are authorized for implementation; benchmark execution remains separately gated.

- `template/` and `copier.yml`: managed factory resources and Copier configuration.
- `tests/`: isolated generation, integration, update, and controller fixtures.
- `evaluation/`: separate operator-side controller; never template-managed or builder-mounted.
- `scripts/adopt.py`: focused render/preflight/adoption helper; no central factory CLI.
- `README.md`: project initialization/updates, customization, sandbox setup, and run modes.
- `CONTRIBUTING.md`: development setup, checks, and validation limits.
- `docs/`: architecture and integration details.

- `.factory-planning/SPEC.md`: product scope, requirements, and open questions.
- `.factory-planning/DECISIONS.md`: confirmed decisions and unresolved choices.
- `.factory-planning/EVALUATION.md`: experimental protocol and evidence rules.
- `.gitignore`: excludes `/.factory-planning/` from version control.

Read these records before proposing implementation. Preserve identifiers such as `REQ-001` and `D-001` when referencing them. The planned TypeScript/React and Python/FastAPI stack belongs to the benchmark application; the separately authorized evaluation controller uses Python.

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

### Collaborative sandbox and host testing

The agent runs inside Docker `sbx`. The owner authorizes modifying the agent's own working environment, including installing tools and adjusting sandbox-local configuration, to develop and iterate on the setup and its tests. Use this access directly when possible; a missing host-management command inside the sandbox does not establish that it is missing on the Mac. Repository edits still follow the Git workflow below.

When a check needs the host Mac, provide a complete, reviewable script and its exact invocation for the owner to run. Save the script in the shared workspace. Scripts must:

- Write logs to a unique per-attempt directory under `.factory-planning/`, using the host checkout path so the agent can read them through the shared mount. Print that directory at startup and completion.
- Capture stdout, stderr, UTC start/end times, relevant tool versions, tested revisions, each check's exit status, and an overall outcome, including on failure. Preserve the original command status when logging through a pipeline; never treat successful logging as a successful check.
- State the intended changes and checks, use explicit resource names, bound potentially hanging operations, and retain failed attempts for inspection. Record cleanup outcomes and leave enough information to clean up resources after interruption.
- Keep credentials and secret values out of logs; avoid shell tracing and wholesale environment/configuration dumps. Keep evidence outside builder-mounted test projects and out of Git.
- Scope changes to the test resources. Do not silently reset global host policy, alter unrelated sandboxes, or remove unrelated data.

After the owner runs a script, read the resulting files directly, explain what passed or failed and what remains unverified, then adjust the setup or provide the next script. Continue this workflow until the owner is satisfied with the setup. Do not ask for pasted terminal output when the shared logs are available. Host-only execution remains with the owner unless host access is explicitly provided.

Continue authorized work autonomously until the current effort's tasks are complete. Do not stop after a successful intermediate check to ask whether to continue. When blocked on host-only execution, provide the next logging script and exact invocation; after the owner reports completion, read its logs and resume independently. Keep the existing scope and evidence boundaries in force.

This authorization covers iterative setup and preflight testing, including sandbox-local provisioning. It does not authorize purchases, benchmark or confirmatory experiment execution, or stable promotion. The subsequent owner authorization separately permits implementing the Python evaluation controller and protected grading suite. Preflight results retain their evidence limits.

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

Keep `.factory-planning/` local; adding it to Git requires the owner's approval. The owner authorized implementation of the component/template plan (D-039 through D-044) and collaborative setup/preflight testing as described above. Provisioning beyond that testing, benchmark or confirmatory experiment execution, purchasing and stable promotion remain outside this task. The owner subsequently authorized implementing the proposed Python evaluation controller and protected grading suite (D-049); keep protected cases out of builder mounts and obtain human review before suite freeze. Keep unresolved recommendations distinct from confirmed requirements.
