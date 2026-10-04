# Contributing

Follow [AGENTS.md](AGENTS.md) for the trunk-first, clean-worktree, atomic-commit
workflow and planning boundaries. See [architecture](docs/architecture.md) for
component ownership and [README.md](README.md) for project usage.

## Setup and checks

Install [uv](https://docs.astral.sh/uv/) and Python 3.11 or newer, then run:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -v
git diff --check
```

There is no application build or development server. `pyproject.toml` and
`uv.lock` pin template development tools (Copier 9.14.0); they do not define
a factory application or select the future harness's language. Generated check
and integration scripts use Python's standard library; the adoption helper uses
the pinned Copier and PyYAML dependencies. Use four-space indentation, descriptive snake-case
names, and standard-library `unittest` for behavior fixtures. Keep skills concise
and maintain their YAML `name` and `description` fields.

The template's verification commands are deliberately unconfigured. Projects
select their actual commands in `.factory/project/config.json`; an empty list
does not count as passing verification. See the generated customization reference
for the full extension contract.

## Validation limits

Fixtures exercise generation, adoption, hook composition, explicit overrides,
and updates between two temporary template tags, including conflicts. They check
Codex's documented discovery paths and instruction links, not an actual Codex
session or the effectiveness of the workflows. A separate live smoke test has
now exercised discovery and one bounded workflow; it is not comparative workflow
evaluation. No benchmark, stable release, promotion, or downstream PR has been
performed.

Local validation used Python 3.14.4, Git 2.53.0, and Copier 9.14.0 on Linux.
The preparation helper has also run on macOS with Python 3.13.16. The full fixture
suite on macOS and other supported Python versions remains unverified.

The [runtime preflight](docs/runtime-preflight.md) supplies a disposable smoke
fixture and operator runbook. `scripts/prepare_smoke.py DESTINATION --ref REVISION`
pins a trusted template revision and prepares an initially failing Python project;
it never launches sbx or a model. Preparation tests cover destination refusal,
revision pinning, the expected failure and known correction, and hook enforcement.
The deliberately failing source fixture under `tests/fixtures/runtime-smoke/`
is copied into isolated projects; it is not part of top-level test discovery.
The target Mac completed the bounded Luna Medium smoke with sbx 0.46.0 and
Codex 0.160.0, including the MCP compatibility correction and scoped network-denial
checks. See the runbook's observed results for timings and evidence limits.
Subsequent disposable preflights also passed nested Kubernetes startup, a job,
and paired sandbox/pod HTTPS checks under temporary default deny with the kit's
allowlist. Global TCP allow-all was restored afterward; its rule ID changed.
UDP checks remain inconclusive, and the sampled checks do not establish full
REQ-021 acceptance or protected grader isolation. See the runbook's completed
infrastructure preflight for the tested corrections and remaining limits.

The README sandbox recipes were checked against current Docker and OpenAI
documentation. `sbx` is not installed in the editing environment; the owner ran
the live smoke checks on the target Mac. The tested non-interactive launch uses
`sbx exec`; the full initialization recipes and run-forever loop remain unverified.
Validate authentication and effective network policy before unattended use.
