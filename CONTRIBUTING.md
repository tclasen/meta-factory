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
session or the effectiveness of the workflows. Live model discovery and workflow
evaluation remain runtime preflight and evaluation-harness work. No benchmark,
stable release, promotion, or downstream PR has been performed.

Local validation used Python 3.14.4, Git 2.53.0, and Copier 9.14.0 on Linux.
macOS execution and older supported Python versions have not yet been exercised.

The [runtime preflight](docs/runtime-preflight.md) supplies a disposable smoke
fixture and operator runbook. `scripts/prepare_smoke.py DESTINATION --ref REVISION`
pins a trusted template revision and prepares an initially failing Python project;
it never launches sbx or a model. Preparation tests cover destination refusal,
revision pinning, the expected failure and known correction, and hook enforcement.
The deliberately failing source fixture under `tests/fixtures/runtime-smoke/`
is copied into isolated projects; it is not part of top-level test discovery.
Live Luna Medium validation on the target Mac remains pending.

The README sandbox recipes were checked against current Docker and OpenAI
documentation. `sbx` is not installed in the editing environment; the recipes
have not been exercised against a live sandbox here. Validate runtime versions,
authentication, and network policy on the target host before unattended use.
