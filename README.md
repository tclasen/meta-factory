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
