# Factory architecture

The factory is an experimental collection of repository-contained resources for
Codex, distributed through Copier. It has no central application or service.
A separate evaluation harness remains to be designed.

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

The run-once and run-forever recipes in the [user guide](../README.md) launch
ordinary Codex sessions. Each loop iteration starts a fresh conversation; this
is not the continuous-conversation experimental protocol or a benchmark runner.
