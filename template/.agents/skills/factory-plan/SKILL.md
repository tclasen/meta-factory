---
name: factory-plan
description: Plan a repository change by tracing the requested outcome to project constraints, a focused implementation unit, and observable verification.
---

# Plan a change

Read `.factory/core/instructions.md` and project guidance. Inspect the relevant
implementation and configured checks before proposing changes. Identify the
requested outcome, affected interfaces, constraints, and an observable acceptance
condition. Preserve existing requirement or decision identifiers.

Resolve discoverable facts by inspection. Ask only about consequential intent
that remains unclear. Split larger work into independently verifiable units;
identify the first unit and its checks. Name compatibility or migration work
only when the change needs it. Keep plans in the project's selected task-state
mechanism; do not introduce a tracker as a side effect of planning.

Finish with a plan another agent can execute without guessing important product
decisions. Planning alone does not authorize implementation or external actions.
