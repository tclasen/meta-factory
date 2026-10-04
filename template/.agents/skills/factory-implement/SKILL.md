---
name: factory-implement
description: Implement an authorized repository change in a focused unit, preserving project extensions and following the project's verification and Git policy.
---

# Implement a change

Read `.factory/core/instructions.md` and project guidance. Confirm the requested
unit and acceptance condition from the conversation or selected task-state source.
Inspect worktree changes and resolve ownership before modifying overlapping work.
Follow the project's branch and commit rules; do not invent a universal policy.

Implement the smallest coherent change. Keep project customization out of the
managed factory core. If scope or an interface must change, explain the concrete
reason and resolve consequential ambiguity before dependent work.

Use `factory-verify` for the resulting change, inspect its diff, and fix failures
within scope. Report the outcome, evidence, and unresolved limitations. Commit or
publish only as authorized by the user's task and project policy.
