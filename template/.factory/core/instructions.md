# Factory working instructions

Read `.factory/project/policy.md` and `.factory/project/config.json` with the
repository's own guidance. Project-specific defaults use the extension contract
in `.factory/core/references/customization.md`; do not infer an override from
contradictory prose. Surface unresolved conflicts before the affected work.

Use the appropriate `factory-plan`, `factory-implement`, `factory-verify`, or
`factory-review` skill for the requested work. Scale the workflow to the change;
these skills do not require four separate sessions or a persistent task tracker.
Respect the project's chosen task-state mechanism, branch policy, and user scope.

Treat `.factory/core/` and `.agents/skills/factory-*/` as template-managed. Make
project customizations in `.factory/project/`. Propose core changes upstream or
as explicit, reviewable template changes rather than incidental local edits.

Record what was actually verified and any incomplete checks. Project checks and
builder-written tests are not independent benchmark grading. Do not modify or
claim approval from externally controlled acceptance or release gates.
