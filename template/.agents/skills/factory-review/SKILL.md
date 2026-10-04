---
name: factory-review
description: Review a repository diff for defects, requirement gaps, compatibility issues, and insufficient verification, with actionable findings tied to changed behavior.
---

# Review a change

Read `.factory/core/instructions.md` and project guidance. Establish the intended
outcome and inspect the diff with its callers and tests. Check behavior against
the acceptance condition, project extension boundaries, and relevant failure
paths. Evaluate the reported verification rather than assuming it proves the
change correct.

Report actionable defects with file locations, triggering conditions, impact,
and evidence. Separate unresolved questions and coverage gaps from demonstrated
defects. If no defects are found, say so and note material verification limits.
Do not edit code during a review-only task or imply that review is independent
benchmark grading, release approval, or permission to merge.
