---
name: factory-verify
description: Verify a repository change with project-configured commands and acceptance checks, distinguishing passing results from missing or incomplete verification.
---

# Verify a change

Read `.factory/core/instructions.md`, project policy, and configured commands.
Inspect commands before execution and respect the execution environment and
permissions of the task. Run the required project verification from the root:

```sh
python3 .factory/core/tools/check.py verify
```

If verification is unconfigured, identify appropriate checks from the actual
project and explicitly configure them within authorized scope, or report that
verification is incomplete. Never turn an empty check list into a success claim.
Add acceptance checks for changed behavior when existing checks do not cover it;
avoid tests that merely mirror implementation wording.

Inspect the diff for unintended changes. Report the commands, outcomes, and
material coverage gaps. Distinguish project tests from independent acceptance
grading; passing these commands does not approve a release or catalog promotion.
