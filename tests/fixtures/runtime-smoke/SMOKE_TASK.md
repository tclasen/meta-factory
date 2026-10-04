# Bounded factory runtime smoke task

Read `AGENTS.md` and the factory instructions. This task authorizes planning
and implementation in this one session; do not stop after proposing a plan.
Read and apply `factory-plan`, `factory-implement`, `factory-verify`, and
`factory-review`, briefly identifying each skill as you use it.

Fix `normalize_tag()` in `normalizer.py` so it removes surrounding whitespace
and lowercases the input while preserving internal spaces. Keep its public
signature. Inputs for this task are strings only.

Only change `normalizer.py`. Do not modify tests, instructions, configuration,
factory resources, Git hooks, or history. Do not delegate. Run configured
verification, inspect the diff, and review your change. Leave it unstaged and
uncommitted. Report the checks and outcomes, any review findings, and anything
you could not verify. Then stop.

Acceptance: all four fixed tests pass; only `normalizer.py` changes; the initial
commit and branch remain intact; and the operator can observe use of the four
factory skills. A successful process exit or completion claim alone is not a pass.
