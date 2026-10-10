# Native task-state comparison (REQ-007)

This developmental study ran one fresh, uninterrupted builder attempt for each native state workflow against the same frozen application specification. It is a descriptive comparison, with partial independent grading and no authoritative acceptance, default selection or promotion.

## Shared inputs and boundaries

- Conversation: task status, progress and next actions remain in the running conversation and natural compaction summaries; no persistent task tracker.
- Git file: the assigned committed task-state file holds the same fixed work packages, current status, progress and next action. Ordinary file editing and Git are the native interface.
- GitHub Projects: a fresh private Projects v2 resource contains the same seeded draft items and native status/progress/next-action fields, accessed through the GitHub CLI. No local mirror or common task API is supplied.

Each builder received the entire frozen workload and chose its own task order. There was one continuous Luna Medium turn per arm, natural compaction, no delegated builder, human rescue, forced compaction or retries. Necessary native tools and credentials differ by treatment; Projects access was broader than the assigned project, so credential capabilities were not isolated to a single resource.

Runs were sequential in the fixed order conversation, Git file, then Projects. Each owned sandbox was configured for eight CPUs and 16g memory. Concurrent activity was recorded; the host was not required to be idle. Configured memory is reported without claiming a specific usable-memory threshold or performance acceptance.

| Shared identity | Value |
| --- | --- |
| Model / reasoning | `gpt-6-luna` / `medium` |
| Factory revision | `1c51d12e316b70b8bdd23e178686b7dee3ea4738` |
| Shared workload/input identity | `440c15c5de1a082eb858def8224c4b5767ffa1417c7c2711117296e7f099bd7d` |
| Frozen comparison manifest SHA-256 | `f21b9ce0df6458004e3817f9c66241ebf6529f9ca2d93e153143e95751996504` |
| Protocol SHA-256 | `8523b92a791737dc76dd0898a65e21cddbfe9fd7cc1ec6051e401660846ed406` |

Protected grading cases and raw private evidence remain outside Git and builder mounts. The saved operator adapter archive preserves the original bytes for later review; post-study maintenance changes do not alter consumed grading inputs.

## Original outcomes

| Arm | Builder declaration | Builder minutes | Natural compactions | Independent grading |
| --- | --- | ---: | ---: | --- |
| conversation | blocked | 81.05 | 1 | 17 pass, 6 fail, 0 inconclusive, 57 untested |
| git-file | complete | 77.09 | 2 | Bootstrap failed; no native cases recorded |
| github-projects | complete | 91.48 | 2 | 32 pass, 6 fail, 0 inconclusive, 42 untested |

The denominator is 12 frozen work packages and 80 registered grading groups, with 38 selected native HTTP groups and 42 unsupported groups in this study. Missing original entries are reported separately; derived accounting never invents a verdict. Grading outcomes and interruptions are retained exactly as observed.

The conversation deployment passed the original real-time, hour-long session-expiry check. Its later failures occurred before their target checks completed, with a shared-fixture/session interaction consistent with the observations. Those failures alone do not establish failure of the underlying application invariants; the original verdicts remain unchanged. The Git-file bootstrap failed before cases began. Credential-safe logging retained the status and byte counts, so its cause is unestablished.

Projects completed all 38 selected groups: 32 passed and six failed. Five failures report status differences for API validation or creation, and one reports a missing or duplicate operation audit event. The disclosed specification defines these contracts. Status differences alone do not establish database corruption or loss of atomicity; later invariant checks were not always reached. Root causes and every failed payload were not independently traced, and all original verdicts remain unchanged.

Conversation recorded 23 selected groups before its shared-fixture interruption, leaving 15 selected groups unexecuted plus 42 unsupported groups. Git-file has no original case entries: all 80 remain missing after bootstrap failure. Its derived accounting records missingness and the plan, without filling verdicts.

The first common grader CLI preflight failed before any grading sandbox or native case. A common execution-only correction was made after the conversation capture and before the first native grade and subsequent builders. Failed receipts and the frozen original were preserved. The correction did not change candidate source, selected cases, oracles, scoring, treatment or limits; it was not wholly prospective to the original freeze.

Saved state reviews are scoped: initial/final instruction equality, reachable Git tracker identity/status history, selected command contexts, and initial/final native Project readbacks. Four Git tracker entries remained in progress despite the completion declaration; all final Projects items were marked Done. These labels are builder claims. The reviews do not establish complete semantic compliance, absence of transient changes or hidden/deleted channels, or protection against malicious guest tampering.

## Time, usage and overhead

| Arm | Input tokens | Cached input subset | Output tokens | Reasoning output subset | Total tokens |
| --- | ---: | ---: | ---: | ---: | ---: |
| conversation | 57,067,452 | 56,084,992 | 250,294 | 127,196 | 57,317,746 |
| git-file | 70,274,447 | 68,950,784 | 264,716 | 127,940 | 70,539,163 |
| github-projects | 71,381,324 | 69,954,816 | 304,701 | 145,095 | 71,686,025 |

Native state work and waits are included in continuous builder time and usage. Cached input and reasoning output are included subsets, not extra tokens. Stage/task/state-only token attribution is unallocated, and no monetary tariff or accepted-task cost is inferred.

| Arm | Builder/capture parent minutes | Independent grader parent minutes | Handoff wall gap minutes |
| --- | ---: | ---: | ---: |
| conversation | 81.89 | 64.37 | 4.75 |
| git-file | 77.93 | 4.45 | 0.44 |
| github-projects | 92.37 | 64.32 | 0.79 |

The one-use Projects seeding attempt took 36.71 seconds across 61 native commands, including its preflight, and is allocated once to Projects. Parent spans contain their nested phases and commands; those durations are not added again. Handoff gaps are calendar time, not measured active effort or causal state overhead.

The prospective sequential forecast was 443–1,530 minutes: preparation 30–80; three builders 60–300 each; captures 3–30 total; grading 210–480 total; reporting/reconciliation 20–40. Original rounded bounds and the pre-launch correction remain preserved. Builder and grading actuals are measured; complete disjoint preparation/capture/reporting effort was not metered. Incomplete grading can shorten actual elapsed time without delivering planned coverage.

## Interpretation and retention

One workload and one attempt per arm, fixed order, prior exposure, cache/provider effects, partial unapproved grading, shared-fixture assumptions and incomplete state semantics prevent a causal ranking or reliability claim. A separate calibration reached three natural compactions; it is not pooled with these comparison arms. The earlier feasibility study and failed development attempts remain separate evidence.

All original terminal reviews verified removal of their owned builder/capture/grading sandboxes and grading scratch, with global host policy unchanged. Retained protected captures, receipts and adapter archive support audit. Resource retention and later cleanup are recorded separately; unrelated resources are not pruned.

The study exercises the three native workflows and reports their total overhead and independent outcomes. It does not establish authoritative accepted work packages, strict application success, a practical default winner or stable promotion. Full grading coverage, substantive human suite review, fixture/session assumptions and observer trust boundaries remain unresolved for authoritative or confirmatory evaluation. Production DORA metrics are unavailable; disposable study deployments are not production deliveries.
