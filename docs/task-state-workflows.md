# Native task-state workflows — comparison design draft

Status: implementation-ready design proposal; not a frozen experimental protocol.
Operator-side documentation for REQ-007, Q-004, and Q-005; not template-managed.
The three native arms are confirmed by D-008/D-009; the detailed schemas and cadence below are
proposed defaults for review before pilot launch. No Projects resources, accounts,
acceptance suites, or evaluation harness are created by this document.

Traceability: REQ-007, REQ-008, REQ-009, REQ-012, REQ-013, REQ-014, REQ-020,
REQ-021; D-008 through D-014, D-018/D-019; EP-02, EP-05 through EP-08.

## WS-01 Shared input and operating rules

- Mount the same frozen specification package read-only at `/spec` in every
  fresh attempt. Record a manifest of content hashes, specification version,
  immutable acceptance-work-package IDs, titles, dependencies, requirements,
  and public acceptance commands. Keep holdouts and evaluator logs outside the
  builder's mounts and credentials. Do not put mutable status in the package.
- Give the builder the whole package and control of task order. Do not dispatch
  work packages individually. A completed label is the builder's claim; only
  independent grading establishes accepted tasks or project success.
- Start a single continuous Luna Medium conversation, no delegated agents or
  human rescue. Preserve natural compaction and the same context settings in
  all arms. Short smoke tests do not establish long-horizon capability.
- Supply identical factory skills, application toolchain, public checks, Git
  policy, runtime settings, limits, and shared instruction text. Only the
  arm-specific state instructions, native state tools, and necessary credentials
  vary. Record every such difference in the run manifest.
- Use the frozen work-package IDs as the common identity, never builder-created
  subtasks as denominators. Builder-created substeps may appear in the allowed
  notes mechanism but do not add, delete, or redefine acceptance packages.
- The conceptual status vocabulary is `todo`, `in_progress`, `blocked`, `done`.
  A dependency or implementation problem may be marked blocked; the builder may
  choose other ready work. Reopen done work when public verification exposes a
  defect. Only one package is the current focus, although incomplete packages
  may remain in progress. There is no imposed priority beyond frozen dependencies.
- Application changes follow the same focused, verified commit policy in all
  arms. Do not use messages, branches, tags, or commit notes as a task tracker.
  State-only commits in the Git arm are treatment overhead, not extra task credit.

The setup manifest must record attempt ID, arm, model/runtime and reasoning settings,
template revision, tool versions, specification hashes, starting application
commit, state resource IDs, credential capability descriptions (not secrets),
network rules, time limits, and public/holdout suite identities. Freeze these
values before a real comparison rather than inheriting moving `latest` versions.

## WS-02 Conversation arm

The builder maintains status, progress, and next actions in the running
conversation and normal runtime compaction summaries. On selecting a work
package, briefly state its ID and intended next action; on completion, blockage,
or switching focus, update that conversational assessment. Use native in-session
planning if available consistently across arms; do not add a custom summarizer.

There is no task file, Project, issue list, scratchpad, custom memory, or transcript
retrieval. The builder may inspect source, public tests, and ordinary Git history
to recover facts from the work product. It must not read runtime rollout files,
logs of prior conversation turns, or evaluator snapshots as a memory channel.

Initial state is implicit: all packages in the shared immutable specification
are todo. No evaluator status refresh or human reminder is provided after launch.

## WS-03 Git-file arm

Use exactly `.factory/project/task-state.md` as the persistent task tracker.
Prepare and commit it before launch with one section per frozen package in the
same order as the specification. Example shape (the example ID is not a real
benchmark requirement):

```markdown
# Task state
Schema: 1
Specification: SPECIFICATION_VERSION

## WP-001 — Frozen package title
Status: todo
Progress:
Next:
```

IDs, titles, and specification identity are immutable. Status uses WS-01's four
values. Progress is concise current findings and verification references; Next
is the immediate action or blocker. Update in place; Git provides history.
Do not append transcripts, duplicate requirements, hidden cases, or secrets.

Read the tracker when choosing work or recovering context. Update it when work
starts, a material finding changes the next action, public verification completes,
a blocker appears, or focus changes. Commit each changed state at these boundaries
before beginning the next package. Include state with a related application
commit where possible; otherwise use `chore(state): update task state`. Do not
commit every tool call. A crash can leave uncommitted state; retain it in the
final snapshot and record the cadence violation rather than rewriting history.

Use ordinary file editing and Git; introduce no tracker service or common task API.
Transient conversational planning remains allowed, but this one file is the
persistent source of task state. Do not mirror state to GitHub or other files.

## WS-04 GitHub Projects arm

Use one private GitHub Projects v2 project per attempt, with draft items rather
than repository issues. The coordinator creates the project before launch and
seeds one item per frozen package, in specification order:

| Field | Type | Initial value / rule |
| --- | --- | --- |
| Title | Native draft-item title | `WP-001 — Frozen package title`; immutable |
| Body | Native draft-item body | Immutable requirement/specification reference |
| Work package | Text | Frozen ID; immutable |
| Status | Single select | `Todo`, `In progress`, `Blocked`, `Done`; initially Todo |
| Progress | Text | Empty initially; current findings and public verification references |
| Next action | Text | Empty initially; immediate next action or blocker |

Use native `gh project` commands (`item-list`, `field-list`, `item-edit`) inside
sbx. Native GitHub GraphQL via `gh api graphql` is allowed only for equivalent
read/update operations not exposed by the pinned CLI. Verify these operations
and pagination against the selected gh/API version before freezing prompts.
Do not introduce a shared abstraction used by all three arms.

Provide the project owner, number, project node ID, and configured field/option
IDs in an immutable arm-specific resource descriptor. Item IDs are obtained
through native listing; do not precompute a mutable local state cache. Map the
four display labels to WS-01's vocabulary. Read all items when selecting work or
recovering context; update at the same semantic boundaries as WS-03. Read back
updates to confirm persistence. If a multi-field update partially succeeds,
reconcile by reading the item and finishing the intended update; do not assume
all fields were changed atomically.

The builder may update only Status, Progress, and Next action on its seeded
items. It must not create/delete items, change schema, edit the frozen descriptors,
or use issues, comments, local files, or Git as a persistent mirror. Command
output in the current conversation is ordinary native-tool output, not a mirror.

Use a dedicated test owner/account and minimum verified Projects read/write
capabilities. Record the actual permission breadth; do not claim per-project
credential isolation if GitHub only grants broader access. Keep repository writes,
project creation/deletion, and evidence snapshots with the coordinator where
supported. Confirm owner, credentials, and cleanup responsibility under Q-019
before provisioning. Scope sbx access to required GitHub/model endpoints.

A state-service authentication or connectivity failure ends the attempt as a
separately recorded state-service incomplete; do not switch to a task file or
continue using an unassigned memory workflow. Preserve partial item updates and
account for service latency and all calls. Any retry/replacement policy requires
protocol freeze under Q-009/Q-012; this draft adds no automatic reruns.

## WS-05 Artifact and leakage rules

Apply these rules identically except for the assigned persistent tracker:

| Artifact or operation | Permitted | Prohibited |
| --- | --- | --- |
| Source, tests, migrations, deployment files | Implement and explain product behavior; inspect existing code and failures | Embed status queues, future-work lists, compaction summaries, or tracker references as memory aids |
| Product documentation | Required user/API/operations documentation and design rationale | Progress journals, completed/remaining-package lists, scratch plans |
| Git history | Focused descriptions of actual changes, ordinary code/history inspection | State encoded in commit messages, refs, tags, notes, or repeated empty commits |
| Comments/TODOs | Necessary explanations of behavior and genuine code constraints | Work-package status, next-session instructions, TODO lists used as a hidden tracker |
| Logs and terminal output | Current command results and application-generated diagnostics | Deliberately redirect conversations or progress notes to durable files for later retrieval |
| Factory/project instructions | Frozen instructions and approved product customization required by the specification | Edit workflow rules, add memory tools, or change assigned treatment during a run |
| Runtime sessions and evaluator artifacts | Normal automatic compaction, inaccessible evaluator-side capture | Query session databases/rollouts, search transcripts, access holdouts or audit snapshots |
| External services | Disclosed product fixtures and assigned native task-state service | Personal notes, additional Projects, issues, chat messages, or unrelated integrations as memory |

Product artifacts inevitably reveal implemented behavior. That is permitted;
this is a practical workflow comparison, not an attempt to erase all clues about
progress. Detect deliberate task tracking by content and use, not by banning
every occurrence of a status word or every legitimate TODO.

Before launch, provide these boundaries to every builder. The coordinator keeps
state/evidence snapshots outside the builder's access; no snapshot becomes a
recovery channel. Capture command/tool events, changed paths and Git history,
and final native tracker state for auditing. Where filesystem/runtime boundaries
cannot enforce a rule, disclose it as an audited instruction rather than claiming
technical prevention. Resolve runtime memory/log access under Q-003/Q-010 before
the pilot; do not silently enable global Codex memories in the conversation arm.

## WS-06 Audit, outcomes, and teardown

Reviewers classify suspected leakage using the frozen rules and actual artifacts.
Do not add forbidden categories retrospectively because an arm performed well.
Unclear cases remain marked for review; they do not become accepted clean runs.
Confirmed deliberate cross-arm tracking is a protocol violation: retain the
attempt, its time/usage, and its final artifacts; report it separately and exclude
it from clean-treatment comparisons. Never silently delete or replace it.
Confirmatory reliability denominators and replacement policy remain Q-012.

Infrastructure errors, quota, timeout, task failure, and protocol violation stay
distinct. Public tests and builder done labels are not authoritative holdout
grading. Capture final state only after builder access ends, then run independent
grading under Q-007. Teardown revokes attempt credentials and stops sandbox/cluster
resources after evidence capture. Archive the GitHub project read-only where
supported; delete only after the evidence-retention policy and owner authorize it.

## WS-07 Pre-pilot acceptance and freeze checklist

1. Verify all arms receive byte-identical frozen specification/public checks and
   equivalent todo initialization; protected grading artifacts remain inaccessible.
2. Exercise each native workflow through todo → in progress → blocked → in
   progress → done → reopened, confirming Git persistence or native Project
   field updates without introducing an alternate state channel.
3. Inspect compaction recovery within one continuous conversation. In the memory
   arm, allow normal summaries and source inspection; confirm no deliberate
   tracker or transcript retrieval was introduced.
4. Exercise failed Git writes and partial GitHub updates, credential failure,
   timeout, and quota classification. Preserve every attempt; do not create an
   automatic rerun or fallback arm.
5. Validate audit examples: harmless product TODO, hidden task queue in a comment,
   state in a commit message, a copied transcript, and accidental versus deliberate
   leakage. Have a human approve the boundary interpretation before freezing it.
6. Attribute native read/write/commit/API overhead and service delays to the arm;
   keep setup cost separately visible and avoid counting calls or subtasks as
   accepted work packages (Q-010/Q-011).
7. Freeze exact file format, seeded Project schema/IDs, native tool versions,
   credentials/scopes, common and arm-specific prompt texts, snapshots/retention,
   and interruption policy. Record reviewer approval and artifact hashes.

This draft resolves the design shape of Q-004/Q-005, not their readiness gates.
Remaining external inputs are the frozen application specification, GitHub owner
and permission verification, operational limits, telemetry/retention mechanics,
and human review. No numerical promotion criteria are invented here.

## WS-08 Prompt fragments to freeze with the shared launch prompt

Common: “Read the full specification at `/spec` and the factory instructions.
Choose your own task order while respecting disclosed dependencies. Use only the
assigned task-state mechanism below. Follow WS-01 and WS-05. Public verification
supports your work; it does not establish independent acceptance. Do not delegate,
request human rescue, edit protocol instructions, or access evaluator artifacts.”

Conversation: “Keep status, progress notes, and next actions in this conversation
and normal compaction summaries. Do not persist a tracker or retrieve transcripts.
Use source inspection as needed. State package selection and outcome changes here.”

Git file: “Use `.factory/project/task-state.md` as your only persistent tracker.
Read it when selecting work or recovering context. Update the seeded package
sections and commit changes at the WS-03 boundaries; preserve immutable IDs and
titles. Do not mirror task state elsewhere.”

GitHub Projects: “Use the assigned private Project through native gh commands.
List seeded items, update only Status, Progress, and Next action, and read back
updates at the WS-04 boundaries. Do not create a local mirror. On loss of state
service access, stop and report the incomplete attempt rather than changing arms.”

## WS-09 Completion evidence for REQ-007

This document establishes reviewable allowed-state boundaries, not completion
of the comparison. Before claiming completion, retain authoritative evidence of:

- Human-reviewed, hash-bound common and arm-specific prompts and boundary rules.
- Identical immutable specification/public-check hashes across the three arms,
  equivalent initial todo state, and inaccessible protected artifacts.
- Verified native state transitions and recovery, including Git write failure,
  Projects pagination/partial updates, and state-service interruption.
- Continuous-conversation operation and an audit of alternate-state leakage.
- Verified Projects ownership, scopes, endpoint access, retention, and cleanup.
- Frozen versions, limits, interruption policy, and reconciled overhead accounting.
- Separately authorized execution and independent results for all three arms,
  with native overhead included in the reported comparison.

The builder interval includes native tracker reads, writes, state commits,
API reconciliation, and service delays. Their usage remains in the arm total
when separately attributed. Keep coordinator setup/seeding and snapshot/teardown
costs separately visible. Reconcile attributed usage to run totals and label
missing/unallocated usage explicitly. Failed work remains included; native calls
and builder-created subtasks never enlarge accepted-work-package denominators.
Exact clock boundaries and attribution methods require protocol freeze.

Memory-only calibration and synthetic fixtures cannot establish a three-arm
result or authorize further benchmark execution. The current documentation is
not a frozen protocol, a selected default, or promotion evidence.

## WS-10 Git seed preparation and local validation

`evaluation.git_state.render_git_seed(package_bytes, expected_sha256)` renders
the initial Markdown from the exact reviewed `packages.json` bytes. The operator
must obtain the expected digest from the reviewed workload record, not recompute
it from an unreviewed replacement. The function preserves specification order,
IDs and titles, seeds todo state, and rejects duplicate IDs/JSON keys and injected
line breaks. Hash matching alone does not establish human approval or freeze.

The coordinator owns writing the returned bytes to `TRACKER_PATH` in the fresh
Git-arm project and committing them before launch. The renderer does not write
files, dispatch tasks, update builder state, or create resources. Conversation
and Projects arms must not receive this tracker. Specification copying and launch
gates remain separate. The builder uses ordinary editing and Git after launch.

Setup and run the native Git fixture with:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -p test_evaluation_git_state.py -v
```

The fixture uses temporary repositories and real bounded Git commands to exercise
start, blockage, resumption, completion, reopening, fresh-checkout recovery, and
failed staging with retained uncommitted state. It verifies unchanged specification
bytes and initial-state history. This is synthetic Git persistence evidence only;
it does not verify sbx mounts, model compaction, Projects, usage accounting, human
review, or any comparative outcome.
