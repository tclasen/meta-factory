# Evaluation controller

Separate operator-side tooling for REQ-012/014/015/020. This package is not copied
into generated projects and must never be mounted into a benchmark builder.
The owner authorized implementation; experiment launch, protected-suite approval,
and host-wide policy changes remain separately gated.

Python 3.11+ with pinned `jsonschema` 4.25.1 for the generated protocol contract; no service, build step, or model call is required
for deterministic controller tests. From the repository root:

```sh
uv sync --locked
uv run --locked python -m unittest discover -s tests -p 'test_evaluation*.py' -v
uv run --locked python -m unittest discover -s tests -v
git diff --check
```

`evidence.py` supplies exclusively created private attempt directories, durable
JSONL transitions, atomic status/result snapshots and bounded subprocess logs.
Commands preserve actual exit status and separately classify timeout/output limits.
They never use a shell. Callers must keep secrets out of arguments and manifests.
Terminating an sbx client does not prove its remote children stopped: a separate
sandbox termination check is required before capture/grading.

Controller fixture success is not benchmark or promotion evidence. There is no
experiment launch command until runtime, containment, grading and readiness gates
are implemented and validated. Concrete protected suites remain outside builder
mounts and are reviewed independently of builder-written tests.


`runtime.py` implements one initialized app-server connection, one thread and one
turn, with optional write-only stage reports. It preserves cumulative usage,
deduplicates compaction items, refuses unexpected approvals, distinguishes quota
from builder failure, and bounds transport/output/deadline handling. Schemas in
`schema/` are selected directly from installed Codex 0.160.0; provenance records
both original bundle and selected-schema hashes. Online documentation is not used
as a substitute for the pinned wire contract. Generate a comparison bundle with:

```sh
codex app-server generate-json-schema --experimental --out /tmp/factory-codex-schema
```

Deterministic fake-server fixtures cover the adapter; live stage tools, natural
compaction and remote termination still require bounded host preflight. Reported
model configuration and runtime telemetry are not provider-side attestation.


`sandbox.py` builds explicit 8-vCPU/16-GiB, loopback-only sbx plans and refuses
workspace/specification mounts overlapping operator evidence or controller files.
It verifies stop with the pinned `sbx ls` status table, never `exec` (which would
restart the sandbox). Source capture reads regular files without executing Git,
hooks or build scripts on the host; bounds and unsafe paths fail capture rather
than manufacture an application failure. Live sbx behavior still needs Mac
preflight. No global policy mutation or resource deletion is implemented here.


`grading.py` and `grade_worker.py` run externally stored, hash-verified operator
suite code in bounded processes. The suite binds its package mapping, enumerates
case-to-criterion coverage, and declares which criteria have complete coverage.
Independent review must bind the suite manifest hash before final acceptance.
Missing tests, partial coverage, unapproved suites, changed source, worker crashes,
and timeouts cannot yield project success. Development runs explicitly report
unapproved observations; they never populate accepted-package counts.

Protected cases and approval records are operator-local, outside all application
mounts. This repository contains grader mechanics and synthetic fixtures only;
those fixtures are not the application acceptance suite. The controller does not
execute application build scripts on the host or trust application-produced
passing-test messages as grading results.

Readiness inspection is available without enabling experiment launch:

```sh
uv run --locked python -m evaluation inspect \
  --workload .factory-planning/first-test \
  --suite .factory-planning/protected-first-test
```

It writes a unique directory under `.factory-planning/evaluation-readiness-logs/`
and exits 2 while gates remain unresolved. This is expected, not an application
failure. No `run` command or boolean bypass is exposed while long-run containment,
protected-suite coverage/review and host integration remain incomplete. The network
checker rejects wildcard/global allow-all and unreviewed effective destinations;
that check alone is not live enforcement evidence.


`watchdog.py` is an independent stop-only process. It arms before protected work,
monitors its actual parent and a bounded wall/monotonic deadline, and stops only
its declared evaluator sandbox. Release also performs a fresh stop/status check;
parent claims cannot disable cleanup verification. It survives controller process-
group death, but not host shutdown or daemon failure. Those remain explicit
recovery/incomplete outcomes, not claims of protection while the host is offline.
No cloud TTL is used: sbx 0.46.0 documents `--ttl` as cloud-only.

The first live Mac adapter preflight (`evaluation-host-logs/run-r3k3oe1f`, local
operator evidence, 2026-10-04) passed after event review: exact pinned schema,
one requested Luna/medium stage call, completed turn, blank runtime stderr,
canary capture, shell grading sandbox, and verified stops for both resources.
No shell/delegation calls occurred in the model trace. It did not exercise natural
compaction, controller death, default deny, or full application grading.


`deployment.py` verifies captured source identities, copies them into a new isolated
project, runs `ops/bootstrap.sh` only through the shell grading sandbox, and invokes
the external suite against the operator-selected loopback origin. A separate guard
bounds the sandbox lifetime; failure paths retain evidence and attempt verified
cleanup. The grading budget includes source verification/copy, provisioning and
bootstrap, not just test execution. This adapter is fixture-tested; its full live
redeployment path passed the synthetic Mac preflight described below.

The Mac watchdog preflight (`evaluation-failure-logs/run-znnxk7d0`, local evidence,
2026-10-04) passed both deadline and local-controller SIGKILL cases: exact named
sandboxes stopped, heartbeat files ceased changing, and stop status was verified.
Transport exits 143 and -9 were retained as expected failure evidence. No model
calls, host reboot, daemon failure or network policy changes were part of that test.

`source.py` inventories the stopped builder project through a separate shell
sandbox with a readonly project mount. It selects tracked and nonignored untracked
files, records tracked deletions and ignored artifacts explicitly, and preserves
regular Git metadata. Thus ignored virtual environments and dependency directories
do not block source capture merely because they contain symlinks. Git does not run
against application repositories on the host. Relative source symlinks that stay
inside the project are preserved without host traversal, and their identities are
checked during redeployment. Absolute or escaping links, linked worktrees,
submodules and hardlinks remain unsupported; these produce
incomplete infrastructure evidence, not an application-failure verdict. A source
inventory alone does not prove reproducible deployment or capture container images.
The inspector uses a separate disposable writable primary workspace because
sbx 0.46.0 rejects a readonly primary mount; its retained path is logged for cleanup.
This constraint was observed in Mac preflight `evaluation-deployment-logs/run-zndm65hl`:
the source fixture stopped successfully, inspector creation was rejected before
resource creation, and redeployment/grading remained untested in that attempt.

The corrected Mac attempt `evaluation-deployment-logs/run-0p3cha5v` passed source
inventory (including ignored symlink and tracked deletion), capture, fresh shell
deployment, protected external HTTP grading and all three verified sandbox stops.
The synthetic unapproved suite correctly produced no accepted packages. This does
not validate Kubernetes deployment, container-image capture or application acceptance.

### Cleanup after controller or host interruption

After the original controller has exited and the host sbx daemon is available,
run on the Mac, replacing `RUN` with the original protected attempt directory:

```sh
uv run --isolated --locked python -m evaluation.recovery --attempt RUN
```

Recovery logs to a new `.factory-planning/evaluation-recovery-logs/run-*/` directory.
It validates exact recorded resource names against original creation events, stops
only those resources, verifies their stopped/absent status, and preserves original
evidence. A missing or unavailable daemon cannot establish cleanup. It never resumes
the builder or restarts a sandbox. This explicit recovery command does not provide
deadline enforcement during host reboot or daemon failure; that launch gate remains.

### Sandbox-local Kubernetes preflight

The synthetic cluster check `local-cluster-grading-logs/run-bkg84rkg` passed on
the agent's sbx Docker daemon (29.7.2, kernel 7.0.14): live Pod/ReplicaSet/Deployment
ownership, application Pod security, private services, paired allowed/denied
ingress and egress probes, and verified removal of the named cluster container.
It used k3s v1.34.1-k3s1 with Canal v3.30.3, flannel and the native k3s policy
controller disabled, upstream CNI directories, and private node cgroup/mount setup.
This is synthetic local evidence, not Mac publication, benchmark allocation,
application grading, or an approved operator egress policy.

The native k3s policy controller failed enforcement in the same environment.
An isolated netfilter probe accepted ipset/set matches but rejected NFLOG; the
controller's NFLOG rules caused its entire iptables update to fail. Retained
failure logs identify the limitation. Do not infer enforcement from NetworkPolicy
objects or healthy application connectivity; both permitted and denied connections
must be observed. The tested alternative remains a preparation candidate pending
complete toolchain identity capture and final protocol review.

`images.py` runs a standalone image probe inside the grading sandbox, using an
operator-selected kubectl command prefix. It records declared references and
runtime-reported SHA-256 image IDs for application, init and ephemeral containers.
Missing identities or failed queries remain incomplete. Raw Pod environment and
query diagnostics are excluded from host logs; the underlying query exit status
is retained. These observations are neither registry attestations nor archived
image layers. The adapter has local fixtures; live image-inventory integration
is still pending.

### Scoped workload faults

`workloads.workload_operation` executes a trusted probe inside the grading sandbox
against an operator-selected namespace and Deployment or StatefulSet. Inspection
records UID, resource version, desired replicas, observed generation and Pods
linked through exact controller UIDs. Raw Pod/container environment and kubectl
error text remain inside the probe; query exit codes are preserved.

Scaling uses a JSON Patch with UID, resource-version and original-replica tests.
It waits at most 120 seconds for the controller to observe the change and for
owned Pods to disappear (zero replicas) or become ready (restoration). A replaced
workload, concurrent replica change, rejected patch or timeout remains incomplete.
A failed operation can still have changed replicas. Persist the original
observation before suspension, inspect the same UID in `finally`, and restore
its original count; never overwrite an independently changed workload. The caller
must run this inside a lifetime-guarded disposable grading sandbox and stop that
sandbox if scoped restoration cannot be verified.

This adapter does not infer application roles, support arbitrary operators or
standalone Pods, or prove storage outage merely from scaling. It requires
independent role mapping and service-level fault/recovery probes. HPA/operator
interference makes the attempt incomplete. StatefulSet ownership has synthetic
fixtures; live coverage must be reported separately from Deployment testing.

Focused validation:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_workloads.py -v
```

The sandbox-local synthetic run `local-cluster-grading-logs/run-ay0r88oj`
verified one Deployment at 1 → 0 → 1 replicas, no owned Pods during suspension,
continued API service availability, restored worker readiness/connectivity, and
verified cluster removal. This used the local fixture transport, not Mac sbx
transport. It does not validate S3 storage failures, durable worker jobs, or restoration
after controller death.

The subsequent local run `local-cluster-grading-logs/run-a433yxlz` also verified
a StatefulSet at 1 → 0 → 1 replicas. A separate synthetic HTTP dependency was
reachable before suspension, refused three connections while its owned Pods were
absent, and became reachable after restoration. Independent API positive controls
passed before and after the outage; final cluster removal was verified. The
StatefulSet used a disposable HTTP server, not an S3 service or persistent volume.
Object-write atomicity, orphan cleanup, durable data and job recovery remain
unverified by this fixture.

### Fault contexts and grading aborts

`faults.suspended_workload` wraps the workload adapter for an operator-selected
resource. It requires a ready baseline, writes the original UID/replicas before
suspension, and verifies restoration in `finally`, including when suspension may
have changed replicas before reporting failure. Body errors and restoration
outcomes are recorded separately. A replaced or independently scaled workload is
not overwritten. This supports REQ-012/015/020; it does not discover storage roles
or establish an application-level fault by itself.

Protected cases that alter runtime infrastructure must declare
`"mutates_runtime": true` in their hashed suite manifest. An inconclusive result
from such a case aborts the remaining suite; a restoration failure explicitly
requests the same abort. Remaining cases stay untested. The deployment owner then
stops the disposable sandbox using its existing guard/cleanup path. Cases cannot
continue on uncertain cluster state after a worker timeout or exception.

The context's `finally` cannot run after SIGKILL or host loss. Its surrounding
sandbox lifetime guard remains required. This is a callable operator adapter;
serialized transport configuration and protected application fault-case wiring
remain separate integration work.

The local synthetic run `local-cluster-grading-logs/run-12nbsq9r` exercised this
context around the StatefulSet service outage and recorded
`restoration_verified: true`, recovered connectivity, and verified cluster removal.
Controller fixtures additionally cover interruption, failed suspension after a
mutation, replacement/concurrent scaling, and restoration failure. These are fault
control checks; protected S3/application observations remain to be integrated.

### Parent-owned fault transport

`fault_broker.FaultBroker` serves authenticated requests on a private Unix socket
(mode 0600 in a 0700 temporary directory). It accepts only `suspend` for a reviewed
role and `restore`; worker-supplied commands, arguments and workload names are
refused. Its parent-owned factory opens the scoped fault context. Disconnection,
idle timeout or uncertain restoration blocks subsequent faults. Broker shutdown
waits for bounded context cleanup. A dead parent leaves no endpoint for the worker
to execute or restart a sandbox; workers never receive `sbx exec` capability.

`run_suite(..., fault_broker=broker)` supplies this capability only to cases marked
`mutates_runtime`. Any `_fault_control` supplied in the ordinary target is removed.
The parent waits for fault cleanup and aborts grading if the broker is uncertain.
The nonce stays in the private per-case target file outside application mounts;
requests and tokens must not be copied into application evidence or public logs.

Factories must use separate child evidence attempts, since broker callbacks run
in a parent thread while the grader records its subprocess. They must bound all
operations and prevent new commands near/after the sandbox guard deadline. Wiring
that lifecycle-aware factory into `grade_capture`, and live protected application
fault cases, remain pending. This transport alone is not a launch gate bypass.

### Binding faults to a grading attempt

`grade_capture` accepts optional operator-created `fault_workloads` and
`kubectl_prefix` arguments. Each role maps to exactly `namespace`, `kind`, `name`
and the independently observed workload `uid`; namespace must be `incident-app`.
For a fresh deployment, `fault_workloads` may be an operator-owned resolver
called with the sandbox after bootstrap, when the live UIDs exist. The resolver
must independently inspect the deployed roles. These arguments are separate from
application target data. `FaultRuntime` creates
a parent-owned broker and private child evidence attempts for each fault, checking
the selected UID before suspension. It revokes new commands and closes the broker
before releasing the grading sandbox's guard.

Admission requires at least 630 seconds of remaining grading time for four bounded
commands, the 60-second fault body, and scheduling allowance. Every command checks
both wall and monotonic deadlines again, reserving 150 seconds, and refuses after
guard exit/release, sandbox stop or explicit revocation. Insufficient time is
inconclusive; it does not shorten restoration silently or extend the grading budget.
These checks do not resolve host sleep/reboot or independently initiated host stops;
that interruption/containment gate remains part of launch review.

Local run `local-cluster-grading-logs/run-7bpoxv6c` exercised the connected runtime
and broker against the synthetic StatefulSet, using a node with a 900-second
internal ceiling. Its private child attempt recorded `fault_restored` and
`restoration_verified: true`; service outage/recovery, independent API controls
and cluster removal passed. This validates local transport and lifecycle wiring,
not Mac sbx transport, real S3 behavior, or host-interruption containment.

Fault factories may yield `{"service_outage_verified": true}` only after an
independent service observation. The broker forwards only that exact Boolean,
never arbitrary callback fields; missing evidence and truthy strings become
false. `remote_fault` yields this projected observation to the protected case.
Replica suspension alone does not set it: `FaultRuntime` leaves service-level
verification false unless independent service probes are configured. Storage oracles must remain inconclusive without that precondition.

### Independent service connectivity probes

Optional `fault_service_probes` in `grade_capture` is an operator-created mapping
(or post-bootstrap resolver) from fault role to `peer_prefix`, `target`, and
`control`. The prefix executes a trusted diagnostic peer inside the grading
sandbox; it must not use builder-modified utilities. Targets are private HTTP IP
addresses with explicit ports, no credentials/query/path. The control must be an
independent service reachable from the same permitted peer. Operator role/peer
selection remains required; this does not infer network policy or application
roles from builder declarations.

The sanitized probe records HTTP connectivity and original exit statuses, excluding
response bodies, headers and arbitrary stderr from operator logs. HTTP errors such
as a private bucket's 403 still prove connectivity. Only recognized connection
failures prove unreachability; missing utilities, exec errors and ambiguous output
remain inconclusive. Baseline and recovery require a reachable target plus controls;
outage requires three unreachable target observations bracketed by working controls.
Each probe process is bounded to 40 seconds. Three phases raise fault admission
reserve to 750 seconds; the private worker RPC timeout is 360 seconds.

Local run `local-cluster-grading-logs/run-jn_nu41f` passed all three phases, propagated
the verified-outage flag, restored the StatefulSet and removed its cluster. The
peer used the locked BusyBox fixture image; its API and storage services were
synthetic HTTP servers. This does not verify S3 data semantics, HTTPS/raw-TCP
probes, real application peer selection, or Mac fault transport.

### Shared application fixture changes

Cases that alter shared users, memberships or configuration declare
`"mutates_shared_state": true` in the hashed manifest. They must preserve original
values and restore them in `finally`; uncertain restoration raises
`FaultRestoreError`. Any non-passing result, including timeout or an untested
observation, aborts the remaining suite because later permissions or behavior may
be contaminated. A passing case is responsible for verifying restoration.

This declaration does not grant the parent fault-control capability. Only
`mutates_runtime` grants that separate capability when a broker is configured.
Ordinary tests that create isolated records need neither declaration unless they
also change shared state or runtime infrastructure. This protects REQ-012/015/020;
it does not prove the application's own authorization or transaction behavior.


### Audit persistence fault observations

A parent fault callback can additionally report `audit_insert_failure_verified`.
The broker forwards only an explicit Boolean true as verified, and never forwards
connection details, SQL, table/constraint identities or other callback fields.
This reports audit-insert failure separately from a service outage; an available
database can reject audit writes while other operations remain available.

The parent must independently demonstrate audit insertion succeeds before the
fault, fails under the actual mapped runtime identity while the fault is active,
and succeeds after exact restoration. Installing DDL alone is insufficient.
Protected cases must treat absent/false verification as inconclusive. Existing
restoration uncertainty still aborts grading. This protocol support does not yet
provide a live database adapter or establish application rollback behavior.

### PostgreSQL audit probes and disposable live preflight

`database_probe.py` generates bounded SQL for an independently mapped disposable
grading database. It observes actual session/current roles, owner/RLS settings,
SET ROLE reachability, table/column UPDATE and DELETE/TRUNCATE privileges. It also
supports rollback-only UPDATE/DELETE observations and an exact-identity,
reversible audit-write fault using CHECK(false) NOT VALID. The latter blocks new
inserts and updates while preserving existing rows; it is not an INSERT-only
permission fault. PostgreSQL 16+ is needed for the SET membership query.

Run the live fixture inside Linux sbx with Docker available:

```sh
uv run --locked python scripts/test_evaluation_postgres.py
```

The script caches a pinned PostgreSQL 17.6 image if needed, creates one uniquely
named network-disabled container with no published ports, 2 CPUs, 512 MiB memory,
tmpfs data and a 240-second internal lifetime, and verifies removal. It uses only
synthetic data and local trust authentication inside that isolated container;
no credentials, model calls, global policies or unrelated resources are involved.
Each attempt records revision, source hashes, tool versions, command output/status
and cleanup under `.factory-planning/postgres-preflight-logs/run-*/`. It prints
that path and retains failures. It refuses direct execution on the host Mac.

The live fixture distinguishes atomic rollback from a separate-commit defect,
checks restoration and stale-identity refusal, and covers inherited/column-only
permissions, RLS, error sanitization, query timeout and identifier escaping.
This is separate from standard-library fixture discovery, which needs no Docker.

These SQL helpers do not create a trusted database connection or assign acceptance
verdicts. Operator identity/relation binding and bounded transport are still
required. Missing tables, SQL rejection and zero affected rows are observations,
not proof of complete append-only protection. Rollback does not undo sequence
increments or arbitrary external trigger effects: mutation/fault helpers must be
used only in an isolated disposable grading database with independent canaries
and privileged before/after verification. Do not expose SQL or connection details
to the builder or protected worker.

### Parent audit-fault lifecycle adapter

`audit_faults.audit_insert_failure` consumes an operator-created binding containing
`schema`, `table`, `table_oid`, `database_name`, runtime `runtime_user`/`session_user`,
operator `operator_user`/`operator_session_user`, and a `canary` mapping of column
names to bounded synthetic string/null values. Canary values must satisfy the
actual audit schema and its references; they are never written into controller
evidence. The probe emits only row counts, identity and SQLSTATE/constraint metadata.

The caller supplies two trusted functions, kept outside worker target data:

- `execute(identity, sql, timeout=15)` selects one of two fixed connections,
  `runtime` or `operator`, waits for the entire SQL command including commit or
  rollback, requires a successful process/connection outcome, and returns one JSON
  object. It must not log connection credentials, raw server diagnostics or canary
  values. A malformed/missing reply is an incomplete command, not a safe retry.
- `check(reserve_seconds)` verifies the exact trusted peer identity and active
  disposable-environment guard, with sufficient time remaining. It runs before
  every command; initial admission reserves 210 seconds, each command 20 seconds.
  The caller must bound the protected body (the broker normally allows 60 seconds).

Use a dedicated child `Attempt` when called from the broker, to avoid concurrent
writes to grader evidence. The adapter verifies runtime/operator database/table
identities, a successful baseline insertion, rejection by the exact installed
constraint under the runtime identity, exact removal, recovered insertion, and
unchanged runtime identity. It yields `audit_insert_failure_verified: true` and
`audit_constraint_canary`, the exact generated constraint name. The private fault
broker projects that bounded identifier only for a verified audit fault, allowing
protected cases to detect its appearance in application errors/logs. It never
forwards SQL, connection details, rows or arbitrary exception text. Constraint
identity remains in operator restoration metadata; it is a diagnostic canary,
not a credential. Missing markers cannot establish diagnostic leak coverage.

A durable restoration plan precedes mutation; exact constraint identity is saved
when received. Lost installation replies remain explicitly uncertain: the adapter
never guesses an OID to drop. Lost/failed removal, expired guards or failed recovery
raise `FaultRestoreError`; abort grading and dispose the environment. `finally`
handles ordinary exceptions/interruption, while process death requires the outer
lifetime guard. These contracts still require a concrete trusted application
connection/peer binding; this adapter does not discover credentials or topology.

### Secret-safe database command transport

`DatabaseTransport` implements the audit adapter's `execute` contract using a
fixed operator-owned peer prefix and exactly two libpq service aliases (`runtime`
and `operator`). It invokes trusted `psql -X` with password prompting disabled,
ON_ERROR_STOP enabled and SQL supplied through stdin. Connection credentials
belong in private service/password files on the peer; neither query values nor
connection diagnostics are copied to evidence files.

The caller's `check` must verify exact peer identity, immutable service configuration
and sandbox lifetime. Use an exact container identity or equivalently protected
peer binding, preserve stdin through every transport layer, and keep the peer and
service files outside application control. The implementation checks this scope
before execution and again before returning an observation. A Docker fixture now
exercises the entire adapter through an exact container ID and verified service
file hash; live application Kubernetes binding and Mac sbx stdin transport remain
separate integration obligations.

Commands are limited to 15 seconds, SQL to 256 KiB, and combined stdout/stderr to
64 KiB by default (at most 1 MiB when explicitly configured). Input and output are
pumped concurrently so large input or a blocked child cannot deadlock the caller.
Only successful completion with one JSON object is accepted; duplicate keys,
nonfinite numbers, malformed output, partial input and nonzero exits are refused.
Evidence retains UTC times, SQL hash, byte counts, status and elapsed time, never
raw SQL/stdout/stderr or command argv. Local process-group termination is recorded
without claiming remote query termination. Timeout or truncated evidence during
a mutation therefore remains uncertain and invokes the audit adapter's disposal
path; there are no automatic retries.

`FaultRuntime` can bind this adapter to its existing sandbox guard and broker.
Supply `audit_binding` as above, `database_peer` with exactly `prefix`, `services`
and `cwd`, and a trusted `database_peer_check(reserve_seconds)` callback. The
prefix must address the independently verified peer in that same disposable
grading environment; service files must remain outside application control.
The callback verifies the peer identity and service-file integrity. The runtime
checks both clocks, guard process, release state and revocation before and after
each peer check. These inputs are parent configuration, never worker target data.

The broker exposes the fixed `audit` role alongside configured workload roles;
that name cannot also identify a suspended workload. An audit-only runtime may
use an empty workload mapping (the constructor still takes a kubectl prefix).
It requires the audit adapter's 210-second admission reserve. Each fault owns a
separate evidence attempt and transport, and only the verified audit flag reaches
the worker. Closing or revoking the runtime prevents further database commands;
uncertain restoration aborts grading and requires disposal by the outer guard.
This wiring does not discover or establish application credential/table mappings.

For fresh redeployment, `grade_capture(..., fault_audit=resolver)` calls the
trusted `resolver(box)` only after bootstrap succeeds. It must use bounded,
operator-owned inspection to return exactly `audit_binding`, `database_peer`,
and `database_peer_check` for that fresh sandbox. Static dictionaries are refused:
old table/container identities are not a valid binding for a new deployment.
Resolver errors or missing bindings leave grading incomplete and still dispose
the sandbox. These values go only to `FaultRuntime`; the protected worker receives
its broker capability, never database connections, SQL or credential mappings.
Audit-only grading does not require a workload suspension mapping. Providing a
resolver remains an integration obligation, not evidence that its observations
are independently correct.

### Bounded audit metadata reads

`database_probe.audit_read_sql` supports privileged inspection of global
authentication events without adding a hidden application endpoint. The operator
maps each of the nine public audit fields to a scalar column or a column plus
JSON key path. The query accepts at most 32 canonical request UUIDs, compares
correlations case-insensitively, locks the relation, checks its observed OID, and
runs read-only with five-second statement and two-second lock limits.

The result contains connection identity, relation OID, a truncation flag and at
most 128 event projections (64 by default). It never returns whole rows. Supplied
known password/token/text canaries are checked against both the row's JSON text
and projected metadata. A matching row returns only `forbidden_text_present`;
metadata fields larger than 256 bytes return only `metadata_oversized`. This
redaction is for known strings in those representations, not a universal detector
for arbitrary encodings or secrets the operator has not supplied.

Use `DatabaseTransport` so neither SQL containing canaries nor raw observations
are copied into logs. Native database timestamp spellings are retained; an oracle
must interpret the mapped type rather than require an API wire representation in
storage. Truncation, unsupported schema mappings, unavailable identity and query
failure cannot establish a passing audit criterion. The reader supplies
observations only: the caller must establish the actual application/table/role
binding and compare events with independently observed HTTP actions. It does not
prove runtime append-only privileges, inspect general logs, or grant acceptance.

`AuditBroker` provides a separate private Unix-socket capability for these
read-only observations. `read_audit(configuration, correlations, forbidden_values)`
can submit bounded request UUIDs and known text controls, never SQL, relation
names, connection aliases or commands. The parent supplies a guarded, bounded
reader callback and verifies its database/table identity before returning data.
The broker strips connection metadata and extra callback fields; only bounded
audit fields, redaction flags and the truncation flag reach the worker.

The socket is owner-only inside a private directory and requires a random token.
Messages are capped at 64 KiB; duplicate JSON keys, invalid UUIDs, oversized text
controls and exhausted request budgets are refused. Callback exceptions return
only an inconclusive status; requests, canaries and exception text are not logged.
Revocation suppresses in-flight replies, and unfinished callback cleanup raises
an explicit observation error. Callbacks must enforce their own execution bounds
and sandbox/peer lifetime checks: a socket timeout does not terminate a remote
database command. Grader injection and live application binding remain separate
integration steps; this capability alone grants no audit acceptance.

### Fixed HTTP relay for isolated browsers

`http_relay.RelayServer` is a transport primitive for a browser container with no
network interface except loopback. A loopback relay can connect through a private
Unix socket to a separate trusted relay whose TCP destination is fixed by the
operator. Sharing that socket between Linux containers through a private Docker
volume avoids exposing host networking to the browser. Container orchestration,
peer identity binding and lifetime guards remain separate integration obligations.

The operator provides a numeric upstream IP/port or private socket path and the
exact loopback browser authority. Requests cannot select a destination: absolute
URLs, CONNECT, mismatched/duplicate Host and ambiguous framing are refused. The
logical Host/Origin stay unchanged, allowing the browser's loopback port to match
the application's configured origin. Redirects are returned without following them.
Repeated Set-Cookie headers and opaque multipart/binary bytes are preserved.

Requests have a total deadline (30 seconds by default, at most 60), including
header/body reads, queuing, upstream I/O and delivery. Four requests run at once;
default body bounds are 8 MiB input and 128 MiB output. Responses stream in bounded
chunks rather than buffering full downloads. Normal chunked framing is supported;
chunk extensions/trailers and protocol upgrades are currently unsupported. A
long-lived stream is still subject to the total request deadline. Bounds and
unsupported features must produce an **inconclusive transport result**, never an
application failure or acceptance claim. A caller must inspect relay observations
in addition to a browser verdict before accepting any case.

No paths, headers, cookies, bodies or exception text are logged. Observations are
fixed counters only. The `check` callback must verify the operator-owned peer and
active guard with bounded work; it runs before connection and during delivery.
Closing the server revokes in-flight sockets and waits boundedly for handlers;
uncertain cleanup raises an error. This does not replace an independent container
lifetime guard or establish networking isolation without live topology probes.

Focused transport fixtures:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_http_relay.py -v
```

### Browser case execution boundary

Suite cases may declare `browser` as `page`, `page_request`, `browser`, or
`browser_request`, selecting the protected journey's invocation signature. These
cases route exclusively through an operator-provided `run_suite`
`browser_executor`; the ordinary host worker refuses them. A missing executor
is inconclusive. Browser cases cannot receive host audit, fault, job or staging capabilities.

The executor receives `(attempt, suite, case, target, timeout_seconds=...)` and
must enforce that total budget independently, including preparation and cleanup.
It owns container isolation, pinned browser provisioning, peer identity checks,
both relay hops, deadline/parent-death guards and resource cleanup. This callback
interface does not itself provide those controls; the Docker executor below
implements them for the tested Linux topology. Fresh-deployment resolution is described below. Boundary tests use synthetic callbacks; separate live executor
preflights exercise the Docker topology.

Results require the matching `case_id`, a recognized `verdict`, exact true
`guard_verified` and `cleanup_verified`, and `transport` counters for both
`browser` and `upstream` hops. Each hop must have completed requests and no errors,
refusals, limits or disconnects. Transport uncertainty overrides either pass or
fail with inconclusive; this conservative rule may reject harmless disconnects.
Uncertain lifetime, restoration or malformed result identity aborts the suite.
Existing shared-state declarations still stop later cases after any non-pass.
Only fixed reasons reach the case record; arbitrary executor observations and
exception text are discarded. No new browser acceptance coverage is declared.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_browser.py -v
```

`evaluation.browser_worker` now provides the container-side journey adapter. It
checks the manifest and all source hashes before import, dispatches the four
signatures, and accepts `None` or a dictionary of journey observations (discarded
from results). Local protected `BrowserFixtureUnavailable` signals are
inconclusive; `BrowserRestorationError` aborts the suite. Assertion messages,
observations and exception text are not retained. Browser/context/relay cleanup
failures cannot pass. Playwright infrastructure errors currently stay inconclusive.

The worker requires a nonroot process, zero effective capabilities, no-new-privileges
and only the loopback network interface. It starts a fixed loopback-to-Unix relay,
requires an exact `http://127.0.0.1:PORT` origin, launches Chromium with its sandbox
enabled and returns that hop's counters. It does not certify container identity,
readonly mounts, the upstream hop or parent-death containment; those remain the
parent executor's responsibility. It cannot forcibly bound Playwright or cleanup
calls, so a separately enforced container lifetime is mandatory.

Container-side invocation (paths are private operator mounts):

```sh
python3 -m evaluation.browser_worker \
  --suite /protected --manifest-sha256 "$SUITE_DIGEST" --case content \
  --target /input/target.json --socket /channel/app.sock \
  --wall-deadline "$CASE_WALL_DEADLINE" --result /output/worker.json
```

Focused worker fixtures:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_browser_worker.py -v
```

### Independent browser resource cleanup

`browser_guard.BrowserGuard` reserves exact random names for the browser, relay
and private socket volume, then arms a separate-session watchdog before creation.
Callers attach its `factory.browser` nonce label to each resource. After each
create command exits and identity inspection succeeds, `settled(role,
created=True, identity=...)` records the container ID or volume creation time.
Known unattempted/failed creations can be recorded with `created=False`; a timeout
is never a settled creation. No unrelated resource names are accepted.

The watchdog acts on owner exit, bounded wall/monotonic lifetime, clock
discontinuity or explicit release. It verifies ownership and recorded identity
before deletion, removes containers by immutable ID, and independently lists
resources afterward. Name collisions, replaced identities, daemon failure and
unsettled creation cannot establish cleanup. A matching resource with no creation
receipt is removed as a precaution, but the result stays incomplete because a
late create cannot be ruled out. The private config, creation receipts and command
evidence form the recovery record. Volume removal is by name after ownership and
creation-time checks; Docker has no immutable volume ID for that operation.

`check()` rejects exited, expired, released or triggered guards. `release()` waits
for actual cleanup evidence, not just successful delivery of the release request.
Each Docker command is bounded to 10 seconds; cleanup can take up to 120 seconds
for three resources, and this reserve must be included within the parent grading
budget. The caller must also impose an internal container timeout and integrate
guard checks with browser/peer execution. This process cannot enforce a deadline
while its host or Docker daemon is unavailable, and does not establish reboot
containment. The Docker executor below connects this lifecycle to `run_suite`.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_browser_guard.py -v
```

### Guarded Docker browser executor

`browser_runtime.BrowserExecutor` is the `run_suite` callback for the isolated
worker. Supply an immutable browser image ID, seccomp file/hash, immutable relay
network ID, numeric peer IP/port, and a trusted bounded `peer_check` callback. No
image pull/build, host networking, Docker socket mount, or application command is
performed by this adapter. The operator must provision the pinned browser image
and resolve the peer from the fresh deployment through the binding below.
Actual application-specific discovery and Mac transport remain unverified. Current live evidence is Linux nested Docker with a synthetic app.

Each case snapshots hashed suite files and controller modules into private
readonly mounts, gives only the browser its synthetic target and protected cases,
and gives only the trusted relay a fixed TCP destination. Docker creates each
container without starting it; the parent verifies the immutable ID, ownership,
image, nonroot user, dropped capabilities, seccomp, no-new-privileges, readonly
root, resource bounds, private IPC, network and exact mounts before starting code.
Container logging is disabled; worker evidence is structured and redacted.
Temporary target inputs are removed in finally. Directory/file permissions permit
the unprivileged container to read its specific mounts while the containing
attempt remains private. Mac file-sharing behavior is not yet verified.

The parent checks peer identity and the independent resource guard before
renewing a two-second relay lease, normally every 250 ms. The relay checks this
lease before connecting and during delivery; expiration or invalid identity
closes the transport. This allows up to the lease interval before peer-check
failure revokes traffic; it is not instantaneous endpoint authentication.
`peer_check` must bound its own calls and verify the outer grading sandbox guard.
It is trusted operator code and receives no browser-selected commands.

The executor imposes an internal container timeout and reserves 130 seconds of
each supplied case budget for watchdog cleanup and join overhead; it refuses
to start with 135 seconds or less. That reserve stays inside the caller's budget,
not an extension of the proposed 90-minute grading ceiling. A completed browser
worker must also have a clean upstream relay shutdown, live peer/guard checks,
error-free counters from both hops and verified resource cleanup. Setup failures,
worker timeout or lost peer checks cannot pass; uncertainty aborts following
cases through the browser result boundary. The protected suite remains
unapproved and browser journey registration is still incomplete.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_browser_runtime.py -v
```

### Post-bootstrap browser binding

`grade_capture(..., browser_resolver=...)` invokes that trusted callback with the
fresh grading sandbox only after successful bootstrap. It must return exactly
`image`, `seccomp`, `seccomp_sha256`, `network`, `peer_host`, `peer_port`,
`peer_check`, and `fixtures`. The first six configure `BrowserExecutor`;
`peer_check(allowance_seconds)` verifies the peer with its supplied one-second
budget. `fixtures` maps protected case IDs to JSON-compatible fixture values and
semantic control labels. Keep this resolver operator-owned; application output
must not become executable configuration or a browser-selected endpoint.

`BrowserBinding` copies those fixtures and combines only the selected case's
values with the common target. Fixtures cannot replace `base_url` or introduce
host fault/audit/job/staging capabilities. The URL must remain the loopback endpoint fixed
by `grade_capture`. The binding checks owner process identity, sandbox stop state,
outer watchdog liveness/release/result, revocation and both grading deadlines
before and after peer verification and case execution. Per-case preparation and
cleanup stay within the remaining grading budget. Missing fixtures or insufficient
budget are inconclusive preconditions before browser creation.

The binding is revoked before outer sandbox cleanup, including grading failure.
Unit tests verify resolution and teardown ordering and guard/precondition failures;
they do not establish actual Kubernetes endpoint/fixture discovery, Mac Docker
file-sharing/transport, or application acceptance. Those remain preflight work.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_browser_binding.py -v
uv run --locked python -m unittest discover -s tests -p test_evaluation_deployment.py -v
```

The fault broker projects `workload_suspended_verified: true` only after the
runtime has verified the selected workload's unchanged UID and convergence to
zero replicas. This receipt is distinct from `service_outage_verified`: suspension
alone does not prove a particular network/service failure. Workload identities,
Pod details and command data remain private to the parent. Worker queue/restart
oracles must require this receipt before relying on a stopped-worker precondition.

A broker may additionally register parent-owned `restart_actions` keyed by an
exact `(held_role, restart_role)` pair. `remote_fault_session` retains the outer
fault and allows one restart of a distinct reviewed role, followed by verified
outer restoration. The callback must bound its operations, enforce the grading
lifetime and verify both restart completion and continued outer fault. Only the
literal `workload_restarted_verified` and `held_fault_verified` receipts cross the
protocol; callback diagnostics and commands do not. Unknown actions, incomplete
receipts, connection loss or restoration failures abort control. Ordinary
`remote_fault` callers keep their existing observation interface.

`FaultRuntime(storage_worker_restart=True)` opts into the single reviewed
storage-held/worker-restart pair. It requires distinct exact workload identities
and an independent storage service probe. The runtime checks storage UID,
zero-replica convergence and service unavailability before and after a verified
worker suspend/restore cycle. Each component keeps separate restoration evidence;
uncertain outer or inner state aborts the broker. Compound configuration reserves
additional time for both contexts and observation/restoration commands.

`grade_capture(fault_storage_worker_restart=True)` explicitly opts into this
capability. It requires callable trusted `fault_workloads` and
`fault_service_probes` resolvers, evaluated only after fresh bootstrap. Static
compound mappings and malformed selection are rejected before sandbox creation.
The capability stays parent-owned and is closed before the outer sandbox guard.
The default is false, preserving ordinary single-fault setup.

Fixture unit checks do not establish live Kubernetes, interrupted lease
reclamation or storage retry evidence. Scoped live preflight remains required
before protected worker/storage journeys can rely on this capability.

`JobBroker` supplies a private read-only boundary for independently normalized job
observations. `read_job` accepts only a canonical export UUID. A parent-owned
reader returns export status, durable processing-attempt count, active lease and
a fixed SHA-256 lease fingerprint, physical published-artifact count and successful
completion-event count. Credentials, schema/SQL, lease owner/token and arbitrary
callback fields do not cross the socket. Missing observations stay inconclusive;
counts above application limits remain data so protected oracles can fail them.

The reader must independently bind live database/object-store peers and enforce
guard lifetime and bounded operations. Status from the public application API is
insufficient to establish a claimed lease; database metadata alone cannot prove
physical artifact cardinality. Suite cases explicitly declare boolean `reads_jobs`
to receive the parent-owned broker configuration through `run_suite(job_broker=...)`.
Supplied common-target capabilities are stripped; undeclared and browser cases
receive none. An unsettled job reader makes the case inconclusive and aborts
later cases. Browser fixture bindings also reject job capability injection.
Actual readers and a publication barrier remain unimplemented. No lease-recovery or artifact-uniqueness evidence is claimed.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_job_broker.py -v
```

The lease fingerprint identifies the retained owner/token pair even when its
expiry has passed. An inactive lease with the same fingerprint is an expired
claim, not proof that the application processed its abandonment. `None` means
no complete owner/token pair remains. Trusted adapters must preserve this
meaning; expiry alone must not erase the fingerprint. This allows an oracle to
separate timestamp expiry from explicit claim clearing without disclosing lease
material. Active lease observations still require a fingerprint.

### Guarded job observation callbacks

`job_runtime.JobRuntime` brackets durable database reads and independent physical
object enumeration with both peer checks and the outer sandbox guard, owner
identity, revocation and two grading clocks. It reserves 40 seconds before each
observation, supplies a 15-second timeout to each reader and a one-second timeout
to each peer check, and suppresses results if guard or peer verification fails.
Database-provided artifact counts are ignored. Malformed durable observations
prevent enumeration; malformed physical counts stay inconclusive. Evidence records
only operation/outcome and exception type, excluding export identity and lease data.

These are trusted operator callbacks, each required to enforce its supplied
timeout; this wrapper cannot interrupt a callback that violates that contract.
An unsettled callback therefore aborts suite execution and makes cleanup uncertain.
The database reader must verify actual relation/database identities and normalize
durable lease, attempt and completion-event fields; the object enumerator must
verify its physical storage scope independently. Neither discovery nor concrete
readers are supplied here. Sequential reads do not establish an atomic snapshot
across the database and object store. Protected race oracles still require a
reviewed barrier or convergence procedure. This runtime does not establish application lease/retry evidence.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_job_runtime.py -v
```


`grade_capture(..., job_observer=...)` invokes a trusted operator resolver only
following successful fresh bootstrap. Its exact result contains four callbacks:
`database_read`, `artifact_count`, `database_peer_check`, `storage_peer_check`.
Static, incomplete or noncallable selections are rejected. Both grading deadlines
and the outer guard bind the resulting `JobRuntime`; only its broker is passed to
`run_suite`. Readers and peer configuration stay parent-side. The capability
closes before the outer guard is released, including later resolver failures.
A close failure prevents acceptance while sandbox cleanup still proceeds.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_deployment.py -v
```

### Durable PostgreSQL job adapter

`job_database.JobDatabaseReader` supplies the database callback for a reviewed
operator mapping of one job-state relation and one audit relation. Each mapped
field selects a physical column or bounded JSON-object path. Bindings include
observed relation OIDs, database name and both operator role identities. Reads
lock both relations, verify their OIDs and use a read-only transaction with a
five-second statement timeout and two-second lock timeout. Missing, duplicate
or mismatched job observations stay inconclusive. Opaque owner/token material is
hashed inside PostgreSQL and never returned; lease activity requires an owner,
token and future timestamp. Successful `export.ready` audit events are counted
from the independently mapped audit relation in the same statement snapshot.

The operator must verify that the mapped attempt counter counts all processing
attempts durably and that owner/token/expiry fields represent actual claiming.
This adapter supports that lease-expiration representation; other queue/storage
layouts require reviewed adapters. It does not impose table or column names on
the application, discover relations, enumerate S3 objects or establish abandoned
lease recovery. Supply an independently guarded `DatabaseTransport` as its client.
The physical object count still comes from the separate storage callback.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_job_database.py -v
```

### Independent physical artifact enumeration

`job_storage.S3ListTransport` invokes a trusted AWS CLI prefix bound by the
operator to an independently verified storage endpoint and immutable private
config/credential files. Secrets must stay out of that prefix. A hard subprocess
deadline, combined output limit, single CLI attempt and fixed page size bound the
read. Raw keys, continuation tokens, command arguments and diagnostics are not
recorded; only UTC times, byte counts, exit status and outcome enter evidence.
Peer/lifetime checks bracket the command. Provisioning the CLI is separate.

`S3ArtifactCounter` enumerates current physical objects over bounded pages and a
single total deadline. It verifies bucket/prefix, page counts, unique keys and
continuation progress; truncation beyond the page allowance is inconclusive.
Two physical keys remain observable as two artifacts. The trusted export-prefix
resolver must derive its scope independently of application artifact rows and
include only that export's published artifacts. Staging, evidence and unrelated
objects need separate scopes. Unsupported layouts require reviewed adapters.
This does not inspect object version history, prove private access/orphan cleanup,
or establish an atomic snapshot while publication is in progress. Barrier or
convergence checks and live storage transport evidence remain required.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_job_storage.py -v
```

### Ordered job staging protocol

`staging_broker.StagingBroker` supplies a separate private capability for an
operator-reviewed worker-to-storage staging sequence. Its trusted factory owns
all phases and partial-failure restoration. It initially verifies worker suspension
and API availability so the protected grader can enqueue and approve work safely.
The single allowed `handoff()` must suspend/verify storage before restoring the
worker. The grader may then request one worker restart while storage stays held.
Only literal verified receipts cross the socket; identities, commands and other
callback data stay parent-side. Unknown, repeated or out-of-order actions abort.

`remote_staging` restores on body failure and client disconnect. `session.verify()`
requires the parent to independently recheck the current phase. Long observations
must request these verifications within the bounded idle window; verification
cannot extend the outer deployment deadlines. Restoration failure is fatal.
The protocol avoids nesting a second fault socket while the first is held.
The concrete staging runtime and scoped grants are described below; receipt
callbacks alone do not establish a publication barrier or lease recovery.
Actual parent-death containment still belongs to the outer sandbox watchdog.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_staging_broker.py -v
```

### Verified worker-to-storage handoff runtime

`staging_runtime.StagingRuntime` attaches to an explicitly compound-enabled
`FaultRuntime` with distinct operator-observed API, worker and storage workloads
and independent API/storage service probes. It captures ready API/worker replica
counts, suspends the worker and checks its zero-replica convergence while the API
remains ready and reachable. The grader must successfully enqueue and approve
work in that phase; connectivity alone does not prove authenticated API success.

Handoff rechecks that phase, enters an owned storage suspension context and
verifies its outage before closing the worker context. It then independently
checks storage remains suspended/unreachable and the original worker replicas
are ready. A single optional restart uses the verified storage-held restart
runtime and checks the held state again. Current-phase verification observes
live state rather than returning cached receipts. Binding changes, UID replacement,
guard loss, revocation and either expired clock refuse further actions.

Separate context stacks restore storage before worker on partial handoff failure;
a successful handoff leaves only storage to restore at session end. The staging
capability must close before its parent fault runtime, permitting owned restoration
under the still-active guard after new staging authority is revoked. Different
broker threads cannot concurrently mutate the deployment: `FaultRuntime` now
uses a nonblocking, reentrant mutation lock for its entire fault context.

The initial conservative reserve is 4800 seconds with the standard service-probed
compound configuration. It consumes the existing grading allowance and does not
increase the proposed grading limit. Fresh-deployment staging is opt-in as described
below. Fixture controls do not establish live Kubernetes, actual job claiming, lease recovery or a frozen acceptance suite.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_staging_runtime.py -v
```

Cases declare boolean `stages_jobs`, `mutates_runtime` and `reads_jobs` together
to receive `_staging_control` through `run_suite(staging_broker=..., job_broker=...)`.
They receive the staging and job capabilities, rather than the general fault
capability. Common-target injections are stripped. Browser manifests and fixture
bindings forbid staging capabilities. Missing staging/job capabilities abort
before launching a child; an unsettled or aborted staging broker prevents later
cases. Independent job-reader settlement remains required as well.

`grade_capture(..., job_staging=True)` requires trusted post-bootstrap workload,
service-probe and job-observation resolvers. It enables the parent compound fault
runtime, binds job observations, then attaches staging. Static selections are
rejected before sandbox creation; the default is false. The staging capability
closes before job observations and the parent fault runtime, including preparation
failures. Cleanup failures prevent acceptance while sandbox termination proceeds.
No protected lease/retry case is declared complete by this wiring.


Staged restart receipts include a parent-monotonic `restart_window` with finite
`earliest` and `latest` bounds. The first precedes the owned worker restart; the
second follows verified restoration and precedes subsequent storage verification.
Ordinary fault receipts continue to expose only their boolean fields. Host-side
grading workers share the controller's monotonic clock domain; this receipt is
not granted to browser/container graders. To prove recovery within 60 seconds,
a completed independent observation by `earliest + 60` is sufficient. To prove
failure, an observation beginning after `latest + 60` must still show the
abandoned lease unreclaimed. Intermediate observations remain ambiguous. Receipt
arrival time must not start a fresh application recovery allowance.


`read_lease` uses the same private job capability but selects a separate durable
reader. It returns job status, attempts, lease metadata and completion-event count;
there is no `published_artifacts` field. `JobRuntime` checks only the database peer
and lifetime for this mode, so deliberately suspended storage does not prevent
lease observations. Its 25-second control reserve and 15-second database timeout
remain bounded. Combined `read_job` still requires the independent physical
storage read and refuses unavailable storage. Missing durable callbacks cannot
fall back to the combined reader, and both modes share one request budget.
Physical cardinality must be checked after storage restoration; a missing count
must never be interpreted as zero. These modes do not establish job recovery by
themselves.

`session.restart_worker(export_id)` optionally requests a canonical export UUID
observation while the worker is verified suspended and before restoration. Fresh
deployment binds the same `JobRuntime` to staging; a foreign sandbox/guard is
rejected. The parent uses only the durable database reader during the storage
hold. Its fixed `paused_job` projection contains no artifact count, credentials
or SQL. Reader failure restores owned contexts and aborts. The ordinary no-ID
restart remains available for lifecycle transport preflights.

The reclaim oracle must use this paused snapshot's lease fingerprint and confirm
an active processed lease. A job that finished or expired before suspension does
not establish an interrupted-lease precondition, even if an earlier poll saw it
running. Such attempts remain inconclusive. Observing and timing actual recovery
still requires independent post-restart reads and the parent restart bounds.


The parent rechecks zero worker replicas and the unchanged suspension generation
after the paused database query, and reverifies the held storage state before
restoring the worker. Changed holds suppress the receipt. A bound paused reader
adds 475 seconds of conservative command/read reserve, making the initial standard
staging reserve 5275 seconds. This consumes the existing grading allowance; it
requires scheduling review and does not authorize increasing the proposed limit.

The trusted workload probe offers separate `ready` (default) and `running`
convergence modes. Running requires the observed generation and exact Pod count,
no terminating Pods, Pod phase Running, and a running state with a start timestamp
for every declared regular container and restartable init sidecar. Missing,
duplicated, replaced, waiting or terminated container observations do not count.
Dependency readiness and startup-probe success are distinct from process running.
Only boolean running/readiness projections leave the probe; raw container
configuration and diagnostics remain excluded.

`workload_operation(..., convergence='running')` lets a reviewed parent lifecycle
wait for processes during an intentional dependency outage. Ordinary calls retain
ready convergence. Owned compound worker lifetimes use running convergence while storage is held;
ordinary restoration requires readiness. These process observations do not alone
establish queue progress, continuous uptime or APP-009 retry timing. The same command deadlines and UID/replica conditional writes
apply to either mode.

Staging begins with ready workers. When the parent owns a verified storage hold,
worker baseline/restart restoration uses process-running convergence; the fixed
wire protocol does not let a case select this policy. Restoration evaluates the
parent's current hold at cleanup time, so partial handoff cleanup that restores
storage first requires ready worker restoration. After storage cleanup, staging
also waits for worker readiness using an unchanged UID/replica conditional
operation. Failed readiness recovery suppresses the restored receipt and aborts
later grading. Additional checks reserve 300 seconds of the existing allowance:
standard initial staging reserve is 4800 seconds, or 5275 with the bound paused
reader. The grading deadline is unchanged and scheduling remains unresolved.

Workload Pod projections include an opaque `process_fingerprint` when running
container-instance metadata is complete. It hashes declared container names,
container IDs, restart counts and running start timestamps, including restartable
init sidecars. Replaced containers, changed start timestamps or restart counts
change the fingerprint. Raw container IDs and configuration are excluded; missing
or invalid metadata yields no fingerprint rather than invented continuity.
A parent continuity observer must also compare Pod UIDs and the exact Pod set.
These are identity observations, not a bound running-service clock by themselves.
No retry oracle should substitute sampled HTTP health or raw wall time for that
clock, or count preclaim latency as proven storage-retry duration.

`running_clock.RunningClock` supplies a parent-only continuity primitive for exact
API/worker workloads. Trusted callbacks bracket bounded workload reads with the
outer guard, owner and immutable grading deadlines. Each sample requires running
Pods, unique Pod identities and complete instance fingerprints; it rejects changed
workload generations, Pod sets, container instances or restart counts. Failure or
explicit invalidation permanently refuses subsequent samples. Only fixed numeric
`minimum`/`maximum` seconds are returned.

The lower bound uses the intersection between the first completed role observations
and the current role-observation starts. The upper bound covers the interval from
an independently bracketed earliest possible handoff through the final clock read.
This assumes the reviewed operator envelope excludes external process/container
pauses. Kubernetes container continuity does not prove internal subprocess identity,
CPU scheduling or useful queue progress; worker-command semantics need independent
binding. Retry-start uncertainty is separate from process duration. The private staging protocol now attaches this primitive to explicit timing
requests; the protected retry draft still needs its API wrapper and live controls.

`session.observe_running()` is available after verified storage/worker handoff.
The parent brackets fresh API/worker process observations with current hold checks
and returns only finite, nonnegative, ordered `minimum`/`maximum` duration bounds.
Changed hold generations suppress receipts; process continuity or guard loss
invalidates the clock. The possible-start anchor precedes owned worker restoration;
verified lower duration begins only after the first complete role observations.
Unknown container metadata is inconclusive. Client receipts reject extra fields.

Timing and worker restart are mutually exclusive within a staging session, enforced
by both the client and parent before mutation. Verification/restoration remain
available in either procedure. Timing requests use existing guarded command reserves
and immutable deadlines; they do not increase the initial staging reserve or total
grading limit. Extra observations consume that allowance, so scheduling still needs
review. No continuous application uptime or APP-009 retry acceptance is claimed
from protocol/fixture controls alone.


### Private password-storage observations

`password_database.PasswordDatabaseReader` reads only an independently selected
scope of known account identities from an operator-mapped PostgreSQL account
relation (APP-002; AC-004). Supply a guarded `DatabaseTransport`, observed relation
OID, database/operator role identities and mappings for `identity`/`encoded_hash`;
scalar columns and fixed JSON object paths are supported. The read holds a table
lock through identity checks and commit, uses a fixed catalog search path and
bounded read-only transaction, and refuses missing, duplicate, truncated,
oversized or mismatched observations. Unsupported physical layouts need a
reviewed adapter; the application is not required to use these column names.

The return value contains credential encodings for private operator inspection.
Never log it, pass it to a grader child/socket, or serialize it as evidence.
`DatabaseTransport` logs command metadata and SQL digest, not SQL, observations
or connection diagnostics. Independently bind the actual account semantics and
captured dependency/default-cost profile before cryptographic inspection. This
reader does not verify passwords, discover a schema, enforce hashing policy or
establish salt uniqueness outside the supplied account scope. It is not wired to
an acceptance case or deployment resolver.

Run its focused fixture checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_password_database.py -v
```


### Private known-canary scanning

`secret_scan.scan_secret_chunks` inspects one private byte stream for operator-known
canaries (APP-007; AC-018). It detects literal UTF-8 and selected JSON, URL, HTML,
base64 and hexadecimal representations, including matches split across chunks.
Keep each source separate. It returns only a presence flag, completeness flag,
byte count and fixed outcome code; neither chunks nor matched values are logged.

A presence flag remains conclusive even if later input is truncated or fails.
Absence requires `complete=True`; byte/chunk limits, malformed input and source
errors never establish absence. Default limits are 8 MiB and 65,536 chunks per
stream. The caller must enforce source/time bounds and cleanup; the scanner
cannot interrupt an iterator blocked on a read. Bound independently observed Pod
and container identities, source inventory, current/previous log selection and
collection interval before assigning an application verdict. An empty stream is
not proof that a required source was collected. Arbitrary encoding, encryption,
partial-secret detection and complete application log history are not guaranteed.
No deployment resolver or acceptance case is wired to this helper.

For trusted operator-side binary values, pass `binary_values=[known_bytes]` to
`scan_secret_chunks`. Text values may be omitted or combined with binary values.
Exact bytes (including NUL/non-UTF-8) and selected base64/hex forms are inspected
across chunk boundaries. At most four binary values of 8–65,536 bytes are allowed,
with a total of at most 131,072 bytes. Unsupported scopes raise a fixed validation
error; the caller must treat unavailable coverage as inconclusive. This adds no
worker capability or source/history attestation. Arbitrary enclosing encodings
and reconstructed archive representations remain outside the scanner guarantee.

Run its focused fixture checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_secret_scan.py -v
```


### Private Kubernetes log snapshots

`log_transport.LogTransport` requests fixed read-only `kubectl logs` snapshots for
one operator-bound Pod/container source. The source contains namespace, Pod name,
observed Pod UID, container name/ID and explicit current/previous selection.
Supply a trusted pinned client prefix and `check(source, reserve)` that returns
exactly `True` only after independently verifying those identities and the active
grading guard/deadline. Credentials belong in private client configuration files,
never prefix arguments. Current sources require the selected current container ID;
previous sources require its independently observed terminated container ID.

The adapter reads the complete available snapshot (`--tail=-1`) with
`--timestamps=false` to preserve payload bytes across line boundaries. Added
timestamp prefixes can otherwise conceal multiline text or raw binary canaries.
Collection UTC times are recorded separately; log timestamps are not used to
prove history or source coverage.

The client has a 15-second default/30-second maximum bound and the scanner's byte
ceiling. It privately scans application logs from client stdout; client stderr is
bounded, discarded connection diagnostics. Kubernetes merges application stdout
and stderr into that log stream. It writes only byte counts, source/client hashes,
fixed outcomes, identity-check flags and sanitized scanner receipts. It terminates
and verifies absence of its local client process group; it does not mutate Pods.

Both identity checks must succeed for a source verdict. A matching canary remains
visible in the receipt if later collection/source checks fail, but lost source
identity makes the transport outcome incomplete. A correctly bound positive match
can be reported despite later collection truncation/failure. Clean output requires
complete EOF, successful client exit, retained source/guard identity and verified
client cleanup. An unavailable previous instance, log rotation, removed Pod or
missing source coverage cannot be silently replaced by a clean current snapshot.
This adapter does not discover or prove complete application log inventory/history;
no deployment resolver, capability socket or acceptance case is wired to it.

Known binary values can be supplied privately as
`transport(binary_values=[known_bytes], timeout=...)`, alone or with text canaries.
The same fixed source, output/time bounds and before/after identity checks apply;
raw bytes and encoded representations are discarded. Unsupported binary scopes
are refused before starting a client. This does not establish complete inventory
or historical log coverage.

Run its focused lifecycle checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_log_transport.py -v
```


### Available Kubernetes log inventory

`log_inventory.available_log_inventory(namespace, pods, binding=...)` privately
parses a complete unfiltered `PodList` and exact operator-bound namespace name/UID.
It includes regular, init, restartable sidecar and ephemeral container sources,
including available current and previous container IDs. Missing or ambiguous
status, pagination, duplicate identities and unsupported bounds are unavailable.
A known never-started waiting container has no log source; waiting after a restart
is refused because its current identity may be stale.

The result contains private source bindings, the list resource version, a stable
identity/restart-count fingerprint and `restart_history_gap`. More than one restart
sets that flag because a snapshot cannot recover all earlier container logs.
A false flag or unchanged fingerprint does not prove absence of deleted Pods,
transient replacements, log rotation or lost intervals. The caller still owns
trusted API/client binding, unfiltered namespace scope, bounded collection and
continuous inventory/history evidence. This parser is not a full-history verifier
or a deployment resolver. Private identities and raw Pod fields must not enter
public evidence; unsupported inventory must remain inconclusive.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_log_inventory.py -v
```


### Private Pod watch windows

`pod_watch.PodWatchTransport` requests one bounded unfiltered raw Pod watch from
an operator-bound namespace UID and an opaque resource-version anchor. The
trusted prefix must use private credential configuration. Query values are
escaped; workers select neither namespace nor selectors. `consume(event)` gets
private validated Pod/bookmark objects and must enforce its own processing bound.
`check(binding, reserve)` independently checks API/namespace identity, owner,
sandbox and original deadlines before and after collection.

Malformed/duplicate-key/nonfinite JSON, truncated frames, watch/API errors
(including expired anchors), scope mismatch, output/event limits, timeout,
callback failure or lost identity make the window incomplete. Raw objects and
client diagnostics are discarded; evidence contains counts, hashes, fixed
outcomes/error types and cleanup flags. Client groups are terminated and verified.
A normal `watch_window_closed` is not full-history evidence: continuous resumption,
fences, deleted-container log retention, rotation and owner-death containment
still need independent implementation and validation. No deployment observer or
acceptance case is wired to this transport yet.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_pod_watch.py -v
```


### Private watch resumption cursor

`watch_cursor.PodWatchCursor(binding, resource_version)` starts from an
independently verified complete PodList anchor. `begin()` returns a private
resource version and fresh window ID. Use those for the next `PodWatchTransport`
constructor and its `window_id` argument; feed every event through `accept()`.
`finish(receipt)` commits only the matching successful window with exact event
count, namespace/anchor hashes, identity checks and verified client cleanup.
A quiet window preserves its existing anchor; bookmarks advance it without
numeric ordering assumptions. Kubernetes' unanchored special version `0` is
refused. Raw versions/events never appear in commit summaries.

Incomplete/foreign/replayed windows, missed consumer events, malformed data,
overlapping windows, late events, bounds and abandonment permanently invalidate
the cursor. Call `abandon()` if a transport invocation fails before returning a
receipt; never silently relist or reset the cursor to hide a gap. Cursor access
requires its original parent PID. At most 4,096 windows are allowed. This manages
resumption state, not a time fence or complete log-history attestation; deleted
and rotated log retention and owner-death handling remain separate work.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_watch_cursor.py -v
```


### Private CRI log decoding

`cri_log.decode_cri_log(chunks, max_bytes=...)` reconstructs private payload bytes
from bounded Kubernetes CRI log files. It strips record headers, joins `P`
fragments without inserting bytes, and restores the newline at each `F` record.
Stdout and stderr stay separate; binary bytes and carriage returns are preserved.
Malformed timestamps/headers, unfinished fragments, truncated final records,
reader errors and size/count limits refuse a result. Defaults bound input to
8 MiB, with at most 65,536 records/chunks and 1 MiB per record; the configurable
input ceiling is 64 MiB. Returned streams contain private raw bytes: do not save
them in evidence or expose them to builder mounts.

The operator must independently bind node files to the exact Pod/container and
verify reads, cleanup, rotation and collection continuity. Parsing a supplied
file through EOF does not establish full log history or an acceptance verdict.
This decoder is a building block for private node collection, not a collector.
`decode_cri_prefix(...)` returns validated payload prefixes plus `complete`;
malformed/truncated/unfinished tails and reader failures retain earlier payloads
with `complete=False`. It supports positive detection after a later error and
cannot establish absence. The strict decoder still refuses incomplete results.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_cri_log.py -v
```


### Private in-memory CRI retention

`log_retention.PrivateCRIRetention(binding, max_bytes=...)` retains private raw
CRI bytes for later canary requests, including after the original files or Pods
are deleted. A trusted collector calls `open(source, file_identity)`, then
`append(source, file_identity, offset, data)` at exact contiguous offsets.
File identities contain an independently verified `node_uid`, `device` and
`inode`. At rotation, call `rotate(source, old_file, new_file, final_size=...)`
only after reading the old file through its independently verified final size.
`seal(...)` closes a collected source when its final size is verified. Rotation
requires the same node/device, a fresh inode and a complete CRI record boundary;
`P` fragments can continue in the next generation. Current/previous selectors
refer to the same immutable container's bytes; distinct containers and streams
are never joined.

Skipped/overlapping offsets, reused identities, foreign sources, late writes,
bounds and `abandon()` permanently invalidate further collection. Already
retained valid payloads remain inspectable, including before a malformed tail.
`inspect(values, binary_values=...)` returns fixed counts and a canary-presence
flag, with `history_complete=False` in every result. A positive may be failure
evidence when its source was independently bound; absence never authorizes a
pass. This class does not collect files, discover unseen rotations, verify
collector identity or establish watch/time fences or full source coverage.

The aggregate raw-byte default is 8 MiB, configurable up to 64 MiB. At most 128
immutable sources, 512 file identities and 65,536 collection operations are
allowed. State belongs to its original parent PID and stays in memory; `close()`
releases references without claiming secure memory erasure. No raw bytes are
returned or saved in evidence. The caller must bound inspection/collector work
within the original grading guard and deadlines. Memory is lost on owner death,
which must remain incomplete.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_log_retention.py -v
```


### Linux node-local CRI following

`cri_follower.LinuxCRIFollower(retention, source, directory, active_name,
node_uid=..., check=..., deadline=...)` follows an existing independently bound
CRI file on a trusted Linux node. `poll()` drains inotify events and reads growth
through held descriptors; captured prefixes are rehashed to refuse overwrite or
truncation. Rename cookies establish rotation order. The old writer must close
after rename before the collector advances to the new inode; late old writes
are read first. Unlink does not erase bytes from a held descriptor. Directory
and active-file symlinks/nonregular files are refused.

The fixed active filename is a canonical numeric restart index followed by
`.log`. The caller must independently verify its container/node mapping and
both original deadlines through `check(source, reserve)`, and run collection in
an owned child that the outer watchdog can terminate if filesystem or check work
blocks. The CRI writer must be trusted and append-only with rename/reopen
rotation. Older rotations at startup, overlapping/ambiguous rotations, queue
overflow, unobserved generations, writes to a retired generation, identity loss
and bounds are unavailable. At most 4,096 polls, 4,096 events per drain, 128
rotations and 512 initial directory entries are accepted; retention's aggregate
byte/file/source bounds also apply. Poll frequently enough for the tested load;
there is no silent recovery from a missed generation.

`close()` closes descriptors and abandons further retention; already captured
positives remain inspectable. Every receipt says `history_complete=False`.
This follows one existing source, not recursive Pod/container discovery, API/time
fences, a complete namespace history or owner-death recovery. Source coverage
and actual deployment orchestration remain separate work.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_cri_follower.py -v
```


### Private anchored Pod identity history

`pod_history.PodIdentityHistory(namespace, pods, binding=...)` starts from the
independently verified Namespace and complete unfiltered PodList. The verified
list type supplies omitted item TypeMeta; explicit wrong types and untyped watch
events are refused. Use its
`begin()` window ID/version, feed every transport callback through `accept()`,
then `finish(receipt)` with the exact verified window receipt. It retains deleted
Pod tombstones and every observed immutable container ID/restart index across
regular, init/sidecar and ephemeral containers. Pending or missing statuses stay
explicitly pending; a waiting container's cached ID is not a new instance.
Same-name Pod recreation requires observing deletion and a new UID. Unknown
events, UID/node/declaration changes, count/identity regressions, failed windows
and bounds permanently invalidate tracking without silently relisting.

`sources()` returns copied private collector inputs with restart index, role,
node name and latest `current|previous|historical` availability. Historical/deleted
sources need independent node/file binding; an availability label does not verify
a retrieval route. Summaries expose only fixed counts and pending/gap flags;
Pod annotations, environment and diagnostic text are discarded. Limits are 128
lifetime Pods, 128 declared containers and 128 immutable container identities,
with a 16 MiB initial snapshot and 1 MiB per Pod/event. State belongs to the
original parent PID and shares the watch cursor's exact count/correlation rules.

Every summary has `history_complete=False`. API identity tracking does not collect
bytes or prove bootstrap/rotation history, namespace log coverage, API/time fences
or owner-death recovery. Keep these private source inputs outside builder mounts
and operator evidence; collectors still require independent peer/guard binding.

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_pod_history.py -v
```


### Sanitized parent security observations

`security_broker.SecurityBroker` provides three fixed read-only parent operations:
`password_storage` (APP-002; AC-004) and `log_canaries`/`log_binary_canaries`
(APP-007; AC-018). Its trusted
`reader(operation, canaries)` must independently bind the actual inspection scope,
verify the active guard/deadlines and use bounded private readers. Password
requests accept no account/profile selection. Text log requests accept only bounded
known canary strings; they cannot select Pods, history, paths or commands.
`log_binary_canaries` accepts one to four exact binary values (8 bytes minimum,
32,768 bytes total maximum). Canonical base64 is used only on the private wire;
the trusted reader receives bytes. The existing 65,536-byte message bound remains
in force. Binary and text inspections use separate operations and grants; missing
binary grants remain inconclusive. Neither operation selects logging sources.
Requests, callback exceptions and raw callback extras are discarded.

The response contains only `verdict`, an enumerated `reason` and a finite integer
`observations_checked`. Pass requires `verified` and at least two password-account
observations or one log-source observation. Fail requires a fixed applicable
reason (`plaintext`, `forbidden_algorithm`, `wrong_defaults`, `reused_salt`,
`password_mismatch` or `canary_present`); incompleteness uses `unavailable`.
These fields are a protocol, not independent evidence of successful inspection.
The trusted parent must establish actual default/dependency/account bindings and
log-source inventory/completeness before emitting a pass. Missing bindings,
unsupported layouts or collection failures remain inconclusive. Raw credential
rows/hashes/logs must never enter the response or evidence serializers.

`read_security` validates exact response fields; unknown extra wire fields are
refused. The authenticated private socket inherits bounded requests/cleanup,
request budgeting, close revocation and socket removal from the audit channel.
This broker is not yet wired into deployment, grading or an acceptance case.

Run its focused channel/lifecycle checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_security_broker.py -v
```


### Guarded parent security inspection lifetime

`security_runtime.SecurityRuntime` wraps a fixed nonempty subset of the security
operations in owned sandbox/watchdog lifetime checks. `inspections` maps each
operation to trusted `reader(canaries, timeout=...)` code; password canaries are
always `None`. Readers must independently bind actual accounts/library defaults or
log source inventory/history, enforce their command/time limits and return the
sanitized receipt described above. `peer_check(operation, timeout=...)` must return
exactly `True` for the bound active peer. These are operator integration contracts,
not automatic application discovery or self-attestation.

The parent checks owner PID, stopped sandbox, watchdog process/release/result
markers and both immutable wall/monotonic deadlines before and after peer checks
and inspection. Initial reserve is 40 seconds; reader timeout is 30 seconds, with
a five-second final allowance. A late callback or lost lifetime/peer suppresses
its receipt. Closing revokes in-flight observation, closes the broker and removes
the private socket. Evidence contains operation names, fixed outcomes/verdicts
and exception types only, never requests, hashes, passwords or raw callback text.
This adds no grading time or authorization to change peers/policy; unsupported
operations are unavailable. No deployment resolver or grading case grants this
runtime yet.

Run its focused lifetime checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_security_runtime.py -v
```


### Security grants in protected suites

A non-browser case must declare `inspects_security: true` to receive the parent
security capability. `run_suite(..., security_broker=...)` strips injected
`_security_control` from base target input and writes the live capability only to
that case's private target. An undeclared case receives none. A declared case with
no broker is inconclusive before child launch (`security_capability_unavailable`);
it cannot claim pass by omitting the inspection. Browser cases cannot request this
host capability. The declaration must be an exact boolean.

After the case, the security reader must settle. Otherwise the saved case verdict
and aggregate become inconclusive (`security_reader_unsettled`), and the suite
stops before following cases. Read-only missing-grant cases can leave unrelated
later checks runnable; shared/runtime mutation declarations retain their existing
abort rules. No acceptance coverage, suite approval or grading time is added.
Private credential/log values must remain inside independently bound parent
inspectors. The executor can receive a guarded SecurityRuntime broker, but fresh
capture/deployment discovery and lifecycle resolution are not wired yet.

Run the executor capability checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_grading.py -v
```


### Fresh deployment security resolution

`grade_capture(..., security_observer=...)` resolves security inspection callbacks
only after successful fresh bootstrap. The trusted operator function receives
`box`, plus keyword arguments `guard`, `monotonic_deadline` and `wall_deadline` so
it can bind private readers to that exact deployment and its original lifetime.
It must return exactly `inspections` (a nonempty fixed-operation/callable map) and
`peer_check` (a callable). Static configuration dictionaries, unknown operations,
noncallable readers and extra fields are refused. Actual account/library-default
and log inventory/history bindings remain independent operator work; builder
stdout is not executable or authoritative resolver configuration.

The controller constructs SecurityRuntime with those same immutable deadlines
and supplies only its broker to the suite executor. Parent callback/configuration
objects and raw values are not added to worker targets. Default deployment grants
no security capability. Failed bootstrap never invokes the resolver. Security
inspection closes before browser/job/audit/fault resources and guard release;
resolution or cleanup failures still dispose the owned sandbox. A close failure
revokes acceptance and records only its exception type. No grading time, policy
changes, suite coverage approval or benchmark launch is implied by this hook.

Run its focused deployment checks with:

```sh
uv run --locked python -m unittest discover -s tests -p test_evaluation_deployment.py -v
```

### Coordinating observed namespace log sources

`log_collector.NamespaceLogCollector(history, retention, resolve, check=...,
 deadline=...)` attaches a `LinuxCRIFollower` to each immutable identity from
`PodIdentityHistory`. Both inputs must have the same exact Namespace name/UID
and original process. Trusted `resolve(entry, reserve)` privately returns
`directory`, `node_uid`, and the per-source `check`, or `None` for a binding that
is not yet available. The restart index determines the canonical active filename.
The resolver must independently verify the source/node/file binding, including
historical sources; builder-selected paths are not trusted. The global
`check(reserve)` verifies the original Namespace, owner, and clock bindings.
Run callbacks and filesystem operations inside an owned bounded child.

`poll()` retries unresolved identities, attaches each immutable source only once,
and polls every attached follower. Current/previous selector changes and Pod
deletion do not detach sources. Public summaries disclose unresolved sources,
pending containers and observed identity gaps without exposing raw identities or
bytes. Failure or `close()` closes all followers and abandons shared retention;
already captured positives remain inspectable until retention itself is closed.

This connects observed API identities to existing Linux files. It does not
capture files before CID publication, discover unseen generations, establish
bootstrap/API/time/closed-writer fences, prove owner-death cleanup or complete
namespace history. All receipts retain `history_complete=False`; absence cannot
pass acceptance. This supports D-049 and REQ-012/015/020 without removing those
evidence limits.

```bash
uv run --locked python -m unittest discover -s tests -p test_evaluation_log_collector.py -v
```
