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
