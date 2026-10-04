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
