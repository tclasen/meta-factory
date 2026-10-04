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
