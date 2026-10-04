# Evaluation controller

Separate operator-side tooling for REQ-012/014/015/020. This package is not copied
into generated projects and must never be mounted into a benchmark builder.
The owner authorized implementation; experiment launch, protected-suite approval,
and host-wide policy changes remain separately gated.

Python 3.11+ standard library; no service, build step, or model call is required
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
