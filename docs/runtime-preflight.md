# Factory runtime preflight

Use this operator-run smoke test on the target Apple Silicon Mac to check the
factory with Docker `sbx` and **`gpt-6-luna` at `medium` reasoning**. It addresses
the factory-runtime portions of Q-001 and Q-003 and exercises D-039 through
D-044. It does not validate Kubernetes, long-horizon behavior, benchmark quality,
or the full isolation requirements of REQ-021. It cannot authorize promotion.

**Live status: bounded workflow and scoped network smoke checks passed on the target Mac.** The observed configuration
is sbx 0.46.0, Codex 0.160.0, and requested `gpt-6-luna`/`medium` through Docker's
`sandboxd` provider. Catalog discovery, MCP configuration migration, and the task
passed without reported runtime errors. Network and model-identity evidence limits
remain. See [observed results](#observed-results).
If Luna or Medium is unavailable on a later run, record a blocker; do not
substitute another model or reasoning setting.

## Observed results

The owner executed these smoke attempts on 2026-10-04 (UTC). The first four used
template commit `012166dd3a78d4ef3d2bb0ee989ce1c0d4ca9ec7`; the final run used
`c1a95ce2d5403866f05b58e2494f33a000084319`. Raw logs remain local under
`.factory-planning/runtime-smoke-logs/`; they are not committed or benchmark evidence.

| Attempt | Observation |
| --- | --- |
| 01:42 UTC | Preparation passed; `sbx run` attachment failed after about 30 seconds with `inspect exec: context deadline exceeded`. No task events captured. |
| 01:45 UTC | `sbx exec` completed the task in 56.76 seconds on Codex 0.149.1; acceptance passed, but Luna metadata was missing. |
| 01:55 UTC | Model discovery stopped before inference: the old CLI catalog lacked `gpt-6-luna`. |
| 02:01 UTC | Updating Codex from 0.149.1 to 0.160.0 made Luna/Medium discoverable. Task time was 33.91 seconds; all four tests, guidance integration, staged hook, and file/history checks passed. |
| 02:20 UTC | Explicit Codex 0.160.0 pin and MCP migration passed; no runtime errors were reported. Scoped denial checks passed, then the task completed in 29.24 seconds with all acceptance checks passing. |

The final attempt read and applied all four factory skills and changed only
`value.lower()` to `value.strip().lower()`. Cleanup stopped each sandbox. The
host reported macOS 27.0.1 on arm64, preparation used uv-managed Python 3.13.16,
and the sandbox reported Python 3.14.4 and Git 2.53.0.

The 02:01 attempt reported that Docker's generated MCP gateway `headers` and `type`
keys were ignored by Codex 0.160.0. The validated compatibility correction maps `headers` to
`http_headers` and removes the legacy `type` for a recognized HTTP URL transport,
preserving values and all other settings. The 02:20 attempt applied this correction
with a sandbox-local backup and produced no configuration warnings. This establishes
configuration compatibility, not functional coverage of every gateway tool. Never log header values
or overwrite an unfamiliar configuration without review.

The effective global network policy was allow-all and was left unchanged. The
02:20 run added explicit sandbox-only denies for `registry.npmjs.org:443` and
`example.com:443`; policy checks reported both denied. An actual request to the
registry returned HTTP 200 before the rule and HTTP 403 afterward. No live request
to example.com was needed. This is not default-deny validation or full REQ-021 acceptance.
Runtime catalog/configuration evidence does not independently attest the provider's
served model identity. These observations do not establish benchmark performance,
natural compaction, Kubernetes isolation, or stable promotion.

## 1. Prepare a disposable project

Use a trusted template checkout with Python 3.11+, Git, and uv. In a host Bash
terminal, replace the checkout path and run:

```sh
FACTORY_TEMPLATE=/absolute/path/to/factory
cd "$FACTORY_TEMPLATE"
uv sync --locked
FACTORY_REF=$(git rev-parse HEAD)
FACTORY_SMOKE_BASE=$(mktemp -d "${TMPDIR:-/tmp}/factory-smoke.XXXXXX")
FACTORY_SMOKE_BASE=$(cd "$FACTORY_SMOKE_BASE" && pwd -P)
FACTORY_PROJECT="$FACTORY_SMOKE_BASE/project"
FACTORY_EVIDENCE="$FACTORY_SMOKE_BASE/evidence"
mkdir "$FACTORY_EVIDENCE"
uv run --locked python scripts/prepare_smoke.py "$FACTORY_PROJECT" --ref "$FACTORY_REF"
```

Stop if preparation fails. The helper refuses any existing destination, including
symlinks; invalid revisions do not create it. Later failures retain a partial
destination for inspection. Use a new path after resolving the cause. Custom
`core.hooksPath` setups are rejected by automatic integration; use a Git environment
with ordinary hooks for this smoke test rather than changing your global settings.

The helper renders the selected template commit, adds the checked-out smoke
fixture, configures standard-library tests and a staged whitespace check, and
commits the initial project. Its Git identity and signing setting are local to
that disposable repository. It starts no sandbox or model. There is no application
build, dependency installation, or server for the smoke project.

Capture the baseline outside the project that will be mounted:

```sh
git -C "$FACTORY_TEMPLATE" rev-parse HEAD > "$FACTORY_EVIDENCE/preparation-commit.txt"
git -C "$FACTORY_TEMPLATE" status --porcelain > "$FACTORY_EVIDENCE/preparation-status.txt"
git -C "$FACTORY_PROJECT" rev-parse HEAD > "$FACTORY_EVIDENCE/initial-commit.txt"
git -C "$FACTORY_PROJECT" archive HEAD > "$FACTORY_EVIDENCE/initial-project.tar"
cp "$FACTORY_PROJECT/.git/hooks/pre-commit" "$FACTORY_EVIDENCE/initial-pre-commit"
cp "$FACTORY_PROJECT/.factory-answers.yml" "$FACTORY_EVIDENCE/template-answers.yml"
sw_vers > "$FACTORY_EVIDENCE/host-version.txt"
uname -m >> "$FACTORY_EVIDENCE/host-version.txt"
printf '%s\n' "$FACTORY_PROJECT" > "$FACTORY_EVIDENCE/project-path.txt"
```

Preparation status should be empty for a reproducible run; otherwise record the
local changes and do not claim that a commit alone reproduces the fixture.

## 2. Check sandbox setup and the expected failure

Follow [README setup](../README.md#3-install-and-configure-docker-sbx) for sbx
installation and host OAuth login if needed. Inspect existing global policy;
do not reset it. Choose a fresh sandbox name for every attempt:

```sh
FACTORY_SANDBOX="factory-smoke-$(date -u +%Y%m%dT%H%M%SZ)"
printf '%s\n' "$FACTORY_SANDBOX" > "$FACTORY_EVIDENCE/sandbox-name.txt"
sbx version > "$FACTORY_EVIDENCE/sbx-version.txt" 2>&1
sbx create --name "$FACTORY_SANDBOX" codex "$FACTORY_PROJECT"
sbx policy ls "$FACTORY_SANDBOX" --wide > "$FACTORY_EVIDENCE/network-policy.txt"
FACTORY_WORKSPACE="$FACTORY_PROJECT"
sbx exec "$FACTORY_SANDBOX" git -C "$FACTORY_WORKSPACE" rev-parse --show-toplevel
sbx exec "$FACTORY_SANDBOX" codex --version > "$FACTORY_EVIDENCE/codex-version-before.txt" 2>&1
sbx exec "$FACTORY_SANDBOX" npm install --global @openai/codex@0.160.0
sbx exec "$FACTORY_SANDBOX" codex --version > "$FACTORY_EVIDENCE/codex-version.txt" 2>&1
sbx exec "$FACTORY_SANDBOX" codex exec --help > "$FACTORY_EVIDENCE/codex-exec-help.txt" 2>&1
sbx exec "$FACTORY_SANDBOX" python3 --version > "$FACTORY_EVIDENCE/python-version.txt" 2>&1
sbx exec "$FACTORY_SANDBOX" git --version > "$FACTORY_EVIDENCE/git-version.txt" 2>&1
sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" \
  python3 .factory/core/tools/integrate.py --check \
  > "$FACTORY_EVIDENCE/integration-before.txt" 2>&1
```

Check each result before continuing. Confirm the repository path is the mounted
project. If the installed sbx uses a different mount path, inspect it and set
`FACTORY_WORKSPACE` to that project path inside the sandbox; never mount the
template checkout or evidence directory to solve a path error. Record any change.
Inspect the saved CLI help for support of the execution flags below.
Require Python 3.11 or newer. Review each captured version and integration result;
redirection into an evidence file does not itself indicate success.
Require Codex 0.160.0 for this smoke version. Keep CLI installation outside the
timed model task and preserve its output. An update failure is a setup blocker.

Inspect effective policy, including kit rules, before launching the agent. This
task needs only model/authentication access, with no package registries, GitHub,
or application integrations. Record unexpected allowances or setup changes.
An inspected policy is not proof of network enforcement or host isolation.
Unmatched requests can prompt for approval under Docker's policy; blocked access
must be resolved before the attempt, not approved during the unattended task.

Run the intentionally failing check and save its status without a pipeline:

```sh
if sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" \
  python3 .factory/core/tools/check.py verify \
  > "$FACTORY_EVIDENCE/verification-before.txt" 2>&1; then
  FACTORY_BASELINE_EXIT=0
else
  FACTORY_BASELINE_EXIT=$?
fi
printf '%s\n' "$FACTORY_BASELINE_EXIT" > "$FACTORY_EVIDENCE/verification-before.exit"
cat "$FACTORY_EVIDENCE/verification-before.txt"
git -C "$FACTORY_PROJECT" status --porcelain
```

Require exit **1**, exactly four tests, and exactly one failure:
`test_surrounding_whitespace`. Require a clean project worktree. Missing tools,
integration failures, or other test errors are setup blockers, not the expected
baseline. Resolve them before launching the model.

## 3. Run one bounded task

Keep a second host terminal available with the recorded sandbox name. Set a
**10-minute timer immediately before the command below**. This is an
operator-enforced smoke limit, not the experiment deadline in Q-009. There is no
automatic watchdog or retry loop. Do not leave this procedure unattended.

```sh
date -u +%Y-%m-%dT%H:%M:%SZ > "$FACTORY_EVIDENCE/start.txt"
printf '%s\n' 'model=gpt-6-luna' 'model_reasoning_effort=medium' \
  'limit_seconds=600 (operator enforced)' > "$FACTORY_EVIDENCE/requested-runtime.txt"
FACTORY_SMOKE_PROMPT=$(cat "$FACTORY_PROJECT/SMOKE_TASK.md")
if sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" \
  codex exec --cd "$FACTORY_WORKSPACE" --dangerously-bypass-approvals-and-sandbox \
  --model gpt-6-luna --config 'model_reasoning_effort="medium"' --json \
  "$FACTORY_SMOKE_PROMPT" \
  > "$FACTORY_EVIDENCE/events.jsonl" 2> "$FACTORY_EVIDENCE/runtime.stderr"; then
  FACTORY_RUN_EXIT=0
else
  FACTORY_RUN_EXIT=$?
fi
printf '%s\n' "$FACTORY_RUN_EXIT" > "$FACTORY_EVIDENCE/runtime.exit"
date -u +%Y-%m-%dT%H:%M:%SZ > "$FACTORY_EVIDENCE/stop.txt"
```

The bypass flag applies only to Codex **inside sbx**. Do not run this command
directly with host Codex. The task authorizes one implementation, with no
delegation, commits, or modifications outside `normalizer.py`.

At the limit, run `sbx stop THE_RECORDED_SANDBOX_NAME` in the second terminal.
If the first terminal remains attached, interrupt it with Ctrl-C; record the stop
time and timeout manually if the trailing commands did not run. Also stop on a
model-access, reasoning-setting, authentication, quota, or runtime error. Do not
change model settings, provide task help, or retry within the same attempt.

Capture any runtime-reported model/reasoning identity in the evidence notes.
Requested flags alone do not prove effective configuration, and an agent's own
claim is not runtime evidence. If the installed CLI does not expose that evidence,
mark configuration as **unverified**. Keep stdout and stderr separately even if
sbx adds non-JSON startup output; do not silently discard it.

## 4. Check the result independently

First inspect the saved events and stderr for errors, unexpected tool access,
delegation, and evidence that each factory skill was read and applied. A statement
that a skill was used is insufficient without the corresponding workflow actions.
This is operator inspection, not protected benchmark grading.

Before executing project tools again, compare against the external baseline:

```sh
FACTORY_INITIAL_COMMIT=$(cat "$FACTORY_EVIDENCE/initial-commit.txt")
git -C "$FACTORY_PROJECT" rev-parse HEAD > "$FACTORY_EVIDENCE/final-commit.txt"
cmp "$FACTORY_EVIDENCE/initial-commit.txt" "$FACTORY_EVIDENCE/final-commit.txt"
git -C "$FACTORY_PROJECT" branch --show-current
git -C "$FACTORY_PROJECT" status --porcelain --untracked-files=all
git -C "$FACTORY_PROJECT" diff --cached --exit-code
git -C "$FACTORY_PROJECT" diff --exit-code "$FACTORY_INITIAL_COMMIT" -- . ':!normalizer.py'
cmp "$FACTORY_EVIDENCE/initial-pre-commit" "$FACTORY_PROJECT/.git/hooks/pre-commit"
git -C "$FACTORY_PROJECT" diff "$FACTORY_INITIAL_COMMIT" -- normalizer.py \
  > "$FACTORY_EVIDENCE/change.diff"
cat "$FACTORY_EVIDENCE/change.diff"
```

Require unchanged HEAD, branch `main`, an empty index, and only an unstaged
`normalizer.py` change. Require no unexpected untracked files, unchanged fixed
resources, and the original hook bytes. Inspect the implementation before executing
it. If these conditions fail, record a task/policy failure; do not repair the result
and call it a pass. Do not run changed acceptance tools or hooks.

For a completed attempt meeting those conditions, rerun checks in the sandbox:

```sh
if sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" \
  python3 .factory/core/tools/check.py verify \
  > "$FACTORY_EVIDENCE/verification-after.txt" 2>&1; then
  FACTORY_VERIFY_EXIT=0
else
  FACTORY_VERIFY_EXIT=$?
fi
printf '%s\n' "$FACTORY_VERIFY_EXIT" > "$FACTORY_EVIDENCE/verification-after.exit"
sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" \
  python3 .factory/core/tools/integrate.py --check \
  > "$FACTORY_EVIDENCE/integration-after.txt" 2>&1
sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" git diff --check
```

Require four passing tests, integration success, and no whitespace errors. Then
exercise the installed executable hook against the actual change without committing:

```sh
sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" git add -- normalizer.py
if sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" .git/hooks/pre-commit \
  > "$FACTORY_EVIDENCE/hook.txt" 2>&1; then
  FACTORY_HOOK_EXIT=0
else
  FACTORY_HOOK_EXIT=$?
fi
printf '%s\n' "$FACTORY_HOOK_EXIT" > "$FACTORY_EVIDENCE/hook.exit"
sbx exec -w "$FACTORY_WORKSPACE" "$FACTORY_SANDBOX" git restore --staged -- normalizer.py
git -C "$FACTORY_PROJECT" status --porcelain > "$FACTORY_EVIDENCE/final-status.txt"
```

Require hook exit zero. Unstaging preserves the code change. These commands are
not a reason to restart a timed-out or errored run; retain its partial work and
classify it separately.

## 5. Record the outcome and stop

Write `result.md` in the evidence directory with:

- Template and preparation commits, initial project commit, versions, sandbox name,
  commands or deviations, and inspected policy.
- Requested and runtime-observed model/reasoning, or precisely what is unverified.
- Start/stop UTC timestamps, elapsed seconds, process/check/hook exit statuses,
  and whether the timer intervened.
- Evidence of each skill's use, final diff, protected-file checks, and limitations.
- Outcome: **pass** only when configuration is verified and every acceptance
  condition passes; **qualified** for passing mechanics with missing runtime or
  skill-use evidence; **blocked** for setup/access issues; **incomplete** for quota
  or timeout; **failed** for task, policy, or runtime failures.

Missing or explicitly skipped skill behavior is a failure; only insufficient
observability warrants qualification. Successful process exit alone is not a pass.
Never treat missing data as success. Review logs for secrets before sharing; keep
raw evidence local and do not add it to this repository. Each later attempt needs
a new project, sandbox, and evidence directory, linked to the earlier outcome.

Stop the dedicated sandbox:

```sh
sbx stop "$FACTORY_SANDBOX"
```

After retaining the evidence you need, optional removal is explicit and scoped:

```sh
sbx rm "$FACTORY_SANDBOX"
```

Review Docker's confirmation prompt; do not use `--all`. Retain the host project
and evidence until reviewed, then remove that one disposable directory manually.

## Sources and local checks

Command guidance was checked against official documentation on 2026-10-03;
installed-version behavior still needs this live preflight:

- [Docker sbx run](https://docs.docker.com/reference/cli/sbx/run/),
  [exec](https://docs.docker.com/reference/cli/sbx/exec/), and
  [removal](https://docs.docker.com/reference/cli/sbx/rm/).
- [Docker Codex authentication](https://docs.docker.com/ai/sandboxes/agents/codex/)
  and [local network policy](https://docs.docker.com/ai/sandboxes/governance/access-controls/local/).
- [Codex non-interactive execution](https://developers.openai.com/codex/noninteractive),
  [CLI flags](https://developers.openai.com/codex/cli/reference),
  [reasoning configuration](https://developers.openai.com/codex/config-reference),
  and [model availability](https://developers.openai.com/codex/models).

To check preparation and fixed acceptance without sbx or a model:

```sh
uv run --locked python -m unittest discover -s tests -p test_smoke.py -v
```

The full development check remains
`uv run --locked python -m unittest discover -s tests -v`, followed by
`git diff --check`. Neither command is live runtime evidence.
