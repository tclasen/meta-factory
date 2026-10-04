# Knowledge-work factory

Initialize a project with this Copier template, customize its instructions and
checks, then run Codex against it inside Docker `sbx`.

## 1. Initialize or update a project with Copier

Install [uv](https://docs.astral.sh/uv/getting-started/installation/), Python 3.11+
(locally or through uv), and Git. Set the template checkout and the project path
in your host shell, replacing the example paths:

```sh
FACTORY_TEMPLATE=/absolute/path/to/factory
FACTORY_PROJECT=/absolute/path/to/my-project
FACTORY_REF=$(git -C "$FACTORY_TEMPLATE" rev-parse HEAD)
```

This pins the template to a commit. There is no stable release yet; select a
reviewed release tag or commit when updating. Keep the template checkout available:
Copier records its location in the project's `.factory-answers.yml`.

### Initialize a new project

Use a destination that does not already exist:

```sh
uv tool run --from copier==9.14.0 copier copy \
  --vcs-ref "$FACTORY_REF" --defaults \
  "$FACTORY_TEMPLATE" "$FACTORY_PROJECT"
cd "$FACTORY_PROJECT"
git init
python3 .factory/core/tools/integrate.py
python3 .factory/core/tools/integrate.py --check
git status --short
```

Review the generated files in your editor, customize them as below, and commit
the initialization under your project's Git policy. Integration adds the factory
section to `AGENTS.md` and installs a local pre-commit dispatcher.

### Add the factory to an existing project

Start at a clean Git repository root, with no untracked files. Use the
Copier-based adoption helper so collisions are checked before files are changed:

```sh
cd "$FACTORY_TEMPLATE"
uv sync --locked
uv run --locked python scripts/adopt.py "$FACTORY_PROJECT" --ref "$FACTORY_REF"
cd "$FACTORY_PROJECT"
git status --short
git diff
```

The helper preserves existing application files, guidance, skills, and project
extensions. Review untracked generated files too, then customize and commit.
For a hook manager, `core.hooksPath`, or a linked worktree, pass `--hooks manual`
and follow [hook composition](docs/integration.md#hook-composition). Resolve
reported collisions rather than using Copier's overwrite option.

### Update an initialized project

Select the new template commit or tag in `FACTORY_REF`. Start with a clean,
committed project on the branch required by its policy:

```sh
cd "$FACTORY_PROJECT"
uv tool run --from copier==9.14.0 copier update \
  --answers-file .factory-answers.yml --vcs-ref "$FACTORY_REF" --defaults
git diff --check
git diff
```

Resolve any conflicts before continuing. Then refresh the managed guidance:

```sh
python3 .factory/core/tools/integrate.py
python3 .factory/core/tools/integrate.py --check
```

Use `--hooks manual` for both commands if you maintain hook composition yourself.
Run the project's verification inside the sandbox, as shown below, before
committing or submitting the update for review. Project extensions are preserved;
managed-file edits may need reconciliation. See [update conflicts](docs/integration.md#update-conflicts).

## 2. Customize the initialized factory

Make project-specific changes in these locations:

| Location | What to customize |
| --- | --- |
| `.factory/project/config.json` | Verification and pre-commit commands. |
| `.factory/project/policy.md` | Project conventions, task source, task selection/completion rules, and commit policy. |
| `AGENTS.md`, outside the factory markers | Repository guidance and commands. |
| `.agents/skills/<project-skill>/SKILL.md` | Additional project skills; reserve `factory-*` names for the template. |

For example, a Python project using `unittest` could configure:

```json
{
  "schema_version": 1,
  "verification_commands": [["python3", "-m", "unittest", "discover", "-s", "tests"]],
  "pre_commit_commands": [["git", "diff", "--cached", "--check"]]
}
```

Replace the example verification command with your actual test/build commands.
Commands run from the project root, as argument arrays without an implicit shell.
Every configured command must succeed. The initial empty verification list means
**unconfigured**, not a successful check. Validate your configuration with:

```sh
python3 .factory/core/tools/check.py config
```

For run-forever, describe in `policy.md` where ready tasks come from, their order,
acceptance criteria, how to record completion/blockers, and whether Codex should
commit completed work. Use the task tracker you already maintain; the factory
does not create one. Each new session must be able to read that task source and
see what previous sessions completed. Without it, use an explicit run-once task.

Keep `.factory/core/`, `.agents/skills/factory-*/`, and the marked `AGENTS.md`
section template-managed. Read the generated
`.factory/core/references/customization.md` for supported overrides. Commit
`.factory/project/integration.json` along with guidance integration changes; it
lets updates detect local edits. Hook activation is local to a clone, so rerun
`integrate.py` in each new clone. Restart an existing Codex session after changing
its project instructions.

## 3. Install and configure Docker sbx

These instructions target the Apple Silicon Mac host (macOS Sonoma 14 or newer).
Docker's standalone `sbx` CLI does not require Docker Desktop or a host Docker
Engine. For other hosts, use [Docker's installation instructions](https://docs.docker.com/ai/sandboxes/install/).

Install with Homebrew, initialize the network policy on a new installation, and
sign in to Docker and your OpenAI subscription:

```sh
brew trust docker/tap
brew install docker/tap/sbx
sbx --help
sbx policy init deny-all
sbx login
sbx secret set openai --oauth
```

Policy initialization is global. On an existing installation, inspect `sbx policy
ls` and adjust the current policy rather than resetting other sandboxes' rules.
OAuth runs on the host and stores credentials in the host keychain. A host Codex
installation or copied `~/.codex` credentials are not required.

Create a named Codex sandbox with just this project mounted:

```sh
cd "$FACTORY_PROJECT"
FACTORY_SANDBOX=my-project-factory
sbx create --name "$FACTORY_SANDBOX" codex "$PWD"
sbx policy ls "$FACTORY_SANDBOX" --wide
```

The project mount is read-write: agent edits appear in your host worktree. The
sandbox supplies its own Docker daemon and Linux environment. Host-level Codex
configuration is not imported; use project configuration or explicit run flags.

`deny-all` starts without a baseline allowlist, but the Codex kit may add rules.
Inspect the effective policy and allow the package registries, documentation, and
state services your project needs. For example, for a Python project:

```sh
sbx policy allow network --sandbox "$FACTORY_SANDBOX" pypi.org
sbx policy allow network --sandbox "$FACTORY_SANDBOX" files.pythonhosted.org
sbx policy check network --sandbox "$FACTORY_SANDBOX" pypi.org
```

Verify that the kit's rules permit the OpenAI endpoints required by your chosen
authentication. Add other destinations deliberately; blocked requests will not
be resolved automatically in an unattended run. See [Docker network policy](https://docs.docker.com/ai/sandboxes/governance/access-controls/local/).
If tasks need authenticated GitHub access, configure it on the host with
`sbx secret set github --command 'gh auth token'` after signing in with `gh`.

Check the tools inside the sandbox, install your project's dependencies there,
and run its configured verification:

```sh
sbx exec "$FACTORY_SANDBOX" codex --version
sbx exec "$FACTORY_SANDBOX" python3 --version
sbx exec "$FACTORY_SANDBOX" git --version
sbx exec "$FACTORY_SANDBOX" docker version
```

The bundled Codex CLI can lag behind the model catalog. The runtime smoke test
used **Codex 0.160.0** after updating the image's 0.149.1 installation. For that
tested version, install it inside the sandbox before launching Codex:

```sh
sbx exec "$FACTORY_SANDBOX" npm install --global @openai/codex@0.160.0
sbx exec "$FACTORY_SANDBOX" codex --version
```

Stop if installation fails or the active version is not 0.160.0; do not continue
using the old binary. See the [preflight findings](docs/runtime-preflight.md#observed-results)
for the validated Docker MCP compatibility correction and network-policy limits.

Open a sandbox shell and run your project's documented dependency setup:

```sh
sbx exec -it "$FACTORY_SANDBOX" bash
```

Then, inside that shell:

```sh
python3 .factory/core/tools/integrate.py --check
python3 .factory/core/tools/check.py verify
exit
```

Use `--hooks manual` on the integration check if applicable. Missing tools or
failing checks must be resolved before relying on unattended task execution.
See [Docker's Codex guide](https://docs.docker.com/ai/sandboxes/agents/codex/)
for authentication and agent configuration details.

## 4. Start the factory

Use the named sandbox created above. In a host Bash or Zsh terminal, define a
small run-once function:

```sh
FACTORY_SANDBOX=my-project-factory
factory_run_once() {
  sbx exec -w "$FACTORY_PROJECT" "$FACTORY_SANDBOX" \
    codex exec --cd "$FACTORY_PROJECT" \
    --dangerously-bypass-approvals-and-sandbox "$@"
}
```

This launches `codex exec` through sbx's non-interactive command transport. The
bypass flag is appropriate here because `sbx` provides the external isolation; do not use this
recipe to run Codex directly on the host. See [Codex non-interactive mode](https://developers.openai.com/codex/noninteractive).
To select a model, pass `--model MODEL_ID` to the function using an identifier
available to your account; otherwise it uses the sandbox's Codex configuration.

### Run once: one task, then exit

Replace the example with one concrete task and its acceptance criteria:

```sh
factory_run_once 'Read AGENTS.md and the factory instructions. Use the factory
skills to implement exactly this task: fix the failing date-parser test without
changing the public API. Run the configured verification, review the diff, and
report the result. Follow the project commit policy, then stop.'
```

The Codex process exits after its response; the sandbox and its installed tools
persist. Review the result and diff: a successful process exit alone does not
prove task acceptance.

### Run forever: repeat one task at a time

After configuring a durable task source in `policy.md`, run this loop in the same
terminal where you defined `factory_run_once`:

```sh
FACTORY_NEXT_TASK='Read AGENTS.md and the factory instructions. Read the task
source and selection rules in .factory/project/policy.md. Select exactly one
ready task and use the factory skills to implement, verify, and review it.
Record completion only when its acceptance criteria pass; otherwise record the
blocker. Follow the project commit policy. If no task is ready, report that and
make no changes. Do not invent work or start a second task. Then exit.'

(
  trap 'exit 130' INT
  trap 'exit 143' TERM
  while :; do
    if factory_run_once "$FACTORY_NEXT_TASK"; then
      sleep 30
    else
      factory_exit_code=$?
      printf 'Run failed (exit %s); inspect before restarting.\n' "$factory_exit_code" >&2
      exit "$factory_exit_code"
    fi
  done
)
```

The loop runs sequentially until interrupted, polling every 30 seconds even when
no task is ready. Each iteration starts a fresh conversation in the same sandbox;
progress comes from the project task source. It stops on a nonzero process exit
rather than repeatedly retrying authentication, quota, or runtime errors. Inspect
any partial work before restarting. The loop has no scheduler, per-task timeout,
or automatic restart after closing the terminal or rebooting.

Press **Ctrl-C** to stop the loop. To stop the sandbox as well, use another host
terminal:

```sh
sbx stop my-project-factory
```

The `sbx exec` launch path has passed a bounded factory smoke task on the target
Mac; the full setup recipes and run-forever loop have not been validated end to
end. Use the [runtime preflight](docs/runtime-preflight.md) to prepare
a disposable project and validate one bounded Luna Medium task on the target Mac,
including factory skill use, fixed acceptance checks, and hook activation.
The latest recorded smoke passed after the MCP compatibility correction; see the
preflight findings for network and model-identity evidence limits. For development and validation
details, see [CONTRIBUTING.md](CONTRIBUTING.md); for component ownership, see
[architecture](docs/architecture.md).

The [infrastructure preflight](docs/runtime-preflight.md#completed-infrastructure-preflight)
also passed nested Kubernetes and sampled sandbox/pod HTTPS allowlist checks.
Those tests temporarily removed global TCP allow-all and restored it afterward;
the host remains allow-all. UDP results are inconclusive. The runbook records
the tested setup corrections and the limits of this evidence.
