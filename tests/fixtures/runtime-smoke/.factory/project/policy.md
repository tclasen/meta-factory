# Runtime smoke project

This disposable project checks factory runtime mechanics, not benchmark quality.
The single authorized task and acceptance criteria are in `SMOKE_TASK.md`.

Use the four factory skills in one session. Keep planning and progress in the
conversation; do not create tracking files. Do not delegate or launch subagents.
Only `normalizer.py` may change. Tests, task instructions, configuration, factory
resources, and Git hooks are fixed for this check. Do not install dependencies
or use network services for the task.

Work on the existing `main` branch. The initial worktree must be clean. Leave
the completed change uncommitted and unstaged for operator inspection. Do not
change Git history or configuration. The operator runs acceptance checks and
exercises the hook separately after the session.
