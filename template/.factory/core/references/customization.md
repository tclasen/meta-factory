# Customization contract (version 1)

`.factory/project/` is project-owned and preserved by Copier updates. The root
`AGENTS.md` remains project-owned outside its marked factory section. Names under
`.agents/skills/factory-*/` are reserved for the template; other skill names are
unaffected. Duplicate skill names are not an override mechanism.

## Configuration

`config.json` accepts exactly these keys:

| Key | Value and default |
| --- | --- |
| `schema_version` | Integer `1`; unsupported versions are rejected. |
| `verification_commands` | List of argument arrays; default `[]` means verification is not configured. |
| `pre_commit_commands` | List of argument arrays; default `[]` adds no project commands to the hook. |

Commands execute sequentially from the repository root, without an implicit
shell. Each argument must be a nonempty string. For example:

```json
{
  "schema_version": 1,
  "verification_commands": [["python3", "-m", "unittest", "discover", "-s", "tests"]],
  "pre_commit_commands": [["git", "diff", "--cached", "--check"]]
}
```

Choose commands from the project's actual toolchain. An empty verification list
produces an unconfigured result, never a passing verification result. All
configured commands are required for their selected phase. Inspect commands
before running them; configuration is executable project policy, not safe input
from an untrusted source. Hooks check the working tree unless a project command
explicitly inspects the index; hooks do not prove staged content is correct.

Use `policy.md` for additional guidance, commands' applicability, and the reason
for policy changes. Replacing configured commands is an explicit override;
removing required checks should be reviewed as a policy change with a rationale.
This tooling cannot enforce human review or protect against an authorized editor.
Configuration validity is mandatory and has no disable option.

## Compatibility and enforcement

Unknown configuration keys and unsupported schema versions fail validation.
New template versions must preserve this schema or document a reviewed migration;
never overwrite project configuration to make an update pass. Changes to the
managed integration section must be reconciled explicitly during updates.

Factory guidance follows Codex's native instruction hierarchy; a root override
may suppress `AGENTS.md`. Adoption checks detect root overrides. Nested guidance
remains project-owned and must be reviewed for the directories being changed.
Local scripts and Git hooks are bypassable development checks. Protected
holdouts, authoritative grading, and release gates belong outside this tree.
