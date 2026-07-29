# Claude Code flash gate: repo governance as the authorizer

This repo can act as its own permission authority for Claude Code sessions:
instead of a human approving every tool call, a `PreToolUse` hook delegates
device-write authorization to the bringup governance v4 chain.

## Decision table

| Bash tool call | Decision | Decided by |
| --- | --- | --- |
| Invokes `scripts/72_stage_downstream_ssh_wifi_test.sh` (governed D110 executor) | **allow** if `scripts/65_lmi_release_safety_lint.sh` passes, **deny** if it fails | the safety lint, at call time |
| Raw `fastboot flash/boot/reboot/erase/format`, or `dd` onto a block device | **deny**, always | the hook (mirrors lint check 1/2) |
| D114 Python/PowerShell transition entrypoints | no opinion — normal permission prompt | the operator (until D114 is wired to v4 claims) |
| Everything else | no opinion — normal permission flow / allowlist | harness |

The hook lives at `scripts/hooks/claude_flash_gate.sh` and is tracked. It
never talks to the phone itself; it only runs the (read-only) safety lint.

## Activation — a human step, by design

Claude agents are prevented (by the Claude Code harness itself) from
authoring the file that grants their own permissions. To activate the gate,
an operator creates `.claude/settings.json` in their checkout with exactly
this content:

```json
{
  "permissions": {
    "allow": [
      "Bash(scripts/59_release_static_ci.sh:*)",
      "Bash(scripts/65_lmi_release_safety_lint.sh:*)",
      "Bash(scripts/68_mainline_progress_loop.sh:*)",
      "Bash(git status:*)",
      "Bash(git diff:*)",
      "Bash(git log:*)",
      "Bash(git grep:*)"
    ]
  },
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "\"$CLAUDE_PROJECT_DIR\"/scripts/hooks/claude_flash_gate.sh"
          }
        ]
      }
    ]
  }
}
```

`.claude/` is gitignored, so the grant stays local to the operator who made
it. (If the team later decides the grant should be shared and reviewed like
code, remove the `.claude/` ignore line and commit `settings.json` — but be
aware that any future PR could then modify the permission grant, so treat
changes to it with the same scrutiny as changes to `scripts/65`.)

## Keeping the gate honest

- The hook's governed-executor pattern must stay in sync with the
  `allowed_fastboot_scripts` set in `scripts/65_lmi_release_safety_lint.sh`.
  Today both name `scripts/72` as the only live executor. If the executor
  set changes, update both in the same commit.
- `scripts/22_static_check_pmos_v27.sh`-style verification of the hook:
  pipe a fake payload and check the decision, e.g.

  ```sh
  printf '{"tool_input":{"command":"fastboot flash boot x.img"}}' \
    | scripts/hooks/claude_flash_gate.sh
  # -> permissionDecision "deny"
  ```
