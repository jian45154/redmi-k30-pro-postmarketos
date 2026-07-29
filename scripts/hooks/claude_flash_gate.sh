#!/usr/bin/env bash
# Claude Code PreToolUse gate (bringup governance v4).
#
# The repo's own governance chain — not a human prompt — decides whether a
# Bash tool call that changes device or raw-image state may proceed:
#   * governed D110 executor (scripts/72) with a green safety lint -> allow
#   * governed executor with a failing safety lint                 -> deny
#   * any other fastboot state change or raw block-device write    -> deny
#   * everything else -> no opinion (normal permission flow applies)
#
# The D114 Python/PowerShell transition graph is hash-locked and linted
# separately (scripts/65 check 3); it is NOT auto-approved here and falls
# through to the normal permission flow until it is wired to v4 claims.
set -euo pipefail

cd "${CLAUDE_PROJECT_DIR:-$(git rev-parse --show-toplevel)}"

cmd=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("tool_input",{}).get("command",""))')

decide() {
	printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}\n' \
		"$1" "$2"
	exit 0
}

# Governed executor: authorization is delegated to the safety lint, which
# statically re-verifies the whole invoker set before every device session.
if printf '%s' "$cmd" | grep -qE \
	'(^|[[:space:]])(bash[[:space:]]+)?scripts/72_stage_downstream_ssh_wifi_test\.sh'; then
	if bash scripts/65_lmi_release_safety_lint.sh >/dev/null 2>&1; then
		decide allow "governed D110 executor, safety lint green"
	fi
	decide deny "safety lint failed; fix governance before touching the device"
fi

# Raw device/image state changes outside the governed set are never approved.
if printf '%s' "$cmd" | grep -qE \
	'fastboot(\.exe)?[[:space:]]+(flash|boot|reboot|erase|format)([[:space:]]|$)|of=/dev/(sd[a-z]|mmcblk|nvme|block/)'; then # detection regex only; this gate never executes device commands
	decide deny "fastboot/image write outside the governed invoker set (see scripts/65_lmi_release_safety_lint.sh)"
fi

exit 0
