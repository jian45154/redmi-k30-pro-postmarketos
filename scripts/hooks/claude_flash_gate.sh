#!/usr/bin/env bash
# Claude Code PreToolUse classifier (bringup governance v4).
#
# This hook is not an authorization, receipt, claim, or executor. It only
# prevents the harness permission layer from approving raw state changes and
# lets one exact D110 command reach that executor's own independent gates:
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

# Bash removes backslash-newline pairs before parsing and permits command and
# verb names to be assembled with backslash escapes or adjacent quotes. Scan a
# conservative joined form so those spellings cannot split a raw state change
# across grep lines. The unmodified command is still used by the exact allow
# rule below, so normalization can only widen denial, never auto-approval.
scan_cmd=${cmd//$'\\\n'/}
scan_cmd=${scan_cmd//\\/}
scan_cmd=${scan_cmd//\'/}
scan_cmd=${scan_cmd//\"/}

# Raw device/image state changes outside the governed set are never approved.
# This deliberately matches options between fastboot and its verb (for example
# ``fastboot -s SERIAL flash``) and treats every /dev target as sensitive.
# Run this check before the governed-executor allow rule so a compound Bash
# command can never smuggle a raw state change behind an allowed invocation.
if printf '%s' "$scan_cmd" | grep -qE \
	'fastboot(\.exe)?[^[:cntrl:]]*[[:space:]](flash|boot|reboot|erase|format)([[:space:];&|]|$)|(^|[[:space:];&|])([^[:space:];&|]*/)?dd[[:space:]][^[:cntrl:]]*of=/dev/'; then # detection regex only; this gate never executes device commands
	decide deny "fastboot/image write outside the governed invoker set (see scripts/65_lmi_release_safety_lint.sh)"
fi

# Governed executor: only one complete, canonical command is auto-approved.
# Anchoring the whole string is intentional: quoting, redirection, pipelines,
# command substitution, environment prefixes, and compound commands fall
# through to the normal permission flow instead of inheriting this allow.
if printf '%s' "$cmd" | grep -qE \
	'^((/usr/bin/)?bash[[:space:]]+)?(\./)?scripts/72_stage_downstream_ssh_wifi_test\.sh[[:space:]]+--stage[[:space:]]+ramboot[[:space:]]+(--dry-run|--preflight|--authorize-session|--execute|--revoke-session)[[:space:]]*$'; then
	if bash scripts/65_lmi_release_safety_lint.sh >/dev/null 2>&1; then
		decide allow "governed D110 executor, safety lint green"
	fi
	decide deny "safety lint failed; fix governance before touching the device"
fi

exit 0
