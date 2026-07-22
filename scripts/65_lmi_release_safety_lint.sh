#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/65_lmi_release_safety_lint.sh

Static safety lint (bringup governance v4). Three checks, all read-only:

1. Invoker set: fastboot state-change command text (flash/boot/reboot/
   erase/format) may only appear in the enumerated script set below. Adding
   a new fastboot-invoking script requires editing this allowlist in review.
2. Forbidden operations: no live shell script may contain erase/format/
   relock commands or flash targets outside the governed set.
3. Governance data: config/governance/constants.json and policy.json must
   validate against scripts/bringup_loop.py, which asserts that the data
   file's forbidden_command_words match the engine's hardcoded copy.

This script never talks to the phone. Literal-line pinning of individual
retired scripts was removed with governance v4; the retired r6 stage
scripts remain listed here only until they are deleted (migration M2').
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	usage
	exit 0
fi
if [ "$#" -ne 0 ]; then
	echo "unknown argument: $1" >&2
	usage >&2
	exit 2
fi

failures=0

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	failures=$((failures + 1))
}

echo "lmi safety lint: fastboot invoker set"
# Scripts permitted to contain fastboot state-change command text.
#   executor (active):  72 — guarded D110 RAM-boot session flow
#   executor (retired): 53 55 60 61 — mainline r6 stages; evidence only,
#                       scheduled for deletion in migration M2'
#   generator/lint:     48 49 57 59 63 65 — emit or check command text,
#                       never execute device state changes
allowed_fastboot_scripts='scripts/48_preflight_lmi_fastbootd.sh
scripts/49_generate_lmi_flash_command_sheet.sh
scripts/53_stage_lmi_fastbootd_flash.sh
scripts/55_stage_lmi_rollback_boot.sh
scripts/57_archive_lmi_release_manifest.sh
scripts/59_release_static_ci.sh
scripts/60_stage_lmi_enter_fastbootd.sh
scripts/61_stage_lmi_reboot_after_flash.sh
scripts/63_generate_lmi_handoff_status.sh
scripts/65_lmi_release_safety_lint.sh
scripts/72_stage_downstream_ssh_wifi_test.sh'
fastboot_invokers=$(git grep -lE \
	'(^|[^A-Za-z_"])("\$fastboot_bin"|fastboot(\.exe)?)[[:space:]]+(flash|boot|reboot|erase|format)([[:space:]]|$)' \
	-- 'scripts/*.sh' | sort || true)
unexpected=$(comm -23 <(printf '%s\n' "$fastboot_invokers") \
	<(printf '%s\n' "$allowed_fastboot_scripts" | sort))
if [ -n "$unexpected" ]; then
	printf '%s\n' "$unexpected" >&2
	fail "fastboot state-change text outside the allowlisted invoker set"
fi

reject_pattern() {
	local label=$1
	local pattern=$2
	local matches
	matches=$(git grep -n -E "$pattern" -- 'scripts/*.sh' \
		| grep -v '^scripts/65_lmi_release_safety_lint.sh:' \
		| grep -v 'never executes' \
		| grep -v 'No reboot, boot, flash, erase, format' \
		| grep -v 'Do not run any' \
		| grep -v 'pmbootstrap flasher flash_rootfs' \
		| grep -v 'without fresh exact approval' \
		|| true)
	if [ -n "$matches" ]; then
		printf '%s\n' "$matches" >&2
		fail "$label"
	fi
}

echo "lmi safety lint: forbidden operations"
reject_pattern "forbidden fastboot flash target in scripts" \
	'fastboot.*flash[[:space:]]+(super|dtbo|vbmeta|persist|modem|modemst|fsg|vendor_boot|init_boot|abl|xbl|tz|hyp|devcfg|bluetooth|userdata|system)'
reject_pattern "forbidden dynamic fastboot flash target in scripts" \
	'"\$fastboot_bin"[[:space:]]+flash[[:space:]]+(super|dtbo|vbmeta|persist|modem|modemst|fsg|vendor_boot|init_boot|abl|xbl|tz|hyp|devcfg|bluetooth|userdata|system)'
reject_pattern "forbidden pmbootstrap flasher write helper in scripts" \
	'flasher[[:space:]]+(flash_kernel|flash_dtbo|flash_vbmeta|sideload)'
reject_pattern "forbidden erase/format/relock in scripts" \
	'(fastboot|"\$fastboot_bin")[^[:cntrl:]]*(erase|format|oem[[:space:]]+lock|flashing[[:space:]]+lock)'

echo "lmi safety lint: governance data consistency"
if ! python3 scripts/bringup_loop.py validate >/dev/null; then
	fail "bringup governance validation failed (constants/policy/active record)"
fi

if [ "$failures" -ne 0 ]; then
	exit 1
fi

echo "lmi safety lint: OK"
