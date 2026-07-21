#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/65_lmi_release_safety_lint.sh

Static safety lint for the lmi r6 release helpers. It checks that persistent
write/reboot helpers stay within the documented allowlist:

- rootfs stage: pmbootstrap flasher flash_rootfs --partition userdata
- D110 recovery stage: fastboot -s <verified lmi> boot <hash-bound image>
- boot stage: fastboot flash boot <copydown boot image>
- rollback stage: fastboot flash boot <rollback boot image>
- fastbootd entry: fastboot reboot fastboot
- post-flash test reboot: fastboot reboot

This script is read-only and never talks to the phone.
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

require_line() {
	local path=$1
	local expected=$2
	if ! grep -Fxq "$expected" "$path"; then
		fail "missing expected line in $path: $expected"
	fi
}

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

echo "lmi release safety lint: expected command allowlist"
require_line scripts/53_stage_lmi_fastbootd_flash.sh 'rootfs_command=("$pmbootstrap_bin" flasher flash_rootfs --partition userdata)'
require_line scripts/53_stage_lmi_fastbootd_flash.sh 'boot_command=("$fastboot_bin" flash boot "$boot_img")'
require_line scripts/72_stage_downstream_ssh_wifi_test.sh $'\t\t/usr/bin/timeout "$action_deadline_timeout" "$fastboot_bin" -s "$device_serial" boot "$fastboot_candidate_path" >/dev/null 2>&1'
require_line scripts/55_stage_lmi_rollback_boot.sh '"$fastboot_bin" flash boot "$rollback_boot" 2>&1 | tee -a "$report"'
require_line scripts/60_stage_lmi_enter_fastbootd.sh '"$fastboot_bin" reboot fastboot 2>&1 | tee -a "$report"'
require_line scripts/61_stage_lmi_reboot_after_flash.sh '"$fastboot_bin" reboot 2>&1 | tee -a "$report"'

echo "lmi release safety lint: forbidden partition targets"
reject_pattern "forbidden fastboot flash target in scripts" \
	'fastboot.*flash[[:space:]]+(super|dtbo|vbmeta|persist|modem|modemst|fsg|vendor_boot|init_boot|abl|xbl|tz|hyp|devcfg|bluetooth|userdata|system)'
reject_pattern "forbidden dynamic fastboot flash target in scripts" \
	'"\$fastboot_bin"[[:space:]]+flash[[:space:]]+(super|dtbo|vbmeta|persist|modem|modemst|fsg|vendor_boot|init_boot|abl|xbl|tz|hyp|devcfg|bluetooth|userdata|system)'
reject_pattern "forbidden pmbootstrap flasher write helper in scripts" \
	'flasher[[:space:]]+(flash_kernel|flash_dtbo|flash_vbmeta|sideload)'
reject_pattern "forbidden erase/format/relock in scripts" \
	'(fastboot|"\$fastboot_bin")[^[:cntrl:]]*(erase|format|oem[[:space:]]+lock|flashing[[:space:]]+lock)'

if [ "$failures" -ne 0 ]; then
	exit 1
fi

echo "lmi release safety lint: OK"
