#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/60_stage_lmi_enter_fastbootd.sh [--dry-run|--execute]

Dry-run validates the current read-only fastboot state and prints the exact
confirmation token for entering recovery fastbootd.

Execute mode runs exactly one hardware-state command:
  fastboot reboot fastboot

Execute mode requires fresh exact approval and:
  LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi
EOF
}

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
fastboot_bin=${FASTBOOT:-fastboot}
report=${LMI_FASTBOOTD_REBOOT_REPORT:-$bundle_dir/FASTBOOTD_REBOOT_STAGE.txt}
mode="dry-run"
confirm_token="enter-fastbootd-xiaomi-lmi"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--dry-run)
			mode="dry-run"
			shift
			;;
		--execute)
			mode="execute"
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown argument: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

mkdir -p "$(dirname "$report")"

log() {
	printf '%s\n' "$*" | tee -a "$report"
}

getvar() {
	local key=$1
	local output
	set +e
	output=$("$fastboot_bin" getvar "$key" 2>&1)
	local status=$?
	set -e
	printf '%s\n' "$output" | sed -n "s/^$key: //p" | tail -n 1
	return "$status"
}

: > "$report"
log "LMI enter recovery fastbootd stage"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "mode=$mode"
log
log "This script can only run: fastboot reboot fastboot"
log "No reboot is executed in dry-run or when confirmation/preflight fails."
log
log "Required execute confirmation token:"
log "  LMI_FASTBOOTD_REBOOT_CONFIRM=$confirm_token"
log
log "Selected command:"
printf '  %q' "$fastboot_bin" reboot fastboot | tee -a "$report"
log
log

devices=$("$fastboot_bin" devices 2>&1 || true)
product=$(getvar product || true)
unlocked=$(getvar unlocked || true)
is_userspace=$(getvar is-userspace || true)

log "fastboot device list:"
if [ -n "$devices" ]; then
	printf '%s\n' "$devices" | sed 's/^/  /' | tee -a "$report"
else
	log "  <none>"
fi
log
log "preflight:"
log "  product=${product:-}"
log "  unlocked=${unlocked:-}"
log "  is-userspace=${is_userspace:-}"

errors=()
if [ -z "$devices" ]; then
	errors+=("no fastboot device detected")
fi
if [ "$product" != "lmi" ]; then
	errors+=("product must be lmi, got '${product:-<empty>}'")
fi
if [ "$unlocked" != "yes" ]; then
	errors+=("unlocked must be yes, got '${unlocked:-<empty>}'")
fi
if [ "$is_userspace" = "yes" ]; then
	errors+=("device is already in recovery fastbootd; reboot command is unnecessary")
fi

if [ "${#errors[@]}" -ne 0 ]; then
	log
	log "fastbootd reboot preflight: FAIL"
	for error in "${errors[@]}"; do
		log "- $error"
	done
	if [ "$mode" = "execute" ]; then
		log "execute: REFUSED because preflight failed"
		exit 1
	fi
	log "dry-run: preflight failed as reported; no reboot was executed"
	exit 1
fi

if [ "$mode" = "dry-run" ]; then
	log
	log "dry-run: OK"
	log "No reboot, boot, flash, erase, format, or partition write was executed."
	exit 0
fi

if [ "${LMI_FASTBOOTD_REBOOT_CONFIRM:-}" != "$confirm_token" ]; then
	log
	log "execute: REFUSED"
	log "LMI_FASTBOOTD_REBOOT_CONFIRM does not match the required token."
	log "No reboot, boot, flash, erase, format, or partition write was executed."
	exit 2
fi

"$fastboot_bin" reboot fastboot 2>&1 | tee -a "$report"
exit "${PIPESTATUS[0]}"
