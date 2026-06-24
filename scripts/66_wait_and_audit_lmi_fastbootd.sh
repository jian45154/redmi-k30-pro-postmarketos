#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/66_wait_and_audit_lmi_fastbootd.sh [--quick]

Wait for recovery fastbootd, run the existing read-only fastbootd preflight,
then run the persistent readiness audit. This script does not execute reboot,
boot, flash, erase, format, or partition writes.

Use this after the phone has manually entered fastbootd, or after a separately
approved fastbootd entry command has completed.

--quick shortens the fastbootd polling timeout for current-state checks.
EOF
}

quick=0
while [ "$#" -gt 0 ]; do
	case "$1" in
		--quick)
			quick=1
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

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
report=${LMI_FASTBOOTD_AUDIT_REPORT:-$bundle_dir/FASTBOOTD_AUDIT_GATE.txt}
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}

mkdir -p "$(dirname "$report")"
: > "$report"

log() {
	printf '%s\n' "$*" | tee -a "$report"
}

run_step() {
	local name=$1
	shift
	log "## $name"
	set +e
	"$@" 2>&1 | tee -a "$report"
	local status=${PIPESTATUS[0]}
	set -e
	log "status=$status"
	log
	return "$status"
}

wait_timeout=${LMI_FASTBOOTD_WAIT_TIMEOUT:-120}
wait_interval=${LMI_FASTBOOTD_WAIT_INTERVAL:-2}
if [ "$quick" -eq 1 ]; then
	wait_timeout=3
	wait_interval=1
fi

log "LMI fastbootd wait and readiness audit"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "quick=$quick"
log "bundle_dir=$bundle_dir"
log "rollback_boot=$rollback_boot"
log
log "No reboot, boot, flash, erase, format, or partition write is executed by this script."
log

if ! run_step "wait for recovery fastbootd and run preflight" \
	env LMI_FASTBOOTD_WAIT_TIMEOUT="$wait_timeout" \
	LMI_FASTBOOTD_WAIT_INTERVAL="$wait_interval" \
	scripts/52_wait_lmi_fastbootd.sh; then
	log "fastbootd audit gate: WAITING_FOR_RECOVERY_FASTBOOTD"
	log "report=$report"
	exit 1
fi

if ! run_step "persistent readiness audit" \
	env LMI_ROLLBACK_BOOT_IMG="$rollback_boot" \
	scripts/64_audit_lmi_persistent_readiness.sh; then
	log "fastbootd audit gate: READINESS_AUDIT_FAILED"
	log "report=$report"
	exit 1
fi

log "fastbootd audit gate: OK"
log "report=$report"
