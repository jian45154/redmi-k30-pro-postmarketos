#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/62_refresh_lmi_release_docs.sh [--quick]

Refresh the lmi r6 release reports and repository docs from the current local
bundle. This is a read-only maintenance entry point: it does not execute reboot,
boot, flash, erase, format, or partition writes.
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
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}
summary=${LMI_RELEASE_REFRESH_SUMMARY:-$bundle_dir/RELEASE_REFRESH_SUMMARY.txt}

mkdir -p "$(dirname "$summary")"

log() {
	printf '%s\n' "$*" | tee -a "$summary"
}

run_step() {
	local name=$1
	shift
	log "## $name"
	"$@" 2>&1 | tee -a "$summary"
	local status=${PIPESTATUS[0]}
	log "status=$status"
	log
	return "$status"
}

: > "$summary"
log "LMI release docs refresh"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "bundle_dir=$bundle_dir"
log "rollback_boot=$rollback_boot"
log
log "No reboot, boot, flash, erase, format, or partition write is executed by this script."
log

plan_args=()
if [ "$quick" -eq 1 ]; then
	plan_args=(--quick)
fi

run_step "persistent flash route plan" env LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/56_lmi_persistent_flash_plan.sh "${plan_args[@]}"
run_step "approval command sheet" env LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/49_generate_lmi_flash_command_sheet.sh
run_step "release archive manifest" env LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/57_archive_lmi_release_manifest.sh
run_step "execution checklist" env LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/58_generate_lmi_execution_checklist.sh
run_step "release static CI" scripts/59_release_static_ci.sh

log "refresh: OK"
log "summary=$summary"
