#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/56_lmi_persistent_flash_plan.sh [--quick]

Generate a read-only execution plan for the lmi persistent fastbootd route.
It runs local/dry-run gates, records current device state, and prints the exact
commands that still require fresh approval. It never executes reboot, boot,
flash, erase, format, or partition writes.

--quick shortens polling checks for the current host/device state.
EOF
}

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-$bundle_dir/xiaomi-lmi-r6-bootmem.img}
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}
report=${LMI_PERSISTENT_PLAN_REPORT:-$bundle_dir/PERSISTENT_FLASH_PLAN.txt}
fastboot_bin=${FASTBOOT:-fastboot}
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

wait_timeout=10
wait_interval=2
post_timeout=10
post_interval=2
if [ "$quick" -eq 1 ]; then
	wait_timeout=3
	wait_interval=1
	post_timeout=3
	post_interval=1
fi

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

run_gate() {
	local name=$1
	shift
	log "## gate: $name"
	set +e
	"$@" 2>&1 | tee -a "$report"
	local status=${PIPESTATUS[0]}
	set -e
	log "gate_status=$status"
	log
	return "$status"
}

for path in "$boot_img" "$manifest" "$rootfs_img" "$rollback_boot"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

boot_sha=$(sha256sum "$boot_img" | awk '{print $1}')
rootfs_sha=$(sha256sum "$rootfs_img" | awk '{print $1}')
rollback_sha=$(sha256sum "$rollback_boot" | awk '{print $1}')

: > "$report"
log "LMI persistent fastbootd execution plan"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "quick=$quick"
log "bundle_dir=$bundle_dir"
log
log "No reboot, boot, flash, erase, format, or partition write is executed by this script."
log
log "artifacts:"
log "  boot_img=$boot_img"
log "  boot_img_sha256=$boot_sha"
log "  manifest=$manifest"
log "  rootfs_img=$rootfs_img"
log "  rootfs_img_sha256=$rootfs_sha"
log "  rollback_boot=$rollback_boot"
log "  rollback_boot_sha256=$rollback_sha"
log

devices=$("$fastboot_bin" devices 2>&1 || true)
product=$(getvar product || true)
unlocked=$(getvar unlocked || true)
is_userspace=$(getvar is-userspace || true)
boot_size=$(getvar partition-size:boot || true)
userdata_size=$(getvar partition-size:userdata || true)

log "current fastboot state:"
if [ -n "$devices" ]; then
	printf '%s\n' "$devices" | sed 's/^/  device=/' | tee -a "$report"
else
	log "  device=<none>"
fi
log "  product=${product:-}"
log "  unlocked=${unlocked:-}"
log "  is-userspace=${is_userspace:-}"
log "  partition-size:boot=${boot_size:-}"
log "  partition-size:userdata=${userdata_size:-}"
log

failures=0
if ! run_gate "fastbootd entry dry-run" scripts/60_stage_lmi_enter_fastbootd.sh --dry-run; then
	log "note: fastbootd entry dry-run should pass while the device is in bootloader fastboot."
	log
fi

if ! run_gate "copydown boot verifier" env OUT_DIR="$(dirname "$boot_img")" LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" scripts/46_verify_lmi_copydown_boot.sh; then
	failures=$((failures + 1))
fi

if ! run_gate "rootfs staged dry-run" env LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" LMI_ROOTFS_IMG="$rootfs_img" scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --dry-run; then
	failures=$((failures + 1))
fi

if ! run_gate "boot staged dry-run" env LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" LMI_ROOTFS_IMG="$rootfs_img" scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --dry-run; then
	failures=$((failures + 1))
fi

if ! run_gate "rollback dry-run default policy" env LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/55_stage_lmi_rollback_boot.sh --dry-run; then
	log "note: rollback default dry-run is expected to fail while is-userspace is not yes."
	log
fi

if ! run_gate "fastbootd wait/preflight current state" env LMI_FASTBOOTD_WAIT_TIMEOUT="$wait_timeout" LMI_FASTBOOTD_WAIT_INTERVAL="$wait_interval" LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" LMI_ROOTFS_IMG="$rootfs_img" scripts/52_wait_lmi_fastbootd.sh; then
	log "note: fastbootd wait is expected to fail until the device enters recovery fastbootd."
	log
fi

if ! run_gate "post-flash reboot dry-run" scripts/61_stage_lmi_reboot_after_flash.sh --dry-run; then
	log "note: post-flash reboot dry-run is expected to fail until the device is in recovery fastbootd after approved flash stages."
	log
fi

if ! run_gate "post-boot monitor current state" scripts/54_monitor_lmi_post_boot.sh --timeout "$post_timeout" --interval "$post_interval"; then
	log "note: post-boot monitor is expected to report only fastboot before a successful rebooted test."
	log
fi

log "approval-required next commands:"
log "  LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute"
log "  scripts/52_wait_lmi_fastbootd.sh"
log "  scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute"
log "  scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute"
log "  LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi scripts/61_stage_lmi_reboot_after_flash.sh --execute"
log "  scripts/54_monitor_lmi_post_boot.sh --timeout 180"
log
log "rollback command if needed, also requiring fresh exact approval:"
log "  scripts/55_stage_lmi_rollback_boot.sh --execute"
log

if [ "$failures" -ne 0 ]; then
	log "plan: FAIL"
	log "One or more local gates that should pass before hardware writes failed."
	exit 1
fi

if [ "$is_userspace" = "yes" ]; then
	log "plan: READY_FOR_FASTBOOTD_PREFLIGHT"
else
	log "plan: WAITING_FOR_RECOVERY_FASTBOOTD"
fi
log "report=$report"
