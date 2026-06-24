#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/64_audit_lmi_persistent_readiness.sh

Read-only audit for the lmi r6 mainline/copydown persistent route. This checks
artifact identity, release docs, rollback candidate, dry-run stage guards, and
current fastbootd gate state. It never executes reboot, boot, flash, erase,
format, or partition writes.
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

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-$bundle_dir/xiaomi-lmi-r6-bootmem.img}
export_rootfs=${LMI_PMBOOTSTRAP_EXPORT_ROOTFS:-/tmp/postmarketOS-export/xiaomi-lmi.img}
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}
plan_report=${LMI_PERSISTENT_PLAN_REPORT:-$bundle_dir/PERSISTENT_FLASH_PLAN.txt}
manifest_doc=${LMI_RELEASE_ARCHIVE_MANIFEST:-docs/release/lmi-r6-bootmem-release-manifest-20260624.md}
checklist=${LMI_EXECUTION_CHECKLIST:-docs/release/lmi-r6-bootmem-execution-checklist-20260624.md}
handoff=${LMI_HANDOFF_STATUS:-docs/release/lmi-r6-current-handoff-20260624.md}
report=${LMI_PERSISTENT_READINESS_REPORT:-$bundle_dir/PERSISTENT_READINESS_AUDIT.txt}
fastboot_bin=${FASTBOOT:-fastboot}
fastboot_timeout=${LMI_FASTBOOT_TIMEOUT:-5}

mkdir -p "$(dirname "$report")"
: > "$report"

log() {
	printf '%s\n' "$*" | tee -a "$report"
}

failures=0
warnings=0

fail() {
	log "FAIL: $*"
	failures=$((failures + 1))
}

warn() {
	log "WARN: $*"
	warnings=$((warnings + 1))
}

require_file() {
	local path=$1
	if [ ! -f "$path" ]; then
		fail "missing file: $path"
		return 1
	fi
	return 0
}

sha_of() {
	sha256sum "$1" | awk '{print $1}'
}

getvar() {
	local key=$1
	local output
	set +e
	output=$(timeout "$fastboot_timeout" "$fastboot_bin" getvar "$key" 2>&1)
	local status=$?
	set -e
	printf '%s\n' "$output" | sed -n "s/^$key: //p" | tail -n 1
	return "$status"
}

run_check() {
	local name=$1
	shift
	log "## check: $name"
	set +e
	"$@" 2>&1 | tee -a "$report"
	local status=${PIPESTATUS[0]}
	set -e
	log "status=$status"
	log
	if [ "$status" -ne 0 ]; then
		fail "$name failed with status $status"
	fi
}

log "LMI persistent readiness audit"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "bundle_dir=$bundle_dir"
log
log "No reboot, boot, flash, erase, format, or partition write is executed by this script."
log

for path in \
	"$boot_img" \
	"$manifest" \
	"$rootfs_img" \
	"$export_rootfs" \
	"$rollback_boot" \
	"$plan_report" \
	"$manifest_doc" \
	"$checklist" \
	"$handoff"; do
	require_file "$path" || true
done

if [ "$failures" -eq 0 ]; then
	boot_sha=$(sha_of "$boot_img")
	rootfs_sha=$(sha_of "$rootfs_img")
	export_rootfs_sha=$(sha_of "$export_rootfs")
	rollback_sha=$(sha_of "$rollback_boot")
	rollback_size=$(stat -c '%s' "$rollback_boot")
	rootfs_token="flash-xiaomi-lmi-rootfs-${boot_sha:0:12}-${rootfs_sha:0:12}"
	boot_token="flash-xiaomi-lmi-boot-${boot_sha:0:12}-${rootfs_sha:0:12}"
	rollback_token="rollback-xiaomi-lmi-boot-${rollback_sha:0:16}-${rollback_size}"

	log "artifact identity:"
	log "  boot_img=$boot_img"
	log "  boot_sha256=$boot_sha"
	log "  rootfs_img=$rootfs_img"
	log "  rootfs_sha256=$rootfs_sha"
	log "  export_rootfs=$export_rootfs"
	log "  export_rootfs_sha256=$export_rootfs_sha"
	log "  rollback_boot=$rollback_boot"
	log "  rollback_sha256=$rollback_sha"
	log "  rollback_size=$rollback_size"
	log

	if [ "$export_rootfs_sha" != "$rootfs_sha" ]; then
		fail "pmbootstrap export rootfs hash does not match release rootfs"
	fi

	grep -q "$boot_sha" "$bundle_dir/SHA256SUMS" || fail "boot hash missing from bundle SHA256SUMS"
	grep -q "$rootfs_sha" "$bundle_dir/SHA256SUMS" || fail "rootfs hash missing from bundle SHA256SUMS"
	grep -q "$boot_sha" "$manifest_doc" || fail "boot hash missing from release manifest"
	grep -q "$rootfs_sha" "$manifest_doc" || fail "rootfs hash missing from release manifest"
	grep -q "$boot_sha" "$checklist" || fail "boot hash missing from execution checklist"
	grep -q "$rootfs_sha" "$checklist" || fail "rootfs hash missing from execution checklist"
	grep -q "$rollback_sha" "$checklist" || fail "rollback hash missing from execution checklist"
	grep -q "$rootfs_token" "$checklist" || fail "rootfs execute token missing from checklist"
	grep -q "$boot_token" "$checklist" || fail "boot execute token missing from checklist"
	grep -q "$rollback_token" "$checklist" || fail "rollback execute token missing from checklist"
	grep -q 'RAM-only boot is no longer a prerequisite' "$handoff" || fail "handoff does not record non-RAM prerequisite route decision"
	grep -q 'guarded recovery-fastbootd persistent test' "$handoff" || fail "handoff does not record guarded fastbootd route"
	grep -q 'Do not write `super`' "$checklist" || fail "checklist missing forbidden super boundary"
	grep -q 'Do not touch `super`' "$manifest_doc" || fail "manifest missing forbidden super boundary"
fi

if [ "$failures" -eq 0 ]; then
	run_check "copydown boot verifier" env OUT_DIR="$(dirname "$boot_img")" LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" scripts/46_verify_lmi_copydown_boot.sh
	run_check "rootfs stage dry-run" env LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" LMI_ROOTFS_IMG="$rootfs_img" scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --dry-run
	run_check "boot stage dry-run" env LMI_COPYDOWN_BOOT_IMG="$boot_img" LMI_COPYDOWN_MANIFEST="$manifest" LMI_ROOTFS_IMG="$rootfs_img" scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --dry-run
fi

devices=$(timeout "$fastboot_timeout" "$fastboot_bin" devices 2>&1 || true)
product=$(getvar product || true)
unlocked=$(getvar unlocked || true)
is_userspace=$(getvar is-userspace || true)
boot_size=$(getvar partition-size:boot || true)
userdata_size=$(getvar partition-size:userdata || true)

log "current fastboot gate:"
if [ -n "$devices" ]; then
	printf '%s\n' "$devices" | sed 's/^/  device=/' | tee -a "$report"
else
	log "  device=<none>"
	warn "no fastboot device listed"
fi
log "  product=${product:-}"
log "  unlocked=${unlocked:-}"
log "  is-userspace=${is_userspace:-}"
log "  partition-size:boot=${boot_size:-}"
log "  partition-size:userdata=${userdata_size:-}"
log

if [ "$product" != "lmi" ]; then
	fail "product must be lmi before this route continues"
fi
if [ "$unlocked" != "yes" ]; then
	fail "bootloader must be unlocked before this route continues"
fi
if [ "$is_userspace" = "yes" ]; then
	route_status="READY_FOR_FASTBOOTD_PREFLIGHT"
else
	route_status="WAITING_FOR_RECOVERY_FASTBOOTD"
	warn "device is not in recovery fastbootd yet; writes remain blocked"
fi

log "route_status=$route_status"
log "warnings=$warnings"
log "failures=$failures"
log "report=$report"

if [ "$failures" -ne 0 ]; then
	exit 1
fi

exit 0
