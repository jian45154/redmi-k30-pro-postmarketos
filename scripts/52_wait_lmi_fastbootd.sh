#!/usr/bin/env bash
set -euo pipefail

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
timeout_s=${LMI_FASTBOOTD_WAIT_TIMEOUT:-120}
interval_s=${LMI_FASTBOOTD_WAIT_INTERVAL:-2}
fastboot_bin=${FASTBOOT:-fastboot}
report=${LMI_FASTBOOTD_WAIT_REPORT:-$bundle_dir/FASTBOOTD_WAIT_RESULT.txt}

boot_img=${LMI_COPYDOWN_BOOT_IMG:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-$bundle_dir/xiaomi-lmi-r6-bootmem.img}

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
log "LMI fastbootd wait result"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "timeout_s=$timeout_s"
log "interval_s=$interval_s"
log "bundle_dir=$bundle_dir"
log "boot_img=$boot_img"
log "manifest=$manifest"
log "rootfs_img=$rootfs_img"
log
log "No reboot, boot, flash, erase, format, or partition write is executed by this script."
log

for path in "$boot_img" "$manifest" "$rootfs_img"; do
	if [ ! -f "$path" ]; then
		log "missing file: $path"
		exit 2
	fi
done

deadline=$((SECONDS + timeout_s))
attempt=0

while [ "$SECONDS" -le "$deadline" ]; do
	attempt=$((attempt + 1))
	devices=$("$fastboot_bin" devices 2>&1 || true)
	product=$(getvar product || true)
	unlocked=$(getvar unlocked || true)
	is_userspace=$(getvar is-userspace || true)

	log "attempt=$attempt seconds=$SECONDS product=${product:-<empty>} unlocked=${unlocked:-<empty>} is-userspace=${is_userspace:-<empty>}"
	if [ -n "$devices" ]; then
		printf '%s\n' "$devices" | sed 's/^/fastboot-device: /' | tee -a "$report"
	else
		log "fastboot-device: <none>"
	fi

	if [ "$is_userspace" = "yes" ]; then
		log
		log "fastbootd detected; running read-only fastbootd preflight."
		LMI_COPYDOWN_BOOT_IMG="$boot_img" \
			LMI_COPYDOWN_MANIFEST="$manifest" \
			LMI_ROOTFS_IMG="$rootfs_img" \
			"$(dirname "$0")/48_preflight_lmi_fastbootd.sh" 2>&1 | tee -a "$report"
		exit "${PIPESTATUS[0]}"
	fi

	if [ "$SECONDS" -le "$deadline" ]; then
		sleep "$interval_s"
	fi
done

log
log "fastbootd wait: FAIL"
log "Timed out before is-userspace became yes."
log "Current state is not sufficient for the recovery fastbootd flashing path."
log "No reboot, boot, flash, erase, format, or partition write was executed."
exit 1
