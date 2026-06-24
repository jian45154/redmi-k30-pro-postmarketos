#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/55_stage_lmi_rollback_boot.sh [--dry-run|--execute]

Dry-run validates the rollback boot image and current read-only fastboot state.
Execute mode flashes exactly one partition:
  fastboot flash boot <rollback-boot.img>

Execute mode requires LMI_ROLLBACK_CONFIRM to match the printed token.
By default, execute mode also requires recovery fastbootd (is-userspace=yes).
Set LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT=1 only after separate exact approval
if recovery fastbootd is unavailable and bootloader fastboot rollback is the
chosen recovery path.
EOF
}

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}
fastboot_bin=${FASTBOOT:-fastboot}
fastboot_timeout=${LMI_FASTBOOT_TIMEOUT:-5}
report=${LMI_ROLLBACK_STAGE_REPORT:-$bundle_dir/ROLLBACK_STAGE_RESULT.txt}
mode="dry-run"

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
	output=$(timeout "$fastboot_timeout" "$fastboot_bin" getvar "$key" 2>&1)
	local status=$?
	set -e
	printf '%s\n' "$output" | sed -n "s/^$key: //p" | tail -n 1
	return "$status"
}

[ -f "$rollback_boot" ] || {
	echo "missing rollback boot image: $rollback_boot" >&2
	exit 2
}

rollback_sha=$(sha256sum "$rollback_boot" | awk '{print $1}')
rollback_size=$(stat -c '%s' "$rollback_boot")
confirm_token="rollback-xiaomi-lmi-boot-${rollback_sha:0:16}-${rollback_size}"

python3 - "$rollback_boot" <<'PY'
import struct
import sys
from pathlib import Path

path = Path(sys.argv[1])
head = path.read_bytes()[:4096 + 128]
if len(head) < 4096:
    raise SystemExit("rollback image too small")
if head[:8] != b"ANDROID!":
    raise SystemExit("rollback image is not an Android boot image")
kernel_size = struct.unpack_from("<I", head, 8)[0]
ramdisk_size = struct.unpack_from("<I", head, 16)[0]
page_size = struct.unpack_from("<I", head, 8 + 7 * 4)[0]
if page_size not in (2048, 4096, 8192, 16384):
    raise SystemExit(f"unexpected Android boot page size: {page_size}")
if kernel_size == 0:
    raise SystemExit("rollback image has zero kernel size")
print(f"android_boot_magic=OK kernel_size={kernel_size} ramdisk_size={ramdisk_size} page_size={page_size}")
PY

: > "$report"
log "LMI rollback boot stage"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "mode=$mode"
log "rollback_boot=$rollback_boot"
log "rollback_boot_sha256=$rollback_sha"
log "rollback_boot_size=$rollback_size"
log "allow_bootloader_fastboot=${LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT:-0}"
log
log "This script can only write the boot partition, and only in --execute mode."
log "No write is executed in dry-run or when confirmation/preflight fails."
log
log "Required execute confirmation token:"
log "  LMI_ROLLBACK_CONFIRM=$confirm_token"
log
log "Selected command:"
printf '  %q' "$fastboot_bin" flash boot "$rollback_boot" | tee -a "$report"
log
log

devices=$(timeout "$fastboot_timeout" "$fastboot_bin" devices 2>&1 || true)
product=$(getvar product || true)
unlocked=$(getvar unlocked || true)
is_userspace=$(getvar is-userspace || true)
boot_size_hex=$(getvar partition-size:boot || true)
boot_type=$(getvar partition-type:boot || true)

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
log "  partition-type:boot=${boot_type:-}"
log "  partition-size:boot=${boot_size_hex:-}"

errors=()
if [ "$product" != "lmi" ]; then
	errors+=("product must be lmi, got '${product:-<empty>}'")
fi
if [ "$unlocked" != "yes" ]; then
	errors+=("unlocked must be yes, got '${unlocked:-<empty>}'")
fi
if [ -z "$boot_size_hex" ]; then
	errors+=("missing partition-size:boot")
else
	boot_size_dec=$((boot_size_hex))
	if [ "$rollback_size" -gt "$boot_size_dec" ]; then
		errors+=("rollback boot image too large for boot partition: $rollback_size > $boot_size_dec")
	fi
fi
if [ "$is_userspace" != "yes" ] && [ "${LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT:-0}" != "1" ]; then
	errors+=("recovery fastbootd is required by default; got is-userspace='${is_userspace:-<empty>}'")
fi

if [ "${#errors[@]}" -ne 0 ]; then
	log
	log "rollback preflight: FAIL"
	for error in "${errors[@]}"; do
		log "- $error"
	done
	if [ "$mode" = "execute" ]; then
		log "execute: REFUSED because rollback preflight failed"
		exit 1
	fi
	log "dry-run: preflight failed as reported; no write was executed"
	exit 1
fi

if [ "$mode" = "dry-run" ]; then
	log
	log "dry-run: OK"
	log "No reboot, boot, flash, erase, format, or partition write was executed."
	exit 0
fi

if [ "${LMI_ROLLBACK_CONFIRM:-}" != "$confirm_token" ]; then
	log
	log "execute: REFUSED"
	log "LMI_ROLLBACK_CONFIRM does not match the required token."
	log "No reboot, boot, flash, erase, format, or partition write was executed."
	exit 2
fi

"$fastboot_bin" flash boot "$rollback_boot" 2>&1 | tee -a "$report"
exit "${PIPESTATUS[0]}"
