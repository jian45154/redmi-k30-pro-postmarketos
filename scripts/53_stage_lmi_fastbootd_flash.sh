#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs [--dry-run|--execute]
  scripts/53_stage_lmi_fastbootd_flash.sh --stage boot [--dry-run|--execute]

Default mode is --dry-run. Execute mode performs exactly one persistent write
after read-only preflight passes and LMI_FLASH_CONFIRM matches the printed
confirmation token.

This script never flashes more than one partition per invocation.
EOF
}

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-$bundle_dir/xiaomi-lmi-r6-bootmem.img}
export_rootfs=${LMI_PMBOOTSTRAP_EXPORT_ROOTFS:-/tmp/postmarketOS-export/xiaomi-lmi.img}
fastboot_bin=${FASTBOOT:-fastboot}
pmbootstrap_bin=${PMBOOTSTRAP:-pmbootstrap}
report=${LMI_FLASH_STAGE_REPORT:-$bundle_dir/FLASH_STAGE_RESULT.txt}

stage=""
mode="dry-run"

while [ "$#" -gt 0 ]; do
	case "$1" in
		--stage)
			stage=${2:-}
			shift 2
			;;
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

case "$stage" in
	rootfs|boot)
		;;
	*)
		echo "missing or invalid --stage; expected rootfs or boot" >&2
		usage >&2
		exit 2
		;;
esac

mkdir -p "$(dirname "$report")"

for path in "$boot_img" "$manifest" "$rootfs_img"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

boot_sha=$(sha256sum "$boot_img" | awk '{print $1}')
rootfs_sha=$(sha256sum "$rootfs_img" | awk '{print $1}')
confirm_token="flash-xiaomi-lmi-${stage}-${boot_sha:0:12}-${rootfs_sha:0:12}"

rootfs_command=("$pmbootstrap_bin" flasher flash_rootfs --partition userdata)
boot_command=("$fastboot_bin" flash boot "$boot_img")

{
	echo "LMI staged fastbootd flash"
	echo "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "mode=$mode"
	echo "stage=$stage"
	echo "bundle_dir=$bundle_dir"
	echo "boot_img=$boot_img"
	echo "boot_img_sha256=$boot_sha"
	echo "manifest=$manifest"
	echo "rootfs_img=$rootfs_img"
	echo "rootfs_img_sha256=$rootfs_sha"
	echo "export_rootfs=$export_rootfs"
	echo
	echo "This script requires recovery fastbootd and only writes one selected stage."
	echo "It never writes super, dtbo, vbmeta, persist, modem/EFS/calibration, vendor_boot, init_boot, or bootloader lock state."
	echo
	echo "Required execute confirmation token:"
	echo "  LMI_FLASH_CONFIRM=$confirm_token"
	echo
	echo "Selected command:"
	if [ "$stage" = "rootfs" ]; then
		printf '  %q' "${rootfs_command[@]}"
		echo
	else
		printf '  %q' "${boot_command[@]}"
		echo
	fi
	echo
} | tee "$report"

if [ "$stage" = "rootfs" ]; then
	if [ ! -f "$export_rootfs" ]; then
		echo "missing pmbootstrap export rootfs: $export_rootfs" | tee -a "$report"
		exit 2
	fi
	export_rootfs_sha=$(sha256sum "$export_rootfs" | awk '{print $1}')
	{
		echo "pmbootstrap_export_rootfs_sha256=$export_rootfs_sha"
		if [ "$export_rootfs_sha" != "$rootfs_sha" ]; then
			echo "rootfs hash mismatch: pmbootstrap export does not match release bundle"
			echo "Refusing rootfs stage because pmbootstrap flasher would not prove the exact bundled rootfs."
		fi
	} | tee -a "$report"
	if [ "$export_rootfs_sha" != "$rootfs_sha" ]; then
		exit 1
	fi
fi

if [ "$mode" = "dry-run" ]; then
	{
		echo
		echo "dry-run: OK"
		echo "No reboot, boot, flash, erase, format, or partition write was executed."
		echo "To execute this one stage after fresh exact approval, use --execute with the token above."
	} | tee -a "$report"
	exit 0
fi

if [ "${LMI_FLASH_CONFIRM:-}" != "$confirm_token" ]; then
	{
		echo
		echo "execute: REFUSED"
		echo "LMI_FLASH_CONFIRM does not match the required token."
		echo "No reboot, boot, flash, erase, format, or partition write was executed."
	} | tee -a "$report"
	exit 2
fi

{
	echo
	echo "running read-only fastbootd preflight before write"
} | tee -a "$report"

LMI_COPYDOWN_BOOT_IMG="$boot_img" \
	LMI_COPYDOWN_MANIFEST="$manifest" \
	LMI_ROOTFS_IMG="$rootfs_img" \
	"$(dirname "$0")/48_preflight_lmi_fastbootd.sh" 2>&1 | tee -a "$report"
preflight_status=${PIPESTATUS[0]}
if [ "$preflight_status" -ne 0 ]; then
	echo "execute: REFUSED because preflight failed" | tee -a "$report"
	exit "$preflight_status"
fi

if [ "$stage" = "rootfs" ]; then
	"${rootfs_command[@]}" 2>&1 | tee -a "$report"
	exit "${PIPESTATUS[0]}"
fi

"${boot_command[@]}" 2>&1 | tee -a "$report"
exit "${PIPESTATUS[0]}"
