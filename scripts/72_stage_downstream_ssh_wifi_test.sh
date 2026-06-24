#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
variant=${VARIANT:-v35-downstream-sshfirst-wifimanual}
tag=${TAG:-20260624}
boot_img=${DOWNSTREAM_BOOT_IMG:-$repo/artifacts/images/pmos-lmi-normalboot-$variant-$tag.img}
userdata_img=${DOWNSTREAM_USERDATA_IMG:-$repo/artifacts/images/xiaomi-lmi-$variant-userdata-$tag.img}
manifest=${DOWNSTREAM_MANIFEST:-$repo/artifacts/images/pmos-lmi-$variant-full-$tag.manifest}
pmbootstrap_bin=${PMBOOTSTRAP:-pmbootstrap}
fastboot_bin=${FASTBOOT:-fastboot}
pmaports=${PMAPORTS:-/home/microstar/.local/var/pmbootstrap/cache_git/pmaports}
disabled_dir="$pmaports/device/.lmi-overlay-disabled"
mode=dry-run
stage=plan

while [ "$#" -gt 0 ]; do
	case "$1" in
		--stage)
			stage=$2
			shift 2
			;;
		--dry-run)
			mode=dry-run
			shift
			;;
		--execute)
			mode=execute
			shift
			;;
		-h|--help)
			cat <<'EOF'
Usage:
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage plan
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage rootfs [--dry-run|--execute]
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot [--dry-run|--execute]

Stages:
  rootfs   writes only userdata via pmbootstrap flasher flash_rootfs --partition userdata
  ramboot  temporary-boots the downstream boot image via fastboot boot

Execute confirmations:
  rootfs:  DOWNSTREAM_ROOTFS_CONFIRM=flash-downstream-userdata-<sha12>
  ramboot: DOWNSTREAM_RAMBOOT_CONFIRM=boot-downstream-<sha12>
EOF
			exit 0
			;;
		*)
			echo "unknown argument: $1" >&2
			exit 2
			;;
	esac
done

for path in "$boot_img" "$userdata_img" "$manifest"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

boot_sha=$(sha256sum "$boot_img" | awk '{print $1}')
userdata_sha=$(sha256sum "$userdata_img" | awk '{print $1}')
rootfs_token="flash-downstream-userdata-${userdata_sha:0:12}"
ramboot_token="boot-downstream-${boot_sha:0:12}"

getvar() {
	local key=$1
	timeout 5 "$fastboot_bin" getvar "$key" 2>&1 |
		sed -n "s/^$key: //p" | tail -n 1
}

print_state() {
	echo "boot_img=$boot_img"
	echo "boot_sha256=$boot_sha"
	echo "userdata_img=$userdata_img"
	echo "userdata_sha256=$userdata_sha"
	echo "manifest=$manifest"
	echo "fastboot_devices:"
	timeout 5 "$fastboot_bin" devices 2>&1 | sed 's/^/  /' || true
	echo "product=$(getvar product || true)"
	echo "unlocked=$(getvar unlocked || true)"
	echo "is-userspace=$(getvar is-userspace || true)"
	echo "partition-type:userdata=$(getvar partition-type:userdata || true)"
	echo "partition-size:userdata=$(getvar partition-size:userdata || true)"
}

disable_mainline_lmi_overlay() {
	local path
	mkdir -p "$disabled_dir" "$pmaports/device/testing"
	for path in \
		"$pmaports/device/testing/device-xiaomi-lmi" \
		"$pmaports/device/testing/firmware-xiaomi-lmi" \
		"$pmaports/device/testing/linux-postmarketos-qcom-sm8250-lmi"; do
		if [ -e "$path" ]; then
			mv "$path" "$disabled_dir/${path##*/}.downstream-test-disabled"
		fi
	done
}

restore_mainline_lmi_overlay() {
	local disabled name base
	shopt -s nullglob
	for disabled in "$disabled_dir"/*.downstream-test-disabled; do
		name=${disabled##*/}
		base=${name%.downstream-test-disabled}
		mv "$disabled" "$pmaports/device/testing/$base"
	done
	shopt -u nullglob
}

case "$stage" in
	plan)
		print_state
		echo
		echo "Recommended order:"
		echo "1. Reboot LineageOS to bootloader fastboot."
		echo "2. Dry-run rootfs stage."
		echo "3. Execute rootfs stage only after accepting userdata destruction."
		echo "4. Execute ramboot stage to temporary-boot downstream without writing boot."
		echo "5. Monitor RNDIS/SSH first, then run lmi-wifi-start over SSH."
		echo
		echo "rootfs confirmation: DOWNSTREAM_ROOTFS_CONFIRM=$rootfs_token"
		echo "ramboot confirmation: DOWNSTREAM_RAMBOOT_CONFIRM=$ramboot_token"
		;;
	rootfs)
		print_state
		echo "selected_command=$pmbootstrap_bin flasher flash_rootfs --partition userdata"
		echo "required_confirmation=DOWNSTREAM_ROOTFS_CONFIRM=$rootfs_token"
		if [ "$mode" = dry-run ]; then
			echo "dry-run: no write executed"
			exit 0
		fi
		[ "${DOWNSTREAM_ROOTFS_CONFIRM:-}" = "$rootfs_token" ] || {
			echo "execute refused: confirmation token mismatch" >&2
			exit 2
		}
		disable_mainline_lmi_overlay
		trap restore_mainline_lmi_overlay EXIT
		"$pmbootstrap_bin" flasher flash_rootfs --partition userdata
		;;
	ramboot)
		print_state
		echo "selected_command=$fastboot_bin boot $boot_img"
		echo "required_confirmation=DOWNSTREAM_RAMBOOT_CONFIRM=$ramboot_token"
		if [ "$mode" = dry-run ]; then
			echo "dry-run: no boot executed"
			exit 0
		fi
		[ "${DOWNSTREAM_RAMBOOT_CONFIRM:-}" = "$ramboot_token" ] || {
			echo "execute refused: confirmation token mismatch" >&2
			exit 2
		}
		"$fastboot_bin" boot "$boot_img"
		;;
	*)
		echo "unknown stage: $stage" >&2
		exit 2
		;;
esac
