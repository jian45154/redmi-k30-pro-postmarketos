#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
pmaports=${PMAPORTS:-/home/microstar/.local/var/pmbootstrap/cache_git/pmaports}
disabled_dir="$pmaports/device/.lmi-overlay-disabled"
tag=${TAG:-20260624}
variant=${VARIANT:-v46-daemon-status-idempotent}

export TAG="$tag"
export PMOS_INSTALL_PASSWORD=${PMOS_INSTALL_PASSWORD:-147147}
export OUT_BOOT=${OUT_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-$variant-$tag.img}
export OUT_USERDATA=${OUT_USERDATA:-$repo/artifacts/images/xiaomi-lmi-$variant-userdata-$tag.img}
export OUT_MANIFEST=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-$variant-full-$tag.manifest}
export EXPORT_DIR=${EXPORT_DIR:-/tmp/postmarketOS-export-$variant}
export LOG=${LOG:-$repo/logs/pmaports-build-$variant-$tag.txt}

mainline_paths=(
	"$pmaports/device/testing/device-xiaomi-lmi"
	"$pmaports/device/testing/firmware-xiaomi-lmi"
	"$pmaports/device/testing/linux-postmarketos-qcom-sm8250-lmi"
)

restore_mainline() {
	local base name disabled

	shopt -s nullglob
	for disabled in "$disabled_dir"/*.lmi-build-disabled; do
		name=${disabled##*/}
		base=${name%.lmi-build-disabled}
		case "$base" in
			device-xiaomi-lmi|firmware-xiaomi-lmi|linux-postmarketos-qcom-sm8250-lmi)
				mkdir -p "$pmaports/device/testing"
				mv "$disabled" "$pmaports/device/testing/$base"
				;;
		esac
	done
	shopt -u nullglob
}

trap restore_mainline EXIT

mkdir -p "$disabled_dir"
for path in "${mainline_paths[@]}"; do
	if [ -e "$path" ]; then
		mv "$path" "$disabled_dir/${path##*/}.lmi-build-disabled"
	fi
done

"$repo/scripts/21_build_pmos_v27_full_reproducible.sh"

{
	echo "variant=$variant"
	echo "purpose=downstream boot/rootfs with RNDIS+SSH baseline and manual Wi-Fi bring-up"
	echo "device_xiaomi_lmi_expected=1-r107"
	echo "linux_xiaomi_lmi_expected=4.19.325-r8"
	echo "ssh_strategy=shelli/postmarketos-base OpenRC SSH as in verified v27 baseline"
	echo "wifi_strategy=SSH-first boot; run static qrtr-ns before CNSS; mount stock Android system/vendor/runtime APEX read-only; mount persist read-only for WLAN MAC; create /data/vendor/wifi sockets; link vendor wlan/qca_cld/WCNSS_qcom_cfg.ini and wlan_mac.bin into /lib/firmware; run vendor cnss-daemon with LD_PRELOAD Android property shim; manual WLAN trigger"
	echo "wifi_services_expected=/usr/sbin/lmi-qrtr-ns /etc/init.d/lmi-qrtr-ns /usr/sbin/lmi-wifi-start /etc/conf.d/lmi-wlan-firmware"
	echo "safety=no flashing or rebooting performed by this build script"
} >> "$OUT_MANIFEST"

cat "$OUT_MANIFEST"
