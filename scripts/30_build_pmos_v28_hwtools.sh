#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
tag=${TAG:-20260623}

export TAG="$tag"
export OUT_BOOT=${OUT_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v28-hwtools-$tag.img}
export OUT_USERDATA=${OUT_USERDATA:-$repo/artifacts/images/xiaomi-lmi-v28-hwtools-userdata-$tag.img}
export OUT_MANIFEST=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-v28-hwtools-full-$tag.manifest}
export EXPORT_DIR=${EXPORT_DIR:-/tmp/postmarketOS-export-v28-hwtools}
export LOG=${LOG:-$repo/logs/pmaports-build-v28-hwtools-$tag.txt}

echo "Building v28 hardware-tools image set."
echo "This script builds and exports images only; it does not flash or reboot the device."
echo "Output boot: $OUT_BOOT"
echo "Output userdata: $OUT_USERDATA"
echo "Output manifest: $OUT_MANIFEST"

"$repo/scripts/21_build_pmos_v27_full_reproducible.sh"

{
	echo "hardware_tools=alsa-utils bluez bluez-deprecated iw kmscube libdrm-tests mesa-demos mesa-utils tinydm weston wpa_supplicant"
	echo "purpose=display-audio-mic-wifi-bluetooth enablement baseline"
} >> "$OUT_MANIFEST"

cat "$OUT_MANIFEST"
