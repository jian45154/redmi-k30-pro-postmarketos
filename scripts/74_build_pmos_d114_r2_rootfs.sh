#!/usr/bin/env bash
# Build the D114 P2 r2 "most complete" base rootfs (device r144 + kernel r15).
#
# Same-type flow as scripts/21_build_pmos_v27_full_reproducible.sh and the
# lmi_linx build_lmi_greetd_rootfs_artifact.sh, adapted for the D114 track:
# - package sources come from artifacts/d114-pmaports (NOT the P1-frozen
#   artifacts/wsl-pmaports tree; see artifacts/d114-pmaports/README.md);
# - the produced raw userdata is copied into the dated private build
#   directory for the injection pipeline, together with a manifest.
#
# Requires: pmbootstrap (sudo-capable session), PMOS_INSTALL_PASSWORD.
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
aports_src=${APORTS_SRC:-$repo/artifacts/d114-pmaports}
aports_dst=${APORTS_DST:-$HOME/.local/var/pmbootstrap/cache_git/pmaports/device/downstream}
rootfs_source=${PMOS_ROOTFS_SOURCE:-$HOME/.local/var/pmbootstrap/chroot_native/home/pmos/rootfs/xiaomi-lmi.img}
pmbootstrap=${PMBOOTSTRAP:-pmbootstrap}

tag=${TAG:-20260722}
build_dir=${BUILD_DIR:-$repo/private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-build-$tag}
out_userdata=$build_dir/xiaomi-lmi-d114-r2-most-complete-userdata-$tag.img
out_manifest=$build_dir/xiaomi-lmi-d114-r2-most-complete-userdata-$tag.manifest
log=${LOG:-$repo/logs/pmaports-build-d114-r2-$tag.txt}
install_password=${PMOS_INSTALL_PASSWORD:-}

expected_device_pkgrel=144
expected_kernel_pkgrel=15

[ -n "$install_password" ] || {
	echo "PMOS_INSTALL_PASSWORD must be set locally for D114 r2 builds." >&2
	echo "Do not commit the password; pass it only in the local shell environment." >&2
	exit 1
}
case "$install_password" in
	*$'\n'*|*$'\r'*) echo "PMOS_INSTALL_PASSWORD must not contain a newline" >&2; exit 1 ;;
esac

for pkg in device-xiaomi-lmi linux-xiaomi-lmi; do
	[ -f "$aports_src/$pkg/APKBUILD" ] || { echo "missing aport: $aports_src/$pkg" >&2; exit 1; }
done
grep -qx "pkgrel=$expected_device_pkgrel" "$aports_src/device-xiaomi-lmi/APKBUILD" ||
	{ echo "device-xiaomi-lmi is not r$expected_device_pkgrel" >&2; exit 1; }
grep -qx "pkgrel=$expected_kernel_pkgrel" "$aports_src/linux-xiaomi-lmi/APKBUILD" ||
	{ echo "linux-xiaomi-lmi is not r$expected_kernel_pkgrel" >&2; exit 1; }
grep -q '^SKIP' "$aports_src/linux-xiaomi-lmi/APKBUILD" &&
	{ echo "kernel APKBUILD must not carry SKIP checksums" >&2; exit 1; }
grep -q 'runlevels/default/lmi-wlan-on' "$aports_src/device-xiaomi-lmi/APKBUILD" ||
	{ echo "device APKBUILD lacks the lmi-wlan-on runlevel link" >&2; exit 1; }
grep -q 'runlevels/default/lmi-cnss-fs-ready' "$aports_src/device-xiaomi-lmi/APKBUILD" ||
	{ echo "device APKBUILD lacks the lmi-cnss-fs-ready runlevel link" >&2; exit 1; }

[ "$("$pmbootstrap" config device)" = xiaomi-lmi ] || { echo "pmbootstrap device is not xiaomi-lmi" >&2; exit 1; }
[ "$("$pmbootstrap" config ui)" = phosh ] || { echo "pmbootstrap ui must be phosh (v114 baseline parity)" >&2; exit 1; }
[ "$("$pmbootstrap" config service_manager)" = openrc ] || { echo "pmbootstrap service_manager must be openrc" >&2; exit 1; }

mkdir -p "$build_dir" "$(dirname "$log")"
chmod 700 "$build_dir"
for output in "$out_userdata" "$out_manifest"; do
	[ ! -e "$output" ] || { echo "refusing to overwrite output: $output" >&2; exit 1; }
done

echo "syncing D114 aports into pmbootstrap cache"
mkdir -p "$aports_dst"
for pkg in device-xiaomi-lmi linux-xiaomi-lmi; do
	rm -rf "$aports_dst/$pkg"
	cp -a "$aports_src/$pkg" "$aports_dst/$pkg"
done

echo "building packages and installing rootfs (log: $log)"
{
	"$pmbootstrap" checksum linux-xiaomi-lmi
	"$pmbootstrap" checksum device-xiaomi-lmi
	"$pmbootstrap" build --force linux-xiaomi-lmi
	"$pmbootstrap" build --force device-xiaomi-lmi
	"$pmbootstrap" install --zap --no-fde --sector-size 4096 --no-sparse --password "$install_password"
} 2>&1 | awk -v secret="$install_password" '{ while ((i = index($0, secret)) != 0) { $0 = substr($0, 1, i - 1) "[REDACTED]" substr($0, i + length(secret)) } print }' | tee "$log"

[ -f "$rootfs_source" ] || { echo "missing rootfs image after install: $rootfs_source" >&2; exit 1; }

cp --reflink=never "$rootfs_source" "$out_userdata"
chmod 600 "$out_userdata"

device_apkbuild_sha256=$(sha256sum "$aports_src/device-xiaomi-lmi/APKBUILD" | cut -d' ' -f1)
kernel_apkbuild_sha256=$(sha256sum "$aports_src/linux-xiaomi-lmi/APKBUILD" | cut -d' ' -f1)
{
	echo "variant=d114-r2-most-complete"
	echo "tag=$tag"
	echo "artifact_userdata=$(basename "$out_userdata")"
	echo "artifact_userdata_sha256=$(sha256sum "$out_userdata" | cut -d' ' -f1)"
	echo "artifact_userdata_size=$(stat -c %s "$out_userdata")"
	echo "source_userdata=$rootfs_source"
	echo "device_package=device-xiaomi-lmi=1-r$expected_device_pkgrel"
	echo "kernel_package=linux-xiaomi-lmi=4.19.325-r$expected_kernel_pkgrel"
	echo "device_apkbuild_sha256=$device_apkbuild_sha256"
	echo "kernel_apkbuild_sha256=$kernel_apkbuild_sha256"
	echo "aports_source=artifacts/d114-pmaports"
	echo "pmbootstrap_ui=phosh"
	echo "pmbootstrap_service_manager=openrc"
	echo "sector_size=4096"
	echo "purpose=D114 P2 r2 base rootfs: wlan runlevel links + rootctl + pd-mapper service foundation"
	echo "note=UUIDs are normalized to the D110 boot pairing by scripts/75_stage_d114_r2_candidate.sh"
} > "$out_manifest"

cat "$out_manifest"
