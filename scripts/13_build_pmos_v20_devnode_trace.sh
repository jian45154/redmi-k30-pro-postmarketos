#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
source_boot=${SOURCE_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-r4-subpartfix-20260623.img}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
mkbootimg=${MKBOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/mkbootimg}
include=$repo/scripts/pmos_http_devnode_trace.inc
out_img=${OUT_IMG:-$repo/artifacts/images/pmos-lmi-devnode-trace-v20-20260623.img}
out_manifest=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-devnode-trace-v20-20260623.manifest}

for file in "$source_boot" "$unpack_bootimg" "$mkbootimg" "$include"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-pmos-v20-build.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/unpack" "$work/ramdisk"
python3 "$unpack_bootimg" --boot_img "$source_boot" --out "$work/unpack" >/dev/null
(
	cd "$work/ramdisk"
	gzip -dc "$work/unpack/ramdisk" | cpio -idmu --quiet
)

marker=$'\ttelnetd -b "${HOST_IP}:23" -l /sbin/pmos_getty &'
awk -v marker="$marker" -v inc="$include" '
	{ print }
	$0 == marker {
		while ((getline line < inc) > 0) print line
		close(inc)
		found = 1
	}
	END { if (!found) exit 42 }
' "$work/ramdisk/init_functions.sh" > "$work/init_functions.sh.new"
mv "$work/init_functions.sh.new" "$work/ramdisk/init_functions.sh"

grep -Fq 'deviceinfo_rootfs_image_sector_size="4096"' \
	"$work/ramdisk/usr/share/deviceinfo/device-xiaomi-lmi"
grep -Fq 'part_count="$(fdisk $_lmi_fb -l "$partition"' \
	"$work/ramdisk/init_functions.sh"
grep -Fq 'lmi_populate_block_devs' "$work/ramdisk/init_functions.sh"
grep -Fq 'mount_subpartitions 2>&1' "$work/ramdisk/init_functions.sh"
grep -Fq '${HOST_IP}:8080' "$work/ramdisk/init_functions.sh"

(
	cd "$work/ramdisk"
	find . -exec touch -h -d '@0' {} +
	find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 --reproducible --quiet | gzip -9 > "$work/devnode-trace-ramdisk.gz"
)

cmdline='androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 androidboot.usbcontroller=a600000.dwc3 swiotlb=2048 loop.max_part=7 cgroup.memory=nokmem,nosocket reboot=panic_warm androidboot.fstab_suffix=qcom androidboot.init_fatal_reboot_target=recovery pmos.debug-shell pmos_boot_uuid=2c2600b1-700f-4bdd-a22c-bb12cc589baa pmos_root_uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370 pmos_rootfsopts=defaults'

python3 "$mkbootimg" \
	--header_version 2 \
	--kernel "$work/unpack/kernel" \
	--ramdisk "$work/devnode-trace-ramdisk.gz" \
	--dtb "$work/unpack/dtb" \
	--pagesize 0x00001000 \
	--base 0x00000000 \
	--kernel_offset 0x00008000 \
	--ramdisk_offset 0x01000000 \
	--second_offset 0x00000000 \
	--tags_offset 0x00000100 \
	--dtb_offset 0x0000000001f00000 \
	--cmdline "$cmdline" \
	--output "$out_img"

{
	echo "artifact=$(basename "$out_img")"
	echo "source_boot=$source_boot"
	echo "source_boot_sha256=$(sha256sum "$source_boot" | cut -d' ' -f1)"
	echo "kernel_sha256=$(sha256sum "$work/unpack/kernel" | cut -d' ' -f1)"
	echo "dtb_sha256=$(sha256sum "$work/unpack/dtb" | cut -d' ' -f1)"
	echo "source_ramdisk_sha256=$(sha256sum "$work/unpack/ramdisk" | cut -d' ' -f1)"
	echo "devnode_trace_ramdisk_sha256=$(sha256sum "$work/devnode-trace-ramdisk.gz" | cut -d' ' -f1)"
	echo "artifact_sha256=$(sha256sum "$out_img" | cut -d' ' -f1)"
	echo "artifact_size=$(stat -c %s "$out_img")"
	echo "cmdline=$cmdline"
} > "$out_manifest"

cat "$out_manifest"
