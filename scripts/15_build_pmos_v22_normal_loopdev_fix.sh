#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
source_boot=${SOURCE_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-r4-subpartfix-20260623.img}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
mkbootimg=${MKBOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/mkbootimg}
out_img=${OUT_IMG:-$repo/artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.img}
out_manifest=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.manifest}

for file in "$source_boot" "$unpack_bootimg" "$mkbootimg"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-pmos-v22-build.XXXXXX)
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

cat > "$work/helper.awk" <<'AWK'
function print_populate_function() {
	print "lmi_populate_block_devs() {"
	print "\tmkdir -p /dev /dev/disk/by-partlabel /dev/block/by-name"
	print "\tfor uevent in /sys/class/block/*/uevent; do"
	print "\t\t[ -r \"$uevent\" ] || continue"
	print "\t\tblock=\"${uevent%/uevent}\""
	print "\t\tname=\"${block##*/}\""
	print "\t\t[ -r \"/sys/class/block/$name/dev\" ] || continue"
	print "\t\tmajor_minor=\"$(cat \"/sys/class/block/$name/dev\")\""
	print "\t\t[ -b \"/dev/$name\" ] || mknod \"/dev/$name\" b \"${major_minor%:*}\" \"${major_minor#*:}\" 2>/dev/null || true"
	print "\t\tpartname=\"$(grep '^PARTNAME=' \"$uevent\" 2>/dev/null | cut -d= -f2- || true)\""
	print "\t\tif [ -n \"$partname\" ] && [ -b \"/dev/$name\" ]; then"
	print "\t\t\tln -sf \"../../$name\" \"/dev/disk/by-partlabel/$partname\" 2>/dev/null || true"
	print "\t\t\tln -sf \"../../$name\" \"/dev/block/by-name/$partname\" 2>/dev/null || true"
	print "\t\tfi"
	print "\tdone"
	print "}"
	print ""
}
{
	if ($0 == "mount_subpartitions() {") {
		print_populate_function()
		print
		print "\tlmi_populate_block_devs 2>/dev/null || true"
		next
	}
	print
	if (index($0, "SUBPARTITION_LOOP=\"$(losetup $losetup_args \"$partition\")\"") > 0) {
		print "\t\t\t\t\tfor _lmi_wait in 1 2 3 4 5; do"
		print "\t\t\t\t\t\t_lmi_loop_name=\"${SUBPARTITION_LOOP##*/}\""
		print "\t\t\t\t\t\tlmi_populate_block_devs 2>/dev/null || true"
		print "\t\t\t\t\t\t[ -b \"/dev/${_lmi_loop_name}p2\" ] && break"
		print "\t\t\t\t\t\tsleep 0.2"
		print "\t\t\t\t\tdone"
	}
}
AWK

awk -f "$work/helper.awk" "$work/ramdisk/init_functions.sh" > "$work/init_functions.sh.new"
mv "$work/init_functions.sh.new" "$work/ramdisk/init_functions.sh"

grep -Fq 'deviceinfo_rootfs_image_sector_size="4096"' \
	"$work/ramdisk/usr/share/deviceinfo/device-xiaomi-lmi"
grep -Fq 'part_count="$(fdisk $_lmi_fb -l "$partition"' \
	"$work/ramdisk/init_functions.sh"
grep -Fq 'lmi_populate_block_devs() {' "$work/ramdisk/init_functions.sh"
grep -Fq 'lmi_populate_block_devs 2>/dev/null || true' "$work/ramdisk/init_functions.sh"
grep -Fq '[ -b "/dev/${_lmi_loop_name}p2" ] && break' "$work/ramdisk/init_functions.sh"

(
	cd "$work/ramdisk"
	find . -exec touch -h -d '@0' {} +
	find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 --reproducible --quiet | gzip -9 > "$work/normal-loopdevfix-ramdisk.gz"
)

cmdline='androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 androidboot.usbcontroller=a600000.dwc3 swiotlb=2048 loop.max_part=7 cgroup.memory=nokmem,nosocket reboot=panic_warm androidboot.fstab_suffix=qcom androidboot.init_fatal_reboot_target=recovery pmos_boot_uuid=2c2600b1-700f-4bdd-a22c-bb12cc589baa pmos_root_uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370 pmos_rootfsopts=defaults'

python3 "$mkbootimg" \
	--header_version 2 \
	--kernel "$work/unpack/kernel" \
	--ramdisk "$work/normal-loopdevfix-ramdisk.gz" \
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
	echo "normal_loopdevfix_ramdisk_sha256=$(sha256sum "$work/normal-loopdevfix-ramdisk.gz" | cut -d' ' -f1)"
	echo "artifact_sha256=$(sha256sum "$out_img" | cut -d' ' -f1)"
	echo "artifact_size=$(stat -c %s "$out_img")"
	echo "cmdline=$cmdline"
} > "$out_manifest"

cat "$out_manifest"
