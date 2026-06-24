#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
aports_src=${APORTS_SRC:-$repo/artifacts/wsl-pmaports}
aports_dst=${APORTS_DST:-/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
mkbootimg=${MKBOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/mkbootimg}

tag=${TAG:-20260623}
out_boot=${OUT_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-$tag.img}
out_userdata=${OUT_USERDATA:-$repo/artifacts/images/xiaomi-lmi-v27-rndis-usbid-userdata-$tag.img}
out_manifest=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-v27-rndis-usbid-full-$tag.manifest}
export_dir=${EXPORT_DIR:-/tmp/postmarketOS-export-v27}
log=${LOG:-$repo/logs/pmaports-build-v27-$tag.txt}
install_password=${PMOS_INSTALL_PASSWORD:-}

[ -n "$install_password" ] || {
	echo "PMOS_INSTALL_PASSWORD must be set locally for v27 builds." >&2
	echo "Do not commit the password; pass it only in the local shell environment." >&2
	exit 1
}

mkdir -p "$repo/artifacts/images" "$(dirname "$log")"

for file in "$unpack_bootimg" "$mkbootimg"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

echo "syncing local pmaports into pmbootstrap cache"
cp -a "$aports_src/device-xiaomi-lmi/." "$aports_dst/device-xiaomi-lmi/"
cp -a "$aports_src/linux-xiaomi-lmi/." "$aports_dst/linux-xiaomi-lmi/"

echo "building packages and installing rootfs"
{
	pmbootstrap checksum linux-xiaomi-lmi
	pmbootstrap checksum device-xiaomi-lmi
	pmbootstrap build linux-xiaomi-lmi
	pmbootstrap build device-xiaomi-lmi
	pmbootstrap install --zap --no-fde --sector-size 4096 --no-sparse --password "$install_password"
	rm -rf "$export_dir"
	pmbootstrap export "$export_dir"
} 2>&1 | tee "$log"

source_boot="$export_dir/boot.img"
source_userdata="/home/microstar/.local/var/pmbootstrap/chroot_native/home/pmos/rootfs/xiaomi-lmi.img"

[ -f "$source_boot" ] || source_boot="/home/microstar/.local/var/pmbootstrap/chroot_rootfs_xiaomi-lmi/boot/boot.img"
[ -f "$source_boot" ] || { echo "missing boot image after export" >&2; exit 1; }
[ -f "$source_userdata" ] || { echo "missing userdata/rootfs image after install: $source_userdata" >&2; exit 1; }

work=$(mktemp -d /tmp/lmi-pmos-v27-build.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/unpack" "$work/ramdisk"
python3 "$unpack_bootimg" --boot_img "$source_boot" --out "$work/unpack" >"$work/unpack.log"
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
	if (index($0, "part_count=\"$(fdisk -l \"$partition\"") > 0) {
		print "\t\t\t_lmi_fdisk_block_size=\"\""
		print "\t\t\t[ -n \"${deviceinfo_rootfs_image_sector_size:-}\" ] && _lmi_fdisk_block_size=\"-b $deviceinfo_rootfs_image_sector_size\""
		print "\t\t\tpart_count=\"$(fdisk $_lmi_fdisk_block_size -l \"$partition\" 2>/dev/null | grep -cE '^ +[0-9]|^'\"$partition\")\""
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

deviceinfo="$work/ramdisk/usr/share/deviceinfo/device-xiaomi-lmi"
grep -Fq 'deviceinfo_rootfs_image_sector_size="4096"' "$deviceinfo"
grep -Fq 'deviceinfo_usb_network_function="rndis.usb0"' "$deviceinfo"
grep -Fq 'deviceinfo_usb_idVendor="0x0525"' "$deviceinfo"
grep -Fq 'deviceinfo_usb_idProduct="0xA4A2"' "$deviceinfo"
grep -Fq 'fdisk $_lmi_fdisk_block_size -l "$partition"' "$work/ramdisk/init_functions.sh"
grep -Fq 'lmi_populate_block_devs() {' "$work/ramdisk/init_functions.sh"
grep -Fq '[ -b "/dev/${_lmi_loop_name}p2" ] && break' "$work/ramdisk/init_functions.sh"

(
	cd "$work/ramdisk"
	find . -exec touch -h -d '@0' {} +
	find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 --reproducible --quiet | gzip -9 > "$work/v27-ramdisk.gz"
)

cmdline="$(sed -n 's/^command line args: //p' "$work/unpack.log")"
[ -n "$cmdline" ] || { echo "missing boot cmdline" >&2; exit 1; }

python3 "$mkbootimg" \
	--header_version 2 \
	--kernel "$work/unpack/kernel" \
	--ramdisk "$work/v27-ramdisk.gz" \
	--dtb "$work/unpack/dtb" \
	--pagesize 0x00001000 \
	--base 0x00000000 \
	--kernel_offset 0x00008000 \
	--ramdisk_offset 0x01000000 \
	--second_offset 0x00000000 \
	--tags_offset 0x00000100 \
	--dtb_offset 0x0000000001f00000 \
	--cmdline "$cmdline" \
	--output "$out_boot"

cp -f "$source_userdata" "$out_userdata"

{
	echo "artifact_boot=$(basename "$out_boot")"
	echo "artifact_userdata=$(basename "$out_userdata")"
	echo "source_boot=$source_boot"
	echo "source_userdata=$source_userdata"
	echo "source_boot_sha256=$(sha256sum "$source_boot" | cut -d' ' -f1)"
	echo "source_userdata_sha256=$(sha256sum "$source_userdata" | cut -d' ' -f1)"
	echo "kernel_sha256=$(sha256sum "$work/unpack/kernel" | cut -d' ' -f1)"
	echo "dtb_sha256=$(sha256sum "$work/unpack/dtb" | cut -d' ' -f1)"
	echo "source_ramdisk_sha256=$(sha256sum "$work/unpack/ramdisk" | cut -d' ' -f1)"
	echo "v27_ramdisk_sha256=$(sha256sum "$work/v27-ramdisk.gz" | cut -d' ' -f1)"
	echo "artifact_boot_sha256=$(sha256sum "$out_boot" | cut -d' ' -f1)"
	echo "artifact_userdata_sha256=$(sha256sum "$out_userdata" | cut -d' ' -f1)"
	echo "artifact_boot_size=$(stat -c %s "$out_boot")"
	echo "artifact_userdata_size=$(stat -c %s "$out_userdata")"
	echo "deviceinfo_rootfs_image_sector_size=4096"
	echo "deviceinfo_usb_network_function=rndis.usb0"
	echo "deviceinfo_usb_idVendor=0x0525"
	echo "deviceinfo_usb_idProduct=0xA4A2"
	echo "loopdevfix=post-export init_functions.sh patch"
	echo "cmdline=$cmdline"
} > "$out_manifest"

cat "$out_manifest"
