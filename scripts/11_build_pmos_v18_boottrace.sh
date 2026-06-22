#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-/mnt/c/Users/microstar/Documents/lmi_linx}
source_boot=${SOURCE_BOOT:-$repo/artifacts/images/pmos-lmi-normalboot-r4-subpartfix-20260623.img}
unpack_bootimg=${UNPACK_BOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/unpack_bootimg}
mkbootimg=${MKBOOTIMG:-/mnt/c/Users/microstar/Latest\ ADB\ Fastboot\ Tool/lmi/sm8250-xiaomi-lmi-boot/tools/ubuntu-mkbootimg/mkbootimg}
boottrace=$repo/scripts/lmi_boottrace.inc
out_img=${OUT_IMG:-$repo/artifacts/images/pmos-lmi-boottrace-v18-20260623.img}
out_manifest=${OUT_MANIFEST:-$repo/artifacts/images/pmos-lmi-boottrace-v18-20260623.manifest}

for file in "$source_boot" "$unpack_bootimg" "$mkbootimg" "$boottrace"; do
	[ -f "$file" ] || { echo "missing input: $file" >&2; exit 1; }
done

work=$(mktemp -d /tmp/lmi-pmos-v18-build.XXXXXX)
cleanup() {
	rm -rf -- "$work"
}
trap cleanup EXIT

mkdir -p "$work/unpack" "$work/ramdisk"
python3 "$unpack_bootimg" --boot_img "$source_boot" --out "$work/unpack" >"$work/unpack.log" 2>&1
(
	cd "$work/ramdisk"
	gzip -dc "$work/unpack/ramdisk" | cpio -idmu --quiet
)

install -m 0755 "$boottrace" "$work/ramdisk/usr/bin/lmi-boottrace"

awk '
	$0 == "mount_root_partition" {
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace before_mount_root_partition"
		print
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace after_mount_root_partition"
		next
	}
	$0 == "exec switch_root /sysroot \"$init\"" {
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace exec_switch_root"
		print
		next
	}
	{ print }
	$0 == "start_unudhcpd" {
		print ""
		print "if [ -r /usr/bin/lmi-boottrace ]; then"
		print "\t. /usr/bin/lmi-boottrace"
		print "\tlmi_http_start"
		print "\tlmi_trace after_start_unudhcpd"
		print "fi"
	}
	$0 == "mount_subpartitions" {
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace after_mount_subpartitions"
	}
	$0 == "wait_root_partition" {
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace after_wait_root_partition"
	}
	$0 == "echo \"Switching root\"" {
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace before_switch_root_cleanup"
	}
	$0 == "echo \"$LOG_PREFIX ERROR: switch_root failed!\" > /dev/kmsg" {
		print "command -v lmi_trace >/dev/null 2>&1 && lmi_trace switch_root_failed"
	}
' "$work/ramdisk/init_2nd.sh" > "$work/init_2nd.sh.new"
mv "$work/init_2nd.sh.new" "$work/ramdisk/init_2nd.sh"

awk '
	$0 == "\ttelnetd -b \"${HOST_IP}:23\" -l /sbin/pmos_getty &" {
		print "\ttelnetd -b \"${HOST_IP}:23\" -l /sbin/pmos_getty 2>/tmp/lmi-telnetd.err &"
		print "\techo \"telnetd_pid=$!\" >> /tmp/lmi-trace.log"
		print "\tcommand -v lmi_trace >/dev/null 2>&1 && lmi_trace debug_shell_telnetd_started"
		next
	}
	{ print }
' "$work/ramdisk/init_functions.sh" > "$work/init_functions.sh.new"
mv "$work/init_functions.sh.new" "$work/ramdisk/init_functions.sh"

grep -Fq 'deviceinfo_rootfs_image_sector_size="4096"' \
	"$work/ramdisk/usr/share/deviceinfo/device-xiaomi-lmi"
grep -Fq 'part_count="$(fdisk $_lmi_fb -l "$partition"' \
	"$work/ramdisk/init_functions.sh"
grep -Fq 'lmi_http_start' "$work/ramdisk/init_2nd.sh"
grep -Fq 'lmi_trace exec_switch_root' "$work/ramdisk/init_2nd.sh"
grep -Fq 'lmi-telnetd.err' "$work/ramdisk/init_functions.sh"

(
	cd "$work/ramdisk"
	find . -exec touch -h -d '@0' {} +
	find . -print0 | LC_ALL=C sort -z | cpio --null -o --format=newc --owner=0:0 --reproducible --quiet | gzip -9 > "$work/boottrace-ramdisk.gz"
)

cmdline='androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 androidboot.usbcontroller=a600000.dwc3 swiotlb=2048 loop.max_part=7 cgroup.memory=nokmem,nosocket androidboot.fstab_suffix=qcom pmos_boot_uuid=2c2600b1-700f-4bdd-a22c-bb12cc589baa pmos_root_uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370 pmos_rootfsopts=defaults'

python3 "$mkbootimg" \
	--header_version 2 \
	--kernel "$work/unpack/kernel" \
	--ramdisk "$work/boottrace-ramdisk.gz" \
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
	echo "boottrace_ramdisk_sha256=$(sha256sum "$work/boottrace-ramdisk.gz" | cut -d' ' -f1)"
	echo "artifact_sha256=$(sha256sum "$out_img" | cut -d' ' -f1)"
	echo "artifact_size=$(stat -c %s "$out_img")"
	echo "cmdline=$cmdline"
} > "$out_manifest"

cat "$out_manifest"
