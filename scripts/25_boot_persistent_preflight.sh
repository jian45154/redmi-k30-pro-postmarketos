#!/bin/sh
set -eu

echo "=== uname ==="
uname -a

echo "=== cmdline relevant ==="
tr ' ' '\n' </proc/cmdline | grep -E 'pmos_|androidboot.bootdevice|androidboot.slot|slot_suffix' || true

echo "=== by-name boot entries ==="
ls -l /dev/block/by-name 2>/dev/null | grep -E ' boot$|boot_a|boot_b|recovery|dtbo|vbmeta|vendor_boot|init_boot' || true

echo "=== resolved boot entries ==="
for p in boot boot_a boot_b recovery dtbo dtbo_a dtbo_b vbmeta vbmeta_a vbmeta_b vendor_boot vendor_boot_a vendor_boot_b init_boot init_boot_a init_boot_b; do
	if [ -e "/dev/block/by-name/$p" ]; then
		r="$(readlink -f "/dev/block/by-name/$p")"
		s="$(blockdev --getsize64 "/dev/block/by-name/$p" 2>/dev/null || true)"
		echo "$p $r $s"
	fi
done

echo "=== root mounts ==="
findmnt / /boot -o SOURCE,FSTYPE,TARGET 2>/dev/null || true

echo "=== battery ==="
cat /sys/class/power_supply/battery/capacity 2>/dev/null || true
cat /sys/class/power_supply/battery/status 2>/dev/null || true

echo "=== block devices around boot ==="
lsblk -b -o NAME,MAJ:MIN,SIZE,TYPE,FSTYPE,LABEL,PARTLABEL,PARTUUID,MOUNTPOINTS | grep -E 'boot|dtbo|vbmeta|recovery|sda|sdb|sdc|sdd|sde' | head -160 || true
