#!/bin/sh
set -eu

section() {
	echo
	echo "=== $1 ==="
}

run() {
	echo "\$ $*"
	"$@" 2>&1 || true
}

section "identity"
run date
run cat /proc/sys/kernel/random/boot_id
run uptime
run uname -a
run id

section "boot and mounts"
run cat /proc/cmdline
for target in / /boot /dev /sys /proc /run /tmp; do
	run findmnt "$target"
done
run lsblk -o NAME,MAJ:MIN,SIZE,TYPE,FSTYPE,LABEL,PARTLABEL,MOUNTPOINTS
run blkid /dev/loop0p1 /dev/loop0p2

section "usb network ssh"
run ip addr show usb0
run ip route
run ps aux

section "display baseline"
run ls -l /dev/dri /dev/kgsl-3d0 /sys/class/drm 2>/dev/null
for f in /sys/class/drm/*/status /sys/class/drm/*/modes /sys/class/drm/*/enabled /sys/class/drm/*/dpms; do
	[ -e "$f" ] || continue
	printf "%s=" "$f"
	cat "$f" 2>/dev/null || true
done
for cmd in modetest kmscube weston tinydm drm_info fbset; do
	if command -v "$cmd" >/dev/null 2>&1; then
		echo "$cmd=$(command -v "$cmd")"
	else
		echo "$cmd=<missing>"
	fi
done

section "power"
for d in /sys/class/power_supply/*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in type status capacity voltage_now current_now temp health present online; do
		[ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f" 2>/dev/null || true
	done
done

section "focused dmesg"
dmesg | grep -Ei 'pmOS|loop0|EXT4|drm|dsi|panel|kgsl|adreno|usb0|rndis|ssh|wlan|bluetooth|audio|alsa|snd|fail|error|timeout|firmware' || true
