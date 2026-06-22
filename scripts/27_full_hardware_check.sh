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
run uname -a
run id
run cat /etc/os-release
run uptime

section "boot and mounts"
run cat /proc/cmdline
run findmnt
run lsblk -o NAME,MAJ:MIN,SIZE,TYPE,FSTYPE,LABEL,PARTLABEL,PARTUUID,MOUNTPOINTS
run blkid

section "usb gadget and network"
run ip addr
run ip route
run find /sys/kernel/config/usb_gadget -maxdepth 4 -type f
for f in $(find /sys/kernel/config/usb_gadget -maxdepth 4 -type f 2>/dev/null | sort); do
	printf "%s=" "$f"
	cat "$f" 2>/dev/null | tr '\n' ' ' || true
	echo
done

section "display and gpu"
run ls -l /dev/dri /dev/fb* /dev/kgsl* /sys/class/drm /sys/class/graphics 2>/dev/null
for f in /sys/class/drm/*/status /sys/class/drm/*/modes /sys/class/drm/*/enabled /sys/class/drm/*/dpms; do
	[ -e "$f" ] || continue
	printf "%s=" "$f"
	cat "$f" 2>/dev/null || true
done
run cat /sys/class/kgsl/kgsl-3d0/gpu_model
run cat /sys/class/kgsl/kgsl-3d0/gpu_busy_percentage
run ps aux

section "input"
run ls -l /dev/input
run cat /proc/bus/input/devices

section "audio"
run ls -l /dev/snd
run cat /proc/asound/cards
run cat /proc/asound/devices
command -v aplay >/dev/null 2>&1 && run aplay -l
command -v pactl >/dev/null 2>&1 && run pactl list short sinks

section "wifi and bluetooth"
run ip link
command -v iw >/dev/null 2>&1 && run iw dev
command -v rfkill >/dev/null 2>&1 && run rfkill list
command -v hciconfig >/dev/null 2>&1 && run hciconfig -a
run ls -l /sys/class/net
run find /sys/module -maxdepth 1 -iname '*wlan*' -o -iname '*wifi*' -o -iname '*bluetooth*'

section "modem remoteproc firmware"
run ps aux
run ls -l /sys/class/remoteproc
for d in /sys/class/remoteproc/remoteproc*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in name state firmware recovery coredump; do
		[ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f" 2>/dev/null || true
	done
done
run ls -l /dev/subsys* /dev/rmtfs* /dev/qrtr* 2>/dev/null

section "camera and media"
run ls -l /dev/video* /dev/media* /dev/v4l* 2>/dev/null

section "sensors and iio"
run ls -l /sys/bus/iio/devices
for d in /sys/bus/iio/devices/iio:device*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	[ -e "$d/name" ] && cat "$d/name" || true
	find "$d" -maxdepth 1 -type f | sed 's#^.*/##' | sort | head -80
done

section "power battery charging"
run ls -l /sys/class/power_supply
for d in /sys/class/power_supply/*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in type status capacity voltage_now current_now charge_now charge_full temp health present online usb_type; do
		[ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f" 2>/dev/null || true
	done
done

section "thermal"
run ls -l /sys/class/thermal
for d in /sys/class/thermal/thermal_zone*; do
	[ -d "$d" ] || continue
	printf "%s " "$d"
	[ -e "$d/type" ] && printf "type=" && cat "$d/type" 2>/dev/null | tr '\n' ' '
	[ -e "$d/temp" ] && printf "temp=" && cat "$d/temp" 2>/dev/null | tr '\n' ' '
	echo
done

section "storage"
run cat /proc/partitions
run ls -l /dev/block/by-name /dev/disk/by-partlabel 2>/dev/null

section "kernel firmware and hardware errors"
run dmesg

section "focused dmesg summary"
dmesg | grep -Ei 'fail|error|timeout|defer|firmware|remoteproc|subsys|rmtfs|pd-mapper|tqftp|wlan|wifi|ath|qca|bluetooth|bt|audio|alsa|snd|adsp|cdsp|slpi|modem|venus|camera|cam|sensor|iio|drm|dsi|panel|gpu|kgsl|adreno|touch|input|battery|charger|thermal|usb|ufs|sde|mdss' || true
