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

section "cpu memory clocks"
run cat /proc/cpuinfo
run cat /proc/meminfo
run ls -l /sys/devices/system/cpu
for d in /sys/devices/system/cpu/cpu[0-9]*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in online cpufreq/scaling_cur_freq cpufreq/scaling_available_frequencies cpufreq/scaling_governor; do
		[ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f" 2>/dev/null || true
	done
done

section "pci and pcie"
run ls -l /sys/bus/pci/devices
for d in /sys/bus/pci/devices/*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in vendor device class subsystem_vendor subsystem_device modalias current_link_speed current_link_width max_link_speed max_link_width enable; do
		[ -e "$d/$f" ] && printf "%s=" "$f" && cat "$d/$f" 2>/dev/null || true
	done
done
command -v lspci >/dev/null 2>&1 && run lspci -nnvv

section "major buses"
run ls -l /sys/bus/i2c/devices
run ls -l /sys/bus/spi/devices
run ls -l /sys/bus/platform/devices

section "firmware files"
run find /lib/firmware -maxdepth 4 -type f

section "services"
run rc-status -a
run ps aux
