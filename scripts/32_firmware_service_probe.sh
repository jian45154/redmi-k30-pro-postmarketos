#!/bin/sh
set -eu

section() {
	echo
	echo "=== $1 ==="
}

run() {
	echo "$ $*"
	"$@" 2>&1 || true
}

grep_dmesg() {
	pattern=$1
	dmesg | grep -Ei "$pattern" | tail -240 || true
}

section "identity"
run id
run uname -a
run cat /proc/cmdline

section "firmware inventory"
run find /lib/firmware -maxdepth 5 -type f

section "qualcomm service nodes"
run ls -l /dev/subsys_adsp /dev/subsys_cdsp /dev/subsys_slpi /dev/subsys_venus /dev/subsys_wlan /dev/rmtfs0 /dev/rmtfs1 /dev/qrtr /dev/qrtr* 2>/dev/null
run ls -l /sys/class/remoteproc 2>/dev/null

section "service state"
run rc-status -a
run ps w
for svc in pd-mapper rmtfs tqftpserv qrtr-ns bluetooth wpa_supplicant; do
	if command -v rc-service >/dev/null 2>&1; then
		run rc-service "$svc" status
	fi
done

section "wifi state"
run ip link
if command -v iw >/dev/null 2>&1; then
	run iw dev
else
	echo "iw=<missing>"
fi
run cat /sys/bus/pci/devices/0000:01:00.0/enable 2>/dev/null
run cat /sys/module/wlan/parameters/* 2>/dev/null

section "bluetooth state"
if command -v rfkill >/dev/null 2>&1; then
	run rfkill list
else
	echo "rfkill=<missing>"
fi
run ls -l /sys/class/bluetooth /sys/class/rfkill 2>/dev/null
if command -v hciconfig >/dev/null 2>&1; then
	run hciconfig -a
fi
if command -v btmgmt >/dev/null 2>&1; then
	run btmgmt info
fi
if command -v bluetoothctl >/dev/null 2>&1; then
	run bluetoothctl list
fi

section "audio state"
run cat /proc/asound/cards
run cat /proc/asound/devices
run ls -l /dev/snd
if command -v aplay >/dev/null 2>&1; then
	run aplay -l
fi
if command -v arecord >/dev/null 2>&1; then
	run arecord -l
fi
run find /sys/bus/platform/devices -maxdepth 1 -iname '*audio*' -o -iname '*msm-dai*' -o -iname '*wcd*' -o -iname '*lpass*'

section "focused dmesg firmware services"
grep_dmesg 'firmware|pil|subsys|adsp|cdsp|slpi|venus|wlan|cnss|qca|ath|mhi|rmtfs|qrtr|pdr|service|failed|error'

section "focused dmesg audio bluetooth"
grep_dmesg 'alsa|snd|asoc|audio|apr|q6|wcd|slim|bluetooth|bt|hci|rfkill|failed|error'
