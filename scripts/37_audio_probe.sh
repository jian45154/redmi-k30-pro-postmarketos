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

grep_dmesg() {
	pattern=$1
	dmesg | grep -Ei "$pattern" | grep -Eiv 'FTS|TOUCH_UP|Points All Up' | tail -260 || true
}

show_file() {
	f=$1
	[ -e "$f" ] || return 0
	printf "%s=" "$f"
	cat "$f" 2>/dev/null | tr '\n' ' ' || true
	echo
}

section "identity"
run date
run uname -a
run id
run cat /proc/cmdline

section "kernel audio config"
if [ -r /proc/config.gz ]; then
	zcat /proc/config.gz 2>/dev/null | grep -E 'CONFIG_(SND|SND_SOC|QCOM_APR|QRTR|QCOM_PDR|QCOM_Q6V5|QCOM_RMTFS|MSM_ADSPRPC|RPMSG|REMOTEPROC|SLIMBUS|SOUNDWIRE|PINCTRL_LPASS|CLK_GFM_LPASS|TFA9874|WCD938|LPASS|SM8250)' || true
else
	echo "/proc/config.gz=<missing>"
fi

section "alsa enumeration"
run cat /proc/asound/cards
run cat /proc/asound/devices
run cat /proc/asound/pcm
run ls -l /dev/snd
if command -v aplay >/dev/null 2>&1; then
	run aplay -l
	run aplay -L
else
	echo "aplay=<missing>"
fi
if command -v arecord >/dev/null 2>&1; then
	run arecord -l
	run arecord -L
else
	echo "arecord=<missing>"
fi

section "audio platform devices"
run find /sys/bus/platform/devices -maxdepth 1 \( -iname '*audio*' -o -iname '*msm-dai*' -o -iname '*wcd*' -o -iname '*lpass*' -o -iname '*swr*' -o -iname '*slim*' -o -iname '*adsp*' \)
for d in /sys/bus/platform/devices/*audio* /sys/bus/platform/devices/*msm-dai* /sys/bus/platform/devices/*wcd* /sys/bus/platform/devices/*lpass* /sys/bus/platform/devices/*swr* /sys/bus/platform/devices/*slim* /sys/bus/platform/devices/*adsp*; do
	[ -e "$d" ] || continue
	echo "--- $d"
	show_file "$d/uevent"
	show_file "$d/modalias"
	show_file "$d/driver_override"
	run readlink "$d/driver"
done

section "soundwire and slimbus"
run ls -l /sys/bus/soundwire/devices /sys/bus/slimbus/devices 2>/dev/null
run find /sys/bus/soundwire/devices /sys/bus/slimbus/devices -maxdepth 2 -type f 2>/dev/null

section "adsp apr pdr services"
run ls -l /dev/subsys_adsp /dev/subsys_cdsp /dev/subsys_slpi /dev/rmtfs0 /dev/rmtfs1 /dev/qrtr /dev/qrtr* 2>/dev/null
run ls -l /sys/class/remoteproc 2>/dev/null
run find /sys/kernel/debug -maxdepth 3 \( -iname '*apr*' -o -iname '*qrtr*' -o -iname '*pdr*' -o -iname '*adsp*' -o -iname '*audio*' \) 2>/dev/null
if command -v rc-status >/dev/null 2>&1; then
	run rc-status -a
fi
if command -v rc-service >/dev/null 2>&1; then
	for svc in pd-mapper rmtfs tqftpserv qrtr-ns; do
		run rc-service "$svc" status
	done
fi
run ps w

section "firmware inventory audio"
run find /lib/firmware -maxdepth 6 \( -iname '*adsp*' -o -iname '*audio*' -o -iname '*wcd*' -o -iname '*tfa*' -o -iname '*q6*' -o -iname '*sm8250*' -o -iname '*.mbn' -o -iname '*.mdt' -o -iname '*.b[0-9][0-9]' \)

section "focused dmesg audio"
grep_dmesg 'alsa|asoc|snd|sound|audio|apr|q6|q6asm|q6afe|q6adm|adsp|adsprpc|lpass|wcd|bolero|soundwire|swr|slim|tfa|codec|defer|firmware|pdr|qrtr|failed|error|timeout'
