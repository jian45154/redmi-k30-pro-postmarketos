#!/usr/bin/env sh
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
	dmesg | grep -Ei "$pattern" | grep -Eiv 'FTS|TOUCH_UP|Points All Up' | tail -260 || true
}

active=${LMI_PROBE_ACTIVE:-0}

section "identity"
run id
run uname -a
run cat /proc/cmdline
run cat /proc/device-tree/reserved-memory/pil_wlan_fw_region@86700000/compatible
run hexdump -Cv /proc/device-tree/reserved-memory/pil_wlan_fw_region@86700000/qcom,client-id

section "rmtfs device nodes"
run ls -l /dev/qcom_rmtfs* /dev/qcom_rmtfs_uio* /dev/rmtfs* /dev/qrtr* /dev/uio* /dev/mem 2>/dev/null
run ls -l /sys/bus/platform/drivers/qcom_rmtfs_mem /sys/bus/platform/drivers/qcom_rmtfs_mem/* 2>/dev/null

section "stock firmware partitions"
run blkid /dev/disk/by-partlabel/modem /dev/disk/by-partlabel/bluetooth /dev/disk/by-partlabel/dsp 2>/dev/null
run mount | grep -E 'firmware_mnt|fw-modem|fw-bluetooth|fw-dsp' 2>/dev/null
run ls -l /mnt/vendor/firmware_mnt/image/qca6390/amss20.bin /lib/firmware/qca6390/amss20.bin 2>/dev/null
run find /lib/firmware -maxdepth 3 -type f -o -type l

if [ "$active" = 1 ]; then
	section "active service start"
	for svc in lmi-firmware-mount pd-mapper rmtfs tqftpserv wpa_supplicant; do
		if command -v rc-service >/dev/null 2>&1; then
			run rc-service "$svc" start
			run rc-service "$svc" status
		fi
	done
fi

section "service state"
if command -v rc-status >/dev/null 2>&1; then
	run rc-status -a
fi
for svc in lmi-firmware-mount pd-mapper rmtfs tqftpserv qrtr-ns wpa_supplicant bluetooth; do
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
run cat /sys/bus/pci/devices/0000:01:00.0/vendor 2>/dev/null
run cat /sys/bus/pci/devices/0000:01:00.0/device 2>/dev/null
run cat /sys/bus/pci/devices/0000:01:00.0/enable 2>/dev/null
run cat /sys/module/wlan/parameters/* 2>/dev/null
run ls -l /sys/class/net /sys/class/wlan /sys/kernel/cnss 2>/dev/null

section "focused dmesg"
grep_dmesg 'rmtfs|qcom_rmtfs|qrtr|pdr|pd-mapper|tqftp|subsys|wlan|cnss|qca|ath|mhi|firmware|amss20|bdwlan|regdb|failed|error|timeout'
