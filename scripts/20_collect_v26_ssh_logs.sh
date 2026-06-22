#!/bin/sh
set -eu

HOST="${1:-172.16.42.1}"
USER="${2:-lmi}"
OUT="${3:-logs/repair-ssh-systemcheck-v26-2026-06-23.txt}"
KNOWN_HOSTS="${KNOWN_HOSTS:-/tmp/lmi_known_hosts}"

mkdir -p "$(dirname "$OUT")"

ssh -o BatchMode=yes \
	-o StrictHostKeyChecking=no \
	-o UserKnownHostsFile="$KNOWN_HOSTS" \
	-o ConnectTimeout=10 \
	"$USER@$HOST" 'sh -s' > "$OUT" <<'REMOTE'
echo "=== date ==="
date
echo "=== uname ==="
uname -a
echo "=== id ==="
id
echo "=== cmdline ==="
cat /proc/cmdline
echo "=== pmOS_init.log ==="
cat /pmOS_init.log 2>&1 || true
echo "=== mounts ==="
mount
echo "=== findmnt ==="
findmnt 2>&1 || true
echo "=== lsblk ==="
lsblk -o NAME,MAJ:MIN,SIZE,TYPE,FSTYPE,LABEL,PARTLABEL,PARTUUID,MOUNTPOINTS 2>&1 || true
echo "=== blkid ==="
blkid 2>&1 || true
echo "=== proc_partitions ==="
cat /proc/partitions
echo "=== ip_addr ==="
ip addr
echo "=== routes ==="
ip route
echo "=== sshd ==="
ps aux | grep sshd | grep -v grep || true
ps aux | grep dropbear | grep -v grep || true
echo "=== systemctl ==="
systemctl is-system-running 2>&1 || true
systemctl --no-pager --failed 2>&1 || true
echo "=== usb_configfs ==="
find /sys/kernel/config/usb_gadget -maxdepth 4 -type f 2>/dev/null | sort | while read -r f; do
	printf "%s=" "$f"
	cat "$f" 2>/dev/null | tr "\n" " "
	echo
done
REMOTE

sha256sum "$OUT"
wc -l "$OUT"
