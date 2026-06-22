#!/bin/busybox ash

lmi_trace() {
	tag="$1"
	mkdir -p /tmp/lmi-http
	{
		echo "[$(cat /proc/uptime 2>/dev/null | cut -d' ' -f1)] $tag"
		echo "PMOS_ROOT=${PMOS_ROOT:-}"
		echo "PMOS_BOOT=${PMOS_BOOT:-}"
		echo "SUBPARTITION_DEV=${SUBPARTITION_DEV:-}"
		echo "SUBPARTITION_LOOP=${SUBPARTITION_LOOP:-}"
	} >> /tmp/lmi-trace.log
	lmi_collect "$tag" >/dev/null 2>&1 &
}

lmi_collect() {
	reason="$1"
	mkdir -p /tmp/lmi-http
	report_tmp=/tmp/lmi-http/debug.txt.tmp
	{
		echo "generated=$(date)"
		echo "reason=$reason"
		echo "uptime=$(cat /proc/uptime 2>/dev/null)"
		echo "PMOS_ROOT=${PMOS_ROOT:-}"
		echo "PMOS_BOOT=${PMOS_BOOT:-}"
		echo "SUBPARTITION_DEV=${SUBPARTITION_DEV:-}"
		echo "SUBPARTITION_LOOP=${SUBPARTITION_LOOP:-}"

		echo __LMI_TRACE__
		cat /tmp/lmi-trace.log 2>&1

		echo __PMOS_INIT_LOG__
		cat /pmOS_init.log 2>&1

		echo __CMDLINE__
		cat /proc/cmdline 2>&1

		echo __NETWORK__
		ip addr 2>&1
		ip route 2>&1

		echo __PORTS__
		/usr/bin/busybox-extras netstat -ltnp 2>&1 || /bin/busybox netstat -ltnp 2>&1 || true
		cat /proc/net/tcp 2>&1

		echo __TELNET_HTTP_ERRORS__
		cat /tmp/lmi-telnetd.err /tmp/lmi-httpd.log /tmp/ncm-telnetd.err 2>&1

		echo __PROCESSES__
		ps 2>&1

		echo __MOUNTS__
		mount 2>&1

		echo __PARTITIONS__
		cat /proc/partitions 2>&1
		blkid 2>&1
		losetup -a 2>&1 || true

		echo __DEVICES__
		ls -l /dev/disk/by-partlabel /dev/block/by-name /dev/loop* /dev/sda34* 2>&1
		grep -H '^PARTNAME=' /sys/class/block/*/uevent 2>&1

		echo __USERDATA_FDISK__
		userdata=""
		for candidate in /dev/disk/by-partlabel/userdata /dev/block/by-name/userdata /dev/sda34; do
			if [ -e "$candidate" ]; then
				userdata="$(readlink -f "$candidate" 2>/dev/null || echo "$candidate")"
				break
			fi
		done
		echo "userdata=$userdata"
		if [ -n "$userdata" ]; then
			fdisk -l "$userdata" 2>&1 || true
			fdisk -b 4096 -l "$userdata" 2>&1 || true
		fi

		echo __SYSROOT__
		mountpoint -q /sysroot && echo sysroot_mounted=yes || echo sysroot_mounted=no
		ls -la /sysroot 2>&1
		ls -l /sysroot/sbin/init /sysroot/etc/os-release /sysroot/etc/runlevels/default/sshd 2>&1
		cat /sysroot/etc/os-release 2>&1

		echo __DMESG_TAIL__
		dmesg | tail -n 220
	} > "$report_tmp"
	mv "$report_tmp" /tmp/lmi-http/debug.txt
}

lmi_http_start() {
	if [ -e /tmp/lmi-http-started ]; then
		return 0
	fi
	touch /tmp/lmi-http-started
	mkdir -p /tmp/lmi-http
	echo "lmi boottrace pending" > /tmp/lmi-http/debug.txt
	(
		i=0
		while [ "$i" -lt 120 ]; do
			lmi_collect "periodic_$i" >/dev/null 2>&1
			i=$((i + 1))
			sleep 2
		done
	) &
	/usr/bin/busybox-extras httpd -f -p "${HOST_IP:-172.16.42.1}:8080" -h /tmp/lmi-http >/tmp/lmi-httpd.log 2>&1 &
	lmi_trace "http_start"
}
