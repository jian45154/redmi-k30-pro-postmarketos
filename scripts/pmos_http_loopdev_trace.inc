
	lmi_populate_block_devs() {
		mkdir -p /dev /dev/disk/by-partlabel /dev/block/by-name
		for uevent in /sys/class/block/*/uevent; do
			[ -r "$uevent" ] || continue
			block="${uevent%/uevent}"
			name="${block##*/}"
			[ -r "/sys/class/block/$name/dev" ] || continue
			major_minor="$(cat "/sys/class/block/$name/dev")"
			if [ ! -b "/dev/$name" ]; then
				mknod "/dev/$name" b "${major_minor%:*}" "${major_minor#*:}" 2>/tmp/lmi-mknod.err || true
			fi
			partname="$(grep '^PARTNAME=' "$uevent" 2>/dev/null | cut -d= -f2- || true)"
			if [ -n "$partname" ] && [ -b "/dev/$name" ]; then
				ln -sf "../../$name" "/dev/disk/by-partlabel/$partname" 2>/dev/null || true
				ln -sf "../../$name" "/dev/block/by-name/$partname" 2>/dev/null || true
			fi
		done
	}

	# v21: prove whether loop partition device nodes are the remaining blocker.
	mkdir -p /tmp/lmi-http /mnt/lmi-loopdev-root
	echo "loopdev trace pending" > /tmp/lmi-http/debug.txt
	(
		sleep 2
		report_tmp=/tmp/lmi-http/debug.txt.tmp
		{
			echo "generated=$(date)"
			echo __CMDLINE__
			cat /proc/cmdline 2>&1
			echo __PMOS_INIT_LOG__
			cat /pmOS_init.log 2>&1
			echo __POPULATE_BASE_DEVS__
			lmi_populate_block_devs 2>&1
			echo __BASE_DEVICES__
			ls -l /dev/sda34 /dev/disk/by-partlabel/userdata /dev/block/by-name/userdata 2>&1
			echo __USERDATA_FDISK__
			fdisk -b 4096 -l /dev/sda34 2>&1 || true
			echo __CALL_MOUNT_SUBPARTITIONS__
			mount_subpartitions 2>&1 || true
			echo __AFTER_MOUNT_SUBPARTITIONS__
			echo "PMOS_ROOT=${PMOS_ROOT:-}"
			echo "PMOS_BOOT=${PMOS_BOOT:-}"
			echo "SUBPARTITION_DEV=${SUBPARTITION_DEV:-}"
			echo "SUBPARTITION_LOOP=${SUBPARTITION_LOOP:-}"
			losetup -a 2>&1 || true
			blkid 2>&1
			echo __LOOP_DEVS__
			ls -l /dev/loop* /dev/disk/by-partlabel/pmOS_* /dev/block/by-name/pmOS_* 2>&1
			echo __LOOP_SYSFS__
			grep -H '^PARTNAME=' /sys/class/block/loop*p*/uevent 2>&1
			echo __ROOT_RO_MOUNT__
			if [ -n "${PMOS_ROOT:-}" ]; then
				type="$(get_partition_type "$PMOS_ROOT" 2>/dev/null || true)"
				echo "root_type=$type"
				mount -t "${type:-ext4}" -o ro,noload "$PMOS_ROOT" /mnt/lmi-loopdev-root 2>&1 || true
				mountpoint -q /mnt/lmi-loopdev-root && echo root_mount=ok || echo root_mount=failed
				ls -l /mnt/lmi-loopdev-root/sbin/init /mnt/lmi-loopdev-root/etc/os-release /mnt/lmi-loopdev-root/etc/runlevels/default/sshd 2>&1
				cat /mnt/lmi-loopdev-root/etc/os-release 2>&1
				umount /mnt/lmi-loopdev-root 2>&1 || true
			fi
			echo __PARTITIONS__
			cat /proc/partitions 2>&1
			echo __MOUNTS__
			mount 2>&1
			echo __DMESG_TAIL__
			dmesg | tail -n 240
		} > "$report_tmp"
		mv "$report_tmp" /tmp/lmi-http/debug.txt
	) &
	/usr/bin/busybox-extras httpd -f -p "${HOST_IP}:8080" -h /tmp/lmi-http >/tmp/lmi-httpd.log 2>&1 &
