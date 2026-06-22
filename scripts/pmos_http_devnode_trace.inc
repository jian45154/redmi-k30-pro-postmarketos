
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

	# v20: prove whether missing /dev block nodes are the remaining blocker.
	mkdir -p /tmp/lmi-http /mnt/lmi-devnode-root
	echo "devnode trace pending" > /tmp/lmi-http/debug.txt
	(
		sleep 2
		report_tmp=/tmp/lmi-http/debug.txt.tmp
		{
			echo "generated=$(date)"
			echo __CMDLINE__
			cat /proc/cmdline 2>&1
			echo __PMOS_INIT_LOG__
			cat /pmOS_init.log 2>&1
			echo __DEV_BEFORE__
			ls -l /dev/sda34 /dev/disk/by-partlabel /dev/block/by-name 2>&1
			echo __SYSFS_USERDATA__
			grep -H '^PARTNAME=userdata$' /sys/class/block/*/uevent 2>&1
			echo __POPULATE_BLOCK_DEVS__
			lmi_populate_block_devs 2>&1
			cat /tmp/lmi-mknod.err 2>/dev/null || true
			echo __DEV_AFTER__
			ls -l /dev/sda /dev/sda34 /dev/disk/by-partlabel/userdata /dev/block/by-name/userdata 2>&1
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
			echo __BEFORE_MOUNT_SUBPARTITIONS__
			echo "PMOS_ROOT=${PMOS_ROOT:-}"
			echo "PMOS_BOOT=${PMOS_BOOT:-}"
			echo "SUBPARTITION_DEV=${SUBPARTITION_DEV:-}"
			echo "SUBPARTITION_LOOP=${SUBPARTITION_LOOP:-}"
			echo __CALL_MOUNT_SUBPARTITIONS__
			mount_subpartitions 2>&1 || true
			echo __AFTER_MOUNT_SUBPARTITIONS__
			echo "PMOS_ROOT=${PMOS_ROOT:-}"
			echo "PMOS_BOOT=${PMOS_BOOT:-}"
			echo "SUBPARTITION_DEV=${SUBPARTITION_DEV:-}"
			echo "SUBPARTITION_LOOP=${SUBPARTITION_LOOP:-}"
			losetup -a 2>&1 || true
			blkid 2>&1
			ls -l /dev/loop* /dev/disk/by-partlabel /dev/block/by-name 2>&1
			echo __ROOT_RO_MOUNT__
			if [ -n "${PMOS_ROOT:-}" ]; then
				type="$(get_partition_type "$PMOS_ROOT" 2>/dev/null || true)"
				echo "root_type=$type"
				mount -t "${type:-ext4}" -o ro,noload "$PMOS_ROOT" /mnt/lmi-devnode-root 2>&1 || true
				mountpoint -q /mnt/lmi-devnode-root && echo root_mount=ok || echo root_mount=failed
				ls -l /mnt/lmi-devnode-root/sbin/init /mnt/lmi-devnode-root/etc/os-release /mnt/lmi-devnode-root/etc/runlevels/default/sshd 2>&1
				cat /mnt/lmi-devnode-root/etc/os-release 2>&1
				umount /mnt/lmi-devnode-root 2>&1 || true
			fi
			echo __PARTITIONS__
			cat /proc/partitions 2>&1
			echo __MOUNTS__
			mount 2>&1
			echo __DMESG_TAIL__
			dmesg | tail -n 220
		} > "$report_tmp"
		mv "$report_tmp" /tmp/lmi-http/debug.txt
	) &
	/usr/bin/busybox-extras httpd -f -p "${HOST_IP}:8080" -h /tmp/lmi-http >/tmp/lmi-httpd.log 2>&1 &
