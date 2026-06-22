
	# v19: expose the official subpartition discovery path over HTTP.
	# Runs from debug_shell after USB networking is already available.
	mkdir -p /tmp/lmi-http /mnt/lmi-official-root
	echo "subpartition trace pending" > /tmp/lmi-http/debug.txt
	(
		sleep 2
		report_tmp=/tmp/lmi-http/debug.txt.tmp
		{
			echo "generated=$(date)"
			echo __CMDLINE__
			cat /proc/cmdline 2>&1
			echo __PMOS_INIT_LOG__
			cat /pmOS_init.log 2>&1
			echo __BEFORE__
			echo "PMOS_ROOT=${PMOS_ROOT:-}"
			echo "PMOS_BOOT=${PMOS_BOOT:-}"
			echo "SUBPARTITION_DEV=${SUBPARTITION_DEV:-}"
			echo "SUBPARTITION_LOOP=${SUBPARTITION_LOOP:-}"
			echo "root_uuid=${root_uuid:-}"
			echo "boot_uuid=${boot_uuid:-}"
			echo "deviceinfo_rootfs_image_sector_size=${deviceinfo_rootfs_image_sector_size:-}"
			echo __NETWORK__
			ip addr 2>&1
			ip route 2>&1
			echo __PORTS__
			/usr/bin/busybox-extras netstat -ltnp 2>&1 || /bin/busybox netstat -ltnp 2>&1 || true
			echo __PARTITIONS__
			cat /proc/partitions 2>&1
			echo __BLKID_BEFORE__
			blkid 2>&1
			echo __USERDATA__
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
			echo __ROOT_TYPE__
			if [ -n "${PMOS_ROOT:-}" ]; then
				get_partition_type "$PMOS_ROOT" 2>&1 || true
				mount -t ext4 -o ro,noload "$PMOS_ROOT" /mnt/lmi-official-root 2>&1 || true
				echo __ROOT_MOUNT_CHECK__
				mountpoint -q /mnt/lmi-official-root && echo root_mount=ok || echo root_mount=failed
				ls -l /mnt/lmi-official-root/sbin/init /mnt/lmi-official-root/etc/os-release /mnt/lmi-official-root/etc/runlevels/default/sshd 2>&1
				cat /mnt/lmi-official-root/etc/os-release 2>&1
				umount /mnt/lmi-official-root 2>&1 || true
			fi
			echo __MOUNTS__
			mount 2>&1
			echo __DMESG_TAIL__
			dmesg | tail -n 220
		} > "$report_tmp"
		mv "$report_tmp" /tmp/lmi-http/debug.txt
	) &
	/usr/bin/busybox-extras httpd -f -p "${HOST_IP}:8080" -h /tmp/lmi-http >/tmp/lmi-httpd.log 2>&1 &
