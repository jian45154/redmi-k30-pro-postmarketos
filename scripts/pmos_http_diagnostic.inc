
	# Export a static, read-only storage report when telnet is unreliable.
	# This intentionally does not continue boot or expose any write action.
	mkdir -p /tmp/lmi-http /mnt/lmi-diag-root
	echo "diagnostic report pending" > /tmp/lmi-http/debug.txt
	(
		sleep 2
		report_tmp=/tmp/lmi-http/debug.txt.tmp
		{
			echo "generated=$(date)"
			echo __PMOS_LOG__
			cat /pmOS_init.log 2>&1
			echo __CMDLINE__
			cat /proc/cmdline 2>&1
			echo __PARTITIONS__
			cat /proc/partitions 2>&1
			echo __BY_NAME__
			ls -l /dev/block/by-name /dev/disk/by-partlabel 2>&1
			echo __BLKID__
			blkid 2>&1
			echo __SYSFS_PARTNAMES__
			grep -H '^PARTNAME=' /sys/class/block/*/uevent 2>&1
			echo __NETWORK__
			ip addr 2>&1
			ip route 2>&1

			userdata=""
			for candidate in /dev/disk/by-partlabel/userdata /dev/block/by-name/userdata; do
				if [ -e "$candidate" ]; then
					userdata="$(readlink -f "$candidate")"
					break
				fi
			done
			if [ -z "$userdata" ]; then
				for uevent in /sys/class/block/*/uevent; do
					[ -r "$uevent" ] || continue
					grep -q '^PARTNAME=userdata$' "$uevent" || continue
					block_name="${uevent%/uevent}"
					block_name="${block_name##*/}"
					major_minor="$(cat "/sys/class/block/$block_name/dev")"
					echo "userdata_sysfs=$block_name dev=$major_minor"
					if [ ! -b "/dev/$block_name" ]; then
						mknod "/dev/$block_name" b "${major_minor%:*}" "${major_minor#*:}" 2>&1 || true
					fi
					ls -l "/dev/$block_name" 2>&1 || true
					[ -b "/dev/$block_name" ] && userdata="/dev/$block_name"
					break
				done
			fi
			echo "userdata=$userdata"
			if [ -n "$userdata" ]; then
				block_name="${userdata##*/}"
				echo __BLOCK_SIZES__
				blockdev --getss "$userdata" 2>&1 || true
				cat "/sys/class/block/$block_name/queue/physical_block_size" 2>&1 || true
				echo __LOOP_NODES__
				[ -c /dev/loop-control ] || mknod /dev/loop-control c 10 237 2>&1 || true
				for loop_index in 0 1 2 3 4 5 6 7; do
					loop_minor="$((loop_index * 8))"
					rm -f "/dev/loop$loop_index"
					mknod "/dev/loop$loop_index" b 7 "$loop_minor" 2>&1 || true
				done
				ls -l /dev/loop-control /dev/loop0 /dev/loop7 2>&1 || true
				for sector_size in 512 4096; do
					echo "__SECTOR_${sector_size}__"
					fdisk -b "$sector_size" -l "$userdata" 2>&1 || true
					loopdev="$(losetup --show --read-only -Pf --sector-size "$sector_size" "$userdata" 2>/tmp/lmi-losetup.err || true)"
					echo "loopdev=$loopdev"
					cat /tmp/lmi-losetup.err 2>/dev/null || true
					if [ -n "$loopdev" ]; then
						sleep 1
						loop_name="${loopdev##*/}"
						for part_sysfs in /sys/class/block/"$loop_name"p*; do
							[ -r "$part_sysfs/dev" ] || continue
							part_name="${part_sysfs##*/}"
							major_minor="$(cat "$part_sysfs/dev")"
							rm -f "/dev/$part_name"
							mknod "/dev/$part_name" b "${major_minor%:*}" "${major_minor#*:}" 2>&1 || true
							ls -l "/dev/$part_name" 2>&1 || true
						done
						for part in "${loopdev}"p*; do
							[ -b "$part" ] || continue
							blkid "$part" 2>&1 || true
							label="$(blkid -s LABEL -o value "$part" 2>/dev/null || true)"
							if [ "$label" = "pmOS_root" ]; then
								echo __FILESYSTEM_SUPPORT__
								cat /proc/filesystems 2>&1
								modprobe ext4 2>&1 || true
								losetup -d /dev/loop1 2>/dev/null || true
								losetup --read-only --sector-size 4096 \
									-o 511705088 --sizelimit 1247805440 \
									/dev/loop1 "$userdata" 2>&1 || true
								blkid /dev/loop1 2>&1 || true
								if /usr/bin/lmi-mount-syscall 2>&1; then
									ls -la /mnt/lmi-diag-root 2>&1
									ls -l /mnt/lmi-diag-root/etc/os-release /mnt/lmi-diag-root/sbin/init 2>&1
									cat /mnt/lmi-diag-root/etc/os-release 2>&1
									/usr/bin/lmi-mount-syscall umount 2>&1 || true
								else
									echo __MOUNT_DMESG__
									dmesg | tail -n 40
								fi
								losetup -d /dev/loop1 2>&1 || true
							fi
						done
						losetup -d "$loopdev" 2>&1 || true
					fi
				done

				echo __DM_LINEAR_ROOT__
				mkdir -p /dev/mapper
				[ -c /dev/mapper/control ] || mknod /dev/mapper/control c 10 236 2>&1 || true
				/usr/bin/dmsetup remove lmi-root 2>/dev/null || true
				major_minor="$(cat "/sys/class/block/$block_name/dev")"
				echo "dm_backing=$major_minor start_512=999424 length_512=2437120"
				if /usr/bin/dmsetup create lmi-root --readonly \
					--table "0 2437120 linear $major_minor 999424" 2>&1; then
					/usr/bin/dmsetup mknodes lmi-root 2>&1 || true
					/usr/bin/dmsetup table lmi-root 2>&1 || true
					dm_node=/dev/mapper/lmi-root
					if [ ! -b "$dm_node" ]; then
						for dm_sysfs in /sys/class/block/dm-*; do
							[ -r "$dm_sysfs/dev" ] || continue
							dm_name="${dm_sysfs##*/}"
							dm_major_minor="$(cat "$dm_sysfs/dev")"
							mknod "/dev/$dm_name" b "${dm_major_minor%:*}" "${dm_major_minor#*:}" 2>&1 || true
							dm_node="/dev/$dm_name"
							break
						done
					fi
					echo "dm_node=$dm_node"
					ls -l "$dm_node" 2>&1 || true
					blkid "$dm_node" 2>&1 || true
					if /usr/bin/lmi-mount-syscall "$dm_node" 2>&1; then
						ls -la /mnt/lmi-diag-root 2>&1
						ls -l /mnt/lmi-diag-root/etc/os-release /mnt/lmi-diag-root/sbin/init 2>&1
						cat /mnt/lmi-diag-root/etc/os-release 2>&1
						/usr/bin/lmi-mount-syscall umount 2>&1 || true
					else
						echo __DM_MOUNT_DMESG__
						dmesg | tail -n 60
					fi
					/usr/bin/dmsetup remove lmi-root 2>&1 || true
				else
					echo dm_create=failed
				fi

				echo __MINIMAL_EXT2_CONTROL__
				losetup -d /dev/loop2 2>/dev/null || true
				if losetup --read-only --sector-size 4096 \
					/dev/loop2 /usr/share/lmi/ext2-control.img 2>&1; then
					blkid /dev/loop2 2>&1 || true
					if /usr/bin/lmi-mount-syscall /dev/loop2 ext2 2>&1; then
						ls -la /mnt/lmi-diag-root 2>&1
						/usr/bin/lmi-mount-syscall umount 2>&1 || true
					else
						echo __CONTROL_MOUNT_DMESG__
						dmesg | tail -n 60
					fi
					losetup -d /dev/loop2 2>&1 || true
				else
					echo control_losetup=failed
				fi

				echo __RAM_BLOCK_EXT2_CONTROL__
				rm -f /dev/ram0
				mknod /dev/ram0 b 1 0 2>&1 || true
				if /bin/busybox dd if=/usr/share/lmi/ext2-control.img \
					of=/dev/ram0 bs=1048576 count=8 2>&1; then
					blkid /dev/ram0 2>&1 || true
					if /usr/bin/lmi-mount-syscall /dev/ram0 ext2 2>&1; then
						ls -la /mnt/lmi-diag-root 2>&1
						/usr/bin/lmi-mount-syscall umount 2>&1 || true
					else
						echo __RAM_CONTROL_MOUNT_DMESG__
						dmesg | tail -n 60
					fi
				else
					echo ram_control_copy=failed
				fi
			fi
			echo __MOUNTS__
			mount 2>&1
			echo __DMESG__
			dmesg | tail -n 240
		} > "$report_tmp"
		mv "$report_tmp" /tmp/lmi-http/debug.txt
	) &
	/usr/bin/busybox-extras httpd -f -p "${HOST_IP}:8080" -h /tmp/lmi-http >/tmp/lmi-httpd.log 2>&1 &
