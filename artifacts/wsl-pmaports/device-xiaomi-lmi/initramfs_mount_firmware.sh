#!/bin/busybox ash

set -u

log() {
	echo "xiaomi-lmi firmware: $*"
}

find_modem_partition() {
	local uevent block name major_minor

	if [ -b /dev/disk/by-partlabel/modem ]; then
		echo /dev/disk/by-partlabel/modem
		return 0
	fi

	mkdir -p /dev/disk/by-partlabel /dev/block/by-name

	for uevent in /sys/class/block/*/uevent; do
		[ -r "$uevent" ] || continue
		grep -q '^PARTNAME=modem$' "$uevent" || continue

		block="${uevent%/uevent}"
		name="${block##*/}"
		[ -r "/sys/class/block/$name/dev" ] || continue

		major_minor="$(cat "/sys/class/block/$name/dev")"
		[ -b "/dev/$name" ] || mknod "/dev/$name" b \
			"${major_minor%:*}" "${major_minor#*:}" 2>/dev/null || true
		ln -sfn "../../$name" /dev/disk/by-partlabel/modem
		ln -sfn "../../$name" /dev/block/by-name/modem
		echo /dev/disk/by-partlabel/modem
		return 0
	done

	return 1
}

link_firmware_aliases() {
	local sysroot_fw="/sysroot/mnt/vendor/firmware_mnt/image"
	local root_fw="/sysroot/lib/firmware"
	local target_fw="/mnt/vendor/firmware_mnt/image"
	local fw_file

	mkdir -p "$root_fw"

	for fw_file in "$sysroot_fw"/*.mdt "$sysroot_fw"/*.b[0-9][0-9] \
		"$sysroot_fw"/*.jsn "$sysroot_fw"/*.sig; do
		[ -e "$fw_file" ] || continue
		ln -sfn "$target_fw/${fw_file##*/}" "$root_fw/${fw_file##*/}"
	done

	if [ -d "$sysroot_fw/qca6390" ]; then
		ln -sfn "$target_fw/qca6390" "$root_fw/qca6390"
	fi
}

main() {
	local modem_dev fw_mnt="/sysroot/mnt/vendor/firmware_mnt"

	[ -d /sysroot/etc ] || {
		log "sysroot is not mounted yet"
		return 0
	}

	modem_dev="$(find_modem_partition)" || {
		log "modem partition not found"
		return 0
	}

	mkdir -p "$fw_mnt"
	if ! mountpoint -q "$fw_mnt"; then
		mount -o ro -t vfat "$modem_dev" "$fw_mnt" || {
			log "failed to mount $modem_dev"
			return 0
		}
	fi

	link_firmware_aliases
	log "mounted modem firmware before switch_root"
}

main
