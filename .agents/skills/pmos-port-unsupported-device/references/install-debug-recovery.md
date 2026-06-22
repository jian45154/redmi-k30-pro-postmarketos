# Installation, debugging, and recovery

## Preflight gate

Before any hardware action, verify:

- exact device and variant;
- unlocked bootloader without plans to relock;
- battery comfortably charged;
- reliable cable and host tools;
- current partition map;
- artifact provenance and hashes;
- backup of user data and device-specific partitions where appropriate;
- known-good stock ROM, boot image, or recovery path;
- exact command and partitions it will touch.

Ask for approval immediately before the action. Approval to RAM-boot is not approval to flash. Approval to write rootfs is not approval to write boot, DTBO, vbmeta, super, or anything else.

## Prefer a temporary boot

When the bootloader and generated format support it, prefer:

```sh
pmbootstrap flasher boot
```

or an explicitly inspected equivalent such as `fastboot boot <boot.img>`. Confirm with current CLI help. A temporary boot can still crash hardware or leave the device needing a forced reboot, but it does not intentionally write a partition.

## Debug initramfs first

For early boot failures, add `pmos.debug-shell` through the supported device/package mechanism and ensure the debug-shell hook is present. The verified official initramfs implementation provides:

- a log at `/pmOS_init.log`;
- a telnet debug path on the postmarketOS USB network, normally port 23;
- `pmos_continue_boot` to leave the debug hold and continue booting.

Collect:

```sh
cat /pmOS_init.log
dmesg
cat /proc/cmdline
cat /proc/partitions
ls -l /dev/disk/by-partlabel /dev/mapper 2>/dev/null
blkid
mount
ip addr
ip route
```

Then run `pmos_continue_boot` only after the evidence is captured. If SSH is refused while ping works, do not diagnose SSH first: confirm rootfs discovery, mount, `switch_root`, and whether debug-shell is intentionally holding boot.

## Rootfs discovery checks

When rootfs is stored as subpartitions inside an Android partition:

1. Confirm the intended Android partition exists.
2. Confirm the generated image partition table and sector size.
3. Confirm `deviceinfo_rootfs_image_sector_size` matches the image/storage requirement.
4. Confirm the loop driver and required storage drivers are built-in or in initramfs.
5. Inspect `losetup`, `blkid`, and `/pmOS_init.log` errors before changing SSH or firewall settings.

Official pmaports initramfs code passes `--sector-size` to `losetup` only when `deviceinfo_rootfs_image_sector_size` is set.

## Partition writes

Current pmbootstrap help describes:

- `flasher flash_rootfs`: write the rootfs to the configured partition without changing the partition table;
- `flasher flash_kernel`: write the kernel or boot image;
- `flasher flash_dtbo`: write DTBO;
- `flasher flash_vbmeta`: generate/write a verification-disabled vbmeta image;
- `flasher sideload`: install a recovery ZIP.

These are destructive operations. Verify current help and the expanded target variables in the device package before use. Never use a write merely as a diagnostic shortcut.

## Rollback

Write a rollback procedure before installation. Include:

- how to force reboot and enter bootloader/recovery;
- which known-good image restores each touched partition;
- exact stock ROM and variant;
- required host tools and drivers;
- whether userdata must be formatted after restoration;
- hashes and provenance of recovery artifacts.

Do not claim recovery is guaranteed merely because fastboot was reachable earlier. Test the least destructive recovery step where practical, and preserve partitions that contain calibration, modem, EFS, persist, or unique device data.

## Diagnose by milestone

Use this order:

1. no bootloader acceptance: inspect boot format, size, header, signature policy, and partition target;
2. no kernel signs: inspect kernel config, DTB, cmdline, console, and decompression;
3. USB network but no shell: inspect initramfs hold and rootfs discovery;
4. rootfs mounted but no SSH: inspect `switch_root`, service enablement, keys, account, firewall, and logs;
5. missing hardware: inspect DTB, driver probe, modules, firmware, regulators, clocks, remoteproc, and userspace daemons.

