# Repair Phase 23: v21 Rootfs Discovery and Read-only Mount Success

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-loopdev-trace-v21-20260623.img
sha256=033b1c5bb38afa6c612ecfe8ef237a3dc2a884cedb91adf0ef38bb310389015f
mode=fastboot boot (RAM-only, no partition writes)
```

## Logs

```text
logs/repair-http-debug-v21-2026-06-23.txt
logs/repair-http-debug-v21-2026-06-23.redacted.txt
```

## Result

v21 reached the debug HTTP path and proved that the remaining v20 blocker was
missing loop subpartition device nodes.

Key observations:

```text
PMOS_ROOT=/dev/loop0p2
SUBPARTITION_DEV=/dev/sda34
SUBPARTITION_LOOP=/dev/loop0
/dev/loop0p1: LABEL="pmOS_boot" TYPE="ext2"
/dev/loop0p2: LABEL="pmOS_root" TYPE="ext4"
root_type=ext4
root_mount=ok
/mnt/lmi-loopdev-root/sbin/init -> /bin/busybox
PRETTY_NAME="postmarketOS edge"
```

## Interpretation

The initramfs can now:

- expose the Android userdata block node from sysfs;
- expand the 4096-sector nested GPT through loop;
- expose `/dev/loop0p1` and `/dev/loop0p2`;
- identify `pmOS_root`;
- mount the rootfs read-only.

The next milestone is no longer rootfs discovery. It is a normal boot candidate
that carries the proven initramfs fixes and then tests `switch_root`, OpenRC, and
SSH.

## Next step

Build a normal boot candidate with:

- the kernel `fc->source` mount fix;
- `deviceinfo_rootfs_image_sector_size=4096`;
- `fdisk -b 4096` partition counting in `mount_subpartitions()`;
- sysfs-based creation of base block nodes before rootfs discovery;
- sysfs-based creation of loop subpartition nodes after `losetup -Pf`;
- no `pmos.debug-shell`, but retain HTTP/boottrace if needed for nonintrusive
  post-failure evidence.
