# Repair Phase 22: v20 Loop Partition Devnode Blocker

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-devnode-trace-v20-20260623.img
sha256=facd3d5a4a1d00f1f663b6cc8800fdb0037e1fbe988d998380b5cc90cec4c7ec
mode=fastboot boot (RAM-only, no partition writes)
```

## Result

v20 reached the debug HTTP path. Report saved:

```text
logs/repair-http-debug-v20-2026-06-23.txt
logs/repair-http-debug-v20-2026-06-23.redacted.txt
```

Key observations:

```text
before: /dev/sda34 missing
sysfs: /sys/class/block/sda34/uevent has PARTNAME=userdata
after: /dev/sda34 exists
after: /dev/disk/by-partlabel/userdata -> ../../sda34
after: /dev/block/by-name/userdata -> ../../sda34
fdisk -b 4096 /dev/sda34: valid nested GPT
mount_subpartitions: repeatedly tries /dev/sda34
dmesg: loop0: p1 p2
after: no PMOS_ROOT
after: no PMOS_BOOT
```

## Interpretation

The base UFS partition device-node problem is fixed by populating `/dev` from
sysfs, but the next blocker is the same issue one level deeper: after
`losetup -Pf`, the kernel exposes `loop0p1` and `loop0p2` in sysfs, but the
initramfs does not create `/dev/loop0p1` and `/dev/loop0p2` nodes or
by-partlabel links. As a result, `find_root_partition()` still cannot discover
`pmOS_root`.

## v21 artifact built

```text
file=artifacts/images/pmos-lmi-loopdev-trace-v21-20260623.img
sha256=033b1c5bb38afa6c612ecfe8ef237a3dc2a884cedb91adf0ef38bb310389015f
```

v21 modifies the debug initramfs path to:

- populate base block device nodes from `/sys/class/block`;
- call official `mount_subpartitions()`;
- after `losetup -Pf`, populate `/dev/loopXp1` and `/dev/loopXp2` from sysfs;
- create by-partlabel/by-name symlinks for loop subpartitions;
- verify `PMOS_ROOT`, `PMOS_BOOT`, and read-only rootfs mount.

