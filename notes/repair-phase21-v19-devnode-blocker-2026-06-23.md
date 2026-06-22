# Repair Phase 21: v19 Devnode Blocker

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-subpart-trace-v19-20260623.img
sha256=66eb4f16ac683a3b0d12fcc86103e45b78fd7ecf5d0924acffac23118179e92c
mode=fastboot boot (RAM-only, no partition writes)
```

## Result

v19 reached the debug HTTP path. Report saved:

```text
logs/repair-http-debug-v19-2026-06-23.txt
logs/repair-http-debug-v19-2026-06-23.redacted.txt
```

Key observations:

```text
tcp/8080: open
tcp/23: open
/proc/partitions: sda34 exists, 112205804 blocks
/dev/sda34: missing
/dev/disk/by-partlabel: missing
/dev/block/by-name: missing
blkid: empty
userdata=
mount_subpartitions: ERROR: failed to mount subpartitions
PMOS_ROOT=
PMOS_BOOT=
```

Kernel log also shows:

```text
do_new_mount enter fstype=devtmpfs name=dev data=mode=0755
request_module fs-devtmpfs succeeded, but still no fs?
```

## Interpretation

The v17/v19 normal rootfs discovery failure is not the 4096-sector GPT count
anymore. It fails earlier: the initramfs has no block device nodes or partition
symlinks for the UFS partitions even though the kernel sees them in
`/proc/partitions`.

`mount_subpartitions()` scans candidate paths such as `/dev/sda34`, but those
paths do not exist, so the official 4096-sector `fdisk` and `losetup` path never
gets a valid block device.

## Fix hypothesis

Before `mount_subpartitions()`, populate `/dev` from sysfs:

```sh
for uevent in /sys/class/block/*/uevent; do
    name="${uevent%/uevent}"
    name="${name##*/}"
    major_minor="$(cat "/sys/class/block/$name/dev")"
    mknod "/dev/$name" b "${major_minor%:*}" "${major_minor#*:}"
done
```

Then create by-partlabel/by-name symlinks from `PARTNAME=` in each uevent. This
is safe to test in initramfs because it only creates volatile device nodes in
RAM.

## v20 artifact built

```text
file=artifacts/images/pmos-lmi-devnode-trace-v20-20260623.img
sha256=facd3d5a4a1d00f1f663b6cc8800fdb0037e1fbe988d998380b5cc90cec4c7ec
```

v20 keeps the v19 debug HTTP path but adds a volatile `/dev` population step
before calling official `mount_subpartitions()`. It then verifies whether
`PMOS_ROOT` appears and whether the rootfs mounts read-only.

