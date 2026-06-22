# Repair Phase 17: initramfs Subpartition Discovery (blocker #2)

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Context

With the kernel `fc->source` fix (phase 16, r4), `pmOS_root` mounts when the
nested GPT is exposed manually. But a normal RAM boot of the r4 kernel did NOT
reach SSH: it stayed in initramfs (telnet:23 briefly open, ssh:22 refused,
ping ok), i.e. `switch_root` never ran.

## Root cause (blocker #2)

The rootfs is a full disk image (nested GPT: pmOS_boot + pmOS_root) flashed onto
`userdata` (/dev/sda34). The pmOS initramfs `mount_subpartitions()`
(init_functions.sh) decides whether to loop-expand a partition by COUNTING its
subpartitions with `fdisk -l "$partition"` — at the **default 512-byte** sector
size — and only proceeds if the count is exactly 2:

```sh
part_count="$(fdisk -l "$partition" 2>/dev/null | grep -cE '^ +[0-9]|^'"$partition")"
if [ "$part_count" -eq 2 ]; then ... losetup --sector-size 4096 -Pf ...
```

This device's nested GPT is valid only at 4096-byte sectors. Confirmed from the
v16 report:

```text
fdisk -l        /dev/sda34 (512):  1 entry  -> "/dev/sda34p1 ... ee EFI GPT"  => part_count=1
fdisk -b 4096 -l /dev/sda34:        2 parts  -> 480M primary + 1190M primary    => part_count=2
```

So `part_count=1 != 2`, the loop-expansion is skipped, `pmOS_root` is never
exposed, `find_root_partition` fails, and init drops to the fallback shell.
(`losetup` already used `--sector-size 4096`; only the *counting* step ignored
it. There are also no `/dev/disk/by-partlabel` symlinks and `blkid` is empty, so
label-based discovery cannot help either.)

## Fix

Make the subpartition COUNT honor `deviceinfo_rootfs_image_sector_size`:

```sh
_lmi_fb=""
[ -n "$deviceinfo_rootfs_image_sector_size" ] && _lmi_fb="-b $deviceinfo_rootfs_image_sector_size"
part_count="$(fdisk $_lmi_fb -l "$partition" 2>/dev/null | grep -cE '^ +[0-9]|^'"$partition")"
```

This is a `postmarketos-mkinitfs` (init_functions.sh) defect for
4096-sector-subpartition devices; the permanent fix belongs in that package
(candidate upstream report). For RAM verification it is injected into the
initramfs, mirroring how the HTTP diagnostic patches init_functions.sh.

## Artifact (RAM verify candidate — both fixes)

```text
file=artifacts/images/pmos-lmi-normalboot-r4-subpartfix-20260623.img
sha256=5f35017c9b2420918ebefff872d80c3a0e13fe43aac18005d728a968b1c6316e
size=50.6 MiB  header_v2  kernel=r4 (fc->source fix, 18 LMI_VFS_DIAG)
cmdline: normal (NO pmos.debug-shell) + pmos_boot_uuid/pmos_root_uuid + 4096 path
```

## Expected boot chain

userdata found -> `fdisk -b 4096` counts 2 -> `losetup --sector-size 4096 -Pf`
exposes pmOS_boot/pmOS_root -> find_root_partition matches pmos_root_uuid ->
mount (kernel fix) -> switch_root -> real init -> sshd on :22.

## Next step (separate approval)

RAM-boot the artifact; after switch_root re-enumerates USB, re-attach to WSL,
configure 172.16.42.2/24, and test SSH on 22. If SSH works, build a CLEAN kernel
(drop LMI_VFS_DIAG, keep only the do_new_mount source fix) and fold the
init_functions.sh fix into postmarketos-mkinitfs, then consider persistent
`fastboot flash boot`.
