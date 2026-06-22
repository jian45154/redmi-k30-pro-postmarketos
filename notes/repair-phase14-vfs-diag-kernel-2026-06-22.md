# Repair Phase 14: VFS Block-Filesystem Diagnostic Kernel

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Purpose

V13 excluded UFS, sector size, loop, device-mapper, filesystem contents,
manual `mknod` and generic VFS pathname resolution: a bind mount of the source
block node succeeds, but its ext2/ext4 filesystem mount still returns `ENOENT`
with no EXT4/VFS dmesg record. The remaining failure is inside the kernel
block-filesystem path between `legacy_get_tree`, `mount_bdev`,
`blkdev_get_by_path`/`lookup_bdev` and `ext4_fill_super`.

Every prior diagnostic image (v3–v13) reused the **existing** chroot kernel and
changed only the initramfs, so none could observe those functions. V14 is the
first image built with a kernel **recompiled** with
`lmi-vfs-mount-diagnostic.patch`, which adds `pr_err("LMI_VFS_DIAG ...")`
logging at exactly those four points. The goal is to identify the last
checkpoint reached and localize the failing layer.

This phase covers build + local inspection only. No partition was written; the
RAM boot is a separate, explicitly-approved step.

## Controlled change

V14 reuses the V13 diagnostic ramdisk byte-for-byte; the only difference is the
patched kernel:

```text
diagnostic_ramdisk_sha256=2e8191495f3c266708790435dfb1cc8c2d1a8159af64f1ad8ba24255a39f578e   (identical to v13)
```

## Kernel package

```text
aport=device/downstream/linux-xiaomi-lmi
pkgver=4.19.325
pkgrel=2 (bumped 1 -> 2 to force rebuild)
apk=linux-xiaomi-lmi-4.19.325-r2.apk
patch=lmi-vfs-mount-diagnostic.patch
patch_sha512=6e39665012ca84d74aa2c45045b884a78313d4e34a05a4b83f8e52bd06e47b8ab0ef1f4b42c1a573b2146a1e2ca5559ee88306f8e6c9ce5afa4b46dcf45f522f
```

Note: the hand-written patch shipped with malformed unified-diff hunk headers
(several `@@` old/new line counts were wrong, e.g. hunk 1 stated `+471,17`
where the body has 16 new lines). `patch(1)` rejected it with
`malformed patch at line 23`. The hunk headers were recomputed from the bodies
(equivalent to `recountdiff`); contents are unchanged. The corrected patch
applies cleanly and is mirrored to the repo
`artifacts/wsl-pmaports/linux-xiaomi-lmi/`.

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v14.img
sha256=b5a57412bc47c7b5426fb41b1d604fa4fb0f4d6ec3699d9e0084d64eb620a2fc
artifact_size=53100544
kernel_sha256=7a7d73e6f5daba5d0e923f50799fb72967bca4a061d45db050c4301e58276906
source_boot_sha256=defaf6364391d940186e00e4956198502cb8a72f7184aa7d96cc0ba7ef2c8d5e
dtb_sha256=212d80826ceef522aff2d967082b5708d20ddccc13ae322edce72412f1a06b51
reproducible=yes
syntax=ok
inspection=ok
```

## Local inspection (no phone)

```text
android_magic=ANDROID!
header_version=2
kernel_size=43231256
ramdisk_size=8982636
total=50.6 MiB (within 128 MiB boot limit)
LMI_VFS_DIAG_strings_in_final_image=15
```

Per-function diagnostic coverage confirmed in the packed kernel:

```text
legacy_get_tree : 3  (enter / fail / ok)
mount_bdev      : 4  (enter / blkdev_get fail / blkdev_get ok / fill_super ret)
lookup_bdev     : 6  (enter / kern_path fail / inode mode / bd_acquire fail / ok / fail)
ext4_fill_super : 2  (enter / exit ret)
```

The diagnostic ramdisk still carries the static mount-probe and the
4096-sector deviceinfo (build-script greps passed).

## Hardware result (RAM boot, 2026-06-22, explicit approval)

V14 was RAM-booted (`fastboot boot ...v14.img`, OKAY; no partition written) and
served a stable, byte-identical report:

```text
report_size=53463
report_sha256=6e4acbeb327673454e0dc0e44b5c2c0ed98713ed919fa6fd32bf96ba5e8e5014
reports_identical=yes
```

`LMI_VFS_DIAG` lines in dmesg confirm the patched r2 kernel ran. Decisive
findings:

- ext4 IS registered: `/proc/filesystems` lists `ext4`/`ext2`/`ext3` (non-nodev),
  matching `CONFIG_EXT4_FS=y`. The `modprobe: FATAL: Module ext4 not found` line
  is the diag script's own redundant `modprobe ext4` failing because ext4 is
  built-in (no `.ko`) — a red herring, NOT missing ext4 support.
- Every block-fs mount (loop0p1 ext2, loop0p2 ext4, loop1 ext4, mapper/lmi-root,
  loop2 ext2, ram0 ext2) returns `ENOENT` and **never reaches `mount_bdev`,
  `legacy_get_tree fs=ext4`, or `ext4_fill_super`**.
- `legacy_get_tree` fires normally for pstore/proc/sysfs/devpts, so the
  instrumentation works; tmpfs (nodev) and bind mounts succeed.

Root cause located by source read (this downstream kernel's `do_new_mount` uses
the new fs_context API): `fs/super.c` `vfs_get_tree` returns `-ENOENT` at

```c
if (fc->fs_type->fs_flags & FS_REQUIRES_DEV && !fc->source)
    return -ENOENT;
```

before calling `get_tree`. ext4/ext2 are `FS_REQUIRES_DEV`, so `fc->source` is
empty at that point; tmpfs is not `FS_REQUIRES_DEV` so it is unaffected. The open
question — why `fc->source` is empty despite `mount(2)` passing a device — is the
target of v15 (instrument `do_new_mount` + `vfs_get_tree`); see
`notes/repair-phase15-*` / the plan file.

## Next step (separate approval required)

RAM-boot v14 only after explicit approval of the exact
`fastboot boot pmos-lmi-http-diagnostic-20260622-v14.img` command. On boot,
fetch `http://172.16.42.1:8080/debug.txt` twice (10 s apart) for stability and
capture the dmesg tail with the `LMI_VFS_DIAG` lines.

Read the result by the last-printed checkpoint:

```text
no "legacy_get_tree enter"      -> failure before fs-driver dispatch (fs_context / syscall path)
"mount_bdev enter", blkdev fail -> block-device acquisition path
blkdev ok, no "ext4_fill_super" -> between bdev acquisition and superblock fill
"ext4_fill_super enter" + ret!=0-> inside the ext4 superblock parser (read the ext4 error)
```

This feeds Phase 4 ("Decide From The Report") of
`notes/repair-plan-2026-06-21.md`.
