# Repair Phase 16: fc->source Fix — pmOS_root Mounts (BREAKTHROUGH)

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Summary

The boot blocker is fixed. v15 proved the downstream 4.19 fs_context backport
left `fc->source` NULL for legacy block-fs mounts via `mount(2)`, so
`vfs_get_tree` returned `-ENOENT` at `FS_REQUIRES_DEV && !fc->source` before the
ext4 driver. v16 adds a minimal source safety-net in `fs/namespace.c`
`do_new_mount`:

```c
if (!err && name && !fc->source)
    fc->source = kstrdup(name, GFP_KERNEL);
```

With this, `pmOS_root` mounts for the first time.

## Kernel package / artifact

```text
pkgrel=4   apk=linux-xiaomi-lmi-4.19.325-r4.apk
image=artifacts/images/pmos-lmi-http-diagnostic-20260623-v16.img
sha256=d6ee8f2c516533507cdf12a8905d1af749db840452fb7f73c20a25ddf3400fa1
artifact_size=53100544  header_v2  50.6 MiB  LMI_VFS_DIAG_strings=18
diagnostic_ramdisk_sha256=2e8191495f3c266708790435dfb1cc8c2d1a8159af64f1ad8ba24255a39f578e (== v13/v14/v15)
```

## Hardware result (RAM boot, 2026-06-23, explicit approval)

Report stable/byte-identical (`report_size=41521`). The full chain now executes
for an ext4 mount:

```text
do_new_mount pre_get_tree fs=ext4 name=/dev/loop1 err=0 fc_source=/dev/loop1   <- FIXED (was (null))
vfs_get_tree enter        fs=ext4 fs_flags=0x1 source=/dev/loop1
mount_bdev enter          fs=ext4 dev=/dev/loop1 flags=0x1                     <- reached for first time
ext4_fill_super enter     dev=7:8 data=noload                                  <- ext4 driver runs
```

Probe results (first loop iteration, all required nodes present):

```text
tmpfs_mount=ok
pmos_boot_mount=ok                 (ext2 /dev/loop0p1)
pmos_root_partition_mount=ok       (ext4 /dev/loop0p2)
mount2=ok filesystem=ext4 data=noload
/mnt/lmi-diag-root/etc/os-release -> ../usr/lib/os-release
/mnt/lmi-diag-root/sbin/init -> /bin/busybox
PRETTY_NAME="postmarketOS edge"  NAME="postmarketOS"  ID="postmarketos"
```

(`errno=6 ENXIO` for pmos_boot/pmos_root in *later* probe blocks is only because
those reuse `/dev/loop0p1/p2` after the loop device was detached — unrelated to
the mount bug; `mount2` on the live device succeeds every block.)

Conclusion: the postmarketOS rootfs on `userdata` is healthy and mountable; the
only blocker was the kernel fs_context source defect. GPT, UUIDs, ext4 features
and filesystem contents were never the problem.

## Next step

The fix is in the kernel (r4). The diagnostic image still carries
`pmos.debug-shell` and only mounts read-only for inspection. To complete the
boot:

1. RAM-boot a **normal** pmOS boot image built with the r4 kernel (the rootfs
   chroot `boot.img` now uses r4). Let initramfs find/mount `pmOS_root` and run
   `switch_root` into real init.
2. Verify `switch_root` completes and sshd listens on 22.
3. Once SSH works, drop the LMI_VFS_DIAG logging (clean kernel, new pkgrel) and
   keep the `do_new_mount` source fix as the permanent patch.
4. Then proceed to Phase 6/7 hardware bring-up (display, Wi-Fi, etc.).

The permanent fix to retain: the `do_new_mount` `fc->source` kstrdup safety-net
in `lmi-vfs-mount-diagnostic.patch` (rename to a non-diagnostic patch name when
the logging is removed).
