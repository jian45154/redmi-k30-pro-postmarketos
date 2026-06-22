# Architecture Review: boot/rootfs flow
签名：codex | 2026-06-18 Australia/Sydney

## Main finding

The most likely early-flow mistake is missing:

```sh
deviceinfo_rootfs_image_sector_size="4096"
```

The device is recorded as `SM8 UFS` in `notes/fastboot-check-2026-05-28.md`.
postmarketOS initramfs only passes `--sector-size $deviceinfo_rootfs_image_sector_size`
to `losetup` when probing nested pmOS subpartitions inside Android partitions.
Without this on UFS devices, the initramfs may fail to find the internal
`pmOS_boot` / `pmOS_root` partitions after `pmbootstrap flasher flash_rootfs`.

This has been fixed in:

- `artifacts/wsl-pmaports/device-xiaomi-lmi/deviceinfo`
- `artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD`

The fix still needs to be synced into pmbootstrap's pmaports cache, rebuilt,
reinstalled, and reflashed to `userdata`.

## Corrections to prior assumptions

### `pmos.debug-shell` is not a normal-boot fix

The latest generated boot image intentionally contains `pmos.debug-shell`.
That drops into the initramfs debug shell before rootfs mounting and waits for
`pmos_continue_boot`. While it is waiting there, SSH on the final rootfs will
not be up.

Use cases:

- Debug image: boot it, telnet to `172.16.42.1:23`, read `/pmOS_init.log`, then
  run `pmos_continue_boot`.
- Normal SSH validation: build/boot an image without `pmos.debug-shell`.

### The debug hook is present

The rootfs apk log shows `postmarketos-mkinitfs-hook-debug-shell` installed.
The generated initramfs contains `telnetd`, `evtest`, and `fbdebug`.
So "debug-shell hook missing from initramfs" is not the primary hypothesis.

### SSH refused is not enough evidence for sshd/firewall failure

postmarketOS documents "ping works but SSH refused" as a boot/rootfs debugging
case. On this setup, the stronger hypothesis is: initramfs has not completed
rootfs discovery/mount/switch_root, or debug-shell is intentionally holding it
before that point.

## Current artifact facts

- `artifacts/images/pmos-lmi-debug-boot.img` is byte-identical to
  `/home/microstar/.local/var/pmbootstrap/chroot_rootfs_xiaomi-lmi/boot/boot.img`.
- `artifacts/images/pmos-lmi-boot.img` is older and lacks `pmos.debug-shell`.
- The boot image DTB size matches `kona-v2.1-lmi.dtb`, so the premerged DTB is
  being included in the latest debug image.
- `sshd` is enabled in the rootfs default runlevel.

## Revised next flow

1. Sync the updated device package into pmbootstrap's pmaports cache.
2. Rebuild `device-xiaomi-lmi`.
3. Run `pmbootstrap install --no-fde` again so the rootfs image is regenerated
   with 4096-byte sector metadata.
4. Re-export/copy the debug boot image.
5. Flash rootfs to `userdata` again.
6. Boot debug image and read `/pmOS_init.log`.
7. If rootfs mounts, run `pmos_continue_boot` and then test SSH.
8. After that, build a normal image without `pmos.debug-shell` for ordinary
   SSH validation.
