# Repair Phase 24: v22 Normal Boot Candidate Build

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact built

```text
file=artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.img
sha256=cf848d79b4c3ab60d0d58cee99abfd1b5ee9b73c5b0a52be5d6df3bac1518e89
size=53063680
```

Manifest:

```text
artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.manifest
```

## Build script

```text
scripts/15_build_pmos_v22_normal_loopdev_fix.sh
```

## Included fixes

- kernel `fc->source` mount fix inherited from the r4 source boot image;
- `deviceinfo_rootfs_image_sector_size=4096`;
- `fdisk -b 4096` partition counting in `mount_subpartitions()`;
- sysfs-based creation of base block nodes before rootfs discovery;
- sysfs-based refresh of loop subpartition nodes after `losetup -Pf`.

## Intent

v22 removes `pmos.debug-shell` and tests the next boot milestone after v21:

```text
rootfs discovery -> rootfs mount -> switch_root -> OpenRC/SSH
```

This artifact is RAM-boot only until explicitly approved for testing.
