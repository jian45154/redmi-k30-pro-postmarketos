# Repair Phase 28: v24 devtmpfs Build

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Goal

Replace the failed v23 `mdev -s` workaround with a kernel-level device node
fix:

```text
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
```

## Package changes

```text
linux-xiaomi-lmi pkgrel: 4 -> 5
config-xiaomi-lmi.aarch64 sha512:
1c080dc379471e782c5c52ef9b89e9c6ef0fcd369041ae446566519488064bdf61ec9c25f096cc707bd3bbf0c94c4425b216c70b4efb7b4323c0f4f046ca8448
```

`pmbootstrap build linux-xiaomi-lmi` completed successfully and produced
`linux-xiaomi-lmi-4.19.325-r5.apk`.

## Full userdata image

```text
file=artifacts/images/xiaomi-lmi-v24-devtmpfs-userdata-20260623.img
sha256=a3823533ea2b681f3a17c8ba346b7cc39add6a16bb3d5ba755729f8ab35c703f
size=1760550912
sector_size=4096
pmos_boot_uuid=4621fb48-e1e9-41bb-8e3e-fec0cb003942
pmos_root_uuid=c5d70b23-8126-4e79-8df9-72e4185bd130
```

This image has not been flashed.

## Boot image candidates

The direct pmbootstrap v24 boot image was generated:

```text
file=artifacts/images/pmos-lmi-normalboot-v24-devtmpfs-20260623.img
sha256=eeb38546a9d69fa4c73b5f8fc9b95ec88db1d0655a8179e72461762a99414c4e
```

Inspection showed that this direct image does not carry the v22 initramfs
loopdev fixes. It should not be used as the next RAM-only test candidate.

The testable v24 image is:

```text
file=artifacts/images/pmos-lmi-normalboot-v24-devtmpfs-loopdevfix-currentuserdata-20260623.img
sha256=043afac4db51cd461e5fe740a6c6792a6c9ce14d1ff78f98e6494831896d75c0
size=53075968
userdata_pairing=current-v22-userdata
```

It uses the v24 devtmpfs kernel and v24 ramdisk, then reapplies the initramfs
fixes required for the currently flashed v22-compatible userdata:

```text
fdisk block size follows deviceinfo_rootfs_image_sector_size=4096
lmi_populate_block_devs()
loop partition wait for /dev/${loop}p2
```

## Next action

After the phone is manually returned to fastboot, the next hardware action is a
RAM-only boot of:

```text
artifacts/images/pmos-lmi-normalboot-v24-devtmpfs-loopdevfix-currentuserdata-20260623.img
```

This requires a fresh explicit approval before running `fastboot boot`.
