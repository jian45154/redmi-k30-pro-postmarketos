# Repair Phase 37: v27 Userdata Prewrite Check

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Purpose

Prepare for a possible full v27 userdata rewrite after v27 RAM-only boot
validated the kernel, initramfs, RNDIS USB ID, loopdev rootfs discovery, and SSH
against the currently flashed userdata.

This phase is preflight only. No partition write was performed.

## Device state

```text
fastboot devices: device present
product: lmi
unlocked: yes
current-slot: not reported by bootloader
partition-size:userdata: 0x1AC07FB000
userdata_partition_bytes=114898743296
```

## Candidate images

```text
userdata=artifacts/images/xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img
userdata_sha256=9035ae1e1ba035134553dafed1b1900288b4d082c408018a1ebd31fe89cd7fb4
userdata_size=1754267648

boot=artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
boot_sha256=e6e6a20bee87ca21e5cc4fdcc295dbaaf6faaeaa697672a542943e6afbc9d26e
boot_size=52920320
```

## Capacity and transfer check

```text
userdata partition > userdata image: yes
margin_bytes=113144475648
fastboot max-download-size=805306368
userdata image > max-download-size: yes
```

The image must be flashed with fastboot sparse/chunk splitting, not as a single
unbounded transfer. The proposed command is:

```bat
fastboot -S 256M flash userdata artifacts\images\xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img
```

## Static image check

The v27 userdata image was checked with `fdisk -b 4096`:

```text
Disklabel type: gpt
Sector size: 4096 bytes / 4096 bytes
Partition 1: 480M EFI System
Partition 2: 1.2G Linux root (ARM-64)
```

## Safety boundary

Writing `userdata` will overwrite the currently working pmOS userdata image and
all user data on that partition. It does not intentionally write `boot`, `dtbo`,
`vbmeta`, `super`, modem/EFS, persist, or calibration partitions.

Proceed only after a separate explicit confirmation for the exact userdata
write command.
