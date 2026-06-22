# Repair Phase 35: v27 Full Reproducible Build

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Purpose

Build a complete v27 image set from the current local pmaports after v26 proved
normal boot, RNDIS USB networking, rootfs mount, and SSH.

This phase only builds and statically checks artifacts. It does not boot or
write any phone partition.

## Password handling

The first v27 build attempt was stopped because `pmbootstrap install` did not
explicitly set an install password. The build script now requires
`PMOS_INSTALL_PASSWORD` from the local shell environment and does not store the
password in the script, manifest, or note.

The final v27 build was generated with an explicit local install password. The
build log and manifest were checked for plaintext password leakage.

## Artifacts

```text
boot=artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
boot_sha256=e6e6a20bee87ca21e5cc4fdcc295dbaaf6faaeaa697672a542943e6afbc9d26e
boot_size=52920320

userdata=artifacts/images/xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img
userdata_sha256=9035ae1e1ba035134553dafed1b1900288b4d082c408018a1ebd31fe89cd7fb4
userdata_size=1754267648

manifest=artifacts/images/pmos-lmi-v27-rndis-usbid-full-20260623.manifest
manifest_sha256=5a271522f4ae7ca7580e683a00f4b0c5dbe428470cbfeda7ec7da26849125524
```

## Static checks

`fdisk -b 4096` sees the userdata image as a 4096-byte-sector GPT:

```text
Disk size: 1754267648 bytes
Logical sector size: 4096
Partition 1: 480M, EFI System, expected pmOS_boot content
Partition 2: 1.2G, Linux root (ARM-64), expected pmOS_root content
```

The boot ramdisk contains:

```text
deviceinfo_rootfs_image_sector_size="4096"
deviceinfo_usb_network_function="rndis.usb0"
deviceinfo_usb_idVendor="0x0525"
deviceinfo_usb_idProduct="0xA4A2"
```

The post-export `init_functions.sh` loopdev fix markers are present:

```text
lmi_populate_block_devs()
_lmi_fdisk_block_size="-b $deviceinfo_rootfs_image_sector_size"
_lmi_loop_name="${SUBPARTITION_LOOP##*/}"
[ -b "/dev/${_lmi_loop_name}p2" ] && break
```

## Logs

```text
build_log=logs/pmaports-build-v27-20260623.txt
static_check_log=logs/static-check-v27-20260623.txt
```

These logs are local raw logs and remain ignored by Git unless explicitly
redacted.

## Interpretation

v27 is the first full rebuild from current local pmaports with the v26 USB ID
fix included and the loopdev rootfs fix applied as a reproducible post-export
step. It is ready for the next reversible test: RAM-only boot of the v27 boot
image against the currently flashed v22 userdata, or a separate explicit
userdata rewrite using the v27 userdata image.

No partition write was performed.
