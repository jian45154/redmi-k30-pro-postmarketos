# Repair Phase 30: v25 RNDIS Build

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Reason

v24 reached USB gadget enumeration but Windows bound the device as
WinUSB/Google ADB instead of exposing the known-good USB network path. v22 and
v24 initramfs USB gadget scripts were identical, so v25 tests a narrower
hypothesis: the default `ncm.usb0` gadget is not binding as a usable network
device on this host after the devtmpfs kernel rebuild.

## Package changes

Kernel:

```text
linux-xiaomi-lmi pkgrel: 5 -> 6
CONFIG_USB_CONFIGFS_RNDIS=y
```

Device package:

```text
device-xiaomi-lmi pkgrel: 1 -> 2
deviceinfo_usb_network_function="rndis.usb0"
```

Both `linux-xiaomi-lmi` and `device-xiaomi-lmi` built successfully.

## Full userdata image

```text
file=artifacts/images/xiaomi-lmi-v25-rndis-userdata-20260623.img
sha256=886ccc155124278f4a8d5e619198b4cef78d647e788ee1879a54ab58f2ea87aa
size=1760550912
sector_size=4096
pmos_boot_uuid=9bace797-e74b-45f5-b30c-863e0f611f2a
pmos_root_uuid=58cf56d2-d98a-4496-9421-0364a78a2f1d
```

This image has not been flashed.

## RAM-only test image

```text
file=artifacts/images/pmos-lmi-normalboot-v25-rndis-loopdevfix-currentuserdata-20260623.img
sha256=440dbf2f9e0879b5b31add0ee87e6712abca7a1c02dd86c08e62b65a9fef9d86
size=53080064
userdata_pairing=current-v22-userdata
```

Local unpack verification confirmed:

```text
deviceinfo_usb_network_function="rndis.usb0"
fdisk block size follows deviceinfo_rootfs_image_sector_size=4096
lmi_populate_block_devs()
loop partition wait for /dev/${loop}p2
cmdline UUIDs match current v22 userdata
```

## Next action

After the phone is manually returned to fastboot, the next hardware action is a
RAM-only boot of:

```text
artifacts/images/pmos-lmi-normalboot-v25-rndis-loopdevfix-currentuserdata-20260623.img
```

This requires fresh explicit approval before running `fastboot boot`.
