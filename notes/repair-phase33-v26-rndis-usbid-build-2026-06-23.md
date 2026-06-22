# Repair Phase 33: v26 RNDIS USB-ID Build

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Purpose

v22 previously reached SSH, but later v22/v24/v25 RAM boots all enumerated on
Windows as `USB\VID_18D1&PID_D001\POSTMARKETOS` bound to Google ADB/WinUSB
instead of a network adapter. v26 keeps the v25 RNDIS and loopdev changes, but
changes the gadget VID/PID away from the Google-bound ID.

## Artifact built

```text
file=artifacts/images/pmos-lmi-normalboot-v26-rndis-usbid-currentuserdata-20260623.img
sha256=0d9ef93b7ed119a814c9a2766f426e95ba85377561a1ca1b611fac6e58fb0973
size=53080064
source=artifacts/images/pmos-lmi-normalboot-v25-rndis-loopdevfix-currentuserdata-20260623.img
source_sha256=440dbf2f9e0879b5b31add0ee87e6712abca7a1c02dd86c08e62b65a9fef9d86
mode=fastboot boot candidate (RAM-only, not flashed)
userdata_pairing=current-v22-userdata
```

## Static verification

```text
deviceinfo_usb_network_function="rndis.usb0"
deviceinfo_usb_idVendor="0x0525"
deviceinfo_usb_idProduct="0xA4A2"
```

The boot cmdline still contains the current userdata UUID pair:

```text
pmos_boot_uuid=2c2600b1-700f-4bdd-a22c-bb12cc589baa
pmos_root_uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370
```

The loopdev rootfs fix markers are still present in `init_functions.sh`.

## Interpretation

This is a narrow host-access test. It does not change kernel storage behavior
or rootfs discovery compared with v25. The expected signal is whether Windows
enumerates the booted device as a USB network gadget instead of Google
ADB/WinUSB.

No partition write was performed.
