# Repair Phase 29: v24 devtmpfs Boot Status

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-v24-devtmpfs-loopdevfix-currentuserdata-20260623.img
sha256=043afac4db51cd461e5fe740a6c6792a6c9ce14d1ff78f98e6494831896d75c0
size=53075968
mode=fastboot boot (RAM-only, no partition writes)
```

## Preflight

```text
fastboot max-download-size=805306368
image_size=53075968
```

The image is below the bootloader download limit.

## Command result

```text
Sending 'boot.img' (51832 KB) OKAY
Booting OKAY
Finished. Total time: 1.221s
```

## Post-boot host status

```text
fastboot devices: no device
adb devices: no usable device
ping 172.16.42.1: 100% loss
host 172.16.42.x address: none
Windows USB/RNDIS network adapter: none
```

Windows did enumerate one USB device:

```text
InstanceId=USB\VID_18D1&PID_D001\POSTMARKETOS
BusReportedDeviceDesc=xiaomi lmi
FriendlyName=Google Galaxy Nexus ADB Interface
Class=AndroidUsbDeviceClass
Service=WinUSB
DriverProvider=Google, Inc.
DriverInfPath=oem10.inf
```

## Interpretation

v24 is different from v23. v23 exposed no host-visible gadget interface. v24
does expose a POSTMARKETOS USB device, but Windows binds it as a WinUSB/ADB
interface instead of a RNDIS/USB network adapter. Because `adb devices` has no
usable session and no RNDIS adapter appears, there is still no shell path.

This means the boot likely reaches USB gadget setup, but the exposed gadget
composition or Windows driver binding is not the working v22 USB networking
state.

## Next action

Do not write v24 userdata yet. Return the phone to fastboot manually. The next
diagnostic should compare v22 and v24 USB gadget descriptors or build a v24
diagnostic image that forces the known-good v22 USB networking path before
normal userspace.
