# Repair Phase 31: v25 RNDIS Boot Status

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-v25-rndis-loopdevfix-currentuserdata-20260623.img
sha256=440dbf2f9e0879b5b31add0ee87e6712abca7a1c02dd86c08e62b65a9fef9d86
size=53080064
mode=fastboot boot (RAM-only, no partition writes)
```

## Preflight

```text
fastboot max-download-size=805306368
image_size=53080064
```

The image is below the bootloader download limit.

## Command result

```text
Sending 'boot.img' (51836 KB) OKAY
Booting OKAY
Finished. Total time: 1.220s
```

## Post-boot host status

```text
fastboot devices: no device
adb devices: no usable device
ping 172.16.42.1: 100% loss
host 172.16.42.x address: none
Windows USB/RNDIS network adapter: none
```

Windows enumerated the same USB device shape seen with v24:

```text
InstanceId=USB\VID_18D1&PID_D001\POSTMARKETOS
BusReportedDeviceDesc=xiaomi lmi
FriendlyName=Google Galaxy Nexus ADB Interface
Class=AndroidUsbDeviceClass
Service=WinUSB
DriverProvider=Google, Inc.
DriverInfPath=oem10.inf
```

Restarting the adb server did not produce an adb session.

## Interpretation

v25 forced `deviceinfo_usb_network_function="rndis.usb0"` and enabled
`CONFIG_USB_CONFIGFS_RNDIS=y`, but the host-visible result did not change from
v24. The phone still exposes VID/PID `18D1:D001` without a Windows-visible
RNDIS network interface.

This weakens the hypothesis that the issue is merely NCM vs RNDIS function
selection. The next diagnostic should change the USB descriptor identity or
capture gadget state from the device side. Since there is no shell path in v25,
the practical next step is to return to a known-good v22 SSH baseline and read
the working gadget descriptors from sysfs, then build v26 to match those values
explicitly.

## Next action

Return the phone to fastboot manually. Boot known-good v22 RAM-only to restore
SSH, then collect:

```text
/sys/kernel/config/usb_gadget/g1/idVendor
/sys/kernel/config/usb_gadget/g1/idProduct
/sys/kernel/config/usb_gadget/g1/functions/*/ifname
/sys/kernel/config/usb_gadget/g1/UDC
/sys/class/net/usb0/device/uevent
```

Do not write v25 userdata yet.
