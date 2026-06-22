# Repair Phase 32: v22 Baseline USB Driver Regression

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.img
sha256=cf848d79b4c3ab60d0d58cee99abfd1b5ee9b73c5b0a52be5d6df3bac1518e89
mode=fastboot boot (RAM-only, no partition writes)
```

## Command result

```text
Sending 'boot.img' (51820 KB) OKAY
Booting OKAY
Finished. Total time: 1.225s
```

## Post-boot host status

```text
fastboot devices: no device
adb devices: no usable device
ping 172.16.42.1: 100% loss
host 172.16.42.x address: none
Windows USB/RNDIS/NCM network adapter: none
```

Windows enumerated:

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

This is the same host-visible binding seen with v24 and v25. Because v22 was
previously proven to reach SSH, the current failure is probably not a v22 image
regression. The host has bound VID/PID `18D1:D001` to the Google ADB/WinUSB
driver and is not exposing the gadget as a network adapter.

That blocks the planned SSH-based collection of working gadget descriptors.

## Next action

Do not continue kernel iterations until the host access path is restored.
Possible next steps:

1. Change the Windows driver binding for `USB\VID_18D1&PID_D001\POSTMARKETOS`
   from Google ADB/WinUSB to a network-compatible driver, if available.
2. Build a diagnostic boot image with a different VID/PID that Windows has not
   pinned to the Google ADB driver.
3. Use another host or Linux VM with direct USB passthrough to avoid Windows
   driver binding.

No partition write was performed.
