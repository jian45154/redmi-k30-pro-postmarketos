# Repair Phase 34: v26 RNDIS USB-ID Boot Success

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-v26-rndis-usbid-currentuserdata-20260623.img
sha256=0d9ef93b7ed119a814c9a2766f426e95ba85377561a1ca1b611fac6e58fb0973
mode=fastboot boot (RAM-only, no partition writes)
```

## Command result

```text
Sending 'boot.img' (51836 KB) OKAY
Booting OKAY
Finished. Total time: 1.248s
```

## Host-visible result

Windows enumerated the device as a RNDIS network gadget:

```text
USB\VID_0525&PID_A4A2\POSTMARKETOS
Remote NDIS based Internet Sharing Device
Interface: Ethernet 2
Host IPv4: 172.16.42.2/24
Device ping: 172.16.42.1 reachable
SSH port 22: open
```

This confirms the v22/v24/v25 USB failure was caused by the host binding
`18D1:D001` to Google ADB/WinUSB instead of a network driver. Changing the
gadget VID/PID restored the Windows network path.

## Device-side result

SSH login succeeded as `lmi`. The system reached normal userspace:

```text
Linux xiaomi-lmi 4.19.325-cip128-st12-perf #7-postmarketOS
/dev/loop0p2 mounted on /
/dev/loop0p1 mounted on /boot
devtmpfs mounted on /dev
usb0=172.16.42.1/16
sshd.pam listener running
```

The live USB gadget config confirms the intended ID and function:

```text
idVendor=0x0525
idProduct=0xa4a2
function=rndis.usb0
UDC=a600000.dwc3
```

## Logs

```text
raw=logs/repair-ssh-systemcheck-v26-2026-06-23.txt
raw_sha256=3b2f1a5521ca0ef956cb41d2c40068cfd515a8892c572a4ce0cbb3f06c7ec5b9
redacted=logs/repair-ssh-systemcheck-v26-2026-06-23.redacted.txt
redacted_sha256=b1f2edfc4464b352cf3eae67e20f1348dd958ce0d60a6eac8b68c51c59f31974
```

Use the redacted log for GitHub. The raw log contains device identifiers from
the kernel cmdline.

## Interpretation

v26 is the first confirmed normal-boot milestone after the USB host regression:
rootfs discovery, loop partition mount, switch_root, USB network, and SSH are
all working from a RAM-only boot image against the existing userdata.

No partition write was performed.
