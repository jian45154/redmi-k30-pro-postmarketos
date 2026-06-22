# Repair Phase 36: v27 Current-Userdata RAM Boot Success

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

The full v27 boot image points at the new v27 userdata UUIDs, so a direct
RAM-only boot would not validate the currently flashed userdata. For this test,
the v27 kernel and ramdisk were repacked with the known-good current userdata
UUID pair.

```text
file=artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-currentuserdata-20260623.img
sha256=40ed61c2eaf8bd4c732ffa42e961cfd5d3f70a0959efe012d070959ea1c12bef
mode=fastboot boot (RAM-only, no partition writes)
userdata_pairing=current-v22-v26-userdata
pmos_boot_uuid=2c2600b1-700f-4bdd-a22c-bb12cc589baa
pmos_root_uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370
```

## Command result

```text
Sending 'boot.img' (51680 KB) OKAY
Booting OKAY
Finished. Total time: 1.232s
```

## Host-visible result

```text
USB\VID_0525&PID_A4A2\POSTMARKETOS
Remote NDIS based Internet Sharing Device
Host IPv4: 172.16.42.2/24
Device ping: 172.16.42.1 reachable
SSH port 22: open after extended wait
```

The first 120-second probe saw ping but not SSH. A follow-up probe saw SSH 22
open. Static comparison showed v26 and v27-currentuserdata have identical
cmdline, `init`, and `init_functions.sh`, so this was treated as delayed
userspace/sshd availability rather than a different rootfs discovery failure.

## Device-side result

SSH login succeeded as `lmi`. The system reached userspace:

```text
Linux xiaomi-lmi 4.19.325-cip128-st12-perf #7-postmarketOS
/dev/loop0p2 mounted on /
/dev/loop0p1 mounted on /boot
devtmpfs mounted on /dev
usb0=172.16.42.1/16
sshd.pam listener running
```

The live USB gadget config confirms the expected v27 USB settings:

```text
idVendor=0x0525
idProduct=0xa4a2
function=rndis.usb0
```

## Logs

```text
raw=logs/repair-ssh-systemcheck-v27-currentuserdata-2026-06-23.txt
raw_sha256=8b8e4386416859195fb9d9035c4bcf91776b2a34151c1da0f3dc276164e918c4
redacted=logs/repair-ssh-systemcheck-v27-currentuserdata-2026-06-23.redacted.txt
redacted_sha256=944ce167204d27d585b8d901e3c0de15b517ecd663cab17a04ed4f180ea45c4e
compare_log=logs/compare-v26-v27-currentuserdata-20260623.txt
```

Use the redacted log for GitHub. The raw log contains device identifiers from
the kernel cmdline and USB gadget state.

## Interpretation

v27 RAM-only boot is successful against the currently flashed userdata when the
boot image uses the current userdata UUIDs. This validates the v27 kernel,
ramdisk, RNDIS USB ID, devtmpfs, and loopdev fixes without rewriting storage.

The full v27 userdata image has not been written yet. Testing the full v27
image pair requires a separate explicit approval to overwrite `userdata`.

No partition write was performed.
