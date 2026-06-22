# Repair Phase 39: Full v27 RAM Boot Success

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
boot=artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
boot_sha256=e6e6a20bee87ca21e5cc4fdcc295dbaaf6faaeaa697672a542943e6afbc9d26e
mode=fastboot boot (RAM-only, no boot partition write)
```

This boot image targets the newly written v27 userdata image:

```text
pmos_boot_uuid=3c14f75f-450e-4457-b109-6fc5d9f7c54c
pmos_root_uuid=b50c1119-2cd9-4675-a9be-3201c98d54ec
```

## Command result

```text
Sending 'boot.img' (51680 KB) OKAY
Booting OKAY
Finished. Total time: 1.351s
```

## Host-visible result

```text
USB\VID_0525&PID_A4A2\POSTMARKETOS
Remote NDIS based Internet Sharing Device
Host IPv4: 172.16.42.2/24
Device ping: 172.16.42.1 reachable
SSH port 22: open
```

## Device-side result

SSH login succeeded as `lmi`. The system reached userspace from the newly
written v27 userdata:

```text
Linux xiaomi-lmi 4.19.325-cip128-st12-perf #7-postmarketOS
/dev/loop0p2 mounted on /
/dev/loop0p1 mounted on /boot
devtmpfs mounted on /dev
usb0=172.16.42.1/16
sshd.pam listener running
```

`blkid` confirms the mounted loop partitions match the v27 UUID pair:

```text
/dev/loop0p1: LABEL="pmOS_boot" UUID="3c14f75f-450e-4457-b109-6fc5d9f7c54c" TYPE="ext2"
/dev/loop0p2: LABEL="pmOS_root" UUID="b50c1119-2cd9-4675-a9be-3201c98d54ec" TYPE="ext4"
```

The live USB gadget config confirms the expected v27 USB settings:

```text
idVendor=0x0525
idProduct=0xa4a2
function=rndis.usb0
```

## Logs

```text
raw=logs/repair-ssh-systemcheck-v27-full-2026-06-23.txt
raw_sha256=d538abe2d900b8b2181b9e355e3f54a3f14e4dc81c3a73c10b54d89f62e90d86
redacted=logs/repair-ssh-systemcheck-v27-full-2026-06-23.redacted.txt
redacted_sha256=1568ecb138f962596a11e3df7cea3915394a579517d2c294a8a92f796b94cb46
```

Use the redacted log for GitHub. The raw log contains device identifiers from
the kernel cmdline and USB gadget state.

## Interpretation

The full v27 image pair is validated:

1. v27 userdata was written to `userdata`.
2. v27 boot image was RAM-booted without writing the boot partition.
3. The v27 `pmOS_boot` and `pmOS_root` UUIDs were discovered and mounted.
4. `switch_root`, RNDIS USB networking, and OpenSSH all reached working state.

No persistent boot partition write was performed.
