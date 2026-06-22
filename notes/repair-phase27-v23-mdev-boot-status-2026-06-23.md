# Repair Phase 27: v23 mdev Normal Boot Status

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-v23-mdev-20260623.img
sha256=d0303001990bda7ebf05816a8ddcbca086e10a490349b6717edb95c8293838b3
mode=fastboot boot (RAM-only, no partition writes)
```

## Command result

```text
Sending 'boot.img' (51820 KB) OKAY
Booting OKAY
Finished. Total time: 1.223s
```

## Post-boot host status

```text
fastboot devices: no device
adb devices: no device
ping 172.16.42.1: 100% loss
host 172.16.42.x address: none
Windows USB PnP: no Android/Fastboot/RNDIS/Linux gadget device present
Windows network adapters: no USB/RNDIS gadget adapter present
```

## Interpretation

v23 was accepted by the bootloader, then stopped before exposing the postmarketOS
USB network or any host-visible USB gadget interface. This is a regression
relative to v22, which reached SSH.

The likely failure point is before or during early userspace USB gadget setup,
or the `mdev -s` change disrupted normal initramfs flow. Because no telnet,
SSH, adb, fastboot, or RNDIS path is available, the next recovery action is a
manual reboot back to fastboot.

## Next action

Do not reuse v23 as the next baseline. Return to fastboot and either:

- boot known-good v22 to restore the working SSH baseline; or
- build v24 with `CONFIG_DEVTMPFS=y` and `CONFIG_DEVTMPFS_MOUNT=y`, then test
  it as the next normal boot candidate.
