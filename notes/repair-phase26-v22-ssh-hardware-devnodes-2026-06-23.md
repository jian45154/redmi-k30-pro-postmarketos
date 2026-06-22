# Repair Phase 26: v22 SSH Hardware and Devnode Findings

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Logs

```text
logs/repair-ssh-systemcheck-v22-2026-06-23.txt
logs/repair-ssh-systemcheck-v22-2026-06-23.redacted.txt
logs/repair-ssh-devnodes-v22-2026-06-23.txt
logs/repair-ssh-udev-runtime-v22-2026-06-23.txt
logs/repair-ssh-mdev-runtime-v22-2026-06-23.txt
logs/repair-ssh-hardware-after-mdev-v22-2026-06-23.txt
```

## Confirmed working

```text
hostname=xiaomi-lmi
kernel=4.19.325-cip128-st12-perf aarch64
root=/dev/loop0p2 ext4 rw
sshd=started
networkmanager=started
wpa_supplicant=started
usb0=172.16.42.1/16
```

## New blocker

The kernel config has:

```text
# CONFIG_DEVTMPFS is not set
```

Runtime evidence:

```text
/dev is tmpfs
udev status: stopped
udev start: CONFIG_DEVTMPFS=y is required
```

This explains why `/dev/dri`, `/dev/input`, `/dev/snd`, and `/dev/rfkill` were
missing even though sysfs had devices.

## Runtime workaround tested

```text
sudo mdev -s
```

After `mdev -s`:

```text
/dev/dri/card0
/dev/dri/renderD128
/dev/input/event0..event5
/dev/snd/timer
/dev/rfkill
```

Hardware classes observed:

```text
input: xiaomi-touch, qpnp_pon, uinput-goodix, aw8697_haptic, fts_ts, gpio-keys
DRM: card0-DSI-1 connected, mode 1080x2400x60x184345cmd
sound: no soundcards, only timer
rfkill: Bluetooth present, soft blocked
network: no wlan interface yet, only usb0 and virtual interfaces
```

## Next candidate

v23 is a RAM-only normal boot candidate that runs `mdev -s` in initramfs before
`switch_root`, to validate automatic device-node creation without writing
`userdata`.

Long-term fix remains enabling `CONFIG_DEVTMPFS=y` in the downstream kernel
config so eudev can run normally.
