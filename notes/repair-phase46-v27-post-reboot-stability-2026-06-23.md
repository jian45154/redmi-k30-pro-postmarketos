# Repair Phase 46: v27 Post-Reboot Stability

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Trigger

The operator manually rebooted the phone after the SSH user was unable to issue
a reboot command non-interactively.

## Result

The persistent v27 install came back after manual reboot.

SSH/RNDIS recovery:

```text
poll=1..25 ssh_down_or_booting
ssh_up_after_poll=26
```

Device identity after reboot:

```text
boot_id=c1e0a6cb-856d-415b-91f5-defde8c085e0
uptime=2 min at collection time
kernel=4.19.325-cip128-st12-perf #7-postmarketOS
```

Rootfs and boot mounts:

```text
/      /dev/loop0p2 ext4
/boot  /dev/loop0p1 ext2
/dev   devtmpfs
/sys   sysfs
/proc  proc
/run   tmpfs
/tmp   tmpfs
```

USB/RNDIS:

```text
usb0 UP, LOWER_UP
172.16.42.1/16
route: 172.16.0.0/16 dev usb0
```

Display baseline remains the same:

```text
/dev/dri/card0
/dev/dri/renderD128
/dev/kgsl-3d0
card0-DSI-1 connected
1080x2400x60x184345cmd
cont_splash enabled
```

## Interpretation

Manual reboot stability is verified for the current persistent v27 install:

- boot partition is accepted;
- initramfs starts;
- userdata subpartitions are discovered;
- `/dev/loop0p2` mounts as root;
- userspace starts;
- USB/RNDIS comes up;
- SSH returns;
- display kernel bring-up remains present.

The remaining display issue is still userspace takeover, not boot stability.

## Evidence

Raw log is local-only:

```text
logs/post-reboot-stability-v27-20260623.txt
```

Redacted log:

```text
logs/post-reboot-stability-v27-20260623.redacted.txt
```
