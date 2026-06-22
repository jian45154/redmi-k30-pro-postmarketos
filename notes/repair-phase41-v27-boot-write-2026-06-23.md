# Repair Phase 41: v27 Boot Partition Write

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Explicit approval

The operator confirmed:

```text
确认重启到 fastboot 并写入 v27 boot 到 boot 分区
```

The device could not reboot to bootloader from pmOS without interactive sudo, so
the operator manually entered fastboot and confirmed:

```text
已进入 fastboot，继续写入 v27 boot
```

## Written partition

```text
partition=boot
command=fastboot flash boot artifacts\images\pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
```

No `dtbo`, `vbmeta`, `super`, `userdata`, modem/EFS, persist, or calibration
partition was written in this phase.

## Image

```text
file=artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
sha256=e6e6a20bee87ca21e5cc4fdcc295dbaaf6faaeaa697672a542943e6afbc9d26e
size=52920320
```

## Prewrite fastboot check

```text
fastboot devices: device present
product: lmi
unlocked: yes
partition-size:boot: 0x8000000
```

`0x8000000` is 134217728 bytes, larger than the v27 boot image.

## Fastboot result

```text
Sending 'boot' (51680 KB) OKAY
Writing 'boot' OKAY
Finished. Total time: 1.416s
```

## Post-write state

```text
fastboot devices: device present
product: lmi
partition-size:boot: 0x8000000
```

The device remained reachable in fastboot after the boot partition write.

## Next validation

The next step is a normal reboot from fastboot to validate persistent boot:

```bat
fastboot reboot
```

Expected result:

```text
RNDIS USB network appears as 0525:a4a2
ping 172.16.42.1 succeeds
SSH port 22 opens
/dev/loop0p2 mounts as /
/dev/loop0p1 mounts as /boot
```
