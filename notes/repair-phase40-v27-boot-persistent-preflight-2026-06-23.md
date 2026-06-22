# Repair Phase 40: v27 Boot Persistence Preflight

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Purpose

Prepare for a possible persistent boot partition write after the full v27 image
pair was validated with RAM-only `fastboot boot`.

This phase is preflight only. No boot partition write was performed.

## Current running state

The device is running the full v27 system:

```text
kernel=Linux xiaomi-lmi 4.19.325-cip128-st12-perf #7-postmarketOS
pmos_boot_uuid=3c14f75f-450e-4457-b109-6fc5d9f7c54c
pmos_root_uuid=b50c1119-2cd9-4675-a9be-3201c98d54ec
androidboot.bootdevice=1d84000.ufshc
battery=100%, Full
```

## Boot partition mapping

From `/dev/block/by-name`:

```text
boot -> /dev/sde50
recovery -> /dev/sda28
dtbo -> /dev/sde47
vbmeta -> /dev/sde16
```

From `lsblk`:

```text
/dev/sde50 size=134217728
```

No A/B `boot_a` or `boot_b` entry was observed in the running system. The
bootloader also previously did not report `current-slot`.

## Candidate boot image

```text
file=artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
sha256=e6e6a20bee87ca21e5cc4fdcc295dbaaf6faaeaa697672a542943e6afbc9d26e
size=52920320
```

Capacity check:

```text
boot partition size=134217728
boot image size=52920320
fits=yes
```

## Proposed command

After rebooting to bootloader:

```bat
fastboot flash boot artifacts\images\pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
```

This is a persistent boot partition write. It does not intentionally write
`userdata`, `dtbo`, `vbmeta`, `super`, modem/EFS, persist, or calibration
partitions.

## Safety boundary

Persistent boot flashing is higher risk than RAM-only boot. If the written boot
image fails, recovery depends on the bootloader remaining reachable by key combo
or USB and on having a known-good boot image available locally.

Proceed only after separate explicit confirmation for rebooting to bootloader
and writing the exact `boot` partition command above.
