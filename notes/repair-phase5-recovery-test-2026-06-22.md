# Repair Phase 5: Recovery RAM-Boot Test

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Scope

Two separately approved temporary recovery boots. No recovery image or phone
partition was flashed, erased or formatted.

## A15 Candidate

```text
file=artifacts/images/[REC_BOOT]3.7.1_12-RedmiK30Pro-POCOF2Pro_v9.0_A15-lmi-skkk.img
sha256=61946D4DA0B1B07C8E110423E2FE3E2DAA14EC18F25BE0E9C0936B392FB426A2
```

Fastboot accepted the image but the device returned to fastboot. ADB never
appeared. This image is not an approved recovery path for the current device
state.

## A12 Candidate

```text
file=artifacts/images/[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk.img
sha256=D9E5A6BA2ED86CA345EFDAFB65B36961B157ABFF39200079053751B046DF2A45
product=lmi
unlocked=yes
battery_voltage_mv=4419
is_userspace=no
```

Fastboot accepted and RAM-booted the image. Windows enumerated a Redmi K30 Pro
ADB interface and `adb devices -l` reported recovery mode.

Read-only observations:

```text
ro.product.device=lmi
ro.product.model=Redmi K30 Pro
ro.build.version.release=12
ro.twrp.version=3.6.2_12-RedmiK30Pro_v5.6_A12
userdata=/dev/block/sda34
userdata_size=114898743296
```

TWRP exposes `format data`, `wipe`, `sideload` and `reboot bootloader` through
its CLI. None was executed.

Recovery automatically mounted the existing `/dev/block/sda34` on `/data` as
read-write ext4 during startup. This was recovery behavior, not an explicit
mount or format command from this test, but it means the RAM boot was not
strictly storage-read-only.

## Result

The A12 TWRP image is a demonstrated RAM-boot recovery path. Since the existing
Android boot and super partitions remain untouched, returning from a
postmarketOS userdata image can use this recovery to format data for Android.
A full LineageOS or MIUI ROM is still preferable and was not found locally.
