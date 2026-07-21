# Xiaomi lmi r7 earlydebug build result - 2026-06-24

> **Archived evidence — do not execute commands from this file.**
> This completed result is historical evidence. Any suggested next step or
> approval language below has expired and is not present authorization.

## Context

After the r6 persistent rootfs and boot writes, the device rebooted only to the
Redmi logo. The 180 second post-boot monitor observed no fastboot, no ADB, no
postmarketOS USB network, no telnet on `172.16.42.1:23`, and no SSH on
`172.16.42.1:2222`.

The next strategy is not another rootfs write. The next candidate is a boot-only
r7 earlydebug image with more kernel-side visibility:

- r6 bootmem DTS path preserved;
- no EFI stub/zboot path preserved;
- 48-bit arm64 VA/PA path preserved;
- `pmos.debug-shell` preserved;
- cmdline adds `loglevel=8 ignore_loglevel initcall_debug printk.devkmsg=on`;
- cmdline adds ramoops parameters for the bootmem reserved region;
- kernel config enables larger pstore kmsg, printk timestamps, debugfs, and
  dynamic debug.

## Build command

```sh
scripts/68_mainline_progress_loop.sh --build --r7-earlydebug --once --quick
```

The loop did not execute reboot, boot, flash, erase, format, sideload, or any
partition write.

## Result

- Bundle: `/tmp/lmi-release-r7-earlydebug-20260624`
- Copydown dir: `/tmp/lmi-copydown-r7-earlydebug-20260624`
- Loop report: `/tmp/lmi-release-r7-earlydebug-20260624/MAINLINE_PROGRESS_LOOP.txt`
- `sha256sum -c SHA256SUMS`: OK for all listed r7 artifacts
- Copydown verifier: OK

## Artifact hashes

```text
154ddbdf09ad42b5fd6652907431bf4f7dbcf26463b785ac462fab7ee65ed595  boot-linux-copydown-lmi-r7-earlydebug.img
f4dbc69168f534ce64b802b7f68c0fc1d88162cdcf2b0142fd89b4110e72867f  boot-linux-copydown-lmi-r7-earlydebug.manifest
0c98ede92d20a175964bba98873206b1b701a4b730a05089530c241c21969a66  xiaomi-lmi-r7-earlydebug.img
2b11719d0fd31aa6fa821ef3b3ba740f2d38abc560524882f5e68985fd7934cf  pmbootstrap-direct-boot-r7-earlydebug.img
d76f24df1b7d74b7131a531544d8af7132530ac5fb01c04703d59e0564d4de7c  vmlinuz-r7-earlydebug
b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32  sm8250-xiaomi-lmi-r7-earlydebug.dtb
4d538f120458e004530d982ddd082bc8e5a3f20aee733cc9379f100031931d95  initramfs-r7-earlydebug
```

## Copydown verifier

```text
copydown boot verification: OK
boot_img=/tmp/lmi-copydown-r7-earlydebug-20260624/boot-linux-copydown-lmi.img
boot_img_sha256=154ddbdf09ad42b5fd6652907431bf4f7dbcf26463b785ac462fab7ee65ed595
boot_img_size=16306176
boot_partition_size=134217728
outer_text_offset=0x80000
runtime_dtb_sha256=b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32
```

## Safety boundary

Current best next hardware strategy:

1. Recover the phone to bootloader fastboot or recovery fastbootd manually.
2. Confirm host visibility with read-only checks only.
3. Prefer testing only the r7 boot image next. Do not rewrite rootfs unless new
   evidence proves the existing userdata rootfs is wrong.
4. Require fresh exact approval before any boot partition write or reboot.

The r7 rootfs image exists only because `pmbootstrap install/export` produces a
complete image set. It is not the recommended next write target.

## Current device checkpoint

After reattaching USB from Windows to WSL with `usbipd.exe attach --wsl --busid
2-5`, WSL sees the phone again:

```text
fastboot devices: <redacted-device-serial> fastboot
product: lmi
unlocked: yes
is-userspace: no
partition-type:boot: raw
partition-size:boot: 0x8000000
partition-type:userdata: f2fs
partition-size:userdata: 0x1AC07FB000
```

This is bootloader fastboot, not recovery fastbootd. The existing guarded write
path remains blocked until `fastboot getvar is-userspace` returns `yes`.

The fastbootd entry dry-run passed from this state:

```text
LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi
fastboot reboot fastboot
```

Do not execute that command without fresh exact approval.

The r7 boot-only staged dry-run also passed:

```text
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-154ddbdf09ad-0c98ede92d20
fastboot flash boot /tmp/lmi-release-r7-earlydebug-20260624/boot-linux-copydown-lmi-r7-earlydebug.img
```

That is not an approval and was not executed. It should only be considered after
the phone is in recovery fastbootd and the r7 fastbootd preflight passes.

## Fastbootd checkpoint

The approved fastbootd entry command was executed:

```sh
LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute
```

The command completed after WSL USB reattach. The device then reported:

```text
fastboot devices: <redacted-device-serial> fastboot
product: lmi
unlocked: yes
is-userspace: yes
partition-type:boot: raw
partition-size:boot: 0x8000000
partition-type:userdata: f2fs
partition-size:userdata: 0x1AC07FB000
```

The r7 fastbootd preflight passed:

```text
preflight: OK
boot_img_sha256=154ddbdf09ad42b5fd6652907431bf4f7dbcf26463b785ac462fab7ee65ed595
boot_img_size=16306176
rootfs_img_sha256=0c98ede92d20a175964bba98873206b1b701a4b730a05089530c241c21969a66
rootfs_expanded_size=2155872256
```

The current approval boundary is boot-only r7 write. Rootfs should not be
rewritten for this test.

Exact command requiring fresh approval:

```sh
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-154ddbdf09ad-0c98ede92d20 \
  LMI_RELEASE_BUNDLE_DIR=/tmp/lmi-release-r7-earlydebug-20260624 \
  LMI_COPYDOWN_BOOT_IMG=/tmp/lmi-release-r7-earlydebug-20260624/boot-linux-copydown-lmi-r7-earlydebug.img \
  LMI_COPYDOWN_MANIFEST=/tmp/lmi-release-r7-earlydebug-20260624/boot-linux-copydown-lmi-r7-earlydebug.manifest \
  LMI_ROOTFS_IMG=/tmp/lmi-release-r7-earlydebug-20260624/xiaomi-lmi-r7-earlydebug.img \
  scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
```

## Boot write result

The r7 boot-only write was explicitly approved and executed:

```sh
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-154ddbdf09ad-0c98ede92d20 \
  LMI_RELEASE_BUNDLE_DIR=/tmp/lmi-release-r7-earlydebug-20260624 \
  LMI_COPYDOWN_BOOT_IMG=/tmp/lmi-release-r7-earlydebug-20260624/boot-linux-copydown-lmi-r7-earlydebug.img \
  LMI_COPYDOWN_MANIFEST=/tmp/lmi-release-r7-earlydebug-20260624/boot-linux-copydown-lmi-r7-earlydebug.manifest \
  LMI_ROOTFS_IMG=/tmp/lmi-release-r7-earlydebug-20260624/xiaomi-lmi-r7-earlydebug.img \
  scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
```

Result:

```text
Sending 'boot' (15924 KB) OKAY [1.164s]
Writing 'boot' OKAY [0.122s]
Finished. Total time: 1.298s
```

Post-write read-only state:

```text
fastboot devices: <redacted-device-serial> fastboot
product: lmi
unlocked: yes
is-userspace: yes
```

No reboot was executed after this write. The next approval boundary is the
post-write test reboot:

```sh
LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi \
  scripts/61_stage_lmi_reboot_after_flash.sh --execute
```

## Post-reboot result

The post-write test reboot was explicitly approved and executed:

```sh
LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi \
  LMI_RELEASE_BUNDLE_DIR=/tmp/lmi-release-r7-earlydebug-20260624 \
  scripts/61_stage_lmi_reboot_after_flash.sh --execute
```

Result:

```text
Rebooting OKAY [0.002s]
Finished. Total time: 0.052s
```

A 180 second read-only monitor was then run:

```sh
LMI_RELEASE_BUNDLE_DIR=/tmp/lmi-release-r7-earlydebug-20260624 \
  scripts/54_monitor_lmi_post_boot.sh --timeout 180 --interval 3 --collect-telnet-log
```

Observed host interfaces:

```text
seen_fastboot=0
seen_adb=0
seen_telnet_23=0
seen_ssh_2222=0
summary=NO_DEVICE_INTERFACE_OBSERVED
```

Post-monitor USB state:

```text
usbipd.exe list: no connected Android Bootloader Interface or ADB device
lsusb: only WSL root hubs
```

User-visible device state:

```text
screen: continuously stays on the Redmi logo page
host USB: no connected Android Bootloader Interface or ADB device
WSL USB: only root hubs
fastboot devices: empty
```

Current milestone assessment:

- bootloader accepted the r7 boot image write;
- no evidence yet that the r7 kernel reached an observable initramfs;
- no evidence yet that USB gadget/network initialized;
- no rootfs, switch_root, or userspace milestone is proven.

Next safe step is manual recovery to bootloader fastboot, then read-only
visibility checks. Do not write another partition until this result is reviewed.

## Recovery checkpoint after stuck logo

After the user reported that the device continuously stayed on the Redmi logo,
host checks were repeated. Windows saw the phone again as an Android Bootloader
Interface, and after reattaching `2-5` to WSL the device reported:

```text
fastboot devices: <redacted-device-serial> fastboot
product: lmi
unlocked: yes
is-userspace: no
```

This is bootloader fastboot, not recovery fastbootd.

Rollback boot dry-run using the known backup image validated the image metadata:

```text
rollback_boot=/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img
rollback_boot_sha256=0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf
rollback_boot_size=134217728
android_boot_magic=OK
partition-type:boot=raw
partition-size:boot=0x8000000
```

The rollback helper correctly refused by default because the device is not in
recovery fastbootd:

```text
rollback preflight: FAIL
- recovery fastbootd is required by default; got is-userspace='no'
```

The fastbootd entry helper dry-run passed from this state:

```text
LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi \
  scripts/60_stage_lmi_enter_fastbootd.sh --execute
```

Recommended next step is recovery, not another experimental boot image:

1. Enter recovery fastbootd with the guarded helper after fresh approval.
2. Run rollback dry-run again and confirm `is-userspace=yes`.
3. If approved, flash only the known-good rollback boot image.
4. Reboot only after separate approval.

## Rollback fastbootd checkpoint

The fastbootd entry command was approved and executed again for recovery:

```text
fastboot reboot fastboot: OKAY
```

After WSL USB reattach, the device reported:

```text
fastboot devices: <redacted-device-serial> fastboot
product: lmi
unlocked: yes
is-userspace: yes
```

The guarded rollback dry-run then passed:

```text
rollback_boot=/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img
rollback_boot_sha256=0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf
rollback_boot_size=134217728
partition-type:boot=raw
partition-size:boot=0x8000000
dry-run: OK
```

Current approval boundary is rollback boot write only:

```sh
LMI_ROLLBACK_CONFIRM=rollback-xiaomi-lmi-boot-0c06ad2aca2ab0d5-134217728 \
  scripts/55_stage_lmi_rollback_boot.sh --execute
```

This writes only the `boot` partition with the known backup image. It does not
write rootfs/userdata and does not reboot.

## Rollback boot write result

The rollback boot write was explicitly approved and executed:

```sh
LMI_ROLLBACK_CONFIRM=rollback-xiaomi-lmi-boot-0c06ad2aca2ab0d5-134217728 \
  scripts/55_stage_lmi_rollback_boot.sh --execute
```

Result:

```text
Sending 'boot' (131072 KB) OKAY [12.015s]
Writing 'boot' OKAY [0.733s]
Finished. Total time: 18.551s
```

Post-write read-only state:

```text
fastboot devices: <redacted-device-serial> fastboot
product: lmi
unlocked: yes
is-userspace: yes
```

No reboot was executed after rollback. The next approval boundary is a reboot
to verify the restored boot image.

## Rollback reboot result

The post-rollback reboot was explicitly approved and executed:

```sh
LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi \
  scripts/61_stage_lmi_reboot_after_flash.sh --execute
```

Result:

```text
Rebooting OKAY [0.002s]
Finished. Total time: 0.052s
```

The host monitor did not observe fastboot, ADB, telnet, or SSH during the first
60 seconds after reboot. The user then reported that the phone screen was in
recovery.

Windows USB/IP saw the recovery ADB interface:

```text
2-5 18d1:4e11 Android ADB Interface Not shared
```

WSL could not attach the interface because it is not shared, and `usbipd bind`
requires Windows administrator privileges in this shell:

```text
usbipd: error: Access denied; this operation requires administrator privileges.
```

Windows `adb.exe devices` also showed no listed device at that moment. The
rollback nevertheless changed the visible device behavior from persistent Redmi
logo to recovery screen, so the backup boot image appears to have restored a
recoverable boot path.
