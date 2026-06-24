# Xiaomi lmi r6 post-reboot result - 2026-06-24

This records the approved reboot after the r6 rootfs and boot writes. It is not
an approval for rollback, another reboot, or any additional partition write.

## Executed Command

```sh
LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi scripts/61_stage_lmi_reboot_after_flash.sh --execute
```

## Pre-Reboot State

- Product: `lmi`
- Unlocked: `yes`
- is-userspace: `yes`
- Rootfs write: completed successfully to `userdata`
- Boot write: completed successfully to `boot`
- Boot image SHA256: `45bc097634b521037a9a7b1298046e9ca56bae21c54e612876b8ad3be9610254`
- Rootfs image SHA256: `d778d4ea659e6fa09ea9038f3626d837d0ec2cea5d09aeb9d0653ce5ea38c4af`

## Reboot Result

The reboot command was accepted:

```text
Rebooting OKAY
Finished. Total time: 0.053s
```

User-visible state after reboot:

```text
screen stopped at Redmi logo
```

Host-side 180 second monitor:

```text
seen_fastboot=0
seen_adb=0
seen_telnet_23=0
seen_ssh_2222=0
summary=NO_DEVICE_INTERFACE_OBSERVED
```

Windows USB side after the monitor no longer listed the phone as a connected
Android Bootloader Interface.

## Current Assessment

The bootloader accepted the flashed boot path far enough to leave fastbootd and
show the Redmi splash. No postmarketOS USB network, telnet debug shell, SSH,
ADB, or fastboot interface appeared within the monitor window.

This does not prove that the rootfs was mounted or that initramfs started. The
next evidence needed is earlier boot visibility: returning to bootloader or
fastbootd for rollback, or building a new boot variant with earlier debug
signals before another persistent boot attempt.

## Next Safety Boundary

Do not write any additional partition and do not relock the bootloader.

Recovery or rollback requires a fresh exact approval for the selected command,
for example the guarded rollback helper:

```sh
LMI_ROLLBACK_CONFIRM=rollback-xiaomi-lmi-boot-0c06ad2aca2ab0d5-134217728 scripts/55_stage_lmi_rollback_boot.sh --execute
```

By default that helper requires recovery fastbootd. Using
`LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT=1` is a separate recovery decision if
only bootloader fastboot can be reached.
