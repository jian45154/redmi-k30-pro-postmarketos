# Xiaomi lmi r6 rootfs write result - 2026-06-24

> **Archived evidence — do not execute commands from this file.**
> This completed result is historical evidence. Any suggested next step or
> approval language below has expired and is not present authorization.

This records the approved rootfs write that was executed after the r6
mainline/copydown fastbootd preflight passed. It is not an approval for any
additional write or reboot.

## Executed Command

```sh
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-rootfs-45bc097634b5-d778d4ea659e scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
```

## Result

- Stage: `rootfs`
- Target partition: `userdata`
- Status: `OK`
- Fastbootd device after write: `<redacted-device-serial> fastboot`
- Product after write: `lmi`
- is-userspace after write: `yes`
- userdata size reported after write: `0x1AC07FB000`
- Stage report: `/tmp/lmi-release-r6-bootmem-20260624/FLASH_STAGE_RESULT.txt`

The fastboot output completed all sparse chunks:

```text
Sending sparse 'userdata' 1/5 ... OKAY
Writing 'userdata' ... OKAY
Sending sparse 'userdata' 2/5 ... OKAY
Writing 'userdata' ... OKAY
Sending sparse 'userdata' 3/5 ... OKAY
Writing 'userdata' ... OKAY
Sending sparse 'userdata' 4/5 ... OKAY
Writing 'userdata' ... OKAY
Sending sparse 'userdata' 5/5 ... OKAY
Writing 'userdata' ... OKAY
Finished. Total time: 45.269s
```

## Artifact Identity

- Boot image SHA256: `45bc097634b521037a9a7b1298046e9ca56bae21c54e612876b8ad3be9610254`
- Rootfs image SHA256: `d778d4ea659e6fa09ea9038f3626d837d0ec2cea5d09aeb9d0653ce5ea38c4af`
- Rollback boot candidate SHA256: `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`

## Post-Write Gate

The read-only fastbootd audit after the rootfs write passed:

```text
route_status=READY_FOR_FASTBOOTD_PREFLIGHT
warnings=0
failures=0
fastbootd audit gate: OK
```

## Next Approval Boundary

The rootfs write does not authorize the boot write or a reboot. The next
persistent-write command still requires fresh exact approval:

```sh
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-45bc097634b5-d778d4ea659e scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
```

Do not touch `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state as part of this route.
