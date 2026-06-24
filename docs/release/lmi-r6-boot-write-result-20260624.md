# Xiaomi lmi r6 boot write result - 2026-06-24

This records the approved boot write that was executed after the r6 rootfs
write and fastbootd preflight passed. It is not an approval to reboot.

## Executed Command

```sh
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-45bc097634b5-d778d4ea659e scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
```

## Result

- Stage: `boot`
- Target partition: `boot`
- Status: `OK`
- Fastbootd device after write: `8336ded7 fastboot`
- Product after write: `lmi`
- is-userspace after write: `yes`
- boot partition size after write: `0x8000000`
- Stage report: `/tmp/lmi-release-r6-bootmem-20260624/FLASH_STAGE_RESULT.txt`

The fastboot output completed successfully:

```text
Sending 'boot' (15520 KB) OKAY
Writing 'boot' OKAY
Finished. Total time: 2.969s
```

## Artifact Identity

- Boot image SHA256: `45bc097634b521037a9a7b1298046e9ca56bae21c54e612876b8ad3be9610254`
- Rootfs image SHA256: `d778d4ea659e6fa09ea9038f3626d837d0ec2cea5d09aeb9d0653ce5ea38c4af`
- Rollback boot candidate SHA256: `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`

## Post-Write Gate

The read-only fastbootd audit after the boot write passed:

```text
route_status=READY_FOR_FASTBOOTD_PREFLIGHT
warnings=0
failures=0
fastbootd audit gate: OK
```

## Next Approval Boundary

The boot write does not authorize a reboot. The next hardware-state command
still requires fresh exact approval:

```sh
LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi scripts/61_stage_lmi_reboot_after_flash.sh --execute
```

After an approved reboot, collect evidence:

```sh
scripts/54_monitor_lmi_post_boot.sh --timeout 180
scripts/67_summarize_lmi_post_boot_evidence.sh
```

Do not touch `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state as part of this route.
