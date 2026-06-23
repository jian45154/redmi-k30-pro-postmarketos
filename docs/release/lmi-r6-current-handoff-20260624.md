# Xiaomi lmi r6 current handoff - 2026-06-24

This is the short handoff for the current `edge` mainline/copydown route. It
is not an approval to execute hardware commands.

## Repository

- Branch: `edge`
- HEAD: `8d629e1`
- Remote: `https://github.com/jian45154/redmi-k30-pro-postmarketos.git`

## Device Gate

- Product: `lmi`
- Unlocked: `yes`
- is-userspace: `no`
- Route status: `WAITING_FOR_RECOVERY_FASTBOOTD`

Current blocker: the device is still in bootloader fastboot. The next approved
hardware-state step must be entering recovery fastbootd.

## Exact Next Command Requiring Approval

```sh
LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute
```

After that, run:

```sh
scripts/52_wait_lmi_fastbootd.sh
```

Do not flash unless the wait/preflight result reports `is-userspace=yes`.

## Artifact Hashes

- Boot: `cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570`
- Rootfs: `24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7`
- Rollback boot candidate: `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`

## Canonical Local Reports

- Release manifest: `docs/release/lmi-r6-bootmem-release-manifest-20260624.md`
- Execution checklist: `docs/release/lmi-r6-bootmem-execution-checklist-20260624.md`
- Plan report: `/tmp/lmi-release-r6-bootmem-20260624/PERSISTENT_FLASH_PLAN.txt`
- Refresh summary: `/tmp/lmi-release-r6-bootmem-20260624/RELEASE_REFRESH_SUMMARY.txt`

## Refresh Command

```sh
scripts/62_refresh_lmi_release_docs.sh --quick
```

## Hard Safety Boundary

Do not run any `fastboot flash`, `fastboot reboot`, `fastboot reboot
fastboot`, `pmbootstrap flasher flash_rootfs`, erase, format, sideload, or
bootloader-lock command without fresh exact approval for that command.

Do not touch `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state as part of this route.
