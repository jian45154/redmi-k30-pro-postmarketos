# Xiaomi lmi r6 bootmem release manifest - 2026-06-24

> **Archived evidence — do not execute commands from this file.**
> This snapshot preserves the M-r6 state recorded on 2026-06-24. Any "current"
> wording below is historical and does not describe the present device route.

This is a lightweight repository archive of the host-side release bundle. Large
images are intentionally not committed to git; use the paths and hashes below to
identify the exact artifacts in the local release bundle.

## Bundle

- Bundle path: `/tmp/lmi-release-r6-bootmem-20260624`
- Plan report: `/tmp/lmi-release-r6-bootmem-20260624/PERSISTENT_FLASH_PLAN.txt`
- Command sheet: `/tmp/lmi-release-r6-bootmem-20260624/APPROVAL_REQUIRED_COMMANDS.txt`
- Rollback scan: `/tmp/lmi-release-r6-bootmem-20260624/ROLLBACK_BOOT_CANDIDATES.txt`

## Current Gate Status

- Product: `lmi`
- Unlocked: `yes`
- is-userspace: `yes`
- Persistent route plan: `READY_FOR_FASTBOOTD_PREFLIGHT`

The expected current state is `READY_FOR_FASTBOOTD_PREFLIGHT`. The fastbootd read-only gate has passed, but no flash should be attempted without fresh exact approval for the selected stage.

## Bundle SHA256SUMS

```text
45bc097634b521037a9a7b1298046e9ca56bae21c54e612876b8ad3be9610254  boot-linux-copydown-lmi-r6-bootmem.img
b8062698cc60a39979b7965ba05f8a07ab54e4d67a569e8788004b54a66e40d6  boot-linux-copydown-lmi-r6-bootmem.manifest
d778d4ea659e6fa09ea9038f3626d837d0ec2cea5d09aeb9d0653ce5ea38c4af  xiaomi-lmi-r6-bootmem.img
d1f9978dd6b24141e596350281abb17eed4b17e86538543a8e74ef0393393dad  pmbootstrap-direct-boot-r6-bootmem.img
353dba72fbacde0bd59f3ab71b3e354dd3d96fd706e776919bc7ae72619ab9fb  vmlinuz-r6-bootmem
b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32  sm8250-xiaomi-lmi-r6-bootmem.dtb
c3f6fe0b58c6ad1a8329deff8ac35305dd5868bac71ddeca55708ad259fd4a85  initramfs-r6-bootmem
```

## Bundle File Sizes

| File | Size bytes |
| --- | ---: |
| `boot-linux-copydown-lmi-r6-bootmem.img` | 15892480 |
| `boot-linux-copydown-lmi-r6-bootmem.manifest` | 2613 |
| `xiaomi-lmi-r6-bootmem.img` | 1256631208 |
| `pmbootstrap-direct-boot-r6-bootmem.img` | 40128512 |
| `vmlinuz-r6-bootmem` | 30296072 |
| `sm8250-xiaomi-lmi-r6-bootmem.dtb` | 135561 |
| `initramfs-r6-bootmem` | 9551148 |

## Rollback Boot Candidate

- Path: `/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img`
- SHA256: `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`
- Size bytes: `134217728`

This rollback image is a candidate, not a proven guarantee, until matched to the
exact ROM/device state and tested as part of recovery.

## Read-Only Regeneration

```sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/56_lmi_persistent_flash_plan.sh --quick
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/49_generate_lmi_flash_command_sheet.sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/57_archive_lmi_release_manifest.sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/58_generate_lmi_execution_checklist.sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/64_audit_lmi_persistent_readiness.sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/66_wait_and_audit_lmi_fastbootd.sh --quick
scripts/67_summarize_lmi_post_boot_evidence.sh
```

Single-command refresh:

```sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" scripts/62_refresh_lmi_release_docs.sh --quick
```

## Approval-Required Hardware Commands

These commands are listed for review only. They still require fresh exact
approval immediately before execution.

```sh
fastboot reboot fastboot
scripts/60_stage_lmi_enter_fastbootd.sh --dry-run
scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
scripts/61_stage_lmi_reboot_after_flash.sh --dry-run
scripts/55_stage_lmi_rollback_boot.sh --execute
```

Do not touch `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state as part of this experiment.
