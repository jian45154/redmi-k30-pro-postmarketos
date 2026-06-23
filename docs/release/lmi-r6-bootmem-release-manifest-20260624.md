# Xiaomi lmi r6 bootmem release manifest - 2026-06-24

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
- is-userspace: `no`
- Persistent route plan: `WAITING_FOR_RECOVERY_FASTBOOTD`

The expected current state is `WAITING_FOR_RECOVERY_FASTBOOTD`. No flash should
be attempted while `is-userspace=no` unless a separately approved rollback
decision explicitly chooses bootloader fastboot.

## Bundle SHA256SUMS

```text
cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570  boot-linux-copydown-lmi-r6-bootmem.img
facabcaac7745be9e5bf1c94338ffd974d6ca6fa8982513edac69b721af0cf0b  boot-linux-copydown-lmi-r6-bootmem.manifest
24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7  xiaomi-lmi-r6-bootmem.img
bdccac69e54cab35044f24d3ce4914e2fced548879af47ae1d88038024d9cf5e  pmbootstrap-direct-boot-r6-bootmem.img
91e17b132e95c48a86e3fe910075344162fd8e5082ba0f36e9441cb0675bc49c  vmlinuz-r6-bootmem
b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32  sm8250-xiaomi-lmi-r6-bootmem.dtb
c3f6fe0b58c6ad1a8329deff8ac35305dd5868bac71ddeca55708ad259fd4a85  initramfs-r6-bootmem
```

## Bundle File Sizes

| File | Size bytes |
| --- | ---: |
| `boot-linux-copydown-lmi-r6-bootmem.img` | 15892480 |
| `boot-linux-copydown-lmi-r6-bootmem.manifest` | 2613 |
| `xiaomi-lmi-r6-bootmem.img` | 1256602620 |
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
```

Execution checklist:

```text
docs/release/lmi-r6-bootmem-execution-checklist-20260624.md
```

## Approval-Required Hardware Commands

These commands are listed for review only. They still require fresh exact
approval immediately before execution.

```sh
fastboot reboot fastboot
scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
fastboot reboot
scripts/55_stage_lmi_rollback_boot.sh --execute
```

Do not touch `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state as part of this experiment.
