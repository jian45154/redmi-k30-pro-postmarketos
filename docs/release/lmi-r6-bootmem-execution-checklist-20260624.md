# Xiaomi lmi r6 bootmem execution checklist - 2026-06-24

This checklist is a compact handoff for the current persistent fastbootd route.
It is not an approval and does not make any hardware command safe by itself.

## Current State

- Product: `lmi`
- Unlocked: `yes`
- is-userspace: `no`
- Route plan: `WAITING_FOR_RECOVERY_FASTBOOTD`
- Bundle: `/tmp/lmi-release-r6-bootmem-20260624`

Current blocker: the phone is in bootloader fastboot, not recovery fastbootd.

## Artifact Identity

- Boot image: `/tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.img`
- Boot SHA256: `cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570`
- Rootfs image: `/tmp/lmi-release-r6-bootmem-20260624/xiaomi-lmi-r6-bootmem.img`
- Rootfs SHA256: `24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7`
- Copydown manifest: `/tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.manifest`
- Rollback boot: `/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img`
- Rollback SHA256: `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`

## Next Approval Boundary

The next hardware-state command requiring fresh exact approval is:

```sh
fastboot reboot fastboot
```

Use the guarded stage helper for dry-run review:

```sh
scripts/60_stage_lmi_enter_fastbootd.sh --dry-run
```

After that command, run the read-only wait/preflight:

```sh
scripts/52_wait_lmi_fastbootd.sh
```

Do not flash unless the resulting preflight reports `is-userspace=yes`.

## Readiness Audit

Before requesting any execute approval, refresh and inspect the read-only
readiness audit:

```sh
scripts/64_audit_lmi_persistent_readiness.sh
```

This audit checks artifact hashes, release docs, rollback candidate identity,
dry-run stage guards, and the current fastbootd gate. It does not reboot, boot,
flash, erase, format, or write partitions.

## Stage Tokens

These tokens are derived from the current artifact hashes.

```text
rootfs:   LMI_FLASH_CONFIRM=flash-xiaomi-lmi-rootfs-cfc5748035bc-24918896b43c
boot:     LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-cfc5748035bc-24918896b43c
rollback: LMI_ROLLBACK_CONFIRM=rollback-xiaomi-lmi-boot-0c06ad2aca2ab0d5-134217728
fastbootd: LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi
test reboot: LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi
```

## Persistent Test Order

Each execute command still requires separate fresh exact approval immediately
before use.

1. Enter recovery fastbootd:

   ```sh
   LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute
   ```

2. Wait for fastbootd and run read-only preflight:

   ```sh
   scripts/52_wait_lmi_fastbootd.sh
   ```

   Or use the combined read-only gate, which waits, preflights, and reruns the
   persistent readiness audit:

   ```sh
   scripts/66_wait_and_audit_lmi_fastbootd.sh
   ```

3. Flash rootfs to `userdata` only if userdata destruction is accepted:

   ```sh
   LMI_FLASH_CONFIRM=flash-xiaomi-lmi-rootfs-cfc5748035bc-24918896b43c scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
   ```

4. Flash the copydown boot image to `boot`:

   ```sh
   LMI_FLASH_CONFIRM=flash-xiaomi-lmi-boot-cfc5748035bc-24918896b43c scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
   ```

5. Reboot only after separate approval:

   ```sh
   LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi scripts/61_stage_lmi_reboot_after_flash.sh --execute
   ```

6. Collect post-boot evidence:

   ```sh
   scripts/54_monitor_lmi_post_boot.sh --timeout 180
   ```

## Rollback Boundary

Rollback boot write also requires fresh exact approval:

```sh
LMI_ROLLBACK_CONFIRM=rollback-xiaomi-lmi-boot-0c06ad2aca2ab0d5-134217728 scripts/55_stage_lmi_rollback_boot.sh --execute
```

By default rollback execute mode requires recovery fastbootd. Using
`LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT=1` is a separate recovery decision if
fastbootd cannot be reached.

## Forbidden In This Route

Do not write `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state.
