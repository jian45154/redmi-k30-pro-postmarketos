# Mainline Track (`M-rNN`)

## Identity

- Canonical version label: `M-rNN`.
- Legacy file label: `rNN`, `mainline-rNN`, or `copydown-rNN`.
- Kernel/package source: external SM8250 mainline overlay imported under
  `artifacts/mainline-pmaports/`.
- Package roots:
  - `artifacts/mainline-pmaports/device-xiaomi-lmi/`
  - `artifacts/mainline-pmaports/firmware-xiaomi-lmi/`
  - `artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi/`
- Primary boot strategy: copydown boot image that presents an ABL-compatible
  outer image and passes a runtime mainline DTB.
- Persistent test gate: recovery fastbootd with `is-userspace=yes`, exact
  artifact hashes, and separate approvals for each write.

## Distinctive Features

- Intended long-term path for mainline SM8250 hardware support.
- Uses Linux 6.19 based artifacts in the imported overlay work.
- Separates host-side candidate generation from hardware writes.
- Uses guarded scripts for preflight, stage execution, rollback, and monitoring.
- Treats failed USB/SSH after boot as an early kernel/initramfs visibility
  problem, not as a rootfs or firewall problem.

## Progress

| Version | Feature / change | Evidence | Status |
| --- | --- | --- | --- |
| `M-r5` | No-EFI-stub 48-bit mainline build plus copydown boot image. | `docs/lmi-mainline-overlay-build-20260623.md` | Built and machine-verified; not hardware-verified. |
| `M-r6` | Boot-critical DTS memory/reserved-region experiment and release bundle. | `docs/release/lmi-r6-bootmem-release-manifest-20260624.md`; `docs/release/lmi-r6-rootfs-write-result-20260624.md`; `docs/release/lmi-r6-boot-write-result-20260624.md`; `docs/release/lmi-r6-post-reboot-result-20260624.md` | Rootfs and boot writes succeeded; reboot stuck at Redmi logo with no observable USB/ADB/telnet/SSH. |
| `M-r7` | Early-debug boot-only image with stronger printk/ramoops/debug settings. | `docs/release/lmi-r7-earlydebug-build-result-20260624.md` | Boot-only write succeeded; reboot again stuck at Redmi logo with no observable interface; rollback restored recovery path. |

## Current Mainline State

The mainline/copydown track is not the current working hardware path. It has
good host-side generation, verification, and rollback discipline, but no
evidence yet that the `M-r6` or `M-r7` kernel reaches an observable initramfs.

## Open Work

- Recover or collect earlier boot evidence before another mainline write.
- Use read-only fastbootd/preflight checks before any future write.
- Avoid rewriting rootfs unless new evidence proves the existing rootfs image is
  wrong.
- Keep `super`, `dtbo`, `vbmeta`, `persist`, modem/EFS, calibration,
  `vendor_boot`, `init_boot`, and bootloader lock state out of this route.

## Safety Boundary

Every hardware-state change in this track requires fresh exact approval:
entering fastbootd, writing rootfs, writing boot, rebooting, or rollback. The
recorded `M-r7` rollback changed the visible device behavior from persistent
Redmi logo to recovery screen, so recovery appears available but must not be
treated as guaranteed.
