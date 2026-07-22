---
name: pmos-port-unsupported-device
description: Assess, port, build, temporarily boot, debug, and install postmarketOS on phones or tablets that do not have a supported device package. Use when an agent must investigate an unsupported postmarketOS device, create or audit pmaports device and kernel packages, determine deviceinfo values, build images with pmbootstrap, diagnose initramfs/rootfs/SSH failures, or plan a reversible installation without risking Android partitions.
---

# Port an Unsupported Device to postmarketOS

Treat an unsupported device as a porting project, not as a normal installation. Build an evidence-backed device package before proposing any flash operation.

## Required references

- Read [references/official-sources.md](references/official-sources.md) before researching or claiming current postmarketOS behavior.
- Read [references/porting-workflow.md](references/porting-workflow.md) when assessing hardware, creating packages, selecting a kernel, or building images.
- Read [references/install-debug-recovery.md](references/install-debug-recovery.md) before booting hardware, debugging initramfs, writing a partition, or planning rollback.

## Workflow

1. **Confirm support status.** Search the current official pmaports tree by exact codename and aliases. If there is no matching device package, state that installation requires a port.
2. **Establish identity.** Collect model, codename, SoC, storage type, bootloader state, slot layout, partition names and sizes, stock kernel cmdline, boot image header, DTB/DTBO arrangement, panel identifier, and available recovery method. Separate observed facts from inference.
3. **Preserve recovery.** Require backups and a known-good stock ROM, boot image, or recovery path before any write. Never assume an unverified local image is restorable.
4. **Choose the kernel path.** Prefer an existing generic/mainline SoC path when it supports the hardware. Use a downstream Android kernel only when necessary and record its exact source and commit.
5. **Create or audit packages.** Use `pmbootstrap init`, then inspect the generated device and kernel packages. Determine every `deviceinfo` value independently; do not infer rootfs sector size from boot-image page size.
6. **Build without touching hardware.** Run checksum, package build, install/image generation, export, and artifact inspection. Verify the produced partition layout, boot image metadata, initramfs contents, DTB, modules, and firmware before connecting a phone.
7. **Test the smallest reversible step.** Prefer a supported RAM-only boot. Obtain explicit approval immediately before booting even when it does not write storage.
8. **Debug from evidence.** Capture `/pmOS_init.log`, `dmesg`, block devices, `blkid`, mounts, network state, and service state. Change one hypothesis at a time and rebuild.
9. **Install incrementally.** Obtain separate explicit approval immediately before each partition write. Start with the smallest required write and verify it before considering persistent kernel installation.
10. **Record results.** Save exact commands, hashes, package revisions, logs, observed behavior, and rollback status. Redact serials, unlock tokens, and other identifiers.

## Safety gates

- Never run `flash`, `erase`, `format`, repartition, sideload, or bootloader-lock commands without explicit user approval for that exact action.
- Never write `boot`, `vendor_boot`, `init_boot`, `dtbo`, `vbmeta`, `super`, `persist`, modem/EFS, or userdata based only on a guessed layout.
- Never relock a bootloader while non-stock images or partitions are present.
- Treat `pmbootstrap flasher boot` as temporary but still hardware-affecting; confirm device support and obtain approval.
- Treat `pmbootstrap flasher flash_rootfs` as destructive to the selected partition even though official help says it does not change the partition table.
- Stop when device identity, partition target, image provenance, battery state, or rollback path is uncertain.

## Completion criteria

Do not call a port installed or supported merely because the kernel starts. Report milestones separately:

- image builds reproducibly;
- bootloader accepts the image;
- initramfs starts;
- rootfs is found and mounted;
- `switch_root` completes;
- a stable shell is reachable;
- storage, display, input, USB, networking, audio, modem, suspend, charging, and sensors are tested individually;
- rollback is tested or demonstrably available.

