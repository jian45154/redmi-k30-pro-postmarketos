# Porting and build workflow

## 1. Identify the target

Collect read-only evidence from the running stock OS, recovery, and bootloader where available:

```sh
adb shell getprop
adb shell cat /proc/cmdline
adb shell ls -l /dev/block/by-name
adb shell cat /proc/partitions
fastboot getvar product
fastboot getvar unlocked
fastboot getvar current-slot
fastboot getvar all
```

Redact serials, tokens, IMEI, MAC addresses, and device IDs. Do not assume `fastboot getvar all` is harmless on every broken bootloader; use known-good platform tools and stop if the transport hangs.

Record:

- exact codename and variants;
- SoC and architecture;
- eMMC/UFS/NVMe storage and logical sector size;
- A/B slots and dynamic partitions;
- kernel source, version, config, compiler, and commit;
- boot image header version, page size, offsets, cmdline, DTB and DTBO;
- USB controller, panel string, firmware paths, and recovery route.

## 2. Select a kernel strategy

Check current pmaports for:

- a supported target device;
- a generic package for the same SoC or architecture;
- a mainline kernel with adequate hardware support;
- a maintained downstream kernel package for a close device.

Do not combine DTBs, configs, or firmware from a similar device without checking compatible strings, hardware revisions, and partition layout.

## 3. Initialize the port

Use the installed CLI help as the source of truth:

```sh
pmbootstrap --version
pmbootstrap init --help
pmbootstrap init
```

When prompted, create a new device port. Audit the generated device package, kernel dependency, `APKBUILD`, `deviceinfo`, `modules-initfs`, firmware packaging, and checksums.

## 4. Determine device metadata independently

Read the current `pmaports/deviceinfo_schema.toml`. Verify at least:

- `deviceinfo_arch`, codename, manufacturer, and chassis;
- flash method and exact kernel/rootfs partition targets;
- `deviceinfo_generate_bootimg` and header version;
- boot-image page size and offsets;
- DTB filename, append/copy behavior, and DTBO requirements;
- rootfs image sector size;
- kernel cmdline and append-only customizations;
- initramfs modules required for storage, USB networking, input, display, or FDE.

Keep these concepts separate:

- boot-image page size controls Android boot image layout;
- rootfs image sector size controls the partition table inside generated images and loop-device parsing;
- physical storage logical block size is evidence for the latter, not an automatic substitute;
- DTB selection and DTBO application depend on boot-image format and bootloader behavior.

## 5. Build and inspect

Check the exact installed command options, then use the standard sequence:

```sh
pmbootstrap checksum <kernel-package>
pmbootstrap checksum <device-package>
pmbootstrap build <kernel-package>
pmbootstrap build <device-package>
pmbootstrap install
pmbootstrap export
```

Use `pmbootstrap install --help` before choosing split images, a single partition, encryption, filesystem, sparse output, or sector size. Do not copy flags from an old guide blindly.

Before hardware testing, verify:

- package checksums and revisions;
- kernel architecture and version;
- boot image header, offsets, cmdline, and size limits;
- initramfs contains required storage and USB support;
- required DTB is present and matches the configured name;
- rootfs partition table uses the intended sector size;
- firmware and userspace daemons required by remote processors are packaged;
- exported artifact hashes are recorded.

## 6. Validate incrementally

Use separate milestones for compile, image generation, bootloader acceptance, kernel boot, initramfs, rootfs mount, shell, and each hardware subsystem. A working USB gadget proves neither rootfs mount nor full userland startup.

