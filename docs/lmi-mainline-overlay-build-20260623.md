# LMI mainline overlay build record - 2026-06-23

## Purpose

Validate the external lmi mainline pmaports overlay as a hardware enablement
baseline before doing any device boot test. This avoids continuing to patch the
downstream 4.19 port when the postmarketOS wiki and external pmaports work point
to a newer SM8250/mainline path.

## Imported reference overlay

Source snapshot:

- `artifacts/mainline-pmaports/device-xiaomi-lmi`
- `artifacts/mainline-pmaports/firmware-xiaomi-lmi`
- `artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi`

The committed reference overlay remains unchanged. `scripts/40_prepare_mainline_lmi_overlay.sh`
creates a temporary pmbootstrap cache copy and applies local-only build fixes:

- disables the missing proprietary `firmware-xiaomi-lmi-Tag.zip` source and
  extraction block for first RAM-only experiments;
- moves the existing downstream `device-xiaomi-lmi` cache package aside to avoid
  duplicate pmaports package names;
- removes stale local `device-xiaomi-lmi-*` and `linux-xiaomi-lmi-*` APKs so
  pmbootstrap cannot select old downstream `1-r18` packages over the imported
  mainline package;
- bumps the temporary `device-xiaomi-lmi` cache copy to `pkgrel=90`.

The downstream cache package can be restored with:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh --restore-downstream
```

## Verified build path

Commands run successfully:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh
pmbootstrap checksum device-xiaomi-lmi
pmbootstrap checksum firmware-xiaomi-lmi
pmbootstrap checksum linux-postmarketos-qcom-sm8250-lmi
pmbootstrap build device-xiaomi-lmi --force
pmbootstrap install --password <temporary-test-password> --zap
pmbootstrap export
```

Installed package evidence from the generated rootfs:

- `device-xiaomi-lmi 1-r90`
- `firmware-xiaomi-lmi 1-r0`
- `linux-postmarketos-qcom-sm8250-lmi 6.19.7-r1`
- no `linux-xiaomi-lmi` package in the regenerated rootfs

Boot artifacts:

- `/tmp/postmarketOS-export/boot.img`
- `/tmp/postmarketOS-export/xiaomi-lmi.img`
- `/tmp/postmarketOS-export/initramfs`
- `/tmp/postmarketOS-export/vmlinuz`
- `/tmp/postmarketOS-export/dtbs/sm8250-xiaomi-lmi.dtb`

Artifact hashes:

```text
adcc69c9fcff43550ce729622577e858cda2e0549217ed17477a1e3bf343d86b  boot.img
7d3b8edf80362b05ccd44ab090bdebc99c8ea873b4c10883b22faa077329f60b  xiaomi-lmi.img
b3a4d89b7d371773f91c23a83b6f4f13790cdeedc4e86841408637195281d028  vmlinuz
a231877633b2905cfa354b149053e62772b32d7915da627af0db844601b5d48c  initramfs
```

Static inspection:

- `boot.img` is an Android boot image with 4096 page size and header <= v2.
- kernel cmdline starts with `quiet loglevel=2`.
- rootfs image is an Android sparse image using 4096-byte output blocks.
- `sm8250-xiaomi-lmi.dtb` is present in the generated rootfs boot DTB tree.

## Next hardware step

The next reversible hardware test is RAM-only boot of the exported `boot.img`.
Do not run it without explicit approval immediately before the command.

## Debug boot image update

The first mainline RAM-only attempts were accepted by fastboot but returned to
fastboot, with no ADB and no postmarketOS USB network. Static comparison showed
the imported mainline kernel artifact was packaged as a compressed `zimg` style
image, while the known-working downstream debug image used the normal ARM64
Image format.

`scripts/40_prepare_mainline_lmi_overlay.sh --debug-shell-android-cmdline` now
applies these temporary cache-only changes:

- bumps `device-xiaomi-lmi` to `pkgrel=92`;
- uses the Android downstream USB/kernel cmdline plus `pmos.debug-shell`;
- adds `deviceinfo_flash_fastboot_partition_rootfs="userdata"` to make the
  rootfs flash target explicit in the temporary cache copy;
- bumps `linux-postmarketos-qcom-sm8250-lmi` to `pkgrel=2`;
- builds `make Image` and installs `arch/arm64/boot/Image` as `/boot/vmlinuz`;
- updates the temporary `deviceinfo` checksum after cmdline edits.

Verified regenerated artifacts:

```text
f4c8fc6cce9ffba36ee5f862c7f2e259d68339fbee0319624b358fe2e8167fb0  boot.img
9207f50ae28739407c832a79018d22ada26df9c8e3e85c9259910a46fceddc30  vmlinuz
ace8417d8b61c907c6b325fdc990e3c8e4db247fad4a714a82f15d785acc8b0f  xiaomi-lmi.img
```

Static boot image inspection:

- Android boot image header v2, page size 4096.
- kernel size: 31598762 bytes.
- ramdisk size: 9565839 bytes.
- ARM64 Image magic `ARMd` is present at kernel offset 56.
- lmi DTB is still appended at kernel offset 31463936 with a 134826-byte tail.

Installed rootfs `deviceinfo` verification:

```text
deviceinfo_flash_method="fastboot"
deviceinfo_flash_fastboot_partition_rootfs="userdata"
deviceinfo_kernel_cmdline="androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 androidboot.usbcontroller=a600000.dwc3 swiotlb=2048 loop.max_part=7 cgroup.memory=nokmem,nosocket reboot=panic_warm androidboot.fstab_suffix=qcom androidboot.init_fatal_reboot_target=recovery pmos.debug-shell"
deviceinfo_rootfs_image_sector_size="4096"
```

## Rootfs flash feasibility boundary

The generated `xiaomi-lmi.img` is an Android sparse image with a 4096-byte sector
GPT inside it. Parsed with 4096-byte sectors, it contains:

- partition 1, `primary`: 503316480 bytes, EFI system type;
- partition 2, `primary`: 1641021440 bytes, Linux root type.

Read-only fastboot metadata observed:

```text
is-userspace: no
partition-type:userdata: f2fs
partition-size:userdata: 0x1AC07FB000
partition-type:boot: raw
partition-size:boot: 0x8000000
partition-type:super: raw
partition-size:super: 0x220000000
partition-type:fastboot: not found
```

Assessment:

- Capacity-wise, the 2.01 GiB raw rootfs image fits in the approximately
  107.01 GiB `userdata` partition.
- `pmbootstrap flasher flash_rootfs --partition userdata` should only target
  `userdata`, not `boot`, `super`, or a `fastboot` partition.
- After the overlay script update, the temporary mainline `deviceinfo` also
  sets `deviceinfo_flash_fastboot_partition_rootfs="userdata"` so the default
  `flash_rootfs` target is explicit; still prefer passing `--partition userdata`
  at execution time to keep the command self-documenting.
- This would overwrite Android userdata and is destructive to user data.
- It would not make the kernel persistent; kernel boot remains a separate
  RAM-only `fastboot boot /tmp/postmarketOS-export/boot.img` step unless a
  separately approved `flash_kernel` writes the boot partition.
- Do not run `flash_rootfs` until the exact command and target partition are
  approved immediately before execution.

## RAM-only boot attempt

Command approved and run:

```sh
fastboot boot /tmp/postmarketOS-export/boot.img
```

Fastboot result:

```text
Sending 'boot.img' (40340 KB) OKAY
Booting OKAY
Finished. Total time: 4.031s
```

Observed result after boot:

- Device remained in or returned to fastboot.
- `fastboot devices` still showed the lmi bootloader.
- `adb devices` showed no device.
- WSL USB still showed `18d1:d00d` fastboot.
- No postmarketOS USB network interface appeared.

Read-only fastboot metadata after the attempt:

```text
product: lmi
unlocked: yes
```

Comparison against the known-working downstream v32 debug image:

- Header version, page size, load offsets, and Android boot image layout match
  the downstream images.
- Mainline boot image:
  - file size: 41308160 bytes;
  - kernel size: 31598762 bytes;
  - ramdisk size: 9565855 bytes;
  - appended DTB size: 134826 bytes.
- Downstream v32 debug image:
  - file size: 52924416 bytes;
  - kernel size: 43233304 bytes;
  - ramdisk size: 8802401 bytes;
  - appended DTB size: 874445 bytes.

Assessment:

- The bootloader accepts the image transport and handoff request.
- The device does not reach observable initramfs USB/debug-shell.
- The remaining failure is likely before initramfs: kernel early boot, DTB
  compatibility, or bootloader handoff expectations for this mainline kernel.
- Do not diagnose this as a rootfs, SSH, or firewall problem.

## No-zboot mainline build

Follow-up build on 2026-06-24:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh --debug-shell-android-cmdline-no-zboot
pmbootstrap checksum linux-postmarketos-qcom-sm8250-lmi
pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force
pmbootstrap build device-xiaomi-lmi --force
pmbootstrap install --password <temporary-test-password> --zap
pmbootstrap export
```

Temporary cache changes:

- `device-xiaomi-lmi 1-r92`;
- `linux-postmarketos-qcom-sm8250-lmi 6.19.7-r3`;
- `CONFIG_EFI_ZBOOT=y` changed to
  `# CONFIG_EFI_ZBOOT is not set` in the temporary kernel config;
- Android downstream USB cmdline plus `pmos.debug-shell` preserved;
- `deviceinfo_flash_fastboot_partition_rootfs="userdata"` preserved.

Verified regenerated artifacts:

```text
25d1d5496f6f36d62842a75227a1794eb2ac0a5488f0e1c66674ee7ca9fdf532  boot.img
bda4d054bcd1f4a6c8173c8c591943b15e01e05525fc7903e76b98ed06812995  vmlinuz
697c3de7a9b55e1b413b906856326f5ba32d75e49da7ae174ba9383bf43c1436  xiaomi-lmi.img
```

Static inspection:

- `boot.img` is an Android boot image with page size 4096.
- `vmlinuz` is an ARM64 boot executable Image.
- Kernel size remains 31598762 bytes.
- Ramdisk size remains 9565855 bytes.
- Kernel first bytes still start with `4d5a` (`MZ`), with:
  - `text_offset=0x0`;
  - `image_size=0x1e80000`;
  - `flags=0xa`;
  - ARM64 Image magic `ARMd` at offset 56;
  - PE header offset `0x40`.
- The known-working downstream debug image starts with a branch instruction,
  uses `text_offset=0x80000`, and has PE header offset `0x0`.

Rootfs sparse image validation:

- The exported rootfs remains an Android sparse image.
- Parsed as a 4096-byte-sector GPT, it contains:
  - partition 1, `primary`: 503316480 bytes, EFI system type;
  - partition 2, `primary`: 1642070016 bytes, Linux root type.

Device state check after this build was read-only only:

```text
fastboot devices: 8336ded7 fastboot
lsusb: 18d1:d00d Google Inc. Xiaomi Mi/Redmi 2 (fastboot)
```

Assessment:

- The no-zboot variant builds cleanly and produces a valid export.
- Disabling `CONFIG_EFI_ZBOOT` does not change the kernel entry/header shape
  that differs from the known-working downstream image.
- This result does not justify rootfs or SSH debugging; the failure boundary is
  still before initramfs.
- Next mainline variable to test is disabling EFI stub/EFI boot wrapping in the
  temporary kernel config, or otherwise producing an ARM64 Image with
  `text_offset=0x80000` and no PE-stub entry.
- This no-zboot image has not been RAM-booted. Do not run `fastboot boot`
  without fresh exact approval for the newly exported image.

## No-EFI-stub mainline build

Follow-up build on 2026-06-24:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh --debug-shell-android-cmdline-no-efi-stub
pmbootstrap checksum linux-postmarketos-qcom-sm8250-lmi
pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force
pmbootstrap build device-xiaomi-lmi --force
pmbootstrap install --password <temporary-test-password> --zap
pmbootstrap export
```

Temporary cache changes:

- `device-xiaomi-lmi 1-r92`;
- `linux-postmarketos-qcom-sm8250-lmi 6.19.7-r4`;
- `CONFIG_EFI_STUB`, `CONFIG_EFI`, `CONFIG_EFI_GENERIC_STUB`,
  `CONFIG_EFI_ZBOOT`, and related EFI wrapper options disabled in the
  temporary kernel config;
- Android downstream USB cmdline plus `pmos.debug-shell` preserved;
- `deviceinfo_flash_fastboot_partition_rootfs="userdata"` preserved.

Verified regenerated artifacts:

```text
fb77960db67b099db9cddc10e23d6a4f25093b6025b58b027448377c20db8a09  boot.img
647523e5cf460beffd351df224b05ac9292a569ba41bd5b2b5a8517277045c1c  vmlinuz
866778fda8b3486b05b0ee08836cb3cf7f0a9a19975ea8bff512a133f6e203df  xiaomi-lmi.img
```

Static boot image inspection:

- `boot.img` is an Android boot image with page size 4096.
- `vmlinuz` is an ARM64 boot executable Image.
- Kernel size: 30496434 bytes.
- Ramdisk size: 9551145 bytes.
- Kernel first bytes are no longer `4d5a` (`MZ`):
  - `code0_le=0xd503201f`;
  - `text_offset=0x0`;
  - `image_size=0x1d70000`;
  - `flags=0xa`;
  - ARM64 Image magic `ARMd` at offset 56;
  - PE header offset `0x0`.
- The known-working downstream debug image still differs:
  - `code0_le=0x148e0000`;
  - `text_offset=0x80000`;
  - `image_size=0x33fa000`;
  - PE header offset `0x0`.

Rootfs sparse image validation:

- The exported rootfs remains an Android sparse image.
- Parsed as a 4096-byte-sector GPT, it contains:
  - partition 1, `primary`: 503316480 bytes, EFI system type;
  - partition 2, `primary`: 1637875712 bytes, Linux root type.

Read-only device state check after this build:

```text
fastboot devices: 8336ded7 fastboot
lsusb: 18d1:d00d Google Inc. Xiaomi Mi/Redmi 2 (fastboot)
```

Assessment:

- Disabling EFI stub is a meaningful forward step: it removes the PE-stub
  `MZ` entry that differed from the downstream known-working image.
- The remaining static mismatch is ARM64 Image placement metadata:
  the mainline image still reports `text_offset=0x0`, while the downstream
  known-working image reports `text_offset=0x80000`.
- The temporary r4 kernel config still uses 52-bit VA/PA and LPA2:
  `CONFIG_ARM64_VA_BITS_52=y`, `CONFIG_ARM64_PA_BITS_52=y`,
  `CONFIG_ARM64_LPA2=y`.
- This result still does not justify rootfs, SSH, or firewall debugging; the
  failure boundary remains before observable initramfs.
- Next host-side variable to test is a mainline build with downstream-like
  ARM64 address sizing, such as 48-bit VA/PA and no LPA2, while keeping
  EFI stub disabled.
- This no-EFI-stub image has not been RAM-booted. Do not run `fastboot boot`
  without fresh exact approval for the newly exported image.

## No-EFI-stub 48-bit mainline build

Follow-up build on 2026-06-24:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh --debug-shell-android-cmdline-no-efi-stub-48bit
pmbootstrap checksum linux-postmarketos-qcom-sm8250-lmi
pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force
pmbootstrap build device-xiaomi-lmi --force
pmbootstrap install --password <temporary-test-password> --zap
pmbootstrap export
```

Temporary cache changes:

- `device-xiaomi-lmi 1-r92`;
- `linux-postmarketos-qcom-sm8250-lmi 6.19.7-r5`;
- EFI stub and EFI wrapper options remain disabled;
- `CONFIG_ARM64_VA_BITS=48`;
- `CONFIG_ARM64_PA_BITS=48`;
- `CONFIG_ARM64_LPA2` disabled;
- Android downstream USB cmdline plus `pmos.debug-shell` preserved;
- `deviceinfo_flash_fastboot_partition_rootfs="userdata"` preserved.

Verified regenerated artifacts:

```text
0ab3d383c3bbf7138b95d717d1d7ab80c91f8500a2023fab087092746b0113ae  boot.img
2951f51817fba40ab6d21291b4840d5dd7c4dfd77d3b96318e4e480818970710  vmlinuz
69092dde63a088b3988c6e02f6513f4c86401b361d0d67c5ea416bf338036173  xiaomi-lmi.img
e5623c9c0e7704c48f7d1de3a09b423ffd2425648c5ebbb4c5c575e25863f6ea  sm8250-xiaomi-lmi.dtb
c3f6fe0b58c6ad1a8329deff8ac35305dd5868bac71ddeca55708ad259fd4a85  initramfs
```

Static boot image inspection:

- `boot.img` is an Android boot image with page size 4096.
- `vmlinuz` is an ARM64 boot executable Image.
- Kernel size: 30430898 bytes.
- Ramdisk size: 9551148 bytes.
- Kernel first bytes remain non-PE/non-MZ:
  - `code0_le=0xd503201f`;
  - `text_offset=0x0`;
  - `image_size=0x1d60000`;
  - `flags=0xa`;
  - ARM64 Image magic `ARMd` at offset 56;
  - PE header offset `0x0`.
- The known-working downstream debug image still differs:
  - `code0_le=0x148e0000`;
  - `text_offset=0x80000`;
  - `image_size=0x33fa000`;
  - PE header offset `0x0`.

Rootfs sparse image validation:

- The exported rootfs remains an Android sparse image with 525056
  4096-byte output blocks.
- Parsed as a 4096-byte-sector GPT, it contains:
  - partition 1, `primary`: 503316480 bytes, EFI system type;
  - partition 2, `primary`: 1637875712 bytes, Linux root type.

Assessment:

- The 48-bit VA/PA and no-LPA2 change builds cleanly.
- It does not change the remaining static bootloader handoff mismatch:
  the direct mainline kernel still reports `text_offset=0x0`.
- r5 is useful as a config exclusion experiment, but it is not the closest
  match to the historical lmi early-boot path.
- RAM-only boot remains optional evidence, not a mandatory gate.
- The next host-side step should be generating a copydown boot image from the
  current no-EFI mainline kernel and `sm8250-xiaomi-lmi.dtb`, following the
  historical `sm8250-xiaomi-lmi-boot` flow:
  - outer shim presented to ABL with `outer_text_offset=0x80000`;
  - embedded runtime mainline DTB passed in `x0`;
  - stock DTB kept in the Android boot image `--dtb` field;
  - manifest checks for source alignment, copy overlap, hashes, and
    `boot_size_ok=True`.

## r5 copydown boot image

Host-side candidate generated on 2026-06-24:

```sh
scripts/45_build_lmi_copydown_boot.sh
scripts/46_verify_lmi_copydown_boot.sh
```

This script normalizes the CRLF historical scripts/lock files into the
temporary output directory, then calls the historical
`sm8250-xiaomi-lmi-boot/scripts/mkboot-linux-copydown-lmi.sh` without modifying
the Windows-side source tree.

Generated files:

- `/tmp/lmi-copydown-r5-20260624/boot-linux-copydown-lmi.img`
- `/tmp/lmi-copydown-r5-20260624/boot-linux-copydown-lmi.manifest`

Hashes:

```text
8101b73283a9314a7554dacb3565822e7141396e8951a1cc67e331f2e99f8a4d  boot-linux-copydown-lmi.img
85ec30c88d47b450746dd915ff0467995ed07b373fcc52927cc4759cfa9a0d1c  boot-linux-copydown-lmi.manifest
2951f51817fba40ab6d21291b4840d5dd7c4dfd77d3b96318e4e480818970710  embedded Linux Image
```

Manifest summary:

```text
stage=M2j
payload=linux-copydown-shim-embedded-runtime-dtb
x0=embedded_runtime_dtb
outer_text_offset=0x80000
outer_magic=b'ARMd'
outer_pe_offset_res5=0x0
linux_source_offset=0x200000
linux_source_alignment_ok=True
copy_entry_outside_destination=True
copy_overlap_safe=True
linux_text_offset=0x0
linux_magic=b'ARMd'
linux_pe_offset_res5=0x0
boot_img_size=15892480
boot_img_sha256=8101b73283a9314a7554dacb3565822e7141396e8951a1cc67e331f2e99f8a4d
runtime_dtb_sha256=e5623c9c0e7704c48f7d1de3a09b423ffd2425648c5ebbb4c5c575e25863f6ea
stock_header_dtb_sha256=dc0dabd0671edb7a5e5b5db494f2471e1ba547255323c9afd9f3599ebe9ba5fd
boot_partition_size=134217728
boot_size_ok=True
```

Assessment:

- This is the closest host-side artifact so far to the historical lmi
  early-boot model.
- It should not be treated as a normal pmbootstrap direct `boot.img`.
- It has not been RAM-booted or flashed.
- Any persistent test requires fresh exact approval and should use recovery
  fastbootd with `fastboot getvar is-userspace` returning `yes`.

Machine verification added on 2026-06-24:

```text
copydown boot verification: OK
boot_img=/tmp/lmi-copydown-r5-20260624/boot-linux-copydown-lmi.img
boot_img_sha256=8101b73283a9314a7554dacb3565822e7141396e8951a1cc67e331f2e99f8a4d
boot_img_size=15892480
boot_partition_size=134217728
outer_text_offset=0x80000
runtime_dtb_sha256=e5623c9c0e7704c48f7d1de3a09b423ffd2425648c5ebbb4c5c575e25863f6ea
```

`scripts/46_verify_lmi_copydown_boot.sh` checks the copydown manifest, boot
image hash, boot image size, Android boot magic, page size, gzip copydown
payload, outer `text_offset=0x80000`, embedded runtime DTB mode, and copy
overlap safety fields.

## r6 boot-critical DTS experiment

Prepared and built on 2026-06-24:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh --debug-shell-android-cmdline-no-efi-stub-48bit-bootmem
pmbootstrap checksum linux-postmarketos-qcom-sm8250-lmi
pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force
pmbootstrap build device-xiaomi-lmi --force
pmbootstrap install --password <temporary-test-password> --zap
pmbootstrap export
OUT_DIR=/tmp/lmi-copydown-r6-bootmem-20260624 scripts/45_build_lmi_copydown_boot.sh
OUT_DIR=/tmp/lmi-copydown-r6-bootmem-20260624 scripts/46_verify_lmi_copydown_boot.sh
```

Temporary cache changes on top of r5:

- `linux-postmarketos-qcom-sm8250-lmi 6.19.7-r6`;
- adds cache-only patch
  `0002-sm8250-xiaomi-lmi-boot-critical-memory.patch`;
- keeps EFI stub disabled;
- keeps 48-bit VA/PA and no LPA2;
- preserves Android downstream USB cmdline plus `pmos.debug-shell`.

The patch aligns the v6.19 lmi DTS with local boot-baseline evidence:

- simple-framebuffer stride changed from `<(1080 * 4)>` to `<4352>`;
- explicit `memory@80000000` DRAM ranges added:
  - `0x80000000` size `0x3bb00000`;
  - `0xc0000000` size `0xc0000000`;
  - `0x1_80000000` size `0x1_00000000`;
- reserved-memory additions:
  - `reserved_xbl_uefi_log` at `0x80880000`;
  - `cont_splash_memory` at `0x9c000000`;
  - `dfps_data_memory` at `0x9e300000`;
  - `ramoops` at `0xb0000000`;
  - `disp_rdump_memory` at `0xb0400000`.

Verification completed:

- patch dry-run against `/tmp/yuweiyuan8-linux-v6.19` succeeded;
- temporary APKBUILD source includes the new patch;
- temporary APKBUILD sha512 entry uses the source filename, not a host path;
- `pmbootstrap checksum linux-postmarketos-qcom-sm8250-lmi` succeeded.
- `pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force` succeeded.
- `pmbootstrap build device-xiaomi-lmi --force` succeeded.
- `pmbootstrap install --password <temporary-test-password> --zap` succeeded.
- `pmbootstrap export` succeeded.

Verified regenerated artifacts:

```text
bdccac69e54cab35044f24d3ce4914e2fced548879af47ae1d88038024d9cf5e  boot.img
91e17b132e95c48a86e3fe910075344162fd8e5082ba0f36e9441cb0675bc49c  vmlinuz
24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7  xiaomi-lmi.img
b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32  sm8250-xiaomi-lmi.dtb
c3f6fe0b58c6ad1a8329deff8ac35305dd5868bac71ddeca55708ad259fd4a85  initramfs
```

Static boot image inspection:

- direct pmbootstrap `boot.img` remains an Android boot image with page size
  4096;
- kernel size: 30431633 bytes;
- ramdisk size: 9551148 bytes;
- direct kernel remains non-PE/non-MZ:
  - `code0_le=0xd503201f`;
  - `text_offset=0x0`;
  - `image_size=0x1d60000`;
  - `flags=0xa`;
  - ARM64 Image magic `ARMd` at offset 56;
  - PE header offset `0x0`.
- The exported DTB contains the boot-critical markers:
  - `memory@80000000`;
  - `cont_splash_region`;
  - `ramoops`;
  - `disp_rdump_region`.

Rootfs sparse image validation:

- The exported rootfs remains an Android sparse image.
- Parsed as a 4096-byte-sector GPT, it contains:
  - partition 1, `primary`: 503316480 bytes, EFI system type;
  - partition 2, `primary`: 1637875712 bytes, Linux root type.

r6 copydown candidate:

```text
/tmp/lmi-copydown-r6-bootmem-20260624/boot-linux-copydown-lmi.img
/tmp/lmi-copydown-r6-bootmem-20260624/boot-linux-copydown-lmi.manifest
```

Machine verification:

```text
copydown boot verification: OK
boot_img_sha256=cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570
boot_img_size=15892480
boot_partition_size=134217728
outer_text_offset=0x80000
runtime_dtb_sha256=b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32
embedded_linux_image_sha256=91e17b132e95c48a86e3fe910075344162fd8e5082ba0f36e9441cb0675bc49c
linux_text_offset=0x0
boot_size_ok=True
```

Copydown hashes:

```text
cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570  boot-linux-copydown-lmi.img
facabcaac7745be9e5bf1c94338ffd974d6ca6fa8982513edac69b721af0cf0b  boot-linux-copydown-lmi.manifest
```

Assessment:

- r6 is now the strongest host-side candidate after the r5 copydown image.
- It targets the two DTS risks identified by read-only research: explicit
  memory layout and reserved splash/ramoops/display memory.
- It is packaged through copydown and passes the verifier.
- It has not been RAM-booted or flashed. Any hardware action still requires
  fresh exact approval and recovery/rollback preflight.

## Subagent research summary

Three read-only subagents reviewed the early-boot evidence on 2026-06-24.

- Bootshim/copydown review: the historical release image is not equivalent to a
  plain pmbootstrap `boot.img`. It deliberately separates the outer image seen
  by ABL from the inner mainline Linux image.
- DTS review: the highest-priority DTS risks are DTB delivery, explicit memory
  layout, and reserved framebuffer/splash/ramoops carveouts. USB differences
  can affect debug visibility but are less likely than handoff or memory
  metadata to explain no initramfs signs.
- Flash-boundary review: RAM boot is not required as a hard gate, but any
  persistent test must use recovery fastbootd, manifest/hash checks, partition
  size checks, and rollback preparation. Do not touch `super`, `dtbo`,
  `vbmeta`, `persist`, modem/EFS/calibration partitions, `vendor_boot`,
  `init_boot`, or bootloader relock paths.
