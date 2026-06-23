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
