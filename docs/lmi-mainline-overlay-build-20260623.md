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
- bumps `linux-postmarketos-qcom-sm8250-lmi` to `pkgrel=2`;
- builds `make Image` and installs `arch/arm64/boot/Image` as `/boot/vmlinuz`;
- updates the temporary `deviceinfo` checksum after cmdline edits.

Verified regenerated artifacts:

```text
1a6be1dd99861a00552fe9dc066d0685e926462a9d5418a61606a669b9a73793  boot.img
9207f50ae28739407c832a79018d22ada26df9c8e3e85c9259910a46fceddc30  vmlinuz
56bd133dca8689d3a1694f91c1c89215a4c0f5306d738f35d949c045c9c8532e  xiaomi-lmi.img
```

Static boot image inspection:

- Android boot image header v2, page size 4096.
- kernel size: 31598762 bytes.
- ramdisk size: 9565839 bytes.
- ARM64 Image magic `ARMd` is present at kernel offset 56.
- lmi DTB is still appended at kernel offset 31463936 with a 134826-byte tail.

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
- This would overwrite Android userdata and is destructive to user data.
- It would not make the kernel persistent; kernel boot remains a separate
  RAM-only `fastboot boot /tmp/postmarketOS-export/boot.img` step unless a
  separately approved `flash_kernel` writes the boot partition.
- Do not run `flash_rootfs` until the exact command and target partition are
  approved immediately before execution.
