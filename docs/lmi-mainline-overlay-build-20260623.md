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
