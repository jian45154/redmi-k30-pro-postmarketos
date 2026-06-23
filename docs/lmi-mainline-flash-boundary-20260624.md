# LMI mainline flash boundary - 2026-06-24

## Decision update

RAM-only `fastboot boot` is useful as a reversible diagnostic, but it is not
proven to be part of the external lmi mainline validation path. The external
mainline package set documents persistent flashing:

```sh
fastboot flash boot boot.img
fastboot flash system xiaomi-lmi.img
fastboot reboot
```

It does not document a successful `fastboot boot boot.img` test. Therefore a
RAM-only failure is not, by itself, proof that a persistent boot partition image
would fail in the same way.

Local historical lmi boot packaging records now provide a stronger path than a
plain pmbootstrap `boot.img`: a copydown bootshim image intended for recovery
fastbootd flashing. This means RAM boot should be treated as optional evidence,
not as a mandatory gate before all persistent experiments.

## Current evidence

- External package source: `macosmojave2-alt/postmarket-xiaomi-lmi`, commit
  `ef326f182d43eebe432f2adb8de6b3be9780309f`.
- External kernel source: `yuweiyuan8/linux` branch `v6.19`, commit
  `999ef8bfd90ca4c214f18ac5d0138bf380386c38`.
- External device package uses:
  - `deviceinfo_dtb="qcom/sm8250-xiaomi-lmi"`;
  - `deviceinfo_append_dtb="true"`;
  - Android boot image header v2;
  - page size 4096;
  - kernel offset `0x00008000`;
  - ramdisk offset `0x01000000`;
  - DTB offset `0x01f00000`;
  - rootfs image sector size 4096.
- External README says initramfs USB networking should expose telnet at
  `172.16.42.1`, but only after the documented flash path.
- Local mainline RAM-only attempts were accepted by fastboot, then the device
  remained in or returned to fastboot, with no USB networking.
- Local historical boot packaging source:
  `/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/sm8250-xiaomi-lmi-boot`.
  Its README says the release boot image is flashed from recovery fastbootd:

```sh
fastboot getvar is-userspace
fastboot flash boot builds/lmi-release/boot-linux-copydown-lmi.img
fastboot reboot
```

  `is-userspace` should return `yes`. The same README says bootloader fastboot
  is not the primary flashing path for the current lmi partition state.
- The historical `device-baseline.lock` records:
  - boot partition size: `134217728`;
  - Android boot header version: `2`;
  - boot page size: `4096`;
  - kernel offset: `0x00008000`;
  - ramdisk offset: `0x01000000`;
  - tags offset: `0x00000100`;
  - boot DTB offset: `0x01f00000`;
  - DTB delivery: `boot-image-dtb-field`.
- The historical release manifest records a copydown bootshim:
  - `stage=M2j`;
  - `payload=linux-copydown-shim-embedded-runtime-dtb`;
  - `outer_text_offset=0x80000`;
  - `linux_text_offset=0x0`;
  - `x0=embedded_runtime_dtb`;
  - `linux_source_alignment_ok=True`;
  - `copy_entry_outside_destination=True`;
  - `copy_overlap_safe=True`;
  - `boot_size_ok=True`.

Assessment: the historical path deliberately presents ABL with an outer ARM64
image header that has `text_offset=0x80000`, then copies and branches into the
embedded mainline Linux image with an embedded runtime DTB in `x0`. A plain
pmbootstrap boot image does not reproduce that handoff shape.

## Non-negotiable safety boundary

Do not run any of the following without exact immediate approval for the exact
command and target partition:

- `fastboot flash ...`
- `pmbootstrap flasher flash_rootfs`
- `pmbootstrap flasher flash_kernel`
- `fastboot erase ...`
- `fastboot format ...`
- `fastboot flash super ...`
- `fastboot flash vbmeta ...`
- `fastboot oem lock` or any bootloader relock operation

Do not flash `super`, `persist`, modem/EFS/calibration partitions, `vbmeta`,
`dtbo`, `vendor_boot`, or `init_boot` as part of this mainline experiment unless
a separate evidence-backed plan proves they are necessary.

## Candidate persistent path

If the user chooses to test persistent mainline boot, the least broad
pmbootstrap-only candidate is:

1. flash rootfs only to the explicit configured rootfs target, currently
   `userdata`;
2. flash kernel only to the boot partition;
3. reboot and collect initramfs/USB/dmesg evidence.

This would overwrite Android userdata and replace the current boot image. It is
not equivalent to RAM boot. It requires a rollback path before execution:

- known-good stock/Lineage boot image for the exact lmi build;
- known-good ROM or recovery procedure;
- ability to return to fastboot;
- acceptance that userdata contents will be destroyed if `userdata` is used.

However, given the historical bootshim evidence, the preferred kernel-side
candidate is now:

1. build the current postmarketOS rootfs image as before;
2. generate a copydown boot image from the current mainline kernel and lmi DTB,
   using the historical `sm8250-xiaomi-lmi-boot` script into a temporary output
   directory;
3. verify its manifest, hashes, boot header, boot partition size, and rollback
   image, including a successful `scripts/46_verify_lmi_copydown_boot.sh` run;
4. only then consider an explicitly approved recovery fastbootd
   `fastboot flash boot ...`.

This avoids treating pmbootstrap's direct kernel packaging as equivalent to the
historical lmi early-boot path.

## Open checks before any flash

- Verify current boot partition naming and slot behavior. `fastboot getvar
  current-slot` returned `FAILED (remote: 'GetVar Variable Not found')`, so do
  not assume a normal A/B slot layout.
- Re-check boot and userdata partition sizes immediately before flashing.
- Record SHA256 hashes of the exact `boot.img` and `xiaomi-lmi.img`.
- Prefer the latest host-side build variant whose boot image shape is closest
  to the known-working downstream image.
- Prefer a boot image whose outer handoff matches the historical copydown
  manifest before attempting persistent `boot` writes.
- Keep RAM-only boot optional, not mandatory.

## Current host-side gate

The r5 copydown candidate passes machine verification:

```text
copydown boot verification: OK
boot_img_sha256=8101b73283a9314a7554dacb3565822e7141396e8951a1cc67e331f2e99f8a4d
boot_img_size=15892480
boot_partition_size=134217728
outer_text_offset=0x80000
runtime_dtb_sha256=e5623c9c0e7704c48f7d1de3a09b423ffd2425648c5ebbb4c5c575e25863f6ea
```

The current strongest host-side candidate is r6:

```sh
scripts/40_prepare_mainline_lmi_overlay.sh --debug-shell-android-cmdline-no-efi-stub-48bit-bootmem
pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force
pmbootstrap build device-xiaomi-lmi --force
pmbootstrap install --password <temporary-test-password> --zap
pmbootstrap export
OUT_DIR=/tmp/lmi-copydown-r6-bootmem-20260624 scripts/45_build_lmi_copydown_boot.sh
OUT_DIR=/tmp/lmi-copydown-r6-bootmem-20260624 scripts/46_verify_lmi_copydown_boot.sh
```

r6 adds only boot-critical DTS memory metadata on top of r5. It has been built,
exported, packaged through copydown, and verified:

```text
copydown boot verification: OK
boot_img_sha256=cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570
boot_img_size=15892480
boot_partition_size=134217728
outer_text_offset=0x80000
runtime_dtb_sha256=b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32
```

Evaluate r6 as a copydown boot image, not as a plain pmbootstrap direct boot
image.
