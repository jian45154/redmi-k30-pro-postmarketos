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

## Release bundle and preflight

Host-side release bundle generated on 2026-06-24:

```sh
scripts/47_make_lmi_release_bundle.sh
```

Bundle path:

```text
/tmp/lmi-release-r6-bootmem-20260624
```

Bundle contents:

```text
boot-linux-copydown-lmi-r6-bootmem.img          15892480 bytes
boot-linux-copydown-lmi-r6-bootmem.manifest        2613 bytes
xiaomi-lmi-r6-bootmem.img                    1256602620 bytes
pmbootstrap-direct-boot-r6-bootmem.img         40128512 bytes
vmlinuz-r6-bootmem                             30296072 bytes
sm8250-xiaomi-lmi-r6-bootmem.dtb                 135561 bytes
initramfs-r6-bootmem                            9551148 bytes
SHA256SUMS
README.txt
```

Bundle hashes:

```text
cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570  boot-linux-copydown-lmi-r6-bootmem.img
facabcaac7745be9e5bf1c94338ffd974d6ca6fa8982513edac69b721af0cf0b  boot-linux-copydown-lmi-r6-bootmem.manifest
24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7  xiaomi-lmi-r6-bootmem.img
bdccac69e54cab35044f24d3ce4914e2fced548879af47ae1d88038024d9cf5e  pmbootstrap-direct-boot-r6-bootmem.img
91e17b132e95c48a86e3fe910075344162fd8e5082ba0f36e9441cb0675bc49c  vmlinuz-r6-bootmem
b9e390e417fe89a1e60549286ab7f1df2ec77eab2a56a6fc0d6d6a7456733b32  sm8250-xiaomi-lmi-r6-bootmem.dtb
c3f6fe0b58c6ad1a8329deff8ac35305dd5868bac71ddeca55708ad259fd4a85  initramfs-r6-bootmem
```

Read-only preflight command:

```sh
LMI_COPYDOWN_BOOT_IMG=/tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.img \
LMI_COPYDOWN_MANIFEST=/tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.manifest \
LMI_ROOTFS_IMG=/tmp/lmi-release-r6-bootmem-20260624/xiaomi-lmi-r6-bootmem.img \
scripts/48_preflight_lmi_fastbootd.sh
```

Current read-only preflight result:

```text
copydown boot verification: OK
product=lmi
unlocked=yes
is-userspace=no
partition-type:boot=raw
partition-size:boot=0x8000000
partition-type:userdata=f2fs
partition-size:userdata=0x1AC07FB000
boot_img_sha256=cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570
boot_img_size=15892480
rootfs_img_sha256=24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7
rootfs_img_size=1256602620
rootfs_expanded_size=2150629376
preflight: FAIL
is-userspace must be yes for recovery fastbootd, got no
```

Assessment:

- The r6 boot image and rootfs pass local verification and capacity checks.
- The device is currently in bootloader fastboot, not recovery fastbootd.
- Do not flash while `is-userspace=no`.

## Fastbootd wait gate

Because the persistent route does not require a successful RAM-only boot, the
next operational gate is entering recovery fastbootd and re-running read-only
checks there. The helper below only polls `fastboot devices` and
`fastboot getvar is-userspace`; it does not reboot, boot, flash, erase, format,
or write any partition:

```sh
LMI_FASTBOOTD_WAIT_TIMEOUT=120 scripts/52_wait_lmi_fastbootd.sh
```

If `is-userspace` becomes `yes`, the helper automatically runs:

```sh
LMI_COPYDOWN_BOOT_IMG=/tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.img \
LMI_COPYDOWN_MANIFEST=/tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.manifest \
LMI_ROOTFS_IMG=/tmp/lmi-release-r6-bootmem-20260624/xiaomi-lmi-r6-bootmem.img \
scripts/48_preflight_lmi_fastbootd.sh
```

The report is written to:

```text
/tmp/lmi-release-r6-bootmem-20260624/FASTBOOTD_WAIT_RESULT.txt
```

Short validation run:

```sh
LMI_FASTBOOTD_WAIT_TIMEOUT=5 LMI_FASTBOOTD_WAIT_INTERVAL=1 scripts/52_wait_lmi_fastbootd.sh
```

Result:

```text
product=lmi
unlocked=yes
is-userspace=no
fastbootd wait: FAIL
Timed out before is-userspace became yes.
No reboot, boot, flash, erase, format, or partition write was executed.
```

Entering recovery fastbootd may be done manually or with a separately approved
hardware state-changing command such as `fastboot reboot fastboot`. That command
has not been executed by the wait/preflight helpers and still requires fresh
exact approval before use.

Guarded dry-run for the next hardware-state command:

```sh
scripts/60_stage_lmi_enter_fastbootd.sh --dry-run
```

Execute mode still requires fresh exact approval and:

```sh
LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute
```

## Guarded staged write helper

The persistent route is split into two independently approved stages. The helper
below defaults to dry-run and never writes more than one partition per
invocation:

```sh
scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --dry-run
scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --dry-run
```

Execute mode is refused unless all of these are true:

- the user has just approved the exact selected stage and command;
- the environment contains the exact `LMI_FLASH_CONFIRM=...` token printed by
  the dry-run;
- read-only fastbootd preflight passes with `product=lmi`, `unlocked=yes`, and
  `is-userspace=yes`;
- for the rootfs stage, `/tmp/postmarketOS-export/xiaomi-lmi.img` has the same
  SHA256 as the release-bundle rootfs, because `pmbootstrap flasher
  flash_rootfs --partition userdata` flashes the current pmbootstrap export.

Stage commands selected by the helper:

```sh
pmbootstrap flasher flash_rootfs --partition userdata
fastboot flash boot /tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.img
```

The helper intentionally does not write `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader lock
state.

## Post-boot evidence monitor

After an explicitly approved reboot from the flashed state, collect milestone
evidence with:

```sh
scripts/54_monitor_lmi_post_boot.sh --timeout 180
```

The monitor is read-only from the host side. It records:

- `fastboot devices`;
- `adb devices`;
- `ip -br addr`;
- TCP reachability to `172.16.42.1:23` for the postmarketOS initramfs telnet
  debug shell;
- TCP reachability to `172.16.42.1:2222` for SSH.

If telnet is reachable and log collection is desired, run:

```sh
scripts/54_monitor_lmi_post_boot.sh --timeout 180 --collect-telnet-log
```

That mode sends read-only debug-shell commands to collect `/pmOS_init.log`,
`/proc/cmdline`, `/proc/partitions`, mounts, and network state. It does not run
`pmos_continue_boot`.

Short validation run in the current bootloader-fastboot state:

```sh
scripts/54_monitor_lmi_post_boot.sh --timeout 5 --interval 1
```

Result:

```text
seen_fastboot=1
seen_adb=0
seen_telnet_23=0
seen_ssh_2222=0
post-boot monitor: only fastboot observed
```

This matches the current known state and confirms the monitor does not mistake
bootloader fastboot for postmarketOS initramfs progress.

## Approval command sheet

Generated on 2026-06-24:

```sh
scripts/49_generate_lmi_flash_command_sheet.sh
```

Output:

```text
/tmp/lmi-release-r6-bootmem-20260624/APPROVAL_REQUIRED_COMMANDS.txt
```

The sheet does not approve or execute anything. It records the exact candidate
artifacts, hashes, preflight command, and persistent write commands that would
require separate fresh exact approval:

```text
fastboot flash boot /tmp/lmi-release-r6-bootmem-20260624/boot-linux-copydown-lmi-r6-bootmem.img
pmbootstrap flasher flash_rootfs --partition userdata
```

Rollback candidate scan:

```sh
scripts/50_scan_lmi_rollback_boots.sh
```

Report:

```text
/tmp/lmi-release-r6-bootmem-20260624/ROLLBACK_BOOT_CANDIDATES.txt
```

The scan found 17 Android boot-image candidates. Most are experiment images,
but it also found a full current boot partition backup:

```text
/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img
sha256=0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf
size=134217728
page_size=4096
kernel_size=47454232
ramdisk_size=1460277
```

Static header inspection of this backup:

```text
magic=ANDROID!
code0_le=0x149e0000
text_offset=0x80000
image_size=0x3805000
flags=0xa
magic56=ARMd
peoff=0x0
```

Assessment: this is the best local rollback boot candidate found so far,
because it is a full-size boot partition backup under `device-backup`. It still
must be treated as a candidate, not a proven guarantee, until matched to the
exact device/ROM state.

Guarded rollback dry-run:

```sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" \
scripts/55_stage_lmi_rollback_boot.sh --dry-run
```

The helper validates Android boot magic, SHA256, image size versus the observed
boot partition, `product=lmi`, and `unlocked=yes`. By default it requires
recovery fastbootd (`is-userspace=yes`) before rollback flashing. If the device
cannot reach fastbootd and bootloader fastboot rollback is chosen, that must be
a separate explicitly approved decision using
`LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT=1`.

Rollback execute mode would still require a fresh exact approval and the printed
`LMI_ROLLBACK_CONFIRM=...` token. It only targets:

```sh
fastboot flash boot /mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img
```

Validation in the current bootloader-fastboot state:

```text
default dry-run: FAIL, because is-userspace=no and recovery fastbootd is required by default
bootloader-fastboot dry-run with LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT=1: OK
execute without LMI_ROLLBACK_CONFIRM: REFUSED
No reboot, boot, flash, erase, format, or partition write was executed.
```

## Persistent route plan

The route can be rechecked from one read-only entry point:

```sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" \
scripts/56_lmi_persistent_flash_plan.sh --quick
```

The plan script runs local verifiers and dry-runs for:

- copydown boot image verification;
- rootfs staged flash dry-run;
- boot staged flash dry-run;
- rollback boot dry-run;
- current fastbootd wait/preflight state;
- current post-boot monitor state.

It writes:

```text
/tmp/lmi-release-r6-bootmem-20260624/PERSISTENT_FLASH_PLAN.txt
```

It never executes reboot, boot, flash, erase, format, or partition writes. In
the current bootloader-fastboot state, the expected route status is
`WAITING_FOR_RECOVERY_FASTBOOTD`.

Short validation run:

```sh
scripts/56_lmi_persistent_flash_plan.sh --quick
```

Result:

```text
copydown boot verification: OK
rootfs staged dry-run: OK
boot staged dry-run: OK
rollback dry-run default policy: expected FAIL while is-userspace=no
fastbootd wait/preflight current state: expected FAIL while is-userspace=no
post-boot monitor current state: expected only fastboot
plan: WAITING_FOR_RECOVERY_FASTBOOTD
No reboot, boot, flash, erase, format, or partition write was executed.
```

## Release Archive Manifest

The large images stay in the local `/tmp` release bundle, but their hashes and
route status are archived in git with:

```sh
LMI_ROLLBACK_BOOT_IMG="/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img" \
scripts/57_archive_lmi_release_manifest.sh
```

Output:

```text
docs/release/lmi-r6-bootmem-release-manifest-20260624.md
```

Current command sheet status after regenerating with `LMI_ROLLBACK_BOOT_IMG`:

- r6 boot image hash recorded:
  `cfc5748035bccb9a4c5b3c1683ef887aa3ce7ce802d6d19fc69d4141b28f6570`;
- r6 rootfs hash recorded:
  `24918896b43c962f1a54da44d53ad7fb722e9324a96dd6f1d1d3c93d832d73a7`;
- rootfs sparse file size: `1256602620` bytes;
- rootfs expanded size: `2150629376` bytes;
- rollback boot image:
  `/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img`;
- rollback boot hash:
  `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`.

The current read-only preflight still fails because the phone is not in recovery
fastbootd:

```text
is-userspace=no
```

Do not proceed to a boot partition write while `is-userspace=no`.

## Fastbootd entry sheet

Generated on 2026-06-24:

```sh
scripts/51_prepare_lmi_fastbootd_entry.sh
```

Output:

```text
/tmp/lmi-release-r6-bootmem-20260624/FASTBOOTD_ENTRY_REQUIRED.txt
```

Current read-only state:

```text
fastboot devices: <redacted-device-serial> fastboot
adb devices: no device
product=lmi
unlocked=yes
is-userspace=no
```

Recommended command recorded by the sheet:

```sh
fastboot reboot fastboot
```

This command was not executed. It requires fresh exact approval immediately
before use because it reboots the phone into recovery fastbootd. After it is
run and the phone reconnects, the next required read-only check is:

```sh
fastboot getvar is-userspace
```

Only continue to `scripts/48_preflight_lmi_fastbootd.sh` if the result is:

```text
is-userspace: yes
```
