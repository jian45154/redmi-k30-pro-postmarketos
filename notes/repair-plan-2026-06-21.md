# lmi Boot/Rootfs Repair Plan

Operator: Lucien Auregin (ian)

## Scope And Assumption

Primary goal: repair the existing postmarketOS boot path on `userdata` so the
device reaches `switch_root` and SSH, while continuing to RAM-boot the kernel.
The separate mainline Linux stack is treated as a fallback migration path, not
as an interchangeable replacement for the current postmarketOS artifacts.

No command in this plan is approval to boot, flash, format, erase, repartition,
or write a device partition. Each hardware boot and each partition write needs
separate approval immediately before execution.

## Evidence From The Supplied Resources

Confirmed:

- A current boot backup exists:
  `device-backup/lmi-current-boot.img`, SHA-256
  `0C06AD2ACA2AB0D510E9D9C97BA31D35A514B9A3D15850B1C4A2121E55FA5CBF`.
- The boot backup is an Android boot image with header v2 and 4096-byte page
  size.
- `boot-pmos-http-rootfs-diagnostic.img` provides a useful read-only HTTP log
  export pattern on `172.16.42.1:8080`.
- The HTTP diagnostic loop mounts its target with `-o ro` and reports the init
  log, partitions, `blkid`, root files and `dmesg`.
- The supplied mainline release boot image matches its manifest SHA-256:
  `0503CB164B306AF9674151EF0EDA544D51C9A5CCC249D4AA00282777B5CD7EBB`.

Blocking inconsistencies:

- The supplied HTTP diagnostic ramdisk omits
  `deviceinfo_rootfs_image_sector_size="4096"`.
- It hard-codes `/dev/sda34`, but the current postmarketOS layout is a nested
  GPT inside `userdata`; it does not directly use a dedicated `sda34` rootfs.
- The 9.5 KiB `lmi-gpt.bin` exposes partition labels but fails GPT CRC and
  backup-header validation when parsed as a disk. It is evidence, not a
  sufficient GPT restore artifact.
- The parsed GPT labels identify entry 34 as `exaid` and entry 38 as
  `userdata`. Therefore `/dev/sda34` must not be formatted or written based on
  the supplied README examples.
- The current initramfs archive does not match its adjacent manifest: the file
  SHA-256 is
  `5AC7D05C7BCED54833A028BED504BEF89E9787A5679F60AFB99A82E3790B0337`,
  while the manifest records a different hash and size.
- The supplied rootfs artifact is named Ubuntu 24.04, while the mainline docs
  describe Ubuntu 26.04 as the validated target. It has not been accepted as a
  verified migration image.

External repository audit:

- `macosmojave2-alt/postmarket-xiaomi-lmi` was reviewed at commit
  `0aade428ff962896d58d9d9278426eb5edbf0d10`.
- Its status document says the author's bootloader was still locked. Claims
  that display, audio, sensors or the SDX55 modem work are therefore not
  accepted as hardware validation for this device.
- Its `deviceinfo_rootfs_image_sector_size="4096"` independently supports the
  current sector-size choice, but that setting is already present in the active
  WSL package.
- The repository's firmware file lists, sensor inventory, fastrpc udev rule and
  hexagonrpcd path are useful packaging references after core boot is repaired.
- Do not copy its complete `deviceinfo`: it enables automatic kernel flashing,
  uses mainline-only DTB append behavior, contains a duplicated super-partition
  path and suppresses useful early logs.
- Do not use its flash instructions. `fastboot flash system` does not match the
  current `userdata` rootfs target.
- Do not import its ALSA UCM unchanged. The microphone disable sequence appears
  to repeat `MUX0`/`DEC0` where the second path should be independently checked.

## Success Criteria

1. A reproducible diagnostic boot image passes local inspection and contains
   the exact expected kernel, DTB, initramfs and 4096-sector device metadata.
2. A RAM-only boot exposes a stable, read-only HTTP report without relying on
   telnet protocol behavior.
3. The report proves whether `userdata` is present and whether its nested GPT
   is valid with 512- or 4096-byte sectors.
4. `pmOS_boot` and `pmOS_root` are identified by label and UUID.
5. `pmOS_root` mounts read-only and contains `/etc/os-release` and `/sbin/init`.
6. `pmos_continue_boot` leads to a successful `switch_root`.
7. SSH listens on port 22 and accepts the intended account/key.
8. No partition other than an explicitly approved `userdata` rewrite is
   modified during the repair.

## Phase 1: Freeze Inputs And Recovery Evidence

1. Record SHA-256, size and timestamp for every candidate boot, initramfs and
   rootfs artifact. Do not overwrite existing artifacts.
2. Treat `lmi-current-boot.img` as a boot rollback candidate, but verify its
   provenance against the device immediately before any future boot write.
3. Obtain a complete, independently parseable partition map and a known-good
   stock ROM/recovery path before any partition write.
4. Do not use `lmi-gpt.bin` as a restore image. Preserve it only as evidence.
5. Reconcile the repository device package with the active WSL package. The
   authoritative package must include:

```text
deviceinfo_dtb="qcom/kona-v2.1-lmi"
deviceinfo_rootfs_image_sector_size="4096"
deviceinfo_flash_fastboot_partition_rootfs="userdata"
```

6. Keep external packaging references in a separate review set. Do not copy an
   external `deviceinfo`, kernel config, APKBUILD or firmware blob directly into
   the authoritative package.

Verification gate: hashes and provenance are recorded; rollback material is
identified; no device write has occurred.

## Phase 2: Build A Corrected Read-Only Diagnostic Image

Reuse the supplied HTTP report mechanism, but do not use the supplied image
unchanged.

Required changes:

1. Start from the verified postmarketOS debug boot configuration already known
   to boot on this device.
2. Embed `deviceinfo_rootfs_image_sector_size="4096"` and the exact current lmi
   DTB.
3. Remove the hard-coded assumption that `/dev/sda34` is the rootfs.
4. Report, without writing:

```text
/proc/cmdline
/proc/partitions
/dev/block/by-name and /dev/disk/by-partlabel
blockdev logical/physical sector sizes
blkid results
fdisk interpretation of userdata at 512 and 4096 bytes
losetup --sector-size 512 and 4096 probe results
pmOS_boot and pmOS_root labels and UUIDs
read-only mount result for pmOS_root
/etc/os-release and /sbin/init presence
mount table, ip state and dmesg tail
```

5. Serve a static report over `http://172.16.42.1:8080/debug.txt`.
6. Do not expose an HTTP action that continues boot or writes storage.
7. Keep telnet available only as an optional interactive path; do not require
   it for evidence capture.

Local validation gate:

- inspect the Android boot header;
- verify boot size against the 128 MiB boot partition limit;
- extract the initramfs and confirm the 4096-sector setting and report code;
- scan the diagnostic path for `flash`, `erase`, `format`, `mkfs`, device-bound
  `dd`, read-write mounts and partition-table writes;
- generate a new manifest from the final artifact, not from an earlier file.

## Phase 3: RAM-Only Diagnostic Session

This phase requires explicit approval for the exact `fastboot boot` command.

1. Confirm `product=lmi`, bootloader unlocked, adequate battery and
   `is-userspace=no`.
2. RAM-boot the corrected diagnostic image. Do not flash it.
3. Attach USB `18d1:d001` to WSL and configure `172.16.42.2/24`.
4. Fetch `http://172.16.42.1:8080/debug.txt` and save a timestamped, redacted
   host copy.
5. Repeat the fetch after 10 seconds to confirm that the report is stable and
   not a partial early-boot snapshot.

Current status (2026-06-22): v3 RAM boot completed without storage writes and
confirmed sysfs `PARTNAME=userdata` on `sda34`. A control-flow error prevented
the sector probes. V4 then confirmed a 4096-byte logical and physical block size,
but missing temporary loop device nodes prevented loop partition discovery. The
corrected, reproducible v5 image is ready but has not been booted; see
`notes/repair-phase3-v4-hardware-2026-06-22.md`.

V5 subsequently completed the read-only loop probes. Neither 512- nor
4096-byte mapping exposed a nested partition, while the local 4096-byte
pmbootstrap image has a valid GPT and matching `pmOS_boot`/`pmOS_root` UUIDs.
This selects Case C, pending a final newer-e2fsprogs check of the local rootfs;
see `notes/repair-phase3-v5-hardware-2026-06-22.md`.

The newer e2fsprogs check subsequently passed. A target-sized 4096-sector
Android sparse candidate was generated and validated to avoid leaving the
backup GPT before the end of userdata. The remaining gate is recovery: no full
LineageOS/MIUI ROM was found locally, so the skkk recovery RAM-boot path must be
tested or a complete ROM supplied before any userdata write. See
`notes/repair-phase5-prewrite-validation-2026-06-22.md`.

The A12 skkk TWRP 3.6.2 image subsequently completed a RAM boot and exposed ADB,
the correct userdata node and format-data capability. The minimum recovery gate
for a userdata-only rewrite is now closed. The next action is the destructive
write approval gate; see `notes/repair-phase5-recovery-test-2026-06-22.md`.

Ian explicitly approved the userdata rewrite. The validated target-sized sparse
candidate was written in two sub-700 MiB chunks, and both send/write operations
completed with `OKAY`. No other partition was written. The device remains in
fastboot pending a separately approved v5 RAM boot; see
`notes/repair-phase5-userdata-write-2026-06-22.md`.

The approved post-write v5 RAM boot proved a valid nested GPT at the required
4096-byte sector size. V5 lacked temporary loop partition nodes, so blkid and
rootfs mount verification did not run. A reproducible v6 image adds those
RAM-only nodes and awaits separate approval; see
`notes/repair-phase6-postwrite-v5-2026-06-22.md`.

The approved v6 RAM boot confirmed both filesystem UUIDs but `pmOS_root` could
not mount. The root cause is ext4 `orphan_file`, unsupported by the downstream
4.19 kernel. A new target-sized candidate removes only that feature and passes
GPT, UUID, old/new e2fsck and split round-trip validation. It requires a new
userdata rewrite approval; see
`notes/repair-phase6-ext4-compatibility-2026-06-22.md`.

Ian explicitly approved the new rewrite. Both 700 MiB-limited sparse chunks
were sent and written with `OKAY`; no other partition was touched. The
bootloader USB transport needs to be re-entered or reconnected before the next
separately approved v6 mount verification; see
`notes/repair-phase6-k419-userdata-rewrite-2026-06-22.md`.

The second approved v6 boot confirmed GPT and UUIDs but returned the same mount
`ENOENT`; removing `orphan_file` was necessary for compatibility but not the
direct mount blocker. The initramfs lacks a mount symlink and relies on BusyBox
standalone applet dispatch. Reproducible v7 explicitly invokes BusyBox mount and
captures filesystem support plus immediate dmesg; see
`notes/repair-phase7-mount-dispatch-2026-06-22.md`.

The approved v7 boot confirmed ext4 is built in, but explicit BusyBox mount
still returned `ENOENT` without an EXT4/VFS dmesg record. Reproducible v8 adds a
minimal static AArch64 program that calls read-only `mount(2)` directly and
prints exact errno; see `notes/repair-phase8-mount-syscall-2026-06-22.md`.

The approved v8 boot proved the source block node can be statted and opened, but
direct `mount(2)` returned `ENOENT` without an EXT4/VFS dmesg record.
Reproducible v9 adds target-directory, RAM-only tmpfs and read-only ext2 control
mounts before the ext4 attempt; see
`notes/repair-phase9-vfs-mount-probes-2026-06-22.md`.

The approved v9 boot proved the target and generic mount syscall work: the
read-only tmpfs control succeeded, while both loop partition filesystem mounts
returned `ENOENT`. Because `loop.max_part=7` spaces whole loop devices by eight
minors, the earlier `/dev/loop1` node was incorrectly `7:1`, not the real
whole-device minor `7:8`. Reproducible v10 maps the exact `pmOS_root` byte range
read-only onto a correctly numbered loop device, bypassing the partition bdev
path; see `notes/repair-phase10-offset-loop-2026-06-22.md`.

The approved v10 boot confirmed the direct mapping as `/dev/loop1` (`7:8`) and
read the expected ext4 UUID, but its mount still returned `ENOENT` without an
EXT4/VFS record. The incorrect loop minor was therefore a real diagnostic bug,
not the final root cause. Reproducible v11 uses a read-only device-mapper linear
target for the exact rootfs range to bypass loop entirely; see
`notes/repair-phase11-dm-linear-2026-06-22.md`.

The approved v11 boot successfully created the read-only DM-linear target and
read the expected ext4 UUID from `/dev/mapper/lmi-root` (`252:0`), but direct
mount still returned `ENOENT`. Loop and nested partition bdev handling are now
excluded as the direct cause. Reproducible v12 embeds a feature-free minimal
ext2 filesystem in initramfs and mounts it through a correctly numbered whole
loop device, testing the shared ext4 compatibility driver independently; see
`notes/repair-phase12-minimal-ext2-control-2026-06-22.md`.

The approved v12 boot identified the feature-free control filesystem on
`/dev/loop2` (`7:16`), but its ext2 mount returned the same `ENOENT`. The
flashed filesystem contents and features are therefore excluded as the direct
cause. Reproducible v13 copies the control to volatile `/dev/ram0` and adds a
block-node bind-mount check, separating block-driver behavior from the VFS
block-filesystem path; see
`notes/repair-phase13-ram-block-vfs-2026-06-22.md`.

The approved v13 boot copied and identified the complete control filesystem on
`/dev/ram0` (`1:0`). A bind mount of the same block node succeeded, while its
ext2 filesystem mount still returned `ENOENT`. This excludes storage drivers,
manual `mknod` and generic pathname lookup. The next diagnostic kernel adds
`LMI_VFS_DIAG` logging only at `legacy_get_tree`, `mount_bdev`,
`lookup_bdev`/`blkdev_get_by_path` and `ext4_fill_super`; it must be built and
inspected before a separately approved RAM boot.

Stop if the image provenance, device identity, USB state or report contents do
not match the expected configuration.

## Phase 4: Decide From The Report

### Case A: Valid 4096-Sector Nested GPT And Mountable Rootfs

Do not reflash. Reboot the same diagnostic image only after a separate approval,
connect with a real telnet client, capture the report, run
`pmos_continue_boot`, then test SSH.

### Case B: Existing Image Is Valid Only At 512 Bytes

The flashed rootfs and current 4096-sector initramfs are mismatched. Rebuild a
matching postmarketOS rootfs and boot image from the same package revisions.
Inspect both locally before proposing a `userdata` rewrite.

### Case C: No Nested GPT Or Missing `pmOS_root`

Treat `userdata` as stale or incomplete. Preserve any recoverable data, rebuild
the rootfs image, and verify labels, UUIDs and filesystem before proposing a
rewrite.

### Case D: Rootfs Mounts But `switch_root` Fails

Inspect `/sbin/init`, architecture, dynamic loader, `/etc/fstab`, filesystem
errors and initramfs cleanup. Do not change SSH yet.

### Case E: `switch_root` Succeeds But SSH Is Refused

Only then inspect sshd enablement, host-key generation, account/key state,
listening addresses, firewall and service logs.

## Phase 5: Conditional `userdata` Repair

This phase is destructive and is not authorized by this plan.

Before requesting approval:

1. Regenerate the postmarketOS image with the verified 4096-byte rootfs sector
   layout.
2. Confirm the image shows exactly two nested GPT partitions at 4096 bytes and
   fails or shows only a protective MBR at 512 bytes.
3. Confirm `pmOS_boot` and `pmOS_root` labels, UUIDs, filesystem checks and
   matching boot cmdline UUIDs.
4. Record hashes for the rootfs and RAM boot image.
5. Reconfirm `product=lmi`, target=`userdata`, battery, backup and rollback.
6. Request explicit approval for the exact `userdata` write command.

After an approved rewrite, continue using RAM-only boot. Do not write `boot`,
`dtbo`, `vbmeta`, `super`, `persist`, modem/EFS or GPT as part of this repair.

## Phase 6: Post-Repair Verification

Verify milestones separately:

```text
bootloader accepts RAM image
initramfs starts
USB networking is stable
userdata nested GPT is discovered
pmOS_root mounts
switch_root completes
SSH works
storage and filesystem checks pass
display and input
Wi-Fi and Bluetooth
charging and battery reporting
audio
suspend/resume
sensors
camera and modem only as explicitly supported experiments
```

Do not describe the port as fully working if only boot, ping or SSH passes.

## Phase 7: Optional Firmware And User-Space Reuse

Run this phase only after rootfs mount, `switch_root` and SSH are stable.

Candidate reference files from `macosmojave2-alt/postmarket-xiaomi-lmi`:

```text
firmware-xiaomi-lmi/firmware.files
firmware-xiaomi-lmi/30-initramfs-firmware.files
firmware-xiaomi-lmi/sensor.files
device-xiaomi-lmi/81-libssc-xiaomi-lmi.rules
device-xiaomi-lmi/hexagonrpcd.confd
device-xiaomi-lmi/modules-initfs
```

Reuse conditions:

1. Treat file lists as inventories, not proof that the referenced blobs match
   this phone.
2. Source proprietary firmware from a verified image or the target device,
   record hashes and keep redistribution boundaries explicit.
3. Use the panel entries in `modules-initfs` only with a mainline kernel that
   actually builds those module names. Do not add them to the downstream 4.19
   initramfs blindly.
4. Add the fastrpc udev rule and hexagonrpcd configuration only after the
   matching remoteproc/fastrpc services and firmware paths are verified.
5. Audit ALSA controls against `amixer controls` from the running kernel before
   adapting any UCM file.

These files may improve GPU, DSP, sensors, display and audio later; none is a
direct fix for the current debug-shell or rootfs discovery failure.

## Optional Mainline Migration Track

The supplied mainline stack is a separate migration project. It must not be
used as a shortcut to repair the current postmarketOS rootfs.

Before any mainline hardware test:

1. Resolve the `/dev/sda34` conflict with a live, read-only partition map.
2. Regenerate the initramfs manifest so it matches the actual archive.
3. Rebuild the mainline boot image from that exact initramfs and regenerate its
   manifest.
4. Validate the sparse rootfs version, label, filesystem and contents; resolve
   the Ubuntu 24.04 versus 26.04 documentation mismatch.
5. Confirm the mainline image can be tested with RAM-only `fastboot boot` on
   this bootloader before considering a persistent boot write.
6. Never format `/dev/sda34`, flash `linuxroot`, or write `boot` until its exact
   partition identity and rollback path are proven on this device.
7. Resolve the SDX55 PCIe controller mapping before applying any modem patch.

### SDX55 PCIe Evidence Gate

`pcie1` and `pcie2` are distinct SM8250 host controllers, not PCIe protocol
versions. They have different PHY, clock, reset, regulator and board-routing
connections and are not interchangeable.

Current conflicting evidence:

- the external patch enables `pcie1` at `pcie@1c08000` and assumes SDX55 is
  routed there;
- the supplied mainline adaptation records associate the observed SDX55
  SBL/Sahara path with the controller named `pcie2` at `1c10000.pcie`.

Before changing either node, capture and correlate:

```text
lspci -nn -t
lspci -nn -vv
dmesg lines for 1c08000.pcie and 1c10000.pcie
/sys/bus/pci/devices/* vendor, device and firmware_node links
the running DT compatible/status values for both controllers and PHYs
the endpoint PCI ID, expected to include 17cb:0306 if SDX55 enumerates
```

Accept a mapping only when the endpoint's sysfs firmware-node path and host
bridge address agree. Do not enable both controllers merely to see which one
works, and do not infer Mission/QMI support from PCI enumeration or a Sahara
HELLO. The external modem patch remains reference-only until this gate passes.

The existing mainline claims and hardware matrix are useful evidence, but they
do not override the contradictory local GPT and artifact manifests.
