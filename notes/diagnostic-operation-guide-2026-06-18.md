# Diagnostic Operation Guide

签名：codex_ian | 2026-06-18 Australia/Sydney

## Purpose

Determine why the Redmi K30 Pro (`lmi`) postmarketOS port reaches USB networking
but does not provide a stable shell. Verify configuration and images before any
further partition write.

This is an operation guide, not approval to boot or flash the phone.

## Current Evidence

Confirmed:

- Device: `lmi`, SM8250, UFS storage, unlocked bootloader.
- Kernel and initramfs start through RAM-only `fastboot boot`.
- USB CDC-NCM networking works and `172.16.42.1` responds to ping.
- The debug-shell hook and `telnetd` exist in the latest initramfs.
- The latest WSL `deviceinfo` contains a premerged lmi DTB and
  `deviceinfo_rootfs_image_sector_size="4096"`.
- The latest locally generated rootfs image is a valid GPT image when interpreted
  with 4096-byte sectors.

Not yet confirmed:

- Whether the rootfs currently on `userdata` was generated with 512- or
  4096-byte sectors.
- Whether 4096-byte sectors are required on this specific phone during boot.
- Whether initramfs sees `userdata`, `pmOS_boot`, and `pmOS_root`.
- Whether rootfs mounts and `switch_root` completes.
- Whether the debug-shell network session is stable enough to capture logs.
- Whether the premerged DTB contains all required panel and WLAN nodes.
- Whether all storage and USB drivers needed before `switch_root` are built-in
  or present in `modules-initfs`.

## Safety Rules

1. Do not run `flash`, `erase`, `format`, repartition, sideload, or bootloader
   lock commands without separate explicit approval for the exact action.
2. Do not write `boot`, `dtbo`, `vbmeta`, `super`, `persist`, modem/EFS, or other
   device-specific partitions during this diagnostic stage.
3. Treat `userdata` writes as destructive even when the partition table of the
   phone is not changed.
4. Verify artifact hashes, partition targets, battery, backups, and rollback
   material immediately before any approved hardware action.
5. Never infer rootfs sector size from `deviceinfo_flash_pagesize`; they control
   different image layers.

## Phase 1: Audit Device Metadata (Read-Only)

Compare the active WSL package, the repository mirror, and the official current
`pmaports/deviceinfo_schema.toml`.

Verify independently:

| Item | Current status | Required evidence |
|---|---|---|
| Boot image page size | `4096` | Stock boot header and offsets |
| Rootfs image sector size | `4096` candidate | Image GPT plus boot-time comparison |
| Rootfs flash target | Expected `userdata` | Expanded pmbootstrap flasher variables |
| Kernel flash target | Expected `boot` | Expanded pmbootstrap flasher variables |
| Boot image header | Version 2 | Stock and generated image inspection |
| DTB | Premerged `kona-v2.1-lmi` in latest WSL copy | Decompile and inspect nodes |
| DTBO behavior | Unconfirmed for RAM boot | Bootloader evidence, not assumption |
| `modules-initfs` | Currently empty in repository mirror | Kernel config and initramfs contents |
| Screen geometry | 1080 x 2400 candidate | Stock panel/cmdline evidence |

Stop if the active build source differs from the repository mirror. Decide which
copy is authoritative before rebuilding; do not synchronize blindly.

## Phase 2: Inspect Images Locally (No Phone)

Record hashes and timestamps for every candidate image. Do not use filenames as
proof of provenance.

Check rootfs layout with both interpretations:

```sh
fdisk -b 512  -l xiaomi-lmi.img
fdisk -b 4096 -l xiaomi-lmi.img
```

Expected result for a 4096-sector image:

- 4096-byte interpretation shows a valid GPT with `pmOS_boot` and `pmOS_root`.
- 512-byte interpretation may show only an invalid/protective MBR or GPT size
  mismatch.

Also verify:

```text
- boot image header, offsets, cmdline, DTB size, and total size
- presence of the selected DTB in the kernel package and boot image
- initramfs contains loop/storage/USB networking support and debug-shell tools
- rootfs contains openssh-server, host keys or key-generation service, user, and
  enabled sshd service
```

Do not conclude that 4096 is required on hardware from local image inspection
alone. It only proves how that particular image must be interpreted.

## Phase 3: Prepare Two Separate Boot Images (Local Build Only)

After the metadata audit is complete, build two clearly named images from the
same package revisions:

1. Debug image: includes `pmos.debug-shell` and the debug-shell hook.
2. Normal image: does not include `pmos.debug-shell`; intended for SSH validation
   only after rootfs discovery is proven.

For each image, record:

- source commits and package revisions;
- complete kernel cmdline;
- DTB hash;
- initramfs hash and contents;
- expected rootfs sector size;
- exported image hash.

Do not build or copy over an existing artifact without preserving its hash and
provenance.

## Phase 4: RAM-Boot the Debug Image (Requires Approval)

Use only a RAM boot supported by the bootloader. Do not flash a partition.

After USB CDC-NCM appears, configure the WSL host address and connect to the
initramfs debug service. Immediately capture:

```sh
cat /pmOS_init.log
dmesg
cat /proc/cmdline
cat /proc/partitions
ls -l /dev/disk/by-partlabel /dev/mapper 2>/dev/null
blkid
mount
losetup -a
ip addr
ip route
```

Save output on the host with timestamps. Redact device identifiers.

If the shell remains stable, run `pmos_continue_boot` once, then observe whether:

1. rootfs is found;
2. rootfs mounts;
3. `switch_root` completes;
4. SSH port 22 begins listening.

## Phase 5: Decide From Evidence

### Case A: `pmOS_root` is not found

Compare 512 and 4096 behavior using the same image and record the exact
`losetup`, `fdisk`, or initramfs errors. Check storage and loop drivers before
changing SSH settings.

Only call 4096 the confirmed fix if the same image/rootfs is discoverable with
4096 and not with 512, or `/pmOS_init.log` gives equivalent direct evidence.

### Case B: Rootfs mounts but `switch_root` fails

Inspect filesystem errors, `/etc/fstab`, init path, architecture, required
libraries, and rootfs integrity.

### Case C: `switch_root` completes but SSH is refused

Inspect sshd enablement, host keys, account configuration, firewall, listening
addresses, and service logs. Do not diagnose SSH before proving `switch_root`.

### Case D: Shell works but display or Wi-Fi does not

Inspect DTB nodes and driver probe logs separately:

```sh
dmesg | grep -iE 'drm|dpu|dsi|panel|mdss'
dmesg | grep -iE 'cnss|icnss|wlan|remoteproc|rproc|adsp|wpss'
```

Then check kernel config, modules, firmware, regulators, clocks, `rmtfs`,
`pd-mapper`, and `tqftpserv`. Do not mix these fixes with rootfs discovery.

## Phase 6: Rebuild or Reflash Only After Diagnosis

If logs prove the flashed rootfs has the wrong layout, first regenerate and
inspect a corrected image locally. Before reflashing `userdata`, reconfirm:

- explicit approval for `userdata` only;
- current fastboot product and target partition;
- recovery/stock ROM availability;
- data-loss acceptance;
- corrected image hash and sector layout;
- boot image and rootfs image were generated from matching package revisions.

After a successful rootfs test, continue using RAM boot. Do not write `boot`
until rootfs, SSH, rollback, and the normal non-debug image have all been
validated.

## Success Criteria

Report each milestone separately:

1. Bootloader accepts the RAM image.
2. Kernel and initramfs start.
3. USB networking is stable.
4. Debug shell is stable and logs are captured.
5. `pmOS_root` is found and mounted.
6. `switch_root` completes.
7. SSH works with the normal image.
8. Display, Wi-Fi, audio, modem, charging, suspend, sensors, and input are tested
   individually.
9. A credible rollback path remains available.

Do not describe the port as installed or supported before these milestones are
explicitly recorded.
