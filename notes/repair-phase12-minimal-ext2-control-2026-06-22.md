# Repair Phase 12: Minimal Ext2 Control

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Purpose

V11 bypassed loop with a valid read-only DM-linear mapping but retained the
same mount `ENOENT`. Both `pmOS_boot` ext2 and `pmOS_root` ext4 use the kernel's
ext4 compatibility driver because `CONFIG_EXT4_USE_FOR_EXT2=y`.

V12 embeds an 8 MiB ext2 control filesystem in initramfs and maps it read-only
through the correctly numbered `/dev/loop2` (`7:16`). The control has no
optional filesystem features and uses a 128-byte inode. It distinguishes a
generic block-filesystem mount failure from incompatibility in the flashed
filesystems.

```text
control=artifacts/images/lmi-ext2-control-8m.img
control_sha256=AB1ADE5A0D53DDEA998248DB0269A3A003A6FB275E450CB6C63A83B848F6A8B6
control_size=8388608
control_uuid=11111111-2222-3333-4444-555555555555
control_features=none
control_e2fsck=pass
```

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v12.img
sha256=DA306C0012732798C5A810BFF6FB3DFC5F2470B903CA6FD5A59D50953C895C7D
artifact_size=53096448
diagnostic_ramdisk_sha256=0963F7C9764D368235B1CDB7D2669717789239B662B27DF3BA905AC5A6EF3D24
mount_probe_sha256=96C478F0AD6E788B0B437F036117FA447C4344BA103687753FA23BDBA2E0B8D7
reproducible=yes
syntax=ok
inspection=ok
```

## Hardware Result

V12 was RAM-booted after separate explicit approval. Fastboot reported `OKAY`
for sending and booting; no partition was written. Two reports were
byte-identical:

```text
report_size=48106
report_sha256=55C9332AC7CC333B7761EA2492884094270050EDB37F6156131C0A6A998DEDD2
reports_identical=yes
sanitized=logs/repair-http-debug-v12-2026-06-22.redacted.txt
sanitized_size=44823
sanitized_sha256=BAF463FC562C28BFBA096770D3F9A39AE95011774590EC52E31E05FACECF30B7
redaction_audit=pass
```

The control was identified correctly on `/dev/loop2` (`7:16`) with the fixed
label and UUID, but direct ext2 `mount(2)` returned `ENOENT` without an
EXT4/VFS dmesg record. Because the control has no optional features, this
excludes the flashed filesystem contents and feature set as the direct cause.
