# Repair Phase 13: RAM Block And VFS Path Probe

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Purpose

V12 proved that a feature-free ext2 filesystem in initramfs still fails to
mount through a correctly numbered whole loop device. V13 copies that same
8 MiB control image into `/dev/ram0`, a traditional RAM block device, and
mounts it read-only as ext2. The only write is to volatile RAM.

The static probe also bind-mounts each source block node onto a temporary file.
A successful bind mount followed by a failed filesystem mount would prove that
the source pathname resolves inside the mount syscall and narrow the failure to
the block-filesystem path after generic VFS resolution.

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v13.img
sha256=CAF6CC29D4DB62A42CCFBE96B4495B04C1E1B9A99C7C5AACDF9314E94E0BB2F1
artifact_size=53100544
diagnostic_ramdisk_sha256=2E8191495F3C266708790435DFB1CC8C2D1A8159AF64F1AD8BA24255A39F578E
mount_probe_sha256=4549BA58AD83A38BFB07FAF5E220ECCDE3C469C2C102A426EB2D1EAF36C2D754
control_sha256=AB1ADE5A0D53DDEA998248DB0269A3A003A6FB275E450CB6C63A83B848F6A8B6
reproducible=yes
syntax=ok
inspection=ok
```

## Hardware Result

V13 was RAM-booted after separate explicit approval. Fastboot reported `OKAY`
for sending and booting; no partition was written. Two reports were
byte-identical:

```text
report_size=53330
report_sha256=C72A5A7B0C8AD94268DF3FCCBD03A7E1B4A9586004CCA8F7158073AB4C174040
reports_identical=yes
sanitized=logs/repair-http-debug-v13-2026-06-22.redacted.txt
sanitized_size=50070
sanitized_sha256=6266BAEC9B85645BA144796AE19B0E34985582C6D90DBE2CA57B28FE34A04C11
redaction_audit=pass
```

The complete 8 MiB control image was copied into `/dev/ram0`; `blkid` then
reported the expected label and UUID. The probe reported `source_rdev=1:0`.
Bind-mounting the same block node onto a temporary file succeeded and
unmounted cleanly, proving that the source path resolves inside `mount(2)`.
The subsequent ext2 filesystem mount still returned `ENOENT` without an
EXT4/VFS record.

This excludes UFS, sector size, loop, device-mapper, filesystem contents,
manual block-node creation and generic VFS pathname resolution. The remaining
failure is inside the block-filesystem path between `legacy_get_tree`,
`mount_bdev`, `blkdev_get_by_path` and `ext4_fill_super`.
