# Repair Phase 10: Direct Offset Loop Probe

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Basis

The kernel command line uses `loop.max_part=7`. With this layout, whole loop
devices occupy minors spaced by eight: `loop0=7:0`, `loop1=7:8`, and so on.
Earlier diagnostics created `loop1` as `7:1`; that minor is actually the first
partition of `loop0`.

V10 keeps the failing `/dev/loop0p1` and `/dev/loop0p2` controls, then maps the
known `pmOS_root` byte range directly onto the real `/dev/loop1` (`7:8`):

```text
backing_device=userdata
sector_size=4096
offset=511705088
sizelimit=1247805440
mode=read-only
filesystem=ext4
mount_options=ro,noload
```

This bypasses the old kernel's loop partition block-device path without
writing storage.

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v10.img
sha256=86988B89EB29C2DED05C3E57C17506F6F4C13BC2BF5DBA948ACF3CEBEBF8813D
artifact_size=53088256
diagnostic_ramdisk_sha256=04FF05AAAF6C23A50967CA9AF57C1767D388A604824B20C90FCA742179E2091C
mount_probe_sha256=5E3A2B8958895B1BBF0E1E38A37465C5B5A31946C55AD851C6E05E3CADAC18B1
reproducible=yes
syntax=ok
inspection=ok
```

The embedded probe is a stripped static PIE for AArch64.

## Hardware Result

V10 was RAM-booted after separate explicit approval. Fastboot reported `OKAY`
for both sending and booting; no partition was written. Two HTTP reports were
byte-identical:

```text
report_size=37552
report_sha256=749DCE93476B12334784DFFA4DF1556EE781DE34805ADBA33176350851029934
reports_identical=yes
sanitized=logs/repair-http-debug-v10-2026-06-22.redacted.txt
sanitized_size=36136
sanitized_sha256=0BF6E1F36ABC857D2587C1D9358E343DD9E7A2783D6C223A66E41010E39FD33E
redaction_audit=pass
```

The direct mapping itself was correct: `blkid` identified `pmOS_root`, and the
probe reported `source_rdev=7:8`. The final direct-offset mount still returned
`ENOENT` without an EXT4/VFS dmesg record. Correcting the whole-loop minor was
necessary, but it did not remove the mount failure.

A subsequent one-shot telnet attempt closed before executing the proposed
device-mapper commands. Its host-side variable expansion error did not run on
the phone and did not modify storage.
