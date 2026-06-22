# Repair Phase 8: Direct Mount Syscall Diagnostic

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## V7 Evidence

```text
report_size=37209
report_sha256=13D20AFC094446B2F9C04B9DB8C0B2C3FA3D8A601437B0C34A33144229AC980C
reports_identical=yes
sanitized=logs/repair-http-debug-v7-2026-06-22.redacted.txt
sanitized_sha256=C4ECD66FF482AF58EEC9F58B01C88F6EF841321C50F8D73A2730B6C23B0B16C8
redaction_audit=pass
```

V7 confirmed that `/proc/filesystems` contains ext4 and the kernel has ext4
built in. `modprobe ext4` therefore correctly reports no module. Explicit
`/bin/busybox mount` still returned `ENOENT`, and immediate dmesg contained no
EXT4 or VFS mount error. This indicates that the BusyBox mount path returned
before a useful kernel filesystem diagnostic was emitted.

## V8

V8 carries a minimal static AArch64 program that:

- stats and opens `/dev/loop0p2` read-only;
- calls `mount(2)` directly with `MS_RDONLY` and `noload`;
- prints exact errno and strerror;
- calls `umount2(2)` after successful inspection.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v8.img
sha256=6333BE78DA1F22F407F8C6CEB7C7797B99F46BFACC7959E65C9243739D776845
artifact_size=53084160
diagnostic_ramdisk_sha256=C129E28584EEFB0D29F677F3EC3A62BEE65385004928AE31A7E9ED0DD2CF640
mount_probe_sha256=8A7096AD26FF565E01F0F3AED5152F7F61602FA69BA4E6DDFDB804E0042CB0C6
reproducible=yes
syntax=ok
```

The build script now uses cpio `--reproducible`; a strict second build was
byte-identical. V8 has not been booted and requires separate explicit approval.
