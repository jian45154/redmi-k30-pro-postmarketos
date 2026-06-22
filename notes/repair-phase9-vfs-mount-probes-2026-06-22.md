# Repair Phase 9: VFS Mount Probes

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## V8 Evidence

```text
report_size=37299
report_sha256=6D4BF88416053380CBF5B348DBFBB305C28CD210D9C179CFFF2FE2B834159B97
reports_identical=yes
sanitized=logs/repair-http-debug-v8-2026-06-22.redacted.txt
sanitized_sha256=BAFF69C203416BEA264DC1F1181A3C16334E3AD10C91E5998F75D9BA0FC0D458
redaction_audit=pass
```

The static diagnostic program successfully statted and opened the source block
device, reporting `source_rdev=7:2`. Its direct read-only mount syscall returned:

```text
errno=2
message=No such file or directory
```

Immediate dmesg still contained no EXT4 or VFS mount error. The ext4 mount
initialization source does not expose a matching normal mount-time `ENOENT`
path, so source/target VFS resolution must be tested independently.

## V9

V9 extends the direct syscall diagnostic to:

- stat and print the target directory mode;
- mount and unmount a RAM-only read-only tmpfs;
- mount and unmount `pmOS_boot` as read-only ext2;
- mount `pmOS_root` as ext4 with `MS_RDONLY` and `noload`.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v9.img
sha256=3BC67690B5B9254423E21A5E80A5F55FBF9093E506F78FFDB0E099843BFFE1F7
artifact_size=53084160
diagnostic_ramdisk_sha256=3389B83333CAB5EE7F74DDBBE1E3E8E1ED34A5681D62E0FBBB8D9C83076B874B
mount_probe_sha256=F238D8868F2A83B138CED0BEBA154B7395AAED788C7F05F31B7F429BD4DBAB88
reproducible=yes
syntax=ok
```

V9 was RAM-booted after separate explicit approval. Two captured reports were
byte-identical:

```text
report_size=37376
report_sha256=3916A5C1701197BF1503D4DDE48E3736234C07703D71F7988B3F6E4D8A3CC804
reports_identical=yes
sanitized=logs/repair-http-debug-v9-2026-06-22.redacted.txt
sanitized_size=35923
sanitized_sha256=D554D504E899E77A9587D4553C68FC89CBF14C4B27CCA3777BC121824FC86C77
redaction_audit=pass
```

The target existed with mode `0755`, and the read-only tmpfs control mounted
and unmounted successfully. The read-only `pmOS_boot` ext2 mount and
`pmOS_root` ext4 mount both returned `ENOENT`, while the kernel had already
reported `loop0: p1 p2`. This isolates the failure to the old loop partition
block-device path rather than the target directory, generic mount syscall or
ext4 alone.
