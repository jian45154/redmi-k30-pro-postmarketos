# Repair Phase 7: Mount Dispatch Diagnostic

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## K4.19 V6 Result

```text
report_size=34041
report_sha256=0BC3B9150F99B321DCA0BE8B7A3A8BC152324CBD8BF04FF7D57511400A41B05C
reports_identical=yes
sanitized=logs/repair-http-debug-v6-k419-2026-06-22.redacted.txt
sanitized_sha256=0B338AEE511818AD87C901E5D077A94163CCFA3211EF370CC462D53D4C91358E
redaction_audit=pass
```

The 4.19-compatible rewrite retained a valid 4096-sector GPT and both expected
filesystem UUIDs. Mounting `pmOS_root` returned the same `ENOENT` result as the
previous filesystem, so ext4 `orphan_file` was a compatibility defect but not
the direct source of this mount error.

The kernel package config confirms:

```text
CONFIG_EXT4_FS=y
CONFIG_JBD2=y
CONFIG_FS_MBCACHE=y
```

The unpacked initramfs contains BusyBox but no `/bin/mount`, `/usr/bin/mount` or
`/sbin/mount` link. The diagnostic's bare `mount` command therefore relies on
BusyBox ash standalone applet dispatch.

## V7

V7 explicitly invokes `/bin/busybox mount`, records `/proc/filesystems`, tries
`modprobe ext4`, and captures immediate dmesg if mount fails.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v7.img
sha256=7F88745C3BE007AA4A455BAA8DD37097F55328282E52DEA671B6F1BFDB10854A
artifact_size=53067776
diagnostic_ramdisk_sha256=F9A69CA761CB4BC608C3E12265343DB7E4BAC946872680892E9B2A293FD2A4F7
reproducible=yes
syntax=ok
```

V7 has not been booted and requires separate explicit RAM-boot approval.
