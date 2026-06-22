# Repair Phase 11: Read-Only DM-Linear Probe

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Purpose

V10 proved that a correctly numbered whole loop device can expose the expected
ext4 UUID but still fails `mount(2)` with `ENOENT`. V11 bypasses loop entirely
by presenting the same rootfs byte range through a read-only device-mapper
linear target.

Device-mapper tables use 512-byte sectors:

```text
backing_device=/dev/sda34
start_512=999424
length_512=2437120
target=linear
mode=read-only
filesystem=ext4
mount_options=ro,noload
```

The report removes the temporary mapping after the probe. It does not write the
mapped filesystem or any Android partition.

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v11.img
sha256=D0A8E5BC233073DCA97FCBFF0F48DAA35194DADA042498340F9A6BBB59E87B86
artifact_size=53088256
diagnostic_ramdisk_sha256=DD569530B51B51C5F04EB30A011C05DB87CB111E9260E457439E18B6FC4A6545
mount_probe_sha256=69C21C12CBBA3874F43E93303D8203D479F77127E0DA5921DE4DCC2F2B7E0709
reproducible=yes
syntax=ok
dmsetup_dependencies=present
inspection=ok
```

## Hardware Result

V11 was RAM-booted after separate explicit approval. Fastboot reported `OKAY`
for sending and booting; no partition was written. Two HTTP reports were
byte-identical:

```text
report_size=42812
report_sha256=6D75C0184CF7379528820A085D82CCC7470929BD587A9059B8ECFC9FE2502BDB
reports_identical=yes
sanitized=logs/repair-http-debug-v11-2026-06-22.redacted.txt
sanitized_size=39776
sanitized_sha256=FEFD3ADA61525E29FE4AE415439965324E9A9EF8FADD74EAB4454436E3FDEC86
redaction_audit=pass
```

The read-only DM target was created successfully from backing device `259:18`:

```text
table=0 2437120 linear 259:18 999424
dm_node=/dev/mapper/lmi-root
dm_rdev=252:0
uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370
```

Direct `mount(2)` still returned `ENOENT` without an EXT4/VFS dmesg record.
This excludes loop and the nested partition block-device path as the direct
cause.
