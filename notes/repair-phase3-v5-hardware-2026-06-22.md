# Repair Phase 3: V5 Hardware Diagnostic

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Scope

Temporary RAM boot and read-only HTTP/debug-shell inspection. No partition was
flashed, erased, formatted, repartitioned or written.

## Artifact And Preflight

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v5.img
sha256=F39858195B7030B33AD07B5D5E245931AD7593AC5B4364DD699441356DEBDAD0
product=lmi
unlocked=yes
battery_voltage_mv=4190
is_userspace=no
```

Fastboot accepted and RAM-booted the image. USB networking returned 3/3 pings
with approximately 4.30 ms average round-trip time.

Two reports captured 10 seconds apart were byte-identical:

```text
size=32700
sha256=F16B469A769D66FD6930CFD4F3785900888608636F2181041D035E4A3C2FFF98
```

Sanitized report:

```text
logs/repair-http-debug-v5-2026-06-22.redacted.txt
sha256=4EEE082A3F94CA4BD186FECBBD1E314BBCFC22CB3B4904CF1EED394CAC9447FF
redaction_audit=pass
```

## Hardware Findings

- Sysfs resolves userdata as `/dev/sda34`.
- The logical block size is 4096 bytes.
- V5 successfully created temporary RAM-only loop nodes.
- Read-only loop mapping succeeded with both 512- and 4096-byte sector sizes.
- Neither mapping produced a partition, filesystem label or UUID.
- The same kernel successfully parsed the outer UFS GPT, so the absence of loop
  partitions is evidence that userdata does not contain the expected nested
  postmarketOS GPT.

## Local Image Comparison

The current pmbootstrap candidate is:

```text
file=/home/microstar/.local/var/pmbootstrap/chroot_native/home/pmos/rootfs/xiaomi-lmi.img
size=1760559104
sha256=320FC99EDA26C71B2D560675D54DE7343768271AC82521A7ADF84CA7A8E226B6
sector_size=4096
disklabel=gpt
```

Its GPT validation reported no problems. It contains:

```text
pmOS_boot  ext2  UUID=2c2600b1-700f-4bdd-a22c-bb12cc589baa
pmOS_root  ext4  UUID=8646c5cd-6298-46b4-8465-47c4a0fbb370
```

These UUIDs match the v5 boot cmdline. Read-only `e2fsck` passed for
`pmOS_boot`. Ubuntu's e2fsck 1.46.5 cannot validate `pmOS_root` because it does
not support `FEATURE_C12`. The final check was repeated with e2fsck 1.47.4 and
passed all five read-only verification stages.

## Decision Gate

The hardware evidence matches repair-plan Case C. Do not rewrite userdata yet.
First complete the `pmOS_root` check with e2fsck 1.47.4, produce a sanitized v5
report, reconfirm rollback inputs, and then request separate explicit approval
for the exact destructive userdata command.
