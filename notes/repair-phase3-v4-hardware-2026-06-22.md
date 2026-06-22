# Repair Phase 3: V4 Hardware Diagnostic

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Scope

Temporary RAM boot and read-only HTTP report capture. No partition was flashed,
erased, formatted, repartitioned or written.

## Artifact And Preflight

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v4.img
sha256=71AF25FA68BB2289F9A6E1AB84CF0FFA2F5BDE697172437C747D467770624F5D
product=lmi
unlocked=yes
battery_voltage_mv=4178
is_userspace=no
```

Fastboot accepted and RAM-booted the image. USB networking returned 3/3 pings
with approximately 5.20 ms average round-trip time.

Two reports captured 10 seconds apart were byte-identical:

```text
size=32987
sha256=AC382D3199E9980E018213D0A6D91DC1312932F27D90DD5366F0F300CC0DCE26
```

Sanitized report:

```text
logs/repair-http-debug-v4-2026-06-22.redacted.txt
sha256=FDBC05AEF802CA90E6174859E71AD64383FAF87C9F2486A4160623274ED26BF6
```

## Findings

- Sysfs resolves userdata as `/dev/sda34` with device number `259:61`.
- The logical and physical block sizes are both 4096 bytes.
- BusyBox `fdisk` reported no valid partition table at either requested sector
  interpretation.
- Neither loop probe actually ran: `/dev/loop0` was absent even though the loop
  driver was available, and `losetup` explicitly reported the lost node.
- Therefore this run does not yet establish whether the nested GPT or
  `pmOS_root` is valid. The `fdisk` result alone is insufficient to classify the
  rootfs as corrupt.

## Corrected Diagnostic

V5 creates `loop-control` and `loop0` through `loop7` only in the temporary RAM
`/dev`, then performs the same read-only 512/4096 probes.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v5.img
sha256=F39858195B7030B33AD07B5D5E245931AD7593AC5B4364DD699441356DEBDAD0
artifact_size=53063680
diagnostic_ramdisk_sha256=76444B572E1049FE34FFE14649C8661A6FF5B942500F52C26304B89E4442B6C7
reproducible=yes
syntax=ok
```

V5 has not been booted and requires a new explicit RAM-boot approval.
