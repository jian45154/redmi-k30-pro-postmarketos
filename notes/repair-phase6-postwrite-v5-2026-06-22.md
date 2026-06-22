# Repair Phase 6: Post-Write V5 Verification

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Scope

Separately approved v5 RAM boot and read-only HTTP report capture after the
userdata write. No partition was written in this phase.

## Artifact And Reports

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v5.img
sha256=F39858195B7030B33AD07B5D5E245931AD7593AC5B4364DD699441356DEBDAD0
report_size=33108
report_sha256=2A9B7F558646BCAA3BB69C55235728D434DFCAC365EAC62C0231D3D489465B28
reports_identical=yes
```

The raw reports remain local. The command runner reached its execution limit
before a sanitized copy could be generated.

## Findings

- Sysfs resolves userdata as `/dev/sda34`.
- The logical sector size is 4096 bytes.
- The 512-byte interpretation exposes only the protective MBR.
- The 4096-byte interpretation reports a valid GPT with disk GUID
  `957cad5b-830c-4257-ab28-c65534debcf5`.
- GPT partition 1 is 480 MiB and partition 2 is 1190 MiB, matching the validated
  candidate.
- This proves the userdata write corrected the missing nested GPT and that the
  configured 4096-byte sector size is required.

V5 did not create `/dev/loop0p1` and `/dev/loop0p2`, so its blkid and read-only
mount loop did not run. A telnet attempt connected, but host-side quoting broke
the remote variable expansion before any mount occurred.

## V6 Diagnostic

V6 creates loop partition nodes from `/sys/class/block/loop0p*/dev` in temporary
RAM `/dev`, then performs blkid and mounts `pmOS_root` with `ro,noload`.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v6.img
sha256=544E15067029E230FFF3CB55C62337D88BAB32709ADDD249819497234B4FB897
artifact_size=53067776
diagnostic_ramdisk_sha256=6A97A862683F1526E6A5273710875D45C49062195577047A2ECFAF083E6E8EC9
reproducible=yes
syntax=ok
```

V6 has not been booted and requires separate explicit RAM-boot approval.
