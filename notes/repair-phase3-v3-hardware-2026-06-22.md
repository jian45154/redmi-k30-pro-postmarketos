# Repair Phase 3: V3 Hardware Diagnostic

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Scope

Temporary RAM boot and read-only HTTP report capture. No partition was flashed,
erased, formatted, repartitioned or written.

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v3.img
sha256=5B2938B3D9775E84300DFFD2AAC65D697397240967CD91A036D101648926C982
```

Fastboot preflight confirmed `product=lmi`, an unlocked bootloader,
`is-userspace=no` and 4155 mV battery voltage. Fastboot accepted and RAM-booted
the image. USB networking was stable with 3/3 successful pings and approximately
4.16 ms average round-trip time.

Two reports were byte-identical:

```text
size=31631
sha256=F5B3B231FDD2D4C9667EDCFFC22D9C43A5F432C53151A2BF6AD4EDA6C963E680
```

Sanitized report:

```text
logs/repair-http-debug-v3-2026-06-22.redacted.txt
sha256=82DC2B13252BA20E9358B1DAD0AF6061E2F37E5C1C6C1F8B782D989CF379D794
```

## Findings

- Sysfs identifies `/sys/class/block/sda34` with `PARTNAME=userdata`.
- The diagnostic still reported an empty `userdata` variable and did not run
  its sector-size or loop-device probes.
- This was caused by a diagnostic script control-flow error: the sysfs fallback
  was nested inside the branch that required `userdata` to already be non-empty.
- The v3 result therefore confirms the userdata block identity but says nothing
  yet about nested GPT validity or rootfs integrity.

## Corrected Diagnostic

V4 moves the sysfs fallback before the read-only probes and reports the selected
block name, major/minor number and temporary `/dev` node.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v4.img
sha256=71AF25FA68BB2289F9A6E1AB84CF0FFA2F5BDE697172437C747D467770624F5D
artifact_size=53067776
diagnostic_ramdisk_sha256=28E103F4C9B1532DF692BAAD5FCC8BE0AD15A1E427545D03EF7C01CDCE5E1BD2
reproducible=yes
```

V4 has not been booted. It requires a new explicit RAM-boot approval.
