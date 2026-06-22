# Repair Phase 3: V2 Hardware Diagnostic

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Scope

Temporary RAM boot and read-only HTTP report capture. No partition was flashed,
erased, formatted, repartitioned or written.

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260621-v2.img
sha256=55DF054C651DE74DAB8EE3A62C93626F99C45ECAC41BBC1A46BB0E94661C6834
```

Fastboot accepted and booted the image. USB CDC-NCM networking was stable:

```text
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max/mdev = 2.994/4.700/6.947/1.658 ms
```

Two reports captured 10 seconds apart were byte-identical:

```text
size=26189
sha256=598D2A02124BCD32B3D071A9BC61F83ED01AEF7ACB0D79D08B1BBF6119379C27
```

Sanitized report:

```text
logs/repair-http-debug-v2-2026-06-22.redacted.txt
sha256=6A55E3D240606BEF88F0E45B805232478E7BD531B6FCF65C04A125423616F168
```

## Findings

- Kernel, initramfs and USB networking start successfully.
- UFS enumerates as `sda` through `sdf`.
- `sda34` is approximately 107 GiB and is the leading `userdata` candidate.
- `/dev/block/by-name` and `/dev/disk/by-partlabel` do not exist.
- A bare `blkid` produced no entries.
- The v2 diagnostic therefore left `userdata` empty and did not reach its
  512/4096 loop probes.
- The failure occurs before rootfs sector-size comparison, mount or
  `switch_root`; it is not yet evidence that the flashed rootfs is corrupt.

The report also shows early-userland gaps unrelated to rootfs discovery:

- USB ACM creation failed because the expected configfs function path was not
  available.
- `uinput` is absent, so buffyboard cannot provide local debug input.
- debugfs and tty0 are unavailable in this initramfs session.

These do not block CDC-NCM or the HTTP report.

## Next Diagnostic

V3 adds a read-only fallback that scans `/sys/class/block/*/uevent` for
`PARTNAME=userdata`, creates a missing block node only in temporary `/dev`, and
then runs the existing 512/4096 read-only loop probes.

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v3.img
sha256=5B2938B3D9775E84300DFFD2AAC65D697397240967CD91A036D101648926C982
```

V3 requires a new explicit RAM-boot approval.
