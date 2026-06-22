# Repair Phase 2: HTTP Diagnostic Build

Operator: Lucien Auregin (ian)
Date: 2026-06-21 Australia/Sydney

## Result

A corrected RAM-only postmarketOS diagnostic image was built from the current
WSL boot artifact. No phone was accessed and no device partition was written.

```text
artifact=artifacts/images/pmos-lmi-http-diagnostic-20260621-v2.img
artifact_size=53063680
artifact_sha256=55DF054C651DE74DAB8EE3A62C93626F99C45ECAC41BBC1A46BB0E94661C6834
diagnostic_ramdisk_sha256=012416BCA1E69A1EFCF00130AAAF5F05ABA26D6C4C767FF356161D3C9378D1D3
```

The normalized build was run twice and produced the same ramdisk and boot-image
SHA-256 values.

## Frozen Inputs

```text
source_boot_sha256=57B07144EBB8CC69E0C334AC8BE3BE9A1543DF80262B006DB167FAEE00B80664
kernel_sha256=D4365A1D0B6B6804C4AF80BA46ACE7040B066383BDE865687CFC09BC8091B9E3
dtb_sha256=212D80826CEEF522AFF2D967082B5708D20DDCCC13AE322EDCE72412F1A06B51
source_ramdisk_sha256=9263D2FD82BF73B11900454AC5B849A5EE8D40D4310E2FAB5E1F73688509D760
```

## Boot Image Inspection

```text
header_version=2
page_size=4096
kernel_size=43231256
ramdisk_size=8949545
dtb_size=874418
total_size=54075392
boot_partition_limit=134217728
```

The cmdline contains `pmos.debug-shell` and the current WSL image UUIDs:

```text
pmos_boot_uuid=2c2600b1-700f-4bdd-a22c-bb12cc589baa
pmos_root_uuid=8646c5cd-6298-46b4-8465-47c4a0fbb370
```

## Diagnostic Behavior

- Serves a static report at `http://172.16.42.1:8080/debug.txt`.
- Does not expose a remote continue-boot or write action.
- Identifies `userdata` by partition label or Android by-name path.
- Reports 512-byte and 4096-byte `fdisk` interpretations.
- Creates loop devices with `--read-only` for both sector sizes.
- Mounts a discovered `pmOS_root` only as `ro,noload`.
- Reports labels, UUIDs, `/etc/os-release`, `/sbin/init`, mounts, network and
  kernel messages.
- Leaves the existing telnet debug shell available for a later explicit
  `pmos_continue_boot` test.

## Local Audit

- Build script syntax: pass.
- Injected diagnostic fragment syntax: pass.
- Extracted initramfs syntax under a compatible parser: pass.
- Embedded 4096-sector device metadata: present.
- Native pmOS `busybox-extras` with the `httpd` applet: present.
- Extracted kernel and DTB hashes match the frozen source inputs.
- Diagnostic source scan found no flash, erase, format, mkfs, repartition,
  sideload, device-bound `dd` or read-write mount operation.

## Build Sources

```text
scripts/10_build_pmos_http_diagnostic.sh
scripts/pmos_http_diagnostic.inc
artifacts/images/pmos-lmi-http-diagnostic-20260621-v2.manifest
```

## Superseded V1 Hardware Result

The first diagnostic image used an added static arm64 BusyBox. Its RAM boot and
USB networking worked, but port 8080 refused connections, so no HTTP report was
captured. That image is superseded and must not be used for the next test:

```text
artifacts/images/pmos-lmi-http-diagnostic-20260621.img
```

V2 removes that external runtime and uses the `httpd` applet already present in
the tested postmarketOS initramfs `busybox-extras` binary.

## Next Gate

The next action is a temporary hardware boot:

```text
fastboot boot artifacts/images/pmos-lmi-http-diagnostic-20260621-v2.img
```

It writes no partition but requires explicit approval immediately before
execution. After boot, fetch the HTTP report twice and preserve a redacted host
copy before any telnet session or `pmos_continue_boot` action.
