# LMI mainline automation loop - 2026-06-24

This document describes the host-side automation added for the current
`xiaomi-lmi` mainline/copydown route. It is not an approval to execute any
hardware write.

## Tools

- `scripts/68_mainline_progress_loop.sh`
  - reusable loop for local resource audit, static CI, optional rebuild, release
    bundle audit, and optional fastbootd read-only gate;
  - default mode is read-only and runs once;
  - `--build` regenerates the r6 overlay/packages/image/copydown bundle/docs;
  - `--fastbootd` adds the existing read-only fastbootd wait/preflight/audit;
  - `--iterations N --interval SECONDS` turns it into a polling loop.
- `scripts/69_audit_lmi_resources.sh`
  - separate resource audit for local package resources, docs, bundle files,
    hashes, and expected metadata;
  - `--network` adds remote ref checks for the external package, kernel,
    firmware, pmaports, and pmbootstrap repositories.

## Typical commands

Read-only current-state loop:

```sh
scripts/68_mainline_progress_loop.sh --once --quick
```

Read-only loop including remote resource comparison:

```sh
scripts/68_mainline_progress_loop.sh --once --quick --network-resources
```

Regenerate the r6 host-side bundle and docs, then audit:

```sh
scripts/68_mainline_progress_loop.sh --once --build --quick
```

After the phone is attached to WSL and `fastboot getvar is-userspace` reports
`yes`, run the read-only fastbootd gate:

```sh
scripts/68_mainline_progress_loop.sh --once --quick --fastbootd
```

Long polling loop for host-side state:

```sh
scripts/68_mainline_progress_loop.sh --iterations 12 --interval 300 --quick
```

## Safety boundary

The loop and resource audit do not execute reboot, boot, flash, erase, format,
sideload, or partition writes. They call the existing guarded scripts for
read-only checks. Any persistent test still requires fresh exact approval for
the specific command immediately before execution.

Do not touch `super`, `dtbo`, `vbmeta`, `persist`, modem/EFS/calibration
partitions, `vendor_boot`, `init_boot`, or bootloader lock state as part of
this route.

## Current expected blocker

If `/tmp/lmi-release-r6-bootmem-20260624` is missing, the loop will report
`bundle_status=MISSING`. Restore or rebuild the bundle before running the
fastbootd gate. If Windows sees fastbootd but WSL does not, attach the USB
device to WSL first; the loop will otherwise record the fastboot gate as not
enumerated.
