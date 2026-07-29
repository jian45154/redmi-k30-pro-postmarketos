# LMI mainline automation loop - 2026-06-24

This document describes the host-side automation added for the current
`xiaomi-lmi` mainline/copydown route. It is not an approval to execute any
hardware write.

## Tools

- `scripts/68_mainline_progress_loop.sh`
  - reusable loop for local resource audit, static CI, optional rebuild, and
    release-bundle hash verification;
  - default mode is read-only and runs once;
  - `--build` regenerates the r6 overlay/packages/image/copydown bundle;
  - `--iterations N --interval SECONDS` turns it into a polling loop.
- `scripts/69_audit_lmi_resources.sh`
  - separate resource audit for local package resources, docs, bundle files,
    hashes, and expected metadata;
  - `--network` adds remote ref checks for the external package, kernel,
    firmware, pmaports, and pmbootstrap repositories.

## Typical commands

Read-only current-state loop:

```sh
scripts/68_mainline_progress_loop.sh --once
```

Read-only loop including remote resource comparison:

```sh
scripts/68_mainline_progress_loop.sh --once --network-resources
```

Regenerate the r6 host-side bundle, then audit:

```sh
scripts/68_mainline_progress_loop.sh --once --build
```

Long polling loop for host-side state:

```sh
scripts/68_mainline_progress_loop.sh --iterations 12 --interval 300
```

## Safety boundary

The loop and resource audit do not execute reboot, boot, flash, erase, format,
sideload, or partition writes. Any future device action must use the v4
governance flow in `scripts/bringup_loop.py`; a persistent profile must first
be entered with the owner-only `authorize-profile` command, and every state
change still consumes a fresh one-shot claim.

Do not touch `super`, `dtbo`, `vbmeta`, `persist`, modem/EFS/calibration
partitions, `vendor_boot`, `init_boot`, or bootloader lock state as part of
this route.

## Current expected blocker

If `/tmp/lmi-release-r6-bootmem-20260624` is missing, the loop reports
`bundle_status=MISSING`. Restore or rebuild the bundle before relying on its
host-side hash verification. The retired M-r6/M-r7 fastbootd helper chain is
not part of this loop.
