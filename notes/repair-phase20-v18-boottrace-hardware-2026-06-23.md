# Repair Phase 20: v18 Boottrace Hardware Result

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-boottrace-v18-20260623.img
sha256=4be1a6109262e9577f51e2414a7a54fa1cd0b5510d104ad650354cc04e627ea0
mode=fastboot boot (RAM-only, no partition writes)
```

## Preflight

```text
product=lmi
unlocked=yes
is-userspace=no
battery-voltage=4387 mV
```

Bootloader accepted the image:

```text
Sending 'boot.img' (51820 KB) OKAY
Booting OKAY
```

## Hardware observation

After booting v18, the host did not observe the postmarketOS USB gadget:

```text
8s:  no 18d1:d001 USB gadget, no WSL USB NIC
20s: no ADB, no fastboot, no USB gadget
45s: no ADB, no fastboot, no USB gadget
75s: no ADB, no fastboot, no USB gadget
```

No partition was written. No HTTP report could be fetched because USB networking
never appeared.

## Local comparison against v17

The boot image format is not the likely cause:

```text
v17 kernel_sha256 = 21f7ba4ecc433c403d1071860dc1d677263427b7ff44042a0bc54a7ea7f77ac4
v18 kernel_sha256 = 21f7ba4ecc433c403d1071860dc1d677263427b7ff44042a0bc54a7ea7f77ac4
v17 dtb_sha256    = 212d80826ceef522aff2d967082b5708d20ddccc13ae322edce72412f1a06b51
v18 dtb_sha256    = 212d80826ceef522aff2d967082b5708d20ddccc13ae322edce72412f1a06b51
v17 cmdline       = normal, no pmos.debug-shell
v18 cmdline       = same as v17
v17 ramdisk size  = 8948068
v18 ramdisk size  = 8949499
```

The only meaningful difference is the v18 boottrace ramdisk. Since v17 reached
USB networking and v18 did not, this v18 design should be treated as too
intrusive for the normal boot path.

## Interpretation

v18 did not reproduce the v17 observable state. It is not useful evidence about
the rootfs/switch_root blocker except that early normal-path boot tracing can
change the failure mode.

## Next safer diagnostic

Use a less intrusive image:

- start from the known-good v16/v17 debug HTTP approach that reaches USB;
- keep `pmos.debug-shell` so boot intentionally holds in initramfs;
- keep both fixes: kernel `fc->source` and initramfs `fdisk -b 4096`;
- add a single explicit `pmos_continue_boot`-style HTTP action or timed
  snapshot only after the debug server is already reachable;
- avoid launching periodic background collectors before USB is proven stable.

