# D114 persistent-boot pairing mismatch — 2026-07-29

Status: **live governed observation; one volatile-tier `fastboot reboot` was
claimed and executed (experiment `d114-p2-r1-reboot-wifi-probe-20260729`).
All other device access was read-only over the initramfs debug shell
(telnet, port 23). No partition write, no runtime handoff, no config change
on the device.**

## What happened

After a governed `fastboot reboot`, the device enumerated USB RNDIS
(`172.16.42.1` reachable) but SSH port 22 stayed refused for >3 minutes while
port 23 (postmarketOS initramfs debug shell) was open: persistent on-disk
boot stops in stage-2 initramfs.

## Evidence captured over the debug shell (read-only)

- Kernel: `4.19.325-cip128-st12-perf #9-postmarketOS` (built 2026-06-24);
  initramfs `3.12.0-r0`.
- `/pmOS_init.log`: `Trying to mount subpartitions for 10 seconds...` six
  attempts of `Mount subpartitions of /dev/sda34`, then
  `ERROR: failed to mount subpartitions!`.
- `which kpartx` → `kpartx: not found` in the initramfs; only `losetup`
  exists. Subpartition mapping can never succeed with this initramfs.
- Kernel cmdline expects `pmos_boot_uuid=c9e06598-…` and
  `pmos_root_uuid=df32eed6-…` — exactly the UUID pair recorded in
  `artifacts/images/pmos-lmi-v46-daemon-status-idempotent-full-20260624.manifest`:
  the flashed boot partition is the **v46 boot image**.
- `blkid`: no filesystem with UUID `df32eed6…` exists on the device.
  `/dev/sda34` (userdata) carries an inner GPT with disk GUID
  `45721c80-e267-4963-bb34-42ada8fad697` — the **D114 assembled-userdata
  baseline** layout, whose pmOS root subpartition (`p2`) has UUID
  `f8eb7c4b…` and pairs with the **D110-compat boot** (`d4f78f7d…`), per the
  assembly attestations.
- Initramfs display: `cannot open framebuffer device` + repeated lvgl
  `No draw buffer` — the frozen splash is an initramfs-UI limitation, not a
  regression of the six-row terminal (which runs in the full OS).

## Conclusion

Persistent boot fails for two independent reasons:

1. **Wrong pairing**: v46 boot image over D114-family userdata — the root
   UUID it searches for does not exist in this layout.
2. **Missing tool**: even a subpartition-aware flow would fail because the
   initramfs contains no `kpartx`.

The 2026-07-23 six-row bring-up is consistent with the guarded RAM-boot path
(D110 recovery boot over this userdata), not with persistent boot.

## Next steps

- Runtime validation today (standing `ram_rw` scope): governed
  `fastboot boot` of
  `private/lmi-p1/recovery/d110-d114/pmos-lmi-normalboot-v110-bpf-fs-context-enoparam-r15-20260713.img`
  over the existing userdata, then the Task-2 wifi runtime checks over SSH.
- Durable fix (persistent tier, hash-bound owner authorization required):
  flash a boot image that (a) pairs with the assembled-userdata layout and
  (b) ships `kpartx` in the initramfs — fold the kpartx dependency into the
  r145 clean rebuild tracked by
  `docs/release/v1-firmware-free-release-plan-2026-07-29.md`.
