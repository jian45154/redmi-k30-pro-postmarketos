# D115: persistent boot flash — 2026-08-15

Status: **owner-authorized persistent partition write, executed and
hardware-verified.** One `fastboot flash boot` plus one `fastboot reboot`
over the locked Windows platform-tools r37 transport
(`fastboot-windows-provenance-lock.json` re-verified the same day: all
three member hashes exact; device present in fastboot).

## What was written

| Partition | Image | sha256 | Provenance |
| --- | --- | --- | --- |
| `boot` | `pmos-lmi-normalboot-v110-bpf-fs-context-enoparam-r15-20260713.img` | `2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487` | `source-lock.json baseline.boot_sha256`; the exact image RAM-boot-validated on 2026-07-24 (six-row bring-up) and used for every governed RAM-boot since |

Previous boot-partition content (v46 boot, `2a455dc6…` ==
`pmos-lmi-v46-…-full-20260624.manifest` `artifact_boot_sha256`) was staged
alongside as the reviewed rollback image before flashing; hashes of both
staged copies were re-verified after the copy. userdata was **not**
touched: it retains the 2026-07-24-flashed r10 userdata (with the D111/D112
on-device provisioning).

## Why this closes the 2026-07-29 pairing mismatch

`notes/d114-boot-pairing-mismatch-2026-07-29.md`: the flashed v46 boot
searched for root UUID `df32eed6…`, which does not exist on the D114
userdata layout, so persistent boot stopped in stage-2 initramfs. The
image written today pairs correctly (`pmos_boot_uuid=d4f78f7d…`,
`pmos_root_uuid=f8eb7c4b…`) and, unlike the v46 initramfs, demonstrably
mounts the userdata subpartitions (every RAM-boot session since 2026-07-24
proves it).

## Verification

- Host-side probe from reboot: RNDIS enumerated; **port 23 (initramfs
  debug shell — the old failure signature) never opened**; port 22 (full-OS
  sshd) opened ~60 s after reboot and stayed up.
- Owner confirmed the six-row Weston terminal rendered on screen.
- Key-only SSH over USB (172.16.42.1) succeeded as `lmi` (the D111-repaired
  authorized key); kernel `4.19.325-cip128-st12-perf`, uptime advancing
  across checks. Wi-Fi autoconnected (same host key visible on the WLAN
  address — the D112 `lmi-owner.nmconnection` provisioning survived, as
  expected for a boot-only flash).
- The device sshd host key differs from the r1-era entry in the private
  `p2-d114-known_hosts` (r2 userdata generated fresh host keys at its first
  boot); the private known_hosts was updated after confirming USB and WLAN
  present the identical key (old entry preserved in `*.pre-20260815`).

**The device now boots postmarketOS with the six-row terminal from power-on,
untethered — no RAM-boot assistance.** The RAM-boot-per-test era ends here.

Residual (unchanged by this flash): the six-row keyboard in this userdata
is the r2-payload generation; the r4 modern-layout upgrade is a separate
on-device `apk add` (owner sudo) staged the same evening.
