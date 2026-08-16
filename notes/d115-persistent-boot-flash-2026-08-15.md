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

## Follow-on same evening: r4 keyboard upgrade + session-package regression

The device booted with `lmi-weston-sixrow-clients=14.0.2-r3` (keyboard
binary `d6b9e514…`). The owner then `apk add`-ed the attested r4 package
(`5bf587a3…`, keyboard `8cb3865b…` == build-attestation-r4). apk **purged
`device-xiaomi-lmi-terminal-0.1.0-r3`** in the process, because every
`device-xiaomi-lmi-terminal` build carries an EXACT dependency
`lmi-weston-sixrow-clients=14.0.2-r<same>` — no r4 companion package exists.
That package provides the greetd session glue (its `.pre-deinstall` runs
`config-lifecycle remove`, which restored the stock greetd confd), so after
the upgrade **greetd crashed → black screen** while the persistent boot
itself was fine (SSH up, no initramfs stall).

Recovery (all owner-sudo over SSH; no reflash):

1. Restored the five session-glue files from the r3 terminal apk payload
   (`greetd.toml`, `weston.ini`, `config-lifecycle`, `session`,
   `greetd.confd`) and ran `config-lifecycle install` — `/etc/conf.d/greetd`
   went baseline `6523d36f…` → active `5be12504…`
   (== source-lock `greetd_active_confd_sha256`). greetd still crashed.
2. Root cause of the second crash: `/usr/libexec/lmi-p2-d114/session` pins
   the keyboard binary by exact sha256 in three places (integrity gate),
   still the r3 value `d6b9e514…`; the running r4 keyboard `8cb3865b…`
   failed the identity check, so the session exited. Patched those three
   pins to the attested r4 hash `8cb3865b…` (verified against
   build-attestation-r4), redeployed the one file (mode 755), rebooted.
3. Result: greetd `[ started ]`; `weston` + `weston-keyboard-sixrow` (exe
   `/proc` = r4 `8cb3865b…`) + `weston-terminal-sixrow` + `desktop-shell`
   all running; six-row terminal on screen with the r4 keyboard, owner
   confirmed arrow-key row present. Persistent boot again clean (port 23
   never opened).

r4 vs r3 is an ergonomic tweak, not a layout overhaul (both are the paged
11-column arrow layout introduced at r2): Shift moved to the modifier row's
leftmost slot, the bottom row always carries `/ : - .`, and digits gained
hardware shift-pairs — hence "looks like r3" at a glance.

**Release-line TODO (not a device fix):** the r4 keyboard is running on the
device via a hand-patched session script, NOT a packaged artifact. Shipping
r4 requires a rebuilt `device-xiaomi-lmi-terminal` that depends on
`lmi-weston-sixrow-clients=14.0.2-r4` and pins the r4 keyboard hash in its
`session` script — the exact-version dependency is the design that made the
upgrade remove the r3 session package. Until that package exists, r4 is a
device-local hand-patch, not a reproducible release configuration.
