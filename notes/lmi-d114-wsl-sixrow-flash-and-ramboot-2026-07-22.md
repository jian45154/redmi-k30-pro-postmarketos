# LMI D114 sixrow userdata flash + D110 RAM-boot verification — 2026-07-22

Status: **sixrow userdata write completed and verified booting to networked
userspace; on-panel display session fails to start (RNDIS/SSH-only). No boot
partition was flashed; the RAM boot is temporary.**

This log records a full run: flashing the latest sixrow userdata through the
fully-gated deployer (no gates bypassed), the host-side `UNKNOWN` confirmation
outcome, the D110 RAM-boot that proved the write actually succeeded, and the
subsequent black-screen investigation.

## 1. Gated userdata flash (r5)

Ran the reviewed-GO one-shot deployer with every gate active:

- deployer `scripts/lmi_p2_d114/deploy_userdata_wsl.py`
  SHA-256 `92bea6669cc07782bd5aff5ee948f31bada655b61bd5fcaa92c92cc21a69d913` (verified)
- profile SHA-256 `31a9674e0fa07999d226d7805364b2b2fc556c243bf9224a80b095a968542219`, mode `0600` (verified)
- run directory `wsl-deploy-run-20260722-r5` (was empty, mode `0700`)
- approved operation `flash-userdata`, approved sparse SHA-256
  `64d5121c3dfc3e143626386417e1f56cd6dcfcd2cf647d51182516415195b217`

All identity/integrity gates passed on the correct device:
`product=lmi`, `unlocked=yes`, `identity_match=true`, `battery_mv=4372`,
`partition_type=f2fs`, `partition_size=114898743296`. One fastboot device
(serial `8336ded7`) was USB-attached to WSL.

Result: **`route_status=USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY`** (deploy exit 3),
report SHA-256 `e60246647bd5b1c89cafe09d9b5cebe04e41ea332f50cce732ad03fe6f0618a9`.

The write itself very likely succeeded: `result.exit_code=0` (fastboot reported
success), `output_size=561` (a full multi-segment success transcript),
`timed_out=false`, `started=true`. It was `_transport_completed()` (the strict
host-side output parser, ~line 1484) that refused to confirm it. This is the
same class of host-side false-negative as today's r1–r4 refusals, but occurring
after the transfer rather than before. The raw 561-byte output is not persisted
(only hashed, to avoid leaking the serial), so it cannot be re-inspected.

The attempt is recorded in both deterministic ledgers (candidate-attempt
`e17a23b2…`, consumed-claim `8c394431…`) → **spent, no automatic retry**.

## 2. RAM-boot verification of the write

Chosen path: temporary RAM boot to confirm the write without a second flash.

- boot image `pmos-lmi-normalboot-v110-bpf-fs-context-enoparam-r15-20260713.img`
  SHA-256 `2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487` (verified;
  it is the profile's declared `compatibility.d110_boot`, size 52944896)
- command: `fastboot boot <img>` → `Sending 'boot.img' OKAY / Booting OKAY / Finished`, exit 0

Post-boot observations (read-only, from WSL):

- device left bootloader (`fastboot devices` empty); did not fall back to fastboot
- WSL `eth1` obtained `172.16.42.2/24` from the phone's `unudhcpd`
- phone `172.16.42.1` pings stably (~0.6–0.9 ms)
- **sshd open on :22** (Ed25519, pubkey-only; correctly rejects password + unauthorized keys)
- early-boot telnet :23 closed → past initramfs into full rootfs

Conclusion: the sixrow userdata write **succeeded**. The `UNKNOWN` was a host
confirmation-parser false negative, not a bad write.

## 3. Black-screen investigation (display session fails)

User reported the panel is black; pressing power does not wake it. The system is
demonstrably **alive** (ping + sshd + RNDIS all up; not back in bootloader), so
this is a display/session bringup failure — the "RNDIS-only" pattern from prior
notes — not a crash or brick.

No live shell was possible: the running image authorizes SSH pubkey
`ssh-ed25519 …AAAAIOIiHcbg/7ytfLFHUNLRgEAubFz/13SwXBOM/05GNZe4` for user `lmi`,
which is **not** the only private key available in the repo
(`private/lmi-p1/owner-test-ed25519`, pubkey `…AAAAIM+FQ1+n9/vEDTDtiF2TOi3em50mfr9Ftm+FuifUlvk+`).
So `weston`/`greetd`/`dmesg` runtime logs could not be collected.

### Root-cause hypothesis (from local rootfs inspection, read-only via debugfs)

Rootfs: `private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/lmi-d114-rootfs-p2-r1-sixrow-injected-20260722.bundle/rootfs.ext4`

- Default runlevel (`/etc/runlevels/default`) enables: `greetd`,
  `lmi-cnss-daemon`, `lmi-power-panel`, `lmi-qrtr-ns`, `lmi-seatd`,
  `lmi-splash-release`, `networkmanager`, `sshd`.
- **`lmi-weston` is NOT in the default runlevel.** The persistent Weston DRM
  panel session (`/etc/init.d/lmi-weston` → `/usr/sbin/lmi-weston-wrapper`,
  4813 bytes, present in the image) is not enabled at boot.
- **`/etc/greetd/config.toml` is empty (0 bytes)** — greetd is enabled but has
  no `[default_session]` to launch.
- `weston.ini` (`/etc/xdg/weston/weston.ini`) targets output `DSI-1`
  `mode=preferred scale=2`, `Virtual-1 mode=off`.

With `lmi-weston` disabled and greetd unconfigured, nothing launches a Weston
session to drive the DSI panel, while `sshd`/`networkmanager`/`lmi-seatd` come
up normally. This matches the observed symptom exactly (network + SSH up, panel
dark). The injection attestation marks this build `hardware_test_only=true`,
`production=false`, `release_eligible=false`, so a failed display bringup is a
legitimate qualification-test result, not a release regression.

## 4. Recovery and next steps (not performed)

Recovery (safe now — nothing persistent was flashed):

- hold **Power ~10–15 s** to force reboot; the userdata write persists.
- to return to a controllable state, enter fastboot with **Vol Down + Power**.

To diagnose/fix the display, either is needed and neither was available in this
session:

1. the authorized `lmi`-user private key (matching pubkey `…OIiHcbg…`) to SSH in
   and check `rc-service lmi-weston status`, `/run/lmi-weston.log`, `dmesg`; a
   live confirmation/fix would be
   `rc-update add lmi-weston default && rc-service lmi-weston start`; or
2. an on-screen observation from the physical panel.

Build-side fix (requires rebuild + a new gated deploy): enable `lmi-weston` in
the default runlevel and/or populate `/etc/greetd/config.toml` with a
`default_session` that launches the Weston + sixrow client session, in the
injection/config-lifecycle step.

## Boundary

No boot/vbmeta/super/other partition was flashed. Only `flash userdata` (r5,
attempt spent) and one temporary `fastboot boot` (RAM) were issued. The
deployer's safety gates were not bypassed at any point.
