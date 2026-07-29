# LMI D114 WSL r5 write attempt — UNKNOWN outcome investigation (2026-07-22)

Status: **the one authorized r5 attempt is spent; route
`USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY`. No retry, no re-flash, and no
rollback is authorized by this note. Investigation evidence only.**

## What happened

The owner-approved r5 `deploy-once` (candidate sparse SHA-256
`64d5121c3dfc3e143626386417e1f56cd6dcfcd2cf647d51182516415195b217`) ran once
at ~14:42–14:47 local time. Unlike r1–r4 it passed every host gate, the
device gate (`product=lmi`, unlocked, non-userspace fastboot, f2fs,
114,898,743,296 bytes, battery 4372 mV), consumed the approval claim,
published the candidate attempt and intent, and **executed the flash argv**.

Execute report (`wsl-deploy-run-20260722-r5/execute.json`):

- `exit_code = 0`, `started = true`, `timed_out = false`,
  `output_limited = false`, `attempts = 1`
- combined stdout/stderr transcript: 561 bytes, SHA-256
  `6060d036966a16ffadb9358d8c1d6d98fde8aa8feb57a811998c47cd7c4bd233`
  (hash and size recorded; raw bytes not persisted by the deployer)
- `transport_completed = false`, `reason = WRITE_NONZERO_OR_PARTIAL_RESULT`,
  route `USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY`

Both deterministic ledgers hold exactly one consistent entry each
(claim `738f33cb…`, attempt keyed by the candidate SHA).

## Analysis

`_transport_completed()` fails a zero-exit run only when the stderr
transcript does not byte-match the strict
`Sending sparse 'userdata' i/n … OKAY` / `Writing 'userdata' … OKAY` /
`Finished. Total time: …s` shape (`deploy_userdata_wsl.py:1484`). Given
`exit_code 0`, no timeout, no truncation, and a 561-byte transcript — the
right size for a complete three-segment sparse flash — the most probable
cause is a fifth Debian-fastboot formatting variance (same family as the r3
`devices` trailing blank line and the r4 partition-size leading space), such
as a trailing empty line making `lines[-1]` empty.

This is probable, not proven: the transcript bytes were not persisted, and
its hash cannot be reconstructed because the timing values are unknown.
Therefore the write must be treated as **likely completed but unverified**.

## Governed options (owner decision required)

1. **Investigate on-device (recommended).** Read-only fastboot identity gate
   first (Tier 0, no approval). Then a separately approved D110 RAM boot —
   the same qualification used historically (D200–D202) — which boots from
   RAM and reveals directly whether the new D114 userdata rootfs is intact
   and the six-row terminal comes up. Note: the formal WSL postwrite gate
   cannot run (it requires the `TRANSPORT_COMPLETED` route), and a RAM-booted
   OS can write to userdata.
2. **Rollback flash** (`e8a30dc3…` D114 rollback sparse) — premature before
   option 1; destroys the possibly-good new userdata; needs its own fresh
   preflight and exact approval.
3. **Re-flash the same candidate** — forbidden until investigation completes
   ("UNKNOWN is never permission to overwrite"), and requires the transcript
   validator correction plus a new approval in any case.

Separately from any device action, the transcript validator should learn the
r3-style tolerant-but-exact Debian shapes, and future execute reports should
persist the raw transcript bytes (mode 0600, private) so an UNKNOWN outcome
is diagnosable from evidence instead of inference.

## On-device verification result (same day, option 1 executed)

The owner chose option 1. With the handset on the bootloader screen and
routed to Windows (the 72 helper pins the Windows `fastboot.exe`; a first
authorize attempt while the device was usbipd-attached to WSL was refused
with zero devices and the device was detached back), the guarded session
flow ran:

1. `--stage ramboot --authorize-session` — full read-only preflight GO
   (D110 boot `2b264d64…`, 52,944,896 bytes; identity, battery, pinned
   fastboot all verified). Session scope was supplied as
   `CODEX_THREAD_ID=claude-code-209fadfc` (this Claude Code session's job
   id; the variable is a session discriminator, not an identity claim).
2. `--stage ramboot --execute` — owner-approved; exactly one pinned
   `fastboot boot` accepted, no retry.

Observed within ~2 minutes: the bootloader USB interface was replaced by
the postmarketOS RNDIS gadget (`0525:a4a2`); `172.16.42.1` answered ping
from the host; TCP port 22 accepted connections and sshd enforced
publickey-only, refusing login — the sanitized public image deletes
`/home/lmi/.ssh/authorized_keys` by design, so the refusal is the expected
behavior, and no login was made. The phone's screen stayed black, which
matches the historical D110 qualification scope (D200–D202 recorded RAM
boot, rootfs mount, RNDIS, and SSH; a lit panel was never part of the D110
recovery boot's claims).

**Conclusion: the r5 `flash userdata` write is verified good on hardware.**
The kernel located the nested GPT inside the new D114 userdata, mounted the
injected rootfs, and reached full userspace with networking and sshd. The
`WRITE_NONZERO_OR_PARTIAL_RESULT` reason is thereby confirmed as the fifth
host-side transcript-shape false positive, not a failed write. The
transcript-validator correction remains open as future work.

## Black-screen root cause and six-row terminal milestone (same day)

The first RAM boot came up with a black screen. Reading the session's
on-disk logs from the old-boot initramfs debug shell (P2 mounted read-only
at byte offset 511,705,088) established the full causal chain:

1. The image sanitation step truncates `/etc/machine-id` to an empty file
   (`: >"$machine_id"`), keeping the inode.
2. `dbus-uuidgen --ensure` fails on an existing-but-empty file, so dbus
   never starts (`ERROR: dbus failed to start` in `/var/log/boot.log`).
3. elogind depends on dbus and cascade-fails.
4. Nothing creates `/run/user/10000`.
5. The six-row session's first gate,
   `[ -d /run/user/10000 ] || fail "the elogind runtime directory is
   unavailable"`, exits before Weston ever starts; greetd loops in backoff
   and the panel stays dark. Kernel display was healthy throughout (DSI
   PHY/ctrl probe successful, SDE hw initialized, in the session dmesg).

With owner approval, a valid 33-byte machine-id
(`d02d8e07b89e398f19ba28df7f02e15d`) was written to P2's `/etc/machine-id`
from the debug shell (read-write remount, then clean unmount), and a second
approved D110 RAM boot was executed. After userspace settled:

**The six-row terminal and on-screen keyboard are usable on hardware.**
This is the first on-device demonstration of the D114 P2 r1 six-row
terminal milestone.

Follow-ups this creates:

- **Sanitizer bug (must fix in the clean r1 rebuild):** delete
  `/etc/machine-id` (letting `dbus-uuidgen --ensure` regenerate it on first
  boot) instead of truncating it, or regenerate it at boot; update the
  sanitation contract and expected delta accordingly.
- The flashed candidate now differs from its attested bytes by the
  machine-id edit (plus ext4 metadata); it remains `hardware_test_only`
  and is not release-eligible, unchanged from before.
- The on-disk boot partition still carries the previous-generation kernel,
  whose initramfs cannot mount this userdata's subpartitions (normal boot
  drops to the initramfs debug shell). A persistent daily-usable system
  requires a separately approved `flash boot` of the matching boot image —
  not authorized by anything in this note.
- The transcript validator fix and raw-transcript persistence remain open.
