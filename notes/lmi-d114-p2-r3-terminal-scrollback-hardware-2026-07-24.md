# D114 P2 r3 terminal scrollback hardware result — 2026-07-24

## Scope

This note records the single authorized `userdata` attempt and the subsequent
separately authorized D110 RAM-only boot used to investigate it. It does not
promote the image to release status and does not disclose the device serial.

## Exact persistent attempt

- profile SHA-256:
  `319cb4375c98ed964ecf25c0740cde02fa7321415ace8b4e8a22528861cf5f73`
- candidate sparse SHA-256:
  `a88a7335f6e0d3fcaeeaf1b987c380b0d81e68a8886034acc3d0a12033792081`
- distinct rollback sparse SHA-256:
  `1315e3a06ddff42e91f930f01b16a62ab30ab3d4f490e8e8e40d0af89c657279`
- target: unsuffixed physical `userdata` only
- attempts: exactly one; no retry

The live read-only D114 preflight passed before the attempt. It observed an
identity-matched `lmi`, an unlocked bootloader, bootloader fastboot rather
than fastbootd, a physical `userdata` mapping, sufficient capacity, and
adequate battery.

The guarded fastboot process started and exited `0`, with no timeout or output
limit. Its strict transcript parser did not accept the captured 560 output
bytes, so the durable result remains:

- route: `USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY`
- reason: `WRITE_NONZERO_OR_PARTIAL_RESULT`
- execute-report SHA-256:
  `1a33096fe406255b692ba2b1d7d023b22557652fc7655b928086b7137543ff3e`

Only the transcript hash and length were retained, not the raw streams.
Therefore a formatting false negative and a partial transport cannot be
distinguished. The one-use claim and candidate-attempt ledgers are consumed.
No reflash or rollback was attempted. The formal postwrite validator was not
run because it correctly refuses an outcome-unknown execute report.

## Separate RAM-only observation

The D110 gate passed a fresh read-only preflight. After a separate,
current-thread approval, it attempted exactly one pinned `fastboot boot`:

- D110 boot SHA-256:
  `2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487`
- gate result: `single-pinned-fastboot-boot-command-accepted`
- automatic retry: none

The D110 helper ran from the main checkout, whose private ledger records the
post-write sequence:

- D114 execute-report time: epoch `1784875533`
  (`2026-07-24T16:45:33+10:00`)
- consumed D110 attempt-receipt time: epoch `1784875763`
  (`2026-07-24T16:49:23+10:00`)
- consumed receipt SHA-256:
  `b97dce8da1b1ea900a9316b4ed80758502d4b18c480a0ca6eee74f4265bfe752`,
  size `1039`
- revoked session-grant SHA-256:
  `f897ed5bac332a14665822580c8bb36c885ae064433e4a824a238d0af0a1a13b`,
  size `966`

The current-thread grant is under the private revoked ledger and no longer
under its active ledger. Windows then observed the phone leave fastboot and
enumerate as the expected `0525:a4a2` USB network gadget. This proves entry
into the RAM-booted runtime, not byte-for-byte identity of the persistent
partition.

## Direct hardware behavior

The owner first reported a black panel while the runtime was coming up. The
Terminal subsequently appeared. The owner then directly observed that finger
swipes scroll the terminal and reported: `可以滑动`.

This is positive real-device behavioral evidence for the r3 touch-scrollback
fix. It also shows that the on-device rootfs reached the graphical terminal
session after the outcome-unknown write. It does not retroactively change the
transport result to completed and is not a byte-for-byte partition
verification.

## Remaining limits

- The USB gadget enumerated, but two sets of three host pings to
  `172.16.42.1`, including one after the Terminal appeared, returned
  `Destination Host Unreachable`; USB networking is not verified in this
  session.
- Wi-Fi was not re-verified in this session.
- The distinct rollback artifact remains host-verified but unexercised on
  hardware.
- Release readiness and whole-system stability are not claimed.
