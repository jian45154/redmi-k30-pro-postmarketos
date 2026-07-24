# lmi terminal touch scrollback r3 (2026-07-24)

## Outcome

The Weston six-row client package now has a host-built `14.0.2-r3` candidate
that routes a one-finger vertical terminal gesture into viewport scrollback.
The exact APK was built twice with byte-identical output and passed the
hash-locked source, payload, signature, ELF, and model checks.

This is not a device-success claim. The owner reports that the earlier D114
r2/r10 RAM boot renders the terminal and connects to Wi-Fi; that observation
establishes the usable baseline, but the r3 APK has not been put into that
image or tested with physical touch.

## Root cause

Weston 14.0.2 already implements bounded terminal scrollback for
`wl_pointer.axis`. Its terminal `wl_touch.motion` handler instead sends every
movement into text selection, so a finger gesture never reaches the viewport
scroll state. The r2 paged-touch patch changes only the separate soft-keyboard
client and cannot fix terminal scrolling.

## Change

`files/lmi-weston-sixrow/0004-terminal-touch-scrollback.patch` changes only
`clients/terminal.c`:

- extracts the existing pointer-axis viewport bounds/update logic into
  `terminal_scroll_view_lines()`, then uses it for both pointer and touch;
- tracks the first active touch ID instead of assuming ID zero and ignores
  additional contacts until the owner contact ends;
- defers tap selection until touch-up, preventing a vertical gesture from
  flashing or extending a text selection first;
- classifies a quick vertical drag as scroll, a quick horizontal drag as
  character selection, and a drag beginning after the 350 ms hold threshold as
  selection;
- accumulates logical pixels by `terminal->extents.height`, preserving
  fractional movement between events;
- uses direct-manipulation direction: drag down reveals older history and drag
  up returns toward the saved live bottom;
- resets ownership and selection-drag state on matching touch-up or compositor
  cancel.

The original `saved_start`, history-limit, row, and selection-row calculations
are retained unchanged inside the shared helper.

## Package and build proof

- Package revision: `lmi-weston-sixrow-clients-14.0.2-r3`
- APK SHA-256:
  `9310963550ac26e28b187a3a1b0a202f9e917c8103a30e0a1dbaaf182626d010`
- Compressed size: `122316`
- Installed size: `335416`
- Keyboard payload SHA-256:
  `d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a`
  (unchanged from r2)
- Terminal payload SHA-256:
  `ed3cda9c8dcdcd197385d125c84e3fdaa0429790b1b166d62f6206c4f853cf24`
- Architecture: AArch64 ELF64 PIE, musl interpreter
  `/lib/ld-musl-aarch64.so.1`
- Signature: direct `pmos@local-6a5d38f2` signature, verified with the recorded
  public key
- Reproducibility: two clean offline aarch64 builds produced the exact same APK
  SHA-256

The tracked proof is
`config/lmi-weston-sixrow/build-attestation-r3.json`; the local APK is under
the gitignored `private/lmi-p1/recovery/d110-d114/` build directory named by
that attestation.

## Host verification

- all four patches apply to the locked official Weston 14.0.2 tarball with
  `--fuzz=0`;
- both `weston-keyboard` and `weston-terminal` compile and link twice with the
  real aarch64 Alpine toolchain;
- the only compile warning is the pre-existing unused keyboard function;
- 14 six-row tests run with the official tarball: 13 pass and the disabled r2
  transient exact-artifact fixture skips;
- gesture models cover slop, vertical/horizontal arbitration, ambiguous
  diagonals, delayed first motion, fractional-line accumulation, direct
  manipulation direction, oldest-history clamp, and saved-bottom clamp;
- an independent read-only port review found no correctness-blocking C defect
  in the scrolling path.

## Known limits and integration boundary

- The hold threshold is checked on motion, not by a timer. A stationary hold
  remains pending until touch-up; the first movement after 350 ms selects even
  when it is vertical. This is a known selection-UX tradeoff, not evidence of a
  scrolling failure.
- Source/model tests cannot establish physical direction preference, gesture
  feel, or touchscreen delivery. Exact-r3 hardware evidence is still required.
- The frozen D114 r2/r10 userdata and its injection/deploy locks remain on r2.
  They were intentionally not repinned in this terminal-only source/package
  iteration.
- The transient takeover path remains disabled and r2-pinned. This change does
  not broaden its authorization or turn it into a runnable r3 deployment path.
- No phone command, RAM boot, partition write, or persistent install occurred
  during this work.

The next device step must first integrate the exact attested r3 APK into a
new host-verified image or a separately repaired and reviewed transient path,
then use a fresh governance record. Physical acceptance should cover old/new
scroll limits, tap and double/triple-tap selection, horizontal selection,
long-hold drag behavior, an extra finger, touch cancel, soft-keyboard
regressions, and continued Wi-Fi use.

## Subsequent integration and hardware result

The statements above describe the terminal-only build stage. Later on
2026-07-24, the exact r3 APK was integrated into a new host-verified D114
userdata candidate. One guarded `userdata` attempt returned exit status zero
but remained conservatively classified as
`USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY`; it was not retried. A separately
authorized D110 RAM boot then reached the graphical Terminal, and the owner
directly confirmed that finger swipes scroll its contents.

The exact hashes, outcome-unknown boundary, and remaining system-level limits
are recorded in
`notes/lmi-d114-p2-r3-terminal-scrollback-hardware-2026-07-24.md`.
