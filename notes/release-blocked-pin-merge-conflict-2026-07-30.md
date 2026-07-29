# Release blocked: semantic pin conflict from the master merge — 2026-07-30

Status: **host-side analysis only. Nothing was pushed, merged to master,
tagged, or released; no device was contacted. The release run stopped at the
CI gate, as designed.**

## What is broken

`python3 scripts/lmi_release_pins.py verify` reports **0 ok, 15 mismatched**.
Bisected:

| commit | pin registry |
| --- | --- |
| `a24e3d1` (WLAN milestone) | 55 ok, 0 mismatched |
| `7917720` (six-row r3) | 55 ok, 0 mismatched |
| `c54d703` (**merge of origin/master**) | **0 ok, 15 mismatched** |
| `7556316` (HEAD) | 0 ok, 15 mismatched |

Neither parent is broken. The merge is: git resolved the files textually while
the hand-copied SHAs disagree semantically. This is the failure mode recorded
for this repo — *a stale copy passes CI but black-screens the device* — so the
values must not be guessed at.

## Root cause

The pin registry's first-order truth for `build-attestation-file-hash` is

```
_BUILD_ATTESTATION = config/lmi-weston-sixrow/build-attestation.json
```

whose current hash is `b4642db4…`. Every copy site now carries `5bb55928…`.
Meanwhile the directory holds three generations:

- `build-attestation.json` (r1-frozen — still what the registry hashes)
- `build-attestation-r2.json`
- `build-attestation-r3.json` (added by `7917720`)

So the six-row work advanced to r2/r3 and updated the *copies*, but the
registry truth still points at the r1-frozen file. The master merge then mixed
r1-frozen and r2 values into a branch carrying r3. The other affected pins are
the same shape: `weston-keyboard-sixrow-binary-frozen-d114-r1` (5 copies) and
`sixrow-clients-apk-transient-r2` (4 copies).

## The decision this needs

**Which six-row build does the D114 image embed — r1-frozen, r2, r3, or r4?**
That answer fixes all 15 copies *and* the `_BUILD_ATTESTATION` pointer in
`scripts/lmi_release_pins.py`. It is a device-safety decision and it belongs to
whoever owns the live six-row work; a worktree already carries **r4**, ahead of
the r3 snapshot in the main tree.

## Second blocker

`tests/lmi_p2_d114` fails 12 tests locally because
`config/lmi-p2-d114/candidate-rebuild-lock.json` pins
`private/…/p2-d114-r2-most-complete-build-20260724`, which no longer exists —
it was replaced by `p2-d114-r4-modern-layout-build-20260729`. These are
`skipUnless(private/)` so public CI skips them, but the lock is stale either
way.

## Identity leak that reached public history

`notes/lmi-d114-p2-r2-weston-r10-fix-2026-07-24.md` carried the raw device
serial and is **already published on `origin/master`** (introduced by
`b098cec`, before this work). It was redacted going forward in `7556316`, but
the value remains in published history and cannot be removed without a history
rewrite — an owner decision, not an agent one.

Why it was not caught: both identity guards, including
`test_public_intended_tree_has_no_private_historical_serial_match`, are
`@skipUnless(private/…)`. They derive the serial by hashing tokens against a
fingerprint stored in private attestations, so **public CI cannot run them at
all**. That design keeps the serial out of the public tree — publishing the
fingerprint would be equivalent to publishing the serial, since an 8-hex-digit
serial is trivially brute-forced against a 64-bit prefix — but it leaves public
CI blind. A format-shaped guard (flagging serial-like tokens near
`androidboot.serialno=` and similar contexts) would close the gap without
revealing anything.

## Unblock sequence

1. Decide the authoritative six-row revision; reconcile all 15 copies and the
   registry truth pointer; `lmi_release_pins.py verify` back to 0 mismatched.
2. Re-point `candidate-rebuild-lock.json` at an existing private build.
3. Quiesce the branch — it moved three times during the release attempt, and
   publishing from a branch under active mutation is unsafe regardless of CI.
4. Re-run `scripts/59_release_static_ci.sh` to green, then re-run the release.
