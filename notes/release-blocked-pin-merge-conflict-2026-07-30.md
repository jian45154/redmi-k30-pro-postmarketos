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

## Update 2026-07-31: pins resolved, a portability regression exposed

`df99e43` reconciled the registry against the merged r2-most-complete chain
(truths now follow the r2 attestation). **`lmi_release_pins.py verify` is back
to 56 ok, 0 mismatched**, and the stale `candidate-rebuild-lock.json` was
re-pointed, clearing the earlier 12 failures.

Static CI still exits 1, now with **3 errors of a different kind**:

```
DeployError: ELF interpreter resolved identity mismatch
  tests/lmi_p2_d114/test_deploy_userdata_wsl.py
  tests/lmi_p2_d114/test_postwrite_revalidate_wsl.py (x2)
```

`config/lmi-p2-d114/fastboot-wsl-runtime-lock.json` pins the ELF interpreter
as sha256 `223b94a4…`; this host now has `c5e80a56…` (same size, 254864).
The cause is benign and verified: Ubuntu updated `libc6` to `2.43-2ubuntu2.3`
on 2026-07-23, `dpkg -S` attributes the file to that package, and `dpkg -V
libc6` reports no modification. Every revision — `a24e3d1`, `7917720`,
`origin/master`, `HEAD` — carries the same locked value, so the merge did not
regress it; the *host* moved.

The real problem is portability, not the lock. `test_deploy_userdata_wsl.py`
reads the **real** lock file and validates it against the **real** host
filesystem:

```python
runtime = json.loads((deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text())
...
prefix, held = deploy._validate_runtime(runtime, runtime_only_runner)
```

Such a test can only pass on the exact machine, with the exact glibc build,
where the lock was captured. `.github/workflows/edge-release-checks.yml` runs
`scripts/59_release_static_ci.sh`, so **these tests will also fail on GitHub's
runner** — they were merged in from the r2 line and contradict the portability
policy recorded in `d14c03a`.

Two ways out, and the choice is a security judgement, not a mechanical fix:

1. **Gate it** — `skipUnless` the captured lock matches the live host. Cheap,
   but a deploy-trust guard that silently skips is a weaker guard.
2. **Use a fixture** — validate against a synthetic runtime tree built in the
   test, and keep the real-lock check in a separate, explicitly host-bound
   suite that public CI does not run.

Option 2 preserves the guard's meaning and is the recommended one. Re-pinning
the lock to the new glibc is a separate owner action: it re-establishes trust
in the deploy toolchain, and the project rule is that pinned attestations are
never regenerated in place.

## Update 2026-08-10: portability regression fixed (option 2)

The owner chose the fixture route. `tests/lmi_p2_d114/runtime_lock_fixture.py`
now derives a synthetic host view from the tracked runtime lock itself and
serves it at the validator's host access points (`Path.lstat`, `os.readlink`,
`os.fstat`, `deploy._open_regular`), so the accept-path tests pass on any
host without weakening the validator. The real-lock-vs-real-host binding
moved to `tests/lmi_p2_d114_hostbound/`, which static CI intentionally does
not run; on this host it currently fails with the known glibc-drift
signature, which is the correct signal that the owner must re-capture the
lock before the next device deploy. `scripts/59_release_static_ci.sh` is
green end to end.

## Unblock sequence

1. Decide the authoritative six-row revision; reconcile all 15 copies and the
   registry truth pointer; `lmi_release_pins.py verify` back to 0 mismatched.
2. Re-point `candidate-rebuild-lock.json` at an existing private build.
3. Quiesce the branch — it moved three times during the release attempt, and
   publishing from a branch under active mutation is unsafe regardless of CI.
4. Re-run `scripts/59_release_static_ci.sh` to green, then re-run the release.
