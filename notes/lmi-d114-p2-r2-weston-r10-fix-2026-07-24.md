# D114 P2 r2 — weston r10 black-screen fix (2026-07-24)

## ✅ CONFIRMED WORKING ON DEVICE (2026-07-24)
Flashed the r10 userdata to the phone (serial 8336ded7, sparse `77ff1993`,
fastboot exit 0), verified the r10 `.so`s on-disk from the initramfs debug shell,
then RAM-booted the D110 boot (`2b264d64`, cmdline `d4f78f7d`/`f8eb7c4b`) via the
sanctioned `scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot`
(preflight → authorize-session → execute; one pinned `fastboot boot`). The device
booted **past** the initramfs (no debug-shell drop — the r10 root mounted) and
**the six-row Weston terminal rendered — no black screen.** The drm-formats
assertion is resolved. Owner confirmed on-screen.

Notes for next time:
- The device does NOT persistently boot the r2/r10 image: its on-disk boot's
  cmdline wants `pmos_root_uuid=df32eed6…` while the normalized userdata root is
  `f8eb7c4b…`. Testing is via RAM-boot of the D110 boot each time (flashing D110
  boot to the boot partition is still a deferred Tier-2 item).
- The ramboot gate requires every `private/` ancestor dir at mode 0700 (this
  worktree had `private/` and `private/lmi-p1/` at 755 — chmod 0700 to pass) and
  uses the **Windows** fastboot, so `usbipd detach` the device from WSL first.


## Root cause (4th black-screen cause, verified on device)
weston in the r2 base was **14.0.2-r5**, which aborts during DRM output creation:
```
Assertion failed: !weston_drm_format_array_find_format(formats, format)
(libweston/drm-formats.c: weston_drm_format_array_add_format:131)
```
The msm/KMS driver reports a duplicate legacy plane format; r5 asserts. The fix
is the d80 patch `lmi-dedupe-legacy-plane-formats.patch` (in
`libweston/backend-drm/kms.c` fallback loop → compiled into **drm-backend.so**),
shipped as the custom weston **14.0.2-r10**. libweston core is unchanged (r5),
which is why no libweston-r10 apk exists. `/usr/bin/weston` is byte-identical r5==r10.

A prior session wrongly reverted the session's drm-backend/desktop-shell pins
r10→r5 to match the accidentally-r5 base — CI went green, device kept crashing.
Internal SHA consistency ≠ correctness.

## Fix artifacts (from `C:\Users\microstar\Documents\lmi_linx`)
- d80 r10 apk set + patch: `artifacts/releases/d80-minimal-gui-osk-20260712/` and
  `artifacts/wsl-pmaports/weston/` (all verified vs SHA256SUMS).
- Staged into repo: r10 apks → `private/.../d80-weston-r10-apks/` (gitignored);
  aport provenance → `notes/d80-weston-r10-aport/`.
- Only two base files change: `drm-backend.so` r5 `72bdbdda…`→r10 `3d745727…`,
  `desktop-shell.so` r5 `8411118894…`→r10 `e4996ef1…`. libweston/weston stay r5.

## DONE (this session, verified)
1. Built r10 base: debugfs-swapped the two `.so`s into p2 of a raw copy, re-ran
   `scripts/75` → r10 base/candidate/sparse. New build dir:
   `private/.../p2-d114-r2-most-complete-build-20260724/`. e2fsck verify exit 0.
   New base carries `3d745727`/`e4996ef1` (confirmed).
2. Re-pinned the source tree to r10 + new staging image hashes, converged the
   whole lock-chain to a fixpoint. **hash_consistency: green (60 pins).**
   New staging hashes (tag 20260724):
   - normalized_raw `33067d69…` (3436183552)
   - base_ext4 `5f351c91…` (2923429888)
   - candidate `d331433a…` (2923429888)  repair_epoch 1784734606
   - sparse `1315e3a0…` (2269624624)  ← size changed from 2269624624
3. Retemplated overlay (`generate.py`): new device APKBUILD sha
   `74ba6626…`→`192fb7aa…` (r10 session `d0bfe969…`), pinned in generated-overlay.json.
4. **P2 terminal apk REBUILT** with the r10 session (noarch/data-only). Sealed
   no-root channel reproduced in `work-proot-chroot2/chroot_native-pre-rootfs-calibration`
   via `unshare -rm` + bind `config_abuild`→`/mnt/pmbootstrap/abuild-config`,
   `SOURCE_DATE_EPOCH=1784522705`, `ABUILD_LAST_COMMIT=uncommitted-p2-d114-source-lock-v4`,
   key `pmos@local-6a5d38f2`. **Byte-reproducible** (run1==run2). New apk:
   sha `f0812056…`, size 8776, datahash `75c1621e…`, Q1 `Q1xmDSKg+38KWGNRvP8eE/06z1gTg=`,
   session inside = r10 `d0bfe969…`. Saved run1/run2 in `build-20260724/`.
   All P2-apk pins updated (attestation artifact/runs/inputs, injector
   P2_APK_SHA256/SIZE/CHECKSUM + session Q1 in the strict record parser,
   injection-policy-lock, deploy contract rollback size).
   **Tests: 200/200 green. hash_consistency: 60 pins green.**

## FLASH-READY (2026-07-24 — all host-side work done)
- Injected: rootfs `a91a2090` (drm-backend `3d745727`, desktop-shell `e4996ef1`,
  session `d0bfe969` verified on disk). Assembled: userdata.raw `c3c3a513`,
  android-sparse `77ff1993` (2236696908).
- Deploy Contract + policy lock + postwrite EXPECTED_* finalized to r10.
  **hash_consistency 60 pins green; release static CI green (200/200 + all suites).**
  Committed b098cec + 2a25154, pushed to PR #10.
- r10 deploy profile built (`build-20260724/...r10-wsl-deploy-profile-20260724.json`,
  private) and **local-audit PASSED** (`LOCAL_AUDIT_PASSED_NO_DEVICE_ACCESS`).
- Turnkey flash script: `.../wsl-run-r10-20260724/run-flash-r10.sh`
  (approved-sparse-sha256 `77ff1993…`).

**ONLY remaining step = the owner-run flash (needs the device):**
1. Put the phone in fastboot, then on Windows `usbipd attach --wsl --busid <id>`.
2. `! bash private/.../wsl-run-r10-20260724/run-flash-r10.sh` (preflight→approve→execute).
3. Reboot; the six-row terminal should render (no black screen).
The device was NOT connected during this session, so the flash could not be run here.

## (superseded) earlier remaining list — kept for reference
5. **Inject**: run `launch_inject_rootfs_candidate.sh` on the r10 candidate.
   First bump the injector's path constants 20260723→20260724 (INPUT_BUILD_DIR,
   BUILD_DIR, RAW/SPARSE/INPUT filenames, OUTPUT_BUNDLE) — hashes already r10.
   The injector recomputes the injection attestation's OUTPUT set (FINAL_SHA256,
   FULL_DELTA, installed_db/world/triggers/scripts, p2_package_record); the base's
   apk db was left at r5 (the two weston pkgs still `=14.0.2-r5`, satisfying the
   terminal apk's r5 depends — only the two .so files were swapped), so the
   db-derived expected values are unchanged. Re-pin per the 2026-07-23 note's
   re-pin order (branch commit 39e676d).
6. **Assemble** → new userdata raw + sparse; finalize the WSL deploy Contract
   (assembly/injection/rootfs/raw + wsl policy lock).
7. **Flash** (owner-approved) + verify the six-row terminal renders (no black screen).

## Governance note for the user's SHA request
The re-pin fixpoint approach used here (`repin_images.py`: seed current digests →
leaf-replace old→new globally across tracked text → converge derived self-digests)
catches EVERY copy — no missed-stale-copy black screen. Worth promoting to a
tracked `repin` writer alongside `hash_consistency` (the verifier). See
memory `d114-p2-r2-weston-r5-drm-formats-blackscreen`.
