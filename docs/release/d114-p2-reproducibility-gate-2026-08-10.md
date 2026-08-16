# D114 P2 downloader-reproducibility gate — 2026-08-10

**Archived evidence — do not execute commands from this file.**

Verdict: **a downloader cannot reproduce or verify the pinned D114 P2 image
from the public repository.** The release must not publish image bytes until
this gate closes. This audit was requested as an explicit release
precondition ("before release, confirm a downloader can reproduce the flash
image") and was performed against the tree at the head of
`agent/lmi-d114-p2-r1-sixrow-release` after the pin registry returned to
56 ok / 0 mismatched.

## What a downloader CAN do today

- Read the complete kernel, device, six-row, and terminal **sources** with
  hash pins: `artifacts/d114-pmaports/` (kernel `_commit` + sha512sums, no
  `SKIP`), `files/lmi-weston-sixrow/` + `config/lmi-weston-sixrow/source-lock.json`
  (tarball sha256+sha512, patches by sha256), `files/lmi-p2-d114/` +
  `config/lmi-p2-d114/source-lock.json`.
- Run `scripts/59_release_static_ci.sh`, `scripts/lmi_release_pins.py verify`
  (56 ok / 0 mismatched), and `python3 -m scripts.lmi_p2_d114.hash_consistency
  verify` (60 cross-file pins OK) to confirm the lock chain is internally
  consistent.
- Build their **own** postmarketOS image from the tracked aports — which will
  have different hashes and different behaviour (see gap 1).

## Gaps that block reproduction of `a91a2090…` / `c3c3a513…` / `77ff1993…`

1. **The pinned rootfs is provably not source-derived.**
   `notes/lmi-d114-p2-r2-weston-r10-fix-2026-07-24.md` records that the
   `a91a2090…` rootfs was produced by `debugfs`-swapping two prebuilt weston
   r10 shared objects (`drm-backend.so` `3d745727…`, `desktop-shell.so`
   `e4996ef1…`) taken from `artifacts/releases/d80-minimal-gui-osk-20260712/`
   and `artifacts/wsl-pmaports/weston/` — **neither path exists in the
   tracked tree**, and the staged r10 APKs live only under gitignored
   `private/`. A perfect from-source rebuild of everything public yields the
   r5 `.so`s, which black-screen the device (the libweston drm-formats
   assert). Closing this requires a source rebuild of the weston r10 aport
   (`notes/d80-weston-r10-aport/` — source is public and sha512-pinned) and a
   re-based, device-revalidated image.
2. **Private build inputs.** The base/candidate ext4 chain, baseline sparse,
   the two injected APKs, and the `apk.static`/`proot`/`qemu-aarch64`
   toolchain all live under gitignored `private/`
   (`config/lmi-p2-d114/candidate-rebuild-lock.json` `inputs.*.path`,
   `config/lmi-p2-d114/injection-policy-lock.json` `input.apks.*.source_path`,
   `scripts/lmi_p2_d114/inject_rootfs_candidate.sh`).
3. **No repository snapshot pin for the D114 chain.**
   `scripts/74_build_pmos_d114_r2_rootfs.sh` builds against rolling
   Alpine/pmOS edge; `source-lock.json` pins 15 package versions but no
   APKINDEX digests, mirror, or pmaports commit. The model to copy exists in
   this repo: `config/lmi-p1/offline-cache-promotion.json` (pmbootstrap +
   pmaports commits, APKINDEX digests, signer keys) — it just does not cover
   D114 P2.
4. **The six-row APK has no build script.** The procedure exists only as
   prose in `config/lmi-weston-sixrow/build-attestation-r3.json` and
   depends on an unenumerated 199-package offline pmbootstrap cache; the r2
   attestation additionally records a by-hand signature-strip/re-sign step.
   The embedded binary is sixrow **r2** while the tracked `APKBUILD` is
   `pkgrel=3` — the public tree does not even build the revision inside the
   pinned image.
5. **Host-bound assembly and deploy.** The injection step fail-closes on
   ~25 exact-hash Ubuntu/WSL host binaries and on `wsl.exe`'s transport hash;
   the deploy gate needs the device serial, privacy nonce, private ledgers,
   and a fastboot ELF closure lock that has already drifted on the
   maintainer's own host.
6. **Nothing to verify against.** No image, no `SHA256SUMS`, no D114
   manifest, and the shipped installer ships no `installer-profile.json`;
   `verify` validates a profile the downloader does not have. A prebuilt
   `lmi-qrtr-ns` static ELF (796,784 bytes, no upstream revision/license)
   also remains inside the device aport (readiness gate 3, still open).

## Consequence for this release

The project's own policy statement remains accurate
(`docs/release/v1-firmware-free-release-plan-2026-07-29.md`: the publishable
firmware-free image "does not exist yet as bytes"). This gate therefore
**blocks binary publication, not source publication**: publishing the source
tree, locks, and attestations is consistent with policy; publishing or
promising a flashable image is not, until:

1. weston r10 is rebuilt from the tracked aport source and the image is
   re-based on source-derived packages only (device revalidation required);
2. the D114 chain gets an `offline-cache-promotion`-style snapshot pin;
3. the six-row build is scripted from its attestation prose and its APKBUILD
   revision matches the embedded binary;
4. a `SHA256SUMS` + installer profile is published alongside the image so
   `scripts/lmi_cli_installer.py verify` works for a downloader.

Known documentation drift found during the audit (stale r1-era sizes in the
v1 release plan §4 table and in
`config/lmi-p2-d114/userdata-deploy-profile-wsl.template.json`, and the
uncovered `inputs.source_lock.sha256` field in `candidate-rebuild-lock.json`)
is recorded here rather than silently fixed: those values are frozen
attestation-adjacent records, and the project rule is that pinned records are
never regenerated in place.
