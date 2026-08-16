# Kickoff brief: r145 clean-source rebuild + flashable image release

Start here for the next work stream. Goal: produce and publish a
**downloader-reproducible, firmware-free, hardware-validated flashable
D114 image** — the one thing still blocked after the 2026-08-15/16 work.
Everything else (source, locks, reproducible APKs, r4 baseline, persistent
boot) is already done and released.

## Where things stand (as of 2026-08-16, branch agent/lmi-d114-p2-r1-sixrow-release @ 76f3a6e)

- **r4 re-baseline complete** — six-row keyboard baseline is r4, governed
  and reproducible; device runs the packaged r4 terminal; persistent boot
  works (boot `2b264d64…`). See
  `docs/release/d114-p2-r4-rebaseline-2026-08-16.md`.
- **weston r10 + six-row reproduced byte-identically from source** —
  `scripts/76_build_weston_r10_source.sh`, `scripts/77_build_sixrow_r2_source.sh`;
  `docs/release/d114-p2-weston-r10-source-reproduction-2026-08-15.md`.
- **Reproducibility artifacts published** — GitHub pre-release
  `d114-p2-repro-20260816` (APKs + build-root closures + SHA256SUMS);
  in-repo checksums `docs/release/d114-p2-repro-20260816-SHA256SUMS.md`.
- **Injection pipeline is r4 and green** — hash_consistency 60, pin
  registry 56, static CI green. The private r4 image was re-injected +
  re-assembled but is the HISTORICAL private baseline, NOT publishable
  (reasons below).

## Why the image is still blocked (the gate this stream must close)

Authoritative gate: `docs/release/d114-p2-reproducibility-gate-2026-08-10.md`.
Readiness gates: `docs/release/lmi-d114-r1-sixrow-readiness-20260722.md` §"Gates
before a binary prerelease" (7 gates). Plan of record:
`docs/release/v1-firmware-free-release-plan-2026-07-29.md` §"Steps" (8 steps).

Concretely, the current pinned userdata cannot be published because:
1. **Credentials in the image.** The `lmi` account carries a real password
   hash (`PMOS_INSTALL_PASSWORD` output) and the image was built on a dirty
   baseline. The public image must ship the r145 hardened defaults:
   key-only SSH, `authorized_keys` removed (installer injects the
   downloader's own key at flash time), locked/again-sanitized password,
   no wheel/owner-mode looseness.
2. **Dirty kernel.** `source-lock.json` records
   `installed_kernel_package: linux-xiaomi-lmi=4.19.325-r15` but the
   historical baseline kernel APK is `commit=-dirty` (r9-era). Gate 2/5:
   clean-source kernel with a generic reproducible Kbuild identity (no
   `pmos@DESKTOP-JID71RJ` binary-patch).
3. **Prebuilt `lmi-qrtr-ns`.** A checked-in static ELF
   (`artifacts/wsl-pmaports/device-xiaomi-lmi/lmi-qrtr-ns`, and the
   d114-pmaports copy) with no pinned upstream revision/license — gate 3:
   rebuild from pinned public source + license notice.
4. **No repo snapshot pin for the D114 chain** — gate/`offline-cache-promotion`
   pattern (`config/lmi-p1/offline-cache-promotion.json` is the model;
   D114 lacks it): pmaports commit, APKINDEX digests, signer keys.
5. **No published SHA256SUMS + installer profile for the image** — the CLI
   installer `verify` needs an `installer-profile.json` the downloader
   doesn't have yet.

Firmware is NOT a blocker: the r145 device package is firmware-free by
design (`lmi-firmware-mount` mounts it at runtime from the device's own
Android partitions). Non-goals: never ship stock/recovery images or any
proprietary firmware binary; never relock the bootloader; never touch
boot/dtbo/vbmeta/super/modem/persist/calibration.

## The work (v1 plan steps 1–8, condensed)

1. **Consolidate/merge** the r145 recipe + this release branch to master;
   commit every source/patch/lock/test used by the build.
2. **Close the recipe.** Fold the weston-r10 drm-formats patch (now
   source-reproduced) into the recipe; harden machine-id/credential
   sanitization to the validated form; rebuild `lmi-qrtr-ns` from pinned
   source (gate 3).
3. **Clean-source rebuild (host, no-sudo).** Clean kernel package (generic
   reproducible Kbuild id, gate 5); fresh pmbootstrap rootfs from the r145
   recipe (firmware-free); rebuild the six-row **r4** + terminal APKs from
   tracked sources via the userns flow (already reproducible — see
   scripts 76/77 and `.work/terminal-r4/`); re-run injector + assembler for
   a single final sparse (gate 6). Injection recipe is already r4.
4. **Re-pin + verify (host).** Walk the full hash re-pin checklist in
   `notes/lmi-d114-p2-next-version-handoff-2026-07-22.md` §3 (source-lock,
   candidate-rebuild-lock, injection-policy-lock, injector inline pins
   incl. the per-package installed-db C/Z/S/t grammar, deploy profiles,
   attestations, pin registry). Then hash_consistency + lmi_release_pins +
   static CI green. NOTE: the injector's installed-db checksums use
   `Q1+base64(sha1(file))` for Z and `Q1+base64(sha1(control.tar.gz))` for
   the package C (control = the apk's 2nd gzip member) — verified method,
   reuse it.
5. **[PHONE] Flash + persistent boot** under owner-authorized profile.
6. **[PHONE] Exact-hash hardware validation (gate 7)** — boot, display,
   every touch key, terminal control sequences, persistence, key-only SSH,
   Wi-Fi auto bring-up.
7. **Release packaging** — SBOM + NOTICE + corresponding-source assets
   (gate 4); tested RECOVERY.md; installer `installer-profile.json` so
   `scripts/lmi_cli_installer.py verify` works for a downloader; SHA256SUMS
   over compressed + sparse + raw.
8. **Publish** a new tag (not `v0.1.0-alpha.1`), GitHub Release with the
   image + SHA256SUMS + build manifest + installer profile.

## Host constraints the new session MUST know (carried from this work)

- **No-sudo build flow.** sudo is interactive-only here; build APKs via
  offline `apk.static` + `proot -0`/`qemu-aarch64` (binfmt is gone). Tools:
  `private/lmi-p1/calibration/acquisition-root/…` (proot, qemu, apk.static,
  canonical key `pmos@local-6a5d38f2.rsa`). See memory
  `no-sudo-userns-build-flow` and `.work/terminal-r4/build-terminal-r4.sh`
  / `.work/weston-r10/build-weston-r10.sh` for working scripts.
- **pmbootstrap needs sudo** (losetup/chroot) → the full rootfs rebuild
  (step 3) will need the owner to run pmbootstrap interactively, OR a
  userns equivalent. This is the main open host question for step 3.
- **Root-owned injector output** must be cleaned via the wsl.exe root
  transport (`wsl.exe -d Ubuntu -u root --exec rm -rf …`), not plain rm.
- **Host-tool identity pins drift.** libc6/ld/libm and wsl.exe are pinned
  by exact hash across the injector/deploy chain; a host update fail-closes
  them (verified benign path: `dpkg -V libc6`, Authenticode for wsl.exe).
  Re-pin cascade order is in the git history around commit 3209c2d.
- **Never** regenerate frozen attestations in place; `private/` never
  leaves the machine; device serial `<device-serial>` + LAN IPs are purged secrets;
  boot-partition flash is owner-only (`NEVER_FLASH_BOOT` in the chain).
- **Device access:** key-only SSH as `lmi@<usb-ip>` (USB) /
  `<lan-ip>` (Wi-Fi) with `private/lmi-p1/owner-test-ed25519`; host key
  in `private/lmi-p1/recovery/d110-d114/p2-d114-known_hosts` (rotates on
  fresh userdata — refresh via ssh-keyscan after confirming USB==WLAN key).
  Windows fastboot at `%LOCALAPPDATA%/lmi-p2-d114/fastboot-r37.0.0/`.

## First concrete actions for the new session

1. Read the three release docs above + `notes/lmi-d114-p2-next-version-handoff-2026-07-22.md` §3.
2. Confirm current git state (branch, `git log`, static CI green).
3. Decide the pmbootstrap-rootfs-rebuild path (owner-interactive sudo vs
   userns) — this is the gating unknown for step 3.
4. Start with the two host-only, no-device gates that don't need pmbootstrap:
   rebuild `lmi-qrtr-ns` from pinned source (gate 3) and add the D114
   `offline-cache-promotion`-style snapshot pin (gate/step) — both are
   self-contained and unblock later steps.

Related memories: `d114-p2-r4-rebaseline`, `d114-p2-byte-identical-reproductions`,
`no-sudo-userns-build-flow`, `deploy-transport-parser-false-negative`,
`p2-d114-sha-duplication-fragility`, `history-rewrite-2026-08-10`.
