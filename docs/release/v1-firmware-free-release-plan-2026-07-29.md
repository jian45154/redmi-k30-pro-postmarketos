# v1 firmware-free public image release plan — 2026-07-29

**Archived evidence — do not execute commands from this file.**

Status: **host-side read-only audit and plan. No build, no device contact, no
git commit, no flashing was performed for this document.** Written on branch
`agent/lmi-d114-p2-r1-sixrow-release`; facts were read from the working tree,
tracked docs/notes, config locks, and branch history only.

Settled v1 definition (task decision context): untethered Wi-Fi SSH working,
plus a hardware-validated, firmware-free image published via GitHub Releases
with hash manifests. Firmware must come from the runtime `lmi-firmware-mount`
design (mounted from the device's own Android partitions) — no
Qualcomm/Xiaomi proprietary blobs embedded. The public image ships the
hardened r145 SSH defaults; the CLI installer injects the downloader's own
pubkey at flash time; owner-mode looseness is opt-in.

---

## 1. Firmware audit: which images embed blobs, which are runtime-clean

### Embedding vs runtime-mount by variant

| Variant family | Firmware handling | Evidence |
| --- | --- | --- |
| `D-v2`–`D-v29` | No firmware in image (`/lib/firmware` had only `regulatory.db*`); Wi-Fi absent | `notes/firmware-inventory-2026-06-23.md` |
| `D-v30`–`D-v32` (`fw`, `wlanon`, `initfs-fw` names) | **Stage proprietary firmware content** into rootfs/initramfs — not publishable | `docs/open-source-release-audit-2026-07-22.md` §3 row "Built boot/rootfs images"; `artifacts/images/pmos-lmi-v30-rmtfs-fw-fsready-full-20260623.manifest`, `…v32-initfs-fw-full-20260623.manifest` |
| `D-v33`–`D-v46` | Runtime mount: `wifi_strategy=lmi-firmware-mount -> pd-mapper/rmtfs/tqftpserv -> lmi-cnss-fs-ready -> lmi-wlan-on -> wpa_supplicant`; vendor `cnss-daemon` is **exec'd from the mounted stock vendor partition**, never copied in | `artifacts/images/pmos-lmi-v33-downstream-sshwifi-full-20260624.manifest`; `artifacts/wsl-pmaports/device-xiaomi-lmi/lmi-cnss-daemon-wrapper` (`exec /vendor/bin/cnss-daemon`) |
| Historical D114 userdata (r142-era baseline, and the r1/r10 candidates built on it) | **Flagged as staging proprietary firmware content** and additionally carries a dirty-source kernel (`linux-xiaomi-lmi-4.19.325-r9`, `commit=-dirty`) and locally built P2 packages without exact public source closure — private hardware-test baseline only | `docs/open-source-release-audit-2026-07-22.md` §3; `docs/release/lmi-d114-r1-sixrow-readiness-20260722.md` "Current verdict"; `config/lmi-p2-d114/source-lock.json` (`installed_kernel_package: linux-xiaomi-lmi=4.19.325-r9`, `authority: current-wsl-project-only`) |

### The current recipe is firmware-free by design

The device package in the working tree (`device-xiaomi-lmi` pkgrel **145**,
`artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD`) contains no firmware
package in `depends=` and no firmware files in `source=`. All firmware access
is runtime:

- `lmi-firmware-mount.initd` mounts the `modem` partition read-only at
  `/mnt/vendor/firmware_mnt` and creates symlinks under
  `/lib/firmware/qca6390/` into the mount;
- `initramfs_mount_firmware.sh` does the same aliasing at initramfs time;
- `lmi-wifi-start` mounts `persist` read-only for `wlan_mac.bin` and links
  `WCNSS_qcom_cfg.ini` — links, not copies;
- vendor `cnss-daemon` runs from the mounted stock partitions via
  `lmi-cnss-daemon-wrapper` with the LD_PRELOAD property shim
  (`lmi-android-prop-shim.c`, built from source in-repo).

**Answer: a D114-era firmware-free build is neither a pmbootstrap flag nor a
package-selection toggle — the r145 recipe already produces a firmware-free
rootfs. The work is a fresh clean-source rebuild** replacing the historical
private baseline: clean kernel package (no `-dirty`), fresh pmbootstrap
rootfs from r145, re-run of the injector/assembler, and the full hash re-pin
chain of `notes/lmi-d114-p2-next-version-handoff-2026-07-22.md` §3. The
readiness doc (gates 2–3) additionally requires replacing the prebuilt
`lmi-qrtr-ns` ELF checked into
`artifacts/wsl-pmaports/device-xiaomi-lmi/lmi-qrtr-ns` with a build from a
pinned public source revision plus its license notice — that binary is the
one non-source payload inside the otherwise-source device package.

## 2. Private sixrow APK dependency

The D114 injector hard-pins two APKs that live under gitignored `private/`:

- `run2-device-xiaomi-lmi-terminal-0.1.0-r1.apk` (8,768 B, SHA-256
  `7cab262b…`) and `lmi-weston-sixrow-clients-14.0.2-r1.apk` (120,891 B,
  SHA-256 `ff8dbb02…`), pinned in
  `scripts/lmi_p2_d114/inject_rootfs_candidate.sh` lines 47–64 and consumed
  from `private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/`;
- four host tests in `tests/lmi_p2_d114/test_inject_rootfs_candidate.py`
  (guarded per commit `6c6bb2b`) skip on hosts without that private material.

**They do not block a fully-open release.** Their complete sources are
tracked:

- six-row clients: `files/lmi-weston-sixrow/APKBUILD` + three patches on the
  upstream Weston 14.0.2 tarball, whose URL and sha512 are pinned in
  `config/lmi-weston-sixrow/source-lock.json`;
- terminal package: rendered by `scripts/lmi_p2_d114/generate.py` from
  `files/lmi-p2-d114/` and `config/lmi-p2-d114/source-lock.json`;
- the patched Weston **r10** aport (the on-device-confirmed fix for the
  libweston drm-formats black screen) is tracked on branch
  `agent/lmi-d114-p2-r2-most-complete` under `notes/d80-weston-r10-aport/`
  (including `lmi-dedupe-legacy-plane-formats.patch`).

What the private APKs block is only **bit-exact reproduction of the current
private candidate**: rebuilt APKs get new hashes and new signing keys, so the
attestations (`config/lmi-p2-d114/apk-build-attestation.json`) and every
downstream pin must be regenerated for the release build — which the policy
requires anyway (readiness gate 1/4). Build flow is the no-sudo userns flow
(apk.static root + proot/qemu); pinned attestations are never regenerated in
place.

## 3. Sizes vs the GitHub Release 2 GiB/file limit

| Artifact | Bytes | vs 2 GiB (2,147,483,648) | Source |
| --- | --- | --- | --- |
| D114 boot image | 52,944,896 | fine | `config/lmi-p2-d114/source-lock.json` `boot_size` |
| D114 userdata **raw** | 3,339,714,560 (~3.11 GiB) | over | same lock, `userdata_raw_size` |
| D114 userdata **sparse** (the flashed artifact) | 2,192,400,084 (~2.04 GiB) | **over by ~45 MB** | same lock, `userdata_sparse_size` |
| P2 rootfs ext4 (inside userdata) | 2,826,960,896 | n/a (not shipped alone) | `scripts/lmi_p2_d114/assemble_userdata_image.py` `P2_SIZE` |
| Downstream v46 boot / userdata raw (reference) | 52,924,416 / 1,819,279,360 | fine | `artifacts/images/pmos-lmi-v46-…manifest` |

Plan: **compress the sparse userdata image** (zstd preferred; a mostly-ext4
sparse image compresses far below 2 GiB) and publish:

- `boot-lmi-<tag>.img` (uncompressed, ~50 MiB);
- `userdata-lmi-<tag>.android-sparse.img.zst`;
- `SHA256SUMS` covering **both** the compressed asset and the decompressed
  sparse bytes (the hash the installer and the hardware-validation manifest
  bind), plus the expanded-raw hash for post-flash verification.

Fallback if a future image resists compression: `split -b 1900M` with a
documented `cat`-reassembly step and per-part hashes. No asset may rely on
Git LFS or the repo tree; Releases only.

## 4. Owner pubkey injection: today vs the v1 story

Today there is **no flash-time SSH key injection anywhere**:

- the public image sanitization **removes** `authorized_keys` outright
  (injector attestation `"authorized_keys":"removed"`;
  `notes/ssh-full-function-contract-2026-07-24.md` records the public D114
  candidate correctly refusing login for exactly this reason);
- the only owner-key mechanisms are private: a never-publish personalization
  of private test images with the single owner Ed25519 key
  (`notes/lmi-d114-p2-next-version-handoff-2026-07-22.md` §2 step 5), and a
  temporary manual key injected into a live session (ibid. §4);
- the installer `v0.1.0-alpha.1` (`scripts/lmi_cli_installer.py`,
  `docs/lmi-cli-installer.md`) is verification-only: no `flash`, `install`
  is always dry-run, and it contains no SSH-key code at all — the
  `public_key` entries in `config/lmi-p2-d114/userdata-deploy-policy-lock-*`
  are APK signing keys, not SSH keys.

Missing for "installer injects the downloader's own pubkey at flash time":

1. A flashable installer version at all — `docs/lmi-cli-installer.md`
   ("升级为可刷版本前必须重新设计") enumerates the mandatory redesign gates:
   authorization bound to exact release + image hashes + device identity,
   single-transaction `userdata → boot → reboot`, per-write device
   re-verification, provenance/license/privacy acceptance for exact bytes, a
   tested recovery path, and signed release assets.
2. A key-injection design that survives the exact-hash policy. Because
   hardware validation binds the **pristine** image bytes, the installer must
   (a) verify the downloaded pristine sparse image against the release
   manifest, (b) perform a deterministic, minimal personalization — write the
   downloader's Ed25519 pubkey to `/home/lmi/.ssh/authorized_keys`
   (uid/gid 10000, the exact modes the SSH contract's StrictModes closure
   requires) inside the P2 ext4 before or during flashing — and (c) emit a
   local personalization attestation recording pre- and post-injection
   hashes. Only the pubkey file may differ from validated bytes.
3. Owner-mode looseness (password console, wheel, etc.) stays out of the
   image and out of the default installer path; it can only be a separate,
   explicit opt-in flag that the attestation records. The shipped image keeps
   the r145 defaults: `files/lmi-p1/sshd_config` (key-only, `AllowUsers lmi`,
   root login off), `lmi` outside `wheel`, locked shadow password, sudo
   surface exactly `NOPASSWD: /usr/sbin/lmi-rootctl`
   (`notes/ssh-full-function-contract-2026-07-24.md`).

## 5. What repo policy requires before shipping a binary

`docs/release/lmi-d114-r1-sixrow-readiness-20260722.md` is the binding
document: "no binary ships without exact-hash hardware validation" (also
`docs/open-source-release-audit-2026-07-22.md` §3/§4). Its seven gates, with
current evidence status:

| Gate | Status today |
| --- | --- |
| 1. Commit/tag every source, lock, test used by the build | Not met: master (`4cf8bbf`) is far behind; the r1 release branch, the r2 `most-complete` branch (weston r10 aport + confirmed-on-device fix), and uncommitted working-tree changes are unmerged |
| 2. Replace dirty P1/P2 inputs with clean-source build (boot + rootfs from same kernel package) | Not met: baseline kernel APK records `commit=-dirty` (r9) while the public recipe was r8 |
| 3. Rebuild `lmi-qrtr-ns` from pinned public source + license notice | Not met: prebuilt ELF still in `artifacts/wsl-pmaports/device-xiaomi-lmi/` |
| 4. Frozen signed APK indexes, binary/source-origin inventory, SBOM, notices, corresponding-source assets | Not started |
| 5. Generic reproducible Kbuild identity (no `pmos@DESKTOP-…` binary patch) | Not met for historical bytes; trivially met by a clean rebuild |
| 6. Single final sparse generation + full verification bound in an immutable manifest | Exists only for the private r1/r10 candidates; must be redone for the release bytes |
| 7. Fresh exact-hash hardware tests: boot, display, touch, every key, terminal control sequences, persistence, SSH, Wi-Fi | Not met for any publishable image. Best current evidence, all on private/hash-different images: six-row terminal + keyboard confirmed on device (r10, 2026-07-24, RAM-booted via D110 boot); USB SSH + persistence proven on `D-v27`; Wi-Fi interfaces + scan proven on `D-v43`. **No image has ever demonstrated an authenticated SSH session over WLAN** (`notes/ssh-full-function-contract-2026-07-24.md` "Evidence boundary"), and no candidate boots persistently from its own boot partition today (on-disk boot drops to the initramfs debug shell; handoff §4) |

Additional required release text (readiness doc, final paragraph): destructive
`userdata` warning, unlocked-`lmi`-only, preserves stock `modem`/`persist`/
`super`, never relocks the bootloader, never auto-retries a failed write, no
authority over `boot`(beyond the paired flash)/`dtbo`/`vbmeta`/`super`/
modem-EFS/calibration.

## 6. Sequencing: today → "v1 release published"

Phone-required steps are marked **[PHONE]**; all phone steps additionally
require the governance path (fresh per-profile owner authorization via
`scripts/bringup_loop.py`; no reuse of historical ready records).

1. **Consolidate the tree.** Merge to master: this release branch (r145
   source contract, release-pins registry `scripts/lmi_release_pins.py`,
   retired staged-flash helpers), `agent/lmi-d114-p2-r2-most-complete`
   (weston r10 aport + patch), and the keyboard/scrollback branches already
   merged into the integration graph. Commit current working-tree changes.
2. **Close the recipe.** Fold the weston-r10 drm-formats patch and any
   keyboard v2/v3 layout decision into the pinned package set; fix the
   machine-id sanitization **to the hardware-validated form** — a populated
   valid machine-id, not deletion (the 2026-07-22 handoff's "delete and let
   dbus-uuidgen recreate" was superseded: on this OpenRC image nothing
   regenerates it early enough and the session dies); rebuild `lmi-qrtr-ns`
   from pinned source (gate 3).
3. **Clean-source rebuild (host).** Clean kernel package (generic reproducible
   Kbuild identity, gate 5), fresh pmbootstrap rootfs from the r145 recipe
   (firmware-free by design), rebuild both sixrow/terminal APKs from tracked
   sources via the userns flow, re-run injector (r145 sanitization: no
   authorized_keys, locked passwords, no wheel) and assembler; single final
   sparse (gate 6).
4. **Re-pin and verify (host).** Walk the full hash re-pin checklist
   (handoff §3), then `python3 scripts/lmi_release_pins.py verify`,
   `scripts/59_release_static_ci.sh`, `scripts/65_lmi_release_safety_lint.sh`,
   full test suite, green public CI.
5. **[PHONE] Flash + persistent boot.** Owner-authorized profile; flash the
   exact-hash userdata **and** the paired boot image (Tier 2: preflight,
   distinct-hash rollback artifact, one-shot claim) so the device boots
   untethered — RAM-boot via the D110 boot does not satisfy "untethered".
6. **[PHONE] Exact-hash hardware validation (gate 7).** Boot, display, touch,
   every keyboard key, terminal control sequences, reboot persistence; Wi-Fi
   auto bring-up (r145 restores the `lmi-wlan-on`/`lmi-cnss-fs-ready`
   runlevel links); then `scripts/74_verify_lmi_ssh_full.sh` **twice — once
   over USB and once over WLAN**; a USB session never proves WLAN SSH. Bind
   all results into the immutable release manifest.
7. **Release packaging (host).** SBOM + notices + corresponding-source assets
   (gate 4); RECOVERY.md tested against the same device state; installer
   `build-bundle` verification directory; ship the installer as a new version
   with the flash + pubkey-injection capability of §4 (or, if v1 ships
   before that installer exists, publish image + manifests + the
   verification-only installer with documented manual fastboot commands and a
   documented manual `authorized_keys` provisioning path — note this fails
   the settled v1 definition and would need an explicit decision).
8. **Publish.** New tag (not `v0.1.0-alpha.1`), GitHub Release with
   `boot-lmi.img`, `userdata-lmi.android-sparse.img.zst` (§3 split fallback if
   needed), `SHA256SUMS` (compressed + sparse + raw hashes), build manifest,
   SBOM, installer tarball + sha256; release text with the mandatory safety
   statements (§5). Asset signing + out-of-band key fingerprint per the
   installer doc's upgrade gates.

## 7. Biggest risk

**Every clean rebuild resets the hardware evidence to zero on a single,
fragile test path.** The publishable firmware-free image does not exist yet
as bytes: all validated images are private, dirty-source, and hash-different,
and the policy (correctly) refuses to transfer their evidence. Each recipe
change → full hash re-pin across ~148 hand-copied SHAs (mitigated but not
eliminated by `scripts/lmi_release_pins.py`) → owner-approved flash through
the WSL/usbipd/fastboot chain that has already produced five transcript
false-negatives and is currently unreachable (device not attached,
`notes/wifi-runtime-probe-2026-07-29.md`) → re-validation of every gate-7
item on the one phone. Two of those items have **never** been demonstrated on
any image: authenticated SSH over WLAN, and untethered persistent boot of a
current candidate from the device's own boot partition. If either fails on
the release bytes, the whole loop repeats. Secondary risk: the flash-time
pubkey injection intentionally mutates validated bytes, so its design must be
settled (pristine-hash + deterministic personalization attestation, §4)
before the validation flash, or v1's installer story slips.
