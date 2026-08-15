# D114 P2 weston r10: byte-identical source reproduction — 2026-08-15

**Archived evidence — do not execute commands from this file.**

Result: **all four pinned weston session components of the D114 P2 image
were reproduced byte-identically from the public aport source** on
2026-08-15, using only public inputs (the tracked
`notes/d80-weston-r10-aport/` aport, the sha512-pinned upstream
`weston-14.0.2.tar.xz`, and Alpine edge packages verified against the
Alpine signing keys). This closes the weston portion of gap 1 of
`docs/release/d114-p2-reproducibility-gate-2026-08-10.md`: the
`debugfs`-injected r10 binaries in the pinned rootfs `a91a2090…` are no
longer "provably not source-derived" — they are now proven source-derived,
and no image re-base or device revalidation is needed for them, because the
image bytes do not change.

## Reproduced components

Payloads hashed directly out of the freshly built .apk files; expected
values are `runtime.component_sha256` of
`config/lmi-p2-d114/source-lock.json` (identical to the bytes extracted
from the pinned candidate ext4 `d331433a…` via debugfs the same day):

| component | sha256 (built == pinned) |
| --- | --- |
| `usr/bin/weston` | `191703aa8da1d965fe7a2e7b4ec7ad7316c484cdc26ac77f31c015d6ee4bd45e` |
| `usr/lib/libweston-14.so.0.0.2` | `2c7565771a3e4097cdaf3e240d5e1dece2cdff78227967153df6088164bde9cd` |
| `usr/lib/libweston-14/drm-backend.so` | `3d74572726b4c7cbbdf1abad75dbeeee6d76f08af766a8bba06f30aeaf617a2f` |
| `usr/lib/weston/desktop-shell.so` | `e4996ef148957fbeaafd1c374611a4831a7afe74b6014e47869e445c88b6cf67` |

The build produced the full 17-package set — including
`libweston-14.0.2-r10.apk`, the subpackage previously unrecoverable from
any archive on this machine.

## Method

`scripts/76_build_weston_r10_source.sh` (added with this record; the
as-run copy is archived with the products). Unprivileged throughout: a
network-capable official `apk-tools-static` (3.0.7-r0) resolved the
455-package aarch64 dependency closure from Alpine edge with
signature-verified indexes; the build root was materialized under
`unshare -r`; `abuild -F -d` ran under `proot -0` with qemu-aarch64
user-mode emulation (`PROOT_NO_SECCOMP=1`). Signing used the canonical P2
key, which affects only the `.SIGN` member of the .apk files — the payload
bytes verified above are independent of the signing key.

Toolchain drawn from the closure: gcc 15.2.0-r8, musl 1.2.6-r2,
binutils 2.45.1-r1, meson 1.11.2-r0, abuild 3.18.0_rc5-r0.
`SOURCE_DATE_EPOCH=1785283200`, `ABUILD_LAST_COMMIT=d80-weston-r10-aport`
(both influence .apk metadata only, not the ELF payloads).

Repository snapshot at fetch time (2026-08-15T06:37:12Z):

- `edge/main/aarch64` APKINDEX sha256
  `37c53afc30d1456fda1338b42427b54405424186a1f9cf9adb9e545b78b47d23`
- `edge/community/aarch64` APKINDEX sha256
  `d4846e2d4ee5e5d6a0f5b683013db43bc315374ad585ceddd30c32080dcaec07`

Products and full evidence (17 .apk files, signed index, per-package
closure digests, abuild log, as-run script) are archived in the private
build tree under `weston-r10-source-rebuild-20260815/`; the byte-identity
proof above is verifiable from public inputs alone.

## Defect found and fixed on the way

Two of the four tracked aport patches did not match the APKBUILD's own
`sha512sums` — `lmi-dedupe-legacy-plane-formats.patch` carried a mangled
hunk header and `lmi-phone-input-safearea.patch` an extra leading space on
context lines (copy-through-terminal corruption from the July recovery).
Any downloader building the aport would have failed at `abuild` checksum
verification. The pinned byte content (which is also what built the
device-validated d80 r10) was restored from the d80-era pmaports copies in
commits `a0324d5` and `24ef7a0`; all four patches now match the APKBUILD
pins.

## Gate status after this record

Of the closing path in the 2026-08-10 gate:

1. weston r10 from source — **done, byte-identical; no re-base needed.**
2. Snapshot pin for the D114 chain — still open; this record's APKINDEX
   digests and archived 455-package closure are the capture pattern to
   formalize (model: `config/lmi-p1/offline-cache-promotion.json`).
3. Scripted six-row build matching the embedded revision — still open.
4. Published `SHA256SUMS` + installer profile — still open.

Binary publication remains blocked until 2–4 close; the source tree is now
strictly stronger: the aport is buildable again and its central claim is
machine-verified.
