# D114 P2 six-row r2: byte-identical source reproduction — 2026-08-15

**Archived evidence — do not execute commands from this file.**

Result: **both embedded six-row binaries of the D114 P2 image were
reproduced byte-identically from published source** on 2026-08-15,
companion to the same-day weston r10 reproduction
(`docs/release/d114-p2-weston-r10-source-reproduction-2026-08-15.md`).
This closes the "unscripted six-row build" core of gap 4 of
`docs/release/d114-p2-reproducibility-gate-2026-08-10.md`: the build is
now scripted (`scripts/77_build_sixrow_r2_source.sh`) and the embedded
revision's source provenance is machine-verified.

## Reproduced components

Payloads hashed directly out of the freshly built
`lmi-weston-sixrow-clients-14.0.2-r2.apk`; expected values are
`runtime.component_sha256` of `config/lmi-p2-d114/source-lock.json` and
the payload whitelist of
`config/lmi-weston-sixrow/build-attestation-r2.json`:

| component | sha256 (built == pinned) |
| --- | --- |
| `usr/libexec/lmi-p2-d114/weston-keyboard-sixrow` | `d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a` |
| `usr/libexec/lmi-p2-d114/weston-terminal-sixrow` | `6602f7ac8e0c11892eec1d9db0411397e95f704a1655b94e0885a1220962a8cf` |

The whole-file .apk hash differs from the attested resigned artifact
(`8d2f2352…`), exactly as the r2 attestation's `claim_limit` predicts:
metadata and signature segments differ across rebuilds; the payload bytes
are what the image embeds and what is verified here.

## Source anchoring (resolves the pkgrel mismatch)

The image embeds six-row **r2** while the tracked
`files/lmi-weston-sixrow/APKBUILD` has moved to `pkgrel=3`. The r2 source
is anchored in published history: commit
`1fbbc708eede2a67e68235185f4f77d1336c20cb` (post-rewrite, reachable from
15 origin branches) carries the exact APKBUILD
(`a42ab2a6…`, matching `source.apkbuild_sha256` of the r2 attestation) and
the three r2 patches; the r2-era
`config/lmi-weston-sixrow/source-lock.json` at that commit matches the
attested `source_lock_sha256` (`263e3ca5…`). The build script extracts the
aport from that commit rather than the current tree, so the gate's
"the public tree does not even build the revision inside the pinned image"
no longer holds — the published repository does, from recorded history.

## Method

`scripts/77_build_sixrow_r2_source.sh`: build root materialized under
`unshare -r` from the recorded 199-package pmbootstrap edge closure — now
identity-pinned in `config/lmi-weston-sixrow/build-root-closure-r2.manifest`
— then `abuild -F -d` under `proot -0` + qemu-aarch64
(`PROOT_NO_SECCOMP=1`), per the r2 attestation's recorded method and
identical to the validated r4 flow. Toolchain from that closure:
gcc 15.2.0-r8, musl 1.2.6-r2, binutils 2.45.1-r1, meson 1.11.2-r0 —
the same versions Alpine edge still served on 2026-08-15, which is also
why the weston r10 rebuild against live edge reproduced July binaries
byte-identically.

Products and logs archived in the private build tree under
`sixrow-r2-source-reproduction-20260815/`.

## Residual limits

- The 199-package closure itself is not redistributed here (Alpine/pmOS
  binaries; rolling edge no longer serves every exact version). The
  manifest pins their identities; a downloader must source them from an
  Alpine mirror archive or rebuild them. This is the same class of residue
  the future snapshot pin (gate step 2) must close for the whole rootfs.
- `SOURCE_DATE_EPOCH`/`ABUILD_LAST_COMMIT` in the script affect .apk
  metadata only, not the verified payloads.

## Gate status after this record

1. weston r10 from source — done (2026-08-15, byte-identical).
2. Snapshot pin for the D114 chain — open;
   `artifacts/images/d114-p2-r2-most-complete-rootfs-packages.manifest`
   (frozen 1198-package rootfs set) and the closure manifests are the
   groundwork.
3. Six-row build scripted + embedded revision provenance — **done with
   this record.**
4. Published `SHA256SUMS` + installer profile — open.
