# D114 P2 image regeneration and the content-determinism result — 2026-08-15

**Archived evidence — do not execute commands from this file.**

The July injected/assembled artifacts (`a91a2090…` rootfs, `77ff1993…`
sparse) no longer existed on disk. On 2026-08-15 the full fail-closed
pipeline — `launch_inject_rootfs_candidate.sh --wsl-root` →
`assemble_userdata_image.py` — was re-run from the unchanged pinned inputs
(candidate `d331433a…`, baseline raw `33067d69…`, the two attested APKs)
after re-pinning the drifted host-tool identities (libc6
2.43-2ubuntu2.3: libc/ld-linux/libm; wsl.exe 2026-08-12; all
provenance-verified — commit `3209c2d`).

## Outputs

| artifact | sha256 |
| --- | --- |
| injected `rootfs.ext4` (run 1) | `00fcbb836bebe8fd1b2e06a0c84d3d5f0e4922bac62aad2b5fb822afcf0fbcfa` |
| injected `rootfs.ext4` (run 2, canonical) | `54b972ed0aec411c03f23f3aa088f45902e48fcdfe82f71ecf68b66e621daf4b` |
| assembled `userdata.raw` | `c4b7e4301ab80e383abf113e96224fe0797d76cd6bfcf31549df899cc134bf59` |
| assembled `userdata.android-sparse.img` | `483df5d627d4203887655128e90fe81a5e4df598f84837f2afebefc7b0706b38` |

## The determinism result

Two consecutive injector runs from identical inputs produced **different
whole-ext4 hashes but identical content-level attestation values** — all
five inner output pins matched exactly across runs:

- `filesystem_delta_sha256 d31f9581…`
- `installed_db_sha256 354089bc…`
- `geometry_sha256 613a7ae8…`
- `key_inventory_sha256 05d870fb…`
- `p2_package_record_sha256 40c0dbd0…`

and the five pinned session components inside the regenerated rootfs are
byte-exact (`source-lock.json runtime.component_sha256`: the weston r10
trio and both six-row binaries — the same values independently reproduced
from public source the same day).

Conclusion for the verification model: **injection is
content-deterministic; the whole-image hash is per-run** (ext4 metadata
carries run timestamps). July's `a91a2090…`/`77ff1993…` are therefore
one-time artifact identities — historically real (they are what was
flashed and validated on 2026-07-24) but not re-derivable, exactly like
today's `54b972ed…`/`483df5d6…`. Whole-image pins belong in per-deploy
records (profiles, deploy locks); durable verification claims belong at
the content level (delta, db, component hashes). The frozen WSL r2 deploy
lock and `deploy_userdata_wsl.py` contract keep the July values as the
historical record of that deploy and are intentionally not rewritten.

## Relation to the reproducibility gate

Together with the same-day byte-identical source reproductions (weston
r10, six-row r2) this replaces gap 6's "nothing to verify against" with a
concrete model: a downloader verifies content (components, delta, package
db) rather than a whole-image hash; an image releaser records the per-run
image hash in `SHA256SUMS` at publication time. Binary publication of this
particular userdata remains blocked for the credential-sanitization reason
recorded on 2026-08-15 (the embedded account password hash), pending the
r145 clean rebuild.
