# Full-SSH offline-cache acquisition evidence — 2026-07-24

Scope: host-only acquisition and curation for the two OpenSSH client packages
required by the full-function SSH contract. No build, sudo, device query,
fastboot command, boot, or partition write was performed.

## Signed-index binding

The unchanged promotion profile binds the Alpine edge/main aarch64 index at
`work/cache_apk_aarch64/APKINDEX.066df28d.tar.gz`:

- size: `527520`
- SHA-256:
  `0aff7152104c42b71de9ad7c1dd12e7cef7ee34160c9bc9d0d9fba2eb889f61e`

That signed index contains these exact records:

| Package | Version | Architecture | `S` | `C:Q1` |
| --- | --- | --- | ---: | --- |
| `openssh-client-common` | `10.4_p1-r0` | `aarch64` | `837935` | `Q1phqMWwWrTFg1uMGDIzVQdoLM974=` |
| `openssh-client-default` | `10.4_p1-r0` | `aarch64` | `354366` | `Q1MUukrZ8sFq7pvYpDRAYopYCGXuI=` |

All dependencies named by those two records were already present in the old
curated closure. The expected closure delta was therefore exactly two APKs.

## Acquired bytes

The APKs were downloaded from the matching Alpine repository paths:

- `http://dl-cdn.alpinelinux.org/alpine/edge/main/aarch64/openssh-client-common-10.4_p1-r0.apk`
  - size: `837935`
  - SHA-256:
    `727f5007a2b89c61aac30b6925813bc31cf86af57b21431da644e94a30139b0d`
- `http://dl-cdn.alpinelinux.org/alpine/edge/main/aarch64/openssh-client-default-10.4_p1-r0.apk`
  - size: `354366`
  - SHA-256:
    `d86f2f44b72817b680628c7aa28f14d6a2f064064988acf06d6bc35fbd29a2ee`

The URL and raw SHA-256 are acquisition evidence, not independent trust
anchors. Repository authorization remains the profile-pinned signed index and
its exact `S` plus `C:Q1` package identity.

## Deterministic curation

The old acquisition and published caches were not modified. A new private
acquisition source was curated twice to two absent outputs with:

```text
python3 -B scripts/lmi_p1_cli.py curate-offline-cache \
  --profile <repo>/config/lmi-p1/offline-cache-promotion.json \
  --acquisition-root <repo>/private/lmi-p1/calibration/acquisition-full-ssh-20260724-source \
  --output <new-absent-private-output>
```

Both runs produced:

- aarch64 packages: `440`
- x86_64 packages: `135`
- acquisition members: `586`
- acquisition inventory SHA-256:
  `c453e0d920bc8a6d48dcaa59514758f07c941f6ee32814ff093b28579b95fd8c`
- canonical package names:
  - `openssh-client-common-10.4_p1-r0.a61a8c5b.apk`
  - `openssh-client-default-10.4_p1-r0.314ba4ad.apk`

## Calibration authorization gate

The existing production attestation is intentionally bound to the old
584-member acquisition and 588-member published cache. It must not be edited
with guessed output hashes.

The first private draft (`ssh-full-20260724-v1`) was rejected after independent
review found mutable callable seams, pathname rebinding gaps, and no durable
execution receipt. Its SHA-256 is
`38b8b57e2ce935141c4877254d806e4fa4ba9388486a780f23b8ba06930a8afc`;
it is stale against the corrected runtime and must not be installed.

The corrected prepare phase revalidated the old cache and new acquisition and
created this replacement private review draft:

- schema: `lmi-p1-offline-cache-calibration-authorization/v1`
- SHA-256:
  `2fa6ef38846bad1f720f53ad7351a7a7be86ad8a4c15dab07276911ecb29a482`
- authorized acquisition: 586 members,
  `c453e0d920bc8a6d48dcaa59514758f07c941f6ee32814ff093b28579b95fd8c`
- expected one-shot bundle:
  `private/lmi-p1/calibration/ssh-full-20260724-v2`
- local metadata: owner-only mode `0600`, one hard link, gitignored.

Execution now copies and holds the authorized acquisition through directory
descriptors, checks both promoted manifests member for member against that
snapshot, revalidates both outputs, and emits an authorization/runtime/output/
candidate hash receipt. The receipt deliberately claims output byte
equivalence only. The production promoter still reopens an ordinary pathname,
and same-UID process-memory or post-exit evidence modification is outside the
local assurance boundary.

The canonical authorization and bundle remain absent. Installing the reviewed
draft is an explicit human action; only then may execution use two fresh real
verifiers to derive the candidate replay and attestation for a second review.
