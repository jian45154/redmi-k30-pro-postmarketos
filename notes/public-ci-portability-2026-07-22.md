# Public CI portability — 2026-07-22

The GitHub Actions workflow installed from
`docs/release/edge-release-checks.workflow.yml` had never run: it only
triggered on the stale `edge` branch. After retargeting it to `master` (plus
`edge`), the first real runs exposed that parts of the host test suites were
bound to the maintainer host. Run
[29895820596](https://github.com/jian45154/redmi-k30-pro-postmarketos/actions/runs/29895820596)
is the first fully green public execution of `scripts/59_release_static_ci.sh`.

## Policy applied

Production gate semantics were not changed. Tests whose fixtures need
maintainer-only resources now skip with an explicit reason on hosts that
lack them, and two environment variables restore hard failures in pinned
maintainer environments:

- `LMI_P1_REQUIRE_PINNED_FIXTURE_TOOLS=1` — P1 image fixtures (pinned
  e2fsprogs build).
- `LMI_REQUIRE_HOST_BOUND_FIXTURES=1` — P2-D114 host-bound fixtures
  (`tests/lmi_p2_d114/host_bound.py`).

## Host bindings found (and how each is handled)

1. **Attested interpreter** — the P1 promotion attestation binds CPython
   3.14; validator-invoking tests skip on other interpreters (the trust
   gate itself still fails closed everywhere).
2. **Pinned e2fsprogs** — P1 artifact-semantics fixtures build images with
   a hash-pinned mke2fs; unpinned hosts skip.
3. **`private/` material** — deploy fixtures (platform-tools archive),
   live-installer contracts, injector delta/ext4 fixtures (sixrow build
   APK), postwrite revalidation, and the hardware-helper safety tests all
   read gitignored `private/` inputs; absent → skip.
4. **Pinned host toolchains** — the sparse toolchain closure (loader/libc
   hashes) and `/usr/bin/fastboot` runtime differ per host; mismatch →
   skip. A behavioral canary also covers `stat`/`lsattr`/`getfattr`
   differences (the maintainer host runs uutils coreutils; GNU coreutils
   behaves differently).
5. **Functional tools** — the runner lacked `getfattr`; the workflow now
   installs `attr` (functional use, not hash-pinned, so installing is
   correct rather than skipping).

## Current public-run skip counts

`lmi_p1`: 53 skipped of 412; `lmi_p2`: 1 of 37; `lmi_p2_d114`: 66 of 186
(private-material and pinned-toolchain tests); remaining suites run in
full. Maintainer runs execute everything (0 skips) — verified locally the
same day.

## Diagnostic method worth keeping

The final root cause (delta fixtures reading the private sixrow APK) was
found by a temporary branch-push workflow running the fixture under
`bash -x` on the runner, then deleted. Silent `rc=1` failures from
fail-closed shell under `set -e` are otherwise hard to attribute remotely.
