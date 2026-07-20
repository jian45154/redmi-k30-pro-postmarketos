# Offline cache quarantine and promotion

`scripts/lmi_p1/offline_cache.py` is the only cache-promotion implementation.
It performs no download, sudo, build, boot, flash, or device operation. The
acquisition root, new quarantine root, final published root, and trusted pinned
pmbootstrap root are explicit inputs. The canonical reviewed attestation is
derived from the real project root of the CLI that is actually executing; it
is not a caller-selected path. The profile and every outer trust pin are
derived from that attestation.

## Trust status

Production promotion uses `PinnedApkStaticVerifier`, bootstrapped through the
same primary-source trust path as pinned pmbootstrap
`pmb/helpers/apk_static.py`:

1. Pin a complete OpenSSL runtime closure outside the offline-cache manifest:
   OpenSSL, its ELF loader, `libssl`, `libcrypto`, `libc`, `libz`, and
   `libzstd`. Every record has one exact normalized symlink-free source path,
   byte size, SHA-256, and fixed SONAME destination basename.
2. Stable-copy those seven files into a new private runtime. Reject missing,
   extra, duplicate, linked, swapped, or changed members. Invoke OpenSSL only
   through the copied loader with `--inhibit-cache` and `--library-path`
   naming only that private closure. Validate the loader's dependency listing
   resolves every needed object into that closure. Set `OPENSSL_CONF=/dev/null`
   and `OPENSSL_MODULES` to an empty
   private directory; inherited loader/config/provider variables are absent.
   Revalidate every runtime byte and metadata identity after the version query
   and signature verification. Ubuntu package/version provenance is review
   metadata only and is never consulted as a runtime trust source.
3. From the already hash-pinned `apk-tools-static` APK, stream-extract only
   `sbin/apk.static` and its single
   `sbin/apk.static.SIGN.RSA.sha256.<key-basename>` member into a new private
   temporary directory. Reject duplicate, link, special, oversized, or
   unexpected members used by the bootstrap.
4. Require `<key-basename>` to match an explicitly pinned
   `pmbootstrap/pmb/data/keys/<key-basename>` regular file and verify its exact
   SHA-256.
5. Invoke only the isolated pinned OpenSSL runtime with `dgst -sha256 -verify ...
   -signature ...` over the extracted `apk.static` bytes.
6. Check the extracted binary's preapproved SHA-256 and version before it is
   executed. Record the verifier/OpenSSL trust facts in the outer seal policy
   or administrator attestation, not as unapproved fields in the v2 cache
   manifest.
7. Configure that verified `apk.static` with only the applicable pinned key
   when authenticating an index and the independently pinned HTTP bootstrap
   APK. Parse their metadata only after the cryptographic command succeeds.

The adapter authenticates each repository index with the bootstrapped
`apk.static verify` applet, an isolated root, and exactly one cache-local index
key. Repository APKs then use the identity verification path described below;
their builder signature is not a repository trust anchor. The independently
pinned HTTP `apk-tools-static` package is still checked with standalone
signature verification. Equal trusted key copies in the two architecture
caches are not ambiguous, while a reused basename with different key bytes is
rejected. Unsupported index/package formats and ambiguous signature members
fail closed.

The production CLI has no `--attestation`, OpenSSL, or `apk.static` pin
arguments. `load_promotion_authorization()` resolves the executing CLI and the
loaded `offline_cache.py`, requires both to be the canonical real files in the
same project tree, and reads only that tree's
`config/lmi-p1/offline-cache-promotion-attestation.json`. A copied or
caller-selected foreign project tree therefore cannot authorize the module
that is currently running. `promote_offline_cache()` requires the resulting
authorization whenever it constructs the production verifier. The explicit
verifier seam used by `tests/lmi_p1/test_offline_cache.py` is a fixture only
and is not exposed by the production CLI.

Promotion imports command implementations lazily. In a clean promotion
process the complete repository-local runtime inventory is exactly
`scripts/lmi_p1_cli.py`, `scripts/lmi_p1/__init__.py`,
`scripts/lmi_p1/common.py`, and `scripts/lmi_p1/offline_cache.py`; all four are
hash-pinned as the promotion runtime. The loader derives the inventory from
every already-loaded module whose real file is below this project tree, rather
than from only a hand-maintained allowlist. Adding an eager local
import makes the attestation fail closed until the newly executing file is
reviewed and pinned. Discovery covers the entire real project tree, not only
`scripts/`, so moving a helper elsewhere in the repository does not evade the
inventory. `scripts/lmi_p1/acquisition.py` is pinned separately as
the curation producer and is not imported by promotion.

The v3 attestation records the runtime assumption as CPython 3.14 with its
matching host standard library treated as trusted. The interpreter, standard
library and its native dependencies are not byte-attested as repository
producer files; the host OS/kernel remains part of the administrative trust
boundary. A different Python implementation or major/minor version fails the
recorded runtime check.

The reviewed production values and resulting cache binding are recorded as
canonical JSON in `config/lmi-p1/offline-cache-promotion-attestation.json`.
That record binds the promotion profile hash; trusted pmbootstrap commit and
tree; bootstrap signer key; curated acquisition's 584-member inventory digest;
the separate curation producer and complete dynamically discovered promotion
runtime hashes; the explicit interpreter/stdlib assumption; isolated OpenSSL
closure; extracted `apk.static`; and the published manifest, aggregate, and
exact 588-member count. The same curated acquisition was promoted a second
time as a reproducibility replay. It is not evidence of an independent
supply-chain acquisition. Its byte-identical result is recorded in canonical,
public-safe `config/lmi-p1/offline-cache-promotion-replay.json`, with no host
paths or credentials, and the attestation pins that report's hash.
`tests/lmi_p1/test_promotion_attestation.py` enforces every cross-binding.

## Preapproved promotion profile

The profile is canonical sorted compact ASCII JSON plus one newline. Its exact
top-level shape is:

```text
schema = lmi-p1-offline-cache-promotion/v1
pins = {pmbootstrap, pmaports}
repositories = eight exact records (four locked URLs x aarch64/x86_64)
http_artifacts = one exact apk-tools-static record
distfiles = one exact kernel distfile record
```

The pmbootstrap pin contains `commit`, `version`, and `work_version` (exactly
8). The pmaports pin contains `commit`, `tree`, and channel `edge`. Repository
records pin URL, architecture, pmbootstrap-derived index path, size, SHA-256,
cache-local signer-key path, and signer-key SHA-256. The kernel record pins its
URL, cache path, size, SHA-256, and the reviewed kernel APKBUILD SHA-512.

The production repositories are exactly:

```text
http://dl-cdn.alpinelinux.org/alpine/edge/community
http://dl-cdn.alpinelinux.org/alpine/edge/main
http://dl-cdn.alpinelinux.org/alpine/edge/testing
http://mirror.postmarketos.org/postmarketos/main
```

`/postmarketos/master` is not accepted. The pinned pmaports checkout uses
`edge.branch_pmaports=main`.

## Accepted acquisition layout

The acquisition root must have exactly these children:

```text
version
cache_apk_aarch64/
cache_apk_x86_64/
cache_http/
cache_distfiles/
```

`version` must contain exactly `8\n`. Each APK cache must contain exactly its
four profile-pinned `APKINDEX.<url-sha1-prefix>.tar.gz` files plus the external
`.apk` closure. `cache_http` contains only the pinned apk-tools-static package,
and `cache_distfiles` contains only the pinned kernel tarball.

The acquisition must not contain `config_apk_keys`, chroots, package outputs,
ccache, git/go/rust caches, logs, FIFOs, sockets, devices, symlinks, hardlinks,
group/world-writable content, `cache_http/APKINDEX_*` copies, alternate index
names, or any other entry. The inspected
`/tmp/lmi-p1-acquire.0BUXiUi4/work-proot-chroot2` contains several such stale
or mutable entries and is evidence only; it must not be promoted.

Signer keys never come from acquisition `config_apk_keys`. Each distinct
repository signer is copied with no-follow streaming from the explicit pinned
pmbootstrap tree into its profile path under `work/cache_apk_<architecture>/`.
The copied basename and SHA-256 must match the authenticated index signature.
An HTTP artifact may reference an existing copied repository key. Reused key
paths are one classified cache member, not duplicate content.

## Quarantine and manifest

The quarantine and published roots must be absent, normalized absolute sibling
paths beneath the same real private directory. That parent must be owned by the
effective UID and have mode `0700`. Promotion creates quarantine as `0700`;
creates all cache directories as `0700`; and creates files and the manifest as
`0600`. Every source file is opened with no-follow semantics, stream-copied
without reflinks, fsynced, and independently rehashed. A failed gate leaves
quarantine unpublished for inspection. Before quarantine is created,
production also rehashes the curation-compatible acquisition inventory and
verifies the attested trusted pmbootstrap `HEAD` commit/tree and signer key.

Before the final full manifest validation, promotion opens and holds a file
descriptor for the private parent and another for the quarantine directory,
binding both to their device/inode, mode, and owner. Immediately before
publication it rechecks those bindings, compares schema, manifest SHA-256,
aggregate SHA-256, and member count to the attested output, and rechecks the
trusted checkout and key. Publication uses Linux
`renameat2(RENAME_NOREPLACE)` relative to the held parent descriptor. It then
requires the published pathname to name the held, validated quarantine inode,
fsyncs the parent, and checks the binding again. A source-path substitution is
rejected and the no-replace rename is rolled back so no unverified final name
remains.

This boundary excludes other UIDs through the owner-only parent and detects
ordinary pathname/inode substitution. It does not claim to defeat a malicious
process running concurrently with the same effective UID: that process can
mutate files and directory entries owned by the promoter, including disrupting
rollback. Production promotion must therefore run under a dedicated
administrative UID (or otherwise exclusive root context) with no untrusted
same-UID process active. Such a same-UID adversary is outside this boundary.

`offline-cache.manifest.json` uses
`schema = lmi-p1-offline-cache/v2` and has exactly:

```text
schema, pins, repositories, external_apks, http_artifacts,
distfiles, members, aggregate_sha256
```

Records use only the approved fields. Arrays are unique and sorted by:

- repositories: `(architecture, url)`;
- external APKs: `(architecture, name, version, path)`;
- HTTP artifacts: `(kind, name, version, url, path)`;
- distfiles: `(url, path)`;
- members: `path`.

Each external APK record distinguishes the repository trust chain from package
builder provenance. It records `index_sha256`, canonical
`apkindex_checksum` (`C:Q1...`), `index_signer_key_path`, and
`index_signer_key_sha256`; `builder_signer` is copied from the APK signature
member as non-authorizing provenance only. A builder signer is never required
to equal the repository index signer and is never looked up in the trusted key
set.

Every member is a regular file below `work/`. `work/version` is bound by the
work-version pin. Every other member is classified exactly once as an index,
distinct cache-local signer key, external APK, HTTP artifact, or distfile;
signer references may reuse the already classified key. Promotion first
cryptographically verifies every pinned APKINDEX with its exact repository
key. Only those verified indexes can authorize repository APKs. It then parses
each APK v2 control member and requires one unique repository binding by
package name/version/cache architecture, exact indexed `S` size, and exact
`C:Q1` identity (SHA-1 of the raw control gzip member). The authenticated
control member's SHA-256 `datahash` must also match the raw data member. This is
apk-tools' repository fetch/install `APK_SIGN_VERIFY_IDENTITY` trust path; it
does not use standalone `apk verify`, whose package-signer trust behavior is a
different operation. Missing, ambiguous, path-like, or malformed builder
signature members still fail as malformed provenance. The manifest records the
repository/cache architecture (`aarch64` or `x86_64`); an authenticated
`noarch` APK is permitted in either cache.

The one HTTP `apk-tools-static` bootstrap APK remains separate: its exact
size/SHA-256, package identity, package signer key, embedded `apk.static`
signature, extracted binary size/SHA-256, complete isolated OpenSSL runtime and
version, and final `apk.static --version` are independently pinned and
verified. Repository APK
builder signer provenance cannot authorize this bootstrap path.

The aggregate digest is SHA-256 of the canonical manifest with only the
top-level `aggregate_sha256` field omitted. Canonical encoding is sorted,
compact, ASCII JSON plus exactly one newline. The full manifest uses the same
encoding. `read_offline_cache_manifest()` revalidates canonical bytes, schema,
aggregate, classification, directory layout, modes, links, sizes, and every
member SHA-256, and can additionally bind it to the exact promotion profile and
external pinned pmbootstrap key bytes without importing seal/build modules.
