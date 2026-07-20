# lmi P1 root boundary

Installation, seal import, activation, and build launch are four separate
operations. Nothing here boots or writes a phone. The production paths are
fixed; none of the root programs accepts a destination path.

## Root-owned installation

Create the roots once from a trusted administrator session:

```sh
sudo install -d -o root -g root -m 0700 /opt/lmi-p1
sudo install -d -o root -g root -m 0700 /opt/lmi-p1/seals
sudo install -d -o root -g root -m 0700 /etc/lmi-p1-builder
sudo install -d -o root -g root -m 0700 /var/lib/lmi-p1
sudo install -d -o root -g root -m 0700 /var/lib/lmi-p1/runs
sudo install -o root -g root -m 0755 scripts/lmi_p1_seal_installer.py /usr/local/sbin/lmi-p1-seal-installer
sudo install -o root -g root -m 0755 scripts/lmi_p1_root_launcher.py /usr/local/sbin/lmi-p1-root-launcher
sudo install -o root -g root -m 0755 scripts/lmi_p1/seal.py /usr/local/sbin/lmi-p1-policy-admin
```

The policy administrator is the exact standalone execution mode in `seal.py`;
it does not import the workspace when run with `-I -S -B`. Never grant a
sudoers rule for arbitrary Python arguments or a repository copy.

Create the `lmi-p1-builders` group and enroll only the intended unprivileged
builder account. Validate the reviewed launcher-only policy offline, have
`visudo` parse it, then install it:

```sh
/usr/bin/python3 -I -S -B config/lmi-p1/root-boundary/validate_sudoers.py
/usr/sbin/visudo -c -f config/lmi-p1/root-boundary/90-lmi-p1-root-launcher
sudo install -o root -g root -m 0440 config/lmi-p1/root-boundary/90-lmi-p1-root-launcher /etc/sudoers.d/90-lmi-p1-root-launcher
sudo /usr/sbin/visudo -c
```

That file grants `NOPASSWD` with explicit `NOSETENV` for exactly
`/usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-root-launcher`. Its
command-specific `!use_pty` is required so launcher fd 0 remains the regular
request file verified by the wrapper. It grants neither the seal installer nor
the policy administrator; those remain trusted-administrator-only operations.
The exact-byte validator checks this repository policy, while the final
whole-policy `visudo` check is also required because another sudoers file could
grant broader authority.

Record and compare the reviewed source hashes and installed hashes, then verify
metadata without following an unexpected launcher/installer symlink:

```sh
sha256sum scripts/lmi_p1_seal_installer.py scripts/lmi_p1_root_launcher.py scripts/lmi_p1/seal.py
sudo sha256sum /usr/local/sbin/lmi-p1-seal-installer /usr/local/sbin/lmi-p1-root-launcher /usr/local/sbin/lmi-p1-policy-admin
sudo stat -c '%U:%G %a %F %n' /usr/local/sbin/lmi-p1-seal-installer /usr/local/sbin/lmi-p1-root-launcher /usr/local/sbin/lmi-p1-policy-admin
```

The two hash lists must match in corresponding order; every stat line must say
`root:root 755 regular file`. Preserve those hashes in the build record.

The launcher also requires `/etc/lmi-p1-builder/python.pin.json` as `root:root
0600`. It is canonical JSON with exactly these fields and one final newline:

```json
{"path":"/usr/bin/python3.X","schema":"lmi-p1-python-pin/v1","sha256":"<64 lowercase hex>"}
```

`path` is the strict final `readlink -f /usr/bin/python3` result, not the
`/usr/bin/python3` symlink, and `sha256` is the digest of that regular file.
Generate it in a root-only temporary file, verify its canonical bytes, owner,
mode, resolved path and digest, fsync it, then atomically rename it into place.
A system Python update intentionally invalidates the pin until an administrator
reviews and replaces it.

## Pack and install an inactive seal

Unprivileged code calls `scripts.lmi_p1.seal.pack_seal_stream(stream, sources,
provenance)`. Write to a new `0600` regular file, flush and fsync it, and publish
it by atomic rename. The packer accepts only repository-native symlinks below
`project`, `pmbootstrap`, or `pmaports`. Their targets must be non-empty UTF-8
relative paths of at most 1024 bytes and 32 components, resolve lexically inside
the same top-level component, and name a manifest regular-file record through
real-directory ancestors. Absolute, escaping, dangling, chained, directory,
overlong, deep, and symlink-as-ancestor layouts fail closed. Hardlinks, special
files, group/world-writable regular inputs, xattrs, unstable metadata, and a
`source-lock.json` whose pmbootstrap or pmaports facts differ from manifest
provenance are rejected.

Use the repository driver to derive provenance and create the stream; do not
hand-assemble `SealProvenance` or pass caller-supplied Git/version/digest
claims. The output directory must already exist as an xattr-free, user-owned
`0700` real directory, and the output name must not exist:

```sh
mkdir -m 0700 /absolute/private-output
/usr/bin/python3 -I -S -B /absolute/repository/scripts/lmi_p1_seal_pack.py pack \
  --project /absolute/seal-inputs/project \
  --pmbootstrap /absolute/seal-inputs/pmbootstrap \
  --pmaports /absolute/seal-inputs/pmaports \
  --offline-cache /absolute/seal-inputs/offline-cache \
  --authorized-key /absolute/seal-inputs/authorized_key.pub \
  --source-lock /absolute/seal-inputs/source-lock.json \
  --generation 1 \
  --output /absolute/private-output/seal.stream
```

Run it only as the unprivileged builder and invoke the CLI with exactly
`/usr/bin/python3 -I -S -B` and no optimization. It fd-binds the non-user-owned,
non-writable `/usr/bin/git`, supplies a fixed environment, and never asks Git
status, diff, ignore, attributes, or clean filters whether a worktree is clean.
For project and pmbootstrap it parses the HEAD tree and stage-0 index, requires
the index to equal HEAD, then hashes the raw physical regular-file and symlink
bytes with Git blob framing and compares every path and executable bit to HEAD.
Untracked and ignored paths therefore fail identically, and a clean filter
cannot hide a changed physical file.

Prepare dedicated seal-input copies; do not strip administrative data from a
working checkout that you still use. Each copy must have a detached SHA-1 HEAD,
every reachable object locally present, no special index flags, and this exact
privacy-minimal `.git` top level:

```text
HEAD
config
index
objects/
refs/heads/
refs/tags/
```

`refs/heads` and `refs/tags` must be empty. There may be no logs/reflogs,
hooks, `info/attributes`, grafts, shallow state, alternate object stores,
packed refs, extra remotes, worktree configuration, includes, credential
helpers, HTTP extra headers, URL rewrites, or filter configuration. `HEAD` is
exactly the 40-lowercase-hex commit plus LF. `config` is exact ASCII bytes in
this form, with literal tab indentation and one final LF:

```ini
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = false
[remote "origin"]
	url = CANONICAL_URL
	fetch = +refs/heads/*:refs/remotes/origin/*
```

Replace `CANONICAL_URL` with exactly one of these label-specific values; no
case, port, suffix, userinfo, query, fragment, percent encoding, or transport
variation is accepted:

```text
project     https://github.com/jian45154/redmi-k30-pro-postmarketos.git
pmbootstrap https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git
pmaports    https://gitlab.postmarketos.org/postmarketOS/pmaports.git
```

The external `--source-lock` bytes must be identical to the physical
stage-0/HEAD file `project/config/lmi-p1/source-lock.json`; a merely equivalent
JSON document is rejected. The driver reads the pmbootstrap version from
tracked `pmb/__init__.py`, hashes raw tracked `pmbootstrap.py`, and compares both
with that lock.

A generated pmaports overlay is the sole allowed dirty tree. Its HEAD and index
must still equal the locked upstream commit. The shared build/pack validator
requires a canonical `.lmi-p1-stage.json`, all three reviewed initramfs patch
members, both downstream package `APKBUILD` files, the lmi `deviceinfo`, only
untracked regular mode-0644 overlay members below the two reviewed package
directories, exact SHA-256 for every deviation, and sector size 4096. Arbitrary
tracked changes, extra or ignored files, index drift, symlinks, hardlinks,
xattrs, mode changes, manifest tampering, and inventory races fail closed. The
driver re-derives all provenance after packing and prints only the policy id.

Publication uses a same-directory `O_EXCL|O_NOFOLLOW` temporary file, forces
`0600` and one link, rejects xattrs, fsyncs the complete file, and uses Linux
`renameat2(RENAME_NOREPLACE)` before fsyncing the parent. If that atomic
no-replace primitive is unavailable, the driver fails closed rather than
emulating it with a replacement-prone rename. Rejection removes its private
temporary and never overwrites a pre-existing or concurrently created name.
The publication boundary also catches `BaseException` failures and the
catchable INT, TERM, HUP, and QUIT signals. Cleanup blocks a second termination
signal, identifies temporary and renamed outputs by their opened inode, removes
only those owned names, and fsyncs the parent before propagating the failure.
After the final parent fsync and identity revalidation, signals are blocked at
an explicit commit point; a later termination can therefore leave only the
already durable, fully verified output, never an uncertain partial publication.

The deterministic stream is:

1. `LMI-P1-SEAL\0V3\n`;
2. an unsigned eight-byte big-endian canonical-manifest length;
3. canonical manifest bytes (sorted keys, compact separators, ASCII escaping,
   exactly one final newline);
4. raw bytes for every regular-file manifest record in sorted path order; and
5. immediate EOF.

Manifest schema 3 represents a symlink with `type: "symlink"`, canonical mode
`0777`, its exact UTF-8 `target`, target byte `size`, and SHA-256 of those target
bytes. Symlink targets have no separate stream body, so record type makes the
framing unambiguous and the canonical manifest binds every link byte.

The standalone installer accepts no arguments, requires root real/effective/
saved IDs, verifies its fixed installed copy, and requires stdin to be a bounded
single-link regular file. Install one inactive generation with:

```sh
sudo /usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-seal-installer < /absolute/path/to/seal.stream
```

It can only create `/opt/lmi-p1/seals/<policy_id>`. Extraction uses directory
file descriptors and `O_NOFOLLOW`, creates a validated symlink only with a
dirfd-relative `symlink` operation into an already opened real parent directory,
and immediately reverifies the link itself without following it. It enforces
byte/member/path/depth/per-file/total limits, validates types, modes, sizes,
SHA-256, source-lock provenance, and pmbootstrap entrypoint binding, fsyncs
files/directories, and rechecks the input fd identity and metadata before the
atomic generation rename. A rejected input race therefore cleans the partial
`.incoming-*` tree and publishes no generation. The installer never creates or
changes `/opt/lmi-p1/active-policy`.

The reviewed stream envelope is 200,000 members, 32 path components, 1024
UTF-8 bytes per path or symlink target, 32 target components, 4 GiB per file and
16 GiB total file data. The exact `offline-cache/offline-cache.manifest.json`
record is limited to 16 MiB when the stream manifest is accepted, before an
incoming generation is allocated or its payload is captured. File copying and
hashing remain streaming in 1 MiB blocks. V3 retains the fixed `offline-cache`
layout member. Its canonical v2 cache manifest binds the exact
eight repository indexes, cache-local signer copies, authenticated external
APK closure by indexed identity/size/`C:Q1`, non-authorizing builder signer
provenance, one pinned `apk-tools-static` artifact, one kernel distfile and
their aggregate digest. The source lock and seal provenance bind that manifest;
arbitrary cache paths, missing bootstrap inputs and extra mutable cache state
are rejected. See `offline-cache-promotion.md` for the quarantine/promotion
trust chain.

Verify the printed policy id before activation:

```sh
policy='<64 lowercase hex printed by installer>'
sudo test -d "/opt/lmi-p1/seals/$policy"
sudo test "$(stat -c '%U:%G %a %F' "/opt/lmi-p1/seals/$policy")" = 'root:root 700 directory'
sudo test "$(sha256sum "/opt/lmi-p1/seals/$policy/seal.manifest.json" | cut -d' ' -f1)" = "$policy"
```

The policy id is a self-hash of the exact manifest bytes, not provenance or an
approval. Before activation, a trusted administrator must review the manifest
and source lock, independently confirm their remotes, commits, trees, version,
entrypoint digest, generation, and input digests, and activate only that
reviewed policy id. Receiving a matching id from the unprivileged packer or
installer proves content addressing, not who reviewed or produced the inputs.

## Ordered V2 to V3 deployment

Manifest V2 is a read-only transition format. It has the exact fixed layout,
provenance and five-field directory/file records used before repository-native
links; it cannot contain a symlink record. The verifier, policy administrator
and launcher accept exact V2 and V3 seals so an already active V2 generation
remains buildable and can be verified inside the activation compare-and-swap.
The packer emits only schema 3, the installer accepts only the V3 stream magic
and schema 3, and ordinary `activate` refuses a V2 target.

Deploy in this order:

1. While the V2 policy remains active, install and independently hash-review the
   updated launcher and policy administrator that have strict V2/V3 readers.
2. Install and review the V3-only seal installer. Do not replace the active
   policy yet; verify that a launch using the existing V2 id still succeeds.
3. Pack and install the reviewed V3 generation, then inspect its canonical
   manifest, source lock and printed policy id as described above.
4. Activate the V3 id with the exact V2 id as `CURRENT`. The administrator holds
   one exclusive active-policy-parent lock while it verifies both generations,
   checks the expected id and generation ordering, and performs the atomic
   replacement; V2 verification does not acquire that lock recursively.
5. Keep the dual-reader launcher and policy administrator installed for the
   entire rollback window. Remove V2 compatibility only after no active or
   approved rollback generation uses schema 2.

Rollback from V3 to V2 is intentionally permitted only through `rollback`, with
the exact V3 current id and a fully verified, strictly older V2 generation. It
does not reinstall or import V2 data, and it does not permit V2 as a normal
activation target. After such a rollback, retain the dual-reader programs and
diagnose the V3 failure before attempting another V3 activation.

The frozen V3 policy ABI fingerprint is
`96aea3fd68aeeba23cd9955cf5996cdc3e6ae14518e2dccdb4c902316696c729`.
Tests recompute it from the canonical schema/layout/limits/provenance contract,
assert exact field cardinalities and run one hostile accept/reject corpus across
the producer, installer and launcher copies. This is the drift check for the
standalone duplicated validators; changing one copy without updating and
reviewing the contract fails the P1 suite.

## Activate or roll back

Initial activation explicitly asserts that no policy is active:

```sh
sudo /usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-policy-admin activate "$policy" none
```

An upgrade names both the new policy and the expected current policy:

```sh
sudo /usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-policy-admin activate "$new_policy" "$current_policy"
```

Both seals are fully verified, the activation target must use current schema 3,
and the new provenance generation must be strictly greater. A downgrade or V2
activation target is rejected by `activate`. Rollback is a separate
compare-and-swap action and requires a fully verified older V2 or V3 generation:

```sh
sudo /usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-policy-admin rollback "$older_policy" "$current_policy"
```

The administrator atomically replaces `/opt/lmi-p1/active-policy` with one
lowercase policy id plus newline, fsyncs its parent, and verifies the persisted
value before releasing the same exclusive directory lock.

## Launch contract

The wrapper creates and fsyncs a new single-link `0600` regular request file.
Its bytes are exactly `LMIR`, an unsigned four-byte big-endian payload length,
and canonical JSON (sorted keys, compact separators, ASCII escaping, exactly one
final newline). The payload is at most 4096 bytes and has exactly:

```json
{"policy_id":"<64 lowercase hex>","schema":"lmi-p1-build-request/v1","tag":"<safe tag>"}
```

After an administrator has independently reviewed the installed policy id and
the intended tag, create the frame in a separate operation. Do not automatically
turn the id printed by `pack` into a request:

```sh
/usr/bin/python3 -I -S -B /absolute/repository/scripts/lmi_p1_seal_pack.py request \
  --policy-id "$reviewed_policy" \
  --tag "$reviewed_tag" \
  --output /absolute/private-output/request.frame
```

The driver uses the launcher's encoder and parser for the exact canonical frame
and gives request files the same new-only, private, fsynced publication
guarantees as seal streams.

Invoke the installed launcher with no arguments and that open regular file on
stdin; do not use a pipe, FIFO, shell here-string, or subprocess `input=`:

```sh
sudo /usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-root-launcher < /absolute/path/to/request.frame
```

The launcher uses `pread` and stable `fstat` checks, so request input is bounded
and cannot wait for a writer. It closes inherited descriptors at or above 3,
replaces child stdin with `/dev/null`, clears supplementary groups, applies
umask `077`, resets signals and their mask, sets core/no-file limits, changes to
a private run directory, and supplies a fixed environment with private `HOME`
and `TMPDIR`. A nonblocking lock permits one build at a time. Setup failures
remove their partial run; before each build, only the eight newest validated run
directories (including the new run) are retained.

After verifying the installed launcher, Python pin, active policy, every seal
member (including exact no-follow symlink targets), provenance, generation and
source lock, it executes the resolved pinned interpreter target. The standalone
launcher repeats the schema-3 target bounds, component confinement, regular-file
target, and real-parent rules instead of trusting the producer or installer.
The verified project CLI receives a root-owned `0600` canonical plain-JSON
request copy. Caller environment, caller paths, argv, and pmbootstrap options do
not cross the boundary.

Residual operational limits: a power loss can leave a harmless root-owned
`.incoming-*` directory if cleanup cannot complete, and an executed build owns
its run until the next serialized launch performs retention. Root compromise,
filesystem corruption that defeats kernel `openat`/`O_NOFOLLOW` semantics, and
replacement of reviewed root-owned programs are outside this boundary.
The unprivileged producer also cannot defend its source trees, private output
directory, or just-published pathname from a malicious process running under
the same effective UID. Run it from a dedicated builder session with no other
same-UID writers; its no-follow, identity, and post-publication checks close
cross-account and accidental races, not the same-EUID trust boundary.

The Python that starts the installer and policy administrator remains part of
the root trusted computing base. A versioned path such as `/usr/bin/python3.X`
would pin only a pathname, not the executable bytes; checking a digest from
inside either Python program cannot establish trust in the interpreter already
executing that check. A true pre-execution content pin would require a separate
trusted native or measured-execution launcher and is not introduced here. The
launcher pin still binds the interpreter it later executes for the build, but
does not remove the system Python used to run the launcher's own verification
logic from the TCB. Treat system Python/package updates as an administrator
review event and re-check all installed program and interpreter hashes.
