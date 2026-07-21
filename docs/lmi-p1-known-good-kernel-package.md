# LMI P1 known-good kernel package

The sealed P1 builder selects a reconstructed package whose `boot/vmlinuz`
bytes match the kernel hash recorded by both the `D-v43` and `D-v46` image
manifests. It does not select a historical `D-v46` package, it does not select
the public D80 r9 package, and it does not change normal unsealed development
builds.

## Evidence boundary

The strongest direct runtime evidence is `D-v43`: its manifest records the
following kernel hash, and its archived hardware evidence records SSH and
Wi-Fi bring-up. The `D-v46` manifest records the same kernel hash, but no
separate `D-v46` runtime verification was found. Consequently, the evidence
transfer is limited to the identical kernel bytes; it does not validate the
complete `D-v46` image or its cleanup changes.

- recovered `boot/vmlinuz` SHA-256:
  `38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e`
- historical installed database SHA-256:
  `0cb29b13383b606e443ff803a3b5ceb55a8ce266951ff0b1ccd1600ecfc595c5`
- input r8 APK SHA-256:
  `67cbc5a543b425d3602ffa33b722fbf0379dcdbf184c5996c960576f16c91610`
  (size `17,418,119` bytes)

The public D80 r9 `vmlinuz` SHA-256 is
`4583ada334aec2e4602519f7559f8a86026681f2a41497438a649d38090e5428`.
That is useful P2 evidence, but it is not the observed P1 SSH-success kernel and
is deliberately absent from the P1 source lock.

The reconstructed package keeps the solver identity
`linux-xiaomi-lmi=4.19.325-r8`, which is required by the pinned P1 device
package. It distinguishes itself from the source r8 binary with origin
`linux-xiaomi-lmi-p1-known-good`, the filename suffix `p1-known-good`, and the
description `P1 reconstructed known-good v46 kernel; not the upstream r8
binary`. Here `v46` identifies the recovered kernel-byte baseline, not a claim
that the complete `D-v46` artifact was directly runtime-verified.

### Input r8 provenance limit

The source lock records only locally verifiable facts for the input r8 APK:
its APKv2 format, size, SHA-256, and the result obtained with the pinned
`apk.static`. Its acquisition URL, transport, archive/index binding, and signer
provenance were not preserved. Verification with the pinned apk-tools
3.0.6-r0 binary reports an untrusted signature, so the signature-member name
and a similarly named local public key are not accepted as signer evidence.

This APK is used only as a byte-locked donor for the DTB/DTBO and
`kernel.release` payload; its original `boot/vmlinuz` is replaced and every
resulting member is checked. Those content checks do not reconstruct missing
chain of custody. The unavailable acquisition and signer provenance blocks
release and device-safe claims. It does not by itself prevent a private,
owner-test build used to gather further evidence.

## Reproducible package

[`known_good_kernel.py`](../scripts/lmi_p1/known_good_kernel.py) uses the
pinned `apk.static` 3.0.6-r0 binary (SHA-256
`a6542dc1fdb6214be1ef462668241bfe91f301e9249c99c0c6c327269d5e5ce4`),
the source r8 APK, the recovered v46 `vmlinuz`, and a locally controlled APK
signing key. It creates the APK and status index twice and fails unless both
pairs are byte-identical. Payload hashes, historical Q1 checksums, modes,
APKv3 root ownership, signature verification, direct installation, and the
installed database are checked before output.

That double construction establishes deterministic regeneration only within
one invocation on the same host trust boundary and with the same input bytes
and signing key. It is not an independent cross-host reproducible-build
result. External commands receive a fixed environment containing only
`LC_ALL=C`, `PATH=/usr/bin:/bin`, the locked `SOURCE_DATE_EPOCH`, and `TZ=UTC`;
the script invokes `/usr/bin/unshare`, `/usr/bin/env`, and the caller-supplied
absolute `apk.static` path without PATH lookup. The Python interpreter, host
kernel/user-namespace behavior, `/usr/bin/unshare`, `/usr/bin/env`, filesystem,
and temporary-directory implementation remain host trust. The locked
`apk.static` bytes and the private signing key remain explicit input trust.

Run it with paths to those verified inputs and a matching local signing-key
pair:

```sh
python3 -m scripts.lmi_p1.known_good_kernel \
  --apk-static /path/to/pinned/apk.static \
  --source-apk /path/to/linux-xiaomi-lmi-4.19.325-r8.apk \
  --vmlinuz /path/to/recovered-v46/vmlinuz \
  --signing-key /path/to/local-signing-key.rsa \
  --signer-public-key /path/to/local-signing-key.rsa.pub \
  --output-directory /path/to/new-empty-output
```

The private signing key must remain outside the project, seal, package, logs,
and output directory. Only its public key is copied into the project artifact
set.

With the matching private key on the recorded host boundary, the observed
outputs are:

| Artifact | Size | SHA-256 |
| --- | ---: | --- |
| `linux-xiaomi-lmi-4.19.325-r8-p1-known-good.apk` | 17,418,891 | `01b199611407c100c621599bd3060084c19e1fd90f8e9df64cc10966f6949eb0` |
| `pmbootstrap-status-APKINDEX.tar.gz` | 332 | `62578fea929f40c9b8ee8a66d96eefb2daaf6b77fb86be52a240d2979d76fe3b` |
| `lmi-p1-known-good-kernel.rsa.pub` | 800 | `c42ba833751ab9ca164c506cd72c2c3b9a6079db09ebe2cf52838ae79e936736` |

All three files and every payload member are bound by
[`source-lock.json`](../config/lmi-p1/source-lock.json) under the strict nested
schema `lmi-p1-known-good-kernel-package/v2`.

## Sealed selection

For a sealed build, the builder performs this sequence:

1. Verify the normal P1 kernel recipe checksum, but expose the locked
   status-only APKINDEX so pmbootstrap recognizes r8 and skips rebuilding the
   kernel.
2. Build `postmarketos-initramfs` and `device-xiaomi-lmi`, then regenerate the
   normal signed local APKv2 index. The builder rejects an index that still
   advertises a kernel or lacks those freshly built packages.
3. Copy the locked APKv3 and public key into the private pmbootstrap work tree.
   Install by the exact staged host path
   `<work>/packages/edge/aarch64/linux-xiaomi-lmi-4.19.325-r8-p1-known-good.apk`
   and the exact `linux-xiaomi-lmi=4.19.325-r8` constraint. In the pinned clean
   pmbootstrap 3.11.1 production call chain, host `apk.static` applies the
   target through `--root`, so this argument must remain host-absolute; it is
   not `/mnt/pmbootstrap/packages/...`, which is the guest-chroot mount path.
   No `--allow-untrusted` path is used by the production builder.
4. After both install passes, require the exact package name, version,
   architecture, distinct origin, file inventory, APKv3 installed-database
   checksums, unique file ownership, root ownership, modes, and SHA-256 payload
   hashes. apk-tools records a direct APKv3 package in `world` with its package
   checksum; the builder accepts only the locked checksum
   `Q17Cf8DcVUIUw2n/xDNf7Pr9WKqpU=` and rewrites it to the reviewable exact
   version constraint `linux-xiaomi-lmi=4.19.325-r8` after each install pass.

The final `world` entry is only a name-and-version constraint. It cannot pin
the package origin, signer, or payload, so a later apk transaction may
substitute another trusted package having the same name and version. The
builder's exact origin, installed-database ownership/checksum, mode, and
SHA-256 checks attest the rootfs immediately after each build install pass;
they do not make that guarantee persistent after the resulting system is
updated. Release/device-safe use therefore needs an independently reviewed
update boundary or an equivalent post-update exact-content attestation.

The status-only index has `install_trust: false` in the source lock. It exists
only because the pinned pmbootstrap version parses APKv2 indexes while the
known-good package is APKv3. Package installation trust comes from the pinned
public key and the APKv3 signature. Unsealed builds retain the existing normal
source-build sequence.

The host-side selection check used the pinned pmbootstrap APKINDEX parser and
confirmed that the status index resolves `linux-xiaomi-lmi` to
`4.19.325-r8/aarch64`. A separate apk-tools 3.0.6 solver check advertised the
public r9 package in a repository and supplied the same three kernel arguments
that pmbootstrap produces: the bare package name, the exact r8 constraint, and
the direct known-good APK path. The solver installed exactly r8 with origin
`linux-xiaomi-lmi-p1-known-good`; the installed `boot/vmlinuz` retained SHA-256
`38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e`.

## Gate status

This mechanism is not a release GO assertion. Build-only GO still requires
the pinned pmbootstrap host-path call chain to remain covered by focused tests,
followed by a complete sealed build from the intended commit/seal with the
produced package, installed database, rootfs, and image checks passing. No
partial or interrupted build satisfies that gate.

Release GO remains blocked after a build-only success by the unavailable input
r8 acquisition/signer provenance, the final-world same-version substitution
boundary, the absence of separate `D-v46` runtime verification, and the normal
device evidence gates: reviewed artifact identity, explicit hardware approval,
incremental runtime results, and a verified recovery/rollback path.
