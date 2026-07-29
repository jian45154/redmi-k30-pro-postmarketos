# D114 P2 r3 terminal scrollback integration — 2026-07-24

## Scope and safety

This record covers host-only integration of the exact r3 six-row client APK,
rootfs injection, userdata assembly, and deploy-gate static validation. No
fastboot, adb, SSH, boot, reboot, device query, claim, authorization, or
partition write was performed. No r3 device profile containing a serial or
privacy nonce was created.

The input client APK was:

- `lmi-weston-sixrow-clients-14.0.2-r3.apk`
- SHA-256
  `9310963550ac26e28b187a3a1b0a202f9e917c8103a30e0a1dbaaf182626d010`
- installed terminal SHA-256
  `ed3cda9c8dcdcd197385d125c84e3fdaa0429790b1b166d62f6206c4f853cf24`
- installed keyboard SHA-256
  `d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a`

The rebuilt `device-xiaomi-lmi-terminal-0.1.0-r3.apk` was byte-identical
across two clean builds:

- SHA-256
  `55d0bfe3353fa34559b21f11319da87894d52efc94a7275c7a72b01d8816aeb6`
- size `8777`
- build attestation SHA-256
  `3889cce0de7d90e70fddcc7bd34b1d791d0b6878717b0b9667fcca1b684d0e48`

## Rootfs and userdata outputs

The injector reused the reviewed r10 base/candidate lineage and retained the
D110 filesystem UUID pairing. Its r3 output is:

- injected rootfs SHA-256
  `4384dee649d86278d1965211c1cb8ddd556a4386fca25b50ccfdff43869c1305`,
  size `2923429888`
- injection attestation SHA-256
  `81b47f382803570acfd72b3d2d4a9036beb6a1c0ae7637ffb72a2deb385f3836`,
  size `7187`
- installed packages:
  `device-xiaomi-lmi-terminal=0.1.0-r3` and
  `lmi-weston-sixrow-clients=14.0.2-r3`
- root UUID `f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f`, paired with D110 boot
  UUID `d4f78f7d-f5b5-4edc-94d5-ba5e6c877888`

The assembled userdata bundle is:

- raw SHA-256
  `beb380238056e599d5dcb0e03aab6917d057c97fa1e2044b8320fa4881af2114`,
  size `3436183552`
- Android sparse SHA-256
  `a88a7335f6e0d3fcaeeaf1b987c380b0d81e68a8886034acc3d0a12033792081`,
  size `2236696936`
- assembly attestation SHA-256
  `ab4bbe2a3bb1f3b843036c3489979ad6d2d395d26a400c0ed7d70e179fc000d6`,
  size `7234`

Sparse-to-raw round trip was byte-identical. GPT geometry and the non-root
prefix/suffix were retained. The distinct reviewed rollback remains:

- sparse SHA-256
  `1315e3a06ddff42e91f930f01b16a62ab30ab3d4f490e8e8e40d0af89c657279`,
  size `2269624624`
- round-trip raw SHA-256
  `33067d6954e28b88b78a79a6ba0f994c1b6aff5e77a664b726e5dbb6e90084d8`

## Deploy-gate hardening

The WSL production contract, policy, profile template, and postwrite binding
now name the r3 artifacts. The deploy policy SHA-256 is
`c6caffcac9c8dbd5635a1a7acc2b1c9512a193354084cbbc3d0aca1dfa52f8d1`.

The transport completion parser remains fail closed. It accepts a complete
strict `Sending sparse` / `Writing` pair sequence followed by the exact
`Finished. Total time` shape only when the whole ASCII transcript is present
on exactly one stream. This covers the observed Debian fastboot stdout
channel and the supported stderr channel. Mixed streams, noise, missing
fractions, missing final newline, non-ASCII output, nonzero exit, timeout,
and output limiting are rejected.

Both the combined `deploy-once` path and the split `execute` path now require
the caller to provide the exact values:

- operation `flash-userdata`
- sparse SHA-256
  `a88a7335f6e0d3fcaeeaf1b987c380b0d81e68a8886034acc3d0a12033792081`

The check occurs before any device query. The only prepared future operator
plan uses `deploy-once`; it is private, non-executable, and contains no serial
or authorization.

## Verification

Host-side verification completed:

- clean r3 package rebuilds: byte-identical
- source/generation/build-attestation focused tests: `12` passed
- injector focused tests: `53` passed, `1` environment skip
- assembly/runtime policy focused tests: `22` passed
- WSL deploy and postwrite focused tests: `47` passed
- legacy policy propagation and read-only postwrite tests: `48` passed
- hash consistency: `60` cross-file pins verified

The later single hardware attempt and direct touch-scroll observation are
recorded separately in
`notes/lmi-d114-p2-r3-terminal-scrollback-hardware-2026-07-24.md`. The
transport result remains outcome-unknown and was not retried; the hardware
note therefore does not convert this host integration record into a release
claim.
