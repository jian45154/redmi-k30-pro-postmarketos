# lmi D114 P2 r1 six-row readiness — 2026-07-22

> **Archived evidence — do not execute commands from this file.**

## Current verdict

The source, package recipes, offline injector, userdata assembler, and guarded
deployment tooling are ready for review. The current binary candidate is **not
approved for a public release or a device write**.

The historical D114 userdata remains a private hardware-test baseline. Its P1
boot filesystem contains a locally built `linux-xiaomi-lmi-4.19.325-r9`
payload whose APK records `commit=-dirty`, while the public package recipe is
still r8. The P2 filesystem also contains locally built packages without an
exact public corresponding-source closure. A GitHub Release must therefore use
a fresh clean-source boot/userdata pair, not re-label the historical D114
bytes.

## Six-row terminal keyboard contract

The r1 source and static verifier bind this exact 12-column layout:

| Row | Keys |
| --- | --- |
| 1 | `Esc` `Tab` `Ctrl` `Shift` `Backspace` |
| 2 | `1` `2` `3` `4` `5` `6` `7` `8` `9` `0` `-` `=` |
| 3 | `q` `w` `e` `r` `t` `y` `u` `i` `o` `p` `[` `]` |
| 4 | `a` `s` `d` `f` `g` `h` `j` `k` `l` `;` `'` `Enter` |
| 5 | `z` `x` `c` `v` `b` `n` `m` `,` `.` `/` `\` `Shift` |
| 6 | eight-column `Space`, then `←` `↑` `↓` `→` |

The backslash key decodes to one literal `\` and shifts to `|`. Both Shift
keys share the same modifier state. Ctrl is visibly latched and is consumed by
the next ordinary, Space, or dedicated terminal key. Esc, Tab, Backspace,
Enter, and the arrows send real keysyms through the terminal's shared encoder;
the arrows retain normal/application cursor mode semantics.

## Frozen r1 package inputs

- `lmi-weston-sixrow-clients-14.0.2-r1.apk`: 120,891 bytes,
  SHA-256 `ff8dbb02208959db4af9f1da735cb7b4f8765138388b6f7daebabce161fe208b`
- `device-xiaomi-lmi-terminal-0.1.0-r1.apk`: 8,768 bytes,
  SHA-256 `7cab262bd73b0bed23b5cc2b5b62d38c66ea715f49afa6b0ad7dd24246dd1db1`

These APKs are private build evidence, not repository payloads or release
assets. Their public sources and input locks live under
`files/lmi-weston-sixrow`, `files/lmi-p2-d114`, and the corresponding `config`
and `scripts` directories.

## Verification completed

- D114 host suite: 143 tests passed; one namespace probe was skipped only
  where the outer sandbox denied its disposable network namespace.
- Six-row host suite: 12 tests passed with the exact Weston 14.0.2 tarball;
  no tests were skipped.
- Full `scripts/59_release_static_ci.sh`: passed, including shell/Python syntax,
  installer, P1/P2/P2-D114/P3, six-row, documentation, and release safety lint.
- No injector, assembler, fastboot command, or device operation was performed
  as part of this source-readiness result.

## Gates before a binary prerelease

1. Commit and tag every source, patch, configuration, build recipe, lock, and
   test used by the build.
2. Replace the historical dirty P1/P2 inputs with a clean-source build. The
   boot image and rootfs modules must come from the same kernel package.
3. Replace the unproven prebuilt `lmi-qrtr-ns` input with a build from a pinned
   public source revision and include its license notice.
4. Freeze signed APK indexes and the complete binary/source-origin inventory;
   publish an SBOM, required notices, and corresponding-source assets.
5. Use a generic reproducible Kbuild user/host/timestamp. Do not binary-patch
   the historical `pmos@DESKTOP-JID71RJ` build identity.
6. Generate the final sparse userdata once, verify its expanded raw image,
   P1/P2 hashes, GPT geometry, free space, inactive journal, credentials, logs,
   keys, machine ID, and network state, then bind all results in an immutable
   manifest.
7. Perform fresh exact-hash hardware tests for boot, display, touch, every
   keyboard key, terminal control sequences, persistence, SSH, and Wi-Fi.

The eventual release must state that writing `userdata` destroys all existing
userdata, requires an unlocked Xiaomi Redmi K30 Pro (`lmi`), preserves the
tested stock `modem`, `persist`, and `super` layout, never relocks the
bootloader, never retries a failed write automatically, and grants no authority
to modify `boot`, `dtbo`, `vbmeta`, `super`, modem/EFS, or calibration
partitions.
