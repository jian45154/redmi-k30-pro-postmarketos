# Xiaomi lmi P1 SSH Recovery Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, archive, boot, and accept a source-audited P1 image for Xiaomi `lmi` that mounts its 4096-byte-sector rootfs, exposes stable USB RNDIS SSH, permits only pinned-key login, and survives reboot without losing data or host identity.

**Architecture:** A Python standard-library control plane stages pinned pmaports and D80 inputs in a repository-local work directory, invokes the pinned pmbootstrap CLI, applies the historical loop-device fix at pmaports source level, and emits fail-closed manifests. Candidate images are uploaded to a private GitHub Draft Release and downloaded into a fresh directory before one manifest-bound fastboot executor may touch `userdata`, temporarily boot, or write the uniquely resolved non-A/B `boot` partition. Runtime acceptance uses TOFU only for the first direct USB host-key capture, pins that key thereafter, proves negative SSH cases and persistence, then publishes an immutable release only after a second fresh-download verification.

**Tech Stack:** Python 3 standard library and `unittest`; Bash only for reviewed package payloads; pmbootstrap `3.11.1` at commit `ce76febabd983db6445fa9a8b75d601970b2f436`; pmaports at `6fb3a1e5eb21c809891645a2ba5ae11fa788e032`; Alpine/OpenRC/OpenSSH; Android boot image v2; a source-locked WSL verifier using Python, util-linux, e2fsprogs, qemu-user-static, and OpenSSH tools; `zstd`; Windows platform-tools fastboot; GitHub CLI and REST API `2026-03-10`.

## Global Constraints

- The target is exactly one unlocked `product=lmi`; any second device, missing variable, timeout, or contradictory result is a hard failure.
- No phone boot, reboot, or write is allowed below `battery-voltage=3800`; the 2026-07-19 read-only snapshot was `3821` mV and must not be reused as a later decision.
- Never erase, format, relock, or write `super`, `vbmeta`, `dtbo`, `vendor_boot`, `init_boot`, modem/EFS, `persist`, calibration, or bootloader partitions.
- `userdata` is non-slot and reports size `0x1AC07FB000`; it may be written only from a freshly downloaded Draft asset after the D81/D82 evidence is bound as proof that current userdata is a disposable postmarketOS test image.
- This bootloader does not report `current-slot`, `slot-count`, or `has-slot:boot`; it reports only `partition-size:boot=0x8000000`, while `boot_a` and `boot_b` are absent. Persistent boot therefore resolves to the unique non-A/B target `boot` or fails.
- `direct-ram-boot` requires bootloader fastboot with `is-userspace=no`; `direct-persistent-boot` resolves only to `boot`; a future `copydown-fastbootd-boot` requires `is-userspace=yes` and is out of this P1 plan.
- The complete userdata image uses a nested GPT interpreted with 4096-byte logical sectors, contains exactly `pmOS_boot` and `pmOS_root`, and is exported non-sparse.
- P1 replays only seven exact D80 APK files under a local, one-shot `apk --no-network --allow-untrusted add "${replay_apks[@]}"` exception. It must not restore the lost signing key, add global trust, re-sign an old identity, or claim source reproducibility.
- Frozen APK versions are `device-xiaomi-lmi=1-r139`, `linux-xiaomi-lmi=4.19.325-r9`, and the selected Weston runtime packages at `14.0.2-r10`; source-restored successors begin at device r140, kernel r10, and Weston r11.
- The build uses only the host Ed25519 public key `/mnt/c/Users/microstar/.ssh/id_ed25519.pub`, whose expected fingerprint is `SHA256:MaX0FIvahR2a2THIjIYYfpbmTGVDk/8fwJ1a+ov3n9o`; no private key is copied.
- Root SSH, password authentication, and keyboard-interactive authentication are disabled. The `lmi` and `root` shadow fields contain only lock markers, and release images contain no SSH host private key.
- Privileged remote actions go only through the versioned allowlist in `files/lmi-p1/lmi-rootctl`; no general passwordless root shell is permitted.
- The P1 replay is not public-distributable until the exact r9 corresponding-source obligation is closed. Its stable full-image release is hosted in the private repository `jian45154/redmi-k30-pro-postmarketos-artifacts`; the public source repository records only non-secret manifests and hashes.
- Every hardware-tested byte comes from a new GitHub download directory. Published releases are immutable; assets and tag are never replaced, and a failed candidate advances from `lmi-p1-ssh-20260719-1` to `lmi-p1-ssh-20260719-2`.
- Runtime evidence from a different image identity, boot ID, root UUID, or release tag cannot satisfy a gate.

---

## File map

- `config/lmi-p1/source-lock.json`: machine-readable upstream, D80, tool, key-fingerprint, and distribution policy lock.
- `config/lmi-p1/verification-tools.json`: exact WSL verifier binary paths, package versions, version output, and binary SHA-256 lock.
- `config/lmi-p1/userdata-disposition.json`: auditable proof that the currently installed userdata is the disposable D80 postmarketOS test image rather than unbacked Android user data.
- `scripts/lmi_p1/common.py`: subprocess, SHA-256, JSON, timeout, redaction, and atomic-output primitives.
- `scripts/lmi_p1/inputs.py`: safe D80 download/extraction and exact-member verification.
- `scripts/lmi_p1/pmaports.py`: pinned pmaports staging, local overlay copy, and source-patch application.
- `scripts/lmi_p1/build.py`: isolated pmbootstrap replay and security finalization orchestration.
- `scripts/lmi_p1/image.py`: boot/rootfs/package/security verification and manifest construction.
- `scripts/lmi_p1/bundle.py`: clean bundle creation, zstd/split transport, and offline restoration.
- `scripts/lmi_p1/github_release.py`: repository visibility, immutability, Draft upload, asset digest, publish, and attestation gates.
- `scripts/lmi_p1/fastboot.py`: unique-device fastboot parser, route resolver, preflight, and exact action executor.
- `scripts/lmi_p1/ssh_accept.py`: strict SSH/runtime/persistence acceptance and redacted evidence.
- `scripts/lmi_p1_cli.py`: one argparse entry point exposing the modules without policy duplication.
- `files/lmi-p1/*`: rootfs security policy, release identity, and audited root helper installed by the finalizer.
- `patches/postmarketos-initramfs/0001-lmi-handle-4096-sector-loop-partitions.patch`: source-level replacement for the historical post-export ramdisk mutation.
- `tests/lmi_p1/*`: standard-library unit and fake-tool integration tests.

### Task 1: Common primitives and immutable D80 input lock

**Files:**
- Create: `config/lmi-p1/source-lock.json`
- Create: `config/lmi-p1/userdata-disposition.json`
- Create: `scripts/lmi_p1/__init__.py`
- Create: `scripts/lmi_p1/common.py`
- Create: `scripts/lmi_p1/inputs.py`
- Create: `tests/lmi_p1/test_common.py`
- Create: `tests/lmi_p1/test_inputs.py`
- Modify: `.gitignore`

**Interfaces:**
- Consumes: local filesystem paths and HTTPS URLs from `source-lock.json`.
- Produces: `sha256_file(path: Path) -> str`, `run(argv: Sequence[str], timeout: int, cwd: Path | None = None, env: Mapping[str, str] | None = None, check: bool = True, sensitive_values: Sequence[str] = ()) -> subprocess.CompletedProcess[str]`, `write_json(path: Path, value: object) -> None`, and `prepare_inputs(lock_path: Path, cache_dir: Path) -> Path` returning the verified extracted D80 directory.

- [ ] **Step 1: Write failing primitive and archive-safety tests**

  Test exact SHA computation, atomic JSON key sorting, timeout conversion to `GateError`, redaction of GitHub tokens/private-key blocks and a synthetic runtime-injected device serial, rejection of empty sensitive values, rejection of `../escape` and absolute tar members, outer hash mismatch, inner `SHA256SUMS` mismatch, a missing required APK, and a fully valid local `file://` archive. Neither production code nor tests may embed the real serial; committed identity uses only its SHA-256. The valid fixture must contain all seven filenames and hashes as zero-byte or test-payload files with a generated internal checksum file; the production lock remains independent from fixture hashes.

  ```python
  class InputTests(unittest.TestCase):
      def test_rejects_parent_traversal(self):
          with self.assertRaisesRegex(GateError, "unsafe archive member"):
              safe_extract(self.make_tar({"../escape": b"x"}), self.out)

      def test_outer_hash_is_checked_before_extract(self):
          lock = self.lock_for(self.make_tar({"SHA256SUMS": b""}), sha="0" * 64)
          with self.assertRaisesRegex(GateError, "outer sha256 mismatch"):
              prepare_inputs(lock, self.cache)

      def test_valid_archive_is_verified(self):
          extracted = prepare_inputs(self.valid_lock(), self.cache)
          self.assertEqual((extracted / "device-xiaomi-lmi-1-r139.apk").read_bytes(), b"device")
  ```

- [ ] **Step 2: Run the focused tests and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_common tests.lmi_p1.test_inputs -v`

  Expected: import failures for `scripts.lmi_p1.common` and `scripts.lmi_p1.inputs`.

- [ ] **Step 3: Implement the primitives and safe input preparation**

  `common.py` must define `GateError`, stream file hashes in 1 MiB blocks, call `subprocess.run(list(argv), text=True, capture_output=True, timeout=timeout, cwd=cwd, env=env, check=False)`, never invoke a shell, and replace pattern secrets plus each explicitly supplied non-empty `sensitive_values` member before including argv/stdout/stderr in exceptions. Hardware stages discover the unique serial at runtime, verify its committed SHA-256, and pass it only through this redaction boundary. `write_json` writes to a sibling temporary file, `fsync`s it, then calls `os.replace`.

  `inputs.py` must download to `*.partial`, hash before rename, and allow only ordinary files plus safe directory entries. It rejects symlinks, hardlinks, devices, FIFOs, and every other tar type; requires every normalized/resolved destination to remain below the extraction root; accepts either a flat archive or exactly one safe top-level wrapper directory; and returns the directory that directly contains `SHA256SUMS`. It verifies the lock-pinned SHA of that internal `SHA256SUMS`, requires the archive's complete regular-file set to equal the checksum-listed set plus `SHA256SUMS`, runs the full listed set through Python SHA-256 logic, and finally verifies the seven required APK hashes below. It must never trust a path supplied by the archive or restore archive ownership/unsafe modes.

  ```text
  ac00f22751607ae736cc26fbe72c1ede9c7d4d26f3af887ab0af800d5d9a3934  device-xiaomi-lmi-1-r139.apk
  678a94cb0d309c69e56e697533ad7f6fe9e9cbfc7dea5a5109ca55b36ee72f50  linux-xiaomi-lmi-4.19.325-r9.apk
  d62a5b63fb1d4a35cec06dedf62c86d7da67b4d796ea7c973ea92035622bf2e7  weston-14.0.2-r10.apk
  53e95028082b3ddecb5460aa100557971b368451f1f51f0b92b9484a6b76bc1b  weston-backend-drm-14.0.2-r10.apk
  1301346e110d7363a5fbe611f3ee282a3074ec2c52d884485ca961bb63835476  weston-clients-14.0.2-r10.apk
  b7bd061487f7ede3ebd102a3552d5596c87091146cf1d60a1a93c6ada847083e  weston-shell-desktop-14.0.2-r10.apk
  868eadb0171214945a34cec73da00a6b78d4a4e3e115611545f56bdb25a3d877  weston-terminal-14.0.2-r10.apk
  ```

  The production lock pins:

  ```json
  {
    "schema": 1,
    "pmbootstrap": {"commit": "ce76febabd983db6445fa9a8b75d601970b2f436", "version": "3.11.1"},
    "pmaports": {"commit": "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"},
    "d80": {
      "url": "https://github.com/jian45154/redmi-k30-pro-postmarketos/releases/download/d80-minimal-gui-osk-20260712/d80-minimal-gui-osk-20260712.tar.gz",
      "size": 19451357,
      "sha256": "f380eb275ef4ba8854dd3bc389f7113a701a29ab3fd302684b729e6ad64286ca",
      "inner_sha256sums_sha256": "561efa3a0e311e4bb5118f661f897da1c54838e2746f18e94665e711e0f85c33",
      "required_members": {
        "device-xiaomi-lmi-1-r139.apk": "ac00f22751607ae736cc26fbe72c1ede9c7d4d26f3af887ab0af800d5d9a3934",
        "linux-xiaomi-lmi-4.19.325-r9.apk": "678a94cb0d309c69e56e697533ad7f6fe9e9cbfc7dea5a5109ca55b36ee72f50",
        "weston-14.0.2-r10.apk": "d62a5b63fb1d4a35cec06dedf62c86d7da67b4d796ea7c973ea92035622bf2e7",
        "weston-backend-drm-14.0.2-r10.apk": "53e95028082b3ddecb5460aa100557971b368451f1f51f0b92b9484a6b76bc1b",
        "weston-clients-14.0.2-r10.apk": "1301346e110d7363a5fbe611f3ee282a3074ec2c52d884485ca961bb63835476",
        "weston-shell-desktop-14.0.2-r10.apk": "b7bd061487f7ede3ebd102a3552d5596c87091146cf1d60a1a93c6ada847083e",
        "weston-terminal-14.0.2-r10.apk": "868eadb0171214945a34cec73da00a6b78d4a4e3e115611545f56bdb25a3d877"
      }
    },
    "ssh": {
      "public_key_path": "/mnt/c/Users/microstar/.ssh/id_ed25519.pub",
      "fingerprint": "SHA256:MaX0FIvahR2a2THIjIYYfpbmTGVDk/8fwJ1a+ov3n9o"
    },
    "release": {
      "source_repo": "jian45154/redmi-k30-pro-postmarketos",
      "artifact_repo": "jian45154/redmi-k30-pro-postmarketos-artifacts",
      "visibility": "private",
      "public_allowed": false
    }
  }
  ```

  Before committing, independently run `sha256sum SHA256SUMS` and require the result to be exactly `561efa3a0e311e4bb5118f661f897da1c54838e2746f18e94665e711e0f85c33`; any difference is a hard failure.

  Add `userdata-disposition.json` with `schema=lmi-userdata-disposition/v1`, `product=lmi`, serial SHA-256 `0d71649b94add9a513413c424925341348208dd8a900ed8474c623cd47c2dfeb`, `classification=disposable-pmos-test-data`, prior D80 userdata SHA-256 `c005e29f2f924154152ff58b228d14e6c3a716cfbbbabf9995be198792b40d90`, D82 evidence member SHA-256 `4ac88bcfbfab1b12c9158f1bd2636626b019712ea2d41ade6c856a56c589f2d1`, and the exact basis: D81 deliberately replaced userdata with that D80 postmarketOS image; D82 successfully booted it and bound the same root UUID; the repository is an installation/porting workspace and the user has authorized replacement of this test image. State explicitly that this is not an Android personal-data backup and would be insufficient if the serial hash, prior image identity, or project history differed.

- [ ] **Step 4: Ignore only generated work and image outputs**

  Add `/.work/`, `/artifacts/builds/`, and `/artifacts/download-verification/` to `.gitignore`. Do not ignore manifests, source locks, tests, patches, or redacted evidence.

- [ ] **Step 5: Run tests and commit**

  Run: `python3 -m unittest tests.lmi_p1.test_common tests.lmi_p1.test_inputs -v`

  Expected: all tests pass.

  ```bash
  git add .gitignore config/lmi-p1/source-lock.json config/lmi-p1/userdata-disposition.json scripts/lmi_p1 tests/lmi_p1/test_common.py tests/lmi_p1/test_inputs.py
  git commit -m "feat: lock and verify lmi p1 inputs"
  ```

### Task 2: Pinned pmaports staging and source-level 4096-sector repair

**Files:**
- Create: `patches/postmarketos-initramfs/0001-lmi-handle-4096-sector-loop-partitions.patch`
- Create: `scripts/lmi_p1/pmaports.py`
- Create: `tests/lmi_p1/test_pmaports.py`
- Modify: `scripts/lmi_p1_cli.py`

**Interfaces:**
- Consumes: pinned pmaports source repository, project device/kernel overlays, and the patch file.
- Produces: `prepare_pmaports(source: Path, destination: Path, commit: str, overlay: Path, patch: Path) -> dict[str, str]`; the returned mapping records the staged commit and SHA-256 of every overlaid or patched file.

- [ ] **Step 1: Write failing staging tests**

  Create a minimal temporary Git repository containing `main/postmarketos-initramfs/APKBUILD`, `init_functions.sh`, and downstream destination directories. Assert wrong HEAD fails, a dirty destination fails, reusing a populated destination fails, overlay collisions fail, the patch changes `pkgrel=0` to `pkgrel=1`, and the staged script contains all markers:

  ```python
  self.assertIn('fdisk -b "$deviceinfo_rootfs_image_sector_size"', init_functions)
  self.assertIn('lmi_populate_block_devs()', init_functions)
  self.assertIn('mknod "/dev/$name" b', init_functions)
  self.assertIn('loop_part="/dev/${loop_name}p2"', init_functions)
  self.assertIn('echo add > "/sys/class/block/${loop_name}p2/uevent"', init_functions)
  self.assertIn('transition=switch_root-ready', init_2nd)
  ```

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_pmaports -v`

  Expected: import failure for `scripts.lmi_p1.pmaports`.

- [ ] **Step 3: Add the exact source patch**

  The patch must bump `postmarketos-initramfs` from `3.12.0-r0` to `r1`, make these three bounded changes inside `mount_subpartitions()`, and add the transition marker shown below immediately before `exec switch_root` in `init_2nd.sh`:

  ```sh
  lmi_populate_block_devs() {
      mkdir -p /dev /dev/disk/by-partlabel /dev/block/by-name
      for uevent in /sys/class/block/*/uevent; do
          [ -r "$uevent" ] || continue
          block="${uevent%/uevent}"
          name="${block##*/}"
          [ -r "/sys/class/block/$name/dev" ] || continue
          major_minor="$(cat "/sys/class/block/$name/dev")"
          [ -b "/dev/$name" ] ||
              mknod "/dev/$name" b "${major_minor%:*}" "${major_minor#*:}" 2>/dev/null || true
          partname="$(grep '^PARTNAME=' "$uevent" 2>/dev/null | cut -d= -f2- || true)"
          if [ -n "$partname" ] && [ -b "/dev/$name" ]; then
              ln -sf "../../$name" "/dev/disk/by-partlabel/$partname" 2>/dev/null || true
              ln -sf "../../$name" "/dev/block/by-name/$partname" 2>/dev/null || true
          fi
      done
  }

  # This call must be the first action in mount_subpartitions(), before the
  # userdata by-partlabel candidate list is evaluated.
  lmi_populate_block_devs 2>/dev/null || true

  if [ -n "$deviceinfo_rootfs_image_sector_size" ]; then
      part_count="$(fdisk -b "$deviceinfo_rootfs_image_sector_size" -l "$partition" 2>/dev/null | grep -cE '^ +[0-9]|^'"$partition")"
  else
      part_count="$(fdisk -l "$partition" 2>/dev/null | grep -cE '^ +[0-9]|^'"$partition")"
  fi

  loop_name="$(basename "$SUBPARTITION_LOOP")"
  loop_part="/dev/${loop_name}p2"
  for wait_try in 1 2 3 4 5; do
      [ -b "$loop_part" ] && break
      [ -e "/sys/class/block/${loop_name}p2/uevent" ] &&
          echo add > "/sys/class/block/${loop_name}p2/uevent"
      lmi_populate_block_devs 2>/dev/null || true
      sleep 0.2
  done
  if [ ! -b "$loop_part" ]; then
      echo "WARNING: $loop_part did not appear after losetup"
      losetup -d "$SUBPARTITION_LOOP"
      SUBPARTITION_DEV=""
      SUBPARTITION_LOOP=""
      continue
  fi
  ```

  Immediately before the existing `exec switch_root /sysroot "$init"`, write a persistent, atomically replaced marker while `/sysroot` is already mounted read-write:

  ```sh
  mkdir -p /sysroot/var/lib/lmi-p1
  {
      echo "transition=switch_root-ready"
      echo "boot_id=$(cat /proc/sys/kernel/random/boot_id)"
      echo "root_device=$PMOS_ROOT"
      echo "root_uuid=$root_uuid"
      echo "boot_uuid=$boot_uuid"
  } > /sysroot/var/lib/lmi-p1/initramfs-transition.new
  mv /sysroot/var/lib/lmi-p1/initramfs-transition.new \
      /sysroot/var/lib/lmi-p1/initramfs-transition
  sync
  ```

  A running OpenRC userspace with the same current boot ID in this marker proves that the marker was written at the end of initramfs and the subsequent `switch_root` reached the real rootfs.

  Refresh the APKBUILD SHA-512 entries for both `init_functions.sh` and `init_2nd.sh` to the patched values. Do not retain the post-export ramdisk rewrite from `scripts/21_build_pmos_v27_full_reproducible.sh` in the new P1 path.

- [ ] **Step 4: Implement fail-closed staging**

  Clone locally with `git clone --shared`, detach at the exact commit, verify it with `git rev-parse HEAD`, copy only `artifacts/wsl-pmaports/device-xiaomi-lmi` and `artifacts/wsl-pmaports/linux-xiaomi-lmi` to `device/downstream/`, apply the patch with `git apply --check` followed by `git apply`, and write `.lmi-p1-stage.json`. Existing destinations, symlinks escaping either tree, a non-empty output path, or any unexpected tracked modification must raise `GateError`.

- [ ] **Step 5: Run tests, static shell checks, and commit**

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_pmaports -v
  bash -n scripts/21_build_pmos_v27_full_reproducible.sh
  git diff --check
  ```

  Expected: tests pass, shell parses, and no whitespace errors.

  ```bash
  git add patches/postmarketos-initramfs scripts/lmi_p1/pmaports.py scripts/lmi_p1_cli.py tests/lmi_p1/test_pmaports.py
  git commit -m "fix: repair 4096 sector rootfs discovery at source"
  ```

### Task 3: P1 rootfs security payload and exact replay builder

**Files:**
- Create: `files/lmi-p1/sshd_config`
- Create: `files/lmi-p1/lmi-rootctl`
- Create: `files/lmi-p1/90-lmi-rootctl`
- Create: `files/lmi-p1/lmi-release-identity`
- Create: `files/lmi-p1/sudoers`
- Create: `files/lmi-p1/lmi-usb0.nmconnection`
- Create: `files/lmi-p1/90-lmi-usb0-takeover.conf`
- Create: `scripts/lmi_p1/build.py`
- Create: `tests/lmi_p1/test_build.py`
- Modify: `scripts/lmi_p1_cli.py`
- Modify: `scripts/70_build_downstream_ssh_wifi.sh`

**Interfaces:**
- Consumes: verified D80 directory, staged pmaports, Ed25519 public key, repository commit, and candidate tag.
- Produces: `build_candidate(ctx: BuildContext) -> BuildResult`, where `BuildResult` contains absolute `boot_img`, `userdata_img`, `vmlinuz`, `initramfs`, `dtb_dir`, package manifest, world file, build log, and identity file paths.

  ```python
  @dataclass(frozen=True)
  class BuildContext:
      repo: Path
      tag: str
      source_commit: str
      work: Path
      pmaports: Path
      d80: Path
      pmbootstrap: Path
      public_key: Path
      public_key_fingerprint: str

  @dataclass(frozen=True)
  class BuildResult:
      boot_img: Path
      userdata_img: Path
      vmlinuz: Path
      initramfs: Path
      dtb_dir: Path
      packages: Path
      world: Path
      build_log: Path
      identity: Path
  ```

- [ ] **Step 1: Write failing command-sequence and secret-policy tests**

  Use a fake pmbootstrap executable that appends JSON argv records. Assert every invocation contains explicit `-c`, `-w`, and `-p`; the temporary password is generated at runtime and is absent from repository files; `--zap` never occurs; the unsigned install first runs without `--allow-untrusted` and must fail, then exactly one command contains both `--no-network` and `--allow-untrusted`; all seven absolute APK paths are present; r107/r8 packages are quarantined before the second install; final export contains `--no-install`; and cleanup runs on exceptions.

  Add a repository scan test that rejects literal `147147`, `StrictHostKeyChecking=no`, `--clobber`, `fastboot erase`, `fastboot format`, or a fastboot write to a forbidden partition in all new P1 files.

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_build -v`

  Expected: import failure for `scripts.lmi_p1.build`.

- [ ] **Step 3: Implement the rootfs policy payload**

  `sshd_config` must contain only the following authentication policy plus normal logging/subsystem directives:

  ```text
  Port 22
  Protocol 2
  HostKey /etc/ssh/ssh_host_ed25519_key
  PermitRootLogin no
  PubkeyAuthentication yes
  PasswordAuthentication no
  KbdInteractiveAuthentication no
  AuthenticationMethods publickey
  AuthorizedKeysFile .ssh/authorized_keys
  AllowUsers lmi
  UsePAM yes
  X11Forwarding no
  AllowTcpForwarding no
  PermitTunnel no
  LogLevel VERBOSE
  Subsystem sftp internal-sftp
  ```

  `lmi-rootctl` accepts only `reboot`, `reboot-bootloader --confirm reboot-bootloader-lmi-p1`, `service sshd status`, and `service sshd restart --confirm restart-sshd-lmi-p1`. It validates exact argument counts, logs caller/action/image identity before and after each returning command with `/usr/bin/logger -t lmi-rootctl`, never invokes `sh -c` or `eval`, and invokes only absolute binaries. The bootloader action invokes `/sbin/reboot bootloader` and is covered by a fake-command unit test before hardware use. `90-lmi-rootctl` grants `lmi ALL=(root) NOPASSWD: /usr/sbin/lmi-rootctl` and no other command.

  `lmi-release-identity` is installed as mode 0644 and is populated with tag, source commit, boot UUID, root UUID, package versions, build UTC, and a non-circular `candidate_id`. Compute `candidate_id` as SHA-256 over the NUL-delimited tag, source commit, boot UUID, root UUID, and package-manifest SHA. The external manifest binds that ID to the final boot and rootfs hashes; the rootfs never attempts to embed its own hash.

- [ ] **Step 4: Implement the isolated two-pass replay**

  The builder creates `.work/lmi-p1/{config,work,pmaports,export}` from an empty candidate directory and verifies pmbootstrap executable version/commit. It writes a dedicated config with `device=xiaomi-lmi`, `ui=shelli`, `user=lmi`, `ssh_keys=True`, the exact public-key path, OpenRC, and the fixed dependency set. It generates a 32-byte URL-safe temporary password only because pmbootstrap requires one and redacts it from all copied logs.

  Execute this exact state machine:

  1. `checksum --verify` and `build` for patched `postmarketos-initramfs`, `linux-xiaomi-lmi`, and `device-xiaomi-lmi`.
  2. `install --no-image --no-fde --add evtest,pd-mapper,pd-mapper-openrc,seatd,seatd-openrc,weston-backend-drm,weston-clients,weston-shell-desktop,weston-terminal --password "$ephemeral_password"`.
  3. Move only r107/r8 APKs from the normal local repository into `packages/bootstrap-quarantine/`, run `pmbootstrap index`, copy the seven hash-verified D80 APKs to `packages/replay/aarch64/`, and hash them again.
  4. Run `apk --no-network add "${replay_apks[@]}"` without `--allow-untrusted`; proceed only if stderr identifies an untrusted signature and the rootfs installed-package manifest is unchanged.
  5. Run one `apk --no-network --allow-untrusted add "${replay_apks[@]}"` for the seven absolute replay paths. Verify no old key appeared under `/etc/apk/keys`, and verify installed/package policy/world identity constraints are r139/r9/r10.
  6. Run `install --no-fde --sector-size 4096 --no-sparse --password "$ephemeral_password"` without `--zap`.
  7. Mount the image only through `pmbootstrap chroot -r --image`, replace the SSH/rootctl/identity payloads, remove `/etc/ssh/ssh_host_*`, set both root and lmi shadow password fields exactly to `!`, verify one matching authorized key and its fingerprint, enable `sshd` and USB network in the default runlevel, and assert no generic sudo rule remains.
  8. Run `export "$empty_export_dir" --no-install`, then hash every output.

  Review correction requirements:

  - Validate staged pmaports as an exact detached tree: HEAD must equal the pinned commit; the index must be clean; tracked modifications plus ordinary and ignored untracked files must equal the hashed manifest inventory, with `.lmi-p1-stage.json` as the only unmanifested metadata file. Reject missing, extra, type-changed, or hash-mismatched members, and run the same validation again after copying into the candidate.
  - Accept only the pinned repository's tracked `pmbootstrap.py` blob. Make a fresh local no-hardlink clone inside the empty candidate, detach it at the pinned commit, verify the checkout is clean and the entrypoint blob matches, and invoke only that copy through `sys.executable -E -B` with all `PYTHON*`, `LD_PRELOAD`, and `LD_LIBRARY_PATH` injection variables removed. Every internal Git child must first remove all inherited `GIT_*` variables, then set `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, and `GIT_TERMINAL_PROMPT=0`; pmbootstrap itself receives that same sanitized Git base so its descendant Git calls cannot recover the hostile environment. Every direct Git argv binds the already-resolved repository with exact `-c safe.directory=...` and disables hooks, clone/checkout cannot execute hooks, and any pinned `.gitattributes` checkout filter fails closed before checkout. No network clone is allowed.
  - Keep root and `lmi` shadow fields exactly `!`, all password and keyboard-interactive authentication disabled, and use `UsePAM yes` so the installed PAM OpenSSH server still admits the locked `lmi` account for its sole Ed25519 key. Real OpenSSH acceptance remains a Task 8 runtime gate.
  - Replace `/etc/sudoers` with the exact sudo-rs-compatible `root ALL=(ALL) ALL` plus `@includedir /etc/sudoers.d` policy, remove `lmi` from `wheel`, retain only `90-lmi-rootctl`, remove all doas grants, and verify the effective file set, ownership, modes, group membership, and syntax with Alpine sudo-rs `/usr/bin/visudo -cf /etc/sudoers`.
  - Normalize `/etc/apk/world` to exact `name=version` pins for all seven replay packages, reject bare or conflicting replay entries after normalization and after the final install, and copy the verified pinned world into the image.
  - Install a root-owned mode-0600 NetworkManager keyfile bound to `usb0`, with autoconnect priority 100, `ipv4.method=shared`, `address1=172.16.42.1/24`, `never-default=true`, `shared-dhcp-range=172.16.42.2,172.16.42.2`, and IPv6 disabled. Also install exact root-owned mode-0644 `/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf` with `[device-lmi-usb0]`, `match-device=interface-name:usb0`, `managed=1`, and `keep-configuration=no`; this forces NetworkManager to replace the initramfs-era external `/16` configuration with the higher-priority persistent profile. Enable and verify NetworkManager in the default runlevel; shelli supplies NetworkManager and dnsmasq.
  - Treat pmbootstrap export entries as absolute symlinks. After shutdown, require the exact boot/rootfs/kernel/initramfs/DTB inventory, reject dangling, escaping, or extra entries, atomically replace every approved link with a copied regular file, reject hardlinks, and hash the complete materialized inventory.

  Add focused RED tests for each correction before production changes: unlisted tracked/ignored pmaports changes and post-copy mutation; ignored/wrong pmbootstrap entrypoints, Python environment sanitization, hostile Git environment/global hooks, explicit safe-directory argv, and checkout-filter rejection; exact PAM/sudo/world/keyfile/takeover policy; real-like absolute export links plus extra/escaping/dangling rejection and regular-file materialization.

  `scripts/70_build_downstream_ssh_wifi.sh` must lose its default password and become a compatibility wrapper that prints a deprecation notice and execs `python3 scripts/lmi_p1_cli.py build`; it must not contain old build logic.

- [ ] **Step 5: Run tests and commit**

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_build -v
  python3 -m unittest discover -s tests/lmi_p1 -v
  git grep -n -E '147147|StrictHostKeyChecking=no|--clobber' -- files/lmi-p1 scripts/lmi_p1 scripts/lmi_p1_cli.py scripts/70_build_downstream_ssh_wifi.sh && exit 1 || true
  ```

  Expected: all tests pass and the grep emits nothing.

  ```bash
  git add files/lmi-p1 scripts/lmi_p1 scripts/lmi_p1_cli.py scripts/70_build_downstream_ssh_wifi.sh tests/lmi_p1/test_build.py
  git commit -m "feat: build isolated secure lmi p1 replay"
  ```

### Task 4: Fail-closed boot, rootfs, package, and secret verifier

**Files:**
- Create: `config/lmi-p1/verification-tools.json`
- Create: `scripts/lmi_p1/image.py`
- Create: `tests/lmi_p1/test_image.py`
- Modify: `scripts/inspect_android_boot_images.py`
- Modify: `scripts/lmi_p1_cli.py`

**Interfaces:**
- Consumes: `BuildResult`, source lock, 128 MiB boot capacity, and expected key fingerprint.
- Produces: `verify_candidate(build: BuildResult, output: Path) -> dict[str, object]`, writing canonical `manifest.json`, `SHA256SUMS`, `packages.txt`, `world`, `static-verification.json`, and two role-bound boot files named `boot-ram.img` and `boot-persistent.img` with identical bytes but separate manifest entries.

- [ ] **Step 1: Write failing fixture-driven verifier tests**

  Factor the existing Android v2 parser into import-safe functions and test the exact 1660-byte v2 header, `header_size`, page size, every aligned component range, recovery-DTBO/DTB bounds, truncated/overlapping/trailing data, capacity, byte-exact `cmdline + extra_cmdline` decoding, UUID extraction, and role validation. Test a bounded stdlib gzip/newc reader against path traversal, duplicate names, hardlinks, symlinks, devices, oversized members/archive totals, truncation, and concatenated/trailing archives. Fake fixed-argv `fdisk`, `losetup`, `blkid`, `e2fsck`, `mount`, `umount`, qemu/chroot isolation, and initramfs inputs to cover wrong tool hashes/versions, non-root invocation, 512-sector rejection, one/three partitions, UUID mismatch, absent `loop.max_part=7`, absent initramfs source-fix markers, wrong package versions, NetworkManager older than 1.52, missing USB takeover policy, missing authorized key, host private key presence, password hashes, failed target-rootfs `sshd.pam -t/-T`, permissive sshd, extra sudo rules, cleanup failure, and a valid fixture.

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_image -v`

  Expected: missing verifier/parser APIs.

- [ ] **Step 3: Implement exact structural checks**

  Implement Android boot parsing directly from the upstream AOSP v2 layout: require magic, version 2, `header_size=1660`, page size 4096, total file size below `0x8000000`, non-empty kernel/ramdisk/DTB, legal optional-component sizes, and every page-aligned range fully contained without overlap. Decode the two fixed command-line arrays by byte concatenation before the first NUL; do not insert a separator that is absent from the image. Require `loop.max_part=7`, one `pmos_boot_uuid`, one `pmos_root_uuid`, and no conflicting duplicate.

  Read the gzip initramfs with bounded stdlib decompression and an in-memory, fail-closed `newc` parser; do not invoke `cpio` or extract attacker-controlled paths. Reject non-regular inspected targets, unsafe/duplicate names, hardlinks, devices, truncation, concatenated archives, trailing non-padding bytes, oversized members, and oversized decompressed totals. Require the patched `fdisk -b`, `mdev -s`, uevent rescan, and bounded loop0p2 wait markers from the parsed regular files.

  The verifier is invoked with fixed argv through `/mnt/c/Windows/System32/wsl.exe -d Ubuntu -u root -- ...`; its Python entry point immediately requires `geteuid()==0`. It validates every absolute tool path, package version, version output, and binary SHA-256 against `verification-tools.json` before consuming a candidate. The lock includes at least Python, util-linux `fdisk`/`losetup`/`mount`/`umount`/`unshare`, e2fsprogs `e2fsck`, qemu-aarch64-static, coreutils `chroot`, and OpenSSH `ssh-keygen`. No interactive `sudo`, PATH lookup, shell string, or unlocked host tool is permitted.

  Attach the userdata read-only with:

  ```bash
  /usr/sbin/losetup --find --show --partscan --read-only --direct-io=on --sector-size 4096 /absolute/candidate/xiaomi-lmi.img
  ```

  First run locked `fdisk -b 4096 -l IMAGE` against the ordinary image file and require exactly two GPT partitions. Attach only that resolved ordinary file, require the returned path to match `/dev/loop[0-9]+`, and prove both partition nodes belong to that exact loop device. Before mounting, run locked `e2fsck -fn` on both partitions and accept only status 0; status 1/2 is not a clean candidate and status 4 is uncorrected corruption. Require `blkid` labels `pmOS_boot` and `pmOS_root`, and match both UUIDs to the boot cmdline. Mount each explicit partition with `ro,noload,nodev,nosuid,noexec`; in one `finally` path, unmount only verifier-owned mountpoints in reverse order and detach only the exact returned loop device. Cleanup failure is itself a failed verification and must retain enough non-secret diagnostics for manual recovery.

  Inspect the mounted rootfs for exact replay package versions, `/etc/apk/world` identity constraints, target-rootfs NetworkManager version at least 1.52, the exact USB keyfile/takeover pair and permissions, default-runlevel `sshd`, RNDIS `0525:a4a2`, one expected authorized key, strict sshd policy, shadow fields exactly `!`, no host keys, no private key headers, no GitHub token patterns, no raw serial whose SHA-256 matches the runtime-bound target, and only the P1 sudoers allowlist.

  For OpenSSH semantic validation, create a verifier-owned ephemeral overlay above the read-only rootfs, place the locked static qemu binary and an ephemeral Ed25519 host key only in the overlay, and enter a new mount/PID/network namespace. Chroot to the merged view, drop to a non-root UID with no network, and run the target aarch64 `/usr/sbin/sshd.pam -t` plus `-T -C user=lmi,host=lmi,addr=172.16.42.2,laddr=172.16.42.1,lport=22` using the ephemeral key. Capture and compare the effective policy; never generate a host key in the candidate image or execute an unverified target binary outside that isolated context. Tear down the overlay/namespace scratch in the same bounded cleanup discipline. Task 8 still provides the authoritative real-login gate.

  Require `/etc/lmi-release-identity` to match the manifest's candidate ID, tag, source commit, UUIDs, and package versions; compare final image hashes only through the external canonical manifest. Hash the candidate before and after all verification and require byte identity.

- [ ] **Step 4: Emit canonical manifest and role-bound copies**

  The manifest schema is `lmi-stage-manifest/v1` and contains `status=candidate`, `stage=P1`, source/tool commits, distribution policy, original image hashes/sizes, partition geometry, UUIDs, package/world hashes, SSH key fingerprint, security results, and hardware routes:

  ```json
  {
    "hardware_routes": {
      "ram": {"artifact": "boot-ram.img", "role": "direct-ram-boot", "mode": "bootloader", "target": null},
      "persistent": {"artifact": "boot-persistent.img", "role": "direct-persistent-boot", "mode": "bootloader", "target": "boot"},
      "userdata": {"artifact": "xiaomi-lmi.img", "role": "userdata-rootfs", "mode": "bootloader", "target": "userdata"}
    }
  }
  ```

  The two boot files must hash identically to the verified export. No manifest permits one named artifact to carry two roles.

- [ ] **Step 5: Run tests and commit**

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_image -v
  python3 -m unittest discover -s tests/lmi_p1 -v
  git diff --check
  ```

  Expected: all tests pass.

  ```bash
  git add config/lmi-p1/verification-tools.json scripts/inspect_android_boot_images.py scripts/lmi_p1/image.py scripts/lmi_p1_cli.py tests/lmi_p1/test_image.py
  git commit -m "feat: verify lmi p1 images fail closed"
  ```

### Task 5: Complete-image bundle and offline round-trip verifier

**Files:**
- Create: `scripts/lmi_p1/bundle.py`
- Create: `tests/lmi_p1/test_bundle.py`
- Modify: `scripts/lmi_p1_cli.py`
- Modify: `artifacts/images/README.md`

**Interfaces:**
- Consumes: verified candidate directory and tag.
- Produces: `make_bundle(candidate: Path, bundle: Path, tag: str) -> Path` and `verify_bundle(bundle: Path, restored: Path) -> dict[str, Path]`; the restored mapping points to exact raw boot and userdata bytes used later.

- [ ] **Step 1: Write failing clean-room bundle tests**

  Test refusal of a pre-existing/non-empty output directory, missing boot or userdata, invalid asset names, modified inputs after manifest creation, a compressed asset at or above 2,000,000,000 bytes, missing/extra/reordered split parts, corrupt zstd, incomplete `SHA256SUMS`, and successful restoration with no access to the build directory.

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_bundle -v`

  Expected: import failure for `scripts.lmi_p1.bundle`.

- [ ] **Step 3: Implement deterministic transport**

  Copy both role-bound boot files, canonical manifest, source lock, packages/world, static verification, redacted build record, license/proprietary-input record, and rollback/disposition record into a newly created bundle. Compress only the raw userdata with `zstd -T0 -15 --no-progress`; if the result exceeds 1,800,000,000 bytes, split into fixed 1,800,000,000-byte parts named `.part-000`, `.part-001`, and so on. Reject every final asset `>=2,000,000,000` bytes and every basename outside `[A-Za-z0-9._-]+`.

  `SHA256SUMS` covers every immutable build payload exactly once but excludes itself and `transport-manifest.json`, avoiding a hash cycle. `transport-manifest.json` lists the expected payload names and the SHA-256/size of `SHA256SUMS`; it does not claim its own hash. Before upload the local verifier treats the clean bundle directory as the trust root; after upload/download the GitHub API digest authenticates `transport-manifest.json` itself. Offline verification reads only the bundle, verifies the complete expected set, restores zstd/split data into a new empty directory, and matches raw sizes/hashes to `manifest.json`.

- [ ] **Step 4: Run tests and commit**

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_bundle -v
  python3 -m unittest discover -s tests/lmi_p1 -v
  ```

  Expected: all tests pass.

  ```bash
  git add scripts/lmi_p1/bundle.py scripts/lmi_p1_cli.py tests/lmi_p1/test_bundle.py artifacts/images/README.md
  git commit -m "feat: archive complete lmi stage images"
  ```

### Task 6: GitHub Draft, immutability, and fresh-download gates

**Files:**
- Create: `scripts/lmi_p1/github_release.py`
- Create: `tests/lmi_p1/test_github_release.py`
- Modify: `scripts/lmi_p1_cli.py`
- Modify: `scripts/59_release_static_ci.sh`

**Interfaces:**
- Consumes: source/artifact repositories, exact commit, annotated tag, clean bundle, Windows gh path, and REST API version.
- Produces: `create_draft(repo: str, tag: str, commit: str, bundle: Path) -> ReleaseIdentity`, `upload_assets(release: ReleaseIdentity, bundle: Path) -> None`, `download_and_verify(release: ReleaseIdentity, output: Path) -> Path`, and `publish_and_verify(release: ReleaseIdentity, download: Path) -> dict[str, object]`.

  ```python
  @dataclass(frozen=True)
  class ReleaseIdentity:
      repo: str
      release_id: int
      tag: str
      commit: str
      draft: bool
      immutable: bool
  ```

- [ ] **Step 1: Write failing fake-gh tests**

  Cover unauthenticated CLI, wrong login, missing `repo`/admin capability, public artifact repository when `public_allowed=false`, immutable setting false, tag/commit mismatch, Draft absent/present, duplicate/renamed/extra asset, API state `starter`, size/hash/digest mismatch, use of `--clobber`, missing acceptance evidence, publish with incomplete asset set, published `isImmutable=false`, and valid post-publish release/asset attestation commands.

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_github_release -v`

  Expected: import failure for `scripts.lmi_p1.github_release`.

- [ ] **Step 3: Implement authenticated Windows-gh transport without exposing credentials**

  Default to `/mnt/c/Program Files/GitHub CLI/gh.exe`, require version at least `2.91.0`, and pass `--repo` explicitly. Convert asset paths with `wslpath -w`; never run through PowerShell string interpolation and never print credential-helper output. Use `X-GitHub-Api-Version: 2026-03-10` for all API calls.

  Preflight both repositories with `gh api repos/{owner}/{repo}`. Create `jian45154/redmi-k30-pro-postmarketos-artifacts` with private visibility only if API returns 404, mirror the exact source commit to it, enable immutable releases on both repositories with `PUT /repos/{owner}/{repo}/immutable-releases`, and read back `enabled=true`. Configure only this repository's credential helper to call the authenticated Windows gh; validate with `git push --dry-run` and never inspect returned credentials.

  Create annotated tag `lmi-p1-ssh-20260719-1`, push source commit and tag, then invoke `gh release create "$tag" --repo "$artifact_repo" --draft --verify-tag --title "$tag" --notes-file "$notes_file"`. Upload each asset once without `--clobber`. Compare the exact asset set against API `name`, `size`, `state=uploaded`, and `digest` equal to `"sha256:" + sha256_file(local_asset)`.

- [ ] **Step 4: Implement the two download barriers and immutable publish**

  Download the Draft into a new empty directory, run Task 5 offline restoration there, and write `draft-download-verification.json`; only restored paths from this directory may enter Task 7. After runtime acceptance, build an additive `acceptance-SHA256SUMS` plus `acceptance-manifest.json` covering only the new redacted evidence and acceptance JSON, then upload those new names while still Draft. Never replace the original bundle manifests or assets. Freeze the union of both exact asset sets and perform another fresh download. Only then publish.

  After publication require `isDraft=false`, `isImmutable=true`, the tag target unchanged, `gh release verify TAG`, and `gh release verify-asset TAG FILE` for every freshly downloaded asset. Save redacted command results as `release-attestation-verification.json`. For private assets, anonymous download is not expected; verify a no-auth attempt fails rather than leaking the assets.

- [ ] **Step 5: Extend static CI and commit**

  `scripts/59_release_static_ci.sh` must invoke all `unittest` files, `bash -n`, the P1 forbidden-pattern scan, and `git diff --check`; retain historical r6 checks as non-authoritative diagnostics rather than letting stale README strings decide P1 status.

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_github_release -v
  bash scripts/59_release_static_ci.sh
  ```

  Expected: all P1 tests and static checks pass.

  ```bash
  git add scripts/lmi_p1/github_release.py scripts/lmi_p1_cli.py scripts/59_release_static_ci.sh tests/lmi_p1/test_github_release.py
  git commit -m "feat: gate immutable lmi image releases"
  ```

### Task 7: Manifest-bound fastboot executor

**Files:**
- Create: `scripts/lmi_p1/fastboot.py`
- Create: `tests/lmi_p1/test_fastboot.py`
- Modify: `scripts/lmi_p1_cli.py`
- Modify: `scripts/65_lmi_release_safety_lint.sh`
- Replace: `scripts/72_stage_downstream_ssh_wifi_test.sh`

**Interfaces:**
- Consumes: freshly restored image directory, manifest, Draft verification record, D81/D82 userdata-disposition evidence, action `plan|userdata|ramboot|persistent-boot|reboot`, and absolute fastboot executable.
- Produces: a redacted append-only JSONL action record; mutating methods return only after fastboot reports success and a read-only state probe completes.

- [ ] **Step 1: Write failing fake-fastboot tests**

  Fake both plain `key: value` and `(bootloader) key: value`. Test no device, two devices, wrong serial binding, wrong product, locked bootloader, missing/low/malformed battery, wrong mode, unavailable target, slot contradiction, too-small partition, modified image hash, build-directory path rather than verified-download path, missing Draft proof, missing userdata-disposition proof, and every forbidden target. Positive cases must assert the exact argv arrays below and no shell usage:

  ```text
  [fastboot.exe, -s, <runtime-serial>, -S, 256M, flash, userdata, /absolute/fresh/xiaomi-lmi.img]
  [fastboot.exe, -s, <runtime-serial>, boot, /absolute/fresh/boot-ram.img]
  [fastboot.exe, -s, <runtime-serial>, flash, boot, /absolute/fresh/boot-persistent.img]
  [fastboot.exe, -s, <runtime-serial>, reboot]
  ```

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_fastboot -v`

  Expected: import failure for `scripts.lmi_p1.fastboot`.

- [ ] **Step 3: Implement a fresh preflight for every action**

  Resolve exactly one serial from `fastboot devices`; pass `-s SERIAL` on every later command. Query `product`, `unlocked`, `is-userspace`, `battery-voltage`, `current-slot`, `slot-count`, `has-slot:boot`, `partition-size:boot`, `partition-size:boot_a`, `partition-size:boot_b`, `partition-size:userdata`, and `partition-type:userdata` with five-second timeouts. Preserve “Variable Not found” as a typed absence, not an empty success.

  Require current lmi's non-A/B proof tuple: all three slot variables absent, `boot=0x8000000`, `boot_a/boot_b` absent. Require userdata capacity `>=` raw image size and boot capacity `>=` boot file size. Hash files immediately before action, require their resolved parent to equal the recorded fresh-download restoration directory, and bind the serial only as a SHA-256 in committed evidence.

  `userdata` additionally verifies the D81/D82 hashes and route statement proving current userdata was the disposable D80 postmarketOS test image. If that record cannot be verified, the action fails without offering an override.

- [ ] **Step 4: Replace the unsafe historical executor**

  `scripts/72_stage_downstream_ssh_wifi_test.sh` becomes a compatibility wrapper around `python3 scripts/lmi_p1_cli.py hardware`; it may expose `plan` but must not retain `pmbootstrap flasher flash_rootfs`, manual token logic, or an image path independent of the manifest. Extend `scripts/65_lmi_release_safety_lint.sh` to allow only the exact argv construction in `fastboot.py` and reject dynamic targets or forbidden strings.

- [ ] **Step 5: Run tests and commit**

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_fastboot -v
  bash scripts/65_lmi_release_safety_lint.sh
  python3 -m unittest discover -s tests/lmi_p1 -v
  ```

  Expected: all tests and the safety lint pass.

  ```bash
  git add scripts/lmi_p1/fastboot.py scripts/lmi_p1_cli.py scripts/65_lmi_release_safety_lint.sh scripts/72_stage_downstream_ssh_wifi_test.sh tests/lmi_p1/test_fastboot.py
  git commit -m "feat: bind lmi fastboot actions to verified assets"
  ```

### Task 8: Strict USB SSH and persistence acceptance

**Files:**
- Create: `scripts/lmi_p1/ssh_accept.py`
- Create: `tests/lmi_p1/test_ssh_accept.py`
- Modify: `scripts/lmi_p1_cli.py`
- Replace: `scripts/20_collect_v26_ssh_logs.sh`

**Interfaces:**
- Consumes: manifest, expected image identity, Ed25519 private-key path, direct USB endpoint `172.16.42.1:22`, and fastboot action record.
- Produces: `p1-acceptance.json`, candidate-specific `known_hosts`, a persistence token, and redacted runtime logs tied to boot ID and image hashes.

- [ ] **Step 1: Write failing fake-ssh tests**

  Fake `ssh-keyscan`, `ssh-keygen`, `ssh`, TCP probing, PowerShell USB restart, and fastboot. Cover first-key capture, fingerprint change, candidate identity mismatch, correct-key failure, wrong-key success, password success, root success, fewer than five clean sessions, wrong mounts/IP/services, token loss, host-key change after reboot, and a fully passing two-boot transcript.

- [ ] **Step 2: Run the focused test and confirm RED**

  Run: `python3 -m unittest tests.lmi_p1.test_ssh_accept -v`

  Expected: import failure for `scripts.lmi_p1.ssh_accept`.

- [ ] **Step 3: Implement bounded TOFU followed by strict pinning**

  Wait at most 180 seconds for TCP 22. On the direct point-to-point RNDIS link only, capture one Ed25519 host key, record its fingerprint, then use `UserKnownHostsFile=.work/lmi-p1/lmi-p1-ssh-20260719-1/evidence/known_hosts`, `StrictHostKeyChecking=yes`, `IdentitiesOnly=yes`, `BatchMode=yes`, and the one expected private key for every command. Never use the global known_hosts file.

  Before SSH, require the Windows PnP inventory to expose exactly one present `USB\\VID_0525&PID_A4A2` RNDIS device and TCP 22 at `172.16.42.1`. Prove correct login and five independent sessions. Generate a temporary wrong Ed25519 key and require failure. Require `PreferredAuthentications=password` with `BatchMode=yes` to fail for `lmi`; require the correct key to fail for `root`. Runtime checks require `/` from loop partition 2, `/boot` from loop partition 1, NetworkManager's active `usb0` connection ID exactly `lmi-usb0`, exactly one `usb0` IPv4 address `172.16.42.1/24` with no retained `/16`, `172.16.42.2` as the sole shared-DHCP lease, `sshd` started, current boot ID, package versions, and `/etc/lmi-release-identity` equal to the manifest. Verify the `lmi` account is neither expired nor blocked by aging, has an interactive shell rather than `nologin`, and completes public-key login with the locked `!` shadow field. Capture `dmesg`/initramfs evidence showing the 4096-sector loop partition discovery, root mount, and completed `switch_root`; the two mount facts alone do not replace that boot-transition evidence.

- [ ] **Step 4: Test USB recovery, persistence, and reboot identity**

  Write a cryptographically random token beneath `/home/lmi/.local/state/lmi-p1/`. Restart only the Windows PnP device whose exact instance ID matches `VID_0525&PID_A4A2`; if no unique device or elevation is unavailable, record `usb-reconnect=pending` and do not accept P1. After connectivity returns, run another strict SSH session.

  After the first-boot checks and USB restart, use `sudo -n /usr/sbin/lmi-rootctl reboot-bootloader --confirm reboot-bootloader-lmi-p1` and wait at most 120 seconds for exactly the same lmi in bootloader fastboot. Task 7 then writes the downloaded `boot-persistent.img` and performs its separately gated `fastboot reboot`. After SSH returns, require the token and host-key fingerprint unchanged and both `sshd` and USB networking started. Save JSON with every required P1 assertion explicitly true; any pending/false value leaves `status=runtime-partial`.

  `scripts/20_collect_v26_ssh_logs.sh` becomes a read-only compatibility wrapper around the strict collector and contains neither `StrictHostKeyChecking=no` nor `systemctl`.

- [ ] **Step 5: Run tests and commit**

  Run:

  ```bash
  python3 -m unittest tests.lmi_p1.test_ssh_accept -v
  python3 -m unittest discover -s tests/lmi_p1 -v
  git grep -n 'StrictHostKeyChecking=no' -- scripts && exit 1 || true
  ```

  Expected: all tests pass and grep emits nothing.

  ```bash
  git add scripts/lmi_p1/ssh_accept.py scripts/lmi_p1_cli.py scripts/20_collect_v26_ssh_logs.sh tests/lmi_p1/test_ssh_accept.py
  git commit -m "test: automate strict lmi p1 ssh acceptance"
  ```

### Task 9: Execute candidate 1, publish immutable P1, and record handoff

**Files:**
- Create: `docs/release/lmi-p1-ssh-20260719-1.md`
- Create: `artifacts/releases/lmi-p1-ssh-20260719-1.manifest.json`
- Create: `logs/lmi-p1-ssh-20260719-1-static.redacted.json`
- Create after hardware: `logs/lmi-p1-ssh-20260719-1-runtime.redacted.json`
- Modify: `README.md`
- Modify: `notes/current-state.md`
- Modify: `docs/tracks/downstream.md`

**Interfaces:**
- Consumes: all prior tasks and the standing authorization recorded in the approved design.
- Produces: an immutable, freshly re-downloaded full-image P1 Release and repository evidence, or an honest `candidate`/`runtime-partial` record with the precise failed gate.

- [ ] **Step 1: Verify the entire implementation before any build**

  Run:

  ```bash
  sudo apt-get update
  sudo apt-get install -y zstd jq shellcheck
  python3 -m unittest discover -s tests/lmi_p1 -v
  bash scripts/59_release_static_ci.sh
  bash scripts/65_lmi_release_safety_lint.sh
  git diff --check
  ```

  Expected: dependencies install, every test passes, both gates print `OK`, and `git diff --check` is silent.

- [ ] **Step 2: Prepare inputs, stage pmaports, build, and statically verify**

  Run from repository root:

  ```bash
  python3 scripts/lmi_p1_cli.py prepare --tag lmi-p1-ssh-20260719-1 --work .work/lmi-p1/lmi-p1-ssh-20260719-1
  python3 scripts/lmi_p1_cli.py build --tag lmi-p1-ssh-20260719-1 --work .work/lmi-p1/lmi-p1-ssh-20260719-1
  python3 scripts/lmi_p1_cli.py verify-image --tag lmi-p1-ssh-20260719-1 --work .work/lmi-p1/lmi-p1-ssh-20260719-1
  python3 scripts/lmi_p1_cli.py bundle --tag lmi-p1-ssh-20260719-1 --work .work/lmi-p1/lmi-p1-ssh-20260719-1 --out artifacts/builds/lmi-p1-ssh-20260719-1
  ```

  Expected: final line from each command is respectively `PREPARE_OK`, `BUILD_OK`, `STATIC_VERIFY_OK`, and `BUNDLE_OK`; boot is below 128 MiB; userdata round-trip succeeds; manifest status remains `candidate`.

- [ ] **Step 3: Commit and push the exact source identity**

  Add only source, plan, tests, non-secret manifests, and documentation; never add `.work`, raw images, compressed images, credentials, host keys, or unredacted logs.

  ```bash
  git status --short
  git add README.md notes/current-state.md docs/tracks/downstream.md docs/release/lmi-p1-ssh-20260719-1.md artifacts/releases/lmi-p1-ssh-20260719-1.manifest.json logs/lmi-p1-ssh-20260719-1-static.redacted.json
  git commit -m "build: freeze lmi p1 ssh candidate 1"
  git push origin master
  ```

  Expected: push succeeds and remote `master` contains the exact candidate source commit.

- [ ] **Step 4: Create private Draft and prove first fresh download**

  Run:

  ```bash
  python3 scripts/lmi_p1_cli.py release create-draft --tag lmi-p1-ssh-20260719-1 --bundle artifacts/builds/lmi-p1-ssh-20260719-1
  python3 scripts/lmi_p1_cli.py release upload --tag lmi-p1-ssh-20260719-1 --bundle artifacts/builds/lmi-p1-ssh-20260719-1
  python3 scripts/lmi_p1_cli.py release download-verify --tag lmi-p1-ssh-20260719-1 --out artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  ```

  Expected: `DRAFT_CREATED`, `ASSETS_VERIFIED`, and `FRESH_DOWNLOAD_OK`. The hardware input record points only to `artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware/restored/`.

- [ ] **Step 5: Execute the gated hardware sequence**

  First run `hardware plan`; it must freshly show one unlocked lmi, `is-userspace=no`, battery at least 3800, boot size `0x8000000`, absent slot variables/boot_a/boot_b, sufficient userdata capacity, matching hashes, verified Draft, and verified D81/D82 disposition evidence.

  ```bash
  python3 scripts/lmi_p1_cli.py hardware plan --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  python3 scripts/lmi_p1_cli.py hardware userdata --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  python3 scripts/lmi_p1_cli.py hardware ramboot --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  python3 scripts/lmi_p1_cli.py accept-ssh first-boot --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  python3 scripts/lmi_p1_cli.py hardware persistent-boot --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  python3 scripts/lmi_p1_cli.py hardware reboot --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  python3 scripts/lmi_p1_cli.py accept-ssh after-reboot --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-prehardware
  ```

  Expected: `PREFLIGHT_OK`, both fastboot actions report the exact target/hash and `OKAY`, and acceptance ends `P1_ACCEPTED`. On any failure, stop writes, collect read-only state, keep the release Draft, and record `runtime-partial`; do not repeat the write blindly.

- [ ] **Step 6: Freeze evidence, publish, and verify from scratch**

  Commit and push the redacted acceptance evidence on `master` without moving or recreating the already-pushed release tag. Upload the exact evidence set to the still-Draft Release, freeze the asset list, and perform the second fresh download. Then publish and verify attestations; the tag continues to identify the exact source/build commit from Step 3 while later evidence commits remain linked by manifest hash.

  ```bash
  python3 scripts/lmi_p1_cli.py release upload-acceptance --tag lmi-p1-ssh-20260719-1 --evidence logs/lmi-p1-ssh-20260719-1-runtime.redacted.json
  python3 scripts/lmi_p1_cli.py release download-verify --tag lmi-p1-ssh-20260719-1 --out artifacts/download-verification/lmi-p1-ssh-20260719-1-final
  python3 scripts/lmi_p1_cli.py release publish --tag lmi-p1-ssh-20260719-1 --download artifacts/download-verification/lmi-p1-ssh-20260719-1-final
  ```

  Expected: `FINAL_FRESH_DOWNLOAD_OK`, `RELEASE_IMMUTABLE`, `RELEASE_ATTESTATION_OK`, and the restored boot/userdata SHA, UUID, packages, and source identity equal the hardware acceptance record.

- [ ] **Step 7: Final P1 regression and documentation truth check**

  Run one last strict SSH session from the published-download directory and update README/current-state/downstream track so they say exactly one of `candidate`, `runtime-partial`, or `accepted`. Do not call P1 accepted if physical USB restart, negative authentication, five reconnects, persistence, stable host key, service state, immutable release, or fresh-download verification is absent.

  Run:

  ```bash
  python3 -m unittest discover -s tests/lmi_p1 -v
  bash scripts/59_release_static_ci.sh
  bash scripts/65_lmi_release_safety_lint.sh
  git diff --check
  git status --short
  ```

  Expected: all verification passes and status contains only the intentional evidence/documentation changes.

  ```bash
  git add README.md notes/current-state.md docs/tracks/downstream.md docs/release/lmi-p1-ssh-20260719-1.md artifacts/releases/lmi-p1-ssh-20260719-1.manifest.json logs/lmi-p1-ssh-20260719-1-static.redacted.json logs/lmi-p1-ssh-20260719-1-runtime.redacted.json
  git commit -m "docs: record accepted lmi p1 ssh release"
  git push origin master
  ```

## P1 exit criteria before the P2 plan

- P1 may advance to `accepted` only when Task 9 produces a stable immutable GitHub Release containing exact full boot and userdata/rootfs assets and the final fresh-download verification succeeds.
- A functional but not yet physically USB-reconnected device is `runtime-partial`, not accepted.
- P2 implementation planning may start from a stable P1 runtime, but final P2-source must replace replay kernel/device/Weston identities with r10/r140/r11+ source builds and rerun all P1 checks.
- The P2 plan must explicitly account for D80's missing `libweston-14.0.2-r10.apk` and may describe replay only as D80 runtime APK replay plus ABI-compatible Alpine libweston.
