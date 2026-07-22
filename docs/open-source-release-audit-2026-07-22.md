# Open-Source Completeness Audit — 2026-07-22

Goal: publish the complete `lmi` porting solution as openly as possible.
This audit records what is already open, what must stay local and why, what
was scanned for leaks, and the remaining steps to reach maximal completeness.

## 1. What is already open (git-tracked, 497 files)

| Area | Content |
| --- | --- |
| Recipe | `artifacts/wsl-pmaports/` device + kernel packages (APKBUILD, merged kernel config, deviceinfo), `artifacts/mainline-pmaports/` mainline references, `artifacts/kernel-source/` config fragments and DT evidence |
| Reproducibility | `artifacts/images/*.manifest` (57 manifests: hashes, kernel/DTB/ramdisk identity, cmdline, sector size, USB IDs for every build v2–v46), pmbootstrap configs |
| Tooling | ~110 scripts (build, static verification, guarded device staging, probes, audits) + `lmi_p1/p2/p2_d114/p3/weston_sixrow/installer` Python packages |
| Tests | 52 host-side test files under `tests/` |
| Knowledge | Full porting field log (EN + 中文), 84 dated notes including the complete 46-phase boot/rootfs repair history, track status docs, release manifests/checklists |
| Evidence | 25 redacted device logs (`logs/*.redacted.txt`) |
| Policy/config | `config/` policy locks, root-boundary sudoers + validator, `files/` target-side service files |
| Licensing | MIT (original work) + GPL-2.0 (kernel, derived config), `NOTICE` |
| Governance | Root `AGENTS.md` (vendor-neutral agent rules), generic Agent Skill under `.agents/skills/` |

Kernel source is not vendored but is fully pinned and public:
`LineageOS/android_kernel_xiaomi_sm8250` @ `a5b3099`
(stock `4.19.325-cip128-st12-perf-ga5b3099017ae`).

## 2. Leak scan of tracked files (clean)

Performed 2026-07-22 over all tracked files:

- MAC addresses: only documentation/test placeholders (`aa:bb:cc:dd:ee:ff`).
- Serial numbers / IMEI / unlock tokens / private keys: no hits; matches were
  kernel config option names (`CONFIG_USB_SERIAL=…`) and `.gitignore`
  comments.
- Passwords/secrets: only `<temporary-test-password>` placeholders and
  sshd/sudoers policy text; `PasswordAuthentication no` throughout.
- Emails: one `Signed-off-by` line in a kernel patch (standard DCO
  convention).
- pmbootstrap configs contain no local usernames or host paths (only the
  `Australia/Sydney` timezone, which dated notes already disclose).

## 3. What must stay local, and why

| Item | Size | Reason | Open substitute |
| --- | --- | --- | --- |
| `private/` | 33 GB | Stock/recovery images (proprietary third-party binaries), device backups, operator notes with device identifiers | Manifests + acquisition docs; users supply their own device's stock images. Pinned recovery/tool images are additionally backed up to the owner-only private vault (`lmi-recovery-images`, release `recovery-20260722`); tiers and rules in `docs/resource-inventory-and-usage-20260722.md` |
| Raw `logs/*.txt` | — | Serial numbers, CPU IDs, bootloader tokens, MACs | Redacted copies are tracked; `scripts/87_redact_downstream_hardware_log.sh` |
| Built boot/rootfs images | `.work/`, local exports | Policy: no binary ships without exact-hash hardware validation (see D114 readiness doc); later images (v30+ `fw`/`initfs-fw` variants, D114 userdata) stage proprietary firmware content | Per-image manifests are tracked; anyone can rebuild from the recipe |
| `.work/`, `tmp` scratch, `__pycache__` | 1.3 GB | Generated build state | Rebuildable via scripts |

Note on firmware: the device package deliberately does **not** package
proprietary firmware — `lmi-firmware-mount` mounts it at runtime from the
device's existing Android partitions. This is the design that keeps the repo
fully redistributable.

## 4. Gaps between "current repo" and "as complete as possible"

1. **Unmerged in-flight work.** The D114 six-row branch carries the CLI
   installer (`v0.1.0-alpha.1` source release, docs, tests), the D114
   launcher relative-invocation fix, and the governance consolidation
   (`AGENTS.md`). These must be committed and merged to `master` to be part
   of the public tree.
2. **CI not installed.** `docs/release/edge-release-checks.workflow.yml` is a
   template only; copying it to `.github/workflows/` (requires a token with
   workflow scope) would let the public run the same static release checks.
3. **Installer release assets.** Tag `v0.1.0-alpha.1` with
   `scripts/73_build_lmi_installer_source_release.sh` output
   (source tarball + sha256) as a GitHub pre-release, per
   `docs/lmi-cli-installer.md`.
4. **Binary images remain future work by policy.** A public ready-to-flash
   image requires the clean rebuild + exact-hash hardware validation defined
   in `docs/release/lmi-d114-r1-sixrow-readiness-20260722.md`. Until then,
   manifests-only is the intended open form, not an omission.

## 5. Non-goals

- Publishing stock/recovery boot images or any proprietary firmware binary.
- Publishing raw (unredacted) device logs.
- Publishing `private/` operator material in any form.
