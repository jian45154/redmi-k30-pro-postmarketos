# Redmi K30 Pro (`lmi`) → postmarketOS / Linux

Turning a **Redmi K30 Pro / POCO F2 Pro** (`lmi`, Qualcomm **SM8250 / Snapdragon 865**)
into a native Linux device with **postmarketOS**. The archived stable baseline
uses the downstream LineageOS 4.19 vendor kernel with **Clang/LLVM** under
**WSL2 + pmbootstrap**. The project now tracks two separate version lines:

- **Downstream (`D-vNN`)**: LineageOS 4.19 downstream kernel. `D-v46` is the
  verified Wi-Fi cleanup baseline, while `D-v43` remains the earlier Wi-Fi
  baseline; the latest built local artifact is `D-v52`.
- **Mainline/copydown (`M-rNN`)**: SM8250 mainline/copydown path, currently
  recorded through `M-r7`; host-side builds and guarded writes work, but no
  observable initramfs/USB milestone is proven.

## Status

- ✅ **Kernel + DTBs + full image build** (Clang/LLVM, pmbootstrap).
- ✅ **Rootfs mounts on real hardware** from `userdata` using nested GPT loop
  partitions (`/dev/loop0p2` as `/`, `/dev/loop0p1` as `/boot`).
- ✅ **Normal userspace + SSH works** on the downstream v27 baseline, including
  prior RAM-only `fastboot boot` validation.
- ✅ **USB networking works on Windows** as RNDIS gadget
  (`0525:a4a2 POSTMARKETOS`, host `172.16.42.2`, device `172.16.42.1`).
- ✅ **Persistent downstream v27 boot was installed**: `boot` and `userdata` boot into
  postmarketOS without `fastboot boot`.
- ✅ **Downstream Wi-Fi bring-up works at `D-v46`**: SSH is reachable, `wlan0`
  is up with a default route, and `p2p0` plus `wifi-aware0` are present. `D-v43`
  remains the earlier Wi-Fi baseline.
- ⏳ **Latest built downstream artifact is `D-v52`** (`v52-d50-service-foundation`);
  it is runtime-unverified. It matches current source package `1-r113`, carries
  the target-side `lmi-rootctl` confirmation gates, and its rootfs static
  verifier proves the `pd-mapper` service-foundation content is present. `D-v51`
  remains an older rootctl target-gate artifact and must not be used to claim
  the D-v52 service-foundation changes on hardware.
- ⚠️ **Mainline/copydown reached `M-r7` but is not boot-verified**. `M-r6` and
  `M-r7` writes were accepted, but reboot testing stopped at the Redmi logo with
  no postmarketOS USB, telnet, SSH, ADB, or fastboot interface observed.
- ✅ **Screen and touch hardware are working** — the DSI panel displays the
  minimal GUI and touch input is available at the hardware/input layer.
- ⚠️ **On-screen keyboard is temporarily unavailable** in the current minimal
  GUI; text entry is limited to the validated terminal/input path.
- ⏳ **Audio / mic and Bluetooth** — next hardware focus. ALSA has no soundcard
  and Bluetooth remains incomplete; Wi-Fi has a verified downstream bring-up
  path but still needs service and policy cleanup.

## Project tracks

Start with the track index:

- [`docs/tracks/README.md`](docs/tracks/README.md) — version-label rules and
  file placement.
- [`docs/tracks/downstream.md`](docs/tracks/downstream.md) — downstream
  `D-vNN` features and progress.
- [`docs/tracks/mainline.md`](docs/tracks/mainline.md) — mainline/copydown
  `M-rNN` features and progress.

The mainline/copydown release records are still archived under `docs/release/`.
Large images are not committed; release identity and hardware gates are
documented in:

- [`docs/release/lmi-r6-bootmem-release-manifest-20260624.md`](docs/release/lmi-r6-bootmem-release-manifest-20260624.md)
- [`docs/release/lmi-r6-bootmem-execution-checklist-20260624.md`](docs/release/lmi-r6-bootmem-execution-checklist-20260624.md)
- [`docs/release/lmi-r7-earlydebug-build-result-20260624.md`](docs/release/lmi-r7-earlydebug-build-result-20260624.md)

The `lmi-r6-current-handoff-20260624.md` file is older than the r6/r7 result
documents; prefer the per-result release records when judging current state.

Static release checks, including the P1, P2, and P3 host test suites, can be run
locally with `scripts/59_release_static_ci.sh`. A GitHub Actions workflow template is kept at
[`docs/release/edge-release-checks.workflow.yml`](docs/release/edge-release-checks.workflow.yml);
copy it to `.github/workflows/` only with a token that has workflow scope.
To refresh all local r6 release reports and docs, run
`scripts/62_refresh_lmi_release_docs.sh --quick`.

The reusable host-side automation loop is documented in
[`docs/mainline-automation-loop-20260624.md`](docs/mainline-automation-loop-20260624.md).
Use `scripts/68_mainline_progress_loop.sh --once --quick` for the default
read-only loop, and `scripts/69_audit_lmi_resources.sh --network` when local
mainline resources need to be compared with remote repository refs.

## Read this first

**[docs/porting-sm8250-downstream-to-postmarketos.md](docs/porting-sm8250-downstream-to-postmarketos.md)**
— the field log of every non-obvious problem and its fix (SELinux host tools,
kheaders, the LLVM `ld` config trap, building/installing the qcom overlay DTBs,
`deviceinfo_dtb` for header-v2 + overlay devices, WSL/usbipd papercuts), plus the
complete working `APKBUILD`. Most of it applies to **any SM8250 / downstream-MSM
device**, not just `lmi`. ([中文版](docs/porting-sm8250-downstream-to-postmarketos.zh.md))

## The recipe

The postmarketOS packaging that produces a bootable image:

- [`artifacts/wsl-pmaports/linux-xiaomi-lmi/`](artifacts/wsl-pmaports/linux-xiaomi-lmi/)
  — kernel package (`APKBUILD`, merged `config-xiaomi-lmi.aarch64`) with
  `devtmpfs` and configfs RNDIS enabled.
- [`artifacts/wsl-pmaports/device-xiaomi-lmi/`](artifacts/wsl-pmaports/device-xiaomi-lmi/)
  — device package (`deviceinfo`, `modules-initfs`) configured for 4096-byte
  rootfs image sectors and RNDIS USB networking.

Kernel source: `LineageOS/android_kernel_xiaomi_sm8250` @ `a5b3099`
(matches the stock `4.19.325-cip128-st12-perf-ga5b3099017ae`).

## Build it

```bash
# in WSL, with pmbootstrap configured for the downstream v27 xiaomi-lmi baseline
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build    linux-xiaomi-lmi          # ~16 min cold
pmbootstrap checksum device-xiaomi-lmi
pmbootstrap build    device-xiaomi-lmi
pmbootstrap install  --no-fde
pmbootstrap export                              # -> /tmp/postmarketOS-export/
fastboot boot /tmp/postmarketOS-export/boot.img # RAM only; writes nothing
```

For the mainline/copydown r6 route, use the release checklist instead of the
downstream quick recipe. The staged persistent path is documented in
[`docs/release/lmi-r6-bootmem-execution-checklist-20260624.md`](docs/release/lmi-r6-bootmem-execution-checklist-20260624.md).

## Repo layout

- `docs/` — the porting write-up (EN + 中文) and the pmaports MR notes.
- `docs/tracks/` — current downstream/mainline split, version labels, features,
  and progress.
- `artifacts/wsl-pmaports/` — the device + kernel pmaports packages.
- `artifacts/mainline-pmaports/` — imported mainline package references.
- `artifacts/kernel-source/` — config fragments and device-tree evidence used to
  derive the kernel config.
- `artifacts/images/` — local image artifacts and manifests; see
  [`artifacts/images/README.md`](artifacts/images/README.md).
- `notes/` — compact archive notes for the current v27 baseline, rollback plan,
  and hardware enablement plan.
- `scripts/` — current WSL/device helper scripts for rebuilding v27/v28,
  checking exported images, collecting hardware evidence, and staging guarded
  mainline/copydown operations; see [`scripts/README.md`](scripts/README.md).
- `config/lmi-p1/root-boundary/` — deployment guide, exact launcher-only
  sudoers policy, and offline validator for the sealed P1 root boundary; see
  [`config/lmi-p1/root-boundary/README.md`](config/lmi-p1/root-boundary/README.md).

## Current hardware focus

The downstream line has moved from boot/rootfs repair into hardware enablement.
For the current local P0/P1/P2 status, run
`scripts/85_audit_downstream_priority_status.sh`; generate the hardware-window
command sheet with `scripts/86_generate_downstream_hardware_window_runbook.sh`.
Redact new hardware-window logs with
`scripts/87_redact_downstream_hardware_log.sh` before committing evidence.
The immediate targets are:

- display: start a minimal compositor or DRM/KMS test so userspace visibly takes
  over the panel;
- sound and microphone: restore ADSP/audio firmware/service bring-up until ALSA
  exposes real cards instead of `auto_null`; start with
  `scripts/84_audit_downstream_p2_audio_bt_readiness.sh`, then passive runtime
  evidence from `scripts/77_probe_downstream_p2_audio_bt.sh --all`;
- networking: keep `D-v46` as the verified Wi-Fi cleanup baseline and `D-v43`
  as the earlier Wi-Fi baseline, then clean up service status and NetworkManager
  MAC behavior;
- Bluetooth: unblock and initialize BT only after WLAN/firmware service
  dependencies are understood from the same P2 static audit and passive runtime
  evidence.

The latest downstream Wi-Fi evidence is summarized in
[`notes/wifi-bringup-live-2026-06-24.md`](notes/wifi-bringup-live-2026-06-24.md).
The stable v27 baseline remains summarized in
[`notes/archive-summary-2026-06-23.md`](notes/archive-summary-2026-06-23.md).

The hardware enablement workflow is tracked in
[`docs/hardware-enablement-workflow.md`](docs/hardware-enablement-workflow.md),
[`docs/hardware-enablement-subagents.md`](docs/hardware-enablement-subagents.md),
and
[`notes/hardware-enablement-queue-2026-06-23.md`](notes/hardware-enablement-queue-2026-06-23.md).

## Safety

This project never flashes the phone without an explicit decision and a
confirmed recovery path. `userdata` rootfs writes were performed only after
explicit confirmation. The v27 `boot` partition write was also performed only
after explicit confirmation. `dtbo`, `vbmeta`, `super`, modem/EFS, and
calibration partitions have not been written. The install plan and rollback
notes are in
[notes/flash-plan-2026-06-17.md](notes/flash-plan-2026-06-17.md) and the dated
repair notes under [`notes/`](notes/).

## Not in this repo (by design)

Stock/recovery boot images for the device (proprietary third-party binaries),
full pmOS images, and rejected flash candidates are **not** distributed here —
they are gitignored. Raw device logs (which contain serial numbers, CPU IDs,
bootloader tokens, and MAC addresses) are gitignored too. Only explicitly
redacted logs may be committed.

## License

MIT for the original work here (notes, scripts, recipes); the kernel and its
derived config are GPL-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
