# Redmi K30 Pro (`lmi`) → postmarketOS / Linux

Turning a **Redmi K30 Pro / POCO F2 Pro** (`lmi`, Qualcomm **SM8250 / Snapdragon 865**)
into a native Linux device with **postmarketOS**, built from the downstream
LineageOS 4.19 vendor kernel with **Clang/LLVM** under **WSL2 + pmbootstrap**.

## Status

- ✅ **Kernel + DTBs + full image build** (Clang/LLVM, pmbootstrap).
- ✅ **Rootfs mounts on real hardware** from `userdata` using nested GPT loop
  partitions (`/dev/loop0p2` as `/`, `/dev/loop0p1` as `/boot`).
- ✅ **Normal userspace + SSH works** with a RAM-only `fastboot boot` kernel.
- ✅ **USB networking works on Windows** as RNDIS gadget
  (`0525:a4a2 POSTMARKETOS`, host `172.16.42.2`, device `172.16.42.1`).
- ✅ **Persistent v27 boot is installed**: `boot` and `userdata` now boot into
  postmarketOS without `fastboot boot`.
- ⏳ **Display userspace takeover** — kernel DRM/KGSL and the DSI panel are
  present, but the screen remains on the Redmi logo because no compositor takes
  over the continuous splash.
- ⏳ **Audio / mic, Wi-Fi, and Bluetooth** — next hardware focus. ALSA has no
  soundcard, Wi-Fi has no exposed wireless interface, and Bluetooth is rfkill
  soft-blocked.

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
# in WSL, with pmbootstrap configured for device xiaomi-lmi (channel edge)
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build    linux-xiaomi-lmi          # ~16 min cold
pmbootstrap checksum device-xiaomi-lmi
pmbootstrap build    device-xiaomi-lmi
pmbootstrap install  --no-fde
pmbootstrap export                              # -> /tmp/postmarketOS-export/
fastboot boot /tmp/postmarketOS-export/boot.img # RAM only; writes nothing
```

## Repo layout

- `docs/` — the porting write-up (EN + 中文) and the pmaports MR notes.
- `artifacts/wsl-pmaports/` — the device + kernel pmaports packages.
- `artifacts/kernel-source/` — config fragments and device-tree evidence used to
  derive the kernel config.
- `notes/` — compact archive notes for the current v27 baseline, rollback plan,
  and hardware enablement plan.
- `scripts/` — current WSL/device helper scripts for rebuilding v27/v28,
  checking the exported images, and collecting hardware evidence.

## Current hardware focus

The v27 baseline is stable enough to move from boot/rootfs repair into hardware
enablement. The immediate targets are:

- display: start a minimal compositor or DRM/KMS test so userspace visibly takes
  over the panel;
- sound and microphone: restore ADSP/audio firmware/service bring-up until ALSA
  exposes real cards instead of `auto_null`;
- networking: make WLAN expose a usable interface; keep USB/RNDIS as the debug
  fallback;
- Bluetooth: unblock and initialize BT after WLAN/firmware service dependencies
  are understood.

The latest evidence is summarized in
[`notes/archive-summary-2026-06-23.md`](notes/archive-summary-2026-06-23.md)
and
[`notes/repair-phase43-v27-full-hardware-check-2026-06-23.md`](notes/repair-phase43-v27-full-hardware-check-2026-06-23.md).

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
