# Redmi K30 Pro (`lmi`) → postmarketOS / Linux

Turning a **Redmi K30 Pro / POCO F2 Pro** (`lmi`, Qualcomm **SM8250 / Snapdragon 865**)
into a native Linux device with **postmarketOS**, built from the downstream
LineageOS 4.19 vendor kernel with **Clang/LLVM** under **WSL2 + pmbootstrap**.

## Status

- ✅ **Kernel + DTBs + full image build** (Clang/LLVM, pmbootstrap).
- ✅ **Boots on real hardware** via `fastboot boot` (RAM only, nothing flashed).
- ✅ **USB networking works** — CDC-NCM gadget (`18d1:d001 POSTMARKETOS`),
  reachable from the host (`ping 172.16.42.1` ~3 ms via usbipd → WSL).
- ⏳ Persistent install (flash rootfs to `userdata`) — planned, not yet done.
- ⏳ Display / modem / Wi-Fi — not yet validated (headless-server focus).

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
  — kernel package (`APKBUILD`, merged `config-xiaomi-lmi.aarch64`).
- [`artifacts/wsl-pmaports/device-xiaomi-lmi/`](artifacts/wsl-pmaports/device-xiaomi-lmi/)
  — device package (`deviceinfo`, `modules-initfs`).

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
- `notes/` — dated working log (build failures, fixes, boot test, flash plan).
- `scripts/` — Windows/WSL helper scripts for env checks, image inspection,
  config generation, and pmaports sync. Output goes to `logs/` (gitignored).

## Safety

This project never flashes the phone without an explicit decision and a
confirmed recovery path. The only hardware action taken so far is a temporary,
RAM-only `fastboot boot` — no partition has been written. The persistent-install
plan (and its rollback) is in
[notes/flash-plan-2026-06-17.md](notes/flash-plan-2026-06-17.md).

## Not in this repo (by design)

Stock/recovery boot images for the device (proprietary third-party binaries) and
build artifacts are **not** distributed here — they are gitignored. Raw device
logs (which contain serial numbers, CPU IDs, bootloader tokens) are gitignored
too.

## License

MIT for the original work here (notes, scripts, recipes); the kernel and its
derived config are GPL-2.0. See [LICENSE](LICENSE).
