# Next Task Memo: Wi-Fi + Display bring-up

签名：codex_ian | 2026-06-18

Goal of the next session: get **display (a usable framebuffer/console on the
panel)** and **Wi-Fi** working on the lmi postmarketOS port.

## Where we are now (starting point)

- Kernel + DTBs + image build cleanly; `fastboot boot` runs on hardware; USB
  networking (CDC-NCM, `ping 172.16.42.1`) works from WSL via usbipd.
- Screen is **black** — there is no framebuffer yet (expected; see below).
- No rootfs is flashed; a RAM `fastboot boot` drops into initramfs with no shell.
- Recipe: `artifacts/wsl-pmaports/{linux,device}-xiaomi-lmi/`. Public repo:
  https://github.com/jian45154/redmi-k30-pro-postmarketos
- `deviceinfo_dtb="qcom/kona-v2.1"` — a **base** kona dtb. The lmi device nodes
  (panel, regulators, wlan/cnss pinmux) live in `lmi-sm8250-overlay.dtbo`, which
  is currently NOT merged into the boot dtb (the on-device dtbo partition may or
  may not be applied by the bootloader on `fastboot boot`).

## Prerequisite: get a persistent system first

Iterating on display/Wi-Fi needs a real booted system with a shell (dmesg, load
modules, run daemons). Do **Plan A** in `notes/flash-plan-2026-06-17.md` first:
flash rootfs to `userdata`, RAM-boot the kernel, `ssh lmi@172.16.42.1`. Then all
the debugging below happens over ssh. (Needs ian approval + recovery path.)

## Display

Root cause of the black screen: the panel/DPU nodes are not in the boot dtb. Two
paths:

1. **Pre-merge the lmi overlay into the base dtb** so the panel + MDSS/DSI nodes
   are present, then point `deviceinfo_dtb` at the merged blob. We already build
   `kona-v2.1.dtb` + `lmi-sm8250-overlay.dtbo`; merge them at build time
   (`fdtoverlay -i kona-v2.1.dtb -o kona-v2.1-lmi.dtb lmi-sm8250-overlay.dtbo`,
   or the kernel's ufdt apply). Qualcomm overlays use `__symbols__`/`__fixups__`,
   so plain `fdtoverlay` may need checking — verify the merged dtb has the
   `qcom,mdss_dsi` / panel nodes (`fdtdump | grep -i panel`).
2. **Full msm DRM/DPU** then needs `CONFIG_DRM_MSM`, DSI, and the lmi panel
   driver enabled, plus the panel dtsi (`dsi-panel-*` under vendor/qcom). The K30
   Pro panel: 1080×2400 AMOLED, 120 Hz.

Quick wins to try first:
- Set `deviceinfo_screen_width="1080"` / `deviceinfo_screen_height="2400"`.
- Check `dmesg | grep -iE 'msm_drm|mdss|dpu|dsi|panel|drm'` after boot.
- Consider a simple-framebuffer / continuous-splash path if DPU is too involved
  for a first pixel.

## Wi-Fi

SM8250 downstream Wi-Fi = **qcacld-3.0** (`wlan.ko`) on the **cnss2/icnss2**
platform driver. It needs:

1. Kernel: confirm the WLAN/cnss config builds (`grep -iE 'CNSS|ICNSS|CLD|WLAN'
   config-xiaomi-lmi.aarch64`); the wlan driver is usually a module → ensure it
   lands in the rootfs and `/lib/modules` (note: our config is mostly built-in,
   `modules-initfs` is empty — revisit).
2. Firmware: pull the lmi WLAN firmware from the device's `/vendor/firmware`
   (e.g. `board-2.bin`, `bdwlan*`, `wlanmdsp.mbn`) into `/lib/firmware` (or the
   `qca` path the driver expects).
3. Userspace remoteproc/firmware daemons (postmarketOS packages exist):
   **`rmtfs`**, **`tqftpserv`**, **`pd-mapper`** — without these the WLAN/modem
   remoteprocs won't load firmware. Add to the device package depends.
4. Check `dmesg | grep -iE 'cnss|icnss|wlan|remoteproc|rproc|adsp|wpss'` and
   `rfkill`, then `ip link` for `wlan0`.

## First steps next session (in order)

1. (approval) Plan A flash rootfs → ssh in → confirm full system boots.
2. `dmesg` triage: display (msm_drm/dpu/dsi) and wifi (cnss/remoteproc) probe.
3. Display: merge lmi overlay into the dtb; verify panel node; rebuild; retest.
4. Wi-Fi: add rmtfs/tqftpserv/pd-mapper to the device pkg; supply firmware;
   bring up `wlan0`.

## Carry-over gotchas

- The lmi device nodes are in the **dtbo overlay**, not the base dtb — this is
  the crux for BOTH panel and wlan pinmux. Merging the overlay is likely the
  single highest-leverage change.
- Remoteproc daemons (rmtfs/pd-mapper/tqftpserv) are mandatory for Qualcomm
  firmware-loaded peripherals (wifi/modem) — easy to forget.
- Keep the SELinux-off / IKHEADERS-off / LLVM-config decisions from the build
  notes; don't regress them.
