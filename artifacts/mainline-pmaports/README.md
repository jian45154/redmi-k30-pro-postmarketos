# xiaomi-lmi mainline overlay reference

This directory preserves the external mainline-oriented xiaomi-lmi package set
for local comparison and future RAM-only experiments.

Imported from:

- Repository: `https://github.com/macosmojave2-alt/postmarket-xiaomi-lmi`
- Commit: `ef326f1`
- Import date: 2026-06-23

Included packages:

- `device-xiaomi-lmi`
- `firmware-xiaomi-lmi`
- `linux-postmarketos-qcom-sm8250-lmi`

This overlay is intentionally separate from `artifacts/wsl-pmaports`. The
current `wsl-pmaports` tree is the downstream fallback path that has already
booted far enough for initramfs/rootfs debugging. Do not merge these packages
into the downstream path mechanically.

Known caveats:

- `device-xiaomi-lmi` references a proprietary local
  `firmware-xiaomi-lmi-Tag.zip` for Cirrus and Focaltech blobs. That zip is not
  present here and must not be committed unless licensing is explicitly cleared.
- `linux-postmarketos-qcom-sm8250-lmi` downloads from
  `https://github.com/yuweiyuan8/linux` branch/tag `v6.19`.
- `firmware-xiaomi-lmi` downloads from
  `https://github.com/yuweiyuan8/firmware-xiaomi-lmi` commit
  `dde156380b2ac372619ed332dbe60640b838b7fe`.
- The modem patch is experimental and should not block display, touch, Wi-Fi,
  Bluetooth, audio, GPU, or sensor bring-up.

Recommended use:

1. Diff package metadata and userspace firmware layout against the downstream
   port.
2. Import low-risk userspace resources first:
   - ALSA UCM
   - `hexagonrpcd` config
   - libssc udev rule
   - firmware file lists
3. Build a separate mainline RAM-only artifact before any persistent install or
   flash attempt.
