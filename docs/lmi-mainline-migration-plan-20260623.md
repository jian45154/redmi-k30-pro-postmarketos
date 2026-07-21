# xiaomi-lmi mainline migration plan

Date: 2026-06-23

> **Archived evidence — do not execute commands from this file.**
> This plan predates the recorded M-r6/M-r7 write results and the current D110
> guarded RAM-boot policy. Its action language is retained only as history.

## Goal

Use the existing xiaomi-lmi mainline work as the primary source for basic
hardware support, while preserving the current downstream kernel path as a
debug fallback.

## Current local baseline

The current `artifacts/wsl-pmaports` path is downstream based:

- Kernel package: `linux-xiaomi-lmi`
- Device DTB: `qcom/kona-v2.1-lmi`
- Runtime firmware strategy: mount Android modem firmware partition and expose
  aliases under `/lib/firmware`
- Current proven milestone: RAM-only downstream boot reaches initramfs/rootfs
  debugging; v32 initramfs hook successfully mounts firmware before
  `switch_root` and lets Venus firmware load.

This path is useful for boot/rootfs/debug work but is not the best basis for
display, GPU, Wi-Fi, Bluetooth, audio, sensors, and touch, because the available
hardware support evidence points to a mainline package set.

## Imported reference overlay

Imported under `artifacts/mainline-pmaports`:

- `device-xiaomi-lmi`
- `firmware-xiaomi-lmi`
- `linux-postmarketos-qcom-sm8250-lmi`

Source repository:

- `https://github.com/macosmojave2-alt/postmarket-xiaomi-lmi`
- Imported commit: `ef326f1`

Supporting source repositories verified:

- `https://github.com/yuweiyuan8/linux`, branch `v6.19`,
  commit `999ef8bfd90ca4c214f18ac5d0138bf380386c38`
- `https://github.com/yuweiyuan8/firmware-xiaomi-lmi`, commit
  `dde156380b2ac372619ed332dbe60640b838b7fe`

## First reusable pieces

These can be compared or imported with low risk because they are userspace or
packaging resources:

- ALSA UCM:
  - `device-xiaomi-lmi/alsa-ucm-conf/lmi.conf`
  - `device-xiaomi-lmi/alsa-ucm-conf/HiFi.conf`
- Sensor/ADSP userspace:
  - `device-xiaomi-lmi/hexagonrpcd.confd`
  - `device-xiaomi-lmi/81-libssc-xiaomi-lmi.rules`
- Firmware layout:
  - `firmware-xiaomi-lmi/firmware.files`
  - `firmware-xiaomi-lmi/sensor.files`
  - `firmware-xiaomi-lmi/30-initramfs-firmware.files`
- Mainline device metadata:
  - `deviceinfo_dtb="qcom/sm8250-xiaomi-lmi"`
  - `deviceinfo_append_dtb="true"`
  - `deviceinfo_rootfs_image_sector_size="4096"`

## Pieces not safe to merge blindly

- The mainline `deviceinfo` is for a different kernel/DTB path and must not
  replace the downstream `deviceinfo` in `artifacts/wsl-pmaports`.
- The external `device-xiaomi-lmi` references proprietary
  `firmware-xiaomi-lmi-Tag.zip`, which is not present and should not be
  committed without license review.
- The modem patch enables SDX55 over PCIe for mainline. It does not apply to
  the current downstream boot path.
- Persistent flash commands from the external README were not approved for
  this historical plan. Do not reuse its old direct RAM-boot guidance; current
  candidates require a newly reviewed and pinned device-action workflow.

## Migration steps

1. Keep `artifacts/wsl-pmaports` unchanged as the downstream fallback.
2. Make `artifacts/mainline-pmaports` buildable as a separate overlay:
   - resolve the missing `firmware-xiaomi-lmi-Tag.zip` dependency;
   - or temporarily disable the subpackage sections that require that local
     proprietary zip for first boot experiments.
3. Build only the mainline package set:
   - `firmware-xiaomi-lmi`
   - `linux-postmarketos-qcom-sm8250-lmi`
   - `device-xiaomi-lmi`
4. Generate a RAM-only boot image and inspect before connecting hardware:
   - boot image header v2, offsets, DTB name, initramfs contents, modules, and
     firmware files.
5. RAM-only test mainline boot.
6. Validate hardware in this order:
   - USB networking and SSH
   - display and touch
   - GPU/Freedreno
   - Wi-Fi and Bluetooth
   - audio
   - battery/charging
   - sensors through `hexagonrpcd`
   - modem last, separately

## Decision rule

If the mainline route boots far enough for shell access, prioritize mainline for
basic hardware. Keep downstream only for recovery/debug and for cases where a
mainline subsystem is clearly missing.
