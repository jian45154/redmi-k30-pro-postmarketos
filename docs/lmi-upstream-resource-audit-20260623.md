# xiaomi-lmi upstream resource audit

Date: 2026-06-23

## Summary

The postmarketOS wiki page for xiaomi-lmi reports many basic hardware blocks as
working, but current official pmaports does not contain an upstream
`device-xiaomi-lmi` package. The reusable work is in an external mainline-based
repository, not in the official pmaports tree we are currently building from.

The current local port is downstream-kernel based. Further hardware work should
stop treating each missing block as a new downstream bring-up problem and should
instead compare against the mainline lmi resources below.

## Confirmed sources

- postmarketOS wiki page:
  `https://wiki.postmarketos.org/wiki/Xiaomi_POCO_F2_Pro_/_Redmi_K30_Pro_(xiaomi-lmi)`
  - Direct page access is currently blocked by Anubis from this environment.
  - Search snippets and the external package README both reference this page as
    the hardware-status source.
- Official pmaports:
  `https://gitlab.postmarketos.org/postmarketOS/pmaports`
  - `main`: no `device-xiaomi-lmi` package found.
  - `master`: no `device-xiaomi-lmi` package found.
  - Reusable official package: `linux-postmarketos-qcom-sm8250`, currently a
    generic SM8250 mainline package.
- Official/community SM8250 kernel:
  `https://gitlab.postmarketos.org/soc/qualcomm-sm8250/linux`
  - Branch/tag checked: `6.17.0` / `sm8250-6.17.0`.
  - Contains SM8250 Xiaomi tablet DTS files such as `elish`, `enuma`, and
    `pipa`, but no `sm8250-xiaomi-lmi.dts`.
- External lmi port:
  `https://github.com/macosmojave2-alt/postmarket-xiaomi-lmi`
  - Contains `device-xiaomi-lmi`, `firmware-xiaomi-lmi`, and
    `linux-postmarketos-qcom-sm8250-lmi`.
  - Claims working: display, Adreno 650 GPU, Wi-Fi, Bluetooth, audio, touch,
    battery/charging, UFS, USB OTG, NFC, flash LED, IR TX, basic sensors, and
    partial camera.
  - Claims broken or incomplete: GPS, proximity, haptics; modem is experimental.
- External lmi mainline kernel:
  `https://github.com/yuweiyuan8/linux`
  - Verified branch: `v6.19` at
    `999ef8bfd90ca4c214f18ac5d0138bf380386c38`.
  - The external package expects this branch to provide
    `sm8250-xiaomi-lmi.dts`.
- External lmi firmware:
  `https://github.com/yuweiyuan8/firmware-xiaomi-lmi`
  - Verified main/HEAD:
    `dde156380b2ac372619ed332dbe60640b838b7fe`.

## Reusable implementation details

The external `device-xiaomi-lmi` package depends on a mainline kernel package:

- `linux-postmarketos-qcom-sm8250-lmi`
- `alsa-ucm-conf`
- `hexagonrpcd`
- `make-dynpart-mappings`
- `mesa-vulkan-freedreno`
- `qbootctl`
- `bootmac`
- `swclock-offset`

Important deviceinfo values from the external package:

- `deviceinfo_dtb="qcom/sm8250-xiaomi-lmi"`
- `deviceinfo_append_dtb="true"`
- `deviceinfo_header_version="2"`
- `deviceinfo_flash_pagesize="4096"`
- `deviceinfo_rootfs_image_sector_size="4096"`
- `deviceinfo_super_partitions="/dev/sda36 /dev/sda36"`

Firmware package layout:

- Runtime firmware path:
  `/lib/firmware/qcom/sm8250/xiaomi/lmi/`
- Includes:
  `a650_zap.mbn`, `adsp.mbn`, `cdsp.mbn`, `ipa_fws.mbn`, `slpi.mbn`,
  `venus.mbn`, and related JSON metadata.
- Initramfs firmware list includes:
  `/lib/firmware/qcom/sm8250/xiaomi/lmi/a650_zap.mbn`,
  `/lib/firmware/qcom/a650_sqe.fw`, and
  `/lib/firmware/qcom/a650_gmu.bin`.

Mainline modem patch from the external package:

- Enables `&pcie1` and `&pcie1_phy` for the external SDX55 modem.
- Expects the modem to be probed by `mhi_pci_generic` as PCI ID `17cb:0306`.
- Notes that `qcom/sdx55m/sbl1.mbn` and `edl.mbn` are required.

## Recommended direction

1. Preserve the current downstream branch as a boot/debug fallback.
2. Create a separate mainline experiment branch or package set based on:
   - `device-xiaomi-lmi` from `macosmojave2-alt/postmarket-xiaomi-lmi`
   - `firmware-xiaomi-lmi` from `yuweiyuan8/firmware-xiaomi-lmi`
   - `linux-postmarketos-qcom-sm8250-lmi` from `yuweiyuan8/linux:v6.19`
3. Compare hardware failures against the mainline package before writing new
   downstream fixes.
4. Prioritize porting the packaging and firmware layout first:
   - ALSA UCM
   - `hexagonrpcd` SDSP firmware directory
   - libssc udev rule
   - QCOM firmware path layout
   - Adreno/venus initramfs firmware files
5. Keep modem work separate. The external repo marks SDX55 modem support as
   experimental; it should not block display, touch, Wi-Fi, Bluetooth, audio,
   sensors, or GPU bring-up.

## Immediate next steps

- Diff local downstream `device-xiaomi-lmi` against the external mainline
  package.
- Import only the non-destructive packaging pieces first: ALSA UCM, firmware
  file lists, `hexagonrpcd` config, and udev rules.
- Build a mainline-only RAM boot artifact before considering any flash action.
- Record every imported source URL and commit in package comments or manifests.
