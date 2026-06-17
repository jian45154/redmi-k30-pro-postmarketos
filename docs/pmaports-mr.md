# Submitting `xiaomi-lmi` to postmarketOS pmaports

Notes for turning the recipe in this repo into an upstream
[pmaports](https://gitlab.com/postmarketOS/pmaports) merge request. New devices
land in the **`testing`** category.

## File layout in pmaports

```
device/testing/device-xiaomi-lmi/
    APKBUILD
    deviceinfo
    modules-initfs
device/testing/linux-xiaomi-lmi/
    APKBUILD
    config-xiaomi-lmi.aarch64
```

Copy the files from this repo's `artifacts/wsl-pmaports/{device,linux}-xiaomi-lmi/`
into those paths (this repo keeps them under `device/downstream/` locally; upstream
new ports go to `device/testing/`).

## Pre-submit checklist

- [ ] **Fill `maintainer=`** in both APKBUILDs (your name + email). Upstream CI
      rejects an empty maintainer.
- [ ] Add a `# Contributor:` / `# Maintainer:` comment line per Alpine/pmOS style.
- [ ] `deviceinfo`: review required keys against the
      [deviceinfo reference](https://wiki.postmarketos.org/wiki/Deviceinfo_reference)
      — `deviceinfo_name` should be the marketing name
      ("Xiaomi Redmi K30 Pro / POCO F2 Pro"), set `deviceinfo_gpu_accelerated`,
      `deviceinfo_screen_width/height`, etc. as known.
- [ ] Run the config check: `pmbootstrap kconfig check linux-xiaomi-lmi`
      (pmOS requires certain options; fix the config until it passes).
- [ ] Build clean from a zapped chroot: `pmbootstrap zap && pmbootstrap build linux-xiaomi-lmi device-xiaomi-lmi`.
- [ ] `pmbootstrap checksum` both packages so `sha512sums` is filled (not the
      placeholder).
- [ ] Add a device wiki page (`Xiaomi Redmi K30 Pro (xiaomi-lmi)`) and a
      `deviceinfo_name`-matching entry; link it in the MR.
- [ ] Confirm what actually works for the device table (boots / USB networking /
      etc.) — be honest about `display: no`, `modem: untested`.
- [ ] Squash to clean commits, one per package is fine:
      `device/testing/device-xiaomi-lmi: new device (MR ...)` and
      `linux-xiaomi-lmi: new kernel (MR ...)`.

## Known deviations from a "clean" upstream recipe

These were pragmatic bring-up choices; reviewers may ask about them:

- **SELinux disabled** in the config to avoid the downstream SELinux host-tool
  build failure. Acceptable for pmOS, but note it in the MR.
- **DTBs installed by hand** in `package()` because `make dtbs_install` does not
  collect this qcom overlay tree. Mention this; a helper in
  `downstreamkernel_package` or a shared snippet may be preferred upstream.
- **`deviceinfo_dtb="qcom/kona-v2.1"`** (single base; header v2). The device dtbo
  overlay is applied by the bootloader from the on-device `dtbo` partition.

## Suggested MR description

> **New device: Xiaomi Redmi K30 Pro / POCO F2 Pro (xiaomi-lmi)**
>
> Adds `device-xiaomi-lmi` and `linux-xiaomi-lmi` (downstream LineageOS SM8250
> 4.19 kernel, built with Clang/LLVM).
>
> **What works**
> - Boots via `fastboot boot` (RAM); kernel + DTBs build with `LLVM=1`.
> - USB networking (CDC-NCM gadget), reachable from the host.
>
> **Not yet validated**
> - Display/panel, modem, Wi-Fi (headless bring-up).
>
> **Notes**
> - SELinux disabled in config (downstream SELinux host tools fail to build).
> - DTBs installed manually in `package()` (qcom overlay tree; `dtbs_install`
>   collects nothing). `deviceinfo_dtb=qcom/kona-v2.1`; device dtbo applied by
>   the bootloader.
>
> Kernel source: LineageOS/android_kernel_xiaomi_sm8250 @ a5b3099.

## Reuse for sibling SM8250 devices

The same kernel/Makefile covers umi, cmi, alioth, munch, elish, enuma, … Each has
its own `*-sm8250-overlay.dtbo` with `-base := kona.dtb kona-v2.dtb kona-v2.1.dtb`.
To port a sibling: copy this kernel package, keep the build/package logic, swap the
device codename and `deviceinfo_dtb` base if needed, and provide that device's
merged config.
