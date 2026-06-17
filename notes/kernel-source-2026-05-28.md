# Kernel Source
签名：codex_ian | 2026-05-28 13:16:00 +10:00 Australia/Sydney

## Result

The best source match for the currently installed LineageOS kernel is:

```text
repo:    LineageOS/android_kernel_xiaomi_sm8250
branch:  lineage-23.2
commit:  a5b3099017ae581aae8bf597b2f9c8c765026af1
```

This matches the phone kernel string:

```text
4.19.325-cip128-st12-perf-ga5b3099017ae
```

The short git suffix `ga5b3099017ae` maps to commit
`a5b3099017ae581aae8bf597b2f9c8c765026af1`.

## Config Fragments

Use these fragments in order:

```text
arch/arm64/configs/vendor/kona-perf_defconfig
arch/arm64/configs/vendor/debugfs.config
arch/arm64/configs/vendor/xiaomi/sm8250-common.config
arch/arm64/configs/vendor/xiaomi/lmi.config
```

Evidence from LineageOS device trees:

- `android_device_xiaomi_sm8250-common/BoardConfigCommon.mk` sets
  `TARGET_KERNEL_SOURCE := kernel/xiaomi/sm8250`.
- `android_device_xiaomi_sm8250-common/BoardConfigCommon.mk` sets
  `TARGET_KERNEL_CONFIG := vendor/kona-perf_defconfig vendor/debugfs.config vendor/xiaomi/sm8250-common.config`.
- `android_device_xiaomi_lmi/BoardConfig.mk` appends
  `TARGET_KERNEL_CONFIG += vendor/xiaomi/lmi.config`.
- `lmi.config` contains `CONFIG_MACH_XIAOMI_LMI=y`.

## Practical pmaports Values

For `artifacts/wsl-pmaports/linux-xiaomi-lmi/APKBUILD`, the likely values are:

```sh
_repository="android_kernel_xiaomi_sm8250"
_commit="a5b3099017ae581aae8bf597b2f9c8c765026af1"
```

Use the LineageOS repository for official-source alignment:

```text
https://github.com/LineageOS/android_kernel_xiaomi_sm8250
```

An alternate source candidate is:

```text
https://github.com/xiaomi-sm8250-devs/android_kernel_xiaomi_sm8250
```

The alternate currently appears closer to the installed commit as a branch head,
but the LineageOS namespace is the preferred source because the official
LineageOS device tree points to `kernel/xiaomi/sm8250`.

## Still Required

- Download or generate `config-xiaomi-lmi.aarch64`.
- Update `linux-xiaomi-lmi/APKBUILD`.
- Run `pmbootstrap checksum linux-xiaomi-lmi`.
- Build only after WSL dependencies are complete.
