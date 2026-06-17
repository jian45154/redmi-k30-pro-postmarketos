# Kernel Config
签名：codex_ian | 2026-05-28 13:30:00 +10:00 Australia/Sydney

## Result

`config-xiaomi-lmi.aarch64` was generated successfully after installing WSL
kernel-build dependencies.

Generated file:

```text
artifacts/wsl-pmaports/linux-xiaomi-lmi/config-xiaomi-lmi.aarch64
```

Observed size:

```text
173636 bytes
```

## Source

The config was generated from the pinned LineageOS kernel source:

```text
repo:   https://github.com/LineageOS/android_kernel_xiaomi_sm8250
commit: a5b3099017ae581aae8bf597b2f9c8c765026af1
```

Config fragments used:

```text
arch/arm64/configs/vendor/kona-perf_defconfig
arch/arm64/configs/vendor/debugfs.config
arch/arm64/configs/vendor/xiaomi/sm8250-common.config
arch/arm64/configs/vendor/xiaomi/lmi.config
```

## Next Step

Sync the updated pmaports package back into WSL pmbootstrap's pmaports worktree,
then run:

```sh
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap checksum device-xiaomi-lmi
pmbootstrap build linux-xiaomi-lmi
pmbootstrap build device-xiaomi-lmi
```

Do not run any flasher command yet.
