# Build Failure: Compiler Path
签名：codex_ian | 2026-05-28 14:22:00 +10:00 Australia/Sydney

## Result

After removing obsolete template patches, `linux-xiaomi-lmi` reached the kernel
build phase and failed during early preparation.

The key error was:

```text
../include/linux/compiler-gcc.h:2:2: error: #error "Please don't include <linux/compiler-gcc.h> directly, include <linux/compiler.h> instead."
```

The build command was using the Alpine GCC cross compiler:

```text
CC=aarch64-alpine-linux-musl-gcc
```

## Assessment

This LineageOS Android kernel should be built with Clang/LLVM rather than the
Alpine musl GCC cross compiler.

## Change Applied

`artifacts/wsl-pmaports/linux-xiaomi-lmi/APKBUILD` was changed to:

- add `clang`, `llvm`, and `lld` to `makedepends`
- build with `LLVM=1 LLVM_IAS=1`
- run `dtbs_install` with `LLVM=1 LLVM_IAS=1`

## Next Command

Sync to WSL, then rebuild interactively in WSL:

```bash
cd /mnt/c/Users/microstar/Documents/lmi_linx
cmd.exe /c scripts\\08_sync_pmaports_to_wsl.bat

export PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build linux-xiaomi-lmi
```

No flashing command is involved.
