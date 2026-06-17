# Build Failure: Host Compiler
签名：codex_ian | 2026-05-28 14:26:00 +10:00 Australia/Sydney

## Result

After switching the target kernel build to LLVM, the build failed later during
host tool compilation:

```text
../include/uapi/linux/types.h:5:10: fatal error: 'asm/types.h' file not found
```

The failing host target was:

```text
scripts/selinux/genheaders/genheaders
```

The log also showed `downstreamkernel_prepare` replacing
`include/linux/compiler-gcc.h` and explicitly advised using `REPLACE_GCCH=0` if
that causes compiler-gcc related errors.

## Change Applied

`artifacts/wsl-pmaports/linux-xiaomi-lmi/APKBUILD` was updated to:

- set `REPLACE_GCCH=0` before sourcing `downstreamkernel_prepare`
- set `HOSTCC=gcc` during prepare
- build target code with `LLVM=1 LLVM_IAS=1`
- build host tools with `HOSTCC=gcc HOSTCXX=g++`
- add `gcc` and `g++` to `makedepends`

## Retry

In WSL:

```bash
cd /mnt/c/Users/microstar/Documents/lmi_linx
cmd.exe /c scripts\\08_sync_pmaports_to_wsl.bat

export PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build linux-xiaomi-lmi
```
