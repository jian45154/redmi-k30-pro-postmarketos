# Build Failure: Host UAPI Include
签名：codex_ian | 2026-05-28 14:31:00 +10:00 Australia/Sydney

## Result

The build still failed in host-side SELinux tools:

```text
../include/uapi/linux/types.h:5:10: fatal error: asm/types.h: No such file or directory
```

The missing generated header exists under the build output directory:

```text
out/arch/arm64/include/generated/uapi/asm/types.h
```

## Change Applied

`linux-xiaomi-lmi/APKBUILD` now passes explicit host include paths through
`HOST_EXTRACFLAGS` during prepare, build, and `dtbs_install`:

```text
-I$out/arch/arm64/include/generated/uapi
-Iarch/arm64/include/uapi
-I$out/include/generated/uapi
-Iinclude/uapi
```

This keeps target compilation on LLVM while giving host tools access to the
generated ARM64 UAPI headers.

## Retry

In WSL:

```bash
export PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build linux-xiaomi-lmi
```
