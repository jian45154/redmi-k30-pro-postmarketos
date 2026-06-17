# Build Fix: Disable SELinux to Drop Host Tools

签名：codex_ian | 2026-06-17

## Root Cause

The kernel build kept failing in host-side SELinux tools:

```text
../include/uapi/linux/types.h:5:10: fatal error: asm/types.h: No such file or directory
```

Failing host targets: `scripts/selinux/genheaders` and `scripts/selinux/mdp`.

These are **host** programs (built with HOSTCC, run on the x86_64 build
machine), but they indirectly include the kernel's arm64 UAPI headers via
`security/selinux/include/classmap.h -> <linux/capability.h> -> <linux/types.h>
-> <asm/types.h>`. On arm64, `asm/types.h` is a `generic-y` wrapper that only
exists after `make prepare/archprepare` generates
`out/arch/arm64/include/generated/uapi/asm/types.h`.

Two mechanisms made the previous `HOST_EXTRACFLAGS` / `KBUILD_HOSTCFLAGS`
include-injection approach fragile:

1. **Generation-order race** — the selinux host-tool Makefiles do not depend on
   the generated UAPI headers, so they can compile before those headers exist.
2. **make override semantics** — passing `HOST_EXTRACFLAGS=` / `KBUILD_HOSTCFLAGS=`
   on the command line overrides the in-Makefile `+=`, which can drop the
   includes the tools actually need.

These host tools are built **only because** `CONFIG_SECURITY_SELINUX=y`.

## Change Applied

postmarketOS replaces Android userspace entirely and the server bring-up
milestone does not need Android SELinux, so SELinux was disabled at the root.

`linux-xiaomi-lmi/config-xiaomi-lmi.aarch64`:

```diff
-CONFIG_SECURITY_SELINUX=y
-# CONFIG_SECURITY_SELINUX_BOOTPARAM is not set
-# CONFIG_SECURITY_SELINUX_DISABLE is not set
-CONFIG_SECURITY_SELINUX_DEVELOP=y
-CONFIG_SECURITY_SELINUX_AVC_STATS=y
-CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=0
-CONFIG_SECURITY_SELINUX_SIDTAB_HASH_BITS=9
+# CONFIG_SECURITY_SELINUX is not set
...
-CONFIG_DEFAULT_SECURITY_SELINUX=y
-# CONFIG_DEFAULT_SECURITY_DAC is not set
-CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,selinux,smack,tomoyo,apparmor,bpf"
+# CONFIG_DEFAULT_SECURITY_SELINUX is not set
+CONFIG_DEFAULT_SECURITY_DAC=y
+CONFIG_LSM="lockdown,yama,loadpin,safesetid,integrity,bpf"
```

`linux-xiaomi-lmi/APKBUILD` — removed the fragile host include injection,
restored a clean LLVM build:

- `prepare()`: keep only `REPLACE_GCCH=0`; dropped `HOST_EXTRACFLAGS` /
  `KBUILD_HOSTCFLAGS` exports.
- `build()`: plain `make O=out ARCH=arm64 LLVM=1 LLVM_IAS=1`; dropped `V=1`,
  `HOSTCC/HOSTCXX`, and the `KBUILD_HOSTCFLAGS` include list.
- `package()`: `dtbs_install` without the host include list.

## Retry (interactive, in WSL — sudo needs ian's password)

```bash
cd /mnt/c/Users/microstar/Documents/lmi_linx
cmd.exe /c scripts\08_sync_pmaports_to_wsl.bat

export PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build linux-xiaomi-lmi
```

## Pass / Fail Criteria

- PASS: build reaches `Image.gz`/`Image` + dtbs and produces
  `aarch64/linux-xiaomi-lmi-4.19.325-r0.apk`. No `asm/types.h` error, no
  `scripts/selinux/genheaders` or `mdp` compile step in the log.
- If `olddefconfig` re-enables SELinux: a fragment is forcing it on. Re-check
  `sm8250-common.config` / `lmi.config` and pin `# CONFIG_SECURITY_SELINUX is
  not set` after the merge.
- If a NEW host tool fails the same way (`asm/types.h`), fall back to備選 A:
  add `make O=out ARCH=arm64 LLVM=1 prepare` at the end of `prepare()` to
  pre-generate the UAPI headers.

## Outcome — RESOLVED 2026-06-17 21:29

`linux-xiaomi-lmi-4.19.325-r0.apk` built successfully (16 min). The full fix
chain that got the kernel to build:

1. Removed the `KBUILD_HOSTCFLAGS=` / `HOST_EXTRACFLAGS=` command-line injection
   from the APKBUILD. Passing those on the make command line overrode the
   kernel's own per-tool `HOST_EXTRACFLAGS +=`, dropping the SELinux host tools'
   `-Isecurity/selinux/include` and the arch UAPI dirs — that was the real cause
   of the `asm/types.h` / `classmap.h` failures, not SELinux itself.
2. `# CONFIG_IKHEADERS is not set` — removed the fragile `kheaders_data.tar.xz`
   step (the `tar: Wrote only 4096 of 10240 bytes` short write; disk was NOT
   full — 930G free — most likely xz OOM-killed).
3. `export LLVM=1 LLVM_IAS=1` in `prepare()` — the config step (`make oldconfig`
   via `downstreamkernel_prepare`) was deriving `LD=aarch64-alpine-linux-musl-ld`
   from abuild's `CROSS_COMPILE`, which is not installed (we build with LLVM).
   Forcing LLVM at config time makes the Kconfig linker probe use `ld.lld`.

Also disabled SELinux (`# CONFIG_SECURITY_SELINUX is not set`) — not strictly
required after fix #1, but reduces the build and is fine for a server bring-up.
Removed 4 unused gcc*.patch files and `g++` from makedepends (abuild warnings).

### Sync gotcha (cost several cycles)

`scripts/08_sync_pmaports_to_wsl.bat` is a Windows batch script; running it from
inside WSL bash fails with `cmd.exe: command not found`, so edits silently never
reached pmbootstrap's pmaports. Sync directly in bash instead:

```bash
SRC=/mnt/c/Users/microstar/Documents/lmi_linx/artifacts/wsl-pmaports
DST=/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream
rm -f "$DST"/linux-xiaomi-lmi/*.patch
cp -a "$SRC"/linux-xiaomi-lmi/.  "$DST"/linux-xiaomi-lmi/
cp -a "$SRC"/device-xiaomi-lmi/. "$DST"/device-xiaomi-lmi/
```

pmbootstrap's aports = `/home/microstar/.local/var/pmbootstrap/cache_git/pmaports`.

## Next Steps

1. `pmbootstrap build device-xiaomi-lmi`
2. `pmbootstrap install` to assemble the rootfs + boot image.
3. `pmbootstrap export` to get `boot.img` for a **temporary** `fastboot boot`
   test — requires ian's explicit approval (human gate, no flashing).

## Safety Status

No `fastboot flash/erase/format/boot` and no `pmbootstrap flasher` command was
run. This change only affects the build inputs.
