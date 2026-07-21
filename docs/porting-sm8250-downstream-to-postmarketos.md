# Porting a downstream SM8250 Android kernel to postmarketOS — lessons learned

Booting **Redmi K30 Pro / POCO F2 Pro (`lmi`, Snapdragon 865 / SM8250)** on
postmarketOS, building the downstream LineageOS 4.19 vendor kernel with
**Clang/LLVM** under **WSL2 (Ubuntu) + pmbootstrap**.

This is a field log of the non-obvious things that cost real time. Most apply to
**any sm8250 / downstream-MSM device** (umi, cmi, alioth, munch, …) and to
downstream Android kernels in general, not just `lmi`.

## TL;DR — what worked

- Kernel: `LineageOS/android_kernel_xiaomi_sm8250` @ `a5b3099` (matches the stock
  string `4.19.325-cip128-st12-perf-ga5b3099017ae`), built with `LLVM=1`.
- Config merged from `vendor/kona-perf_defconfig` + `debugfs.config` +
  `xiaomi/sm8250-common.config` + `xiaomi/lmi.config`, then **SELinux off**.
- Full image builds; `fastboot boot` runs the kernel on real hardware; USB
  networking (CDC-NCM gadget) is reachable from the host.

## Environment

- Windows 11 + WSL2 (Ubuntu 22.04), pmbootstrap 3.10, channel `edge`.
- Device package under `pmaports/device/downstream/{device,linux}-xiaomi-lmi`.
- Cross build mode `pmb:cross-native`, target toolchain Clang/LLVM + ld.lld.

---

## Gotcha 1 — SELinux host tools fail: `asm/types.h: No such file or directory`

Building `scripts/selinux/genheaders` / `mdp` (host programs) fails with missing
`asm/types.h` or `classmap.h`. These host tools `#include` the kernel's arm64
UAPI headers.

**The trap that makes it worse:** injecting include paths via
`make ... KBUILD_HOSTCFLAGS="..."` or `HOST_EXTRACFLAGS="..."` on the **command
line**. GNU make command-line assignments *override* the in-Makefile
`HOST_EXTRACFLAGS += -I.../security/selinux/include`, so you actually **drop**
the include the tool needs. That turned `asm/types.h` into `classmap.h` and back
in a loop.

**Fix:** don't fight the host include paths at all. These tools are only built
because `CONFIG_SECURITY_SELINUX=y`. postmarketOS replaces Android userspace, so
SELinux is not needed for bring-up:

```diff
-CONFIG_SECURITY_SELINUX=y
+# CONFIG_SECURITY_SELINUX is not set
-CONFIG_DEFAULT_SECURITY_SELINUX=y
+CONFIG_DEFAULT_SECURITY_DAC=y
 CONFIG_LSM="...,selinux,smack,tomoyo,apparmor,bpf"   # drop selinux from the list
```

…and remove any `KBUILD_HOSTCFLAGS=`/`HOST_EXTRACFLAGS=` injection from the
APKBUILD. The whole host-tool failure class disappears.

## Gotcha 2 — `kernel/kheaders_data.tar.xz` Error 2 (`tar: Wrote only 4096 of 10240 bytes`)

`CONFIG_IKHEADERS=y` runs `gen_kheaders.sh`, which is fragile in cross / `O=out`
builds (here the `xz` pipe died — looked like a short write but the disk was 97%
free). `/proc/kheaders.tar.xz` is useless for a server.

**Fix:** `# CONFIG_IKHEADERS is not set`.

## Gotcha 3 — config step: `linker 'aarch64-alpine-linux-musl-ld' not found`

`prepare()` runs `make oldconfig` via `downstreamkernel_prepare`. abuild exports
`CROSS_COMPILE=aarch64-alpine-linux-musl-`, so make derives
`LD=aarch64-alpine-linux-musl-ld` — which isn't installed (we build with LLVM).
`scripts/Kconfig.include` probes `$(LD)` and aborts. (It only surfaces once the
chroot is refreshed and the stale GNU cross-binutils are gone.)

**Fix:** configure with the *same* toolchain you build with. Export LLVM in
`prepare()` so `$(LD)` becomes `ld.lld`:

```sh
prepare() {
	default_prepare
	export LLVM=1 LLVM_IAS=1
	export REPLACE_GCCH=0
	. downstreamkernel_prepare
}
```

## Gotcha 4 — no device trees built; `make dtbs_install` installs nothing

Two layered problems:

1. On arm64 the default target builds `Image.gz` but **not** dtbs. Add an
   explicit `make ... dtbs`.
2. Even then, `make dtbs_install` does **not** understand this downstream qcom
   *overlay* tree. `make dtbs` produces the blobs in
   `out/arch/arm64/boot/dts/vendor/qcom/` (`kona.dtb`, `kona-v2.dtb`,
   `kona-v2.1.dtb`, `lmi-sm8250-overlay.dtbo`) but `dtbs_install` collects none
   of them.

**Fix:** build dtbs explicitly and copy the blobs by hand in `package()`. (Probe
trick to confirm what got built, since abuild wipes `srcdir` after packaging:
`find "$_outdir/arch/arm64/boot/dts" -name '*.dtb*'` at the end of `build()`.)

## Gotcha 5 — `deviceinfo_dtb`: header v2 takes exactly ONE dtb; overlay model

Qualcomm downstream uses **base DTB + per-device DTBO overlay**:
`lmi-sm8250-overlay.dtbo-base := kona.dtb kona-v2.dtb kona-v2.1.dtb`. Android's
bootloader merges the base (chosen by SoC revision via `qcom,msm-id`) with the
device dtbo from the `dtbo` partition at boot.

- boot image header v2 allows **one** dtb. Listing three →
  `deviceinfo_dtb specifies more than one dtb!`.
- Ship all three bases in the kernel apk anyway, so switching revisions is a
  one-line deviceinfo change + device-pkg rebuild (no kernel rebuild).
- `qcom/kona-v2.1` matched and booted on this lmi unit. If a peripheral is
  missing, try `kona-v2` / `kona`.
- The lmi bootloader is expected to apply the device's existing dtbo partition
  overlay on top of whichever base the boot image carries.

```sh
deviceinfo_dtb="qcom/kona-v2.1"
```

## Gotcha 6 — pmbootstrap / WSL workflow papercuts

- **`pmbootstrap build` says "is up to date"** when only the config/recipe
  contents changed but `pkgver-pkgrel` didn't → use `--force`.
- **A Windows `.bat` sync script run from inside WSL bash** fails silently with
  `cmd.exe: command not found`; your edits never reach pmbootstrap's pmaports.
  Sync with a plain `cp` in WSL, and **verify the destination** before building.
  pmbootstrap's aports here: `~/.local/var/pmbootstrap/cache_git/pmaports`.
- After editing source files, re-run `pmbootstrap checksum <pkg>` or abuild
  fails with `<file> is missing in checksums`.

## Gotcha 7 — talking to the device over USB from Windows

A temporary boot avoids an explicit partition flash, but the booted operating
system may still modify persisted userdata. Never pass an arbitrary image to
fastboot. For the reviewed D110 recovery image, use the repository's guarded
authorize/execute workflow described in
[`lmi-d110-session-approval.md`](lmi-d110-session-approval.md). After boot, the
postmarketOS gadget enumerates as **`18d1:d001 POSTMARKETOS`**, a **CDC-NCM**
network gadget — but Windows binds an "ADB interface" and exposes no network
adapter.

**Fix:** pass the USB device into WSL with **usbipd-win**; Linux supports CDC-NCM
natively:

```powershell
winget install usbipd
usbipd bind   --busid <BUSID>     # the 18d1:d001 line in `usbipd list`
usbipd attach --wsl --busid <BUSID>
```
```bash
# in WSL — the gadget shows up as enxXXXXXXXXXXXX (was usb0)
IF=$(ip -br link | awk '/^enx/{print $1; exit}')
sudo ip link set "$IF" up
sudo ip addr add 172.16.42.2/24 dev "$IF"
ping 172.16.42.1            # device side; ~3 ms
ssh  lmi@172.16.42.1        # only once a rootfs is flashed (see below)
```

**Note:** a RAM-only `fastboot boot` has no flashed rootfs, so the initramfs
can't mount root and no network shell is exposed (`ssh`/`telnet` refused even
though `ping` works). That's expected — it proves kernel + USB, not a full
system. A full shell needs the rootfs written to `userdata`.

---

## Final working `linux-xiaomi-lmi/APKBUILD`

```sh
maintainer=""
pkgname=linux-xiaomi-lmi
pkgver=4.19.325
pkgrel=0
pkgdesc="xiaomi lmi kernel fork"
arch="aarch64"
_carch="arm64"
_flavor="xiaomi-lmi"
url="https://github.com/LineageOS/android_kernel_xiaomi_sm8250"
license="GPL-2.0-only"
options="!strip !check !tracedeps pmb:cross-native"
makedepends="bash bc bison clang devicepkg-dev findutils flex gcc lld llvm openssl-dev perl"

_repository="android_kernel_xiaomi_sm8250"
_commit="a5b3099017ae581aae8bf597b2f9c8c765026af1"
_config="config-$_flavor.$arch"
source="
	$pkgname-$_commit.tar.gz::https://github.com/LineageOS/$_repository/archive/$_commit.tar.gz
	$_config
"
builddir="$srcdir/$_repository-$_commit"
_outdir="out"

prepare() {
	default_prepare
	export LLVM=1 LLVM_IAS=1          # config with the same toolchain as build (ld.lld)
	export REPLACE_GCCH=0             # keep the tree's own compiler-gcc.h
	. downstreamkernel_prepare
}

build() {
	unset LDFLAGS
	make O="$_outdir" ARCH="$_carch" LLVM=1 LLVM_IAS=1 \
		KBUILD_BUILD_VERSION="$((pkgrel + 1 ))-postmarketOS"
	make O="$_outdir" ARCH="$_carch" LLVM=1 LLVM_IAS=1 dtbs
}

package() {
	downstreamkernel_package "$builddir" "$pkgdir" "$_carch" "$_flavor" "$_outdir"
	_dts="$builddir/$_outdir/arch/arm64/boot/dts/vendor/qcom"
	install -Dm644 "$_dts/kona.dtb"      "$pkgdir/boot/dtbs/qcom/kona.dtb"
	install -Dm644 "$_dts/kona-v2.dtb"   "$pkgdir/boot/dtbs/qcom/kona-v2.dtb"
	install -Dm644 "$_dts/kona-v2.1.dtb" "$pkgdir/boot/dtbs/qcom/kona-v2.1.dtb"
	install -Dm644 "$_dts/lmi-sm8250-overlay.dtbo" \
		"$pkgdir/boot/dtbs/qcom/lmi-sm8250-overlay.dtbo"
}

sha512sums="(run 'pmbootstrap checksum linux-xiaomi-lmi' to fill)"
```

Key `config-xiaomi-lmi.aarch64` deltas vs. the merged downstream defconfig:
`# CONFIG_SECURITY_SELINUX is not set`, `CONFIG_DEFAULT_SECURITY_DAC=y`,
`# CONFIG_IKHEADERS is not set`.

## Reproduce

```bash
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build    linux-xiaomi-lmi          # ~16 min cold, Clang/LLVM
pmbootstrap checksum device-xiaomi-lmi
pmbootstrap build    device-xiaomi-lmi
pmbootstrap install  --no-fde
pmbootstrap export                              # -> /tmp/postmarketOS-export/boot.img
```

Do not boot that arbitrary export directly. A candidate must first be reviewed
and pinned. From the repository root, the existing reviewed D110 recovery image
uses only this guarded flow:

```bash
scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --authorize-session
scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --execute
```

See [`lmi-d110-session-approval.md`](lmi-d110-session-approval.md) for scope,
revocation, and the residual persisted-userdata risk.

## Status

- ✅ Kernel + DTBs + image build; boots on hardware via `fastboot boot`.
- ✅ USB networking works (CDC-NCM, reachable from the host via usbipd→WSL).
- ⏳ No persistent install yet — needs the rootfs flashed to `userdata`
  (destructive; keep a LineageOS/MIUI recovery path ready first).
- ⏳ Display/panel, modem, Wi-Fi, etc. not yet validated (headless-server focus).

---

*Built and debugged as a porting exercise. Kernel sources are GPL-2.0
(LineageOS). The lmi pmaports recipe here is contributed in the same spirit —
adapt freely for sibling SM8250 devices.*
