# 把下游 SM8250 安卓内核移植到 postmarketOS——踩坑实录

把 **红米 K30 Pro / POCO F2 Pro（`lmi`，骁龙 865 / SM8250）** 跑上 postmarketOS：
在 **WSL2（Ubuntu）+ pmbootstrap** 下,用 **Clang/LLVM** 编译下游 LineageOS 4.19
厂商内核。

这是一份「真正花了时间」的非显而易见问题清单。绝大多数适用于**任何 sm8250 /
下游 MSM 设备**(umi、cmi、alioth、munch……)以及下游安卓内核通用,不只 `lmi`。

> English version: [porting-sm8250-downstream-to-postmarketos.md](porting-sm8250-downstream-to-postmarketos.md)

## TL;DR——最终怎么通的

- 内核:`LineageOS/android_kernel_xiaomi_sm8250` @ `a5b3099`(对应机内串
  `4.19.325-cip128-st12-perf-ga5b3099017ae`),用 `LLVM=1` 编译。
- config 由 `vendor/kona-perf_defconfig` + `debugfs.config` +
  `xiaomi/sm8250-common.config` + `xiaomi/lmi.config` 合并,然后**关掉 SELinux**。
- 完整镜像可构建;`fastboot boot` 在真机运行内核;主机能连上 USB 网络(CDC-NCM)。

## 环境

- Windows 11 + WSL2(Ubuntu 22.04),pmbootstrap 3.10,`edge` 通道。
- 设备包位于 `pmaports/device/downstream/{device,linux}-xiaomi-lmi`。
- 交叉构建模式 `pmb:cross-native`,目标工具链 Clang/LLVM + ld.lld。

---

## 坑 1 — SELinux host 工具报 `asm/types.h: No such file or directory`

编译 `scripts/selinux/genheaders` / `mdp`(host 程序)时报缺 `asm/types.h` 或
`classmap.h`。这俩 host 工具 `#include` 了内核的 arm64 UAPI 头。

**让它更糟的陷阱:** 用 `make ... KBUILD_HOSTCFLAGS="..."` 或
`HOST_EXTRACFLAGS="..."` 在**命令行**注入 include 路径。GNU make 的命令行赋值会
**覆盖** Makefile 里的 `HOST_EXTRACFLAGS += -I.../security/selinux/include`,于是
你反而**把工具需要的 include 冲掉了**。这会让报错在 `asm/types.h` 和 `classmap.h`
之间反复横跳。

**修法:** 根本别去跟 host include 路径较劲。这俩工具只因 `CONFIG_SECURITY_SELINUX=y`
才会被编译。postmarketOS 会替换掉安卓用户空间,bring-up 阶段不需要 SELinux:

```diff
-CONFIG_SECURITY_SELINUX=y
+# CONFIG_SECURITY_SELINUX is not set
-CONFIG_DEFAULT_SECURITY_SELINUX=y
+CONFIG_DEFAULT_SECURITY_DAC=y
 CONFIG_LSM="...,selinux,smack,tomoyo,apparmor,bpf"   # 从列表里删掉 selinux
```

……并把 APKBUILD 里所有 `KBUILD_HOSTCFLAGS=`/`HOST_EXTRACFLAGS=` 注入删掉。整类
host 工具失败就此消失。

## 坑 2 — `kernel/kheaders_data.tar.xz` Error 2(`tar: Wrote only 4096 of 10240 bytes`)

`CONFIG_IKHEADERS=y` 会跑 `gen_kheaders.sh`,在 cross / `O=out` 构建下很脆(这里是
`xz` 管道挂了——看着像磁盘短写,其实盘还空着 97%)。`/proc/kheaders.tar.xz` 对服务器
毫无用处。

**修法:** `# CONFIG_IKHEADERS is not set`。

## 坑 3 — 配置阶段报 `linker 'aarch64-alpine-linux-musl-ld' not found`

`prepare()` 通过 `downstreamkernel_prepare` 跑 `make oldconfig`。abuild 导出了
`CROSS_COMPILE=aarch64-alpine-linux-musl-`,于是 make 推导出
`LD=aarch64-alpine-linux-musl-ld`——而它没安装(我们用 LLVM 编)。
`scripts/Kconfig.include` 探测 `$(LD)` 失败即中止。(这个坑只有在 chroot 刷新、旧的
GNU 交叉 binutils 被清掉后才暴露出来。)

**修法:** 用和构建**同一套**工具链来配置。在 `prepare()` 里导出 LLVM,让 `$(LD)`
变成 `ld.lld`:

```sh
prepare() {
	default_prepare
	export LLVM=1 LLVM_IAS=1
	export REPLACE_GCCH=0
	. downstreamkernel_prepare
}
```

## 坑 4 — 设备树没编出来;`make dtbs_install` 啥也不装

两层问题叠加:

1. arm64 默认目标只编 `Image.gz`,**不编** dtbs。要显式 `make ... dtbs`。
2. 即便编了,`make dtbs_install` **不认**这套下游高通 *overlay* 树。`make dtbs`
   会在 `out/arch/arm64/boot/dts/vendor/qcom/` 产出 blob(`kona.dtb`、
   `kona-v2.dtb`、`kona-v2.1.dtb`、`lmi-sm8250-overlay.dtbo`),但 `dtbs_install`
   一个都收不走。

**修法:** 显式编 dtbs,在 `package()` 里手动拷贝。(探针技巧:因为 abuild 打包后会清
`srcdir`,在 `build()` 末尾加 `find "$_outdir/arch/arm64/boot/dts" -name '*.dtb*'`
确认到底编出了啥。)

## 坑 5 — `deviceinfo_dtb`:header v2 只能放一个 dtb;基座/overlay 模型

高通下游用 **基座 DTB + 设备 DTBO overlay**:
`lmi-sm8250-overlay.dtbo-base := kona.dtb kona-v2.dtb kona-v2.1.dtb`。安卓
bootloader 启动时按 SoC 版本(`qcom,msm-id`)选基座,再叠加 `dtbo` 分区里的设备
overlay。

- boot 镜像 header v2 只能放**一个** dtb。列三个会报
  `deviceinfo_dtb specifies more than one dtb!`。
- 但还是把三个基座都打进内核 apk,这样换版本只是改一行 deviceinfo + 重打 device 包
  (不用重编内核)。
- `qcom/kona-v2.1` 在这台 lmi 上匹配并启动成功。若某外设缺失,试 `kona-v2` / `kona`。
- lmi bootloader 预期会把手机上已有的 dtbo 分区 overlay 叠加到 boot 镜像所带的基座上。

```sh
deviceinfo_dtb="qcom/kona-v2.1"
```

## 坑 6 — pmbootstrap / WSL 工作流小刀

- **`pmbootstrap build` 说 "is up to date"**:当只改了 config/recipe 内容但
  `pkgver-pkgrel` 没变时 → 加 `--force`。
- **在 WSL bash 里跑 Windows 的 `.bat` 同步脚本**会无声失败
  (`cmd.exe: command not found`),你的改动永远到不了 pmbootstrap 的 pmaports。改用
  WSL 里纯 `cp` 同步,并在构建前**验证目标目录**。这里 pmbootstrap 的 aports 是
  `~/.local/var/pmbootstrap/cache_git/pmaports`。
- 改完源文件要重跑 `pmbootstrap checksum <pkg>`,否则 abuild 报
  `<file> is missing in checksums`。

## 坑 7 — 从 Windows 经 USB 连设备

临时启动不会显式刷写分区,但启动后的操作系统仍可能修改持久化的 `userdata`。
不要把任意镜像直接交给 fastboot。对于已经审查的 D110 恢复镜像,请使用仓库的
授权/执行守卫流程,详见
[`lmi-d110-session-approval.md`](lmi-d110-session-approval.md)。启动后 pmOS gadget
枚举为 **`18d1:d001 POSTMARKETOS`**,一个 **CDC-NCM** 网络 gadget——但 Windows 给它
绑了个 "ADB 接口",不出网卡。

**修法:** 用 **usbipd-win** 把 USB 设备透传进 WSL,Linux 原生支持 CDC-NCM:

```powershell
winget install usbipd
usbipd bind   --busid <BUSID>     # `usbipd list` 里那行 18d1:d001
usbipd attach --wsl --busid <BUSID>
```
```bash
# 在 WSL 里——gadget 显示为 enxXXXXXXXXXXXX(原 usb0)
IF=$(ip -br link | awk '/^enx/{print $1; exit}')
sudo ip link set "$IF" up
sudo ip addr add 172.16.42.2/24 dev "$IF"
ping 172.16.42.1            # 设备侧;~3 ms
ssh  lmi@172.16.42.1        # 仅在刷了 rootfs 后才有(见下)
```

**注意:** 只进 RAM 的 `fastboot boot` 没有刷 rootfs,initramfs 挂不到 root,也就不会
开网络 shell(`ping` 通但 `ssh`/`telnet` 拒绝)。这是正常的——它证明了内核 + USB,而
非完整系统。要拿到 shell 得把 rootfs 写进 `userdata`。

---

## 最终能用的 `linux-xiaomi-lmi/APKBUILD`

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
	export LLVM=1 LLVM_IAS=1          # 用和 build 同一套工具链配置(ld.lld)
	export REPLACE_GCCH=0             # 保留内核树自带的 compiler-gcc.h
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

`config-xiaomi-lmi.aarch64` 相对合并后下游 defconfig 的关键改动:
`# CONFIG_SECURITY_SELINUX is not set`、`CONFIG_DEFAULT_SECURITY_DAC=y`、
`# CONFIG_IKHEADERS is not set`。

## 复现

```bash
pmbootstrap checksum linux-xiaomi-lmi
pmbootstrap build    linux-xiaomi-lmi          # 冷启 ~16 分钟,Clang/LLVM
pmbootstrap checksum device-xiaomi-lmi
pmbootstrap build    device-xiaomi-lmi
pmbootstrap install  --no-fde
pmbootstrap export                              # -> /tmp/postmarketOS-export/boot.img
```

不要直接启动这个未经固定的导出镜像。候选镜像必须先经过审查并按哈希固定。
在仓库根目录中,已有的 D110 恢复镜像只使用以下守卫流程:

```bash
scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --authorize-session
scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --execute
```

授权范围、撤销方式和持久化 `userdata` 的剩余风险见
[`lmi-d110-session-approval.md`](lmi-d110-session-approval.md)。

## 现状

- ✅ 内核 + DTB + 镜像可构建;经 `fastboot boot` 在真机启动。
- ✅ USB 网络可用(CDC-NCM,经 usbipd→WSL 从主机可达)。
- ⏳ 尚未持久安装——需把 rootfs 刷进 `userdata`(破坏性;先备好 LineageOS/MIUI 回滚路径)。
- ⏳ 显示/面板、基带、Wi-Fi 等未验证(无头服务器优先)。

---

*作为移植练习构建与调试。内核源码为 GPL-2.0(LineageOS)。这里的 lmi pmaports recipe
以同样精神贡献——可自由改用于其他 SM8250 兄弟机。*
