# raphael-ubports 资源审查（2026-07-20）

状态：`reference-only`
适用范围：检查 <https://github.com/raphael-ubports> 是否能为 Xiaomi lmi 的 postmarketOS P2 持久 terminal 提供可复用资源。

## 结论

该组织没有可直接导入当前 lmi P2 的实现。其公开内容主要是 2020 年的 Redmi K20 Pro（`raphael`，SM8150/msmnile）Halium/Ubuntu Touch 移植，而当前项目使用 Redmi K30 Pro / POCO F2 Pro（`lmi`，SM8250）下游 4.19 内核和原生 DRM + seatd + greetd + Weston 路径。

本次没有克隆仓库、下载镜像、复制代码、执行远程脚本或接触设备。当前 D114 source lock、Weston 会话和分区合同均保持不变。

## 逐项判断

| 资源 | 已固定的证据 | 判断 |
| --- | --- | --- |
| `device_xiaomi_raphael` | [`ea4f6d10470c`](https://github.com/raphael-ubports/device_xiaomi_raphael/tree/ea4f6d10470cbca8ad01f1abfe01b83f264f688d)；[`BoardConfig.mk`](https://github.com/raphael-ubports/device_xiaomi_raphael/blob/ea4f6d10470cbca8ad01f1abfe01b83f264f688d/BoardConfig.mk) 固定为 msmnile/SM8150、Android boot header v1、HWC2；[`device.mk`](https://github.com/raphael-ubports/device_xiaomi_raphael/blob/ea4f6d10470cbca8ad01f1abfe01b83f264f688d/device.mk) 使用 Halium。 | 只能用于架构对比；没有 Weston、terminal 或 Weston OSK 实现，不能替代 D114 P2。 |
| Ubuntu 适配文件 | [`android.conf`](https://github.com/raphael-ubports/device_xiaomi_raphael/blob/ea4f6d10470cbca8ad01f1abfe01b83f264f688d/ubuntu/android.conf) 是 Unity8/QtWebKit 缩放配置；[`70-android.rules`](https://github.com/raphael-ubports/device_xiaomi_raphael/blob/ea4f6d10470cbca8ad01f1abfe01b83f264f688d/ubuntu/70-android.rules) 包含 DRM/input 权限规则；[`setupusb`](https://github.com/raphael-ubports/device_xiaomi_raphael/blob/ea4f6d10470cbca8ad01f1abfe01b83f264f688d/ubuntu/setupusb) 操作 Android configfs/property USB 栈。 | 只保留“检查实际权限/缩放/USB 状态”的排障思想。不得复制硬编码 event 节点、Android USB 脚本或给 DRM 节点 `0666` 的宽权限规则。 |
| `kernel_xiaomi_raphael_stock` | Linux 4.14；[`09b2578125aa`](https://github.com/raphael-ubports/kernel_xiaomi_raphael_stock/commit/09b2578125aa71968f5ef6d2e5984d249cf30a4a) 是 Halium 配置；[`9fc38c40418b`](https://github.com/raphael-ubports/kernel_xiaomi_raphael_stock/commit/9fc38c40418bb9428905e9fc00c3e7b7e22d2277) 启用 `CONFIG_QCOM_PRESERVE_MEM`。 | 不可 cherry-pick 到 lmi 4.19/SM8250。`PRESERVE_MEM` 仅可作为以后核对 lmi 自身 pstore/ramoops 配置的提示，且不是当前 P2 前置。 |
| `kernel_xiaomi_raphael` | [`edcfa3e8625d`](https://github.com/raphael-ubports/kernel_xiaomi_raphael/tree/edcfa3e8625d93a5cf17b8b6a857c416566586b4) 是 Android 11、SM8150、4.14 CAFest 树。 | 与当前 P2 无直接关系，也不能作为 lmi 内核来源。 |
| `manifest` | [`xiaomi_raphael.xml`](https://github.com/raphael-ubports/manifest/blob/d7ec1a5c4207731a2bdf96d8741d69b4f552d5a0/xiaomi_raphael.xml) 把 kernel path 指向 `device_xiaomi_raphael`，却要求 `raphael-p-oss` revision。 | 仓库映射与 revision 不自洽，不能作为可复现 manifest。 |
| `installer` | [`ubports.sh`](https://github.com/raphael-ubports/installer/blob/2420318dcebdd8ddb344904e9ade024b5eb6f13c/ubports.sh) 会修改 `/data`、移动 `system.img`、执行 `e2fsck -fy` 并扩容文件系统。 | 明确拒绝执行或复用；设备、镜像和分区模型均不匹配，并且是有破坏性的旧 recovery/GSI 流程。 |
| `proprietary_vendor_xiaomi` | [`16c5262f77f9`](https://github.com/raphael-ubports/proprietary_vendor_xiaomi/tree/16c5262f77f9132b7a6fa348ef0f99e2e7b930fd) 含 raphael 专有 APK/JAR/SO/内核模块。 | 硬件、ABI、固件和许可均不匹配；不得导入或再分发。 |
| 预发布镜像 | [`2020-07-26` prerelease](https://github.com/raphael-ubports/device_xiaomi_raphael/releases/tag/2020-07-26) 提供旧 `halium-boot.img`，页面没有现代内容摘要证明。 | 不下载、不启动；不同设备且无法进入当前项目的供应链锁定。 |

## 对当前项目有用的信息

只有以下排障概念值得吸收，而且必须从 lmi 自身实时证据重新求值：

1. 若物理 P2 验收失败，核对实际 DRM/input 节点的 owner、group、mode，以及 seatd 是否向 UID/GID 10000 的 `lmi` 会话提供设备访问；不使用 raphael 的 `/dev/input/event3` 等硬编码。
2. 若亮度异常，枚举 lmi 实际 backlight sysfs 节点并记录驱动绑定；不复制 raphael 的 panel 节点名。
3. 若需要更早期崩溃诊断，核对 lmi 精确内核的 pstore/ramoops 和 preserve-memory 配置；当前项目已有 `ramoops_memreserve=4M` 证据，不能因为 raphael 的单个提交就改内核。
4. 手持设备缩放只能作为实机可用性指标。当前 D114 已有 Weston `scale=2` 和 stock `weston-keyboard` 证据，Unity8 的 `GRID_UNIT_PX`/QtWebKit DPR 不适用于 Weston。

与项目现有证据交叉检查后，DRM/seatd 权限链和 pstore/ramoops 已有覆盖，均不形成新的 P2 前置项。唯一尚未在当前 D114 会话中采集的诊断量是 backlight sysfs 状态；它只应在下一次实物验收仍黑屏时进行只读采样，不需要预先写亮度或改 udev 规则。

## 许可和来源边界

- 两个 kernel 仓库有 GPLv2 `COPYING`；若以后引用思想或补丁，仍需逐补丁确认作者、来源和适配性。
- device tree 的部分文件带 Apache-2.0 或 BSD 风格文件头，但没有足以覆盖所有 Ubuntu 适配文件的统一许可声明。
- `manifest`、`installer`、多数 `ubuntu/` 文件和 proprietary vendor 内容没有可确认的仓库级开放许可；本项目不复制这些内容。

因此本次审查的实际产物只有这份来源/取舍记录。它不会改变 `config/lmi-p2-d114/source-lock.json`，也不会扩大任何 RAM boot 或分区写入授权。
