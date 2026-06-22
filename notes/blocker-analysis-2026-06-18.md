# 卡点详细分析报告
签名：wsl_oc | 2026-06-18 02:27 +10:00 Australia/Sydney

## 概述

本项目目标：在 Redmi K30 Pro (lmi, SM8250) 上运行 postmarketOS Linux。
当前阶段：内核+rootfs 已构建并 RAM-boot 成功，USB 网络可达，但 SSH 连接失败，
无法进入完整用户态环境。

本文档系统梳理所有存留问题，按优先级分层，逐项分析根因、影响范围、
当前证据状态，以及推荐的解决方案。

---

## 🔴 第一层：阻塞性问题（无绕过路径）

### 1. SSH 连接被拒绝

**症状**
- `fastboot boot pmos-lmi-boot.img` 成功，USB gadget 枚举为 `18d1:d001`
- USB 网络（CDC-NCM）正常工作：`ping 172.16.42.1` ~3ms，0% 丢包
- `ssh lmi@172.16.42.1:22` → `Connection refused`
- `telnet 172.16.42.1:23` 间歇性可达但很快断开
- 端口扫描（22/23/2222/2323/8022/...）无其他服务响应

**根因分析**

有两种可能：

**(A)** rootfs 未正确挂载，系统停留在 initramfs shell 阶段
- 如果 pmOS 找不到 rootfs，initramfs 会 drop 到 busybox shell，不启动 sshd
- `telnet 23` 能间歇性连上印证了这一点 —— 这是 initramfs 调试通道
- `pmos-lmi-boot.img` 可能没有打包 `debug-shell` hook（参见下方包依赖问题）

**(B)** rootfs 已挂载但 sshd 启动失败
- 可能是 `/etc/ssh/sshd_config` 配置问题
- 可能是 `/var/empty` 或 host key 缺失
- 可能是 firewal 规则（安装日志显示 Firewall enabled）

**证据缺口**
- ❌ 未拿到 `/pmOS_init.log` —— 这是第一个需要获取的数据
- ❌ 未确认 `postmarketos-mkinitfs-hook-debug-shell` 是否已加入 initramfs
- ❌ `pmos-lmi-debug-boot.img` 已构建但尚未完成一次完整的 telnet 会话

**推荐下一步 (立即执行)**
1. 手机进 fastboot
2. `fastboot boot artifacts/images/pmos-lmi-debug-boot.img`
3. `usbipd attach --wsl --busid 2-5`
4. 配置 WSL 端 IP（`172.16.42.2/24` on `enx*`）
5. `telnet 172.16.42.1 23`
6. 如果连上，立刻：`cat /pmOS_init.log` → `mount` → `dmesg`
7. 如果连不上，考虑重建 debug image 确保正确包含 hook

---

### 2. Initramfs 调试通道不稳定

**症状**
- `telnet :23` 会话很快断开（几秒到几十秒）
- 来不及执行完整命令序列

**根因分析**
- 可能原因是 `pmbootstrap install` 时 `postmarketos-mkinitfs-hook-debug-shell`
  未正确安装或未集成进 initramfs
- 安装日志显示 `(rootfs_xiaomi-lmi) install postmarketos-mkinitfs` 和
  `(rootfs_xiaomi-lmi) mkinitfs`，但未明确安装 debug-shell hook 包

**解决方案**
- 确认 `postmarketos-mkinitfs-hook-debug-shell` 是否需要显式加入 `pmbootstrap install` 的额外包列表
- 或者直接在 boot 命令行加 `pmos.debug-shell` 参数（debug image 已做但效果不确定）
- 备选方案：在 initramfs 中预置一个 tcp 监听端口（如 2222），超时从 5 秒提到 60 秒

**证据缺口**
- 未检查 debug boot image 的 initramfs 内容（`unmkbootimg` + `cpio` 解压确认 hook 文件）
- 未检查 boot 命令行中 `pmos.debug-shell` 是否生效

---

## 🟠 第二层：核心功能缺失（SSH 解决后需立即推进）

### 3. DTB 未包含 lmi 设备节点

**症状**
- 显示屏始终黑屏（无 framebuffer）
- WiFi/蓝牙硬件不可用
- 可能还有其他外设（传感器、GPIO）未被 probe

**根因分析**

SM8250 的 DTB 架构是**基础 DTB + dtbo overlay** 两段式：

```
qcom/sm8250.dtsi  (SoC 级)
  └─ arch/arm64/boot/dts/vendor/qcom/
       ├── kona.dtb          # SM8250 参考板
       ├── kona-v2.dtb       # v2 修订
       ├── kona-v2.1.dtb     # v2.1 修订 （当前使用）
       └── lmi-sm8250-overlay.dtbo   # ⬅️ K30 Pro 专属节点
```

lmi 的 panel、MDSS/DSI、WLAN/CNSS pinmux、regulators 都在 **overlay** 中，
而 `fastboot boot` 时 bootloader **可能不会** 去读 dtbo 分区并应用 overlay。

目前 `deviceinfo_dtb="qcom/kona-v2.1"` 指向基础 DTB，缺少所有 lmi 专属节点。

**解决方案 (两条路径)**

**路径 A — 构建时合并 DTB（推荐）**
```
fdtoverlay -i kona-v2.1.dtb -o kona-v2.1-lmi.dtb lmi-sm8250-overlay.dtbo
```
- 将 overlay 内容直接嵌入基础 DTB
- 需修改 `linux-xiaomi-lmi/APKBUILD` 的 `package()` 阶段加入 merge 步骤
- 修改后 `deviceinfo_dtb` 指向 `qcom/kona-v2.1-lmi`
- ⚠️ Qualcomm overlay 使用 `__symbols__`/`__fixups__` 进行符号解析，
  需要验证 `fdtoverlay`（来自 dtc 包）能否正确解析这类构造。
  如果不行，需要改用内核的 fdt apply 机制或自行重写 dts。

**路径 B — 依赖 bootloader 应用 overlay**
- 可通过 `fastboot getvar dtbo-current` 检查当前 dtbo 分区状态
- 理论上 bootloader 在 `fastboot boot` 时会自动 apply 匹配的 dtbo
- 但实际行为完全取决于厂商实现，不可靠

**建议**
- 先检查 dtbo 分区内容是否有意义的 overlay（`fastboot flash dtbo XXX` 后有或无），
  如果 bootloader 确实自动 apply，那只需要确认 `deviceinfo_dtb` 选对了基础变体
- 如果 bootloader 不处理，走路径 A

**依赖关系**
- 阻塞 显示屏（4）、WiFi（5）

---

### 4. 显示屏无输出（framebuffer 不可用）

**症状**
- 手机屏幕常黑（无任何文字/logo）
- 未确认 framebuffer 设备是否存在

**根因链**

```
DTB 缺 panel 节点
  → DPU/MSM_DRM 驱动找不到 panel
  → CONFIG_DRM_MSM 无对应硬件驱动
  → 无 /dev/fb0 或 /dev/dri/card0
  → pmOS 启动过程无显示输出
```

**已知硬件参数**
- 面板：1080 × 2400 AMOLED，120Hz
- 驱动接口：4-lane DSI（Qualcomm MDSS/DPU）
- 面板类型：K30 Pro 专属（`dsi-panel-xxx` 在 `vendor/qcom/` 目录下）

**解决方案 (按尝试顺序)**

1. **最低成本验证**：合并 overlay 后，在 `deviceinfo` 中加上
   ```
   deviceinfo_screen_width="1080"
   deviceinfo_screen_height="2400"
   ```
   让 pmOS 知道显示屏尺寸（虽然 framebuffer 未就绪时无实际效果）

2. **检查内核配置**
   - `CONFIG_DRM_MSM=y` — MSM DRM/KMS 驱动
   - `CONFIG_DRM_MSM_DSI=y` — DSI 控制器驱动
   - `CONFIG_DRM_MSM_DPU=y` — Display Processing Unit
   - 检查 `config-xiaomi-lmi.aarch64` 中上述选项

3. **检查 dmesg 日志**（SSH 通后执行）
   ```
   dmesg | grep -iE 'msm_drm|mdss|dpu|dsi|panel|drm'
   ```

4. **考虑 simple-framebuffer 应急方案**
   - 在 DTS 中加入 `simple-framebuffer` 节点，跳过完整 DRM 栈
   - 标准 fbdev，不支持加速但至少能看到控制台
   - 需要知道 UEFI/bootloader 设置的 framebuffer 地址和格式

---

### 5. WiFi 驱动链不完整

**症状**
- 未测试（因 SSH 不可用无法 `ip link` 或 `iwconfig`）
- 预期不可用

**根因分析**

SM8250 的 WiFi 架构是 QCA6390/QCA6391（通过 PCIe/CNSS 连接）：
```
kernel: CNSS2/ICNSS 平台驱动
  └─ wlan.ko (qcacld-3.0) — Qualcomm 闭源无线驱动
       └─ 需要 firmware：board-2.bin, bdwlan*, wlanmdsp.mbn
            └─ firmware 由 remoteproc 子系统加载
                 └─ 需要用户态 daemon: rmtfs, tqftpserv, pd-mapper
```

当前缺失的环节：

| 环节 | 状态 | 操作 |
|---|---|---|
| 内核配置 `CNSS/ICNSS/CLD/WLAN` | 未检查 | `grep -iE 'CNSS\|ICNSS\|CLD\|WLAN' config-xiaomi-lmi.aarch64` |
| wlan.ko 模块 | 未确认 | 模块可能在 dtb 缺 pinmux 时未编译 |
| firmware | ❌ 缺失 | 需从手机 `/vendor/firmware_wlan/` 提取 |
| remoteproc daemons | ❌ 缺失 | `rmtfs`、`tqftpserv`、`pd-mapper` 未加入设备包 |
| `modules-initfs` | ❌ 为空 | 如果 wlan 是模块，initramfs 不会有它 |

**解决方案**

1. 检查内核配置确认驱动已编译
2. 从 LineageOS 运行中的手机上提取 firmware（`adb pull /vendor/firmware_wlan/ .`）
3. 在 `device-xiaomi-lmi/APKBUILD` 的 `depends` 中添加：
   - `rmtfs`
   - `tqftpserv`
   - `pd-mapper`
4. 在 `device-xiaomi-lmi/modules-initfs` 中列出需要预加载的内核模块
5. 将 firmware 打包进 `device-xiaomi-lmi`，或单独建一个 `firmware-xiaomi-lmi-wlan` 包

---

## 🟡 第三层：持久化与恢复保障

### 6. Plan B（flash boot 分区）缺少安全恢复路径

**当前状态**
- Plan A 已执行：rootfs 写入 `userdata`，`boot` 未动
- Plan B 将 pmOS 内核写入 `boot` 分区，实现不插电脑自启动
- 写 `boot` = 破坏 LineageOS 的启动能力

**安全风险**
- 需要一份已知好的 LineageOS boot.img 用于写回
- `artifacts/images/boot.img` 经检查是 Android boot image（header v2），
  内核版本 16.0.0，初步判断是 LineageOS 产出，但**来源未经确认**
  （是 pmbootstrap 的输出还是手动拷贝的？来自哪个 ROM？）
- 如果 boot.img 有问题，写回后手机可能卡启动

**恢复路径现状**

| 方式 | 状态 | 备注 |
|---|---|---|
| `fastboot flash boot <known-good-los-boot.img>` | ⚠️ 缺少可信任的 boot.img | `artifacts/images/boot.img` 来源未确认 |
| `fastboot boot skkk-recovery.img` + sideload ROM | ✅ 可用 | 两个 skkk recovery 在 `artifacts/images/` 中 |
| 线刷 MIUI 全量包（MiFlash） | ✅ 可用（需先下载） | 作为最终 fallback |

**建议**
- 标记 `artifacts/images/boot.img` 为 "未验证"，不要用于恢复
- 从已知源下载一份 lmi 的 LineageOS ROM（至少 boot.img）并存到 `artifacts/images/`，
  更新 hash manifest
- 在此之前只执行 Plan A（RAM-boot），不执行 Plan B

---

### 7. `deviceinfo_dtb` 变体选择未验证

**当前**
- `deviceinfo_dtb="qcom/kona-v2.1"` — USB 正常工作
- 但 `kona`、`kona-v2`、`kona-v2.1` 三个基础 DTB 都已安装到镜像中

**影响**
- 选了错误的基础 DTB 可能造成某些外设无法 probe
- 切换成本低：只需改 deviceinfo + 重建设备包，**不需要**重编内核

**验证方法**
- 在 dmesg 中搜索类似 `"No DTB found for ..."` 或 `"of: fdt: ... not matched"`
- 比对三个 DTB 的 compatible string 列表（`fdtdump | grep compatible`）
- 如果 bootloader 有 dtbo 自动 apply 机制，基础 DTB 必须和 overlay 匹配

---

## ⚪ 第四层：工程实践问题

### 8. WSL ↔ Windows 同步易出错

**问题**
- `scripts/08_sync_pmaports_to_wsl.bat` 是 .bat 文件
- 在 WSL bash 中直接运行会报 `cmd.exe: not found`
- 正确做法：在 PowerShell/CMD 中运行 .bat，或在 WSL 中用 `cp -a` 手动同步
- 这个坑在之前的构建迭代中浪费了几轮时间

**建议**
- 在 `notes/` 里记录正确的同步命令备用：
  ```bash
  SRC=/mnt/c/Users/microstar/Documents/lmi_linx/artifacts/wsl-pmaports
  DST=/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream
  cp -a "$SRC"/linux-xiaomi-lmi/.  "$DST"/linux-xiaomi-lmi/
  cp -a "$SRC"/device-xiaomi-lmi/. "$DST"/device-xiaomi-lmi/
  ```

### 9. 无自动化回归测试

**问题**
- 每次修改内核配置或 APKBUILD 后，没有自动验证：
  - 编译是否通过
  - 启动是否能 USB 网络
  - 关键外设是否 probe
- 全靠人工检查，容易遗漏

**建议**
- 编写一个简单的验证脚本（如 `scripts/10_verify_artifacts.sh`）：
  1. 检查内核版本字符串
  2. 确认 DTB 文件列表
  3. 检查 `deviceinfo` 和 APKBUILD 关键字段
  4. 检查 initramfs 中是否包含所需 hook

---

## 📊 总依赖关系图

```
当前阻塞: SSH 连不上
   │
   ├─ 可能是 rootfs 未挂载
   │     └─ 需读 /pmOS_init.log ← 依赖 debug image telnet
   │
   └─ 可能是 sshd 配置问题
         └─ 需登录后修 ← 依赖 rootfs 挂载成功
               
核心功能缺失:
   ┌─ 显示屏不亮 ← DTB overlay 未合并 (3)
   │                  └─ fdtoverlay  → 重编内核/设备包
   │
   └─ WiFi 不可用 ← DTB overlay 未合并 (3)
                        └─ + firmware + remoteproc daemons + modules-initfs
```

---

## 📋 执行优先级建议

### 阶段一：获取 shell（当前会话）
1. 手机进 fastboot
2. `fastboot boot artifacts/images/pmos-lmi-debug-boot.img`
3. 连 USB gadget 进 WSL
4. `telnet 172.16.42.1 23` → 读 `/pmOS_init.log` 和 `dmesg`
5. 根据日志判断 rootfs 挂载失败的原因，调整 initramfs/rootfs 配置
6. 重制 debug boot image（确认 hook 正确包含），重试直到稳定拿到 shell

### 阶段二：修复系统基础（拿到 shell 后）
7. 确认 sshd 正确配置，`ssh lmi@172.16.42.1` 登录
8. `dmesg` 全面检查，定位缺少的驱动
9. 合并 DTB overlay，重编 → reboot → 检查 panel/DSI 和 CNSS probe
10. 提取 WiFi firmware，添加 remoteproc daemon 包，重装 rootfs

### 阶段三：推进持久化
11. 获取可信任的 LineageOS boot.img 作为恢复材料
12. 执行 Plan B（flash boot 分区）
13. 验证不插电脑自启动

### 阶段四：完善功能
14. 显示屏调通（simple-framebuffer 或 DRM）
15. WiFi 联网
16. 传感器、蓝牙、音频等（按需）
