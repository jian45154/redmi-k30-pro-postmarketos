# D114 P2 六行终端 —— 下一个"最完整版"交接文档 (2026-07-22)

状态：**规划完成，主机侧改动尚未落地。设备安全空闲（initramfs 调试壳）。**
本文档让"做下一个最完整版 D114 P2 镜像"这条线随时可接续。

---

## 1. 今天已完成（已提交推送到 `agent/lmi-d114-p2-r1-sixrow-release`）

- **治理基线 v4 落地**：`config/governance/{constants,policy}.json`、
  `scripts/bringup_loop.py`、`tests/governance/`（27 测试）、lint 重写、
  AGENTS.md 改写。见 `notes/governance-v4-landing-2026-07-22.md`。
- **公开 CI 首次全绿**：workflow 触发器改 master/edge；P1/P2-D114 的宿主绑定
  测试改为异质主机跳过（`LMI_P1_REQUIRE_PINNED_FIXTURE_TOOLS`、
  `LMI_REQUIRE_HOST_BOUND_FIXTURES` 恢复硬失败）。见
  `notes/public-ci-portability-2026-07-22.md`；run 29895820596 起连续绿。
- **PR #9 已合并进 master**（审计缺口 1、2 关闭；缺口 3 安装器 prerelease 早已
  在线且可复现性验证通过）。
- **r5 userdata 写入实机验证通过**：`UNKNOWN` 结局确认为第五个转录格式假阳性，
  D110 RAM boot 成功挂载新 D114 userdata 并进入完整 userspace。
- **六行终端 + 键盘首次真机点亮**：黑屏根因是卫生化把 `/etc/machine-id` 截空
  → dbus 拒启 → elogind 死 → `/run/user/10000` 无人建 → 会话首道门退出。
  写入 33 字节有效 machine-id 后终端与键盘可用。见
  `notes/lmi-d114-wsl-r5-unknown-outcome-2026-07-22.md`。

---

## 2. 下一版本核心发现（最省力配方）

用户要求下一版含三项：**Wi-Fi 触发链修复 + rootctl 提权 + pd-mapper
service-foundation**，外加必做的 **machine-id 卫生化修复**。

### 关键事实：最完整的 device 源是 r143，在 Windows 副本里

- 工作区 `artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD` = **r107**（很旧，
  缺 pd-mapper / rootctl / seatd）。source-lock 钉 r142，但 r108–r142 的源码
  **不在工作区、也不在 WSL pmbootstrap 缓存**（缓存每次被工作区 r107 覆盖）。
- **真正最新最完整的源在**
  `/mnt/c/Users/microstar/Documents/lmi_linx/artifacts/wsl-pmaports/device-xiaomi-lmi/`
  （Windows `C:\Users\microstar\Documents\lmi_linx`，平行项目副本），device 包
  = **r143**，已包含：
  - **lmi-rootctl + lmi-rootctl.sudoers**（装 `/usr/sbin/lmi-rootctl` +
    `/etc/sudoers.d/90-xiaomi-lmi-rootctl`；sudoers 仅
    `lmi ALL=(root) NOPASSWD: /usr/sbin/lmi-rootctl`）。rootctl 已适配
    xiaomi-lmi：reboot / poweroff / service / bluetooth-rfkill / adsp-boot /
    **wifi-start** / display-probe / display-takeover，每个危险动作要精确
    `--confirm <token>-xiaomi-lmi`。
  - **pd-mapper + pd-mapper-openrc**（depends + `runlevels/default/pd-mapper`）。
  - seatd/seatd-openrc、lmi-seatd、lmi-splash-release、lmi-power-panel、
    lmi-display-probe、lmi-display-takeover、lmi-weston 的 initd/wrapper 与部分
    runlevel 链接。

### r143 唯一仍缺的一环（今天 wlan0 不出现的确切根因）

r143 `package()` install 了 `lmi-wlan-on.initd`，但运行级段**没有**
`lmi-wlan-on` 和 `lmi-cnss-fs-ready` 的 `ln -s`。固件/驱动/CNSS 全就绪却没人
向 `/dev/wlan` 写 `ON`。两个 initd 已有正确 `depend`
（`need lmi-cnss-fs-ready`、`before wpa_supplicant networkmanager`），只差链接。

### 配方（r143 → r144）

1. 取 Windows 副本整个 r143 `device-xiaomi-lmi/` 为新基线。
2. `package()` 运行级段补两行：
   `ln -s /etc/init.d/lmi-cnss-fs-ready $pkgdir/etc/runlevels/default/lmi-cnss-fs-ready`
   与 `ln -s /etc/init.d/lmi-wlan-on $pkgdir/etc/runlevels/default/lmi-wlan-on`。
3. `pkgrel` r143→r144；`pmbootstrap checksum device-xiaomi-lmi`。
4. **machine-id 卫生化修复**：`inject_rootfs_candidate.sh` 的
   `sanitize_public_image` 把 `: >"$machine_id"`（截空）改为
   `rm -- "$machine_id"`（删除，让 `dbus-uuidgen --ensure` 首启重建），同步更新
   sanitation 契约与 full-delta expected 集里的 machine-id 项。
5. pmbootstrap 重建 rootfs（`scripts/21_build_pmos_v27_full_reproducible.sh` 同型
   流程，产新 userdata raw）。
6. 重跑注入器 + 重组 sparse。
7. 全链 hash 重钉（见 §3）。
8. flash + 验证（需 owner 逐次批准）。

---

## 3. 全链 hash 重钉清单（改基础 rootfs → userdata_raw_sha256 变 → 全失效）

- **source-lock.json**：`baseline.device_package`(r142→r144)、`dependencies[0]`、
  `userdata_raw_sha256`、`userdata_raw_size`、`userdata_sparse_sha256`、
  `frozen_installed_db_sha256`、`frozen_world_sha256`、`installed_kernel_package`、
  `boot_sha256`（若 boot 变）。同步 `source_lock.py` 的 `EXPECTED_BASELINE`、
  `EXPECTED_DEPENDENCIES`（硬校验依赖完全相等）。
- source-lock 自身 sha 钉在 `assemble_userdata_image.py` `SOURCE_LOCK_SHA256`
  与 `candidate-rebuild-lock.json`。
- **candidate-rebuild-lock.json**：base_ext4/candidate/userdata_raw/userdata_sparse
  sha 全重算；自身 sha 钉在 `inject_rootfs_candidate.sh` `REBUILD_LOCK_SHA256`
  与 `injection-policy-lock.json`。
- **inject_rootfs_candidate.sh** 内联：RAW/SPARSE/BASE/INPUT sha、IMAGE_SIZE、
  REPAIR_EPOCH、WORLD/INSTALLED_DB/SCRIPTS_DB/TRIGGERS_DB/SHADOW（随新 base 重算）、
  P2_APK_SHA256/SIZE/CHECKSUM、P2_BUILD_ATTESTATION_SHA256。
- **injection-policy-lock.json**：base/candidate/raw/sparse/triggers/world/p2-apk/
  sealed-injector sha；自身 sha 钉在 `assemble_userdata_image.py`
  `INJECTION_POLICY_LOCK_SHA256`。
- **assemble_userdata_image.py** Contract：`BASELINE_SHA256`(=userdata raw)、
  `BASELINE_SIZE`、`P2_SIZE`、`P2_UUID`、`SPARSE_TOOL_LOCK_SHA256`、`D110_BOOT_SHA256`。
- **apk-build-attestation.json**（terminal apk 重建后）。
- 六行终端 apk：`generate.py` 从 source-lock dependencies 渲染
  `device-xiaomi-lmi=1-r144`，改依赖即跟随，需重跑 generate。
- **lmi-weston-sixrow-clients apk 不变**。
- rootctl/sudoers/pd-mapper 属**基础 rootfs**（device 包），不经六行终端 delta
  注入，故注入器 full-delta expected 集不用为它们加项；但基础 rootfs 内容变了，
  WORLD/DB 快照必然变，且要处理 machine-id 项变化——务必核对 full-delta
  allowlist 与新基础 rootfs 一致。

---

## 4. 设备当前状态

- 手机在 **initramfs 调试壳**（telnet 172.16.42.1:23）：落盘 boot 仍是旧内核，其
  initramfs 挂不了当前 userdata 子分区而掉壳。userdata 数据持久。
- `pmos_continue_boot` 可回到当前（machine-id 已修的）六行终端会话。
- SSH 诊断公钥 `private/lmi-p1/recovery/d110-d114/host-ssh/id_ed25519` 已注入
  uid 10000 的 `authorized_keys`（仅本会话临时用途，非发布内容，下次重建即消失）。
- usbipd：RNDIS 网卡 busid 2-5 已 bind(Shared)；fastboot 转接用
  `usbipd.exe attach --wsl --busid 2-5`；网络诊断走镜像网络 172.16.42.2 直连。

---

## 5. 引擎 / 治理状态（需回退的 flash-boot 尝试残留）

`bringup_loop.py` 有一条 **ready 未消费**的 persistent 记录
`notes/bringup-active.json`（`d110-boot-persist-1`），为"flash 旧 D110 boot
持久化"而建，配对的是旧不完整镜像，**方向已变应作废**：

- `rm notes/bringup-active.json`（ready 未 claim，无台账副作用）；
- `config/governance/policy.json` 的 `authorized_profiles` 移除
  `profiles/d110-terminal-boot.json` 条目（revision 回退）；
- 未提交工作区改动 `config/governance/policy.json`、
  `profiles/d110-terminal-boot.json`、`notes/bringup-active.json` 三者一并回退。

新版本做好后按新 profile 重新走 per-profile 授权。

---

## 6. 未来 / 待优化项

- **六行键盘优化**（用户提出"r143 的键盘也许还可以优化"）：键盘 =
  `lmi-weston-sixrow-clients` 的 `weston-keyboard-sixrow`（源
  `files/lmi-weston-sixrow/`；布局契约与静态校验 `scripts/lmi_weston_sixrow/`）。
  此包不随 device 包重建，可独立迭代。具体优化点待明确（布局/手感/特殊键映射）。
- **持久化启动**：现只能靠 D110 RAM boot 进终端；开机即用需 `flash boot` 配对
  boot 镜像（Tier 2，需 preflight + 回滚 + owner 逐次批准）。
- **部署器转录校验器修复**：`deploy_userdata_wsl.py` 的 `_transport_completed`
  学习 Debian fastboot 转录格式（第五个假阳性），并持久化 execute 转录原文
  （mode 0600），使 UNKNOWN 结局可从证据诊断而非推断。
- **卫生化契约与测试**：machine-id 改删除后更新契约文档与 `tests/lmi_p2_d114/`。

---

## 7. 一句话接续

以 `/mnt/c/Users/microstar/Documents/lmi_linx/.../device-xiaomi-lmi/` 的 **r143**
为基线，补 `lmi-wlan-on`+`lmi-cnss-fs-ready` 两条 default 运行级链接、bump r144、
改注入器 machine-id 为删除、pmbootstrap 重建 rootfs、重注入组装、按 §3 重钉全链
hash，再 flash + 验证。这一版即含 **Wi-Fi 自动起 + rootctl 提权 + pd-mapper +
不再黑屏**。
