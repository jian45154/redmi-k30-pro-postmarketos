# Xiaomi lmi 可用终端与音频交付设计

**状态：** 已批准；用户已授权执行代理完成书面规格复核并继续实施  
**日期：** 2026-07-19  
**目标设备：** Redmi K30 Pro / POCO F2 Pro（`xiaomi-lmi`，SM8250）  
**目标仓库：** `jian45154/redmi-k30-pro-postmarketos`

## 1. 目标与完成定义

本项目交付一个在真实 `lmi` 上可持续使用的 postmarketOS 系统，并同时满足：

1. **P1：SSH 可用。** 系统能完成 rootfs 挂载和 `switch_root`，通过 USB RNDIS 稳定提供 SSH，登录安全、重连稳定、数据可持久化。
2. **P2：屏幕终端可用。** 内置屏幕和触控可用，GUI 中有最大化终端，以及不裁切、适合 POSIX shell 操作的完整屏幕键盘。
3. **P3：扬声器和麦克风可用。** 真实 ALSA 声卡、播放 PCM 和录音 PCM 均枚举；受控低音量播放可以实际听见，麦克风录音包含真实有效信号并可回放。
4. **阶段镜像不会再失踪。** P1、P2、P3 每个已验收阶段都在 GitHub 保存完整 `boot.img` 和完整 userdata/rootfs 镜像，并完成从 GitHub 重新下载后的哈希复验。

最终完成证据必须来自**同一个 P3 最终镜像**：它需要重新通过 P1、P2 和 P3 的全部回归测试。历史记录、静态配置、单独组件探测或不同镜像之间拼接的证据都不能替代最终实机验证。

本设计不把蜂窝网络、通话、摄像头、GPS、NFC、蓝牙、休眠或日常 Android 双启动纳入完成条件。它们不得破坏 P1—P3，但不是本轮交付范围。

## 2. 已知事实与证据等级

### 2.1 当前现场

- 项目 `master` 当前为 `9759c2730c20ce29efd81e2f238253ecef7f1d47`，开始设计时工作树干净。
- GitHub 远端为 `https://github.com/jian45154/redmi-k30-pro-postmarketos.git`。
- pmbootstrap 3.11.1 已初始化为 `edge / xiaomi-lmi / aarch64 / shelli / OpenRC`。
- pmaports 的 dirty 状态只来自未跟踪的 `device/downstream/device-xiaomi-lmi/` 和 `device/downstream/linux-xiaomi-lmi/`；它们是本项目包的工作副本，不是未知修改。
- fastboot 只读检查确认 `product=lmi`、`unlocked=yes`。2026-07-19 最近一次电池读数为 `3799 mV`。

### 2.2 下游 D80 基线

GitHub Release `d80-minimal-gui-osk-20260712` 的归档和内部 `SHA256SUMS` 已全部校验。它保存了以下可重放 APK：

- `device-xiaomi-lmi 1-r139`
- `linux-xiaomi-lmi 4.19.325-r9`
- Weston `14.0.2-r10` 的完整 split APK 集

D79 实机证据证明了 Space、Backspace、Enter 的输入语义；D82 实机证据证明了 10 列键盘完整可见，但没有在同一次 D82 会话中重复完整输入回归。D80 原始 `boot.img` 和 userdata 镜像已删除，所以历史 SHA-256 只能标识失踪产物，不能被当前材料重新生成或冒充。

Release 中的 APK 足以恢复 P1/P2 的**二进制功能基线**，但不足以恢复 D80 的完整源码构建：设备包源码停在 `1-r107`，kernel 配方停在 r8，三个 Weston 补丁只保存了哈希而没有内容。因此所有新镜像、源码包和补丁使用新版本号、新 UUID 和新哈希。

### 2.3 音频纠错结论

D80 r9 的合并 DTB 实际包含启用的机器声卡节点：

```text
/soc/qcom,msm-audio-apr/qcom,q6core-audio/sound
compatible = "qcom,kona-asoc-snd"
qcom,model = "kona-mtp-snd-card"
```

单体内核 Image 也包含 APR/Q6ASM/Q6AFE、Kona machine driver、Bolero、WCD938x 和 TFA98xx/TFA9874。旧记录只查 `/soc/sound`，并以主线 Kconfig 名称判断 vendor techpack，因此“声卡节点或驱动缺失”的结论不成立。

现有日志最接近的故障边界是：APR 父设备、ADSP/LPASS 基础设施和 TFA9874 probe 存在，但没有看到 `apr_adsp_up: Q6 is Up`，也没有 q6core、machine device 或 ALSA card。首要诊断对象是 `avs/audio → PDR/service locator → APR → q6core → kona-asoc` 的服务上电和通知链。

### 2.4 主线证据边界

外部 lmi 主线包包含 WCD9380、SoundWire、QDSP6、TFA9874、UCM 和固件清单，但其项目记录同时说明设备当时未解锁，硬件功能声明不是 lmi 实机证明。现有本地 M-r7 只证明 boot 写入被接受，180 秒内没有可观察的 initramfs、USB、SSH 或 rootfs。主线目前不是可以立即替换下游的 P3 路线。

## 3. 来源优先与不重复造轮子

实现按以下优先级复用：

1. postmarketOS 官方 pmaports，锁定已审计提交 `6fb3a1e5eb21c809891645a2ba5ae11fa788e032`；复用官方 `linux-postmarketos-qcom-sm8250`、SM8250 设备包、OpenRC 服务和 `postmarketos-ui-weston` 的结构。
2. Weston 14.0.2 官方 tag `015b3b4d4c05da44a22349ea6e651d1a8f678c59` 与 Alpine aports 的 Weston APKBUILD/split-package 方式。
3. LineageOS `android_kernel_xiaomi_sm8250` 提交 `a5b3099017ae581aae8bf597b2f9c8c765026af1`，作为下游设备树、Kona machine driver、APR、PDR 和 notifier 行为的真值源。
4. `macosmojave2-alt/postmarket-xiaomi-lmi@ef326f182d43eebe432f2adb8de6b3be9780309f`、`yuweiyuan8/linux@999ef8bfd90ca4c214f18ac5d0138bf380386c38b` 和 `yuweiyuan8/firmware-xiaomi-lmi@dde156380b2ac372619ed332dbe60640b838b7fe` 只作为候选 DTS、UCM 和文件清单，不作为实机可用性证明。

每个外部输入都记录 URL、提交或 tag、内容哈希、许可证/来源和用途。没有现成实现时才增加 lmi 专用代码，并在提交信息和来源清单中解释不可复用的原因。

## 4. 总体架构与数据流

交付流水线分为六个边界明确的单元：

```text
锁定来源与历史 APK
        ↓
可审计 pmaports overlay
        ↓
确定性构建与静态镜像检查
        ↓
GitHub Draft Release 保存候选完整镜像
        ↓
自动安全门 → 临时启动/限定分区写入 → 实机验收
        ↓
补充脱敏证据 → 发布 Release → 全新下载目录复验
```

### 4.1 来源锁定单元

维护机器可读的来源锁文件，区分：

- 可从官方源重新获取的源码与 APK；
- D80 Release 中经过 SHA-256 校验的冻结二进制输入；
- 仅由本机/stock 分区提供、不能公开再分发的专有输入；
- 新生成的 APK、boot、rootfs 和证据文件。

冻结 D80 APK 可以用来快速恢复功能，但不得被描述成源码可复现构建。源码恢复产物从 `device-xiaomi-lmi r140+`、`linux-xiaomi-lmi r10+`、Weston `r11+` 开始编号。

### 4.2 pmaports 源码单元

`artifacts/wsl-pmaports/` 继续作为项目内下游包的源码真值源。恢复 r139 中可从 APK 精确提取的 OpenRC/wrapper/config 文件，并明确标注二进制来源边界。Weston 以官方/Alpine 源码为基线重新形成最小补丁；不反编译二进制来伪造旧补丁。

lmi 专用层只保留通用 Weston 包无法提供的行为：

- `/dev/dri/card0` 与 `DSI-1` 的设备约束；
- 已验证的 splash framebuffer 清理与 DRM 接管；
- portrait 尺寸和 scale；
- 启动最大化终端和屏幕键盘；
- 设备级故障日志与 OpenRC 依赖。

通用依赖、tinydm/seatd、Weston split packages 和标准配置查找方式复用 postmarketOS/Alpine 实现。

### 4.3 构建与验证单元

构建入口只消费锁定来源、pmaports overlay 和本地注入的非公开输入。它生成：

- `boot.img`
- 未稀疏的完整 userdata/rootfs 镜像；其嵌套 GPT 逻辑扇区大小为 4096 字节
- APK/world 锁定清单
- boot header、kernel、DTB、initramfs、UUID、分区表和文件系统 manifest
- 原始及压缩产物的 SHA-256 与字节数

静态验证必须在任何手机操作前失败关闭。它检查产品名、boot header v2 参数、镜像容量、GPT/4096 字节扇区解释、boot/root UUID 匹配、RNDIS 标识、OpenRC runlevel、关键二进制/脚本哈希、SSH 安全配置、专有文件清单和秘密扫描。

### 4.4 硬件执行单元

所有 fastboot/SSH/显示/音频操作由带超时、日志脱敏和前置条件的单一入口执行，避免把手工命令散落在记录中。每次会话重新确认：

- 唯一设备且 `product=lmi`；
- bootloader 解锁；
- fastboot 模式与操作类型匹配；
- 电池电压至少 `3800 mV`；
- 操作文件的绝对路径、SHA-256、大小和 manifest 身份匹配；
- 目标分区只能是设计允许的 `boot` 或 `userdata`；
- 已发布或已上传 Draft 的候选镜像和已验证回滚路径仍可读取。

用户已授予持续操作授权。通过自动安全门的范围内操作由执行代理自行批准，不要求用户在线等待。任何身份不匹配、哈希变化、多设备、低电量、回滚失效或目标超出边界都会中止，而不是猜测。

### 4.5 证据单元

每个运行时采集文件都包含镜像哈希、包版本、kernel release、开机标识和 UTC 时间。证据分为：

- `static`：只证明文件和配置存在；
- `runtime-readonly`：证明真实系统当前状态；
- `runtime-active`：证明受控状态变化成功；
- `operator-observed`：证明屏幕可见、声音可听等自动化无法替代的物理现象。

只有覆盖相应验收项的证据才能提升阶段状态。缺日志、检查错路径、不同镜像拼接或“没有发现错误”都不能算通过。

### 4.6 GitHub 归档单元

镜像不进入 Git blob 历史；它们作为 GitHub Release assets 保存。候选构建完成并通过静态验证后先上传 Draft，实机验收通过后补充证据并发布。发布后必须下载到新的临时目录并重新验证所有哈希和 manifest 关系。

## 5. P1：稳定安全的 SSH

### 5.1 启动与存储

P1 首先用已校验的 D80 r139/r9 APK 建立 binary-replay 恢复基线，同时恢复项目源码。rootfs 镜像使用 4096 字节扇区；initramfs 显式创建设备节点，按 4096 字节解释嵌套 GPT，并等待 `/dev/loop0p2` 出现后挂载根文件系统。

boot cmdline、initramfs deviceinfo、rootfs UUID 和实际文件系统必须形成闭环。任何 UUID 或分区表不一致都在静态门停止。

### 5.2 USB 网络

设备端提供已在 lmi 实机验证的 RNDIS gadget：

- USB VID:PID `0525:a4a2`
- 设备地址 `172.16.42.1`
- 主机地址 `172.16.42.2`

网络配置必须允许接口重建和 SSH 多次重连，不能依赖一次性的手工命令。

### 5.3 SSH 安全模型

- `root` 不允许远程登录。
- 禁用 SSH 密码认证，仅允许用户 `lmi` 的公钥认证。
- 构建/Release 镜像不包含 SSH host 私钥；首次启动生成设备唯一 host key，之后在持久 rootfs 中保持。
- 发布资产不包含明文密码、密码哈希、私钥、设备序列号、解锁 token 或主机凭据。
- Release manifest 记录预期用户、公钥指纹和首次 host-key 生成策略，不记录私钥。
- 必须执行提权的显示/服务操作只通过参数白名单和目标白名单均固定的 `lmi-rootctl` 完成；不给 `lmi` 用户通用免密 root shell。

### 5.4 P1 验收

同一镜像必须证明：

1. initramfs 完成 `/dev/loop0p2` 挂载和 `switch_root`。
2. Windows/WSL 主机看到 `0525:a4a2`，TCP 22 可达。
3. 正确公钥可以登录，错误密钥和密码登录失败，root 登录失败。
4. 连续五次 SSH 连接成功；断开 USB 后重新连接可以恢复。
5. 在用户目录写入随机标识，重启后内容仍在。
6. 重启后 host-key 指纹不变，`sshd` 和网络服务处于 started 状态。
7. P1 完整镜像 GitHub Release 重新下载复验通过。

## 6. P2：屏幕、GUI、终端与完整屏幕键盘

### 6.1 两步恢复

P2 分为两个有明确身份的子里程碑：

- **P2-replay：** 使用 D80 中已校验的 Weston r10 split APK 和 r139 wrapper，恢复已知可工作的 GUI/键盘基线，尽快获得实机反馈。
- **P2-source：** 以 Weston 14.0.2/Alpine APKBUILD 为源重新制作 r11+ 补丁，并在相同镜像上重复全部验收。只有 P2-source 可以成为最终 P2 和 P3 的构建基础。

P2-replay 是可回滚、可下载的阶段成果，但不能被标记为完整源码复现。

### 6.2 GUI 组成

- OpenRC 管理 seatd 和 Weston 生命周期。
- Weston 使用 DRM backend；在 vendor 4.19 需要时使用已经验证的 pixman renderer。
- lmi wrapper 在启动 compositor 前验证 `/dev/dri/card0`、`DSI-1` 和权限，并只在拓扑匹配时执行 splash handoff。
- Weston 启动后打开最大化 `weston-terminal`；终端崩溃时服务记录原因并受限重启，避免无限快速循环。
- portrait 输出使用 `preferred` mode 和经实机验证的 scale；完整键盘必须位于可触区域内且无横向裁切。

### 6.3 “完整屏幕键盘”的精确定义

本项目的完整键盘是**完整 POSIX shell/终端键盘**，不是通用多语言手机输入法。它至少包含：

- 小写字母、Shift/大写、Space、Backspace、Enter；
- 数字 `0`—`9`；
- shell 常用符号，包括下列完整集合：

  ```text
  - _ / \ | < > = + * ? . , : ; ' " ( ) [ ] { } $ # @ ! % & ~ ^ `
  ```

- 终端控制键：Esc、Tab、Ctrl、Alt、左右上下方向、Home、End、PageUp、PageDown、Delete；
- 可见的字母/数字符号/终端控制层切换键；
- modifier 锁定状态和按键反馈。

不接受依靠 SSH 输入来替代屏幕键盘验收。

### 6.4 P2 验收

同一 P2-source 构建产物在一次连续验收周期中需要证明：

1. 屏幕从启动图交接到 Weston，画面完整、方向正确、无明显持续闪烁。
2. 触控坐标与显示方向一致；所有边缘列均可点击。
3. 终端和键盘完整可见，按键尺寸足以操作，终端内容不会被永久遮挡。
4. 仅用屏幕键盘输入并执行包含大小写、空格、数字、路径、下划线、引号和管道的命令；输出与预期一致。
5. 实测 Backspace 修改、Tab 补全、Ctrl-C、中英文无关的 shell 符号、方向键历史、Home/End 和滚屏键。
6. 创建并编辑文本文件，退出后通过终端重新读取内容一致。
7. 至少一次 blank/unblank 后 GUI、触控、终端和键盘仍可用；亮度可以在安全范围内调整并恢复。
8. 重启后 P1 和上述 P2 服务自动恢复。
9. P2 完整镜像 GitHub Release 重新下载复验通过。

## 7. P3：扬声器与麦克风

### 7.1 下游优先诊断顺序

P3 不先改主线 Kconfig，也不先写新驱动。对 P2-source 最终镜像执行一次完整只读采集：

1. 检查正确 OF 路径及 `compatible`/`qcom,model`。
2. 检查 APR 父设备是否绑定、q6core/Bolero/Kona/WCD/TFA platform devices 是否出现、deferred probe 内容。
3. 检查 `avs/audio`、PDR、service locator、`apr_adsp_up` 和 `Q6 is Up` 日志。
4. 检查 `lmi-firmware-mount`、`lmi-qrtr-ns`、`pd-mapper`、`rmtfs`、`tqftpserv` 的真实状态和启动顺序。
5. 检查 stock-derived ADSP 文件、symlink、签名/分段可见性以及 QRTR 节点；不把缺少 `/dev/qrtr` 单独判作失败。
6. 最后检查 `/proc/asound/cards`、`aplay -l` 和 `arecord -l`。

结果按最近故障边界分类：

- OF 节点不存在：runtime DTB 选择或合并问题；
- OF 存在、APR 未绑定：APR probe 问题；
- APR 已绑定、没有 `Q6 is Up`：固件/PDR/service-locator/notifier 链；
- Q6 已 up、没有 q6core：APR child population；
- machine device 出现、没有 card：组件 deferred probe；
- card 已出现：停止修改内核，转入 UCM、container、校准和安全音量测试。

每个新候选只验证一个明确假设，并保存失败和成功证据。最多完成三个彼此独立、证据闭合的下游修正周期后重新评估路线。

### 7.2 UCM 与专有输入

真实 ALSA card 出现后，以实际 control/PCM 名称编写或修正 lmi UCM。外部 lmi 和官方 Xiaomi pipa UCM 只用于结构参考，不能直接复制不匹配的 control 名称。

TFA container、ACDB、DSP 库或 firmware 如果需要，优先从手机现有 stock 分区只读暴露，不复制进公开镜像。所有实际使用的专有输入记录来源分区/文件、目标、SHA-256 和 ABI 用途。

### 7.3 安全主动测试

扬声器测试必须：

- 初始 mute/最低可用数字音量；
- 使用短时、低幅度、单次播放样本；
- 逐级增加但不超过预先定义的安全上限；
- 每次测试有超时和停止命令；
- 禁止把未知 mixer control 设置为最大值；
- 如果出现爆音、持续直流声、过热或服务崩溃，立即停止并恢复 mute。

麦克风测试使用固定时长和格式录音，自动检查文件长度、非零样本、峰值和 RMS，随后用已经通过安全门的扬声器低音量回放，由现场物理观察确认录到真实声音而不是纯噪声或静音。

如果硬件允许同时播放和录音，优先执行自主声学闭环：扬声器播放带唯一频率序列的低幅度样本，内置麦克风同步录音，验证时域相关性、目标频谱峰和相对噪声底。该测试同时给出扬声器发声与麦克风拾音的客观物理证据；不允许仅把数字 PCM 内部 loopback 当成声学闭环。若声卡不支持全双工，则使用独立主机麦克风/摄像设备记录，最后才需要用户短暂现场观察。

### 7.4 P3 验收

同一最终镜像必须证明：

1. ADSP/PDR/APR/q6core/machine-card 链在冷启动后稳定完成。
2. 真实 ALSA card、至少一个播放 PCM 和一个录音 PCM 枚举。
3. UCM `HiFi` 可以 enable/disable，并在 disable 后恢复安全状态。
4. 内置扬声器的受控样本实际可听见，无明显失真、爆音或持续噪声。
5. 内置麦克风录音具有有效动态范围；回放可辨识测试语音。
6. 连续两次冷启动后重复短播放和录音测试通过。
7. 最终执行 P1、P2 全量回归，不因音频服务破坏 SSH、显示、触控、终端或键盘。
8. P3 完整镜像 GitHub Release 重新下载复验通过。

## 8. 主线后备路线与切换门槛

满足以下任一条件才停止继续投入下游音频：

- 正确 OF、APR 绑定、stock-derived ADSP 输入和所需服务都已证实，但三个隔离修正后 `avs/audio` 仍不能 SERVICE_UP；
- Q6 已 up，但 machine probe 连续暴露多个必须依赖 Android 专有 daemon/HAL/不稳定 ABI 的阻塞；
- 必要输入无法合法、安全、可复现地使用；
- 修复只能依靠不可解释、不可重复的设备时序 workaround。

切换后不直接使用未经实机证明的个人 6.19 镜像。主线路线以 postmarketOS 官方 `linux-postmarketos-qcom-sm8250` 7.1.x 为维护基线，将 lmi DTS/补丁逐项迁移并记录与个人 fork 的差异。进入音频测试前必须：

1. 连续两次冷启动到可观察 initramfs、rootfs、`switch_root` 和稳定 SSH；
2. 重新达到 P2 全部显示/终端/键盘条件；
3. 启用并静态确认 TFA9872/TFA9874、WCD938x、SoundWire、QDSP6/APR 所需驱动；
4. 修正 firmware 子包落盘和 UCM 不对称问题；
5. 通过与下游相同的 P3 验收。

主线候选不能以“源码更完整”替代启动和音频实机证据。

## 9. GitHub Release 防死档协议

### 9.1 阶段命名

- `lmi-p1-ssh-YYYYMMDD-N`
- `lmi-p2-terminal-YYYYMMDD-N`
- `lmi-p3-audio-YYYYMMDD-N`

候选使用 Draft Release 和递增的 `N`。只有完全通过相应实机门的候选才发布为该阶段的稳定 Release。

### 9.2 每个阶段的必需资产

- 实际 `boot.img`；
- 完整 userdata/rootfs 原始镜像的 zstd 压缩文件；
- 必要时小于 2 GiB 的可重组分卷；
- `SHA256SUMS`，同时覆盖上传文件；
- `manifest.json`，记录原始/压缩大小与哈希、UUID、sector size、boot 参数、package/world、源码提交和验证状态；
- 阶段 APK 与来源锁文件，或其独立不可变 Release 引用及哈希；
- 构建命令、静态验证结果、脱敏运行时证据、明确写入映射和回滚说明；
- 许可证/专有输入清单以及秘密扫描结果。

上传完成后，验证器必须从 GitHub API 读取资产列表，下载到全新临时目录，重组/解压，并校验上传资产 SHA、原始镜像 SHA、manifest 引用和预期文件大小。缺少任一完整镜像或复验失败时 Release 保持 Draft，阶段状态不得标记为完成。

### 9.3 公开与私有边界

不包含不可再分发专有内容的镜像发布到当前公开仓库。P3 如果必须把许可证不明的 Xiaomi/Qualcomm/Cirrus/Focaltech blob 嵌入镜像，则：

- 完整镜像发布到用户账号下的私有 GitHub artifact 仓库；
- 公开仓库只记录源代码、脱敏 manifest、哈希和私有资产的逻辑身份；
- 不用加密公开附件规避许可证；
- 私有仓库创建和 Release 发布属于用户已经授权的目标范围。

## 10. 安全、授权与恢复

用户在 2026-07-19 明确授权执行代理自行判断并批准目标范围内操作，不要求用户持续在线。该授权覆盖：

- 构建依赖安装、网络下载和 pmbootstrap 工作目录写入；
- 项目文件修改、提交、推送和 GitHub Release/私有 artifact 仓库操作；
- 只读 fastboot/SSH 采集；
- 通过本设计自动安全门后的 RAM boot、重启；
- 通过本设计自动安全门后，对**精确验证的 `boot` 和 `userdata`**执行必要写入。

该授权不覆盖以下操作；设计内也不需要它们：

- `erase`、`format`、bootloader lock/unlock/relock；
- 写入 `modem`、EFS、`persist`、`super`、`vbmeta`、`dtbo`、`vendor_boot`、`init_boot`、校准或引导加载器相关分区；
- 在产品身份、分区身份、哈希、容量、模式或回滚路径不明确时继续；
- 修改其他设备或扩大到本目标以外的外部系统。

可恢复性规则：

1. 优先 RAM boot，成功后才考虑持久写入。
2. userdata 写入按破坏性操作处理：候选镜像必须先存在于 GitHub Draft，且回滚镜像/Android 恢复路径经过可读性检查。
3. fastboot 使用明确绝对路径，不使用 glob、未解析变量或宽泛目录。
4. 每次动作保存命令、时间、输入 SHA 和结果；失败后先收集只读证据，不立即重复写入。
5. 手机电量低于 `3800 mV` 时不进行启动、重启或分区写入。

## 11. 测试策略

### 11.1 主机侧

- shell 脚本使用临时目录和伪 fastboot/gh 输出进行成功、低电量、错误产品、多设备、哈希变化、缺资产和超时测试。
- pmaports 执行 checksum、APKBUILD 解析/构建检查、包内容和 runlevel 验证。
- Weston 键盘补丁构建后检查预期层、键码和二进制身份；布局使用 Weston 测试客户端和实机触控共同验收。
- boot/rootfs 验证器检查 header、DTB、initramfs、GPT、4096 字节扇区、UUID、文件系统、SSH 策略、world/APK 和秘密模式。
- Release 验证器必须在没有本地构建目录帮助的情况下，仅依靠下载资产恢复并验证镜像。

### 11.2 实机侧

- 每个候选有唯一 boot ID 和镜像 identity 文件。
- P1、P2、P3 的主动测试各自有固定命令、超时、恢复动作和证据格式。
- 屏幕可见性优先使用独立摄像设备取证，音频优先使用非数字 loopback 的声学闭环取证。没有独立传感器时，用户不在线期间先完成全部自动测试并保留待观察状态，不能用 DRM 状态、内部 PCM loopback 或日志伪造物理观察 token。
- P3 最终镜像执行完整回归矩阵，而不是只检查新增音频功能。

## 12. 错误处理与状态晋级

- 一个候选只承载一个主要假设；失败时保留证据，不把多个未知修改叠加到下一镜像。
- 构建、静态验证、上传、下载复验、硬件 preflight、运行时验收是独立门；任一失败都会阻止阶段晋级。
- 超时后先确认设备当前处于 fastboot、系统、USB 断开还是未知状态，再选择只读恢复路径。
- 旧文档与当前证据冲突时，以锁定镜像的真实运行时证据为准，并修正文档，不能同时保留互相矛盾的“当前状态”。
- P1/P2/P3 状态只允许 `candidate`、`runtime-partial`、`accepted`；`accepted` 必须有对应 GitHub 重下载复验记录。

## 13. 完成交付清单

项目只有在以下全部成立时结束：

- P3 最终镜像在这台 `lmi` 上同时通过 P1、P2、P3 完整回归；
- `boot.img` 和完整 userdata/rootfs 镜像可从 GitHub 获取并在新目录恢复；
- GitHub 下载后的 SHA-256、UUID、包版本和源码提交与实机 identity 一致；
- 项目仓库包含所有自有源码、补丁、构建/验证/发布脚本和脱敏证据，没有只剩哈希的自有关键补丁；
- 公开镜像不泄露秘密或不允许公开再分发的固件；需要专有内容的最终镜像在私有 GitHub artifact 仓库完整保存；
- 回滚说明和已知限制清楚、可执行；
- README、track 文档和 Release 状态与最终实机证据一致。

## 14. 主要参考来源

- postmarketOS pmaports：<https://gitlab.postmarketos.org/postmarketOS/pmaports>
- postmarketOS SM8250 kernel：<https://gitlab.postmarketos.org/soc/qualcomm-sm8250/linux>
- postmarketOS UI package guidance：<https://docs.postmarketos.org/pmaports/main/ui-packages.html>
- Weston releases：<https://wayland.freedesktop.org/releases.html>
- Alpine Weston package：<https://pkgs.alpinelinux.org/package/edge/community/aarch64/weston>
- LineageOS lmi kernel baseline：<https://github.com/LineageOS/android_kernel_xiaomi_sm8250/tree/a5b3099017ae581aae8bf597b2f9c8c765026af1>
- 外部 lmi pmaports 候选：<https://github.com/macosmojave2-alt/postmarket-xiaomi-lmi/tree/ef326f182d43eebe432f2adb8de6b3be9780309f>
- 外部 lmi firmware 候选：<https://github.com/yuweiyuan8/firmware-xiaomi-lmi/tree/dde156380b2ac372619ed332dbe60640b838b7fe>
- GitHub Release 大文件说明：<https://docs.github.com/en/repositories/working-with-files/managing-large-files/distributing-large-binaries>
