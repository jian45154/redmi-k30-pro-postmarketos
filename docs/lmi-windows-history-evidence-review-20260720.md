# lmi Windows 历史证据审查（2026-07-20）

状态：`evidence-only`
权威边界：当前 WSL 项目文件是治理、授权、构建、发布和硬件操作的唯一权威。Windows `lmi_linx` 目录只是历史证据源。

## 审查方法和导入决定

本次只使用文本搜索、元数据检查、哈希和只读 Git 查询；没有执行、`source`、导入或修改 Windows 目录中的任何脚本、程序、镜像或配置。

- Windows 树 HEAD 为 `e47ee0143acf3d32aa407a7574e185afa3ab938d`，工作树高度未提交；当前 WSL HEAD 为 `4cf8bbfa54b4dc7da138b0681d08e4a6949afee7`。
- 两个仓库不共享可在当前 WSL 中验证的该 Windows 提交谱系。被 `.gitignore` 排除的原始日志只能作为内容寻址证据，不能被宣称为提交绑定来源。
- Windows `AGENTS.md`、`.agents/`、`.claude/`、`.superpowers/`、`docs/superpowers/`、自动批准策略及旧执行器全部拒绝导入。
- 本次新文件导入列表为空。必要的 D110/D114 manifest、profile、D198–D203 证据、D110 boot 和 D80 证据/APK 包已在 WSL 的 `private/` 或 `.work/` 层按哈希存在，不再复制。
- 审查过的历史证据哈希和取舍见 `config/lmi-windows-history-evidence-lock.json`。

### Windows r37 fastboot 的时序和可追溯性边界

- Windows 历史记录中的版本字符串、路径或一次运行结果，不能追溯证明当时实际加载的 `fastboot.exe`、`AdbWinApi.dll` 和 `AdbWinUsbApi.dll` 字节。历史树是 dirty 的，相关日志也没有绑定到可由当前 WSL 验证的提交；因此不得把历史 r37 使用记录解释为当前副本的来源证明、完整运行时闭包证明或 Authenticode 验证记录。
- 当前 WSL 的 `fastboot-windows-provenance-lock.json` 单独固定官方仓库发布的 SHA-1/size、当前留存 archive 的本地 SHA-256，以及三个 archive member 的 SHA-256/size。这是面向后续执行的新合同，不能反向补强任何历史执行；其中本地 SHA-256 也不是 Google 发布的摘要，且没有找到该 r37 PE 的精确官方 source commit/build manifest。
- 任何后续 Windows 设备查询之前，当前执行副本仍须重新按精确 archive member 固定，并在执行主机上对 signer 和 timestamp 全链执行在线吊销检查；运行时必须再次核对当前 exe/DLL 的 SHA-256、size 和 Authenticode `Valid` 状态。仅完成本次历史只读审查不满足这些门禁，当前 production readiness 继续为 `blocked`。

## 可采信的结论

### P1：SSH

- D114 历史实机证据记录 RNDIS/ICMP 可达、TCP 22 开放、TCP 23 关闭。
- 两次一致的 ED25519 扫描和严格 host-key 校验后，SSH 验证了 `device-xiaomi-lmi-1-r142`、D110 boot UUID、D114 root UUID、`tty1` 和已启动的 `seatd`。
- 这些历史记录已被当前 WSL 中 2026-07-20 的实时 SSH 证明超越：`private/lmi-p1/recovery/d110-d114/d204-d114-live-ssh-attestation.json`。P1 可以标记为当前实时验证，但这不自动授权 reboot、RAM boot 或分区写入。

### P2：显示、terminal 和完整屏幕键盘

- D79 的操作者记录证明 terminal 中的单词+空格、Backspace 和 Enter 语义正常，但当时 12 列布局两侧被裁剪且按键过小。
- D82 运行日志记录 Weston DRM + pixman、`weston-terminal`、`weston-editor` 和 `/usr/libexec/weston-keyboard`同时运行；键盘二进制 SHA-256 为 `4649049a9793172cc592bc8c1a07eef6eb387fb42f5ee4039aab09a4808d99d3`。D82 操作者记录证明完整 10 列键盘可见且按键大小足够。
- D82 没有重复 D79 的 terminal 全套输入回归，因此只能把两次结果组合为历史基线，不能声称它们是同一次端到端验收。
- 当前 D114 已安装与 D82 完全同哈希的 `weston-keyboard`。2026-07-20 的 WSL 实时测试已验证非 root Weston、terminal、OSK、DSI enabled 和 text-input/input-panel 协议链，且清理无残留：`private/lmi-p1/recovery/d110-d114/d205-d114-live-terminal-osk-attestation.json`。
- P2 仍未完成：需要当前 D114 的实时屏幕可见性、触控和 terminal 完整键语义实物验证，以及可重现的持久镜像过渡。

### P3：扬声器和麦克风

- D85 实机只读日志找到了正确的嵌套 sound DT 路径和 `qcom,kona-asoc-snd`，且 `audio_apr` 已绑定、`kona-asoc-snd`/`q6core_audio` 驱动已注册。
- 同一记录中 `qcom,audio-pkt-core-platform` 仍未绑定，ALSA 没有任何真实 sound card。TFA9874 探测成功只证明功放驱动探测，不证明播放或录音可用。
- 旧“`/soc/sound` 不存在”结论是探测路径不完整，已被 D85 反证。同样，不能因为 mainline 命名的 `CONFIG_QCOM_APR`/`CONFIG_SND_SOC_QCOM` 未启用，就否定 downstream vendor techpack APR/Kona 实现；运行时 `audio_apr` 绑定已经反证这种简化推断。
- D85 绑定 D84/r9 历史运行时，不是当前 D110/r15 + D114/r142 的验收。P3 下一步应是当前组合上的新只读 ADSP→APR→q6core→machine-card 第一失败点采集，不应从 DTBO、mixer、音量、播放或录音写操作开始。

### boot、rootfs 和 telnetd

- D110 boot 是 Android boot header v2，52,944,896 bytes，SHA-256 `2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487`。它使用 4.19.325-r15 downstream kernel package，并包含针对 tmpfs/fs-context/BPF 问题的诊断和修复补丁；不应把它宣称为无诊断补丁的通用发布内核。
- 实际部署对应的 D114 transfer manifest 绑定 D110 boot 与 sparse userdata；sparse 为 2,192,400,084 bytes，SHA-256 `e8a30dc37cb4b75508d89725a9603bc15a985f4e51af77384e8d43c2928f8d68`，转换后 raw 为 3,339,714,560 bytes，SHA-256 `61ca69e6c241a92ad86539ffeebc0d4ef296572709445604ce26a78648f27bf6`。
- D114 嵌套 GPT 使用 4096-byte logical sectors；root 分区从 sector 124928 开始，共 690176 sectors。boot-image page size 与 rootfs/GPT sector size 不可混为一个概念。
- 物理 userdata `/dev/sda34` 的容量是 114,898,743,296 bytes。按 4096-byte logical sector 计算，`disk_sector_count=28,051,451`，因此 inclusive `last_lba=28,051,450`；备份 GPT header 位于该末 LBA，128×128-byte 的备份 entry array 占此前 4 个 sectors，即 `first_lba=28,051,446`、`last_lba=28,051,449`。旧 mapping v1 的 `gpt_disk_lbas=28,051,446` 错把 entry array 起点命名为“disk LBA 数”，已在 v2 删除而非保留兼容别名；deployer 对旧字段和关系不一致均 fail closed。
- 上述物理容器坐标不等于 3,339,714,560-byte D114 候选镜像自身的 815,360-sector GPT 几何。历史只读审查暴露的是字段语义错误，不构成新的实机观测、镜像重验或写入授权；两层几何必须分别绑定和验证。
- Windows 的 D114 “full” manifest 含重复 key，且 `artifact_boot` 指向 D86 外壳；判定实际 D110+D114 部署时只使用 transfer manifest 和 profile。
- telnetd/23 是含 `pmos.debug-shell` 的 initramfs 诊断通道，不是正常 userspace 终端。调试 hold 中没有 loop/root mount 不能单独证明 rootfs 故障；正常 D110/D114 运行时 TCP 23 关闭是预期状态。某些 one-shot telnetd 会被端口探测消耗，不应对当前正常运行时重复探测 23 端口。

### 设备身份和恢复边界

- 历史实机只读证据识别设备为 POCO F2 Pro / Xiaomi `lmi`（`M2001J11E`）、AArch64、SM8250，UFS boot device 为 `1d84000.ufshc`。
- bootloader-fastboot 报告 `product=lmi` 且 unlocked；`current-slot`/slot count 没有提供。设备上观测到 128 MiB `boot` 分区而没有 `boot_a`/`boot_b`，但“单 slot”仍是基于缺失的推断，不是 bootloader 显式声明。
- 可用的 D112 sparse userdata 回滚哈希已被 D114 profile 绑定，但它只是 pmOS userdata 回滚，不是完整原厂恢复。
- 历史 A12 recovery 可以 RAM boot，但它会自动以可写方式挂载 userdata，不是 storage-read-only 恢复环境；A15 recovery 曾被拒绝。Windows 目录虽有 LineageOS zip，但没有足够的仓库来源/验证 manifest，也没有找到已验证的完整 MIUI fastboot ROM 和完整 userdata 恢复路径。因此不得把 rollback 宣称为无条件保证。

## 被拒绝或已过期的结论

1. Windows 的 standing/automation approval 不适用。它允许的 reboot 和分区写入范围超过当前 WSL 安全合同；任何新 RAM boot 或分区写入仍受当前 WSL 治理和 `pmos-port-unsupported-device` 的当次精确批准门禁约束。
2. Windows D200 中“RAM boot 不修改持久状态”的表述过强。WSL 修正版明确为：host 没有执行 fastboot 分区写入，但被启动 OS 仍可能修改持久 userdata。
3. D205 completed JSON 说 splash/greetd 日志为空，而对应原始日志实际记录了 splash 已清除 CRTC 129/plane 58，以及 Greetd 的 `no default_session specified`。应优先使用原始输出的具体事实，但不直接导入含 SSH 会话和本地路径信息的整份日志。
4. D206–D209 曾把 `/etc/greetd/config.toml` 视为必需文件，但 D114 的 `/etc/conf.d/greetd` 实际明确指向 `/etc/phrog/greetd-config.toml`。真实的 Greetd 问题是该配置只有 `initial_session` 而没有 `default_session`；对当前终端目标而言，独立 Phoc 测试又被 EGL/Zink 初始化失败阻断，因此当前证据支持 Weston pixman 路线，而不是继续修复 Phosh 作为 P2 前置。
5. 历史记录中的 `outcome=positive` 常表示“证据采集器成功”，不表示功能成功。D85 就是这种情况：音频证据成功采集，但没有 ALSA card、播放、录音或物理声音证据。
6. `private/lmi-p1/recovery/d110-d114/recovery-attestation.json` 是实时 D204/D205 之前的恢复候选快照；其 `status` 和 `current_observation` 不是当前状态。当前 P1/P2 判定必须优先使用后来的 D204 和 D205 实时 attestation，但不改写该历史快照。

## 对当前目标的直接影响

- P1：保留当前 D110+D114 严格 pinned SSH 路线，不从 Windows 导入执行器或批准策略。
- P2：复用 D114 已安装的精确 Weston r10 terminal/OSK 二进制，构建 D114 兼容的最小 Weston pixman 持久 overlay；不降级到 D80 device/kernel 包，不把 Phosh 作为 terminal 目标的必要条件。
- P3：先为 D110/r15 + D114/r142 生成一个新的只读现场证据基线，再决定是 userspace 服务链、ADSP/AVS、APR/q6core 还是 machine-card 绑定问题。不能把当前 r107/r8 source-only P3 候选直接宣称为 D114 可安装包。
- 发布：Windows 中的 recovery/ROM、raw/sparse userdata、原始日志和第三方 APK 不因“哈希匹配”就自动获得再分发权。在公开镜像前，还需要独立清理现有 tracked 文件中的本地用户路径，并审查每个二进制/固件的许可和来源。
