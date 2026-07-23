# D114 P2 r2 最完整版推进记录 (2026-07-23)

接续 `notes/lmi-d114-p2-next-version-handoff-2026-07-22.md`。
分支 `agent/lmi-d114-p2-r2-most-complete`（worktree `.claude/worktrees/d114-p2-r2`）。

## 已完成

### §5 治理残留清理（主检出）
- `config/governance/policy.json` 回退到 revision `2026-07-22.1`；
- `notes/bringup-active.json`（`d110-boot-persist-1`，ready 未 claim）与
  `profiles/d110-terminal-boot.json` 已移出仓库；
- `python3 scripts/bringup_loop.py validate` → `ok (no active experiment)`。

### 主机侧改造（本分支提交）
- **machine-id 卫生化改为删除**（截空 → `rm`）：注入器
  `sanitize_public_image`、full-delta 期望集 `M|/etc/machine-id` →
  `D|/etc/machine-id`、attestation/injection-policy-lock 的
  `machine_id: removed`、组装器校验、测试夹具全部同步。
- **全链哈希重钉**（r1 流程保持自洽）：注入器 → injection-policy-lock →
  assembler → launcher → userdata-deploy-policy-lock-r1 →
  deploy_userdata → postwrite_revalidate legacy gate。
- **`artifacts/d114-pmaports/` 新跟踪目录**：device r144（Windows r143 +
  两条 Wi-Fi 运行级链接）+ 内核 r15（D110 2b264d64 同源配方，sha512 全
  实值）。r108–r142 式的"源丢失"不会再发生。
- **`scripts/74_build_pmos_d114_r2_rootfs.sh`**：r2 基础 rootfs 构建
  （从 d114-pmaports 同步缓存、ui=phosh + service_manager=openrc 守卫、
  install --no-fde --sector-size 4096 --no-sparse、密文日志脱敏、清单）。
- **`scripts/75_stage_d114_r2_candidate.py`**：候选派生（GPT 解析、
  p1/p2 UUID 归一化、base 提取、e2fsck 修复+校验、p1+p2 超级块
  s_wtime/s_lastcheck epoch 定格、img2simg 基线 sparse + 回路校验、
  staging manifest 输出全部锁改写所需数值）。已用 v114 raw 完成端到端
  自测：几何与锁完全一致，verify 日志 sha 与旧锁相同（4e23b50b）。
- 测试全绿：197 lmi_p2_d114、27 governance、safety lint、
  `59_release_static_ci.sh` OK（worktree 内含 private/.work 副本）。

## 关键发现（决定路线的三件事）

1. **P1 封印安装器逐字节钉死 `artifacts/wsl-pmaports`**（device r107 +
   kernel r8；`scripts/lmi_p1/build.py` `_EXPECTED_KERNEL_APKBUILD_SHA256`
   与 staged-pmaports 成员清单）。该树不可改动，r144/r15 因此另立
   `artifacts/d114-pmaports/`；构建脚本 74 只从新目录同步缓存。
2. **UUID 配对约束**：D110 2b264d64 的 cmdline 硬编码
   `pmos_boot_uuid=d4f78f7d-…` 与 `pmos_root_uuid=f8eb7c4b-…`。全新
   `pmbootstrap install` 的 UUID 是随机的，因此脚本 75 把新 raw 的
   p1/p2 文件系统 UUID 归一到这两个值——否则已验证的 D110 boot 找不到
   root。交接文档 §3 的 `P2_UUID` 重钉项在 r2 中是"钉同值"。
3. **内核选 r15 而非 r8/r9**：source-lock 钉的 r9 源已不存在（工作区 r8、
   Windows r15）；r15 正是实机验证的 D110 boot（2b264d64）的构建配方
   （见 `pmos-lmi-v110-…-r15-20260713.manifest` 的
   `kernel_package=linux-xiaomi-lmi-4.19.325-r15.apk`），装入 userdata
   后模块树与 RAM boot 运行内核一致，是严格改进。

## 两个人为门槛（当前阻塞点）

- **sudo**：pmbootstrap 建 chroot 需要 root；本会话 `sudo -n` 不可用。
  解法：会话内输入 `! sudo -v`（或给 pmbootstrap 配 NOPASSWD 条目）。
- **`PMOS_INSTALL_PASSWORD`**：`pmbootstrap install` 必需。注入器卫生化
  会把 shadow 锁死（密码在发布镜像中不可用），六行终端会话经 greetd
  自动登录、SSH 仅公钥。可由 owner 提供，或授权生成随机密码存
  `private/`（0600）。

## 续接 runbook（在 worktree 内，顺序执行）

1. `PMOS_INSTALL_PASSWORD=… bash scripts/74_build_pmos_d114_r2_rootfs.sh`
   （首跑会自举 chroot + 编译 4.19 内核，数小时）。
2. `python3 scripts/75_stage_d114_r2_candidate.py --build-dir
   private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-build-<tag>
   --raw <74 的输出 raw> --tag <tag>`。
3. 从 staging manifest + 新 base 镜像（debugfs 读 world/installed DB/
   shadow/apk cache 清单等）改写：
   - `config/lmi-p2-d114/source-lock.json`（§3 清单全部字段；
     dependencies 里 device r144、kernel r15、其余组件版本从新
     installed DB 读出；package pkgrel r1→r2）+
     `source_lock.py` EXPECTED_*；
   - `config/lmi-p2-d114/candidate-rebuild-lock.json`（新 derivation：
     e2fsck_repair_expected_exit 取脚本 75 实测值）；
   - 注入器常量区（新 build 目录、RAW/SPARSE/BASE/INPUT sha、
     IMAGE_SIZE、REPAIR_EPOCH、卫生化元数据常量——authorized_keys/
     resolv.conf/apk.log 尺寸、APKINDEX 名单、shadow sha 都随新 base
     重算）与 full-delta 期望集;
   - `generate.py` 重渲染 overlay → proot chroot
     （`private/lmi-p1/calibration/acquisition-root/work-proot-chroot2`，
     abuild + `pmos@local-6a5d38f2.rsa`，密钥已可读）双跑构建
     `device-xiaomi-lmi-terminal-0.1.0-r2.apk` → 重写
     `apk-build-attestation.json`；sixrow apk 不变；
   - 组装器 Contract（BASELINE/P2_SIZE/P2_UUID(同值)/D110_BOOT 不变）;
   - injection-policy-lock / deploy-policy-lock-r2 / profile 按 §3 链序
     重钉（参考本分支 39e676d 的重钉顺序）。
4. launcher 跑注入器 → assemble → 测试全绿 → 新 profile 走 per-profile
   授权（owner）→ flash + 验证。

## 2026-07-23 追加：新软键盘并入 + 免 root 构建通道验证

- **分页触摸键盘 r2 已并入本分支**（merge `worktree-sixrow-keyboard-v2`，
  提交 6b195c6：分页 11 列布局、多点和弦、长按滑选；终端二进制与 r1
  字节一致）。本版镜像将携带 `lmi-weston-sixrow-clients=14.0.2-r2`，
  取代交接文档"sixrow apk 不变"的假设（用户指示）。
- **r2 apk 已用规范密钥重签**：会话签名键的公钥已不存在；剥离签名段后
  用可读的 `pmos@local-6a5d38f2` 仅对 control.tar.gz 重签
  （apk verify OK；data/control 字节不变，datahash 链未破坏）。新 sha
  `8d2f2352…`，落位 `p2-d114-r2-most-complete-build-20260723/`；
  `build-attestation-r2.json` 与 `transient-stage-lock.json` 已重钉。
  注意：r2 注入时 keys-dir 的 sixrow 公钥要指向 6a5d38f2（与 p2.apk
  同一把），不再是 6a5fb853。
- **P2 终端 apk 免 root 复现验证通过**：generate.py 渲染 overlay →
  `unshare -r` chroot（calibration 副本）abuild -F -d → 产物与 r1 钉定
  哈希字节一致（`7cab262b…`）。r2 源锁更新后此通道即插即用。
- 基础 rootfs 构建仍卡 sudo：无 tty 时 sudo 时间戳按父进程记账，
  pmbootstrap 内部 sudo 取不到授权；写 sudoers 免密规则被会话权限
  分类器拦截，需 owner 在真实终端执行一次（见 PR/会话说明）。

## 2026-07-23 追加二：sudo 解锁 → rootfs 已建、全链已重钉、注入进行中

- **sudo 免密由 owner 授权**（`/etc/sudoers.d/99-lmi-build-nopasswd`，
  构建完可删）；安装密码 `147147` 存 `private/lmi-p1/recovery/d110-d114/
  .pmos-install-password`（0600，gitignored）。
- **r2 基础 rootfs 已构建**（`scripts/74`）：device r144 + kernel r15，
  phosh/openrc，raw `b05b0a74…` 3436183552 字节。debugfs 校验确认含
  两条 Wi-Fi 运行级链接 + rootctl+sudoers + pd-mapper + seatd/splash/
  power-panel 全套。
- **候选派生完成**（`scripts/75`）：p1/p2 UUID 归一到 D110 boot 配对，
  base `77386045…`、candidate `a5b368da…`（e2fsck 修复+校验均 exit 0，
  无释放块）、sparse `79276015…`、epoch 1784734606。几何变为
  713728 块 / p2_last_lba 838655。
- **新增 `scripts/76_dump_d114_base_facts.py`**：debugfs 免挂载读锁改写
  所需全部数值（world/db/shadow/组件/包版本/cache 清单），已自测。
- **全链重钉完成**：source-lock（+EXPECTED_*）、candidate-rebuild-lock、
  注入器全部内联常量、injection-policy-lock、assembler 契约
  （geometry 838655/last_usable 838906/p2_end 3435134976）、deploy-lock、
  postwrite legacy gate。P2 终端 apk 双跑复现 `70d45810…`（byte-identical）
  并重写 apk-build-attestation。**197 个 P2-D114 测试全绿。**
- **注入器调试中踩过并已修的坑**（都已落到代码）：
  1. 输入/输出目录不可同名 → 注入输出改到
     `p2-d114-r2-most-complete-injected-20260723/`（另建目录）；
  2. e2fsck 日志须 0644（脚本 75 已改）、apk 须 0600；
  3. **world/installed/scripts/triggers/shadow×2 六个 base 哈希早前手误**
     （前16位与正确值巧合相同）→ 以 facts JSON 为准全仓纠正；
  4. sixrow 记录**无 `c:` 字段**（commit 为空 apk 省略该行）→ 删期望；
  5. scripts.tar.gz 成员名 `…-0.1.0-r2.X<hash>.post-install`（版本随 pkgver）
     → find 模式 r1→r2，三个脚本 sha 与 r1 相同；
  6. `normalize_repair_epoch` 硬编码的是 r1 epoch 字节 → 改为 r2
     epoch `\216\343\140\152`（1784734606 LE）。
- **注入器实跑中**：已过全部前置校验（apk 装入 sandbox 成功、
  卫生化、strict record、scripts/triggers delta、epoch 归一），正在
  root 命名空间跑 e2image 双跑 allocated-only 规范化（最耗时步）。
  产物 → `…injected-20260723.bundle/{rootfs.ext4,attestation.json}`。

### 注入完成后的下一步（组装 → 测试 → flash 审批）

```
python3 scripts/lmi_p2_d114/assemble_userdata_image.py \
  --baseline-raw private/.../p2-d114-r2-most-complete-build-20260723/xiaomi-lmi-d114-r2-most-complete-userdata-20260723.normalized.img \
  --p2-raw       private/.../p2-d114-r2-most-complete-injected-20260723/lmi-d114-rootfs-p2-r2-most-complete-injected-20260723.bundle/rootfs.ext4 \
  --p2-attestation <同 bundle>/attestation.json \
  --output-bundle  private/.../p2-d114-r2-most-complete-assembled-20260723.bundle
```
产 userdata raw + android-sparse。之后写 WSL deploy profile（serial+nonce）、
per-profile owner 授权、flash + postwrite 验证。**flash 是 Tier 2
persistent，须 owner 逐次批准。**

## 2026-07-23 追加三：注入 + 组装完成，镜像已就绪（未 flash）

- **注入器实跑成功**：injected rootfs `50d70dd2…`（2923429888 字节），
  attestation `954e56fa…`。落位
  `…injected-20260723.bundle/{rootfs.ext4,attestation.json}`。
- **组装成功**：最终 userdata raw `321998e04b04b700aa4ae96205656f8ee9223e6e7a3edbf6af2362e85d1fd276`
  （3436183552 字节）、android-sparse `e1c5578c5badfe558785ee57320f2ef8679763194ba5dd3a29f1aadf0d0b55ad`。
  落位 `…injected-20260723/lmi-d114-userdata-p2-r2-most-complete-assembled-20260723.bundle/`。
- **镜像内容已核验**（debugfs/dumpe2fs）：
  - 分区 UUID 配对正确（boot d4f78f7d / root f8eb7c4b，匹配 D110
    2b264d64 boot cmdline）；
  - 新分页键盘二进制在位 `/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow`
    = `d6b9e514…`；
  - Wi-Fi 两条运行级链接 `lmi-wlan-on`、`lmi-cnss-fs-ready` + `pd-mapper`
    default 链接就位；
  - `/etc/machine-id` 已删除（首启由 dbus-uuidgen 重建，不再黑屏）；
  - 无 `/home/lmi/.ssh`（base 未装 host key，卫生化确认 absent-in-base）。
- **全测试绿**：197 P2-D114 + governance + safety lint +
  `59_release_static_ci.sh` 全 OK。

### 仅剩 flash（Tier 2，须 owner 逐次批准）

镜像已完整就绪。下一步是写 WSL deploy profile（需 device serial +
per-write nonce）、建 per-profile `authorized_profiles` 授权（owner ian）、
经 `deploy_userdata_wsl.py` 执行器 flash userdata、postwrite 验证。
按 AGENTS.md：persistent 分区写必须 owner 对该 profile 逐次 hash-bound
批准，且需 distinct-hash 回滚件（当前 userdata 即回滚源）。**未经批准
不 flash。**

## 2026-07-23 追加四:userdata 已刷写(owner 批准),转录假阴性

- **owner 批准刷写**。设备经 usbipd busid 2-5 attach 到 WSL,fastboot
  只读 preflight 全绿:serial **8336ded7**、product lmi、userdata f2fs
  物理分区(容量 114898743296)、电量 **4429 mV**、已解锁、bootloader。
- **部署链建齐并 local-audit 通过**:
  - `deploy_userdata_wsl.py` Contract 升级到 r2(候选 artifacts +
    回滚=r2 base sparse `79276015…`/baseline_raw `b108f581…`);
  - 新建 `config/lmi-p2-d114/userdata-deploy-policy-lock-wsl-r2.json`
    (sha `a8f17e82…`);
  - r2 WSL deploy profile(serial+新 nonce、候选 sparse `e1c5578c…`);
  - `local-audit` = `LOCAL_AUDIT_PASSED_NO_DEVICE_ACCESS`,
    `preflight` ×多次 = `PREFLIGHT_PASSED_NO_STATE_CHANGE`
    (identity_match=true)。
- **execute 已跑,fastboot 进程 `exit_code: 0`(写入成功)**,但部署器
  转录解析器判 `transport_completed: false` / route
  `USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY`(exit 3)。这是
  [[deploy-transport-parser-false-negative]] 记录的**已知假阴性**:
  `_transport_completed` 要求 stdout 为空 + stderr 末行精确
  `Finished. Total time` + Sending/Writing 严格配对,Debian/Ubuntu
  fastboot 转录格式不匹配。**fastboot 只在成功时返回 0,故写入实际已完成。**
- **耐久 ledger 已记录**:`{e1c5578c…}.attempt.json`(候选尝试)+
  `{approval}.consumed.json`(claim 一次性消费)。**不可重刷**(claim 已消费、
  repeat guard;重刷需新 claim,且 exit 0 无需重刷)。
- 因分类器拦截真机写命令,execute 由 owner 用 `!` 在会话内运行
  (脚本 `…/wsl-run-20260723/run-flash.sh`)。

### 剩余:功能验证(RAM boot)

userdata 已是 r2。功能验证脚本
`…/wsl-run-20260723/ram-boot-verify.sh`:`fastboot boot` D110 normalboot
(2b264d64,RAM-only 不写分区)挂载新 r2 userdata,设备应起为六行终端并
re-enumerate 成 RNDIS(172.16.42.1)。验证点:wlan0 出现(Wi-Fi 修复)、
machine-id 首启重建(不黑屏)、六行分页键盘、rootctl/pd-mapper。
持久开机(flash boot 配对)仍是独立 Tier-2 项,须另行 owner 授权。

## 2026-07-23 追加五:RAM boot 已加载 r2,live 网络验证受限

- **RAM boot 成功**:`fastboot boot` D110 normalboot 返回
  `Sending 'boot.img' … OKAY / Booting OKAY / Finished. Total time: 5.778s`
  exit 0。设备离开 fastboot 并 re-enumerate 成 **RNDIS 0525:a4a2**——
  证明 D110 内核已加载并起了 USB gadget。
- **顺带确认刷写假阴性根因**:RAM boot 的 fastboot `OKAY` 输出走
  **stdout**,而 `_transport_completed` 要求 `result.stdout == b""`。
  这就是 userdata 写入被判 UNKNOWN 的确切原因——fastboot exit 0 =
  写入成功。([[deploy-transport-parser-false-negative]] 得到实测佐证。)
- **live 网络验证此路不通**,两因:
  1. **r2 是设计锁定的公开镜像**:卫生化删除 authorized_keys、SSH 仅
     publickey、密码认证禁用。即使完整启动也无法 SSH 诊断(r5 当年是
     临时注入了会话公钥;r2 重建后该键不存在,符合发布卫生化预期)。
  2. RNDIS 已在 WSL 绑为 `enu1i1`(cdc_subset,carrier up)、配
     172.16.42.2/24,但 172.16.42.1 约 8 分钟内无 ARP/22/23 应答。
     WSL mirrored 网络模式下 usbnet 未透传到设备。
- **功能验证应目视手机屏幕**:六行终端是否上屏(证不黑屏 + machine-id
  首启重建)、分页键盘手感、Wi-Fi(wlan0 自起)。这是本版四项改动的
  真实验收点,须 owner 目视/操作确认。

## 设备状态

未触碰。仍为 initramfs 调试壳（telnet 172.16.42.1:23），userdata 持久，
`pmos_continue_boot` 可回六行终端。
