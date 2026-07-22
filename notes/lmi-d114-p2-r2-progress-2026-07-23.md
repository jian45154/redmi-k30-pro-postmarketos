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

## 设备状态

未触碰。仍为 initramfs 调试壳（telnet 172.16.42.1:23），userdata 持久，
`pmos_continue_boot` 可回六行终端。
