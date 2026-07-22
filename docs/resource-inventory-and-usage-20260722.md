# 资源表单与使用规范 / Resource Inventory & Usage Rules — 2026-07-22

本文是 `lmi` 移植项目全部资源的分层清单和使用规则。资源分三层：
**A 公开仓库 → B 私有金库 → C 仅限本机**。层级越深，敏感度越高，
使用限制越严格。

## 一、资源总表

### A 层：公开仓库（github.com/jian45154/redmi-k30-pro-postmarketos）

任何人可获取、可再分发（MIT + GPL-2.0，见 `LICENSE`/`NOTICE`）。

| 资源 | 位置 | 用途 |
| --- | --- | --- |
| 设备/内核 pmaports 包 | `artifacts/wsl-pmaports/` | 复现构建的完整 recipe |
| 主线包参考 | `artifacts/mainline-pmaports/` | M-rNN 线参考 |
| 内核配置证据 | `artifacts/kernel-source/` | 配置推导依据 |
| 57 份镜像 manifest | `artifacts/images/*.manifest` | 每个历史构建的哈希/身份凭据 |
| 全部构建与守护脚本 | `scripts/`（约 110 个） | 构建、静态核验、受控设备操作 |
| 主机端测试套件 | `tests/` | installer/P1/P2/P2-D114/P3 静态门禁 |
| 移植实录 + 46 阶段修复史 | `docs/`、`notes/` | 知识与证据链 |
| 脱敏设备日志 | `logs/*.redacted.txt` | 硬件行为证据 |
| 治理规则 | `AGENTS.md` | 任何 agent 的安全与工作流约束 |
| 内核源码（外部钉定） | `LineageOS/android_kernel_xiaomi_sm8250` @ `a5b3099` | 下游内核源 |

### B 层：私有金库（github.com/jian45154/lmi-recovery-images，PRIVATE）

仅所有者账号可访问。Release `recovery-20260722` 含已固定的恢复/工具镜像：

| 资产 | 内容 |
| --- | --- |
| `pmos-lmi-normalboot-v110-…-20260713.img` | D110 已验证恢复 boot（守护 RAM-boot 路径用） |
| `pmos-lmi-ramboot-d111-debug-shell-key-recovery-20260720.img` | D111 调试 shell / 密钥恢复 boot |
| `pmos-lmi-normalboot-v46-…-20260624.img` | D-v46 Wi-Fi 基线 boot |
| `v46-pmOS_root.ext4.zst` | D-v46 基线 rootfs |
| `d114-hw-baseline-userdata-20260716.img.zst`（+ sparse 版） | D114 硬件测试基线 userdata（d198 实写版本） |
| `d114-p2-injected-rootfs-20260720.ext4.zst` | D114 P2 canonical 注入 rootfs |
| `d114-p2-assembled-userdata-20260721.raw.zst`（+ sparse 版） | D114 P2 canonical 组装 userdata |
| `provenance-and-tools.tar.zst` | 全部 attestation/回执/策略/部署报告 + 官方 pmOS 替换件 + platform-tools r37.0.0 |
| `manifest-src.sha256` / `manifest-assets.sha256` | 源文件与上传资产的完整哈希清单 |

### C 层：仅限本机（永不上传、永不入 git）

| 资源 | 位置 | 为什么留在本机 |
| --- | --- | --- |
| 设备校准数据 | `private/lmi-p1/calibration/`（7.8G） | 设备专属、不可再生、含标识 |
| 会话授权状态 | `private/…/d110-session-grants/` | 运行时授权，离机即失义 |
| 密封构建输入/输出 | `private/lmi-p1/seal-*/` | 现行构建状态 |
| 原始（未脱敏）日志 | `logs/*.txt`（gitignored） | 序列号/CPU ID/bootloader token |
| 上传暂存镜像 | `private/…/recovery/.upload-stage-20260722/` | 金库资产的本地镜像，用于日后核验 |
| 构建暂存 | `.work/` | 可再生 |
| 已排除的中间产物 | `.partial`、`.rejected-*`、base/candidate ext4 | 非"已固定"，不具恢复资格 |

## 二、使用规范

### 1. 校验优先（所有层通用）

任何镜像在使用前必须先过哈希：

```sh
sha256sum -c manifest-assets.sha256          # 金库下载后
cat <name>.zst.part* > <name>.zst            # 如有分片（本批无）
zstd -d <name>.zst
sha256sum -c manifest-src.sha256 --ignore-missing   # 还原后对源哈希
```

哈希不匹配的文件一律视为不可用，不修复、不猜测、不降级使用。

### 2. 刷写门禁

- **金库中任何资产都不构成刷写授权。**所有设备操作仍必须走公开仓库的
  守护脚本（如 `scripts/72_stage_downstream_ssh_wifi_test.sh`）+
  按 `AGENTS.md` 的每次写入单独审批。
- D110/D111 boot 镜像只用于 RAM-only 恢复引导；D114 userdata 基线是私有
  硬件测试基线，**不是**公开可刷镜像（见 D114 readiness 文档的门禁）。

### 3. 再分发边界

- A 层：自由分发。
- B 层：**永不公开**。资产含运行时暂存的专有固件内容与设备基线，
  仓库 visibility 必须保持 PRIVATE；不 fork 到组织、不加协作者、
  不生成公开分享链接。
- C 层：**永不离机**。需要异地备份时单独评估加密方案，不进 GitHub。

### 4. 恢复场景速查

| 场景 | 用哪个资产 |
| --- | --- |
| 设备无法进系统，需要 RAM 引导救援 | D110 `v110` boot（走守护 ramboot 流程） |
| 需要调试 shell / 密钥恢复 | D111 debug-shell boot |
| 回退到已验证 Wi-Fi 基线 | v46 boot + `v46-pmOS_root.ext4` |
| 复现 D114 硬件测试状态 | D114 hw-baseline userdata（raw 或 sparse） |
| 核对任何历史构建身份 | A 层 `artifacts/images/*.manifest` |

### 5. 金库维护规范

- 新的"已固定"镜像 → 打**新** Release tag（`recovery-YYYYMMDD`），
  附新的双 manifest，更新金库 README 资产表；不覆盖旧 release。
- 只收录三类：已验证恢复镜像、命名基线、canonical 带 attestation 的
  产物。`.partial`/`.rejected`/中间产物永不入库。
- 每次上传后与本地暂存目录逐资产核对大小与哈希清单。
- 本地删除任何 C 层恢复材料前，必须先确认金库中存在对应资产且哈希可验。
