# LMI CLI Installer v0.1.0-alpha.1 用户指南

这是 `lmi-installer` 的唯一用户指引。Git tag `v0.1.0-alpha.1` 固定本版
程序、文档与发布资产；后续版本必须同时更新三者。

| 项目 | 本版定义 |
| --- | --- |
| CLI 版本 | `0.1.0-alpha.1` |
| Git tag | `v0.1.0-alpha.1` |
| 发布级别 | Experimental / GitHub Pre-release |
| 目标设备 | Xiaomi Redmi K30 Pro / POCO F2 Pro，fastboot `product=lmi` |
| 支持主机 | Linux 或 WSL2，Python 3.10+ |
| 发布内容 | CLI 源码工具包，不含 boot/rootfs 镜像或 profile |
| 设备写入 | **不支持；本版只验证文件并执行可选的只读查询** |

## 先读结论

`v0.1.0-alpha.1` 是严格的 verification-only 源码预览，不是“下载后即可刷机”的
镜像包。发布资产不包含：

- `boot.img` 或 `userdata.img`；
- `installer-profile.json`；
- 原厂或第三方 recovery/rollback 镜像；
- 任何执行授权、设备写入或重启入口。

本版 CLI 没有 `flash`、`erase`、`format`、`boot`、设备重启或 bootloader 重锁
路径。`install` 始终是 dry-run，不连接设备。即使维护者自行提供镜像，
`build-bundle` 也只会复制、描述和校验文件，并固定写入
`release_eligible=false`；它不会授予刷写资格。

不要从其他实验记录中拼接 D-vNN、M-rNN、D110 或 D114 镜像。那些编号不是本版
用户 Release，也不能替代精确镜像验收。

## 下载与校验

从 GitHub Release 下载：

- `lmi-installer-v0.1.0-alpha.1-source.tar.gz`
- `lmi-installer-v0.1.0-alpha.1-source.tar.gz.sha256`

在 Linux/WSL2 中执行：

```sh
base=https://github.com/jian45154/redmi-k30-pro-postmarketos/releases/download/v0.1.0-alpha.1
curl -fLO "$base/lmi-installer-v0.1.0-alpha.1-source.tar.gz"
curl -fLO "$base/lmi-installer-v0.1.0-alpha.1-source.tar.gz.sha256"
sha256sum -c lmi-installer-v0.1.0-alpha.1-source.tar.gz.sha256
tar -xzf lmi-installer-v0.1.0-alpha.1-source.tar.gz
cd lmi-installer-v0.1.0-alpha.1
./lmi-installer --version
./lmi-installer --help
```

预期版本输出：

```text
lmi-installer 0.1.0-alpha.1
```

工具包内的 `SHA256SUMS` 还覆盖 `LICENSE`、`NOTICE`、`USER_GUIDE.md`、启动器
和 Python 源码：

```sh
sha256sum -c SHA256SUMS
```

SHA-256 只能发现下载损坏或内容被替换，不能独立证明发布者身份。本 alpha 版尚未
提供独立签名；高风险环境应从 tag 检出源码并自行复核。

## 本版命令边界

| 命令 | 行为 | 是否访问设备 |
| --- | --- | --- |
| `--version` / `--help` | 显示版本或帮助 | 否 |
| `build-bundle` | 构建 `release_eligible=false` 的验证目录 | 否 |
| `info` / `plan` | 读取 profile 并打印验证计划 | 否 |
| `verify` | 校验 profile、文件类型、大小与 SHA-256 | 否 |
| `install` | 执行 `verify` 后打印 dry-run 计划 | **否** |
| `doctor` | 校验 bundle 后查询 fastboot 工具版本 | 仅主机工具 |
| `preflight` | 只读查询一台设备的产品、解锁、模式、电压和分区大小 | 是，只读 |
| `wait-fastbootd` | 轮询同一组只读属性，等待用户在外部进入 fastbootd | 是，只读 |

本版解析器会拒绝旧设计中的 `--enable-execution`、`--execute`、
`enter-fastbootd`、`flash-rootfs`、`flash-boot` 和 `reboot`。这些名称不是隐藏的
高级接口，也不能通过 profile 打开。

下载的源码工具包没有 profile，所以可以直接使用的是 `--version`、`--help` 和
`build-bundle`。其余命令用于检查维护者单独构建的验证目录。

## 验证目录的使用流程

验证目录必须至少包含：

```text
lmi-installer-<release-id>/
├── lmi-installer
├── lmi_cli_installer.py
├── installer-profile.json
├── SHA256SUMS
├── RECOVERY.md
├── images/
│   ├── boot-lmi.img
│   └── userdata-lmi.img
└── metadata/
    └── build.manifest
```

这些文件的存在只表示它们可以接受静态检查，不表示可以刷写。先执行完全离线的
检查：

```sh
./lmi-installer info
./lmi-installer plan
./lmi-installer verify
./lmi-installer install
```

`install` 的成功结尾应明确包含：

```text
device_state_change=false
dry_run=OK; no device was accessed and no device-state command was executed
```

只有在确实需要读取设备状态、且手机已经由用户手动进入 fastbootd 时，才运行：

```sh
./lmi-installer doctor
./lmi-installer preflight
./lmi-installer wait-fastbootd --timeout 120
```

它们只调用 fastboot 的版本、`devices` 与 `getvar` 查询。CLI 不会把捕获到的
fastboot stdout/stderr 原样写入错误消息；公开输出中的设备标识为序列号的
SHA-256 短指纹，不打印原始序列号。

WSL2 可以使用 Linux fastboot，也可以显式传入 Windows 可执行文件：

```sh
./lmi-installer doctor --fastboot /mnt/c/path/to/platform-tools/fastboot.exe
```

Windows 驱动与 usbipd 连接不由本程序配置。只读设备检查仍要求恰好连接一台
设备，且报告 `product=lmi`、`unlocked=yes`、`is-userspace=yes`；不满足时立即
拒绝。

## 维护者：构建验证目录

以下命令只制作验证目录，不会也不能制作 execution-enabled bundle：

```sh
scripts/lmi-installer build-bundle \
  --boot /path/to/boot-lmi.img \
  --rootfs /path/to/userdata-lmi.android-sparse.img \
  --build-manifest /path/to/build.manifest \
  --recovery-guide /path/to/RECOVERY.md \
  --release-id lmi-v0.1.0-alpha.1 \
  --source-commit "$(git rev-parse HEAD)" \
  --channel experimental \
  --output /tmp/lmi-installer-verification
```

构建器拒绝覆盖已有输出，限制目标产品为 `lmi`，校验 Android boot header、
Android sparse 几何、规范相对路径、常规文件属性、大小与 SHA-256，并始终写入：

```text
release_eligible=false
```

## 维护者：重建 GitHub Release 资产

从 `v0.1.0-alpha.1` tag 的仓库根目录执行：

```sh
scripts/73_build_lmi_installer_source_release.sh /tmp/lmi-release-a
scripts/73_build_lmi_installer_source_release.sh /tmp/lmi-release-b
cmp \
  /tmp/lmi-release-a/lmi-installer-v0.1.0-alpha.1-source.tar.gz \
  /tmp/lmi-release-b/lmi-installer-v0.1.0-alpha.1-source.tar.gz
```

脚本只复制五个明确白名单文件，固定 tar 时间戳、属主、权限和 gzip header，生成
包内及包外 SHA-256，并在交付前重新解包验证。它不会遍历整个 checkout，也不会
包含镜像、日志、测试产物或 `private/`。

## 升级为可刷版本前必须重新设计

未来如需发布“下载即用”的刷机镜像，必须使用新的版本号和 tag，并至少完成：

1. 将确认授权绑定到精确 release、镜像哈希和设备身份；
2. 在单一事务中强制 `userdata → boot → reboot`，不能跳过或单独调用后续阶段；
3. 每次写入前重新验证仍为同一台 `lmi`、已解锁、处于 recovery fastbootd；
4. 对精确输出字节完成来源、许可证、隐私、构建与实机验收；
5. 提供并实测与同一设备状态匹配的恢复路径；
6. 对 Release 资产签名，并通过独立可信渠道公布签名密钥指纹。

本版没有这些执行能力；修改 profile 或自行补充镜像不会改变这一事实。

## 已知限制

- 不含可刷镜像，不能完成手机安装。
- 不为 D-v52、M-r6/M-r7 或任何 D110/D114 实验候选授予发布资格。
- 未提供资产签名，只提供 SHA-256 完整性文件。
- 设备查询测试使用 fake fastboot；本版不据此声明新的实机功能证据。
- 不声明音频、麦克风、蓝牙、相机、蜂窝网络、传感器、休眠或充电功能可用。

许可证见工具包中的 `LICENSE` 与 `NOTICE`。
