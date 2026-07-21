# lmi P3 音频 userspace 候选报告

日期：2026-07-20（Australia/Sydney）

状态：`host-source-only-candidate`；`release_eligible=false`；不是实机 P3 验收结果

## 范围和基线更正

本次只修改 P3 的锁、overlay 生成器、文本运行时文件、离线测试和本报告。没有
构建新的 APK/镜像，没有连接或查询手机，没有执行真实 sysfs、ALSA、ADB、fastboot、
SSH、网络或音频操作，也没有修改 P1、P2、D80 或内核文件。只读核验了已保存的
r8 APK、锁定内核源码和脱敏旧日志。包仍不包含专有
固件、TFA container、ACDB/DSP 库或 UCM，也不加入任何 runlevel。

旧候选错误绑定了不可组合的 D80 冻结 APK `device-xiaomi-lmi=1-r139` 和
`linux-xiaomi-lmi=4.19.325-r9`。现在锁和生成的 APKBUILD 都绑定当前 P1/P2
源码基线：

- `device-xiaomi-lmi=1-r107`；
- `linux-xiaomi-lmi=4.19.325-r8`（是生成 APK 的显式精确依赖，不是只写在报告
  中）；
- 已保存的精确 r8 APK SHA-256 为
  `67cbc5a543b425d3602ffa33b722fbf0379dcdbf184c5996c960576f16c91610`，包内
  `usr/share/kernel/xiaomi-lmi/kernel.release` 精确为
  `4.19.325-cip128-st12-perf`；该值也与已保存的脱敏启动日志一致；
- pmaports commit `6fb3a1e5eb21c809891645a2ba5ae11fa788e032`；
- 不修改内核，仍使用内置 vendor techpack/APR/Kona/TFA9874 路径。

P3 不要求 P2 GUI 包，因此可叠加在 P1-only 或 P1+P2 的相同 r107/r8 根文件系统
上；它不会把 P2 尚未验证的 VT delta 描述为已解决。

## 旧 ADSP 路径和 P1 root 边界

已只读审计当前 P1 r107 合同。P1 最终镜像只允许 `lmi` 通过
`/usr/sbin/lmi-rootctl` 执行精确列举的 reboot、bootloader reboot、sshd status
和经确认的 sshd restart；它没有 ADSP 子命令。P3 锁固定该 helper、主 sudoers
文件和唯一 sudoers drop-in 的 SHA-256。

生成包通过两层阻断旧的无门禁 `adsp-audio` service：

1. APK `depends` 含 `!adsp-audio` 和 `!adsp-audio-openrc`，使包解算阶段拒绝
   共存；
2. `device-xiaomi-lmi-audio.post-install` 调用
   `/usr/libexec/lmi-p3-route-guard`。guard 要求精确 P1 `lmi-rootctl`、主
   sudoers 和唯一 `90-lmi-rootctl` 规则，拒绝任何额外 sudoers/doas 文件、旧
   `/etc/init.d/adsp-audio`、旧 systemd unit、任何旧 ADSP runlevel link，以及
   P3 自身的 runlevel link。每次 P3 probe/boot 又重新执行同一 guard，防止安装
   后漂移绕过门禁。

guard 只证明已审计的包、service 和 P1 非特权入口没有第二条路径。已经取得
root 权限的管理员仍可直接写 root-owned sysfs；P3 自己无法在所拥有的包路径内
取消 kernel 暴露的 root 权限，因此本文不声称系统对 root 具有“唯一写入口”。
若要求连 root 直接写也不可行，需要另行评审内核权限/LSM 或修改 P1 root
治理合同，均不在本次授权范围。

另一个明确的组合限制是安装顺序：post-install 要求 P1 finalizer 已经放置并
封存 rootctl/sudoers。若把 P3 加进 finalizer 之前的 pmbootstrap 包事务，它会
因 P1 边界尚不存在而失败关闭；当前安全路径只能是在已完成 P1 finalizer 的
r107/r8 rootfs 上安装，或以后由 P1 owner 增加一个先封存边界再验证 P3 的构建
阶段。本次没有越权修改 P1 来隐藏这个限制。

## ADSP 状态机

无参数或 `probe` 只执行静态只读检查。完整 probe 和唯一 boot 命令还需要两个
本地 review 文件的精确 SHA-256。默认 conf 中确认值和两个 digest 全为空，所以
源码候选默认不能写 ADSP。

写入前必须全部成立：

1. `/etc/lmi-release-identity` 中 schema、scope、`device_xiaomi_lmi=1-r107`、
   `linux_xiaomi_lmi=4.19.325-r8` 各出现且只出现一次；已安装 deviceinfo 的
   codename 和 DTB 分别精确为 `xiaomi-lmi` 和 `qcom/kona-v2.1-lmi`；
2. `uname -m` 精确为 `aarch64`，`uname -r` 精确为已从上述固定 r8 APK
   `kernel.release` 核验的 `4.19.325-cip128-st12-perf`，不再使用源码字符串猜测；
3. DT `model` 精确为 `Qualcomm Technologies, Inc. xiaomi lmi`，compatible
   顺序精确为 `qcom,kona-mtp`、`qcom,kona`、`qcom,mtp`；
4. `/sys/kernel/boot_adsp/boot` 必须是非 symlink regular sysfs attribute，且
   `stat` 精确为 uid 0、gid 0、mode 0220；任何 owner/group/mode/type 漂移均失败，
   不因调用者 root 本身可写就接受。该检查既用于早期 probe，也在慢哈希后紧邻
   唯一写入再次执行；
5. P1 privilege/legacy-route guard 仍通过；
6. `lmi-firmware-mount`、`lmi-qrtr-ns`、`pd-mapper`、`rmtfs`、`tqftpserv`
   同时有 OpenRC started marker 且 `rc-service ... status` 成功；OpenRC service
   用精确 `need` 列表表达真实依赖和先后语义。包不自动启用该 service，但经
   批准手工 start 时 OpenRC 会先满足这些 needed services；
7. `/sys/bus/msm_subsys/devices/subsys*` 的每个候选都必须是目录，并有可读、
   唯一且受锁允许的 `name`。锁定的 lmi 名称集合是 `a650_zap`、`adsp`、`cdsp`、
   `cvpss`、`esoc0`、`ipa_fws`、`ipa_uc`、`npu`、`slpi`、`spss`、`venus`、
   `wlan`；未知、缺名、不可读或重复名称均失败。其中必须恰好一个 `name=adsp`，
   其 `firmware_name=adsp`，写入前 state 必须精确为大写 `OFFLINE`；已有
   `ONLINE`（重复请求）、大小写不同、`OFFLINING`、`CRASHED`、缺失或多个 ADSP
   节点都失败；
8. 固定 `/etc/lmi-p3/adsp-firmware.provenance` 是 root:root、mode 0600、
   single-link、非空 regular file，其 digest 与本地批准值一致，schema/source
   kind/source root/evidence digest/review id 都完整且唯一；
9. 固定 `/etc/lmi-p3/adsp-firmware.inventory` 同样是 root:root、mode 0600、
   single-link、非空 regular file，具有独立精确 digest，并绑定上面的
   provenance digest。清单必须先列一个非空 `adsp.mdt`，再按编号严格递增
   列出至少一个 `adsp.bNN`；每项固定 basename、size、SHA-256 都必须匹配，实际
   `adsp.b*` 集合不能缺失、额外、重复或含非 `bNN` 名称。每个 `/lib/firmware`
   路径必须解引用为 `/mnt/vendor/firmware_mnt/image/<同名文件>` 下的非空可读
   regular target，从而与 P1 只读 stock firmware mount 组合，而不复制 blob。

boot 命令还要求精确 token `lmi-p3:boot-adsp=1`。它先验证 root:root mode 0755
的 `/run`，再以竞态关闭的 create-or-validate 流程建立 root:root mode 0700 的
私有 `/run/lmi-p3` 边界；转换锁是该边界内原子创建的
`adsp-transition.lock` 目录，不再依赖 OpenRC 会规范为 root:uucp mode 0775 的
`/run/lock`。锁由 helper 持有到进程退出，HUP/INT/TERM 都明确终止并通过 EXIT
清理自己的锁。

在持锁完成可能较慢的 review/firmware 哈希后，helper 会先原子创建同一私有
边界内的 `adsp-boot-attempted` latch，再紧邻写入重新核验身份、service、route、
sysfs 和精确 `OFFLINE`。该 latch 不由 helper 删除，只随重启清空 `/run`；因此
latch 建立后的最终门禁失败、写失败、崩溃、超时或信号退出都禁止本次开机内
重试。随后源码中唯一一次 sysfs 重定向把字面值 `1` 写入固定 boot attribute。
最多检查 50 次、每次间隔 0.1 秒：只允许继续看到 `OFFLINE` 或成功看到精确
`ONLINE`；任意其他状态立即失败，约 4.9 秒后仍未 ONLINE 则超时失败。成功后
再次调用也先被 latch 拒绝。写入后没有 userspace rollback；恢复边界仍是另行
批准的重启。

## 扩展只读 probe

`lmi-audio-probe` 现在盘点：

- release identity、running kernel、DT model/compatible 和整个嵌套音频 DT；
- `boot_adsp`、downstream `msm_subsys` name/state/firmware/crash 信息和可选
  remoteproc 状态；
- 完整 ADSP 文件名集合、regular-target 状态、symlink 解析位置及本地 review
  文件 digest（不输出 review 文件内容）；
- 五个 required services 的 started marker 和 runlevel links；
- platform audio、downstream `swr`、SoundWire、SLIMbus 设备/driver links，以及
  I2C TFA98xx name/modalias/compatible/driver；
- `/proc/config.gz` 或匹配 running release 的 boot config 中 QRTR、subsystem
  restart、service locator/PDR、APR、RPMSG、ALSA、SWR/SLIMbus 相关符号，包括
  `is not set`；
- QRTR/PDR/APR/RPMSG debug/proc/platform/device endpoints 和 `ss -A qrtr`；
- ALSA cards/devices/PCM、`aplay -l/-L`、`arecord -l/-L`、只读
  `amixer scontrols/contents`；
- 最多最后 240 行 `dmesg`。

它不播放、不录音、不改 mixer、不启动/停止 service，也没有 sysfs 重定向。
默认 stdout 是 `evidence_class=redacted-shareable`：`uname` 主动省略 nodename，
整个报告统一经过 redactor；`/etc/lmi-release-identity`、`/proc/version`、dmesg
以及其他输出中的 serial/cpuid/UUID、build user/host、MAC、IPv4/IPv6、SSID/BSSID
和 home user path 均不会原样发布。即使标记为 redacted，分享前仍应人工检查未知
格式；raw 输出禁止分享。

需留存原始证据时只能由 uid 0 显式运行 `lmi-audio-probe --archive-private`。
helper 验证 root:root mode 0755 的 `/var/log`，安全创建或验证 root:root mode 0700
的 `/var/log/lmi-p3`，以不覆盖的 PID 文件名同时生成 root:root mode 0600、
single-link 的 `.raw` 和 `.redacted`。`.raw` 明确标记
`raw-private-do-not-share`，只允许留在私有证据层；只有对应 `.redacted` 可进入归档
或分享流程。行为测试把所有 sys/proc/dev/etc/run/firmware/archive 路径改到临时
fixture，使用 fake uname/sleep/dmesg/ALSA 命令，验证 default probe 前后文件树
完全一致，并验证 raw marker 不会出现在 stdout 或 `.redacted` 文件中。

## 确定性和离线验证

生成命令（输出目录必须不存在）：

```sh
python3 -m scripts.lmi_p3.generate \
  --lock config/lmi-p3/source-lock.json \
  --output /tmp/lmi-p3-overlay-example
```

生成根目录、`device/`、`device/downstream/` 和 package 目录均固定 mode 0755；
manifest、APKBUILD 和所有 package source 固定 mode 0644。源目录必须是非 symlink
mode 0755，源文件必须是 stable single-link mode 0644 regular text。生成器仍拒绝
已存在输出、额外/二进制/可写/模式漂移源，并生成确定性 manifest 和 checksum。

离线验证：

```sh
python3 -m unittest discover -s tests/lmi_p3 -v
for file in files/lmi-p3/*; do sh -n "$file"; done
```

当前 38 项 P3 测试通过；包括目标 r8 release、完整 12-name lmi subsystem
topology、精确 root:root 0220 boot sysfs metadata 及哈希中途漂移、敌对 runtime
parent/stale entry、并发锁、failed-attempt latch、私有 mode 0600 raw archive 和
serial/cpuid/UUID/build host/user/MAC/IP/SSID marker 脱敏，以及临时 fixture/fake
command 上的实际 shell 行为，而
不只是源码字符串断言。`--require-release-ready` 仍故意失败。

## 剩余阻断项

1. 没有采集并评审真实 stock ADSP 的完整 `mdt+bNN` 集合、size、digest 和来源
   证据；package 不提供 inventory/provenance，默认 digest 为空，因此当前候选
   实际不能执行 boot。
2. 没有构建 P3 APK，也没有验证 `pd-mapper`/OpenRC 子包在最终离线仓库中的完整
   dependency closure；r8 kernel APK digest 已固定，但 r107 device artifact 和
   最终可复现 package 集合仍需构建证明。
3. 没有本次当前设备的实机只读 probe 结果。锁定 r8 源码/DTB 与旧硬件日志共同
   支持上述 12-name allowlist，但没有保存的当前 r8 `subsys*/name` 直接清单，
   因而仍未证明当前启动中唯一 ADSP 节点、PDR/APR/QRTR endpoints、SWR/I2C TFA
   binding、machine card 或 PCM 存在。
4. 没有执行 ADSP boot、播放、录音、mixer、UCM、冷启动或 P1/P2 回归。每个主动
   硬件步骤仍需当次独立批准、超时/音量/停止方案和恢复证据。
5. root 直接 sysfs 写无法由此 userspace 包消除；若这被定义为必须消除的全系统
   bypass，P3 保持阻断，不能声称唯一入口或提升为 accepted。

在上述硬件、固件来源、构建 closure、主动音频和 P1/P2 回归全部完成前，P3
必须保持 source-only candidate。
