# 六行键盘 v2：分页 + 多指并击 + 长按滑选（2026-07-23）

状态：**主机侧完成（补丁 + 静态合同 + 重建 APK），未做任何设备操作。**
本次为 `lmi-weston-sixrow-clients` 独立迭代（r1 → r2），不改动 D114 r1 镜像链的
任何钉点（`inject_rootfs_candidate.sh`、`injection-policy-lock.json` 仍锁 r1 APK）。

## 需求 → 实现映射

用户提出 10 项软键盘优化需求，全部落在新补丁
`files/lmi-weston-sixrow/0003-sixrow-paged-touch.patch`（仅改 `clients/keyboard.c`）：

1. **多指并击（大写）**：toytoolkit 的 per-touch-id down/up/motion 回调 +
   每指 `touch_slot` 跟踪。Shift/Ctrl 按下即生效：按住 Shift 另一指点字母 →
   大写（`shift_press/shift_release/shift_after_use`）；单点 Shift = one-shot
   大写；单点 Ctrl = 锁存（原行为保留），按住 Ctrl 可连续并击。
2. **长按放大镜滑选**：按下 350ms（`LONG_PRESS_USEC`，toytimer）进入滑选，
   放大气泡（1.6×）显示当前悬停键并随手指移动，抬起提交悬停键；
   顶行无上方空间时气泡落在键下方。
3. **减少动画**：字符键改为直接 commit（不再走 preedit 增量回显）；
   删除 numeric/arabic 布局与 preedit style 循环键。
4. **分页 10-11 键/行**：11 列 × 6 行两页（字母页/符号页），内容行每行
   10-11 键，键位单元 60×60（逻辑宽 540 = 11×60×540/660）。
5. **功能键固定**：第 0 行（Esc + 方向 + Home/End/PgUp/PgDn + Bksp）、
   第 4 行（Tab/Ctrl/Shift/Enter）、第 5 行（[ABC/#&] + Space）两页共享，
   静态校验强制两页 fixed 行逐键一致。
6. **符号页终端高频字符**：`~ \ | _ # $ @ & ( ) [ ] { } && ||`（另有数字行、
   `` ` `` `! % ^ * = +`），`&&`/`||` 为双字符键一次提交两字节。
7. **方向键在顶部第一行**，与 PgUp/PgDn/Home/End 同排（终端侧
   KM_NORMAL/KM_APPLICATION 编码器已支持 Home/End/PgUp/PgDn）。
8. **路径符号靠右**：字母页行尾 `/`（r1）、`-`（r2）、`.`（r3，2 格宽）。
9. **底部固定 [ABC/#&] 标签**：宽 2 格，双半区渲染，当前页半区高亮填充，
   点按切页（`keyboard_switch_page`）。
10. **键距**：每键四边 4 单位内边距（`key_margin`），命中区仍为整格；
    短点只在抬起仍落在按下键格内才提交，滑过邻键不误触。

## 合同与锁链更新

- `scripts/lmi_weston_sixrow/verify.py`：EXPECTED_LETTER_ROWS /
  EXPECTED_SYMBOL_ROWS（含 fixed 行一致性、11 列、行内 10-11 键、Shift 映射、
  符号页字符覆盖）+ KEYBOARD_BEHAVIOR_TOKENS（并击/长按/放大镜/分页/直接
  commit）。0003 以 `diff -U8` 生成，保证键表完整保留在补丁文本中，
  `verify_patch_contract` 无需 tarball 也能校验布局。
- `files/lmi-weston-sixrow/APKBUILD`：pkgrel 1→2，source + sha512sums 增补 0003。
- `config/lmi-weston-sixrow/source-lock.json`：patches 增补 0003 sha256。
- `config/lmi-weston-sixrow/build-attestation-r2.json`：随 r2 APK 新增
  （supersedes r1，状态 `SUPERSEDED_STATIC_ONLY_R1_TAP_KEYBOARD`）。
- transient 链（`stage_transient.py`、`transient-stage-lock.json`）候选 APK
  钉点 r1→r2；试用执行仍保持 NO-GO（PID-signal-race 审查未解除）。

## 构建方式（无 root 复现记录）

本会话 sudo 不可用（pmbootstrap 需 root 挂 loop/chroot），改用等价的
非特权流程，输入完全相同（同一 aarch64 apk 缓存、同一 weston tarball、
同一 abuild 密钥）：

1. `unshare -r` + `apk.static add --root <rootfs> --initdb --arch aarch64
   --allow-untrusted <cache_apk_aarch64>/*.apk`（199 包）。
2. rootfs 内放入 Alpine `qemu-aarch64`（static-pie）为
   `/usr/bin/qemu-aarch64-static`，匹配既有 binfmt 注册。
3. `unshare -r -m --fork --pid` 挂 proc/dev/tmp + 绑定 `cache_ccache_aarch64`，
   chroot 内 `abuild -F -d` 构建并签名（同一 `pmos@local-6a5fb853` 密钥）。
4. 产物复制到 `.work/pmbootstrap-sixrow/packages/edge/aarch64/`
   `lmi-weston-sixrow-clients-14.0.2-r2.apk`。

补丁另做过 host gcc `-fsyntax-only` 全量类型检查（协议头由 wayland-scanner
经 qemu 生成）。

## 未验证 / 后续

- **未做设备测试**：触控并击、长按滑选手感、350ms 阈值、放大镜遮挡、
  pixman 重绘开销均需真机验证后调参（阈值/气泡尺寸集中在常量区）。
- 下一版镜像（r144 配方，见
  `notes/lmi-d114-p2-next-version-handoff-2026-07-22.md`）需把 r2 APK 及其
  attestation 重钉进 D114 注入链；本次未动 r1 镜像链。
- 上屏路径建议先用 transient /tmp 试用（需先解除 PID race NO-GO）或随
  下一版 userdata 重建走注入链。
