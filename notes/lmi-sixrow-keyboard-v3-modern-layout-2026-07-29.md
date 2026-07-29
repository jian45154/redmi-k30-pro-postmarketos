# 六行键盘 v3：现代软键盘布局修正（2026-07-29）

状态：**主机侧迭代（r3 → r4），不做任何设备操作。**
本次仅改 `lmi-weston-sixrow-clients`（pkgrel 3→4），不改 D114 r3 镜像链的
任何钉点（`inject_rootfs_candidate.sh` 仍锁 r3 APK 与 r3 attestation）。

## 需求 → 实现映射

用户对 r3 真机键盘提出 4 项布局问题，全部落在重新生成的
`files/lmi-weston-sixrow/0003-sixrow-paged-touch.patch`（仍仅改
`clients/keyboard.c`，键表数据；无行为代码改动）：

1. **Shift 移到左侧**：第 4 行 `Tab(2) Ctrl(2) Shift(3) Enter(4)` →
   `Shift(3) Tab(2) Ctrl(2) Enter(4)`，Shift 位于行首，符合现代软键盘
   习惯；并击/one-shot 行为不变。
2. **`.` `/` `-` `:` 常驻两页**：底行（两页共享 fixed 行）
   `ABC/#&(2) Space(9)` → `ABC/#&(2) /(1) Space(5) :(1) -(1) .(1)`。
   路径与冒号字符在字母页、符号页均一击可达（打 `192.168.1.1`、
   `scp user@host:path` 不再翻页）。静态合同的 fixed 行两页一致性检查
   自动保证"always available"。
3. **`\` 与 `|` 同位**：符号页第 2 行末尾改为 `\ |` 相邻，且
   shift+`\` = `|`（物理键盘同键习惯）；`` ` `` 移至第 3 行原 `\` 位，
   shift+`` ` `` = `~`。
4. **`;` 与 `:` 同键**：r3 已有 shift+`;` = `:`（v2 即存在），但键帽
   不显示且 `:` 无一击键位，不可发现。v3 将 `:` 纳入常驻底行（见第 2
   条），shift 映射保留。

顺带补齐物理键盘肌肉记忆 shift 配对（符号页）：
`1-0 → ! @ # $ % ^ & * ( )`、`[→{`、`]→}`、`=→+`。

已知限制（本轮不做，记录备查）：`<` `>` `"` 仍无一击键位（行宽 11 列
已满），可用 shift+`,` / shift+`.` / shift+`'`（`.` 常驻后 shift+`.` = `>`
两页可用）；one-shot Shift（单点 Shift 再点目标键）无需并击。

## 布局（v3）

```
字母页                                符号页
Esc ← ↑ ↓ → Hom End PgU PgD Bksp──    （同左，fixed）
q w e r t y u i o p /                 1 2 3 4 5 6 7 8 9 0 _
a s d f g h j k l ; -                 ~ ! @ # $ % ^ & * \ |
z x c v b n m ' , .──                 ( ) [ ] { } ` = + && ||
Shift── Tab─ Ctrl─ Enter───           （同左，fixed）
ABC/#& / Space──── : - .              （同左，fixed）
```

## 合同与锁链更新

- `scripts/lmi_weston_sixrow/verify.py`：FIXED_MODIFIER_ROW /
  FIXED_BOTTOM_ROW / EXPECTED_SYMBOL_ROWS 更新；新增
  EXPECTED_SYMBOL_SHIFTED（符号页 shift 配对校验）；
  SYMBOL_PAGE_REQUIRED 增补 `/ : - .`；attestation 引用推进
  r3→r4（supersedes 状态
  `SUPERSEDED_R3_CENTER_SHIFT_NO_PERSISTENT_PATH_KEYS`）。
- `files/lmi-weston-sixrow/0003-sixrow-paged-touch.patch`：以 base
  （0001+0002 后）→ v3 树 `diff -U8` 重新生成，键表完整保留在补丁
  文本中；干净树 0001→0004 全部 `--fuzz=0` 应用通过。
- `files/lmi-weston-sixrow/APKBUILD`：pkgrel 3→4，0003 sha512 更新。
- `config/lmi-weston-sixrow/source-lock.json`：0003 sha256 更新。
- `config/lmi-weston-sixrow/build-attestation-r4.json`：随 r4 APK 新增；
  r1–r3 attestation 原样保留（历史钉点不动）。

## 构建方式

与 r3 相同的离线无特权流程（`.work/kbd-v3/build-r4.sh`）：
`apk.static` 从既有 pmbootstrap 缓存铺 aarch64 构建根，
`unshare -r` + `proot -q qemu-aarch64` 翻译子进程，`abuild -F -d`
构建并以 canonical P2 密钥 `pmos@local-6a5d38f2` 签名；
`SOURCE_DATE_EPOCH=1785283200`，双跑对比字节一致性。

## 未验证 / 后续

- **未做设备测试**：Shift 左移后的并击手感、底行 5 格 Space 的误触率
  需真机验证。
- 下一版镜像需把 r4 APK 及其 attestation 重钉进 D114 注入链
  （参考 r3 的重钉顺序）；本次未动 r3 镜像链。
