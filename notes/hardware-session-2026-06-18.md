# Hardware Debug Session
签名：claude-sonnet-4-6 | 2026-06-18

## 手机当前状态

- **pmOS 第三次 RAM boot 运行中**（background fastboot 任务送出）
- `ping 172.16.42.1` ✓ 稳定通，约 3-5ms
- DHCP 分配 `172.16.42.2` → 确认是 pmOS unudhcpd
- USB interface: `enx26b35bf1ef4e`（已配置 172.16.42.2/24）
- Port 22 closed，Port 23 closed
- 手机未关机，可能仍在 debug_shell while 循环（waiting for continue_boot）

## 本次发现的关键问题

### busybox telnetd 单连接退出
`(echo >/dev/tcp/172.16.42.1/23)` 这个探测本身会建立完整 TCP 连接，
busybox telnetd 处理该连接（运行 pmos_getty = /bin/sh -l），
shell 因 stdin 为空立刻 EOF 退出，telnetd 处理完本次连接后也退出。

**结论：port 23 探测 = 杀死 telnetd。之后 port 23 不再开放。**

### 一次成功连接（短暂）
Python 脚本曾成功连上 port 23（`Connected!`），但：
- 等待 2 秒后发 `cat /pmOS_init.log` → 返回空
- 等待 5 秒后发 `mount` → BrokenPipeError
- 原因：shell 在约 9 秒后退出（无输入时 /bin/sh -l 可能因无 TTY 退出）

### /pmOS_init.log 为空
连接时 `/pmOS_init.log` 内容为空。可能原因：
- init 阶段太早，日志还未写入
- 或者 setup_log 写入路径在 debug_shell 之后

## 下一次硬件会话的正确操作

### 方案 A：让用户手动 telnet（推荐）
1. `fastboot boot artifacts/images/pmos-lmi-debug-boot.img`
2. 等 USB 切换后 `usbipd attach --wsl --busid <busid>`
3. `sudo ip link set enx* up && sudo ip addr add 172.16.42.2/24 dev enx*`
4. **用户自己在 Windows 终端运行：** `telnet 172.16.42.1 23`
5. 在 telnet shell 里执行：
   ```sh
   cat /pmOS_init.log
   mount
   blkid
   ls /sysroot
   dmesg | tail -50
   # 然后：
   pmos_continue_boot
   ```

### 方案 B：Python 一次性发命令（不等待）
连接后立刻发所有命令（不要 sleep 2），强制在 telnetd 退出前读取输出：
```python
# 连上后 0.5s 内发所有命令，30s 内读完
```

### 方案 C：不走 debug_shell，改走 SSH
如果 pmos_continue_boot 能被触发（手动 telnet），switch_root 后 sshd 应该启动。
可以在 telnet 里：
```sh
pmos_continue_boot
# 然后等 10 秒
ssh lmi@172.16.42.1
```

## initramfs 已确认正常
- `telnetd` 二进制存在于 initramfs ✓
- `pmos.debug-shell` 触发 debug_shell() in init_2nd.sh:36 ✓
- `find_root_partition` 使用 label `pmOS_root` 查找 ✓
- `wait_root_partition` 30s 超时 → `fail_halt_boot` → 重启 debug_shell

## SSH 仍未通的根因（未确认，待 telnet 诊断）
- 可能 A：rootfs 挂载失败（pmOS_root label 找不到）
- 可能 B：switch_root 成功但 sshd 未启动（日志需确认）
- nftables `50_sshd.nft` 规则已检查：port 22 accept，不是防火墙问题

## 手机当前可用恢复路径
- `fastboot boot <image>` — 可用（手机在 pmOS 循环，迟早自动重启进 fastboot 或 LineageOS）
- skkk recovery 镜像在 `artifacts/images/` — 可用
- MiFlash 线刷 — 备用
