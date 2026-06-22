# Hardware Debug Log - 2026-06-21

Operator: Lucien Auregin (ian)

## Scope

RAM-only boot and read-only diagnostics on a Redmi K30 Pro (`lmi`). No
partition was flashed, erased, formatted, or otherwise written in this session.
Device serial identifiers are omitted.

## Preflight

```text
fastboot product: lmi
bootloader unlocked: yes
battery voltage: 4410 mV
fastboot mode: bootloader (is-userspace: no)
current-slot: variable not supported
slot-count: variable not supported
```

Boot image:

```text
path: artifacts/images/pmos-lmi-debug-boot.img
sha256: BA0CD8EE2B25638C04310E8DC85BE6D5F87BE57514FBF7617CA38D7B98F9CFD2
Android boot header: version 2
page size: 4096
kernel size: 43231256 bytes
ramdisk size: 9308603 bytes
DTB size: 874418 bytes
kernel cmdline includes: pmos.debug-shell
```

## RAM Boot

Approved command:

```text
fastboot boot artifacts/images/pmos-lmi-debug-boot.img
```

Result:

```text
Sending 'boot.img' (52172 KB)  OKAY [1.114s]
Booting                       OKAY [0.095s]
Finished. Total time: 1.230s
```

The device re-enumerated as USB `18d1:d001`. It was attached to WSL with
`usbipd`, where it appeared as CDC-NCM interface `enx8abd3c058ee2`.

## Network

The host interface was configured as `172.16.42.2/24`. The phone remained
reachable at `172.16.42.1`.

Initial ping:

```text
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max/mdev = 3.324/10.212/28.909/10.807 ms
```

Follow-up ping after the debug-shell attempt:

```text
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max/mdev = 2.785/3.043/3.444/0.287 ms
```

## Debug Shell And SSH

A single TCP connection was made directly to the initramfs debug shell on port
23. The client sent the diagnostic command batch immediately after connecting,
without a prior port probe. The peer reset the connection before returning any
command output:

```text
ConnectionResetError: [Errno 104] Connection reset by peer
```

No second connection to port 23 was attempted because the current BusyBox
`telnetd` path may terminate after handling one connection.

After 20 seconds, the device still answered ping, but SSH was unavailable:

```text
nc: connect to 172.16.42.1 port 22 (tcp) failed: Connection refused
```

## Result

- Bootloader accepted the RAM image: pass.
- Kernel/initramfs USB gadget enumeration: pass.
- CDC-NCM networking: pass.
- Stable initramfs debug shell: fail; connection reset by peer.
- Rootfs discovery and mount: not observable without a shell.
- `switch_root`: not observable without a shell.
- SSH: fail; connection refused.
- Display, Wi-Fi, audio, modem, charging, suspend, sensors, and input: not
  tested because no shell was available.

## Suggested Next Diagnostic

Repeat the RAM-only boot and connect with a real telnet client attached to a
pseudo-terminal, rather than a raw socket client. Capture `/pmOS_init.log`,
block devices, mounts, and `dmesg` before running `pmos_continue_boot`.
