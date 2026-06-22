# Repair Phase 18: v17 Normal Boot Observation

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-r4-subpartfix-20260623.img
sha256=5f35017c9b2420918ebefff872d80c3a0e13fe43aac18005d728a968b1c6316e
size=53063680
mode=fastboot boot (RAM-only, no partition writes)
```

## Hardware result

Preflight:

```text
product=lmi
unlocked=yes
battery-voltage=4387 mV
```

Bootloader accepted the image:

```text
Sending 'boot.img' (51820 KB) OKAY
Booting OKAY
```

USB gadget appeared as `18d1:d001` and was attached to WSL. The WSL-side USB
network interface was `enxfaaa03658871`, configured as `172.16.42.2/24`.

Observed network/service states:

```text
initial ping 172.16.42.1: ok
initial tcp/22: refused
initial tcp/23: refused
after reattach ping 172.16.42.1: ok
after reattach tcp/22: refused
after reattach tcp/23: open briefly
later ping 172.16.42.1: ok
later tcp/22: refused
later tcp/23: refused
```

An attempted batch telnet log collection did not return shell output and appears
to have closed the transient telnet shell before `/pmOS_init.log` could be
captured.

## Local rootfs cross-check

The local rootfs has OpenSSH installed and enabled:

```text
/etc/init.d/sshd exists
/etc/runlevels/default/sshd -> /etc/init.d/sshd
sshd_config defaults to Port 22
PasswordAuthentication yes
```

Therefore, if `switch_root` and OpenRC default services complete, tcp/22 should
eventually listen. Persistent tcp/22 refusal is evidence that the boot has not
reached a healthy default runlevel, or that userland networking/service startup
is failing before sshd binds.

## Current interpretation

v17 improved past the earlier static mount blockers enough to create a live USB
network path, but it is not yet proven to complete `switch_root`. The transient
tcp/23 window suggests the boot path still entered an initramfs debug/fallback
state at least briefly.

## Next diagnostic step

Build/boot a v18 diagnostic that keeps the v17 fixes but captures the exact
post-`mount_subpartitions()` state without relying on an interactive telnet
session:

- keep kernel `fc->source` fix;
- keep initramfs `fdisk -b 4096` subpartition-count fix;
- add deterministic logging around `find_root_partition`, `mount_root_partition`,
  `switch_root`, and OpenRC handoff;
- expose logs over the known USB network path without requiring manual shell
  timing.

