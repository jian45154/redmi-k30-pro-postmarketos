# Repair Phase 19: v18 Boottrace Build

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Purpose

v17 created a live USB network path but did not prove `switch_root` completion:
ping worked, tcp/22 stayed refused, and tcp/23 appeared only briefly. Earlier
project notes also show that probing telnet can terminate BusyBox `telnetd`, so
v18 avoids relying on an interactive telnet session.

## Artifact

```text
file=artifacts/images/pmos-lmi-boottrace-v18-20260623.img
sha256=4be1a6109262e9577f51e2414a7a54fa1cd0b5510d104ad650354cc04e627ea0
size=53063680
source=artifacts/images/pmos-lmi-normalboot-r4-subpartfix-20260623.img
source_sha256=5f35017c9b2420918ebefff872d80c3a0e13fe43aac18005d728a968b1c6316e
```

## Contents

v18 keeps the v17 behavior and adds deterministic boot tracing:

- no `pmos.debug-shell` in cmdline;
- keeps kernel `fc->source` mount fix from r4;
- keeps initramfs `fdisk -b 4096` subpartition-count fix;
- starts an HTTP server at `http://172.16.42.1:8080/debug.txt` after USB
  networking starts;
- records snapshots at:
  - after `start_unudhcpd`;
  - after `mount_subpartitions`;
  - after `wait_root_partition`;
  - before and after `mount_root_partition`;
  - before switch-root cleanup;
  - immediately before `exec switch_root`;
  - if `switch_root` returns/fails;
  - when debug-shell telnetd starts.

The report includes `/pmOS_init.log`, trace markers, network state, listening
ports, `/tmp/lmi-telnetd.err`, `/tmp/lmi-httpd.log`, process list, mounts,
partitions, `blkid`, loop state, userdata `fdisk` at 512 and 4096 byte sectors,
`/sysroot` presence, and a `dmesg` tail.

## Local verification

Unpacked boot image confirms:

```text
header_version=2
cmdline has no pmos.debug-shell
/usr/bin/lmi-boottrace exists
init_2nd.sh contains lmi_http_start and lmi_trace hooks
init_functions.sh redirects telnetd stderr to /tmp/lmi-telnetd.err
init_functions.sh still contains fdisk $_lmi_fb subpartition count fix
```

## Next hardware action

RAM-only boot v18, then fetch:

```text
http://172.16.42.1:8080/debug.txt
```

This still requires separate explicit approval immediately before boot:

```text
确认启动 v18 boottrace 验证
```

