# Repair Phase 25: v22 Normal Boot Reaches SSH

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Artifact tested

```text
file=artifacts/images/pmos-lmi-normalboot-v22-loopdevfix-20260623.img
sha256=cf848d79b4c3ab60d0d58cee99abfd1b5ee9b73c5b0a52be5d6df3bac1518e89
mode=fastboot boot (RAM-only, no partition writes)
```

## Probe log

```text
logs/repair-normalboot-v22-2026-06-23.txt
```

## Result

v22 booted far enough to expose the postmarketOS USB network and OpenSSH.

Observed from WSL over USB network:

```text
172.16.42.2/24 configured on host USB interface
ping 172.16.42.1: 3/3 received
tcp/22: open
tcp/23: refused
tcp/8080: refused
SSH banner: SSH-2.0-OpenSSH_10.3
```

## Interpretation

This confirms the next milestone after v21:

```text
rootfs discovery -> rootfs mount -> switch_root/userspace -> OpenSSH
```

Port 23 and 8080 being refused is expected for this artifact because v22 is a
normal boot candidate without `pmos.debug-shell` or the HTTP diagnostic server.

## Remaining work

The port is not complete. The next checks are login credentials/key access and
basic subsystem validation after SSH login:

- OpenRC service state;
- kernel/module state;
- storage mounts;
- display/input;
- Wi-Fi, GPU, audio, charging, suspend, sensors.
