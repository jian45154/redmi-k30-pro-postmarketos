# Flash Plan: Persistent pmOS rootfs (PLAN ONLY — needs ian approval)

签名：codex_ian | 2026-06-17

> NOTHING in this file has been executed. Do not run any write command until
> ian explicitly approves AND the recovery prerequisites below are confirmed.

## Goal

Get a full postmarketOS system with sshd/docker on lmi, instead of the RAM-only
`fastboot boot` (which has no rootfs -> no shell). This requires writing the
rootfs to device storage = a destructive operation.

## Device facts (from notes/fastboot-check-2026-05-28.md)

- Bootloader: unlocked. Secure: yes. `is-userspace:no` (bootloader fastboot,
  NOT fastbootd -> we do not touch the `super` dynamic partitions).
- Physical partitions: `boot` 128M, `recovery` 128M, `dtbo` 32M, `super`
  (LineageOS system lives here), `userdata` ~107G, plus persist/metadata/cache.
- Current OS: LineageOS (system in `super`, kernel in `boot`).
- Max fastboot download size ~768 MiB -> large images must be sparse/chunked
  (fastboot + pmbootstrap handle this automatically).

## What each plan touches

| Partition | Plan A (recommended) | Plan B (standalone) |
|---|---|---|
| `userdata` | OVERWRITTEN (pmOS rootfs) | OVERWRITTEN (pmOS rootfs) |
| `boot` | untouched (kernel via RAM) | OVERWRITTEN (pmOS kernel) |
| `super` (LOS system) | untouched | untouched |
| `recovery`, `dtbo`, `persist` | untouched | untouched |

`super` and `recovery` are never written -> LineageOS system + recovery survive
both plans.

## Recovery prerequisites — CONFIRM ALL before writing

1. Nothing important on the phone. `userdata` will be erased. Back up anything
   needed off the device first.
2. A known-good way back to LineageOS/MIUI is ready, one of:
   - the skkk recovery images already in `artifacts/images/` + a LineageOS ROM
     zip to sideload, OR
   - a full MIUI fastboot ROM for lmi (MiFlash) as ultimate fallback.
3. Battery > 50% (observed 4132 mV earlier — fine).
4. Bootloader stays unlocked (do NOT relock — relocking a non-stock boot can
   hard-brick).

## PLAN A — minimal blast radius (RECOMMENDED for first persistent boot)

Keeps LineageOS kernel in `boot`; only `userdata` is replaced. The pmOS kernel
is RAM-booted each time, finds the pmOS rootfs on `userdata`.

Phone in bootloader fastboot, connected:

```bash
# 1. (dry) see what pmbootstrap would flash and to which partition
pmbootstrap flasher flash_rootfs --help

# 2. write ONLY the rootfs to userdata (destructive to userdata only)
pmbootstrap flasher flash_rootfs

# 3. RAM-boot our kernel; initramfs will now find pmOS root on userdata
fastboot boot /mnt/c/Users/microstar/Documents/lmi_linx/artifacts/images/pmos-lmi-boot.img
```

Then connect from WSL (proven working tonight):

```bash
# attach USB into WSL (admin PowerShell): usbipd attach --wsl --busid 2-5
IF=enx767c52736a23      # re-check name with: ip -br link
sudo ip link set "$IF" up
sudo ip addr add 172.16.42.2/24 dev "$IF"
ping -c2 172.16.42.1
ssh lmi@172.16.42.1     # full system this time -> sshd should answer on :22
```

Restore to LineageOS after Plan A: just reboot (RAM kernel evaporates). `boot`
still holds the LineageOS kernel, so it boots LineageOS — with a wiped
`userdata` (first-time setup). System in `super` is intact. No reflash needed.

## PLAN B — standalone (only after Plan A is verified happy)

Phone boots pmOS by itself, no PC needed. Also overwrites `boot`.

```bash
pmbootstrap flasher flash_kernel      # boot     <- pmOS kernel+initramfs
pmbootstrap flasher flash_rootfs      # userdata <- pmOS rootfs
fastboot reboot
```

Restore to LineageOS after Plan B: reflash a LineageOS `boot.img`
(`fastboot flash boot <los-boot.img>`) — REQUIRES a known-good LineageOS boot
image first (the provenance of `artifacts/images/boot.img` is NOT confirmed; do
not assume it is the LineageOS boot). Then factory reset. Safer to have the
LineageOS recovery + ROM zip ready.

## Failure playbook

- Phone won't boot anything / stuck: hold power ~10 s to force reboot; enter
  fastboot (Vol- + Power). Bootloader is unlocked, so fastboot is always
  reachable — not bricked.
- pmOS boots but no shell: repeat tonight's USB-net steps; check `dmesg`/
  initramfs. If `kona-v2.1` dtb causes a missing peripheral, switch
  `deviceinfo_dtb` to `qcom/kona-v2` or `qcom/kona`, rebuild device pkg, re-flash.
- Need LineageOS back urgently: boot skkk recovery (`fastboot boot
  <recovery.img>`), sideload the LineageOS ROM zip, format data.
- Do NOT `fastboot flash` `super`, `vbmeta`, `persist`, or relock the bootloader.

## Open question to resolve before Plan B

Obtain/confirm a known-good LineageOS `boot.img` (or full ROM) for lmi so the
`boot` partition can be restored if pmOS is later removed.
