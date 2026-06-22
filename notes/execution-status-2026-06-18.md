# Execution Status
签名：codex_ian | 2026-06-18 02:00:00 +10:00 Australia/Sydney

## Completed

- Connected the phone in bootloader fastboot mode and confirmed:
  - `product: lmi`
  - `unlocked: yes`
  - battery voltage around `4424 mV`
- Flashed the postmarketOS rootfs to `userdata` with:
  - `pmbootstrap flasher flash_rootfs`
- RAM-booted the postmarketOS kernel without flashing `boot`:
  - `fastboot boot artifacts/images/pmos-lmi-boot.img`
- Verified USB networking from WSL through usbipd:
  - `172.16.42.2/24` on the host side
  - `ping 172.16.42.1` works with ~4-6 ms latency
- Built and saved a debug RAM boot image:
  - `artifacts/images/pmos-lmi-debug-boot.img`

## Findings

- `ssh lmi@172.16.42.1:22` is still refused after the rootfs flash and RAM boot.
- `telnet 172.16.42.1:23` was intermittently reachable, which points to the initramfs debug path rather than a stable full-userland shell.
- The debug boot image includes `pmos.debug-shell`, but the current session did not capture a stable interactive shell long enough to read `/pmOS_init.log`.
- `debug-shell` is not a standalone package name in pmaports; the correct hook package is `postmarketos-mkinitfs-hook-debug-shell`.

## Current State

- `userdata` now contains the pmOS rootfs.
- `boot`, `super`, `recovery`, and `dtbo` were not flashed.
- The repo now has local changes for:
  - premerged lmi DTB support
  - Wi-Fi/remoteproc-related package dependencies
  - WSL helper script path fixes

## Next Step

1. Re-enter fastboot.
2. RAM-boot `artifacts/images/pmos-lmi-debug-boot.img`.
3. Attach the pmOS USB gadget back into WSL.
4. Open the initramfs telnet shell first, then read `/pmOS_init.log`.

## Safety Status

No permanent boot partition write was performed in this session.
