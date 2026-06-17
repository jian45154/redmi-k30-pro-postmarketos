# Milestone: Bootable Image Built

签名：codex_ian | 2026-06-17 22:12

## Result

`pmbootstrap install` + `pmbootstrap export` succeeded. A complete postmarketOS
image set for `xiaomi-lmi` now exists under `/tmp/postmarketOS-export/`:

- `boot.img` — Fastboot-compatible (bootimg header v2, kernel + initramfs).
- `xiaomi-lmi.img`, `xiaomi-lmi-boot.img`, `xiaomi-lmi-root.img` — partition images.
- `dtbo.img`, `pmos-xiaomi-lmi.zip`, `lk2nd.img`, `vmlinuz`, `initramfs`, `dtbs/`.

UI: `shelli`. Extra packages baked in: openssh-server, docker, vim, htop, iw,
wpa_supplicant. User: `lmi`. Encryption: none (--no-fde is now the default).

## DTB Resolution

The downstream qcom tree builds kona base DTBs + per-device dtbo overlays. Key
facts established this session:

- `make dtbs` produces `vendor/qcom/{kona,kona-v2,kona-v2.1}.dtb` and
  `lmi-sm8250-overlay.dtbo` (confirmed via build probe).
- `make dtbs_install` does NOT collect this overlay tree — `package()` now
  installs the blobs by hand into `/boot/dtbs/qcom/`.
- bootimg header v2 allows only ONE dtb, so `deviceinfo_dtb="qcom/kona-v2.1"`
  (best guess for a 2020 SD865). All three base DTBs are still shipped in the
  kernel apk, so switching revisions needs only a deviceinfo edit + device-pkg
  rebuild, NOT a kernel rebuild.
- The lmi bootloader is expected to merge the device's existing dtbo partition
  overlay onto whichever base DTB the boot image carries.

## Open Question (verify at boot test)

If `fastboot boot` finds no matching DTB / no USB comes up, try
`deviceinfo_dtb="qcom/kona-v2"` then `"qcom/kona"`. Cheap to switch.

## Next Step — HUMAN GATE

The next action is a TEMPORARY, RAM-only `fastboot boot boot.img`. It writes
nothing to the phone (no flash/erase/format). Per PROJECT_LANGGRAPH it still
requires ian's explicit approval before connecting the phone and booting.

Success criterion for the server milestone: after `fastboot boot`, a USB network
interface appears on the PC and we can reach a shell (ssh/telnet) over USB.

## Boot Test Result — 2026-06-17 ~22:18 (ian approved)

Temporary RAM boot only: `fastboot boot pmos-lmi-boot.img` (no partition writes).

- `fastboot boot` returned OKAY; the phone left fastboot and ran our kernel.
- A USB gadget enumerated on the host as `USB\VID_18D1&PID_D001\POSTMARKETOS`
  (Windows labelled it "Google Galaxy Nexus ADB Interface"). Stable for minutes.
- **=> The lmi postmarketOS kernel + image BOOTS on real hardware.** The
  `qcom/kona-v2.1` base dtb matched (bootloader accepted, kernel ran, USB up).
- Phone screen stays black — expected (no display/panel bring-up for a headless
  server). Not a failure signal on its own.

### Open: host-side USB networking (Windows)

No RNDIS/CDC network adapter appeared on Windows and `ping 172.16.42.1` fails —
Windows bound only the ADB-class interface, not a network interface. The kernel
side is fine; this is the well-known Windows + pmOS RNDIS/CDC friction.

Recommended path to a shell: install `usbipd-win`, `usbipd attach` the
`18d1:d001` device into WSL, then use the natively-supported RNDIS/CDC `usb0`
(172.16.42.x) to `ssh lmi@172.16.42.1` (or telnet for the initramfs shell).
usbipd is NOT currently installed.

The boot.img copied to `artifacts/images/pmos-lmi-boot.img` for re-testing.

### Connectivity confirmed via usbipd → WSL

Installed `usbipd-win`, `usbipd attach --wsl --busid 2-5`. In WSL the pmOS gadget
came up as a **CDC-NCM** netdev (`enx767c52736a23`, was `usb0`). After
`ip addr add 172.16.42.2/24` + link up:

- `ping 172.16.42.1` → stable ~3 ms, 0% loss. **USB networking fully works.**
- `ssh :22` refused and `telnet :23` opens then immediately closes; a port scan
  (22/23/2222/2323/8022/...) shows nothing listening.
- Reason: a RAM-only `fastboot boot` has **no flashed rootfs**, so the initramfs
  can't mount root and this pmOS version does not expose a network shell in that
  state. Kernel + USB are proven; the missing shell is purely "no rootfs".

### To get a real server (next milestone — needs approval + recovery plan)

Flash the pmOS rootfs to the device so it boots a full system with sshd/docker.
Options, smallest-blast-radius first:
- `pmbootstrap flasher flash_kernel` + `flash_rootfs` (writes boot + userdata),
  or `fastboot flash` the exported partition images.
- MUST first confirm a recovery/rollback path (the skkk recovery images in
  `artifacts/images/` + a known-good MIUI/fastboot restore) before writing.
- DTB note: `kona-v2.1` worked for boot; keep unless a peripheral needs another.

## Safety Status

Only `fastboot boot` (RAM, temporary, approved by ian) has touched the phone.
No `fastboot flash/erase/format` and no `pmbootstrap flasher` has been run. The
phone can be returned to MIUI by holding power ~10s.
