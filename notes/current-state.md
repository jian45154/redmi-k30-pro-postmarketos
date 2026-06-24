# Current State

> Current project organization is tracked in `docs/tracks/README.md`.
> This file preserves earlier state snapshots and should not be treated as the
> sole current handoff after downstream `D-v43`/`D-v46` and mainline `M-r7`.

## Update: 2026-06-23

- v27 persistent boot is installed and verified.
- `userdata` contains the working postmarketOS image. Rootfs discovery and
  mount are working: `/dev/loop0p2` mounts as `/`, and `/dev/loop0p1` mounts as
  `/boot`.
- USB networking works on Windows as RNDIS (`0525:a4a2 POSTMARKETOS`); SSH is
  reachable at `172.16.42.1:22`.
- Display kernel bring-up is present (`/dev/dri/card0`, DSI panel connected,
  Adreno650v3), but userspace has not taken over the panel, so the screen still
  shows the Redmi logo.
- Audio/mic, Wi-Fi, and Bluetooth are the next main blockers: ALSA exposes no
  soundcard, Wi-Fi exposes no wireless interface, and Bluetooth is rfkill
  soft-blocked.
- Raw logs remain local-only. Use `logs/*.redacted.txt` for published evidence.

签名：codex_ian | 2026-05-28 12:39:41 +10:00 Australia/Sydney

## What Was Extracted

From WSL:

- `/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream/device-xiaomi-lmi`
- `/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream/linux-xiaomi-lmi`
- `/home/microstar/.config/pmbootstrap_v3.cfg`
- `/home/microstar/.local/var/pmbootstrap/workdir.cfg`
- `/home/microstar/boot.img`

From Windows downloads:

- `C:\Users\microstar\Downloads\[REC_BOOT]3.7.1_12-RedmiK30Pro-POCOF2Pro_v9.0_A15-lmi-skkk.img`
- `C:\Users\microstar\Downloads\[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk_ef1ce3b4.zip`

## WSL2 Check

- WSL default version: 2.
- Default distro: `Ubuntu-22.04`.
- Kernel observed: `6.6.87.2-microsoft-standard-WSL2`.
- Ubuntu observed: `22.04.5 LTS`.
- Disk available under WSL root: about 939 GB free.
- Memory visible to WSL: about 15 GiB RAM, 4 GiB swap.
- pmbootstrap observed: `3.10.1`.

Tools found in WSL:

- `git`
- `python3`
- `pip3`
- `gcc`
- `make`
- `pmbootstrap`

Tools not found in the WSL `PATH` during the check:

- `clang`
- `dtc`
- `mkbootimg`
- `fastboot`
- `adb`
- `repo`
- `unzip`

Windows tools found:

- `adb.exe`: `C:\Program Files\platform-tools\adb.exe`, version `37.0.0-14910828`
- `fastboot.exe`: `C:\Program Files\platform-tools\fastboot.exe`, version `37.0.0-14910828`

## Current Risk Assessment

The project has enough material to start an lmi postmarketOS/downstream port
audit, but not enough to flash a Linux build safely.

Main gaps:

- Need to identify the intended lmi kernel source repository.
- Need to identify the exact kernel commit.
- Need to locate or generate `config-xiaomi-lmi.aarch64`.
- Need to confirm whether `artifacts/images/boot.img` is a bootable Linux image,
  Android boot image, or previous pmbootstrap output.
- Need to collect live phone data through USB.

## Next Confirmation With ian

When the phone is connected, run:

```bat
scripts\03_check_phone_usb.bat
```

Then confirm:

- Whether the phone is in Android/LineageOS mode or fastboot mode.
- Whether the phone appears under `adb devices` or `fastboot devices`.
- Whether `logs\phone-adb.txt` and/or `logs\phone-fastboot.txt` were produced.
- Whether `artifacts/images/boot.img` came from pmbootstrap or from another source.
