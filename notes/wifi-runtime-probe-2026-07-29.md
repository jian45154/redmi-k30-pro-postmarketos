# LMI runtime-only Wi-Fi probe attempt — BLOCKED, device not attached (2026-07-29)

Status: **BLOCKED at the reachability probe. Nothing was touched: no SSH
session was opened, no device command ran, no fastboot, no flash, no reboot,
no service or config change anywhere. Host-side actions were read-only
(`ip addr`, `ip link`, `ping`, `lsusb`, `dmesg` tail, `usbipd.exe list`).
The one SSH step planned (`uname -a`) was never reached because the transport
does not exist.**

Task: probe the device over USB RNDIS and, if reachable and permitted,
attempt runtime-only Wi-Fi bring-up via `/usr/sbin/lmi-wifi-start`
(continuation of `notes/wifi-bringup-live-2026-06-24.md`, whose v43 session
proved the full CNSS → `wlan0` path works on a clean boot).

## Governance check (done before any probe)

- `notes/bringup-active.json` is absent — safe idle state per AGENTS.md.
- `scripts/bringup_loop.py` `OPERATIONS` covers only fastboot-side actions
  (`device_reboot`, `ram_boot`, `runtime_handoff`, `partition_write`).
  Runtime service actions over an established SSH session are not
  engine-claimed operations; the June 2026 wifi notes show
  `lmi-wifi-start` runs over SSH as the accepted runtime path.
- Conclusion: a runtime-only `lmi-wifi-start` attempt (no fastboot, no
  persistent config edits, no network join) would have been permissible.
  It was not reached.

## Evidence: why the device is unreachable

All observed on the WSL2 host, 2026-07-29:

- `ip addr` / `ip link`: no `usb0` or other RNDIS interface; only
  `lo`, `eth0`–`eth3`, `loopback0` (WSL virtual NICs).
- `ping -c 2 -W 2 172.16.42.1`: 100 % packet loss.
- `/sys/bus/usb/devices/` does not exist and `lsusb` returns nothing —
  the WSL kernel has **no USB bus at all**, i.e. no usbipd attachment is
  active (not merely a detached RNDIS gadget).
- WSL `dmesg` tail: only `mini_init drop_caches` and WSL
  `CheckConnection` noise; no USB events.
- `"/mnt/c/Program Files/usbipd-win/usbipd.exe" list` (read-only):

  ```text
  Connected:
  BUSID  VID:PID    DEVICE                                       STATE
  1-4    27c6:6092  Goodix MOC Fingerprint                       Not shared
  1-6    8087:0037  Intel(R) Wireless Bluetooth(R)               Not shared

  Persisted:
  37503902-…  Remote NDIS based Internet Sharing Device
  6d9d3e3e-…  Android Bootloader Interface
  718ae266-…  Google Galaxy Nexus ADB Interface
  ```

Interpretation: the phone is **not enumerated by the Windows host at all** —
it is unplugged, powered off, or not presenting a USB gadget. The RNDIS
device exists only in usbipd's *Persisted* (previously shared) list, so once
the phone is plugged in and booted into postmarketOS, attach should succeed
without a new admin `bind`.

## Operator actions needed to unblock (interactive, Windows side)

1. Physically connect the K30 Pro over USB and let it boot postmarketOS
   (wait for the RNDIS gadget; per prior notes it enumerates as
   `0525:a4a2` / "Remote NDIS based Internet Sharing Device").
2. In Windows PowerShell:

   ```powershell
   usbipd list                       # find the BUSID of the RNDIS device
   usbipd attach --wsl --busid <BUSID>
   # only if it shows "Not shared": run once from an elevated prompt:
   #   usbipd bind --busid <BUSID>
   ```

3. Verify from WSL: `ip addr` shows `usb0` (host side 172.16.42.2/16 via
   the postmarketOS default), `ping 172.16.42.1` answers, then
   `ssh lmi@172.16.42.1 uname -a`.

## Host-side baseline comparison: D114 P2 runtime vs the v46 Wi-Fi baseline

Wi-Fi hardware bring-up already worked in June: v42 produced live `wlan0`
scans, v43 verified `wifi_rc=0` with the persisted MAC
(`notes/wifi-bringup-live-2026-06-24.md`), and v44–v46 were service-status
idempotency cleanups (`artifacts/images/pmos-lmi-v44..v46-*.manifest`).
The question is whether the currently flashed D114 P2 image still carries
that stack. Host evidence (device checks pending):

- The device is believed to run the D114 P2 r1 image chain written by the
  one r5 `deploy-once` on 2026-07-22 (outcome recorded UNKNOWN, but
  post-flash six-row terminal bring-up on 2026-07-23 indicates it booted;
  see `notes/lmi-d114-wsl-r5-unknown-outcome-2026-07-22.md` and the
  transport-parser false-negative memory).
- That image was built from a **source-lock pin of device package r142**,
  whose sources (r108–r142) are not in this workspace
  (`notes/lmi-d114-p2-next-version-handoff-2026-07-22.md`).
- The handoff note names the exact known regression vs the v46 baseline:
  the r143-era `package()` installs `lmi-wlan-on.initd` and
  `lmi-cnss-fs-ready.initd` but **omits their default-runlevel symlinks**,
  so nothing writes `ON` to `/dev/wlan` at boot and `wlan0` never appears,
  even though firmware mount / qrtr-ns / cnss-daemon are otherwise ready.
  This is a boot-trigger regression, not a hardware-path regression — and
  it is precisely what a runtime-only `lmi-wifi-start` invocation works
  around.
- The current workspace package r145 (`artifacts/wsl-pmaports/
  device-xiaomi-lmi/APKBUILD`, pinned in `config/lmi-p3/source-lock.json`
  as `device-xiaomi-lmi=1-r145`) already fixes this: it links
  `lmi-cnss-fs-ready` and `lmi-wlan-on` into the default runlevel, and its
  `lmi-wifi-start` carries all v43 fixes (ro `persist` mount,
  `WCNSS_qcom_cfg.ini` link, `wlan_mac.bin` link, qrtr-ns/cnss-daemon
  start ordering). r145 is the *next* image; flashing it needs a fresh
  owner-authorized persistent profile and is out of scope here.
- Unverifiable without the device: whether the on-device (r142-era)
  `/usr/sbin/lmi-wifi-start` matches the fixed v43+ version, and whether
  the flashed image gives user `lmi` any root path
  (`lmi-rootctl`/sudoers arrived in r143 per the handoff; r142's grants
  are unknown). Both must be read before any runtime trigger.

## Next steps once reachable (unchanged plan)

1. Read-only capture first: `iw dev`, `ip link`, `rc-status`,
   `ls /sys/kernel/cnss`, `dmesg | tail -50`, and check
   `/sys/kernel/cnss/*/crash_count` — do not trigger Wi-Fi in a stuck CNSS
   state (June note: recovery from a calibration timeout needs a clean boot).
2. Read-only diff of the on-device stack against the v46 baseline:
   `cat /usr/sbin/lmi-wifi-start` (persist mount? WCNSS/wlan_mac links?),
   `ls /etc/init.d/lmi-* /etc/runlevels/default/`, presence of
   `/usr/sbin/lmi-rootctl` + `/etc/sudoers.d/90-xiaomi-lmi-rootctl`, and
   `sudo -l` for user `lmi`. Expected finding per the handoff note:
   everything present except the `lmi-wlan-on`/`lmi-cnss-fs-ready`
   runlevel links.
3. Then trigger runtime-only via the sanctioned path (`sudo lmi-rootctl
   wifi-start --confirm <token>-xiaomi-lmi` if rootctl exists, otherwise
   whatever root path the image grants; if none, report blocked rather
   than modifying sudoers).
4. On success (`wlan0` in `iw dev`): read-only `nmcli dev wifi list` scan
   only — joining a network and any NetworkManager config change are a
   separate, later task toward SSH-over-wifi.
