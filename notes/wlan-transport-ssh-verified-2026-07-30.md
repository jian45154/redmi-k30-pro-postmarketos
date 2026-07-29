# SSH over WLAN verified — untethered milestone, 2026-07-30

Status: **hardware-verified. One governed `ram_rw` experiment
(`d112-wlan-autoconnect-provision-20260730`) was claimed and executed. The
only persistent writes were two configuration files on rootfs P2, listed
below. No partition write, no boot/vbmeta/super write, no runtime device
configuration change.**

Evidence: `logs/d112-wlan-autoconnect-provision-20260730.redacted.txt`,
`notes/bringup-completed/d112-wlan-autoconnect-provision-20260730.json`.
Prior context: `notes/d111-key-repair-wifi-verified-2026-07-29.md`.

## Result

`lmi` is reachable by key-only SSH **over Wi-Fi**, not just USB:

```
peer as seen by device: SSH_CONNECTION="<lan-ip> 46462 <lan-ip> 22"
client trace: Authenticated to <lan-ip> ([<lan-ip>]:22) using "publickey".
```

`wlan0` associated on WPA2-PSK (full EAPOL 1–4 exchange), completed DHCP
(DISCOVER → OFFER → REQUEST → ACK), took `<lan-ip>/24`, and installed a
default route via the AP. NetworkManager reports the connection `activated`
and the device `connected`.

## Why runtime provisioning was impossible

There is **no runtime path to root** on this image, so the Wi-Fi profile could
not be created over SSH:

- `sudo` requires a password for everything except `lmi-rootctl`, and
  `lmi-rootctl` has no network subcommand (only reboot, poweroff, rc-status,
  service, bluetooth-rfkill, adsp-boot, wifi-start, display-probe/takeover);
- polkit returns `unknown` for every `org.freedesktop.NetworkManager.*` action
  because an SSH session has no local seat, so `nmcli` fails with
  *Not authorized to control networking*;
- the `wpa_supplicant` control socket directory is empty and root-owned.

## What was provisioned offline

From the D111 debug shell, with `losetup --sector-size 4096` (see the
2026-07-29 note — the 512-byte default silently yields no subpartitions):

| Path on P2 | Mode | Purpose |
| --- | --- | --- |
| `/etc/NetworkManager/system-connections/lmi-owner.nmconnection` | `0600 root:root` | Owner AP, `key-mgmt=wpa-psk`, `autoconnect=true`, priority 100, bound to `wlan0`. Wi-Fi now joins at every boot with no interaction. |
| `/etc/polkit-1/rules.d/50-lmi-network-control.rules` | `0644 root:root` | Grants the `wheel` group `org.freedesktop.NetworkManager.*`, so future network management works from SSH sessions. |

WPA2-PSK was chosen deliberately over WPA3-SAE: the AP advertises both, and
SAE on this downstream QCA6390 stack is unproven. The association succeeded
first time.

## Acceptance suite over WLAN, and the gap it exposed

`scripts/74_verify_lmi_ssh_full.sh` against `<lan-ip>:22`:

- **PASS** remote-command, PTY, SFTP metadata, SCP-over-SFTP download
- **FAIL** client-originated local forwarding

Root cause is device-side policy, not transport: this image's
`/etc/ssh/sshd_config` sets `AllowTcpForwarding no`, and carries no
`PermitRootLogin`, `PasswordAuthentication`, or `AllowUsers` directive — it is
close to stock defaults. The r145 full-SSH contract
(`notes/ssh-full-function-contract-2026-07-24.md`) requires local, remote,
dynamic, and Unix-socket forwarding, so **the r142-era image does not
implement the contract it is supposed to ship**. The public image must carry
the hardened r145 `sshd_config`; tracked in
`docs/release/v1-firmware-free-release-plan-2026-07-29.md`.

## Host-side bug found and fixed

`scripts/74_verify_lmi_ssh_full.sh` rejected a genuine authentication because
OpenSSH terminates `-E` log lines with CRLF while the matcher required the
line to *end* with `using "publickey".`. The helper already stripped `\r` for
its PTY check but not here. Fixed, and `tests/lmi_p1/test_ssh_full_helper.py`
now emits CRLF so the on-hardware format is exercised.

This is why the suite had never passed on real hardware: its fixture was more
forgiving than reality.

## Remaining for v1

The workstation goal (untethered key-only SSH over Wi-Fi) is **met on a
RAM-booted OS**. Still open:

1. **Persistent boot** — the phone still needs `fastboot boot` because the
   flashed boot image is mispaired and its initramfs lacks `kpartx`.
2. **Forwarding** — ship the r145 `sshd_config` so the acceptance suite passes
   5/5.
3. **Publication** — the release plan's gates, including key injection at
   install time rather than a keyless image.
