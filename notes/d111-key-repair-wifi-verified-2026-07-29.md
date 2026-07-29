# D111 key repair and first verified Wi-Fi bring-up — 2026-07-29

Status: **hardware-verified over three governed experiments. One
`fastboot reboot` (volatile) and two `fastboot boot` RAM boots (ram_rw) were
claimed and executed. The only persistent write was
`/home/lmi/.ssh/authorized_keys` on the P2 rootfs, performed by the owner from
the D111 debug shell exactly as that image's manifest attests. No partition
write, no boot/vbmeta/super write, no network was joined.**

Ledger: `notes/bringup-completed/{d114-p2-r1-reboot-wifi-probe,
d110-ramboot-wifi-validation,d111-key-repair-wifi-validation}-20260729.json`.
Raw evidence: `logs/d114-boot-pairing-mismatch-20260729.txt`,
`logs/d110-ramboot-ssh-auth-denied-20260729.txt`,
`logs/d111-key-repair-wifi-validation-20260729.txt`.

## Findings

### 1. Persistent boot fails for two independent reasons

The flashed `boot` partition is the **v46** image (cmdline
`pmos_root_uuid=df32eed6…`, matching
`artifacts/images/pmos-lmi-v46-daemon-status-idempotent-full-20260624.manifest`),
but `userdata` holds the **D114 assembled layout** (inner GPT
`45721c80…`, root `f8eb7c4b…`). The UUID it searches for does not exist here.
Additionally its initramfs has **no `kpartx`**, so subpartition mapping cannot
succeed regardless of pairing. See `notes/d114-boot-pairing-mismatch-2026-07-29.md`.

### 2. The image had no SSH key at all

`sanitization.authorized_keys = "removed"` in the r1 injection attestation is
literal: `/home/lmi/.ssh` did not exist on the rootfs (`NO_SSH_DIR_YET`).
Remote access was impossible by construction — not a policy or firewall issue.
Repaired with the attested owner line (sha256 `b86935a2…`, 81 bytes, uid/gid
`10000`, dir `0700`, file `0600`).

### 3. Subpartition access requires 4096-byte sectors

`losetup` defaults to 512-byte sectors and silently produces **no** `loopNpN`
nodes on this image. `--sector-size 4096` (matching
`deviceinfo_rootfs_image_sector_size` and the assembly attestation's
`logical_sector_size`) parses the inner GPT correctly. Any host or initramfs
tooling that omits this will report a corrupt or empty image.

### 4. Wi-Fi works at boot — correcting a prior claim

`notes/lmi-d114-p2-next-version-handoff-2026-07-22.md` states that
`lmi-wlan-on.initd` and `lmi-cnss-fs-ready.initd` are installed but not linked
into the default runlevel. **On this rootfs they are linked and started.**
Observed after `pmos_continue_boot`, with no manual `lmi-wifi-start`:

- `iw dev`: `wlan0`, `p2p0`, `wifi-aware0` on `phy#0`;
- started: `lmi-wlan-on`, `lmi-cnss-fs-ready`, `lmi-cnss-daemon`,
  `lmi-qrtr-ns`, `rmtfs`, `tqftpserv`, `wpa_supplicant`, `networkmanager`;
- scan: `nmcli dev wifi list` returned 11+ SSIDs; kernel log
  `scan id 40961 type COMPLETED reason COMPLETED scan found 23 bss`.

This matches the v43–v46 baseline. Wi-Fi hardware bring-up is **not** a
blocker for the workstation goal.

### 5. The running image is already close to owner-mode

`sudo -n -l` reports `lmi` may run `(ALL) ALL`, plus the
`(root) NOPASSWD: /usr/sbin/lmi-rootctl` rule, and `lmi` is in `wheel`.
The rootfs `sshd_config` sets **no** `PermitRootLogin`,
`PasswordAuthentication`, or `AllowUsers` directive — it runs on OpenSSH
defaults, not the hardened r145 contract. Any public image must ship the
hardened profile; see `notes/ssh-owner-mode-addendum-2026-07-29.md`.

## Consequences for the r145 clean rebuild

1. Pair the boot image with the assembled-userdata layout, or stop shipping a
   mismatched pair.
2. Ship `kpartx` in the initramfs.
3. Provision `authorized_keys` at install time (the release plan's
   key-injection gap) instead of shipping a keyless image.
4. Ship the hardened `sshd_config` explicitly rather than relying on defaults.

Tracked in `docs/release/v1-firmware-free-release-plan-2026-07-29.md`.

## Still unproven

**SSH over WLAN transport.** Every session so far has authenticated over
USB/RNDIS. The Wi-Fi link is up and scanning but no network has been joined;
joining requires owner-supplied credentials. This is the last open v1 gate.
