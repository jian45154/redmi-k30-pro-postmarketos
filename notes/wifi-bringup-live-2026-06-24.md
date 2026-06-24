# Xiaomi lmi Wi-Fi bring-up live notes - 2026-06-24

## Current running state

- Device reachable over postmarketOS USB RNDIS at `172.16.42.1`.
- SSH works on port 22 as user `lmi`.
- Kernel: `4.19.325-cip128-st12-perf #9-postmarketOS`.
- `/dev/wlan` exists and is writable by root.
- `/sys/kernel/cnss` points to `b0000000.qcom,cnss-qca6390`.
- `rmtfs`, `tqftpserv`, `wpa_supplicant`, `networkmanager`, and `sshd` are started.
- No wireless interface is exposed: `iw dev` is empty and `ip link` only shows `usb0` plus non-WLAN dummy/tunnel devices.

## Tested runtime path

`/usr/sbin/lmi-wifi-start` was run over SSH. It:

- starts or confirms `lmi-firmware-mount`, `rmtfs`, and `tqftpserv`;
- links QCA6390 firmware from `/mnt/vendor/firmware_mnt/image/qca6390`;
- writes `1` to `/sys/kernel/cnss/fs_ready`;
- writes `ON` to `/dev/wlan`;
- waits for the WLAN interface.

Observed board data attempts in `/var/log/lmi-wifi-start.log`:

- `bd_j11.elf`
- `bd_j11gl.elf`
- `bd_j11_b.elf`
- `bd_j11in.elf`
- `bd_j1gl.elf`

The latest manual attempt tried to pass `LMI_WLAN_BOARDDATA=bd_j1in.elf`, but the packaged script sourced `/etc/conf.d/lmi-wlan-firmware` after the environment defaults, so the conf value still won. The local package script has been fixed to source conf first, then allow environment overrides.

## Failure signature

CNSS/MHI bring-up reaches:

```text
cnss: Setting MHI state: POWER_ON(2)
cnss: MHI status cb is called with reason MISSION_MODE(6)
wlan: Loading driver v5.2.022.12B
cnss: Start to wait for calibration to complete
```

Then it fails with:

```text
cnss: fatal: Timeout waiting for FW ready indication
cnss: Timeout (80000ms) waiting for calibration to complete
cnss: Calibration timed out, force shutdown
failed to send QMI message -107
cnss: WLFW service is disconnected while sending mode off request
```

The subsystem then enters recovery:

```text
cnss: Driver recovery is triggered with reason: TIMEOUT(3)
subsys-restart: Restart sequence requested for wlan
cnss: Recovery is already in progress
```

`/sys/kernel/cnss/subsys9/state` still reports `ONLINE`, but `crash_count` is `1` and later `fs_ready` writes report:

```text
cnss: Device is already active, ignore calibration
```

Writing `1` to `/sys/kernel/cnss/shutdown` and `/sys/kernel/cnss/recovery` did not restore a clean runtime state.

## Next clean-boot test

Do not keep testing boarddata in the current stuck CNSS state. Use a clean boot or rebooted downstream session, then test one candidate at a time:

```sh
LMI_WLAN_BOARDDATA=bd_j1in.elf LMI_WLAN_POST_ON_DELAY=90 /usr/sbin/lmi-wifi-start
iw dev
dmesg | grep -Ei 'wlan|cnss|qca|mhi|wlfw|firmware|bdwlan|regdb|timeout|failed|error' | tail -220
```

Remaining plausible candidates from the mounted firmware directory include:

- `bd_j1in.elf`
- `bd_j1_b.elf`
- `bd_j1s.elf`
- `bd_j2s.elf`
- `bd_j3s.elf`
- `bd_j3sgl.elf`
- `bd_j3sin.elf`

If every boarddata candidate reaches `MISSION_MODE` but times out waiting for FW ready, shift focus from boarddata to WLFW/QMI dependencies: confirm firmware provenance, remoteproc/service-locator behavior, vendor ramdump/calibration files, and whether a missing userspace daemon or missing calibration partition path is blocking the ready indication.
## v40 qrtr-ns finding

`v40-downstream-cnss-property-shim` proved the Android property shim works:
`cnss-daemon` logs `ro.baseband : [mdm]`, but a clean Wi-Fi trigger still timed
out waiting for FW ready because no QRTR nameservice was running.

Starting a static upstream `qrtr-ns` binary manually after the timeout made
`qrtr-lookup` show `69 1 1 7 1 ATH10k WLAN firmware service`. The kernel then
logged `QMI WLFW service connected`, memory request/ready indications, target
capability, BDF downloads for `qca6390/regdb_j11.bin` and `qca6390/bd_j11.elf`,
`m3.bin`, `FW initialization done`, and `FW_READY`.

Conclusion for v41: stop changing boarddata until this is tested from a clean
boot. Package and start `qrtr-ns` before `cnss-daemon` and before writing
`fs_ready`/`ON` to CNSS.

## v41 clean boot result

`v41-downstream-qrtr-ns-cnss-property` proved the clean boot path:

- `lmi-qrtr-ns` and stock `/vendor/bin/cnss-daemon` were running before Wi-Fi
  trigger.
- `qrtr-lookup` listed modem/RFS/TFTP services before WLAN and later listed
  `69 1 1 7 1 ATH10k WLAN firmware service`.
- CNSS reached `QMI WLFW service connected`, downloaded
  `qca6390/regdb_j11.bin`, `qca6390/bd_j11.elf`, and `m3.bin`, posted
  `FW_READY`, completed cold boot calibration, then registered the host driver.
- The host driver then requested `wlan/qca_cld/WCNSS_qcom_cfg.ini`; this file
  exists in stock vendor at
  `/mnt/android-vendor/firmware/wlan/qca_cld/WCNSS_qcom_cfg.ini`, but v41 did
  not link it into `/lib/firmware`.
- After the 60 second firmware fallback timeout, CNSS logged
  `Failed to probe host driver, err = -1` and no `wlan0` appeared.

Conclusion for v42: link vendor `WCNSS_qcom_cfg.ini` into
`/lib/firmware/wlan/qca_cld/` before writing `ON` to `/dev/wlan`.

## v42 live WLAN success

`v42-downstream-wlan-cfg-qrtr` fixed the missing
`WCNSS_qcom_cfg.ini` path. On a clean v42 boot, CNSS reached host-driver init,
sent the WLAN config message, received `FW ready event received`, and initialized
the QCA6390 data path.

The next firmware request was `wlan/qca_cld/wlan_mac.bin`. Stock vendor has this
as `/mnt/android-vendor/firmware/wlan/qca_cld/wlan_mac.bin`, a symlink to
`/mnt/vendor/persist/wlan_mac.bin`. The `persist` partition was not mounted by
v42, so the request fell back and timed out after 60 seconds. The driver then
used a default MAC and still created:

- `wlan0` managed interface
- `p2p0`
- `wifi-aware0`

`iw dev wlan0 scan` succeeded and reported nearby SSIDs. Conclusion for v43:
mount `persist` read-only at `/mnt/vendor/persist` and link `wlan_mac.bin`
before writing `ON` to `/dev/wlan`, so the interface appears without the
fallback timeout and uses the device's stored MAC.

## v43 verified

`v43-downstream-wlan-mac-persist` was written to `userdata` and temporarily
booted with `fastboot boot`. It preserved the safety boundary: no `boot`,
`vbmeta`, or `super` write.

Result:

- `lmi-wifi-start` returned `wifi_rc=0`.
- `wlan0`, `p2p0`, and `wifi-aware0` appeared under `iw dev`.
- CNSS stayed `ONLINE` with `crash_count=0`.
- The driver log showed `hdd_initialize_mac_address: ... using MAC address from
  wlan_mac.bin`.
- Scan logs completed repeatedly and found BSS entries.

The remaining rough edges are service-status cosmetics (`lmi-qrtr-ns` and
`lmi-cnss-daemon` show `crashed` in OpenRC while their processes remain alive)
and policy/userland cleanup for NetworkManager MAC behavior. The hardware
bring-up path is now working.
