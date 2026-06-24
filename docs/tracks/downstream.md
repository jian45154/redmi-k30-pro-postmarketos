# Downstream Track (`D-vNN`)

## Identity

- Canonical version label: `D-vNN`.
- Legacy file label: `vNN` or `downstream-vNN`.
- Kernel: LineageOS downstream Android kernel
  `4.19.325-cip128-st12-perf`.
- Package roots:
  - `artifacts/wsl-pmaports/device-xiaomi-lmi/`
  - `artifacts/wsl-pmaports/linux-xiaomi-lmi/`
- Primary boot style: Android boot image with downstream DTB/overlay packaging.
- Rootfs strategy: postmarketOS image stored in `userdata` with nested GPT
  loop partitions and 4096-byte rootfs image sectors.
- Debug baseline: RNDIS USB networking and SSH at `172.16.42.1:22`.

## Distinctive Features

- Proven rootfs discovery through `/dev/loop0p2` as `/` and `/dev/loop0p1` as
  `/boot`.
- Uses the downstream CNSS/QCA CLD WLAN path, not mainline `ath11k_pci`.
- Wi-Fi bring-up depends on stock Android firmware mounts, QRTR nameservice,
  vendor `cnss-daemon`, Android property shims, and read-only `persist` for
  `wlan_mac.bin`.
- Keeps USB/RNDIS as the primary recovery and debug interface.

## Progress

| Version | Feature / change | Evidence | Status |
| --- | --- | --- | --- |
| `D-v27` | Reproducible downstream boot/rootfs baseline with RNDIS and SSH. | `notes/archive-summary-2026-06-23.md`; `notes/repair-phase46-v27-post-reboot-stability-2026-06-23.md` | Verified persistent baseline. |
| `D-v28` | Hardware tools rootfs for display/audio/Wi-Fi/BT probes. | `artifacts/images/pmos-lmi-v28-hwtools-full-20260623.manifest` | Built; not the final hardware milestone. |
| `D-v40` | Android property shim for vendor `cnss-daemon`; QRTR nameservice gap identified. | `notes/wifi-bringup-live-2026-06-24.md` | Diagnostic step. |
| `D-v41` | Static `qrtr-ns` and vendor `cnss-daemon` start before WLAN trigger. | `notes/wifi-bringup-live-2026-06-24.md` | WLFW service connects; missing WLAN cfg path. |
| `D-v42` | Links `WCNSS_qcom_cfg.ini`; WLAN interfaces appear with fallback MAC. | `notes/wifi-bringup-live-2026-06-24.md` | Live WLAN scan succeeds, but MAC path incomplete. |
| `D-v43` | Mounts `persist` read-only and links `wlan_mac.bin`. | `artifacts/images/pmos-lmi-v43-downstream-wlan-mac-persist-full-20260624.manifest`; `notes/wifi-bringup-live-2026-06-24.md` | Verified Wi-Fi bring-up: `wlan0`, `p2p0`, `wifi-aware0`, scan success, `crash_count=0`. |
| `D-v44` | Service-status cleanup after Wi-Fi success. | `artifacts/images/pmos-lmi-v44-service-status-cleanup-full-20260624.manifest` | Built. |
| `D-v45` | CNSS status idempotence cleanup. | `artifacts/images/pmos-lmi-v45-cnss-status-idempotent-full-20260624.manifest` | Built. |
| `D-v46` | Daemon status idempotence cleanup. | `artifacts/images/pmos-lmi-v46-daemon-status-idempotent-full-20260624.manifest` | Latest downstream build artifact; no separate runtime verification found. |

## Current Downstream State

The strongest verified hardware milestone is `D-v43`: downstream Wi-Fi works
well enough to create interfaces and scan. The latest downstream artifact is
`D-v46`, which appears to be a cleanup build on top of that Wi-Fi path.

## Open Work

- Verify `D-v46` on hardware if it is intended to replace `D-v43`.
- Clean up OpenRC status reporting for `lmi-qrtr-ns` and `lmi-cnss-daemon`.
- Decide NetworkManager MAC policy after the `persist` MAC path is stable.
- Continue display, audio, Bluetooth, charging, sensors, and suspend work.

## Safety Boundary

Do not write `boot`, `vbmeta`, `super`, `dtbo`, modem/EFS, calibration, or
bootloader state from this track without a fresh exact approval. `D-v43` was
validated by writing `userdata` and temporary `fastboot boot`, preserving that
boundary.
