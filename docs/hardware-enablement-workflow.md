# Hardware Enablement Workflow

This workflow starts from the v27 persistent baseline described in
`notes/archive-summary-2026-06-23.md`. Boot, rootfs discovery, USB/RNDIS, SSH,
and reboot recovery are treated as known-good unless new evidence proves
otherwise.

## Safety Rules

- Do not write `boot`, `userdata`, `dtbo`, `vbmeta`, `super`, modem/EFS,
  `persist`, or calibration partitions without a separate preflight note and
  explicit approval for the exact command.
- Prefer read-only SSH probes on the current v27 install.
- Prefer rebuilding a new rootfs image over mutating the live install.
- Keep USB/RNDIS and SSH as the primary debug path until Wi-Fi is stable.
- Redact raw logs before committing them.
- Change one hardware hypothesis at a time.

## Baseline Inputs

- Packages: `artifacts/wsl-pmaports/device-xiaomi-lmi/` and
  `artifacts/wsl-pmaports/linux-xiaomi-lmi/`
- Build scripts:
  - `scripts/21_build_pmos_v27_full_reproducible.sh`
  - `scripts/22_static_check_pmos_v27.sh`
  - `scripts/30_build_pmos_v28_hwtools.sh`
- Runtime probes:
  - `scripts/26_runtime_display_check.sh`
  - `scripts/27_full_hardware_check.sh`
  - `scripts/28_hardware_extra_check.sh`
  - `scripts/29_display_userspace_probe.sh`
  - `scripts/31_post_reboot_stability_check.sh`
  - `scripts/32_firmware_service_probe.sh`
- Firmware inventory tools:
  - `scripts/33_firmware_inventory.sh`
  - `scripts/34_extract_android_dat_partition.sh`
- Evidence:
  - `logs/full-hardware-check-v27-persistent-20260623.redacted.txt`
  - `logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt`
  - `logs/display-userspace-probe-v27-before-v28-20260623.redacted.txt`
  - `logs/post-reboot-stability-v27-20260623.redacted.txt`
  - `logs/firmware-service-probe-v27-20260623.redacted.txt`

## Phase 0: Reproducible Control Point

Goal: confirm the branch still describes one known-good baseline.

1. Inspect `artifacts/images/pmos-lmi-v27-rndis-usbid-full-20260623.manifest`.
2. Run `scripts/22_static_check_pmos_v27.sh` after any boot/rootfs build change.
3. Keep the v27 boot/userdata image pair local as the rollback baseline.
4. Record any new generated hashes in a new manifest; do not overwrite v27.

Exit criteria:

- The manifest identifies the boot image, userdata image, kernel, DTB, ramdisk,
  rootfs sector size, USB IDs, and cmdline.
- No hardware enablement change has weakened rootfs discovery or USB/RNDIS.

## Phase 1: v28 Hardware-Tools Rootfs

Goal: produce a tool-equipped rootfs without changing the proven boot path.

1. Build with `scripts/30_build_pmos_v28_hwtools.sh`.
2. Inspect the output manifest and verify it retains the v27 loop-device fix.
3. Prefer testing the new rootfs with the already proven boot image unless a
   boot-image change is explicitly required.
4. Do not flash the new rootfs until a write preflight identifies the exact
   target partition and rollback path.

Exit criteria:

- `kmscube`, `libdrm-tests`, `mesa-demos`, `mesa-utils`, `weston`, `tinydm`,
  `alsa-utils`, `iw`, `wpa_supplicant`, and `bluez` are present in the image.
- The v28 manifest records boot/userdata hashes.

## Phase 2: Display Userspace Takeover

Goal: make userspace visibly claim the panel.

Read-only probes:

- `ls -l /dev/dri /sys/class/drm`
- `cat /sys/class/drm/card0-DSI-1/status`
- `cat /sys/class/drm/card0-DSI-1/modes`
- `dmesg | grep -Ei 'drm|dsi|sde|mdss|kgsl|adreno|cont_splash'`

Tool probes after v28:

- `modetest -M msm`
- `kmscube`
- `weston --backend=drm-backend.so --tty=1`

Record exact errno, process state, and dmesg delta for every failed userspace
open or modeset attempt.

Exit criteria:

- The physical panel leaves the boot splash and shows a Linux-controlled test
  pattern, compositor, or terminal.

## Phase 3: Firmware and Qualcomm Services

Goal: provide the firmware and userspace service layer needed by WLAN/BT/audio,
Venus, and remote processors.

Probe:

- `find /lib/firmware -maxdepth 5 -type f | sort`
- `ls -l /dev/subsys_* /dev/rmtfs* /dev/qrtr* 2>/dev/null`
- `rc-status`
- `dmesg | grep -Ei 'firmware|pil|subsys|adsp|cdsp|slpi|venus|wlan|cnss|rmtfs|qrtr'`

Package/service candidates already present in `device-xiaomi-lmi`:

- `pd-mapper`
- `rmtfs`
- `tqftpserv`

Exit criteria:

- Required firmware paths are known and packaged or intentionally staged.
- Required OpenRC services are enabled or have a documented reason not to run.
- Missing firmware errors are reduced to a specific tracked list.

## Phase 4: Wi-Fi and Bluetooth

Goal: expose a wireless interface and a Bluetooth HCI adapter.

Wi-Fi probes:

- `ip link`
- `iw dev`
- `dmesg | grep -Ei 'wlan|cnss|qca|ath|pci|firmware'`
- `cat /sys/bus/pci/devices/0000:01:00.0/enable 2>/dev/null`

Bluetooth probes:

- `rfkill list`
- `rfkill unblock bluetooth`
- `hciconfig -a`
- `bluetoothctl list`
- `dmesg | grep -Ei 'bluetooth|bt|hci|qca|rfkill'`

Exit criteria:

- Wi-Fi interface appears and can scan.
- Bluetooth HCI adapter appears and can scan.

## Phase 5: Audio and Microphone

Goal: expose a real ALSA card and enumerate playback/capture paths.

Probes:

- `cat /proc/asound/cards`
- `aplay -l`
- `arecord -l`
- `dmesg | grep -Ei 'alsa|asoc|snd|wcd|bolero|adsp|apr|q6|audio'`

Exit criteria:

- At least one real ALSA card appears.
- Playback and capture devices enumerate without relying on `auto_null`.

## Phase 6: Follow-Up Hardware

Defer these until display, firmware services, Wi-Fi/BT, and audio have a clear
baseline:

- camera and media graph validation;
- Venus video codec;
- modem-adjacent services;
- suspend/resume;
- charging behavior beyond basic battery reporting;
- sensors beyond current IIO enumeration.
