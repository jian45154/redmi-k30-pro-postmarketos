# Hardware Enablement Queue

Date: 2026-06-23 Australia/Sydney

Baseline: v27 persistent install. Rootfs discovery, USB/RNDIS, SSH, and manual
reboot recovery are working. This queue starts hardware enablement without
changing boot, DTBO, vbmeta, super, modem/EFS, persist, or calibration
partitions.

## Active Agents

- Display Agent: DRM/KMS userspace takeover.
- Firmware Services Agent: Qualcomm firmware, pd-mapper, rmtfs, tqftpserv,
  QRTR/subsys service visibility.
- Wi-Fi and Bluetooth Agent: QCA6390/CNSS, rfkill, HCI, scan path.
- Audio Agent: ALSA/ASoC card enumeration and ADSP/audio dependencies.

## Cross-Cutting Finding

Firmware and Qualcomm service bring-up is the shared blocker for Wi-Fi,
Bluetooth, audio, Venus, and likely later camera/media work.

Observed:

- `/lib/firmware` only contains `regulatory.db` and its signature.
- `venus.mdt` is missing and Venus firmware download fails.
- WLAN/CNSS expects `qca6390/amss20.bin` or `amss20.bin`.
- `pd-mapper`, `rmtfs`, and `tqftpserv` are package dependencies, but runtime
  evidence does not show them running.
- `/dev/rmtfs*` and `/dev/qrtr*` are absent.
- `/sys/class/remoteproc` is absent, while downstream `/dev/subsys_*` nodes are
  present.

## Task 1: Build v28 Hardware-Tools Image

Owner: Coordinator

Purpose: provide display, audio, Wi-Fi, and Bluetooth diagnostic tools in the
rootfs without changing the proven v27 boot path unless required.

Commands:

```sh
scripts/30_build_pmos_v28_hwtools.sh
scripts/22_static_check_pmos_v27.sh
```

Expected tools in v28 rootfs:

- display: `kmscube`, `libdrm-tests`, `mesa-demos`, `mesa-utils`, `weston`,
  `tinydm`;
- audio: `alsa-utils`;
- Wi-Fi: `iw`, `wpa_supplicant`;
- Bluetooth: `bluez`, `bluez-deprecated`.

Exit criteria:

- v28 boot/userdata manifest exists and records hashes.
- Static check confirms the loop-device fix remains present.
- No partition write has occurred.

## Task 2: Display Userspace Probe

Owner: Display Agent

Prerequisite: v28 hardware-tools rootfs available or equivalent tools installed.

Read-only baseline:

```sh
ssh lmi@172.16.42.1 'sh -s' < scripts/29_display_userspace_probe.sh
```

Tool probes:

```sh
ssh lmi@172.16.42.1 'modetest -c; modetest -p'
ssh lmi@172.16.42.1 'kmscube -D /dev/dri/card0'
```

Capture after every failed probe:

```sh
ssh lmi@172.16.42.1 'echo rc=$?; dmesg | grep -Ei "drm|dsi|panel|sde|kgsl|adreno|kms|fail|error|denied" | tail -200'
```

Exit criteria:

- Physical panel leaves continuous splash and shows a Linux-controlled output.

## Task 3: Firmware Inventory and Staging Plan

Owner: Firmware Services Agent

Purpose: produce a file-by-file map before adding proprietary firmware to any
rootfs image.

Collect from stock/vendor/modem/bluetooth partitions or known-good stock image,
read-only:

- `venus.mdt` and matching segment files;
- `qca6390/amss20.bin` and `amss20.bin` fallback;
- ADSP firmware: `adsp.mdt` and matching segment files;
- CDSP firmware: `cdsp.mdt` and matching segment files;
- SLPI/SSC firmware: `slpi.mdt` or `ssc.mdt` and matching segment files;
- IPA firmware: `ipa_fws.*`, `ipa_uc.*`;
- GPU zap firmware: `a650_zap.*`;
- QCA6390 Bluetooth files: `*.tlv`, `*.bin`, `*.hcd`, `bt_*`, and related
  stock files.

Record for each file:

- source partition or image;
- relative source path;
- target `/lib/firmware` path;
- sha256;
- subsystem;
- license/provenance status;
- whether the file can be published or must remain local-only.

Exit criteria:

- `notes/firmware-inventory-YYYY-MM-DD.md` exists.
- No proprietary binary is committed.

## Task 4: Qualcomm Service Visibility Probe

Owner: Firmware Services Agent

Run on device:

```sh
find /lib/firmware -maxdepth 5 -type f | sort
rc-status -a
ps w
ls -l /dev/subsys_* /dev/rmtfs* /dev/qrtr* 2>&1
dmesg | grep -Ei 'firmware|pil|subsys|adsp|cdsp|slpi|venus|wlan|cnss|rmtfs|qrtr|pdr|service' | tail -240
```

Exit criteria:

- `pd-mapper`, `rmtfs`, and `tqftpserv` install/start state is known.
- Missing QRTR/RMTFS behavior is reduced to a kernel, device-node, or service
  issue.

## Task 5: Wi-Fi Bring-Up

Owner: Wi-Fi and Bluetooth Agent

Prerequisite: firmware and service visibility tasks have concrete output.

Probe:

```sh
ip link
iw dev
cat /sys/bus/pci/devices/0000:01:00.0/enable 2>/dev/null || true
dmesg | grep -Ei 'wlan|cnss|qca|ath|pci|firmware|mhi' | tail -220
```

Hypotheses to test in order:

1. missing `qca6390/amss20.bin` or board/NVM/calibration files;
2. PCIe endpoint runtime power-gated after failed firmware load;
3. missing Qualcomm service chain;
4. DT power/reset/clock mismatch.

Exit criteria:

- A wireless interface appears in `iw dev` and can scan.

## Task 6: Bluetooth Bring-Up

Owner: Wi-Fi and Bluetooth Agent

Prerequisite: firmware/service state is understood. Keep USB/RNDIS as the debug
fallback.

Probe:

```sh
rfkill list
rfkill unblock bluetooth
rfkill list
hciconfig -a || btmgmt info || bluetoothctl list
rc-service bluetooth start
bluetoothctl show
dmesg | grep -Ei 'bluetooth|bt|hci|qca|rfkill|firmware' | tail -180
```

Exit criteria:

- `hci0` appears and can perform a basic scan.

## Task 7: Audio and Microphone Enumeration

Owner: Audio Agent

Prerequisite: ADSP/audio firmware and service state is understood.

Probe:

```sh
cat /proc/asound/cards
cat /proc/asound/devices
ls -l /dev/snd
aplay -l
arecord -l
find /lib/firmware -maxdepth 4 -type f | sort
rc-status -a
ls -l /dev/subsys_adsp /dev/rmtfs* /dev/qrtr* 2>&1
dmesg | grep -Ei 'alsa|snd|asoc|audio|adsp|apr|q6|wcd|slim|firmware|service|pdr' | tail -220
```

Config audit:

- explain why `CONFIG_SND_SOC_QCOM` and `CONFIG_QCOM_APR` are disabled in the
  current kernel config despite visible Qualcomm audio platform devices;
- compare against the LineageOS lmi defconfig fragments before changing kernel
  config.

Exit criteria:

- At least one real ALSA card appears.
- Playback and capture device nodes enumerate.

## Deferred

- camera/media graph;
- Venus video codec functional testing beyond firmware-load validation;
- modem-adjacent service testing;
- suspend/resume;
- charging beyond current battery reporting;
- sensors beyond current IIO enumeration.
