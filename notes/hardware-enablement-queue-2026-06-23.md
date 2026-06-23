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
- `pd-mapper`, `rmtfs`, and `tqftpserv` are package dependencies. Runtime
  evidence shows them installed but stopped on v27; `device-xiaomi-lmi`
  `pkgrel=5` enables them in the OpenRC default runlevel for the next rootfs.
- `/dev/rmtfs*` and `/dev/qrtr*` are absent.
- `/sys/class/remoteproc` is absent, while downstream `/dev/subsys_*` nodes are
  present.

## Task 1: Build v28 Hardware-Tools Image

Owner: Coordinator
Status: completed locally on 2026-06-23; not flashed.

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

- v28 boot/userdata manifest exists and records hashes:
  `artifacts/images/pmos-lmi-v28-hwtools-full-20260623.manifest`.
- Static check confirms the loop-device fix remains present.
- Read-only rootfs inspection confirms `device-xiaomi-lmi 1-r7`,
  `linux-xiaomi-lmi 4.19.325-r7`, hardware tools, the rmtfs downstream
  argument override, and OpenRC symlinks for `pd-mapper`, `rmtfs`, and
  `tqftpserv`.
- No partition write has occurred.

## Task 1A: Current v27 Service Probe

Owner: Coordinator
Status: completed once on 2026-06-23.

Command:

```sh
ssh -o BatchMode=yes -o ConnectTimeout=5 lmi@172.16.42.1 'sh -s' < scripts/32_firmware_service_probe.sh
```

Redacted evidence:

- `logs/firmware-service-probe-v27-20260623.redacted.txt`

Observed:

- `/lib/firmware` still contains only `regulatory.db` and
  `regulatory.db.p7s`.
- `/dev/subsys_adsp`, `/dev/subsys_cdsp`, `/dev/subsys_slpi`,
  `/dev/subsys_venus`, and `/dev/subsys_wlan` exist.
- `/dev/rmtfs0`, `/dev/rmtfs1`, `/dev/qrtr`, and `/dev/qrtr*` do not exist.
- `pd-mapper`, `rmtfs`, and `tqftpserv` services are installed but stopped.
- `qrtr-ns` service does not exist.
- `bluetooth` service does not exist.
- WLAN PCI endpoint `0000:01:00.0` has `enable=0`.
- `iw dev` returns no wireless interface.
- Bluetooth has only `bt_power` rfkill and is soft-blocked.
- `/proc/asound/cards` reports no soundcards; `/dev/snd` only has `timer`.
- Qualcomm audio platform devices are present under `/sys/bus/platform`, so the
  current blocker is below PulseAudio/PipeWire.

Kernel config audit notes:

- `CONFIG_QRTR=y`, `CONFIG_QRTR_SMD=y`, and `CONFIG_QRTR_MHI=y`, but no QRTR
  device node is visible.
- `CONFIG_SND_SOC_QCOM` and `CONFIG_QCOM_APR` are disabled, despite visible
  Qualcomm Q6/LPASS/MSM audio platform devices.
- `CONFIG_BT_SLIM_QCA6390=y`; `CONFIG_BT_HCIUART` is disabled.

## Task 2: Display Userspace Probe

Owner: Display Agent

Prerequisite: v28 hardware-tools rootfs available or equivalent tools installed.

Read-only baseline:

```sh
ssh lmi@172.16.42.1 'sh -s' < scripts/29_display_userspace_probe.sh
ssh lmi@172.16.42.1 'sh -s' < scripts/36_display_takeover_probe.sh
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

## Task 3A: Extract LineageOS Dynamic Partitions

Owner: Firmware Services Agent
Status: completed for `vendor`, `odm`, `product`, and `system_ext`.

Known local source:

```text
/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.new.dat.br
/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.transfer.list
```

Tool:

```sh
scripts/34_extract_android_dat_partition.sh \
  "/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.new.dat.br" \
  "/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.transfer.list" \
  /tmp/lmi-lineage-vendor
```

Generate a publishable inventory:

```sh
scripts/33_firmware_inventory.sh /tmp/lmi-lineage-vendor/vendor.files > notes/firmware-inventory-2026-06-23.md
```

Result:

- `vendor` contains IPA and Adreno GPU zap firmware.
- `vendor`, `odm`, `product`, and `system_ext` do not contain the expected
  QCA6390 Wi-Fi firmware names, Bluetooth payloads, or full DSP/Venus firmware
  groups.
- The next firmware source must be an lmi-specific firmware package or
  read-only stock firmware-bearing partition dump. Do not use the unrelated
  local `capricorn` NON-HLOS image.

Do not commit extracted firmware files or raw images.

## Task 3B: Enable Qualcomm Services in Rootfs

Owner: Firmware Services Agent
Status: built and statically verified in v28 rootfs, pending device boot
verification.

Current live v27 finding:

- Starting `pd-mapper`, `rmtfs`, and `tqftpserv` with sudo succeeds initially,
  but `rmtfs` exits again.
- Foreground `rmtfs -s -P -r` fails with `Failed to get rprocfd`.
- Foreground `rmtfs -P -r` gets further, then fails because
  `/dev/qcom_rmtfs_mem1`, `/dev/qcom_rmtfs_uio1`, and `/dev/mem` are absent.
- Current kernel config has `# CONFIG_QCOM_RMTFS_MEM is not set`, no
  `CONFIG_REMOTEPROC`, and no `/sys/class/remoteproc`.

Change:

- `linux-xiaomi-lmi` `pkgrel=7`
- `CONFIG_QCOM_RMTFS_MEM=y`
- `device-xiaomi-lmi` `pkgrel=7`
- `device-xiaomi-lmi.post-install` appends `command_args="-P -r"` to
  `/etc/conf.d/rmtfs` without taking file ownership from `rmtfs-openrc`.
- OpenRC default runlevel symlinks for `pd-mapper`, `rmtfs`, and `tqftpserv`

Static verification:

- `device-xiaomi-lmi` package version in v28 rootfs: `1-r7`
- `linux-xiaomi-lmi` package version in v28 rootfs: `4.19.325-r7`
- build log compiled `drivers/soc/qcom/rmtfs_mem.o`
- `/etc/conf.d/rmtfs` contains `command_args="-P -r"`
- `/etc/runlevels/default/pd-mapper -> /etc/init.d/pd-mapper`
- `/etc/runlevels/default/rmtfs -> /etc/init.d/rmtfs`
- `/etc/runlevels/default/tqftpserv -> /etc/init.d/tqftpserv`
- `iw`, `wpa_supplicant`, `bluetoothctl`, and `kmscube` are present.

Verification after next rootfs boot:

```sh
rc-status default
ls -l /etc/runlevels/default/pd-mapper /etc/runlevels/default/rmtfs /etc/runlevels/default/tqftpserv
ls -l /dev/rmtfs* /dev/qrtr* 2>&1
dmesg | grep -Ei 'rmtfs|qrtr|pdr|pd-mapper|tqftp|subsys|wlan|cnss' | tail -240
```

Exit criteria:

- The three services are enabled and either running or failing with a concrete
  device-node/firmware error.

## Task 3C: RAM-Only rmtfs_mem Verification

Owner: Coordinator
Status: prepared locally; pending explicit hardware approval.

Purpose: test the v28 kernel and initramfs against the current known-good v27
rootfs without writing partitions. This isolates the `CONFIG_QCOM_RMTFS_MEM=y`
change before any rootfs or boot partition update.

Prepared artifact:

```text
artifacts/images/pmos-lmi-v28-kernel-currentroot-20260623.manifest
```

Local boot image, ignored by git:

```text
artifacts/images/pmos-lmi-v28-kernel-currentroot-20260623.img
```

Static verification:

- cmdline points to the current v27 boot/root UUIDs:
  `3c14f75f-450e-4457-b109-6fc5d9f7c54c` and
  `b50c1119-2cd9-4675-a9be-3201c98d54ec`;
- v27 loop-device fix markers remain present;
- RNDIS USB IDs remain present.

Runtime test, only after separate approval for the exact reboot and temporary
boot command:

```sh
fastboot boot artifacts/images/pmos-lmi-v28-kernel-currentroot-20260623.img
```

Post-boot evidence to collect:

```sh
uname -a
zcat /proc/config.gz | grep CONFIG_QCOM_RMTFS_MEM
ls -l /dev/qcom_rmtfs* /dev/uio* /dev/mem 2>&1
rc-status default
dmesg | grep -Ei 'rmtfs|qcom_rmtfs|qrtr|pdr|pd-mapper|tqftp|subsys|wlan|cnss|firmware|failed|error' | tail -260
```

Exit criteria:

- `/dev/qcom_rmtfs_mem*` either appears, or the kernel log gives the next
  concrete DTB/driver reason it did not.
- `rmtfs -P -r` no longer fails solely because all rmtfs memory access devices
  are absent.

## Task 4A: External lmi Mainline Wi-Fi Reference

Owner: Wi-Fi and Bluetooth Agent
Status: read-only reference captured on 2026-06-23.

Local source provided by the user:

```text
/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/linux-sm8250-xiaomi-lmi
```

Useful findings:

- `lmi/HARDWARE_SUPPORT.md` reports QCA6391 Wi-Fi working with `ath11k_pci`,
  real WLAN MAC, auto-connect, and SSH.
- `arch/arm64/boot/dts/qcom/sm8250-xiaomi-lmi.dts` models the combo chip with
  `qcom,qca6390-pmu`, GPIO20 WLAN enable, GPIO21 BT enable, PCI endpoint
  `pci17cb,1101`, and UART6 `qcom,qca6390-bt`.
- `lmi/ADAPTATION_NOTES.md` warns that firmware import, wireless reprobe, and
  Wi-Fi connect should not block `multi-user.target`.
- `lmi/MODEM_BRINGUP.md` is modem-only SDX55M work. It is useful for safety
  boundaries but not a direct WLAN fix.

Current downstream contrast:

- pmOS v27/v28 downstream 4.19 uses CNSS2/QCA CLD, with
  `CONFIG_QCA_CLD_WLAN_PROFILE="qca6390"`.
- The current live rootfs has no WLAN firmware beyond `regulatory.db`, and
  `iw dev` returns no interface.
- Treat the mainline tree as a topology and firmware reference first. Do not
  mix `ath11k_pci` assumptions into the downstream CNSS2 bring-up without a
  deliberate kernel strategy change.
- QRTR/RMTFS visibility is rechecked before changing Wi-Fi driver assumptions.

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

Reference:

```text
notes/audio-bringup-analysis-2026-06-23.md
scripts/37_audio_probe.sh
```

Probe:

```sh
ssh lmi@172.16.42.1 'sh -s' < scripts/37_audio_probe.sh
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

## Task 8: Power, Charging, and Sensors

Owner: Power/Sensors Agent
Status: read-only analysis and probe prepared.

Reference:

```text
notes/power-sensors-status-2026-06-23.md
scripts/38_power_sensors_probe.sh
```

Current finding:

- Battery capacity, voltage, current, temperature, health, and presence are
  readable in v27.
- Charger and Type-C nodes are present but not functionally validated.
- Current sensor evidence only proves PMIC VADC IIO. Motion/environment sensors
  are not yet supported by evidence.
- `CONFIG_REMOTEPROC` remains disabled, which likely blocks the external
  SDSP/sensor route.

Read-only probe:

```sh
ssh lmi@172.16.42.1 'sh -s' < scripts/38_power_sensors_probe.sh
```

Exit criteria:

- Charge-control sysfs availability, Type-C/USB-PD state, IIO channels,
  thermal zones, and real sensor enumeration are known from a fresh v27/v28
  capture.

## Deferred

- camera/media graph;
- Venus video codec functional testing beyond firmware-load validation;
- modem-adjacent service testing;
- suspend/resume;
- charging behavior changes beyond read-only reporting.
