# Audio Bring-Up Analysis

Date: 2026-06-23 Australia/Sydney

Scope: Audio Hardware sub-agent only. This note does not authorize reboot,
fastboot, flash, partition writes, SSH state changes, mixer writes, playback, or
recording. It summarizes read-only evidence and candidate next changes for
xiaomi-lmi postmarketOS ALSA/ADSP/audio bring-up.

## Current Evidence

- Runtime v27 reports no real ALSA card:
  - `/proc/asound/cards`: `--- no soundcards ---`
  - `/proc/asound/devices`: timer only
  - `/dev/snd`: timer only
  - `aplay -l` / `arecord -l`: no soundcards found
- This is below PulseAudio/PipeWire. The fallback `auto_null` sink is a symptom,
  not the root cause.
- DT/platform enumeration is not empty. Existing logs show many Qualcomm audio
  devices under `/sys/bus/platform/devices`, including:
  - `soc:qcom,msm-audio-apr`
  - `soc:qcom,msm-dai-q6`
  - `soc:qcom,msm-dai-fe`
  - `17300000.qcom,lpass`
  - `soc:qcom,audio-pkt-core-platform`
  - `soc:usb_audio_qmi_dev`
- ADSP-related kernel activity exists:
  - `LPASS_*` kernel threads are present.
  - `apr_driver` and `uaudio_svc` kernel threads are present.
  - dmesg shows ADSP reserved memory, LPASS assignment, ALSA core init, and
    `adsprpc: fastrpc_probe: service location enabled for avs/audio`.
- The shared firmware/service layer is incomplete:
  - `/lib/firmware` currently only contains `regulatory.db` and signature.
  - `/sys/class/remoteproc` is absent.
  - `/dev/qrtr*` is absent.
  - `/dev/rmtfs*` is absent on v27.
  - `pd-mapper`, `rmtfs`, and `tqftpserv` were stopped on v27; v28 has service
    enablement and `CONFIG_QCOM_RMTFS_MEM=y` staged by the coordinator.

## Config Gap

Current pmaports kernel config has ALSA basics, but lacks the Qualcomm ASoC
stack needed to bind a real SM8250 card:

- Present:
  - `CONFIG_SND=y`
  - `CONFIG_SND_PCM=y`
  - `CONFIG_SND_SOC=y`
  - `CONFIG_SND_USB_AUDIO=y`
  - `CONFIG_SND_USB_AUDIO_QMI=y`
  - `CONFIG_QRTR=y`
  - `CONFIG_QRTR_SMD=y`
  - `CONFIG_QRTR_MHI=y`
  - `CONFIG_MSM_ADSPRPC=y`
  - `CONFIG_RPMSG_QCOM_GLINK_SMEM=y`
  - `CONFIG_SLIMBUS=y`
  - `CONFIG_SLIMBUS_MSM_NGD=y`
- Missing or disabled in current pmaports config:
  - `CONFIG_QCOM_APR`
  - `CONFIG_SND_SOC_QCOM`
  - `CONFIG_SND_SOC_QCOM_COMMON`
  - `CONFIG_SND_SOC_QDSP6`
  - `CONFIG_SND_SOC_SM8250`
  - `CONFIG_SND_SOC_WCD938X`
  - `CONFIG_SND_SOC_WCD938X_SDW`
  - `CONFIG_SND_SOC_LPASS_RX_MACRO`
  - `CONFIG_SND_SOC_LPASS_TX_MACRO`
  - `CONFIG_SND_SOC_LPASS_VA_MACRO`
  - `CONFIG_SND_SOC_TFA9874`
  - likely `CONFIG_SOUNDWIRE` / `CONFIG_SOUNDWIRE_QCOM`
  - keep/confirm `CONFIG_QCOM_PDR_HELPERS`, `CONFIG_QCOM_PDR_MSG`,
    `CONFIG_QCOM_PD_MAPPER`, and `CONFIG_QRTR_SMD` built-in if available in this
    kernel tree.

The user-supplied Windows path contains a prior lmi bring-up tree at
`/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/linux-sm8250-xiaomi-lmi`.
Its `lmi/configs/m1.config` enables the expected audio chain:

```text
CONFIG_SOUNDWIRE=y
CONFIG_SOUNDWIRE_QCOM=y
CONFIG_QCOM_PDR_HELPERS=y
CONFIG_QCOM_PDR_MSG=y
CONFIG_QCOM_SYSMON=y
CONFIG_QCOM_Q6V5_PAS=y
CONFIG_QCOM_APR=y
CONFIG_SND_SOC_QCOM=y
CONFIG_SND_SOC_QCOM_COMMON=y
CONFIG_SND_SOC_QDSP6=y
CONFIG_SND_SOC_SM8250=y
CONFIG_SND_SOC_WCD938X_SDW=y
CONFIG_SND_SOC_WCD938X=y
CONFIG_SND_SOC_LPASS_VA_MACRO=y
CONFIG_SND_SOC_LPASS_RX_MACRO=y
CONFIG_SND_SOC_LPASS_TX_MACRO=y
CONFIG_SND_SOC_TFA9874=y
```

## Firmware and Service Gap

Even with the kernel config fixed, audio likely needs local-only firmware and
service visibility:

- ADSP firmware and split segments must be staged locally. The prior bring-up
  notes call out `qcom/sm8250/adsp.mbn`; current rootfs has no ADSP firmware.
- QRTR/PDR/APR service visibility must be verified after the coordinator's v28
  RMTFS test. Prior notes explicitly require `CONFIG_QCOM_PD_MAPPER=y` and
  `CONFIG_QRTR_SMD=y` built-in so `audio_pd` and APR subservices appear.
- Proprietary firmware must not be committed. It should be inventoried with
  source path, target path, hash, subsystem, and license/provenance status.

## Minimal Patch Candidates

1. Kernel config-only audio candidate:
   enable the Qualcomm ASoC/APR/SM8250/WCD938x/SoundWire/TFA9874 symbols listed
   above, preserving the already staged RMTFS fix. Build as a separate kernel
   pkgrel and test by RAM-only boot first.

2. Firmware staging candidate:
   add a local-only firmware staging script or documented copy list for ADSP
   firmware after an lmi-specific source is identified. Do not add firmware
   blobs to Git.

3. Userspace audio package candidate:
   after a real ALSA card appears as `Xiaomi lmi`, adapt the prior
   `lmi/rootfs/audio` support package into pmaports packaging or local rootfs
   staging. This is not useful before ALSA card registration.

## Validation Commands

Read-only baseline on the current device:

```sh
ssh lmi@172.16.42.1 'sh -s' < scripts/37_audio_probe.sh
```

Expected after kernel/service/firmware progress:

```sh
cat /proc/asound/cards
aplay -l
arecord -l
dmesg | grep -Ei 'alsa|asoc|snd|audio|apr|q6|adsp|lpass|wcd|soundwire|tfa|pdr|qrtr|firmware|failed|error' | tail -260
```

Success criteria for this phase:

- A real ALSA card appears, expected name from prior bring-up: `Xiaomi lmi`.
- Playback and capture PCM devices enumerate.
- APR/PDR/audio service errors, if any, are concrete missing-firmware or
  device-probe errors rather than absent Qualcomm ASoC/APR kernel support.

Do not run mixer writes, playback, or recording until the card exists and a
separate low-volume test plan is accepted.
