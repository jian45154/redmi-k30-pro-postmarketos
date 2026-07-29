# Hardware Enablement Subagents

These subagents coordinate hardware enablement work for the Xiaomi `lmi`
postmarketOS port. Each agent owns a separate investigation lane and must not
revert work from another lane.

All agents start from the v27 persistent baseline:

- boot/rootfs/USB/RNDIS/SSH are known-good;
- `userdata` rootfs discovery uses the v27 loop-device fix;
- raw logs are not committed;
- partition writes require a separate explicit approval.

## Coordinator

Owner: the main coordinating agent thread.

Responsibilities:

- maintain `docs/hardware-enablement-workflow.md`;
- maintain `notes/hardware-enablement-queue-2026-06-23.md`;
- assign one bounded task per agent at a time;
- review agent output before changing packages or scripts;
- keep commits small and tied to one hardware hypothesis.

## Display Agent

Scope:

- DRM/KMS userspace takeover;
- `kmscube`, `modetest`, `weston`, `tinydm`, Mesa/GBM/EGL runtime;
- screen leaving continuous splash.

Read-only evidence:

- `logs/display-userspace-probe-v27-before-v28-20260623.redacted.txt`
- `logs/full-hardware-check-v27-persistent-20260623.redacted.txt`
- `scripts/26_runtime_display_check.sh`
- `scripts/29_display_userspace_probe.sh`

Writable files, when assigned:

- `scripts/26_runtime_display_check.sh`
- `scripts/29_display_userspace_probe.sh`
- display-specific notes under `notes/`

Deliverables:

- exact command output and dmesg delta for every failed modeset;
- package or service recommendation only after a tool probe;
- success proof when the panel visibly leaves the boot splash.

## Firmware Services Agent

Scope:

- Qualcomm firmware staging;
- `pd-mapper`, `rmtfs`, `tqftpserv`;
- QRTR/RMTFS device nodes;
- ADSP/CDSP/SLPI/Venus/WLAN firmware dependencies.

Read-only evidence:

- `artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD`
- `logs/full-hardware-check-v27-persistent-20260623.redacted.txt`
- `logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt`

Writable files, when assigned:

- `artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD`
- new firmware packaging files under `artifacts/wsl-pmaports/`
- firmware-specific notes under `notes/`

Deliverables:

- firmware path map: expected path, observed source, license/provenance,
  package target, and subsystem;
- OpenRC service enablement proposal;
- validation checklist for dmesg and device nodes.

## Wi-Fi and Bluetooth Agent

Scope:

- CNSS/WLAN/QCA6390 bring-up;
- PCIe WLAN endpoint state;
- `iw`, `wpa_supplicant`;
- rfkill, HCI, `bluez`.

Read-only evidence:

- `logs/full-hardware-check-v27-persistent-20260623.redacted.txt`
- `logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt`
- firmware service output from the Firmware Services Agent.

Writable files, when assigned:

- Wi-Fi/BT probe scripts under `scripts/`
- Wi-Fi/BT notes under `notes/`
- package changes only after firmware dependencies are identified.

Deliverables:

- explanation for driver-present/no-netdev state;
- minimal Wi-Fi scan checklist;
- minimal Bluetooth HCI scan checklist;
- dependency list shared with Firmware Services Agent.

## Audio Agent

Scope:

- ALSA card enumeration;
- ADSP/audio service dependencies;
- playback/capture device visibility;
- PulseAudio/PipeWire fallback diagnosis.

Read-only evidence:

- `logs/full-hardware-check-v27-persistent-20260623.redacted.txt`
- `logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt`
- firmware service output from the Firmware Services Agent.

Writable files, when assigned:

- audio probe scripts under `scripts/`
- audio notes under `notes/`
- package changes only after ADSP/audio firmware requirements are known.

Deliverables:

- ALSA/ASoC dmesg summary;
- dependency map for ADSP/audio firmware and services;
- validation checklist for `aplay`, `arecord`, and `/proc/asound/cards`.

## Rules for All Agents

- Separate observed facts from inference.
- Never use another device's firmware, DTB, or config without recording
  compatible strings and provenance.
- Do not make destructive hardware actions.
- Do not claim hardware works based on node presence alone.
- Prefer read-only probes, then rootfs/package changes, then explicit preflight
  for any boot or userdata write.
