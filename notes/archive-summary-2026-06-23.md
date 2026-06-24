# Archive Summary: v27 Persistent Baseline

Date: 2026-06-23 Australia/Sydney

This branch is a compact public archive of the Xiaomi `lmi` postmarketOS port
at the point where boot/rootfs repair was complete and hardware enablement
became the next task.

## Baseline

The retained baseline is v27:

- downstream LineageOS 4.19.325 kernel package builds with Clang/LLVM;
- generated Android boot image is accepted by the lmi bootloader;
- `userdata` contains the postmarketOS image with nested GPT subpartitions;
- initramfs discovers the rootfs with the loop-device fix;
- `/dev/loop0p2` mounts as `/`;
- `/dev/loop0p1` mounts as `/boot`;
- OpenRC userspace starts;
- USB networking works as RNDIS (`0525:a4a2 POSTMARKETOS`);
- SSH is reachable at `172.16.42.1:22`;
- persistent `boot` plus `userdata` survives a manual reboot.

## Current blockers

The remaining work is hardware enablement, not boot repair:

- display userspace takeover: DRM/KGSL and DSI panel are present, but the panel
  still shows the boot splash until a compositor or KMS test claims it;
- audio and microphone: no ALSA sound card is exposed yet;
- Wi-Fi: WLAN/CNSS starts partially but no wireless netdev is exposed;
- Bluetooth: only an rfkill entry is visible and it is soft-blocked;
- firmware/userspace services: firmware and QRTR/RMTFS-style service bring-up
  still need to be completed for several Qualcomm subsystems.

## Retained evidence

The branch keeps only redacted logs that document the current baseline:

- `logs/full-hardware-check-v27-persistent-20260623.redacted.txt`
- `logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt`
- `logs/display-userspace-probe-v27-before-v28-20260623.redacted.txt`
- `logs/post-reboot-stability-v27-20260623.redacted.txt`

The detailed interpretation is retained in:

- `notes/current-state.md`
- `notes/repair-phase43-v27-full-hardware-check-2026-06-23.md`
- `notes/repair-phase44-hardware-enablement-plan-2026-06-23.md`
- `notes/repair-phase45-reboot-gate-and-v28-hwtools-2026-06-23.md`
- `notes/repair-phase46-v27-post-reboot-stability-2026-06-23.md`

## Removed from the public archive

Earlier repair-phase notes, HTTP/initramfs diagnostic logs, old image manifests,
and transitional build scripts were removed from this branch. They represented
failed or superseded hypotheses from v2 through v26 and are summarized here by
the final v27 outcome.

Raw logs and binary images remain intentionally untracked. They may contain
device identifiers or be too large/proprietary for a public GitHub archive.

## Images to keep locally

For local continuation, the only useful generated image pair is:

- `artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img`
- `artifacts/images/xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img`

Their hashes are recorded in
`artifacts/images/pmos-lmi-v27-rndis-usbid-full-20260623.manifest`.
