# Repair Phase 44: Hardware Enablement Plan

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Baseline

Use v27 persistent boot as the baseline. It has working rootfs mount, USB/RNDIS,
SSH, storage, CPU, memory, battery reporting, thermal reporting, input device
enumeration, and kernel-level DRM/KGSL bring-up.

Evidence:

```text
notes/repair-phase43-v27-full-hardware-check-2026-06-23.md
logs/full-hardware-check-v27-persistent-20260623.redacted.txt
logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt
```

Do not change boot, userdata, dtbo, vbmeta, super, modem/EFS, persist, or
calibration partitions while working on these issues unless a separate plan and
explicit approval exists.

## Priority 1: Display userspace takeover

Observed:

```text
/dev/dri/card0
/dev/dri/renderD128
/dev/kgsl-3d0
card0-DSI-1 status=connected
1080x2400x60x184345cmd
Adreno650v3
```

Problem:

The kernel display stack is present, but no compositor or direct KMS test has
claimed the panel. The physical screen remains on the Redmi logo.

Plan:

1. Add a minimal KMS/DRM validation path that can run over SSH.
2. Check whether `kmscube`, `weston`, `tinydm`, or a simple framebuffer/KMS
   test is available in the rootfs.
3. If userspace cannot open DRM cleanly, collect the exact errno and dmesg delta.
4. Once a visible mode-set works, choose the smallest persistent display service.

Success criteria:

The panel visibly leaves the boot logo and shows a Linux-controlled test pattern,
terminal, or compositor.

## Priority 2: Audio and microphone

Observed:

```text
--- no soundcards ---
aplay: no soundcards found
PulseAudio/PipeWire fallback sink: auto_null
```

Problem:

No ALSA card is exposed, so speaker and microphone cannot be tested yet.

Plan:

1. Confirm ADSP/audio firmware files expected by this kernel and DTB.
2. Check ADSP/subsystem service status and missing userspace daemons.
3. Add only the required firmware/service packages or local firmware staging.
4. Reboot or restart the smallest affected service path and re-check
   `/proc/asound/cards`, `arecord -l`, and `aplay -l`.

Success criteria:

At least one real ALSA card appears, and speaker plus microphone device nodes can
be enumerated.

## Priority 3: Wi-Fi networking

Observed:

```text
/sys/module/wlan
wlan_hdd_state wlan major initialized
iw dev produced no interface
/sys/class/net only shows usb0 and virtual links
```

Problem:

The WLAN driver path initializes partially, but no wireless netdev is exposed.

Plan:

1. Collect CNSS/WLAN firmware expectations and service dependencies.
2. Check whether the PCIe WLAN endpoint is intentionally disabled or power-gated.
3. Compare firmware paths against stock/vendor partitions and packaged rootfs.
4. Re-test `iw dev`, `ip link`, NetworkManager, and dmesg after firmware/service
   changes.

Success criteria:

A wireless interface appears and can scan networks. USB/RNDIS remains the debug
fallback until Wi-Fi is stable.

## Priority 4: Bluetooth

Observed:

```text
bt_power: Bluetooth
Soft blocked: yes
Hard blocked: no
```

Problem:

Bluetooth is visible only through rfkill and is currently soft-blocked. No
functional HCI device has been validated.

Plan:

1. Unblock Bluetooth only after WLAN/firmware dependencies are understood.
2. Check whether BT firmware is shared with the QCA6390/CNSS path.
3. Re-test rfkill, HCI enumeration, and bluetoothd startup.

Success criteria:

An HCI adapter appears and can perform a basic scan without disrupting the
USB/RNDIS debug channel.

## Issue split

Create separate GitHub issues for:

1. Display userspace takeover.
2. Audio and microphone enablement.
3. Wi-Fi interface bring-up.
4. Bluetooth bring-up.

Keep camera, modem, and Venus video codec as follow-up issues unless they become
direct dependencies of the four priority targets above.
