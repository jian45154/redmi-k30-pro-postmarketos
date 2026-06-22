# Repair Phase 43: v27 Full Hardware Check

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Scope

This phase performed read-only hardware inventory and runtime checks over the
working v27 SSH/RNDIS channel. No partition was written and no boot image was
changed.

Raw logs are retained locally and ignored by git:

```text
logs/full-hardware-check-v27-persistent-20260623.txt
logs/full-hardware-check-v27-persistent-extra-20260623.txt
```

Redacted logs are safe to commit:

```text
logs/full-hardware-check-v27-persistent-20260623.redacted.txt
logs/full-hardware-check-v27-persistent-extra-20260623.redacted.txt
```

## Confirmed working

Boot, rootfs, and storage are working:

```text
/dev/loop0p2 mounted as /
/dev/loop0p1 mounted as /boot
/dev/sda34 present as 107G userdata container
```

USB gadget networking and SSH are working:

```text
usb0 UP, 172.16.42.1
RNDIS idVendor=0x0525 idProduct=0xa4a2
sshd started
```

CPU and memory are online:

```text
Hardware: Qualcomm Technologies, Inc SM8250
8 CPUs present and online
MemTotal: 5716072 kB
```

Power, battery, and thermal reporting are working:

```text
battery status=Full
capacity=100
health=Good
thermal zones present, CPU/GPU/battery temperatures readable
```

Basic input devices are present:

```text
xiaomi-touch
qpnp_pon
uinput-goodix
aw8697_haptic
fts_ts
gpio-keys
```

## Kernel-visible but not functionally validated

Display/GPU kernel bring-up is present:

```text
/dev/dri/card0
/dev/dri/renderD128
/dev/kgsl-3d0
card0-DSI-1 status=connected
1080x2400x60x184345cmd
Adreno650v3
Successfully bind display panel 'qcom,mdss_dsi_j11_38_08_0a_fhd_cmd'
Initialized msm_drm 1.3.0
```

The screen still visually remains on the Redmi logo because no compositor or
userspace display takeover was observed.

Camera/media nodes are present, but camera functionality is not validated:

```text
/dev/media0
/dev/media1
/dev/video0
/dev/video1
/dev/video32
/dev/video33
many /dev/v4l-subdev* nodes
```

PMIC ADC/IIO sensors are present:

```text
iio:device0 pm8150l vadc
iio:device1 pm8150b vadc
iio:device2 pm8150 vadc
```

PCIe enumerates one Qualcomm root port and one endpoint:

```text
0000:00:00.0 vendor=0x17cb device=0x010b class=0x060400 enable=1
0000:01:00.0 vendor=0x17cb device=0x1101 class=0xff0000 enable=0
```

## Not working or incomplete

Audio has no ALSA sound card:

```text
--- no soundcards ---
aplay: no soundcards found
PulseAudio/PipeWire fallback sink: auto_null
```

Wi-Fi driver/module evidence exists, but no wireless interface is exposed:

```text
/sys/module/wlan
wlan_hdd_state wlan major initialized
iw dev produced no interface
/sys/class/net only shows usb0 and virtual links
```

Bluetooth is present only as an rfkill entry and is blocked:

```text
bt_power: Bluetooth
Soft blocked: yes
Hard blocked: no
```

Remoteproc sysfs is missing in this kernel/userspace view:

```text
ls: /sys/class/remoteproc: No such file or directory
```

Subsystem device nodes exist for ADSP/CDSP/SLPI/Venus/WLAN/etc., but QRTR and
RMTFS nodes are absent:

```text
/dev/subsys_adsp
/dev/subsys_cdsp
/dev/subsys_slpi
/dev/subsys_venus
/dev/subsys_wlan
ls: /dev/rmtfs*: No such file or directory
ls: /dev/qrtr*: No such file or directory
```

Video codec firmware is missing:

```text
venus: Failed to locate venus.mdt
Failed to load Venus FW
```

One OpenRC service is crashed:

```text
powerkey [crashed]
```

## Interpretation

The port is progressing beyond the boot milestone. The current v27 state has a
stable persistent rootfs, USB networking, SSH, storage, CPU, memory, battery,
thermal reporting, input enumeration, camera node enumeration, and DRM/KGSL
kernel bring-up.

The main blockers are now normal hardware enablement tasks:

1. Display userspace takeover: start or package a minimal compositor/test so the
   panel leaves continuous splash.
2. Firmware/userspace services: add or expose missing firmware and daemons for
   Venus, ADSP/audio, WLAN/BT, QRTR/RMTFS, and modem-adjacent services.
3. Audio: investigate missing ALSA card after ADSP/audio firmware and services
   are in place.
4. Wi-Fi/BT: investigate why CNSS/WLAN initializes but no netdev appears, and
   unblock/initialize Bluetooth after firmware/service work.
5. Camera: defer functional camera testing until firmware and media userspace
   dependencies are clearer.
