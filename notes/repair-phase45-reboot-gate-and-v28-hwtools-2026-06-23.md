# Repair Phase 45: Reboot Gate and v28 Hardware Tools

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Reboot stability check

Goal:

Reboot the persistent v27 install once and verify that USB/RNDIS, SSH, rootfs,
and display nodes return cleanly.

Result:

The reboot could not be triggered from the current SSH user.

Observed:

```text
sudo -n reboot
sudo: interactive authentication is required

/sbin/reboot
reboot: Operation not permitted

root@172.16.42.1
Permission denied

dbus-send org.freedesktop.login1.Manager.Reboot
Error org.freedesktop.DBus.Error.AccessDenied: Permission denied
```

`loginctl reboot` returned without a useful error, but did not reboot the
device. SSH never dropped and the device uptime continued increasing.

Current blocker:

The `lmi` account is in `wheel`, but does not have non-interactive reboot
permission. Root SSH is not available. The current debug channel cannot safely
trigger a reboot without either:

1. a physical reboot by the operator;
2. a known password for interactive sudo; or
3. a deliberate rootfs change that grants a narrow passwordless reboot action.

No partition was written and no reboot occurred during this phase.

## Hardware enablement start

The v27 rootfs has Mesa/DRM runtime libraries, but lacks the direct tools needed
to test display userspace takeover:

```text
present: libdrm, mesa, mesa-dri-gallium, mesa-egl, mesa-gbm, mesa-gl, mesa-gles
missing: weston, kmscube, modetest, drm_info, tinydm, sway, cage
```

Device-side APK index files are not cached, so online package installation on
the phone is not the right next step. The safer path is to build a new rootfs
that includes hardware validation tools.

## v28 package change

`artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD` was prepared for a v28
hardware-tools rootfs:

```text
pkgrel=4
alsa-utils
bluez
bluez-deprecated
iw
kmscube
libdrm-tests
mesa-demos
mesa-utils
tinydm
weston
wpa_supplicant
```

Purpose:

- display: `kmscube`, `libdrm-tests`, `mesa-demos`, `mesa-utils`, `weston`,
  `tinydm`;
- sound and microphone: `alsa-utils`;
- Wi-Fi: `iw`, `wpa_supplicant`;
- Bluetooth: `bluez`, `bluez-deprecated`.

Package names were checked with:

```text
pmbootstrap chroot -- apk search -x ...
```

## New scripts

Added:

```text
scripts/29_display_userspace_probe.sh
scripts/30_build_pmos_v28_hwtools.sh
```

`29_display_userspace_probe.sh` is a device-side read-only probe for DRM/KMS,
display tools, processes, and focused dmesg.

`30_build_pmos_v28_hwtools.sh` builds and exports a v28 hardware-tools boot and
userdata image set. It does not flash or reboot the phone.

## Next step

Before claiming reboot stability, perform one of these:

1. operator physically reboots the phone, then run the post-reboot SSH check; or
2. explicitly approve and implement a narrow passwordless reboot rule for `lmi`.

After that, build v28 hardware-tools and test display takeover first.
