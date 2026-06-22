# Repair Phase 42: v27 Persistent Boot Display Observation

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## User-visible symptom

After persistent v27 boot was written and `fastboot reboot` was executed, the
phone screen appeared to remain on the Redmi logo.

## Host-side result

The device was not stuck at boot. Host-side checks showed:

```text
USB\VID_0525&PID_A4A2\POSTMARKETOS
Remote NDIS based Internet Sharing Device
Host IPv4: 172.16.42.2/24
Device ping: 172.16.42.1 reachable
SSH port 22: open
```

## Device-side result

SSH login succeeded. The system was alive and running the v27 kernel/userspace:

```text
Linux xiaomi-lmi 4.19.325-cip128-st12-perf #7-postmarketOS
sshd.pam listener running
```

Display device nodes exist:

```text
/dev/dri/card0
/dev/dri/renderD128
```

Kernel display logs show the panel and DRM stack initialized:

```text
Successfully bind display panel 'qcom,mdss_dsi_j11_38_08_0a_fhd_cmd'
Initialized msm_drm 1.3.0
cont_splash enabled in 1 of 1 display(s)
```

No graphical compositor was observed:

```text
no weston/sway/tinydm/lightdm/Xorg process observed
```

## Interpretation

The device is booted and reachable. The Redmi logo remains visible because the
display stack has not switched away from the bootloader continuous splash. This
is now a display/userspace graphics milestone, not a boot/rootfs/SSH blocker.

Next work should focus on either starting a simple compositor/framebuffer test
or disabling/replacing continuous splash handling so the running Linux userspace
visibly takes over the panel.
