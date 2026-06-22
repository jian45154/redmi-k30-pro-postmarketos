#!/bin/sh
set -eu

echo "=== alive ==="
date
uname -a
id

echo "=== mounts ==="
findmnt / /boot -o SOURCE,FSTYPE,TARGET 2>/dev/null || true

echo "=== sshd ==="
ps aux | grep sshd | grep -v grep || true

echo "=== display_nodes ==="
ls -l /dev/fb* /dev/dri 2>/dev/null || true

echo "=== graphics_ps ==="
ps aux | grep -E 'weston|sway|tinydm|lightdm|xorg|Xorg|seatd|elogind|dbus' | grep -v grep || true

echo "=== dmesg_display_tail ==="
dmesg | grep -Ei 'drm|msm|dsi|panel|fb|gpu|adreno|kgsl|firmware' | tail -120 || true
