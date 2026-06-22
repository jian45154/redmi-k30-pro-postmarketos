#!/bin/sh
set -eu

section() {
	echo
	echo "=== $1 ==="
}

run() {
	echo "\$ $*"
	"$@" 2>&1 || true
}

section "display nodes"
run id
run uname -a
run ls -l /dev/dri /dev/kgsl-3d0 /sys/class/drm 2>/dev/null
for f in /sys/class/drm/*/status /sys/class/drm/*/modes /sys/class/drm/*/enabled /sys/class/drm/*/dpms; do
	[ -e "$f" ] || continue
	printf "%s=" "$f"
	cat "$f" 2>/dev/null || true
done

section "userspace tools"
for cmd in modetest kmscube weston weston-info tinydm sway cage drm_info fbset fbsplash; do
	if command -v "$cmd" >/dev/null 2>&1; then
		echo "$cmd=$(command -v "$cmd")"
	else
		echo "$cmd=<missing>"
	fi
done

section "package hints"
run apk info

section "drm probing"
if command -v modetest >/dev/null 2>&1; then
	run modetest -c
	run modetest -p
	run modetest -e
fi

if command -v drm_info >/dev/null 2>&1; then
	run drm_info
fi

section "processes"
run ps aux

section "focused dmesg"
dmesg | grep -Ei 'drm|dsi|panel|sde|mdss|kgsl|adreno|gpu|weston|kms|fb|splash|fail|error|denied' || true
