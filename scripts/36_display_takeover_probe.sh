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

cat_file() {
	path="$1"
	[ -e "$path" ] || return 0
	printf "%s=" "$path"
	cat "$path" 2>/dev/null || true
}

section "identity"
run date
run uname -a
run id

section "drm nodes"
run ls -l /dev/dri /dev/kgsl-3d0 /sys/class/drm 2>/dev/null
run find /dev/dri -maxdepth 2 -type l -o -type c 2>/dev/null

section "connector sysfs"
for f in /sys/class/drm/*/status /sys/class/drm/*/modes \
	/sys/class/drm/*/enabled /sys/class/drm/*/dpms; do
	cat_file "$f"
done

section "kms object state"
for f in /sys/kernel/debug/dri/0/name /sys/kernel/debug/dri/0/state \
	/sys/kernel/debug/dri/0/clients /sys/kernel/debug/dri/0/gem_names \
	/sys/kernel/debug/dri/0/gem_objects; do
	cat_file "$f"
done

section "gpu state"
for f in /sys/class/kgsl/kgsl-3d0/gpu_model \
	/sys/class/kgsl/kgsl-3d0/gpu_busy_percentage \
	/sys/class/kgsl/kgsl-3d0/devfreq/cur_freq \
	/sys/class/kgsl/kgsl-3d0/devfreq/available_frequencies; do
	cat_file "$f"
done

section "userspace tools"
for cmd in modetest kmscube weston weston-info tinydm sway cage drm_info \
	fbset fbsplash loginctl seatd dbus-run-session; do
	if command -v "$cmd" >/dev/null 2>&1; then
		echo "$cmd=$(command -v "$cmd")"
	else
		echo "$cmd=<missing>"
	fi
done

section "passive drm queries"
if command -v modetest >/dev/null 2>&1; then
	run modetest -M msm -c
	run modetest -M msm -p
	run modetest -M msm -e
	run modetest -c
	run modetest -p
fi
if command -v drm_info >/dev/null 2>&1; then
	run drm_info
fi

section "processes"
run ps aux

section "focused dmesg before active test"
dmesg | grep -Ei 'drm|dsi|panel|sde|mdss|kgsl|adreno|gpu|kms|fb|splash|fail|error|denied|timeout' | tail -240 || true

if [ "${DISPLAY_TAKEOVER_ACTIVE:-0}" = "1" ]; then
	section "active takeover attempts"
	echo "DISPLAY_TAKEOVER_ACTIVE=1: running short userspace KMS attempts."
	if command -v kmscube >/dev/null 2>&1; then
		run timeout 12 kmscube -D /dev/dri/card0
	fi
	if command -v weston >/dev/null 2>&1; then
		run timeout 18 weston --backend=drm-backend.so --tty=1 --idle-time=0
	fi
	section "focused dmesg after active test"
	dmesg | grep -Ei 'drm|dsi|panel|sde|mdss|kgsl|adreno|gpu|kms|weston|fb|splash|fail|error|denied|timeout' | tail -260 || true
else
	section "active takeover skipped"
	echo "Set DISPLAY_TAKEOVER_ACTIVE=1 only after hardware-action approval to run kmscube/weston."
fi
