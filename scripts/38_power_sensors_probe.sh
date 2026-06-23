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

read_file() {
	file=$1
	[ -e "$file" ] || return 0
	printf "%s=" "$file"
	cat "$file" 2>/dev/null | tr '\n' ' ' || true
	echo
}

section "identity"
run date
run uname -a
run uptime
run cat /proc/cmdline

section "power supply inventory"
run ls -l /sys/class/power_supply
for d in /sys/class/power_supply/*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in \
		type scope status health present online capacity capacity_raw \
		voltage_now voltage_avg voltage_max voltage_min \
		current_now current_avg constant_charge_current \
		charge_now charge_full charge_full_design charge_counter \
		energy_now energy_full temp technology cycle_count \
		usb_type real_type input_current_limit current_max voltage_max_design \
		charge_behaviour charge_control_limit charge_control_limit_max \
		charging_enabled; do
		read_file "$d/$f"
	done
done

section "type-c and usb power state"
run find /sys/class/typec -maxdepth 3 -type f 2>/dev/null
for f in $(find /sys/class/typec -maxdepth 3 -type f 2>/dev/null | sort); do
	read_file "$f"
done
run find /sys/class/usb_power_delivery -maxdepth 4 -type f 2>/dev/null
for f in $(find /sys/class/usb_power_delivery -maxdepth 4 -type f 2>/dev/null | sort); do
	read_file "$f"
done

section "iio devices"
run ls -l /sys/bus/iio/devices
for d in /sys/bus/iio/devices/iio:device*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	read_file "$d/name"
	run find "$d" -maxdepth 1 -type f
	for f in "$d"/in_*_raw "$d"/in_*_input "$d"/in_*_scale "$d"/in_*_offset "$d"/in_*_label; do
		read_file "$f"
	done
done

section "thermal zones"
run ls -l /sys/class/thermal
for d in /sys/class/thermal/thermal_zone*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in type temp mode policy trip_point_0_type trip_point_0_temp; do
		read_file "$d/$f"
	done
done

section "cooling devices"
for d in /sys/class/thermal/cooling_device*; do
	[ -d "$d" ] || continue
	echo "--- $d"
	for f in type cur_state max_state; do
		read_file "$d/$f"
	done
done

section "sensor related platform nodes"
run find /sys/bus/platform/devices -maxdepth 1 \
	\( -iname '*sensor*' -o -iname '*ssc*' -o -iname '*slpi*' -o -iname '*qmi-ts*' -o -iname '*vadc*' -o -iname '*adc*' \) \
	-ls 2>/dev/null
run ls -l /sys/class/remoteproc /dev/subsys_slpi /dev/adsprpc-smd /dev/adsprpc-smd-secure /dev/ion 2>/dev/null
run ps aux

section "input sensor candidates"
run cat /proc/bus/input/devices
run find /dev/input -maxdepth 1 -type c -ls 2>/dev/null

section "focused dmesg"
dmesg | grep -Ei 'power_supply|battery|bms|fg|smb|charger|charging|bq2597|type.?c|tcpm|pdphy|usbpd|thermal|tsens|vadc|iio|adc|sensor|sensors|ssc|slpi|proximity|acceler|gyro|magnet|als|light|qmi-ts|fail|error|timeout|defer' || true
