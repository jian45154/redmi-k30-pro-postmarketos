#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/54_monitor_lmi_post_boot.sh [--timeout SECONDS] [--interval SECONDS] [--collect-telnet-log]

Poll read-only host/device observations after an approved boot or reboot:
- fastboot devices
- adb devices
- ip -br addr
- TCP reachability to postmarketOS telnet/SSH debug ports

By default it does not send commands to the device. With --collect-telnet-log,
it sends read-only telnet debug-shell commands to collect /pmOS_init.log and
basic early-boot state if 172.16.42.1:23 is reachable.
EOF
}

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
report=${LMI_POST_BOOT_REPORT:-$bundle_dir/POST_BOOT_MONITOR.txt}
fastboot_bin=${FASTBOOT:-fastboot}
fastboot_timeout=${LMI_FASTBOOT_TIMEOUT:-5}
adb_bin=${ADB:-adb}
adb_timeout=${LMI_ADB_TIMEOUT:-5}
pmos_host=${LMI_PMOS_HOST:-172.16.42.1}
timeout_s=${LMI_POST_BOOT_TIMEOUT:-180}
interval_s=${LMI_POST_BOOT_INTERVAL:-3}
collect_telnet_log=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--timeout)
			timeout_s=${2:-}
			shift 2
			;;
		--interval)
			interval_s=${2:-}
			shift 2
			;;
		--collect-telnet-log)
			collect_telnet_log=1
			shift
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown argument: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

mkdir -p "$(dirname "$report")"

log() {
	printf '%s\n' "$*" | tee -a "$report"
}

run_capture() {
	local label=$1
	shift
	log "## $label"
	if "$@" >> "$report" 2>&1; then
		log "status=0"
	else
		local status=$?
		log "status=$status"
	fi
}

tcp_probe() {
	local host=$1
	local port=$2
	if command -v nc >/dev/null 2>&1; then
		timeout 2 nc -z "$host" "$port" >/dev/null 2>&1
	else
		timeout 2 bash -c "</dev/tcp/$host/$port" >/dev/null 2>&1
	fi
}

collect_telnet() {
	if ! command -v nc >/dev/null 2>&1; then
		log "telnet-log: skipped because nc is unavailable"
		return
	fi
	log "## telnet debug-shell read-only collection"
	{
		printf 'cat /pmOS_init.log\n'
		printf 'printf "\\n--- cmdline ---\\n"\n'
		printf 'cat /proc/cmdline\n'
		printf 'printf "\\n--- partitions ---\\n"\n'
		printf 'cat /proc/partitions\n'
		printf 'printf "\\n--- mounts ---\\n"\n'
		printf 'mount\n'
		printf 'printf "\\n--- network ---\\n"\n'
		printf 'ip addr\n'
	} | timeout 8 nc "$pmos_host" 23 >> "$report" 2>&1 || log "telnet-log: collection command failed"
}

: > "$report"
log "LMI post-boot monitor"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "timeout_s=$timeout_s"
log "interval_s=$interval_s"
log "pmos_host=$pmos_host"
log "collect_telnet_log=$collect_telnet_log"
log
log "No reboot, boot, flash, erase, format, or partition write is executed by this script."
log

deadline=$((SECONDS + timeout_s))
attempt=0
seen_telnet=0
seen_ssh=0
seen_adb=0
seen_fastboot=0

while [ "$SECONDS" -le "$deadline" ]; do
	attempt=$((attempt + 1))
	log "== attempt=$attempt seconds=$SECONDS =="

	fastboot_devices=$(timeout "$fastboot_timeout" "$fastboot_bin" devices 2>&1 || true)
	adb_devices=$(timeout "$adb_timeout" "$adb_bin" devices 2>&1 || true)
	ip_br=$(ip -br addr 2>&1 || true)

	if [ -n "$fastboot_devices" ]; then
		seen_fastboot=1
		printf '%s\n' "$fastboot_devices" | sed 's/^/fastboot: /' | tee -a "$report"
	else
		log "fastboot: <none>"
	fi

	if printf '%s\n' "$adb_devices" | awk 'NR > 1 && $2 == "device" { found=1 } END { exit found ? 0 : 1 }'; then
		seen_adb=1
	fi
	printf '%s\n' "$adb_devices" | sed 's/^/adb: /' | tee -a "$report"

	printf '%s\n' "$ip_br" | sed 's/^/ip: /' | tee -a "$report"

	if tcp_probe "$pmos_host" 23; then
		seen_telnet=1
		log "tcp:$pmos_host:23 reachable"
	else
		log "tcp:$pmos_host:23 unreachable"
	fi

	if tcp_probe "$pmos_host" 2222; then
		seen_ssh=1
		log "tcp:$pmos_host:2222 reachable"
	else
		log "tcp:$pmos_host:2222 unreachable"
	fi

	log

	if [ "$seen_telnet" -eq 1 ]; then
		if [ "$collect_telnet_log" -eq 1 ]; then
			collect_telnet
		fi
		break
	fi

	if [ "$SECONDS" -le "$deadline" ]; then
		sleep "$interval_s"
	fi
done

run_capture "final fastboot product" timeout "$fastboot_timeout" "$fastboot_bin" getvar product
run_capture "final fastboot is-userspace" timeout "$fastboot_timeout" "$fastboot_bin" getvar is-userspace

log
log "summary:"
log "seen_fastboot=$seen_fastboot"
log "seen_adb=$seen_adb"
log "seen_telnet_23=$seen_telnet"
log "seen_ssh_2222=$seen_ssh"
log "report=$report"

if [ "$seen_telnet" -eq 1 ] || [ "$seen_ssh" -eq 1 ] || [ "$seen_adb" -eq 1 ]; then
	log "post-boot monitor: observed a higher-level interface"
	exit 0
fi

if [ "$seen_fastboot" -eq 1 ]; then
	log "post-boot monitor: only fastboot observed"
	exit 1
fi

log "post-boot monitor: no lmi interface observed"
exit 1
