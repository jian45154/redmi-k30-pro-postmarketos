#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
log=${LOG:-$repo/logs/pmaports-build-v33-downstream-sshwifi-20260624.txt}
interval=${INTERVAL:-30}
iterations=${ITERATIONS:-0}
adb_win=${ADB_WIN:-/mnt/c/Program Files/platform-tools/adb.exe}
fastboot_win=${FASTBOOT_WIN:-/mnt/c/Program Files/platform-tools/fastboot.exe}

count=0
while :; do
	count=$((count + 1))
	printf '\n=== downstream sidecar %s iteration=%s ===\n' \
		"$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$count"

	if [ -f "$log" ]; then
		printf '\n--- build log tail: %s ---\n' "$log"
		tail -n 40 "$log" || true
	else
		printf '\n--- build log missing: %s ---\n' "$log"
	fi

	printf '\n--- WSL fastboot ---\n'
	timeout 5 fastboot devices 2>&1 || true

	printf '\n--- WSL adb ---\n'
	timeout 5 adb devices 2>&1 || true

	printf '\n--- Windows USB/IP ---\n'
	timeout 8 usbipd.exe list 2>&1 || true

	if [ -x "$adb_win" ]; then
		printf '\n--- Windows adb ---\n'
		timeout 8 "$adb_win" devices 2>&1 || true
	fi

	if [ -x "$fastboot_win" ]; then
		printf '\n--- Windows fastboot ---\n'
		timeout 8 "$fastboot_win" devices 2>&1 || true
	fi

	if [ "$iterations" -gt 0 ] && [ "$count" -ge "$iterations" ]; then
		exit 0
	fi
	sleep "$interval"
done
