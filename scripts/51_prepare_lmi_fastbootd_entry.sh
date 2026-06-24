#!/usr/bin/env bash
set -euo pipefail

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
output=${LMI_FASTBOOTD_ENTRY_SHEET:-$bundle_dir/FASTBOOTD_ENTRY_REQUIRED.txt}
fastboot_bin=${FASTBOOT:-fastboot}
fastboot_timeout=${LMI_FASTBOOT_TIMEOUT:-5}
adb_bin=${ADB:-adb}
adb_timeout=${LMI_ADB_TIMEOUT:-5}

mkdir -p "$(dirname "$output")"

run_capture() {
	local cmd=$1
	shift
	set +e
	local out
	case "$cmd" in
		"$fastboot_bin")
			out=$(timeout "$fastboot_timeout" "$cmd" "$@" 2>&1)
			;;
		"$adb_bin")
			out=$(timeout "$adb_timeout" "$cmd" "$@" 2>&1)
			;;
		*)
			out=$("$cmd" "$@" 2>&1)
			;;
	esac
	local status=$?
	set -e
	printf '%s\n' "$out"
	return "$status"
}

fastboot_devices=$(run_capture "$fastboot_bin" devices || true)
adb_devices=$(run_capture "$adb_bin" devices || true)

fastboot_product=$(run_capture "$fastboot_bin" getvar product || true)
fastboot_unlocked=$(run_capture "$fastboot_bin" getvar unlocked || true)
fastboot_is_userspace=$(run_capture "$fastboot_bin" getvar is-userspace || true)

product=$(printf '%s\n' "$fastboot_product" | sed -n 's/^product: //p' | tail -n 1)
unlocked=$(printf '%s\n' "$fastboot_unlocked" | sed -n 's/^unlocked: //p' | tail -n 1)
is_userspace=$(printf '%s\n' "$fastboot_is_userspace" | sed -n 's/^is-userspace: //p' | tail -n 1)

recommended_command=""
recommended_reason=""
if printf '%s\n' "$fastboot_devices" | grep -q '[[:space:]]fastboot$'; then
	recommended_command="$fastboot_bin reboot fastboot"
	recommended_reason="device is currently visible in bootloader fastboot"
elif printf '%s\n' "$adb_devices" | awk 'NR > 1 && $2 == "device" { found=1 } END { exit !found }'; then
	recommended_command="$adb_bin reboot fastboot"
	recommended_reason="device is currently visible through adb"
else
	recommended_command="manual key sequence or recovery UI to enter fastbootd"
	recommended_reason="no usable adb or fastboot transport was detected"
fi

cat > "$output" <<EOF
Xiaomi lmi recovery fastbootd entry sheet

Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')

This file is not an approval. It records current read-only device state and
the command that would require fresh exact approval before execution.

Current fastboot devices:
$(printf '%s\n' "$fastboot_devices" | sed 's/^/  /')

Current adb devices:
$(printf '%s\n' "$adb_devices" | sed 's/^/  /')

Read-only fastboot getvar summary:
  product=${product:-}
  unlocked=${unlocked:-}
  is-userspace=${is_userspace:-}

Recommended next action:
  reason: $recommended_reason
  command: $recommended_command

Do not run the recommended command without fresh exact approval.

After entering recovery fastbootd, verify:
  fastboot getvar is-userspace

Required value:
  is-userspace: yes

Then rerun:
  LMI_COPYDOWN_BOOT_IMG=$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img \\
  LMI_COPYDOWN_MANIFEST=$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest \\
  LMI_ROOTFS_IMG=$bundle_dir/xiaomi-lmi-r6-bootmem.img \\
  scripts/48_preflight_lmi_fastbootd.sh

No reboot, boot, flash, erase, format, or partition write was executed by this
script.
EOF

echo "fastbootd entry sheet: $output"
echo "current is-userspace=${is_userspace:-}"
echo "recommended command requiring approval: $recommended_command"
