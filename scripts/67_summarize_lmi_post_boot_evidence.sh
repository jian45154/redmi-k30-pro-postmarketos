#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/67_summarize_lmi_post_boot_evidence.sh

Summarize post-boot evidence for the lmi r6 route from existing local reports.
This script is read-only: it does not contact the phone and does not execute
reboot, boot, flash, erase, format, or partition writes.
EOF
}

if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then
	usage
	exit 0
fi
if [ "$#" -ne 0 ]; then
	echo "unknown argument: $1" >&2
	usage >&2
	exit 2
fi

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
monitor=${LMI_POST_BOOT_REPORT:-$bundle_dir/POST_BOOT_MONITOR.txt}
readiness=${LMI_PERSISTENT_READINESS_REPORT:-$bundle_dir/PERSISTENT_READINESS_AUDIT.txt}
output=${LMI_POST_BOOT_EVIDENCE_SUMMARY:-$bundle_dir/POST_BOOT_EVIDENCE_SUMMARY.txt}

mkdir -p "$(dirname "$output")"

status_from_report() {
	local pattern=$1
	local path=$2
	if [ -f "$path" ] && grep -q "$pattern" "$path"; then
		printf 'yes'
	else
		printf 'no'
	fi
}

seen_fastboot=$(status_from_report '^seen_fastboot=1$' "$monitor")
seen_adb=$(status_from_report '^seen_adb=1$' "$monitor")
seen_telnet=$(status_from_report '^seen_telnet_23=1$' "$monitor")
seen_ssh=$(status_from_report '^seen_ssh_2222=1$' "$monitor")
readiness_ok=$(status_from_report '^failures=0$' "$readiness")
readiness_fastbootd=$(status_from_report '^route_status=READY_FOR_FASTBOOTD_PREFLIGHT$' "$readiness")
readiness_waiting=$(status_from_report '^route_status=WAITING_FOR_RECOVERY_FASTBOOTD$' "$readiness")

{
	echo "LMI post-boot evidence summary"
	echo "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	echo "bundle_dir=$bundle_dir"
	echo "monitor=$monitor"
	echo "readiness=$readiness"
	echo
	echo "No reboot, boot, flash, erase, format, or partition write is executed by this script."
	echo
	echo "observed_interfaces:"
	echo "  fastboot=$seen_fastboot"
	echo "  adb=$seen_adb"
	echo "  telnet_23=$seen_telnet"
	echo "  ssh_2222=$seen_ssh"
	echo
	echo "pre-boot_readiness:"
	echo "  readiness_failures_zero=$readiness_ok"
	echo "  readiness_ready_for_fastbootd_preflight=$readiness_fastbootd"
	echo "  readiness_waiting_for_fastbootd=$readiness_waiting"
	echo
	echo "milestones:"
	echo "  image_builds_reproducibly=known_from_release_manifest"
	echo "  bootloader_accepts_image=unproven_until_post_reboot_nonfastboot_or_boot_logs"
	if [ "$seen_telnet" = "yes" ]; then
		echo "  initramfs_starts=proven_by_telnet_23"
	else
		echo "  initramfs_starts=unproven"
	fi
	if [ "$seen_ssh" = "yes" ]; then
		echo "  stable_shell_reachable=proven_by_ssh_2222"
	elif [ "$seen_telnet" = "yes" ]; then
		echo "  stable_shell_reachable=debug_shell_only"
	else
		echo "  stable_shell_reachable=unproven"
	fi
	echo "  rootfs_found_and_mounted=requires_pmOS_init_log_or_shell_evidence"
	echo "  switch_root_completes=requires_shell_or_service_evidence"
	echo "  hardware_subsystems=not_tested_by_this_route"
	echo
	if [ "$seen_telnet" = "yes" ] || [ "$seen_ssh" = "yes" ] || [ "$seen_adb" = "yes" ]; then
		echo "summary=POST_BOOT_INTERFACE_OBSERVED"
	elif [ "$seen_fastboot" = "yes" ]; then
		echo "summary=ONLY_FASTBOOT_OBSERVED"
	else
		echo "summary=NO_DEVICE_INTERFACE_OBSERVED"
	fi
	echo "report=$output"
} | tee "$output"
