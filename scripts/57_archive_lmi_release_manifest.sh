#!/usr/bin/env bash
set -euo pipefail

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
output=${LMI_RELEASE_ARCHIVE_MANIFEST:-docs/release/lmi-r6-bootmem-release-manifest-20260624.md}
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}

for path in "$bundle_dir/SHA256SUMS" "$bundle_dir/README.txt" "$bundle_dir/PERSISTENT_FLASH_PLAN.txt"; do
	[ -f "$path" ] || {
		echo "missing bundle metadata: $path" >&2
		exit 2
	}
done

mkdir -p "$(dirname "$output")"

size_of() {
	local path=$1
	if [ -f "$path" ]; then
		stat -c '%s' "$path"
	else
		printf 'missing'
	fi
}

sha_of() {
	local path=$1
	if [ -f "$path" ]; then
		sha256sum "$path" | awk '{print $1}'
	else
		printf 'missing'
	fi
}

plan_status=$(sed -n 's/^plan: //p' "$bundle_dir/PERSISTENT_FLASH_PLAN.txt" | tail -n 1)
is_userspace=$(sed -n 's/^  is-userspace=//p' "$bundle_dir/PERSISTENT_FLASH_PLAN.txt" | head -n 1)
product=$(sed -n 's/^  product=//p' "$bundle_dir/PERSISTENT_FLASH_PLAN.txt" | head -n 1)
unlocked=$(sed -n 's/^  unlocked=//p' "$bundle_dir/PERSISTENT_FLASH_PLAN.txt" | head -n 1)

case "${plan_status:-}" in
	READY_FOR_FASTBOOTD_PREFLIGHT)
		gate_note="The expected current state is \`READY_FOR_FASTBOOTD_PREFLIGHT\`. The fastbootd read-only gate has passed, but no flash should be attempted without fresh exact approval for the selected stage."
		;;
	*)
		gate_note="The expected current state is \`WAITING_FOR_RECOVERY_FASTBOOTD\`. No flash should be attempted while \`is-userspace=no\` unless a separately approved rollback decision explicitly chooses bootloader fastboot."
		;;
esac

cat > "$output" <<EOF
# Xiaomi lmi r6 bootmem release manifest - 2026-06-24

This is a lightweight repository archive of the host-side release bundle. Large
images are intentionally not committed to git; use the paths and hashes below to
identify the exact artifacts in the local release bundle.

## Bundle

- Bundle path: \`$bundle_dir\`
- Plan report: \`$bundle_dir/PERSISTENT_FLASH_PLAN.txt\`
- Command sheet: \`$bundle_dir/APPROVAL_REQUIRED_COMMANDS.txt\`
- Rollback scan: \`$bundle_dir/ROLLBACK_BOOT_CANDIDATES.txt\`

## Current Gate Status

- Product: \`${product:-unknown}\`
- Unlocked: \`${unlocked:-unknown}\`
- is-userspace: \`${is_userspace:-unknown}\`
- Persistent route plan: \`${plan_status:-unknown}\`

$gate_note

## Bundle SHA256SUMS

\`\`\`text
$(cat "$bundle_dir/SHA256SUMS")
\`\`\`

## Bundle File Sizes

| File | Size bytes |
| --- | ---: |
| \`boot-linux-copydown-lmi-r6-bootmem.img\` | $(size_of "$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img") |
| \`boot-linux-copydown-lmi-r6-bootmem.manifest\` | $(size_of "$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest") |
| \`xiaomi-lmi-r6-bootmem.img\` | $(size_of "$bundle_dir/xiaomi-lmi-r6-bootmem.img") |
| \`pmbootstrap-direct-boot-r6-bootmem.img\` | $(size_of "$bundle_dir/pmbootstrap-direct-boot-r6-bootmem.img") |
| \`vmlinuz-r6-bootmem\` | $(size_of "$bundle_dir/vmlinuz-r6-bootmem") |
| \`sm8250-xiaomi-lmi-r6-bootmem.dtb\` | $(size_of "$bundle_dir/sm8250-xiaomi-lmi-r6-bootmem.dtb") |
| \`initramfs-r6-bootmem\` | $(size_of "$bundle_dir/initramfs-r6-bootmem") |

## Rollback Boot Candidate

- Path: \`$rollback_boot\`
- SHA256: \`$(sha_of "$rollback_boot")\`
- Size bytes: \`$(size_of "$rollback_boot")\`

This rollback image is a candidate, not a proven guarantee, until matched to the
exact ROM/device state and tested as part of recovery.

## Read-Only Regeneration

\`\`\`sh
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/56_lmi_persistent_flash_plan.sh --quick
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/49_generate_lmi_flash_command_sheet.sh
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/57_archive_lmi_release_manifest.sh
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/58_generate_lmi_execution_checklist.sh
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/64_audit_lmi_persistent_readiness.sh
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/66_wait_and_audit_lmi_fastbootd.sh --quick
scripts/67_summarize_lmi_post_boot_evidence.sh
\`\`\`

Single-command refresh:

\`\`\`sh
LMI_ROLLBACK_BOOT_IMG="$rollback_boot" scripts/62_refresh_lmi_release_docs.sh --quick
\`\`\`

## Approval-Required Hardware Commands

These commands are listed for review only. They still require fresh exact
approval immediately before execution.

\`\`\`sh
fastboot reboot fastboot
scripts/60_stage_lmi_enter_fastbootd.sh --dry-run
scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
scripts/61_stage_lmi_reboot_after_flash.sh --dry-run
scripts/55_stage_lmi_rollback_boot.sh --execute
\`\`\`

Do not touch \`super\`, \`dtbo\`, \`vbmeta\`, \`persist\`,
modem/EFS/calibration partitions, \`vendor_boot\`, \`init_boot\`, or bootloader
lock state as part of this experiment.
EOF

echo "release archive manifest: $output"
