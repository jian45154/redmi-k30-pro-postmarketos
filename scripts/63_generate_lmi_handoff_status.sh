#!/usr/bin/env bash
set -euo pipefail

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
output=${LMI_HANDOFF_STATUS:-docs/release/lmi-r6-current-handoff-20260624.md}
plan_report=${LMI_PERSISTENT_PLAN_REPORT:-$bundle_dir/PERSISTENT_FLASH_PLAN.txt}
checklist=${LMI_EXECUTION_CHECKLIST:-docs/release/lmi-r6-bootmem-execution-checklist-20260624.md}
manifest=${LMI_RELEASE_ARCHIVE_MANIFEST:-docs/release/lmi-r6-bootmem-release-manifest-20260624.md}

for path in "$plan_report" "$checklist" "$manifest"; do
	[ -f "$path" ] || {
		echo "missing handoff input: $path" >&2
		exit 2
	}
done

mkdir -p "$(dirname "$output")"

branch=$(git rev-parse --abbrev-ref HEAD)
remote_url=$(git remote get-url origin 2>/dev/null || printf 'unknown')
plan_status=$(sed -n 's/^plan: //p' "$plan_report" | tail -n 1)
product=$(sed -n 's/^- Product: `\(.*\)`/\1/p' "$checklist" | head -n 1)
unlocked=$(sed -n 's/^- Unlocked: `\(.*\)`/\1/p' "$checklist" | head -n 1)
is_userspace=$(sed -n 's/^- is-userspace: `\(.*\)`/\1/p' "$checklist" | head -n 1)
boot_sha=$(sed -n 's/^- Boot SHA256: `\(.*\)`/\1/p' "$checklist" | head -n 1)
rootfs_sha=$(sed -n 's/^- Rootfs SHA256: `\(.*\)`/\1/p' "$checklist" | head -n 1)
rollback_sha=$(sed -n 's/^- Rollback SHA256: `\(.*\)`/\1/p' "$checklist" | head -n 1)

cat > "$output" <<EOF
# Xiaomi lmi r6 current handoff - 2026-06-24

This is the short handoff for the current \`edge\` mainline/copydown route. It
is not an approval to execute hardware commands.

## Repository

- Branch: \`$branch\`
- Remote: \`$remote_url\`

This tracked handoff intentionally does not record a commit hash because the
file is generated before the commit that archives it. Use \`git rev-parse HEAD\`
or the GitHub \`edge\` branch tip for the authoritative revision.

## Route Decision

RAM-only boot is no longer a prerequisite for this route. The current path is a
guarded recovery-fastbootd persistent test: enter fastbootd, verify
\`is-userspace=yes\`, flash only \`userdata\` rootfs and \`boot\`, then reboot and
collect evidence.

## Device Gate

- Product: \`${product:-unknown}\`
- Unlocked: \`${unlocked:-unknown}\`
- is-userspace: \`${is_userspace:-unknown}\`
- Route status: \`${plan_status:-unknown}\`

Current blocker: the device is still in bootloader fastboot. The next approved
hardware-state step must be entering recovery fastbootd.

## Exact Next Command Requiring Approval

\`\`\`sh
LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute
\`\`\`

After that, run:

\`\`\`sh
scripts/52_wait_lmi_fastbootd.sh
\`\`\`

Do not flash unless the wait/preflight result reports \`is-userspace=yes\`.

## Artifact Hashes

- Boot: \`$boot_sha\`
- Rootfs: \`$rootfs_sha\`
- Rollback boot candidate: \`$rollback_sha\`

## Canonical Local Reports

- Release manifest: \`$manifest\`
- Execution checklist: \`$checklist\`
- Plan report: \`$plan_report\`
- Refresh summary: \`$bundle_dir/RELEASE_REFRESH_SUMMARY.txt\`

## Refresh Command

\`\`\`sh
scripts/62_refresh_lmi_release_docs.sh --quick
\`\`\`

## Hard Safety Boundary

Do not run any \`fastboot flash\`, \`fastboot reboot\`, \`fastboot reboot
fastboot\`, \`pmbootstrap flasher flash_rootfs\`, erase, format, sideload, or
bootloader-lock command without fresh exact approval for that command.

Do not touch \`super\`, \`dtbo\`, \`vbmeta\`, \`persist\`,
modem/EFS/calibration partitions, \`vendor_boot\`, \`init_boot\`, or bootloader
lock state as part of this route.
EOF

echo "handoff status: $output"
