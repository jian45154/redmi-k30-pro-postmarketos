#!/usr/bin/env bash
set -euo pipefail

bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
output=${LMI_EXECUTION_CHECKLIST:-docs/release/lmi-r6-bootmem-execution-checklist-20260624.md}
boot_img=${LMI_COPYDOWN_BOOT_IMG:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img}
manifest=${LMI_COPYDOWN_MANIFEST:-$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest}
rootfs_img=${LMI_ROOTFS_IMG:-$bundle_dir/xiaomi-lmi-r6-bootmem.img}
rollback_boot=${LMI_ROLLBACK_BOOT_IMG:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img}
plan_report=${LMI_PERSISTENT_PLAN_REPORT:-$bundle_dir/PERSISTENT_FLASH_PLAN.txt}

for path in "$boot_img" "$manifest" "$rootfs_img" "$rollback_boot" "$plan_report"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

mkdir -p "$(dirname "$output")"

boot_sha=$(sha256sum "$boot_img" | awk '{print $1}')
rootfs_sha=$(sha256sum "$rootfs_img" | awk '{print $1}')
rollback_sha=$(sha256sum "$rollback_boot" | awk '{print $1}')
rollback_size=$(stat -c '%s' "$rollback_boot")

rootfs_token="flash-xiaomi-lmi-rootfs-${boot_sha:0:12}-${rootfs_sha:0:12}"
boot_token="flash-xiaomi-lmi-boot-${boot_sha:0:12}-${rootfs_sha:0:12}"
rollback_token="rollback-xiaomi-lmi-boot-${rollback_sha:0:16}-${rollback_size}"

plan_status=$(sed -n 's/^plan: //p' "$plan_report" | tail -n 1)
product=$(sed -n 's/^  product=//p' "$plan_report" | head -n 1)
unlocked=$(sed -n 's/^  unlocked=//p' "$plan_report" | head -n 1)
is_userspace=$(sed -n 's/^  is-userspace=//p' "$plan_report" | head -n 1)

cat > "$output" <<EOF
# Xiaomi lmi r6 bootmem execution checklist - 2026-06-24

This checklist is a compact handoff for the current persistent fastbootd route.
It is not an approval and does not make any hardware command safe by itself.

## Current State

- Product: \`${product:-unknown}\`
- Unlocked: \`${unlocked:-unknown}\`
- is-userspace: \`${is_userspace:-unknown}\`
- Route plan: \`${plan_status:-unknown}\`
- Bundle: \`$bundle_dir\`

Current blocker: the phone is in bootloader fastboot, not recovery fastbootd.

## Artifact Identity

- Boot image: \`$boot_img\`
- Boot SHA256: \`$boot_sha\`
- Rootfs image: \`$rootfs_img\`
- Rootfs SHA256: \`$rootfs_sha\`
- Copydown manifest: \`$manifest\`
- Rollback boot: \`$rollback_boot\`
- Rollback SHA256: \`$rollback_sha\`

## Next Approval Boundary

The next hardware-state command requiring fresh exact approval is:

\`\`\`sh
fastboot reboot fastboot
\`\`\`

Use the guarded stage helper for dry-run review:

\`\`\`sh
scripts/60_stage_lmi_enter_fastbootd.sh --dry-run
\`\`\`

After that command, run the read-only wait/preflight:

\`\`\`sh
scripts/52_wait_lmi_fastbootd.sh
\`\`\`

Do not flash unless the resulting preflight reports \`is-userspace=yes\`.

## Stage Tokens

These tokens are derived from the current artifact hashes.

\`\`\`text
rootfs:   LMI_FLASH_CONFIRM=$rootfs_token
boot:     LMI_FLASH_CONFIRM=$boot_token
rollback: LMI_ROLLBACK_CONFIRM=$rollback_token
fastbootd: LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi
test reboot: LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi
\`\`\`

## Persistent Test Order

Each execute command still requires separate fresh exact approval immediately
before use.

1. Enter recovery fastbootd:

   \`\`\`sh
   LMI_FASTBOOTD_REBOOT_CONFIRM=enter-fastbootd-xiaomi-lmi scripts/60_stage_lmi_enter_fastbootd.sh --execute
   \`\`\`

2. Wait for fastbootd and run read-only preflight:

   \`\`\`sh
   scripts/52_wait_lmi_fastbootd.sh
   \`\`\`

3. Flash rootfs to \`userdata\` only if userdata destruction is accepted:

   \`\`\`sh
   LMI_FLASH_CONFIRM=$rootfs_token scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
   \`\`\`

4. Flash the copydown boot image to \`boot\`:

   \`\`\`sh
   LMI_FLASH_CONFIRM=$boot_token scripts/53_stage_lmi_fastbootd_flash.sh --stage boot --execute
   \`\`\`

5. Reboot only after separate approval:

   \`\`\`sh
   LMI_TEST_REBOOT_CONFIRM=reboot-flashed-xiaomi-lmi scripts/61_stage_lmi_reboot_after_flash.sh --execute
   \`\`\`

6. Collect post-boot evidence:

   \`\`\`sh
   scripts/54_monitor_lmi_post_boot.sh --timeout 180
   \`\`\`

## Rollback Boundary

Rollback boot write also requires fresh exact approval:

\`\`\`sh
LMI_ROLLBACK_CONFIRM=$rollback_token scripts/55_stage_lmi_rollback_boot.sh --execute
\`\`\`

By default rollback execute mode requires recovery fastbootd. Using
\`LMI_ROLLBACK_ALLOW_BOOTLOADER_FASTBOOT=1\` is a separate recovery decision if
fastbootd cannot be reached.

## Forbidden In This Route

Do not write \`super\`, \`dtbo\`, \`vbmeta\`, \`persist\`,
modem/EFS/calibration partitions, \`vendor_boot\`, \`init_boot\`, or bootloader
lock state.
EOF

echo "execution checklist: $output"
