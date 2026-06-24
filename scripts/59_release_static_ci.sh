#!/usr/bin/env bash
set -euo pipefail

max_tracked_file_bytes=${LMI_MAX_TRACKED_FILE_BYTES:-10485760}

echo "release static CI: shell syntax"
while IFS= read -r script; do
	echo "  bash -n $script"
	bash -n "$script"
done < <(git ls-files 'scripts/*.sh' | sort)

echo "release static CI: python syntax"
while IFS= read -r script; do
	echo "  compile $script"
	python3 - "$script" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text()
compile(source, str(path), "exec")
PY
done < <(git ls-files 'scripts/*.py' | sort)

echo "release static CI: release docs"
manifest=docs/release/lmi-r6-bootmem-release-manifest-20260624.md
checklist=docs/release/lmi-r6-bootmem-execution-checklist-20260624.md
handoff=docs/release/lmi-r6-current-handoff-20260624.md
readme=README.md
automation_doc=docs/mainline-automation-loop-20260624.md

for path in "$manifest" "$checklist" "$handoff" "$readme" "$automation_doc"; do
	[ -f "$path" ] || {
		echo "missing release doc: $path" >&2
		exit 1
	}
done

grep -Eq 'WAITING_FOR_RECOVERY_FASTBOOTD|READY_FOR_FASTBOOTD_PREFLIGHT' "$manifest"
grep -Eq 'WAITING_FOR_RECOVERY_FASTBOOTD|READY_FOR_FASTBOOTD_PREFLIGHT' "$checklist"
grep -Eq 'WAITING_FOR_RECOVERY_FASTBOOTD|READY_FOR_FASTBOOTD_PREFLIGHT' "$handoff"
grep -Eq 'is-userspace: `(no|yes|unknown)`' "$manifest"
grep -Eq 'is-userspace: `(no|yes|unknown)`' "$checklist"
grep -Eq 'is-userspace: `(no|yes|unknown)`' "$handoff"
grep -q 'scripts/62_refresh_lmi_release_docs.sh --quick' "$manifest"
grep -q 'scripts/62_refresh_lmi_release_docs.sh --quick' "$handoff"
grep -q 'scripts/64_audit_lmi_persistent_readiness.sh' "$manifest"
grep -q 'scripts/64_audit_lmi_persistent_readiness.sh' "$checklist"
grep -q 'scripts/66_wait_and_audit_lmi_fastbootd.sh' "$manifest"
grep -q 'scripts/66_wait_and_audit_lmi_fastbootd.sh' "$checklist"
grep -q 'scripts/66_wait_and_audit_lmi_fastbootd.sh' "$handoff"
grep -q 'scripts/67_summarize_lmi_post_boot_evidence.sh' "$manifest"
grep -q 'scripts/68_mainline_progress_loop.sh' "$automation_doc"
grep -q 'scripts/69_audit_lmi_resources.sh' "$automation_doc"
grep -q 'scripts/68_mainline_progress_loop.sh --once --quick' "$readme"
grep -q 'scripts/69_audit_lmi_resources.sh --network' "$readme"
grep -q 'fastbootd audit gate: OK' "$handoff"
grep -q 'scripts/64_audit_lmi_persistent_readiness.sh' scripts/49_generate_lmi_flash_command_sheet.sh
grep -q 'scripts/66_wait_and_audit_lmi_fastbootd.sh' scripts/49_generate_lmi_flash_command_sheet.sh
grep -q 'scripts/67_summarize_lmi_post_boot_evidence.sh' scripts/49_generate_lmi_flash_command_sheet.sh
grep -q 'fastbootd audit gate: OK' scripts/49_generate_lmi_flash_command_sheet.sh
grep -q 'RAM-only boot is no longer a prerequisite' "$handoff"
grep -q 'guarded recovery-fastbootd persistent test' "$handoff"
grep -q 'RAM-only boot is optional' "$readme"
grep -q 'Mainline/copydown r6 persistent test is staged, not flashed' "$readme"
grep -q 'downstream v27 xiaomi-lmi baseline' "$readme"
if grep -q '^- HEAD:' "$handoff"; then
	echo "handoff should not archive a self-referential commit hash" >&2
	exit 1
fi
grep -Eq 'fastboot reboot fastboot|scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute' "$checklist"
grep -q 'scripts/60_stage_lmi_enter_fastbootd.sh --dry-run' "$checklist"
grep -Eq 'scripts/60_stage_lmi_enter_fastbootd.sh --execute|scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute' "$handoff"
grep -q 'scripts/61_stage_lmi_reboot_after_flash.sh --execute' "$checklist"
grep -q 'scripts/67_summarize_lmi_post_boot_evidence.sh' "$checklist"
grep -q 'Do not touch `super`' "$manifest"
grep -q 'Do not write `super`' "$checklist"

echo "release static CI: lmi release safety lint"
scripts/65_lmi_release_safety_lint.sh

echo "release static CI: tracked file size"
oversized=0
while IFS= read -r path; do
	size=$(stat -c '%s' "$path")
	if [ "$size" -gt "$max_tracked_file_bytes" ]; then
		echo "tracked file too large: $path ($size bytes > $max_tracked_file_bytes)" >&2
		oversized=1
	fi
done < <(git ls-files)

if [ "$oversized" -ne 0 ]; then
	exit 1
fi

echo "release static CI: no tracked release image payloads"
if git ls-files | grep -E '(^|/)(boot-linux-copydown-lmi-r6-bootmem\.img|xiaomi-lmi-r6-bootmem\.img|pmbootstrap-direct-boot-r6-bootmem\.img|vmlinuz-r6-bootmem|initramfs-r6-bootmem|sm8250-xiaomi-lmi-r6-bootmem\.dtb)$'; then
	echo "release payload file is tracked; keep large/generated payloads out of git" >&2
	exit 1
fi

echo "release static CI: OK"
