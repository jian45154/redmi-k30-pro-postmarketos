#!/usr/bin/env bash
set -euo pipefail

# Shared assertion vocabulary; this script uses the default exit-fast mode.
. "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/release_checks.sh"

max_tracked_file_bytes=${LMI_MAX_TRACKED_FILE_BYTES:-10485760}
known_good_kernel_apk=artifacts/lmi-p1/known-good-kernel/linux-xiaomi-lmi-4.19.325-r8-p1-known-good.apk
known_good_kernel_apk_size=17418891
known_good_kernel_apk_sha256=01b199611407c100c621599bd3060084c19e1fd90f8e9df64cc10966f6949eb0

echo "release static CI: shell syntax"
# The ':(glob)' pathspec with '**' is explicitly recursive: nested helpers
# such as scripts/lmi_p2_d114/*.sh are always covered. The sentinel check
# fails CI if the pattern ever stops matching the nested tree.
shell_scripts=$(git ls-files ':(glob)scripts/**/*.sh' | sort)
if ! printf '%s\n' "$shell_scripts" |
	grep -qx 'scripts/lmi_p2_d114/inject_rootfs_candidate.sh'; then
	echo "shell syntax coverage lost scripts/lmi_p2_d114/inject_rootfs_candidate.sh" >&2
	exit 1
fi
while IFS= read -r script; do
	[ -f "$script" ] || continue
	shebang=$(head -n 1 "$script")
	case $shebang in
		'#!/bin/sh'*|'#!/usr/bin/env sh'*)
			echo "  sh -n $script"
			sh -n "$script"
			;;
		*)
			echo "  bash -n $script"
			bash -n "$script"
			;;
	esac
done <<<"$shell_scripts"

echo "release static CI: python syntax"
python_scripts=$(git ls-files ':(glob)scripts/**/*.py' | sort)
if ! printf '%s\n' "$python_scripts" |
	grep -qx 'scripts/lmi_p1/common.py'; then
	echo "python syntax coverage lost scripts/lmi_p1/common.py" >&2
	exit 1
fi
while IFS= read -r script; do
	[ -f "$script" ] || continue
	echo "  compile $script"
	python3 - "$script" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text()
compile(source, str(path), "exec")
PY
done <<<"$python_scripts"

echo "release static CI: governance, installer, P1/P2/P2-D114/P3, six-row, and pin-registry host test suites"
for suite in governance lmi_installer lmi_p1 lmi_p2 lmi_p2_d114 lmi_p3 lmi_weston_sixrow release_pins; do
	echo "  unittest tests/$suite"
	python3 -m unittest discover -v -s "tests/$suite"
done

echo "release static CI: release pin cross-check"
python3 scripts/lmi_release_pins.py verify

echo "release static CI: release docs"
readme=README.md
ramboot_doc=docs/lmi-d110-session-approval.md
ramboot_helper=scripts/72_stage_downstream_ssh_wifi_test.sh
porting_guide=docs/porting-sm8250-downstream-to-postmarketos.md
porting_guide_zh=docs/porting-sm8250-downstream-to-postmarketos.zh.md
archive_manifest=docs/release/lmi-r6-bootmem-release-manifest-20260624.md
archive_checklist=docs/release/lmi-r6-bootmem-execution-checklist-20260624.md
archive_handoff=docs/release/lmi-r6-current-handoff-20260624.md
archive_migration=docs/lmi-mainline-migration-plan-20260623.md
archive_overlay=docs/lmi-mainline-overlay-build-20260623.md
archive_flash_boundary=docs/lmi-mainline-flash-boundary-20260624.md

# require_file, require_literal, and reject_literal come from
# scripts/lib/release_checks.sh (exit-fast mode).

reject_direct_fastboot_boot() {
	local path=$1
	if grep -Eq '(^[[:space:]]*|`)(sudo[[:space:]]+)?fastboot(\.exe)?[[:space:]]+boot[[:space:]]+[^[:space:]`]' "$path"; then
		printf 'unguarded direct fastboot boot command remains in active guide: %s\n' "$path" >&2
		exit 1
	fi
}

for path in \
	"$readme" \
	"$ramboot_doc" \
	"$ramboot_helper" \
	"$porting_guide" \
	"$porting_guide_zh" \
	"$archive_manifest" \
	"$archive_checklist" \
	"$archive_handoff" \
	"$archive_migration" \
	"$archive_overlay" \
	"$archive_flash_boundary"; do
	require_file "$path"
done

echo "  current guarded D110 RAM-boot contract"
authorize_command='scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --authorize-session'
execute_command='scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --execute'
require_literal "$readme" 'Do not pass an arbitrary export directly to `fastboot`.'
require_literal "$readme" "$authorize_command"
require_literal "$readme" "$execute_command"
require_literal "$readme" 'docs/lmi-d110-session-approval.md'
require_literal "$readme" 'never retries a failed boot automatically'
require_literal "$ramboot_doc" '--stage ramboot --authorize-session'
require_literal "$ramboot_doc" '--stage ramboot --execute'
require_literal "$ramboot_doc" '--stage ramboot --revoke-session'
require_literal "$porting_guide" "$authorize_command"
require_literal "$porting_guide" "$execute_command"
require_literal "$porting_guide" 'lmi-d110-session-approval.md'
require_literal "$porting_guide_zh" "$authorize_command"
require_literal "$porting_guide_zh" "$execute_command"
require_literal "$porting_guide_zh" 'lmi-d110-session-approval.md'
for active_guide in "$readme" "$porting_guide" "$porting_guide_zh"; do
	reject_direct_fastboot_boot "$active_guide"
done
reject_literal "$porting_guide" 'writes nothing'
reject_literal "$porting_guide_zh" '不写任何东西'
reject_literal "$porting_guide_zh" '不写任何分区'

echo "  archived mainline/r6 evidence boundary"
archive_warning='**Archived evidence — do not execute commands from this file.**'
require_literal "$readme" 'The mainline/copydown release records are still archived under `docs/release/`.'
require_literal "$readme" 'The `lmi-r6-current-handoff-20260624.md` file is older than the r6/r7 result'
require_literal "$readme" 'The mainline/copydown r6 checklist is historical evidence, not a current route.'
require_literal "$readme" 'Do not run its fastboot or flash commands.'
reject_literal "$readme" 'For the mainline/copydown r6 route, use the release checklist'
reject_literal "$readme" 'To refresh all local r6 release reports and docs'
for archive_doc in \
	docs/release/*.md \
	"$archive_migration" \
	"$archive_overlay" \
	"$archive_flash_boundary"; do
	require_literal "$archive_doc" "$archive_warning"
done
require_literal "$archive_manifest" 'Do not touch `super`'
require_literal "$archive_checklist" 'Do not write `super`'
if grep -q '^- HEAD:' "$archive_handoff"; then
	echo "archived handoff should not contain a self-referential commit hash" >&2
	exit 1
fi

echo "release static CI: P2-D114 hash consistency"
python3 -m scripts.lmi_p2_d114.hash_consistency verify

echo "release static CI: lmi release safety lint"
bash scripts/65_lmi_release_safety_lint.sh

echo "release static CI: tracked file size"
oversized=0
if ! git ls-files --error-unmatch -- "$known_good_kernel_apk" >/dev/null 2>&1; then
	echo "known-good kernel APK is not tracked: $known_good_kernel_apk" >&2
	exit 1
fi
while IFS= read -r -d '' path; do
	[ -f "$path" ] || continue
	size=$(stat -c '%s' "$path")
	if [ "$size" -gt "$max_tracked_file_bytes" ]; then
		if [ "$path" = "$known_good_kernel_apk" ]; then
			actual_sha=$(sha256sum -- "$path" | awk 'NR == 1 { print $1 }')
			if [ "$size" = "$known_good_kernel_apk_size" ] &&
				[ "$actual_sha" = "$known_good_kernel_apk_sha256" ]; then
				continue
			fi
			echo "known-good kernel APK does not match its exact size/SHA-256 pin" >&2
			exit 1
		fi
		echo "tracked file too large: $path ($size bytes > $max_tracked_file_bytes)" >&2
		oversized=1
	fi
done < <(git ls-files -z)

if [ "$oversized" -ne 0 ]; then
	exit 1
fi

echo "release static CI: no tracked release image payloads"
if git ls-files | grep -E '(^|/)(boot-linux-copydown-lmi-r6-bootmem\.img|xiaomi-lmi-r6-bootmem\.img|pmbootstrap-direct-boot-r6-bootmem\.img|vmlinuz-r6-bootmem|initramfs-r6-bootmem|sm8250-xiaomi-lmi-r6-bootmem\.dtb)$'; then
	echo "release payload file is tracked; keep large/generated payloads out of git" >&2
	exit 1
fi

echo "release static CI: OK"
