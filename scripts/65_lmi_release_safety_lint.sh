#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/65_lmi_release_safety_lint.sh

Static safety lint (bringup governance v4). Six checks, all read-only:

1. Shell invoker set: fastboot state-change command text (flash/boot/reboot/
   erase/format) may only appear in the enumerated shell set below.
2. Forbidden operations: no live shell script may contain erase/format/
   relock commands or flash targets outside the governed set.
3. D114 transition set: every Python/PowerShell file containing the exact
   userdata-flash contract must be in the reviewed transition allowlist.
4. Retired route: removed M-r6/M-r7 helpers may not reappear.
5. D114 Python transition TCB: the WSL deployer must pin and load the
   transcript grammar from verified bytes; the grammar may not invoke tools.
6. Governance data: config/governance/constants.json and policy.json must
   validate against scripts/bringup_loop.py, which asserts that the data
   file's forbidden_command_words match the engine's hardcoded copy.

This script never talks to the phone. The retired M-r6/M-r7 state-change and
command-generation chain has been deleted. D110 remains the only live shell
executor. The separately hash-locked and tested D114 Python/PowerShell
transition graph is enumerated by this lint until it is wired to v4 claims.
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

# Shared assertion vocabulary in count-and-continue mode: fail() prints
# "FAIL: ..." to stderr and increments $release_checks_failures. All
# safety pattern data (allowlists, forbidden operation patterns) stays in
# this file by design; the library holds only generic helpers.
RELEASE_CHECKS_MODE=count
. "$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)/lib/release_checks.sh"

echo "lmi safety lint: fastboot invoker set"
# Scripts permitted to contain fastboot state-change command text.
#   executor (active):  72 — guarded D110 RAM-boot session flow
#   lint/contracts:     59 65 — check command text, never execute device
#                      state changes
allowed_fastboot_scripts='scripts/59_release_static_ci.sh
scripts/65_lmi_release_safety_lint.sh
scripts/72_stage_downstream_ssh_wifi_test.sh'
fastboot_invokers=$(git grep -lE \
	'(^|[^A-Za-z_"])("\$fastboot_bin"|fastboot(\.exe)?)[[:space:]]+(flash|boot|reboot|erase|format)([[:space:]]|$)' \
	-- 'scripts/*.sh' | sort || true)
unexpected=$(comm -23 <(printf '%s\n' "$fastboot_invokers") \
	<(printf '%s\n' "$allowed_fastboot_scripts" | sort))
if [ -n "$unexpected" ]; then
	printf '%s\n' "$unexpected" >&2
	fail "fastboot state-change text outside the allowlisted invoker set"
fi

reject_pattern() {
	local label=$1
	local pattern=$2
	local matches
	matches=$(git grep -n -E "$pattern" -- 'scripts/*.sh' \
		| grep -v '^scripts/65_lmi_release_safety_lint.sh:' \
		| grep -v 'never executes' \
		| grep -v 'No reboot, boot, flash, erase, format' \
		| grep -v 'Do not run any' \
		| grep -v 'pmbootstrap flasher flash_rootfs' \
		| grep -v 'without fresh exact approval' \
		|| true)
	if [ -n "$matches" ]; then
		printf '%s\n' "$matches" >&2
		fail "$label"
	fi
}

echo "lmi safety lint: forbidden operations"
reject_pattern "forbidden fastboot flash target in scripts" \
	'fastboot.*flash[[:space:]]+(super|dtbo|vbmeta|persist|modem|modemst|fsg|vendor_boot|init_boot|abl|xbl|tz|hyp|devcfg|bluetooth|userdata|system)'
reject_pattern "forbidden dynamic fastboot flash target in scripts" \
	'"\$fastboot_bin"[[:space:]]+flash[[:space:]]+(super|dtbo|vbmeta|persist|modem|modemst|fsg|vendor_boot|init_boot|abl|xbl|tz|hyp|devcfg|bluetooth|userdata|system)'
reject_pattern "forbidden pmbootstrap flasher write helper in scripts" \
	'flasher[[:space:]]+(flash_kernel|flash_dtbo|flash_vbmeta|sideload)'
reject_pattern "forbidden erase/format/relock in scripts" \
	'(fastboot|"\$fastboot_bin")[^[:cntrl:]]*(erase|format|oem[[:space:]]+lock|flashing[[:space:]]+lock)'

echo "lmi safety lint: D114 transition contract set"
# These are the only retained Python/PowerShell files allowed to contain the
# exact quoted `flash userdata` contract. Two are executors/orchestrators and
# two revalidate that frozen command in the transition evidence graph.
allowed_d114_contract_files='scripts/lmi_p2_d114/deploy_userdata.py
scripts/lmi_p2_d114/deploy_userdata_helper.ps1
scripts/lmi_p2_d114/deploy_userdata_wsl.py
scripts/lmi_p2_d114/postwrite_revalidate_wsl.py'
d114_contract_files=$(git grep -lE \
	"['\"]flash['\"][^[:cntrl:]]{0,160}['\"]userdata['\"]|['\"]userdata['\"][^[:cntrl:]]{0,160}['\"]flash['\"]" \
	-- 'scripts/**/*.py' 'scripts/**/*.ps1' 'scripts/*.py' 'scripts/*.ps1' \
	| sort || true)
unexpected_d114=$(comm -23 <(printf '%s\n' "$d114_contract_files") \
	<(printf '%s\n' "$allowed_d114_contract_files" | sort))
missing_d114=$(comm -13 <(printf '%s\n' "$d114_contract_files") \
	<(printf '%s\n' "$allowed_d114_contract_files" | sort))
if [ -n "$unexpected_d114" ]; then
	printf '%s\n' "$unexpected_d114" >&2
	fail "userdata flash contract text outside the reviewed D114 transition set"
fi
if [ -n "$missing_d114" ]; then
	printf '%s\n' "$missing_d114" >&2
	fail "reviewed D114 transition contract file is missing its frozen command"
fi
if ! git grep -qF \
	"\$write = Invoke-Fastboot @('-s', \$serial, 'flash', 'userdata', \$candidatePath)" \
	-- scripts/lmi_p2_d114/deploy_userdata_helper.ps1; then
	fail "Windows D114 executor no longer exposes the reviewed exact flash boundary"
fi
if ! git grep -qF \
	'argv = (*audit.argv_prefix, "-s", device.serial, "flash", "userdata", candidate_arg)' \
	-- scripts/lmi_p2_d114/deploy_userdata_wsl.py; then
	fail "WSL D114 executor no longer exposes the reviewed exact flash boundary"
fi

echo "lmi safety lint: retired M-r6/M-r7 helper absence"
retired_helpers=(
	scripts/48_preflight_lmi_fastbootd.sh
	scripts/49_generate_lmi_flash_command_sheet.sh
	scripts/50_scan_lmi_rollback_boots.sh
	scripts/51_prepare_lmi_fastbootd_entry.sh
	scripts/52_wait_lmi_fastbootd.sh
	scripts/53_stage_lmi_fastbootd_flash.sh
	scripts/54_monitor_lmi_post_boot.sh
	scripts/55_stage_lmi_rollback_boot.sh
	scripts/56_lmi_persistent_flash_plan.sh
	scripts/57_archive_lmi_release_manifest.sh
	scripts/58_generate_lmi_execution_checklist.sh
	scripts/60_stage_lmi_enter_fastbootd.sh
	scripts/61_stage_lmi_reboot_after_flash.sh
	scripts/62_refresh_lmi_release_docs.sh
	scripts/63_generate_lmi_handoff_status.sh
	scripts/64_audit_lmi_persistent_readiness.sh
	scripts/66_wait_and_audit_lmi_fastbootd.sh
	scripts/67_summarize_lmi_post_boot_evidence.sh
)
for retired in "${retired_helpers[@]}"; do
	if [ -e "$retired" ] || [ -L "$retired" ]; then
		fail "retired governance helper reappeared: $retired"
	fi
done

echo "lmi safety lint: D114 Python transition TCB"
transcript_path=scripts/lmi_p2_d114/fastboot_transcript.py
deployer_path=scripts/lmi_p2_d114/deploy_userdata_wsl.py
transcript_sha=$(/usr/bin/sha256sum -- "$transcript_path" | /usr/bin/awk 'NR == 1 { print $1 }')
if ! grep -Fqx "FASTBOOT_TRANSCRIPT_SHA256 = \"$transcript_sha\"" "$deployer_path"; then
	fail "D114 WSL deployer does not pin the exact transcript grammar"
fi
if ! grep -Fqx 'fastboot_transcript = _load_pinned_fastboot_transcript()' "$deployer_path"; then
	fail "D114 WSL deployer does not load the transcript grammar through its pinned loader"
fi
if grep -Eq 'subprocess|os\.(exec|system)' "$transcript_path"; then
	fail "D114 transcript grammar contains device-process vocabulary"
fi

echo "lmi safety lint: governance data consistency"
if ! python3 scripts/bringup_loop.py validate >/dev/null; then
	fail "bringup governance validation failed (constants/policy/active record)"
fi

if [ "$release_checks_failures" -ne 0 ]; then
	exit 1
fi

echo "lmi safety lint: OK"
