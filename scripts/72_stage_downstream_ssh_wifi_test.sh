#!/usr/bin/bash -p
set -euo pipefail
set +x

# This is a deliberately narrow D110/D114 recovery gate. Caller-selected
# artifacts, tools, UUIDs, products, and battery thresholds are not accepted.
PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

readonly CLAIM='No explicit fastboot partition flash; the booted OS may mutate persisted userdata.'
readonly TRUSTED_POLICY_SHA256='18d3efc57152f297784e0b97af221789e4d508a73d5485e3fac3c5ba94c232cd'
# Pinned SHA-256 of scripts/lmi_d110_session.py. The module holds the exact
# Python bodies that used to live in this file as heredocs; because it is now
# a separate file on disk it is hashed against this pin before any use and
# re-verified at every helper-identity checkpoint. Re-pin procedure: see
# scripts/README.md ("Re-pinning the D110 session module").
readonly TRUSTED_SESSION_MODULE_SHA256='a266bd4537056002c13acd3aad87f9d7fc20e05b55dca9da125bd03cd860c05f'
readonly POLICY_REL='private/lmi-p1/recovery/d110-d114/d110-recovery-policy.json'
readonly POWERSHELL='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
readonly WSLPATH='/usr/bin/wslpath'
readonly READ_ONLY_TIMEOUT=10
execute_deadline_epoch=
session_lock_fd=

fail() {
	printf 'refused: %s\n' "$*" >&2
	exit 2
}

usage() {
	cat <<'EOF'
Usage:
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --dry-run
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --preflight
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --authorize-session
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --execute
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --revoke-session

Preflight is read-only. Authorize-session performs the same complete read-only
preflight, then grants the current CODEX_THREAD_ID session ongoing authority for
this exact policy, helper, host boot, artifact, device, stage, operation, and
tool. The grant has no short chat-confirmation TTL; it remains valid within the
pinned session safety ceiling until explicit local revocation or any bound
input changes. The raw session ID is neither stored nor printed. It is a thread
scope discriminator, not an independent cryptographic authentication factor.

Execute needs no caller receipt or confirmation. It verifies the same session
grant under a non-blocking exclusive lock, repeats the complete preflight, then
creates and immediately consumes an internal 30-second one-shot attempt receipt
before rechecking and attempting exactly one pinned fastboot boot command. It
never retries. Only one execute may be in progress at a time.

No explicit fastboot partition flash; the booted OS may mutate persisted userdata.
EOF
}

script_input=${BASH_SOURCE[0]}
[ -n "$script_input" ] || fail "script path is unavailable"
[ ! -L "$script_input" ] || fail "the helper itself must not be a symlink"
script_path=$(/usr/bin/readlink -f -- "$script_input") || fail "could not resolve the helper"
[ -f "$script_path" ] && [ ! -L "$script_path" ] || fail "helper path is not a regular file"
script_dir=${script_path%/*}
repo=$(/usr/bin/readlink -f -- "$script_dir/..") || fail "could not resolve repository root"
policy_path=$repo/$POLICY_REL
session_module=$script_dir/lmi_d110_session.py
readonly session_module_fd=9
readonly session_module_exec=/proc/self/fd/$session_module_fd
session_module_identity=

mode=
stage=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--stage)
			[ "$#" -ge 2 ] || fail "--stage requires a value"
			stage=$2
			shift 2
			;;
		--dry-run|--preflight|--authorize-session|--execute|--revoke-session)
			[ -z "$mode" ] || fail "choose exactly one mode"
			mode=$1
			shift
			;;
		--receipt|--confirm|--session-id)
			fail "$1 is a retired caller-approval interface and is not accepted"
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			fail "unknown argument"
			;;
	esac
done

[ "$stage" = ramboot ] || fail "--stage ramboot is required; this gate cannot flash userdata"
case "$mode" in
	--dry-run|--preflight|--authorize-session|--execute|--revoke-session) ;;
	*) fail "choose exactly one documented mode" ;;
esac

# Refuse former caller-selectable trust and approval inputs instead of silently
# ignoring them. CODEX_THREAD_ID is the sole session identity input.
for legacy_name in \
	REPO FASTBOOT DOWNSTREAM_BOOT_IMG DOWNSTREAM_USERDATA_IMG \
	DOWNSTREAM_MANIFEST DOWNSTREAM_FASTBOOT_SHA256 \
	DOWNSTREAM_EXPECTED_BOOT_UUID DOWNSTREAM_EXPECTED_ROOT_UUID \
	DOWNSTREAM_MIN_BATTERY_MV DOWNSTREAM_FASTBOOT_TIMEOUT \
	DOWNSTREAM_FASTBOOT_ACTION_TIMEOUT DOWNSTREAM_RAMBOOT_CONFIRM \
	DOWNSTREAM_ROOTFS_CONFIRM; do
	if [[ -v $legacy_name ]]; then
		fail "$legacy_name is not accepted by the pinned D110 recovery gate"
	fi
done

# The pinned session module carries the exact Python bodies that used to be
# embedded here as heredocs. A heredoc could not be swapped without changing
# this file (which the helper-identity checkpoints detect); the module file
# regains that property by being opened once, hashed against
# TRUSTED_SESSION_MODULE_SHA256, and executed only through the retained fd.
# Path identity is still re-verified at every helper-identity checkpoint.
capture_session_module() {
	local actual_sha before after path_identity
	[[ $TRUSTED_SESSION_MODULE_SHA256 =~ ^[0-9a-f]{64}$ ]] || fail "the session module pin is not a literal SHA-256"
	[ ! -L "$session_module" ] || fail "the session module must not be a symlink"
	[ -f "$session_module" ] || fail "the session module is missing"
	[ "$(/usr/bin/stat -c '%h' -- "$session_module")" = 1 ] || fail "the session module must have exactly one hard link"
	exec 9<"$session_module" || fail "could not retain the session module descriptor"
	before=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' -- "$session_module_exec") || fail "could not inspect the retained session module"
	actual_sha=$(/usr/bin/sha256sum -- "$session_module_exec" | /usr/bin/awk 'NR == 1 { print $1 }')
	[ "$actual_sha" = "$TRUSTED_SESSION_MODULE_SHA256" ] || fail "the session module does not match its trusted pin"
	after=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' -- "$session_module_exec") || fail "could not reinspect the retained session module"
	[ "$before" = "$after" ] || fail "the session module changed while it was hashed"
	[ ! -L "$session_module" ] && [ -f "$session_module" ] || fail "the session module path changed type"
	path_identity=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$session_module") || fail "could not inspect the session module path"
	[ "$path_identity" = "$before" ] || fail "the retained session module differs from its reviewed path"
	session_module_identity=$before
}

verify_session_module() {
	local actual_sha current path_identity
	[ ! -L "$session_module" ] && [ -f "$session_module" ] || fail "the session module changed type"
	current=$(/usr/bin/stat -Lc '%d:%i:%f:%h:%s:%y:%z' -- "$session_module_exec") || fail "could not inspect the retained session module"
	[ "$current" = "$session_module_identity" ] || fail "the session module changed during the gated operation"
	actual_sha=$(/usr/bin/sha256sum -- "$session_module_exec" | /usr/bin/awk 'NR == 1 { print $1 }')
	[ "$actual_sha" = "$TRUSTED_SESSION_MODULE_SHA256" ] || fail "the session module SHA-256 changed during the gated operation"
	path_identity=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$session_module") || fail "could not inspect the session module path"
	[ "$path_identity" = "$session_module_identity" ] || fail "the session module path no longer names the retained file"
}

capture_helper_identity() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" helper-identity "$script_path")
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the helper identity could not be captured safely"
	IFS=$'\t' read -r helper_sha helper_identity <<< "$output"
	[[ $helper_sha =~ ^[0-9a-f]{64}$ ]] && [ -n "$helper_identity" ] || fail "the helper identity record is invalid"
}

verify_helper_identity() {
	local captured_sha=$helper_sha captured_identity=$helper_identity
	verify_session_module
	capture_helper_identity
	[ "$helper_sha" = "$captured_sha" ] && [ "$helper_identity" = "$captured_identity" ] \
		|| fail "the helper changed during the gated operation"
}

# Verify the private policy, its historical D199/D200 identity evidence, both
# exact manifests, and the complete Android boot image semantics. The verifier
# emits only fixed policy fields; it never emits the raw serial or the private
# historical fingerprint.
capture_local_policy() {
	local output
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" local-policy "$repo" "$policy_path" "$TRUSTED_POLICY_SHA256")
	local status=$?
	set -e
	[ "$status" -eq 0 ] || fail "private D110 policy or pinned local evidence validation failed"
	IFS=$'\t' read -r privacy_nonce expected_identity historical_fingerprint \
		boot_path boot_sha boot_size boot_manifest_path boot_manifest_sha \
		pair_manifest_path pair_manifest_sha boot_uuid root_uuid kernel_sha \
		ramdisk_sha dtb_sha fastboot_host_kind fastboot_host_path fastboot_sha \
		fastboot_size expected_product expected_unlocked expected_userspace \
		minimum_battery_mv expected_battery_soc minimum_max_download receipt_ttl \
		action_timeout receipt_dir grant_dir session_max_seconds action_digest output_end <<< "$output"
	[ "$output_end" = END ] || fail "local policy verifier returned an invalid record"
}

capture_fastboot_tool() {
	local before after actual_sha roundtrip
	case "$fastboot_host_kind" in
		linux) fastboot_bin=$fastboot_host_path ;;
		windows)
			[ -x "$WSLPATH" ] || fail "fixed wslpath is unavailable"
			fastboot_bin=$($WSLPATH -u "$fastboot_host_path" | /usr/bin/tr -d '\r') || fail "could not translate the pinned fastboot path"
			roundtrip=$($WSLPATH -w "$fastboot_bin" | /usr/bin/tr -d '\r') || fail "could not round-trip the pinned fastboot path"
			[ "$roundtrip" = "$fastboot_host_path" ] || fail "pinned fastboot path does not round-trip exactly"
			;;
		*) fail "invalid fastboot path kind" ;;
	esac
	case "$fastboot_bin" in /*) ;; *) fail "fastboot did not resolve to an absolute path" ;; esac
	[ ! -L "$fastboot_bin" ] && [ -f "$fastboot_bin" ] && [ -x "$fastboot_bin" ] || fail "pinned fastboot is not an executable regular non-symlink file"
	[ "$(/usr/bin/stat -c '%h' -- "$fastboot_bin")" = 1 ] || fail "pinned fastboot must have exactly one hard link"
	before=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not inspect pinned fastboot"
	[ "$(/usr/bin/stat -c '%s' -- "$fastboot_bin")" = "$fastboot_size" ] || fail "pinned fastboot size mismatch"
	actual_sha=$(/usr/bin/sha256sum -- "$fastboot_bin" | /usr/bin/awk 'NR == 1 { print $1 }')
	[ "$actual_sha" = "$fastboot_sha" ] || fail "pinned fastboot SHA-256 mismatch"
	after=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not reinspect pinned fastboot"
	[ "$before" = "$after" ] || fail "pinned fastboot changed while it was hashed"
	fastboot_identity=$before
}

verify_fastboot_tool() {
	local before after actual_sha
	[ ! -L "$fastboot_bin" ] && [ -f "$fastboot_bin" ] && [ -x "$fastboot_bin" ] || fail "pinned fastboot changed type"
	[ "$(/usr/bin/stat -c '%h' -- "$fastboot_bin")" = 1 ] || fail "pinned fastboot hard-link count changed"
	before=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not inspect pinned fastboot"
	[ "$before" = "$fastboot_identity" ] || fail "pinned fastboot identity changed"
	actual_sha=$(/usr/bin/sha256sum -- "$fastboot_bin" | /usr/bin/awk 'NR == 1 { print $1 }')
	[ "$actual_sha" = "$fastboot_sha" ] || fail "pinned fastboot SHA-256 changed"
	after=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not reinspect pinned fastboot"
	[ "$after" = "$fastboot_identity" ] || fail "pinned fastboot changed during revalidation"
}

bound_timeout_to_execute_deadline() {
	local wanted=$1 now remaining
	bounded_timeout_seconds=$wanted
	[ -n "$execute_deadline_epoch" ] || return 0
	now=$(/usr/bin/date +%s) || fail "could not read the execute deadline clock"
	remaining=$((execute_deadline_epoch - now))
	[ "$remaining" -gt 0 ] || fail "the consumed receipt expired; no fastboot boot action was attempted"
	if [ "$remaining" -lt "$bounded_timeout_seconds" ]; then
		bounded_timeout_seconds=$remaining
	fi
}

require_action_deadline_margin() {
	local now remaining
	now=$(/usr/bin/date +%s) || fail "could not read the execute deadline clock"
	remaining=$((execute_deadline_epoch - now))
	# Keep a full second of margin between this check and process creation so an
	# action is never intentionally launched on the expiry boundary.
	[ "$remaining" -gt 1 ] || fail "the consumed receipt expired or is too close to expiry; no fastboot boot action was attempted"
	action_deadline_timeout=$((remaining - 1))
	if [ "$action_timeout" -lt "$action_deadline_timeout" ]; then
		action_deadline_timeout=$action_timeout
	fi
}

prepare_candidate_view() {
	fastboot_candidate_path=$boot_path
	if [ "$fastboot_host_kind" = windows ]; then
		case "${fastboot_bin,,}" in *.exe) ;; *) fail "pinned Windows fastboot path must end in .exe" ;; esac
		[ -x "$POWERSHELL" ] && [ -f "$POWERSHELL" ] && [ ! -L "$POWERSHELL" ] || fail "fixed Windows PowerShell is unavailable"
		fastboot_candidate_path=$($WSLPATH -w "$boot_path" | /usr/bin/tr -d '\r') || fail "could not translate the pinned boot image path"
		case "$fastboot_candidate_path" in
			\\\\wsl.localhost\\*|\\\\wsl\$\\*) ;;
			*) fail "the Windows boot image view must be an absolute WSL UNC path" ;;
		esac
		if printf '%s' "$fastboot_candidate_path" | /usr/bin/grep -q '[[:cntrl:]]'; then
			fail "the Windows boot image path contains a control character"
		fi
	fi
}

verify_candidate_view() {
	local output extra actual_size actual_sha
	[ "$fastboot_host_kind" = windows ] || return 0
	bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
	set +e
	output=$(/usr/bin/timeout "$bounded_timeout_seconds" "$POWERSHELL" -NoProfile -NonInteractive -Command \
		'& { param([string] $p) $i = Get-Item -LiteralPath $p; $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant(); Write-Output (("{0} {1}" -f $i.Length, $h)) }' \
		"$fastboot_candidate_path" | /usr/bin/tr -d '\r')
	local status=$?
	set -e
	[ "$status" -eq 0 ] || fail "Windows could not hash the pinned boot image"
	IFS=' ' read -r actual_size actual_sha extra <<< "$output"
	[ -z "${extra:-}" ] || fail "Windows boot image identity output is ambiguous"
	[ "$actual_size" = "$boot_size" ] || fail "Windows boot image size differs from the pinned Linux file"
	[ "$actual_sha" = "$boot_sha" ] || fail "Windows boot image SHA-256 differs from the pinned Linux file"
}

run_fastboot_capture() {
	local status
	verify_fastboot_tool
	bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
	set +e
	fastboot_output=$(/usr/bin/timeout "$bounded_timeout_seconds" "$fastboot_bin" "$@" 2>&1)
	status=$?
	set -e
	if [ "$status" -ne 0 ] && [ -n "$execute_deadline_epoch" ]; then
		bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
	fi
	[ "$status" -eq 0 ] || fail "a read-only fastboot query failed"
	fastboot_output=${fastboot_output//$'\r'/}
}

select_single_device() {
	local line only_line= count=0
	run_fastboot_capture devices
	while IFS= read -r line || [ -n "$line" ]; do
		[ -z "$line" ] && continue
		count=$((count + 1))
		only_line=$line
	done <<< "$fastboot_output"
	[ "$count" -eq 1 ] || fail "exactly one nonempty fastboot devices entry is required"
	if [[ $only_line =~ ^([A-Za-z0-9._:-]+)[[:space:]]+fastboot[[:space:]]*$ ]]; then
		device_serial=${BASH_REMATCH[1]}
	else
		fail "the sole fastboot devices entry is malformed or not in fastboot state"
	fi
}

read_getvar() {
	local key=$1 line value
	local -a values=()
	run_fastboot_capture -s "$device_serial" getvar "$key"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			"$key: "*) value=${line#"$key: "}; values+=("$value") ;;
			"(bootloader) $key: "*) value=${line#"(bootloader) $key: "}; values+=("$value") ;;
		esac
	done <<< "$fastboot_output"
	[ "${#values[@]}" -eq 1 ] || fail "a pinned fastboot getvar was missing or ambiguous"
	getvar_value=${values[0]}
	[ -n "$getvar_value" ] || fail "a pinned fastboot getvar was empty"
	if printf '%s' "$getvar_value" | /usr/bin/grep -q '[[:cntrl:]]'; then
		fail "a pinned fastboot getvar contains a control character"
	fi
}

parse_uint() {
	local input=$1 output status
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" parse-uint "$input")
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "a numeric fastboot property is invalid"
	parsed_uint=$output
}

verify_private_device_identity() {
	local status
	set +e
	/usr/bin/python3 -I -S -B "$session_module_exec" device-identity "$privacy_nonce" "$expected_identity" "$historical_fingerprint" 3<<< "$device_serial"
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the connected handset does not match the private D199/D200 identity policy"
}

preflight_device() {
	local enumerated_serial number
	select_single_device
	enumerated_serial=$device_serial
	read_getvar serialno
	[ "$getvar_value" = "$enumerated_serial" ] || fail "fastboot devices and getvar serialno identify different handsets"
	verify_private_device_identity
	read_getvar product
	[ "$getvar_value" = "$expected_product" ] || fail "device product does not match the pinned policy"
	read_getvar unlocked
	[ "$getvar_value" = "$expected_unlocked" ] || fail "bootloader unlock state does not match the pinned policy"
	read_getvar is-userspace
	[ "$getvar_value" = "$expected_userspace" ] || fail "RAM boot requires the pinned non-userspace fastboot state"
	read_getvar battery-voltage
	parse_uint "$getvar_value"
	number=$parsed_uint
	[ "$number" -ge "$minimum_battery_mv" ] || fail "battery voltage is below the pinned minimum"
	device_battery_mv=$number
	read_getvar battery-soc-ok
	[ "$getvar_value" = "$expected_battery_soc" ] || fail "battery-soc-ok does not match the pinned policy"
	read_getvar max-download-size
	parse_uint "$getvar_value"
	number=$parsed_uint
	[ "$number" -ge "$minimum_max_download" ] || fail "max-download-size is below the pinned minimum"
	[ "$boot_size" -le "$number" ] || fail "pinned boot image exceeds max-download-size"
	device_max_download=$number
}

capture_session_scope() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" session-scope)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "a valid current CODEX_THREAD_ID session scope is required"
	IFS=$'\t' read -r thread_binding host_boot_id_sha <<< "$output"
	[[ $thread_binding =~ ^[0-9a-f]{64}$ ]] && [[ $host_boot_id_sha =~ ^[0-9a-f]{64}$ ]] \
		|| fail "the session scope binding is invalid"
	unset CODEX_THREAD_ID
}

prepare_session_storage() {
	local create=$1 status
	set +e
	/usr/bin/python3 -I -S -B "$session_module_exec" session-storage "$grant_dir" "$create"
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the private session grant storage is missing or unsafe"
}

acquire_session_lock() {
	local lock_path=$grant_dir/execute.lock expected actual
	[ ! -L "$lock_path" ] || fail "the session execution lock must not be a symlink"
	exec {session_lock_fd}<> "$lock_path" || fail "could not open the session execution lock"
	[ ! -L "$lock_path" ] || fail "the session execution lock changed type"
	[ "$(/usr/bin/stat -c '%a:%u:%h' -- "$lock_path")" = "600:$(/usr/bin/id -u):1" ] \
		|| fail "the session execution lock ownership, mode, or link count is unsafe"
	expected=$(/usr/bin/stat -c '%d:%i' -- "$lock_path") || fail "could not inspect the session execution lock"
	actual=$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/$session_lock_fd") || fail "could not inspect the open session execution lock"
	[ "$expected" = "$actual" ] || fail "the session execution lock changed while it was opened"
	/usr/bin/flock -n "$session_lock_fd" || fail "another session execution or revocation is already in progress"
}

release_session_lock() {
	[ -n "$session_lock_fd" ] || return 0
	exec {session_lock_fd}>&-
	session_lock_fd=
}

create_session_grant() {
	local output status
	grant_path=$grant_dir/active/grant-$thread_binding.json
	if [ -e "$grant_path" ] || [ -L "$grant_path" ]; then
		# Reauthorization is deliberately idempotent: a valid existing grant is
		# retained with its original deadline. Invalid/expired state must first
		# be explicitly archived with --revoke-session.
		verify_session_grant
		grant_result=reused-with-original-deadline
		return 0
	fi
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" grant-create "$grant_dir" "$thread_binding" \
		"$host_boot_id_sha" "$TRUSTED_POLICY_SHA256" "$action_digest" "$boot_sha" \
		"$expected_identity" "$fastboot_sha" "$fastboot_identity" "$stage" "$helper_sha" \
		"$session_max_seconds")
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "could not atomically create the private session grant"
	grant_path=$output
	grant_result=created
}

verify_session_grant() {
	local status
	grant_path=$grant_dir/active/grant-$thread_binding.json
	set +e
	/usr/bin/python3 -I -S -B "$session_module_exec" grant-verify "$grant_path" "$thread_binding" "$host_boot_id_sha" \
		"$TRUSTED_POLICY_SHA256" "$action_digest" "$boot_sha" "$expected_identity" \
		"$fastboot_sha" "$fastboot_identity" "$stage" "$helper_sha" "$session_max_seconds"
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the current Codex thread has no valid session grant for this exact operation"
}

revoke_session_grant() {
	local status
	set +e
	/usr/bin/python3 -I -S -B "$session_module_exec" grant-revoke "$grant_dir" "$thread_binding"
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the session grant could not be atomically revoked"
}

create_attempt_receipt() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" receipt-create "$receipt_dir" "$TRUSTED_POLICY_SHA256" \
		"$action_digest" "$boot_sha" "$expected_identity" "$thread_binding" \
		"$host_boot_id_sha" "$helper_sha" "$fastboot_identity" "$stage" "$device_battery_mv" \
		"$device_max_download" "$receipt_ttl")
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "could not create the private internal attempt receipt"
	pending_receipt=$output
}

consume_attempt_receipt() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B "$session_module_exec" receipt-consume "$receipt_dir" "$pending_receipt" \
		"$TRUSTED_POLICY_SHA256" "$action_digest" "$boot_sha" "$expected_identity" \
		"$thread_binding" "$host_boot_id_sha" "$helper_sha" "$fastboot_identity" "$stage" "$receipt_ttl")
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the internal attempt receipt is invalid, expired, renamed, replayed, or already consumed"
	consumed_expiry_epoch=$output
	[[ $consumed_expiry_epoch =~ ^[0-9]+$ ]] || fail "attempt receipt consumer returned an invalid expiry"
}

complete_read_only_preflight() {
	preflight_device
	capture_local_policy
	verify_helper_identity
	verify_fastboot_tool
	prepare_candidate_view
	verify_candidate_view
}

capture_session_module
capture_helper_identity
capture_local_policy

case "$mode" in
	--authorize-session|--execute|--revoke-session) capture_session_scope ;;
	*) unset CODEX_THREAD_ID ;;
esac

printf 'claim=%s\n' "$CLAIM"
printf 'policy_sha256=%s\n' "$TRUSTED_POLICY_SHA256"
printf 'boot_sha256=%s\n' "$boot_sha"
printf 'boot_size=%s\n' "$boot_size"
printf 'boot_uuid=%s\n' "$boot_uuid"
printf 'root_uuid=%s\n' "$root_uuid"
printf 'kernel_sha256=%s\n' "$kernel_sha"
printf 'ramdisk_sha256=%s\n' "$ramdisk_sha"
printf 'dtb_sha256=%s\n' "$dtb_sha"
printf 'fastboot_sha256=%s\n' "$fastboot_sha"

case "$mode" in
	--dry-run)
		capture_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		printf 'dry-run=local-only; no phone query or hardware command\n'
		printf 'session_scope=CODEX_THREAD_ID is required only for authorize, execute, and revoke\n'
		;;
	--preflight)
		capture_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		complete_read_only_preflight
		printf 'preflight=passed-read-only\n'
		printf 'session_grant=not-created\n'
		printf 'No action was attempted. %s\n' "$CLAIM"
		;;
	--authorize-session)
		capture_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		complete_read_only_preflight
		# No state is created until the complete read-only preflight above passes.
		prepare_session_storage create
		acquire_session_lock
		verify_helper_identity
		create_session_grant
		release_session_lock
		printf 'authorization=session-grant-%s-after-complete-read-only-preflight\n' "$grant_result"
		printf 'session_scope=current-CODEX_THREAD_ID-hash; raw identifier not stored or printed\n'
		printf 'session_max_seconds=%s\n' "$session_max_seconds"
		printf 'No boot action was attempted. %s\n' "$CLAIM"
		;;
	--execute)
		prepare_session_storage validate
		acquire_session_lock
		capture_fastboot_tool
		verify_session_grant
		prepare_candidate_view
		verify_candidate_view
		complete_read_only_preflight
		verify_session_grant
		create_attempt_receipt
		consume_attempt_receipt
		execute_deadline_epoch=$consumed_expiry_epoch
		printf 'authorization=same-thread-session-grant-verified-under-exclusive-lock\n'
		printf 'attempt_receipt=created-and-consumed-internally-before-execution\n'
		# The internal receipt is already consumed. Every device and local gate is
		# now repeated within its 30-second deadline before the single action.
		complete_read_only_preflight
		bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
		verify_session_grant
		require_action_deadline_margin
		set +e
		/usr/bin/timeout "$action_deadline_timeout" "$fastboot_bin" -s "$device_serial" boot "$fastboot_candidate_path" >/dev/null 2>&1
		action_status=$?
		set -e
		execute_deadline_epoch=
		# The output is intentionally withheld because a hostile or unexpected
		# fastboot build could echo a raw serial. The exit status is sufficient
		# for this one-shot gate, and no retry is made.
		capture_local_policy
		verify_helper_identity
		verify_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		verify_session_grant
		[ "$action_status" -eq 0 ] || fail "the single fastboot boot action failed; the internal attempt receipt remains consumed and no retry was attempted"
		release_session_lock
		printf 'fastboot_boot_attempts=1\n'
		printf 'result=single-pinned-fastboot-boot-command-accepted\n'
		printf 'No automatic retry. %s\n' "$CLAIM"
		;;
	--revoke-session)
		prepare_session_storage validate
		acquire_session_lock
		revoke_session_grant
		release_session_lock
		printf 'revocation=current-CODEX_THREAD_ID-session-grant-atomically-revoked\n'
		printf 'No phone query or boot action was attempted. %s\n' "$CLAIM"
		;;
esac

# Residual boundary: CODEX_THREAD_ID distinguishes the current Codex thread but
# is not itself a cryptographic authentication principal; user authority comes
# from the Codex session/tool approval boundary. A process already running as
# this same EUID can modify the helper or race private pathnames, and Windows
# consumes a pathname rather than a retained Linux file descriptor. Helper and
# host-boot binding, file-descriptor hashing, exact modes, one-link checks,
# before/after identity checks, fixed absolute interpreters, PowerShell
# re-hashing, atomic grant/receipt operations, and the global execution lock
# narrow but cannot remove that same-EUID/WSL-Windows pathname trust boundary.
