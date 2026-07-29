# scripts/lib/release_checks.sh
#
# Shared assertion vocabulary for the release check scripts. Source this
# file; do not execute it. Two failure semantics are supported, selected
# by RELEASE_CHECKS_MODE, so each caller keeps its historical behavior:
#
#   exit-fast (default)  scripts/59_release_static_ci.sh
#       A failed assertion prints its message to stderr and exits 1.
#       Successful assertions are silent.
#
#   count                scripts/65_lmi_release_safety_lint.sh,
#                        scripts/69_audit_lmi_resources.sh
#       A failed assertion emits "FAIL: <message>" and increments
#       $release_checks_failures; the script keeps running and decides
#       its own exit status from the counter. Successful require_*
#       assertions log an "OK ..." line.
#
# Configuration variables (read at call time, all optional):
#   RELEASE_CHECKS_MODE      exit-fast | count      (default: exit-fast)
#   RELEASE_CHECKS_FAIL_TO   stderr | log           (default: stderr)
#       Where count-mode FAIL lines go: plain stderr (65 style) or
#       through log() to stdout plus the report file (69 style).
#   RELEASE_CHECKS_REPORT    path                   (default: unset)
#       When set, log() also appends every line to this file.
#
# This library holds generic helpers only. All safety pattern data —
# device command words, allowlists, forbidden operation patterns — stays
# in scripts/65_lmi_release_safety_lint.sh itself, so the safety lint's
# scans over scripts/*.sh keep their meaning.

release_checks_failures=0
release_checks_warnings=0

log() {
	if [ -n "${RELEASE_CHECKS_REPORT:-}" ]; then
		printf '%s\n' "$*" | tee -a "$RELEASE_CHECKS_REPORT"
	else
		printf '%s\n' "$*"
	fi
}

release_checks_emit_fail() {
	if [ "${RELEASE_CHECKS_FAIL_TO:-stderr}" = log ]; then
		log "$*"
	else
		printf '%s\n' "$*" >&2
	fi
}

fail() {
	if [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
		release_checks_emit_fail "FAIL: $*"
		release_checks_failures=$((release_checks_failures + 1))
	else
		release_checks_emit_fail "$*"
		exit 1
	fi
}

warn() {
	log "WARN: $*"
	release_checks_warnings=$((release_checks_warnings + 1))
}

require_file() {
	local path=$1
	if [ -f "$path" ]; then
		if [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
			log "OK file: $path"
		fi
	elif [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
		fail "missing file: $path"
	else
		fail "missing release contract file: $path"
	fi
}

require_dir() {
	local path=$1
	if [ -d "$path" ]; then
		if [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
			log "OK dir: $path"
		fi
	elif [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
		fail "missing directory: $path"
	else
		fail "missing directory: $path"
	fi
}

require_literal() {
	local path=$1 expected=$2
	if grep -Fq -- "$expected" "$path"; then
		if [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
			log "OK literal: $path"
		fi
	elif [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
		fail "missing literal in $path: $expected"
	else
		fail "missing release contract in $path: $expected"
	fi
}

reject_literal() {
	local path=$1 retired=$2
	if grep -Fq -- "$retired" "$path"; then
		if [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
			fail "retired literal remains in $path: $retired"
		else
			fail "retired release contract remains in $path: $retired"
		fi
	fi
}

require_grep() {
	local label=$1
	local pattern=$2
	local path=$3
	if [ ! -f "$path" ]; then
		fail "$label: missing file $path"
		return
	fi
	if grep -q "$pattern" "$path"; then
		if [ "${RELEASE_CHECKS_MODE:-exit-fast}" = count ]; then
			log "OK grep: $label"
		fi
	else
		fail "$label: pattern not found in $path: $pattern"
	fi
}
