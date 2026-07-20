#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/68_mainline_progress_loop.sh [options]

Run a reusable host-side loop for the xiaomi-lmi mainline/copydown route.
The default loop is read-only: local resource audit, static CI, and release
bundle/readiness checks when the bundle exists. It never executes reboot, boot,
flash, erase, format, sideload, or partition writes.

Options:
  --once                 Run one iteration. This is the default.
  --iterations N         Run N iterations.
  --interval SECONDS     Sleep between iterations. Default: 300.
  --build                Rebuild the r6 overlay, packages, image, copydown boot,
                         bundle, and release docs before audits.
  --r7-earlydebug        With --build, build the r7 earlydebug boot-only
                         candidate naming set instead of the r6 default.
  --fastbootd            Include read-only fastbootd wait/preflight/audit.
  --network-resources    Ask the resource audit to compare remote refs too.
  --quick                Use quick checks where supported.
  --report PATH          Write loop report to PATH.
  -h, --help             Show this help.

Environment overrides:
  LMI_RELEASE_BUNDLE_DIR
  LMI_ROLLBACK_BOOT_IMG
  LMI_PMOS_TEST_PASSWORD   Required with --build; never written to the report.
  PMOS_EXPORT_DIR
  OUT_DIR
EOF
}

repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
copydown_dir=${OUT_DIR:-/tmp/lmi-copydown-r6-bootmem-20260624}
release_tag=${LMI_RELEASE_TAG:-r6-bootmem}
report=${LMI_MAINLINE_LOOP_REPORT:-$bundle_dir/MAINLINE_PROGRESS_LOOP.txt}
iterations=1
interval_s=300
do_build=0
do_fastbootd=0
network_resources=0
quick=0
test_password=
overlay_variant=--debug-shell-android-cmdline-no-efi-stub-48bit-bootmem

while [ "$#" -gt 0 ]; do
	case "$1" in
		--once)
			iterations=1
			shift
			;;
		--iterations)
			[ "$#" -ge 2 ] || {
				echo "--iterations requires a value" >&2
				exit 2
			}
			iterations=$2
			shift 2
			;;
		--interval)
			[ "$#" -ge 2 ] || {
				echo "--interval requires a value" >&2
				exit 2
			}
			interval_s=$2
			shift 2
			;;
		--build)
			do_build=1
			shift
			;;
		--r7-earlydebug)
			release_tag=r7-earlydebug
			bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r7-earlydebug-20260624}
			copydown_dir=${OUT_DIR:-/tmp/lmi-copydown-r7-earlydebug-20260624}
			overlay_variant=--r7-earlydebug
			report=${LMI_MAINLINE_LOOP_REPORT:-$bundle_dir/MAINLINE_PROGRESS_LOOP.txt}
			shift
			;;
		--fastbootd)
			do_fastbootd=1
			shift
			;;
		--network-resources)
			network_resources=1
			shift
			;;
		--quick)
			quick=1
			shift
			;;
		--report)
			[ "$#" -ge 2 ] || {
				echo "--report requires a value" >&2
				exit 2
			}
			report=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown argument: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

case "$iterations" in
	''|*[!0-9]*)
		echo "--iterations must be a non-negative integer" >&2
		exit 2
		;;
esac
case "$interval_s" in
	''|*[!0-9]*)
		echo "--interval must be a non-negative integer" >&2
		exit 2
		;;
esac
if [ "$iterations" -eq 0 ]; then
	echo "--iterations must be greater than zero" >&2
	exit 2
fi
if [ "$do_build" -eq 1 ]; then
	if [ -z "${LMI_PMOS_TEST_PASSWORD:-}" ]; then
		echo "LMI_PMOS_TEST_PASSWORD must be set locally when --build is used." >&2
		echo "The password has no public default and must not be committed." >&2
		exit 2
	fi
	case "$LMI_PMOS_TEST_PASSWORD" in
		*$'\n'*|*$'\r'*)
			echo "LMI_PMOS_TEST_PASSWORD must not contain newline characters." >&2
			exit 2
			;;
	esac
	test_password=$LMI_PMOS_TEST_PASSWORD
	# Do not expose the credential to audited helper commands through their
	# environment. Only the deliberately redacted install step receives it.
	unset LMI_PMOS_TEST_PASSWORD
fi

mkdir -p "$(dirname "$report")"
: > "$report"

log() {
	printf '%s\n' "$*" | tee -a "$report"
}

run_step() {
	local name=$1
	shift
	log "## $name"
	set +e
	"$@" 2>&1 | tee -a "$report"
	local status=${PIPESTATUS[0]}
	set -e
	log "status=$status"
	log
	return "$status"
}

run_sensitive_step() {
	local name=$1
	shift
	log "## $name"
	set +e
	"$@" >/dev/null 2>&1
	local status=$?
	set -e
	log "output=withheld because this command receives a credential"
	log "status=$status"
	log
	return "$status"
}

bundle_complete() {
	local required=(
		"$bundle_dir/boot-linux-copydown-lmi-$release_tag.img"
		"$bundle_dir/boot-linux-copydown-lmi-$release_tag.manifest"
		"$bundle_dir/xiaomi-lmi-$release_tag.img"
		"$bundle_dir/SHA256SUMS"
	)
	local path
	for path in "${required[@]}"; do
		[ -f "$path" ] || return 1
	done
	return 0
}

build_release_bundle() {
	run_step "prepare mainline overlay" \
		"$repo/scripts/40_prepare_mainline_lmi_overlay.sh" \
		"$overlay_variant"
	run_step "build mainline kernel package" \
		pmbootstrap build linux-postmarketos-qcom-sm8250-lmi --force
	run_step "build mainline device package" \
		pmbootstrap build device-xiaomi-lmi --force
	run_sensitive_step "install postmarketOS image" \
		pmbootstrap install --password "$test_password" --zap
	run_step "export postmarketOS image" \
		pmbootstrap export
	run_step "build copydown boot image" \
		env OUT_DIR="$copydown_dir" "$repo/scripts/45_build_lmi_copydown_boot.sh"
	run_step "verify copydown boot image" \
		env OUT_DIR="$copydown_dir" "$repo/scripts/46_verify_lmi_copydown_boot.sh"
	run_step "make release bundle" \
		env OUT_DIR="$copydown_dir" LMI_RELEASE_TAG="$release_tag" \
			LMI_RELEASE_BUNDLE_DIR="$bundle_dir" \
			"$repo/scripts/47_make_lmi_release_bundle.sh"
	run_step "refresh release docs" \
		"$repo/scripts/62_refresh_lmi_release_docs.sh" --quick || true
}

audit_iteration() {
	local idx=$1
	local resource_args=()
	local fastbootd_args=()
	if [ "$network_resources" -eq 1 ]; then
		resource_args+=(--network)
	fi
	if [ "$quick" -eq 1 ]; then
		fastbootd_args+=(--quick)
	fi

	log "# iteration $idx"
	log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
	log "repo=$repo"
	log "bundle_dir=$bundle_dir"
	log "release_tag=$release_tag"
	log "overlay_variant=$overlay_variant"
	log "do_build=$do_build"
	log "do_fastbootd=$do_fastbootd"
	log "network_resources=$network_resources"
	log
	log "No reboot, boot, flash, erase, format, sideload, or partition write is executed by this loop."
	log

	run_step "resource audit" "$repo/scripts/69_audit_lmi_resources.sh" "${resource_args[@]}" || true
	run_step "release static CI" "$repo/scripts/59_release_static_ci.sh" || true

	if [ "$do_build" -eq 1 ]; then
		build_release_bundle
	fi

	if bundle_complete; then
		run_step "persistent readiness audit" "$repo/scripts/64_audit_lmi_persistent_readiness.sh" || true
		if [ "$do_fastbootd" -eq 1 ]; then
			run_step "fastbootd wait and audit" \
				"$repo/scripts/66_wait_and_audit_lmi_fastbootd.sh" "${fastbootd_args[@]}" || true
		fi
	else
		log "bundle_status=MISSING"
		log "bundle_message=run this loop with --build, or restore $bundle_dir before fastbootd preflight."
		log
	fi
}

log "LMI mainline progress loop"
log "started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "report=$report"
log

for ((i = 1; i <= iterations; i++)); do
	audit_iteration "$i"
	if [ "$i" -lt "$iterations" ]; then
		log "sleeping ${interval_s}s before next iteration"
		sleep "$interval_s"
	fi
done

log "loop_complete_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "report=$report"
