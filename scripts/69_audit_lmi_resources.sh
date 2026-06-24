#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/69_audit_lmi_resources.sh [--network] [--report PATH]

Compare the current local xiaomi-lmi mainline resources against the expected
resource set recorded in the project. The default mode is fully local and
read-only. With --network, the script also performs remote ref checks for the
external repositories used by the mainline route.

This script never executes reboot, boot, flash, erase, format, sideload, or
partition writes.
EOF
}

repo=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
bundle_dir=${LMI_RELEASE_BUNDLE_DIR:-/tmp/lmi-release-r6-bootmem-20260624}
report=${LMI_RESOURCE_AUDIT_REPORT:-$bundle_dir/LMI_RESOURCE_AUDIT.txt}
network=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--network)
			network=1
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

mkdir -p "$(dirname "$report")"
: > "$report"

log() {
	printf '%s\n' "$*" | tee -a "$report"
}

failures=0
warnings=0

fail() {
	log "FAIL: $*"
	failures=$((failures + 1))
}

warn() {
	log "WARN: $*"
	warnings=$((warnings + 1))
}

require_file() {
	local path=$1
	if [ -f "$path" ]; then
		log "OK file: $path"
	else
		fail "missing file: $path"
	fi
}

require_dir() {
	local path=$1
	if [ -d "$path" ]; then
		log "OK dir: $path"
	else
		fail "missing directory: $path"
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
		log "OK grep: $label"
	else
		fail "$label: pattern not found in $path: $pattern"
	fi
}

sha_line() {
	local path=$1
	if [ -f "$path" ]; then
		sha256sum "$path" | sed 's/^/SHA256 /' | tee -a "$report"
	fi
}

git_head() {
	local dir=$1
	if [ -d "$dir/.git" ]; then
		git -C "$dir" rev-parse HEAD 2>/dev/null || true
	else
		printf '<no-git>\n'
	fi
}

remote_ref() {
	local label=$1
	local url=$2
	local ref=$3
	log "## network ref: $label"
	set +e
	timeout 30 git ls-remote "$url" "$ref" 2>&1 | tee -a "$report"
	local status=${PIPESTATUS[0]}
	set -e
	log "status=$status"
	if [ "$status" -ne 0 ]; then
		warn "network ref check failed: $label"
	fi
	log
}

log "LMI resource audit"
log "generated_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
log "repo=$repo"
log "bundle_dir=$bundle_dir"
log "network=$network"
log
log "No reboot, boot, flash, erase, format, sideload, or partition write is executed by this script."
log

log "## local package resources"
for dir in \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi" \
	"$repo/artifacts/mainline-pmaports/firmware-xiaomi-lmi" \
	"$repo/artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi" \
	"$repo/artifacts/wsl-pmaports/device-xiaomi-lmi" \
	"$repo/artifacts/wsl-pmaports/linux-xiaomi-lmi"; do
	require_dir "$dir"
done
log

for path in \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/APKBUILD" \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/deviceinfo" \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/modules-initfs" \
	"$repo/artifacts/mainline-pmaports/firmware-xiaomi-lmi/APKBUILD" \
	"$repo/artifacts/mainline-pmaports/firmware-xiaomi-lmi/firmware.files" \
	"$repo/artifacts/mainline-pmaports/firmware-xiaomi-lmi/sensor.files" \
	"$repo/artifacts/mainline-pmaports/firmware-xiaomi-lmi/30-initramfs-firmware.files" \
	"$repo/artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi/APKBUILD" \
	"$repo/artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi/config-postmarketos-qcom-sm8250-lmi.aarch64" \
	"$repo/artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi/0001-sm8250-xiaomi-lmi-enable-sdx55-modem.patch" \
	"$repo/patches/lmi-mainline/0002-sm8250-xiaomi-lmi-boot-critical-memory.patch"; do
	require_file "$path"
done
log

log "## expected local metadata"
require_grep "mainline dtb" 'deviceinfo_dtb="qcom/sm8250-xiaomi-lmi"' \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/deviceinfo"
require_grep "append dtb" 'deviceinfo_append_dtb="true"' \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/deviceinfo"
require_grep "4096 rootfs sectors" 'deviceinfo_rootfs_image_sector_size="4096"' \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/deviceinfo"
require_grep "fastboot method" 'deviceinfo_flash_method="fastboot"' \
	"$repo/artifacts/mainline-pmaports/device-xiaomi-lmi/deviceinfo"
require_grep "kernel package flavor" '_flavor="postmarketos-qcom-sm8250-lmi"' \
	"$repo/artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi/APKBUILD"
require_grep "kernel package name" 'pkgname=linux-$_flavor' \
	"$repo/artifacts/mainline-pmaports/linux-postmarketos-qcom-sm8250-lmi/APKBUILD"
require_grep "external resource audit commit" 'Imported commit: `ef326f1`' \
	"$repo/docs/lmi-mainline-migration-plan-20260623.md"
require_grep "kernel upstream commit" '999ef8bfd90ca4c214f18ac5d0138bf380386c38' \
	"$repo/docs/lmi-mainline-migration-plan-20260623.md"
require_grep "firmware upstream commit" 'dde156380b2ac372619ed332dbe60640b838b7fe' \
	"$repo/docs/lmi-mainline-migration-plan-20260623.md"
log

log "## local git/resource heads"
log "repo_head=$(git -C "$repo" rev-parse HEAD)"
log "pmaports_cache_head=$(git_head /home/microstar/.local/var/pmbootstrap/cache_git/pmaports)"
log "pmbootstrap_cache_head=$(git_head /home/microstar/.local/var/pmbootstrap/cache_git/pmbootstrap)"
log

log "## generated bundle resources"
bundle_required=(
	"$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.img"
	"$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest"
	"$bundle_dir/xiaomi-lmi-r6-bootmem.img"
	"$bundle_dir/pmbootstrap-direct-boot-r6-bootmem.img"
	"$bundle_dir/vmlinuz-r6-bootmem"
	"$bundle_dir/sm8250-xiaomi-lmi-r6-bootmem.dtb"
	"$bundle_dir/initramfs-r6-bootmem"
	"$bundle_dir/SHA256SUMS"
)
for path in "${bundle_required[@]}"; do
	if [ -f "$path" ]; then
		log "OK bundle: $path size=$(stat -c '%s' "$path")"
	else
		warn "missing generated bundle file: $path"
	fi
done
for path in "${bundle_required[@]}"; do
	sha_line "$path"
done
log

if [ -f "$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest" ]; then
	require_grep "copydown stage" '^stage=M2j$' \
		"$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest"
	require_grep "copydown payload" '^payload=linux-copydown-shim-embedded-runtime-dtb$' \
		"$bundle_dir/boot-linux-copydown-lmi-r6-bootmem.manifest"
fi

log "## release docs"
for path in \
	"$repo/docs/lmi-mainline-flash-boundary-20260624.md" \
	"$repo/docs/release/lmi-r6-current-handoff-20260624.md" \
	"$repo/docs/release/lmi-r6-bootmem-release-manifest-20260624.md" \
	"$repo/docs/release/lmi-r6-bootmem-execution-checklist-20260624.md"; do
	require_file "$path"
done
require_grep "fastbootd gate" 'WAITING_FOR_RECOVERY_FASTBOOTD\|READY_FOR_FASTBOOTD_PREFLIGHT' \
	"$repo/docs/release/lmi-r6-current-handoff-20260624.md"
require_grep "copydown route decision" 'guarded recovery-fastbootd persistent test' \
	"$repo/docs/release/lmi-r6-current-handoff-20260624.md"
log

if [ "$network" -eq 1 ]; then
	remote_ref "external package repo main" \
		"https://github.com/macosmojave2-alt/postmarket-xiaomi-lmi.git" HEAD
	remote_ref "external kernel v6.19" \
		"https://github.com/yuweiyuan8/linux.git" refs/heads/v6.19
	remote_ref "external firmware repo" \
		"https://github.com/yuweiyuan8/firmware-xiaomi-lmi.git" HEAD
	remote_ref "official pmaports master" \
		"https://gitlab.postmarketos.org/postmarketOS/pmaports.git" HEAD
	remote_ref "official pmbootstrap master" \
		"https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git" HEAD
else
	log "network_ref_checks=skipped"
	log "Use --network to compare remote repository refs."
	log
fi

log "warnings=$warnings"
log "failures=$failures"
log "report=$report"

if [ "$failures" -ne 0 ]; then
	exit 1
fi
