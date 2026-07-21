#!/bin/sh

set -eu

version="0.1.0-alpha.1"
package_name="lmi-installer-v${version}"
archive_name="${package_name}-source.tar.gz"
checksum_name="${archive_name}.sha256"
source_date_epoch="1784505600"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)

usage() {
	printf 'usage: %s OUTPUT_DIRECTORY\n' "$0" >&2
}

if [ "$#" -ne 1 ]; then
	usage
	exit 2
fi

output_dir=$1
if [ -z "$output_dir" ] || [ "$output_dir" = "/" ]; then
	printf 'error: refusing unsafe output directory: %s\n' "$output_dir" >&2
	exit 2
fi

for command_name in gzip install mktemp sha256sum tar; do
	if ! command -v "$command_name" >/dev/null 2>&1; then
		printf 'error: required command not found: %s\n' "$command_name" >&2
		exit 1
	fi
done

for source_path in \
	"$repo_root/LICENSE" \
	"$repo_root/NOTICE" \
	"$repo_root/docs/lmi-cli-installer.md" \
	"$repo_root/scripts/lmi-installer" \
	"$repo_root/scripts/lmi_cli_installer.py"
do
	if [ ! -f "$source_path" ] || [ -L "$source_path" ]; then
		printf 'error: required regular source file missing or is a symlink: %s\n' "$source_path" >&2
		exit 1
	fi
done

mkdir -p -- "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
archive_path="$output_dir/$archive_name"
checksum_path="$output_dir/$checksum_name"

if [ -e "$archive_path" ] || [ -e "$checksum_path" ]; then
	printf 'error: refusing to overwrite an existing release asset in %s\n' "$output_dir" >&2
	exit 1
fi

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/lmi-installer-source-release.XXXXXX")
cleanup() {
	rm -rf -- "$work_dir"
}
trap cleanup EXIT HUP INT TERM

stage_dir="$work_dir/$package_name"
install -d -m 0755 -- "$stage_dir"
install -m 0644 -- "$repo_root/LICENSE" "$stage_dir/LICENSE"
install -m 0644 -- "$repo_root/NOTICE" "$stage_dir/NOTICE"
install -m 0644 -- "$repo_root/docs/lmi-cli-installer.md" "$stage_dir/USER_GUIDE.md"
install -m 0755 -- "$repo_root/scripts/lmi-installer" "$stage_dir/lmi-installer"
install -m 0644 -- "$repo_root/scripts/lmi_cli_installer.py" "$stage_dir/lmi_cli_installer.py"

(
	cd -- "$stage_dir"
	LC_ALL=C sha256sum \
		LICENSE \
		NOTICE \
		USER_GUIDE.md \
		lmi-installer \
		lmi_cli_installer.py > SHA256SUMS
	chmod 0644 SHA256SUMS
	sha256sum -c SHA256SUMS >/dev/null
)

tar_path="$work_dir/${package_name}.tar"
tar \
	--sort=name \
	--mtime="@$source_date_epoch" \
	--owner=0 \
	--group=0 \
	--numeric-owner \
	--format=gnu \
	-C "$work_dir" \
	-cf "$tar_path" \
	"$package_name"
gzip -n -c -- "$tar_path" > "$work_dir/$archive_name"
(
	cd -- "$work_dir"
	sha256sum "$archive_name" > "$checksum_name"
)

verify_dir="$work_dir/verify"
mkdir -p -- "$verify_dir"
tar -xzf "$work_dir/$archive_name" -C "$verify_dir"
(
	cd -- "$verify_dir/$package_name"
	sha256sum -c SHA256SUMS >/dev/null
	version_output=$(./lmi-installer --version)
	if [ "$version_output" != "lmi-installer $version" ]; then
		printf 'error: unexpected version output: %s\n' "$version_output" >&2
		exit 1
	fi
)

install -m 0644 -- "$work_dir/$archive_name" "$archive_path"
install -m 0644 -- "$work_dir/$checksum_name" "$checksum_path"

printf '%s\n' "$archive_path"
printf '%s\n' "$checksum_path"
