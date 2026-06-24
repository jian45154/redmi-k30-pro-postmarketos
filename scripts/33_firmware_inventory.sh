#!/usr/bin/env bash
set -euo pipefail

root=${1:-}

if [ -z "$root" ] || [ ! -d "$root" ]; then
	echo "usage: $0 <mounted-stock-or-rootfs-directory>" >&2
	echo "example: $0 /mnt/vendor" >&2
	exit 2
fi

case "$root" in
	/*) ;;
	*) root=$PWD/$root ;;
esac

patterns='
venus.mdt
venus.b*
qca6390/amss20.bin
amss20.bin
adsp.mdt
adsp.b*
cdsp.mdt
cdsp.b*
slpi.mdt
slpi.b*
ssc.mdt
ssc.b*
ipa_fws.*
ipa_uc.*
a650_zap.*
*.tlv
*.hcd
bt_*
*qca6390*
'

classify() {
	path=$1
	case "$path" in
		*venus*) echo venus ;;
		*qca6390*|*amss20*|*wlan*|*WLAN*) echo wifi ;;
		*bt_*|*.tlv|*.hcd|*bluetooth*|*Bluetooth*) echo bluetooth ;;
		*adsp*|*audio*|*Audio*) echo adsp-audio ;;
		*cdsp*) echo cdsp ;;
		*slpi*|*ssc*) echo slpi-sensors ;;
		*ipa_*) echo ipa ;;
		*a650_zap*) echo gpu-zap ;;
		*) echo unknown ;;
	esac
}

target_path() {
	rel=$1
	base=${rel##*/}
	case "$rel" in
		*/qca6390/*) echo "/lib/firmware/qca6390/$base" ;;
		*) echo "/lib/firmware/$base" ;;
	esac
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

while IFS= read -r pattern; do
	[ -n "$pattern" ] || continue
	find "$root" -type f -path "*/$pattern" -print 2>/dev/null || true
done <<EOF | LC_ALL=C sort -u > "$tmp"
$patterns
EOF

printf '| subsystem | source path | target path | size | sha256 | publishable |\n'
printf '| :--- | :--- | :--- | ---: | :--- | :--- |\n'

while IFS= read -r file; do
	rel=${file#"$root"/}
	subsystem=$(classify "$rel")
	target=$(target_path "$rel")
	size=$(stat -c '%s' "$file")
	hash=$(sha256sum "$file" | awk '{print $1}')
	printf '| %s | `%s` | `%s` | %s | `%s` | local-only |\n' \
		"$subsystem" "$rel" "$target" "$size" "$hash"
done < "$tmp"
