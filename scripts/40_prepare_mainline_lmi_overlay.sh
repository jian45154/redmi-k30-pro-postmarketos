#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
src=${MAINLINE_OVERLAY_SRC:-$repo/artifacts/mainline-pmaports}
pmaports_root=${PMB_PMAPORTS_ROOT:-/home/microstar/.local/var/pmbootstrap/cache_git/pmaports}
dst_root=${PMB_PMAPORTS_DEVICE_DIR:-$pmaports_root/device/testing}
backup_root=${PMB_LMI_OVERLAY_BACKUP_DIR:-$pmaports_root/.lmi-overlay-disabled}
package_root=${PMB_PACKAGE_ROOT:-/home/microstar/.local/var/pmbootstrap/packages/edge/aarch64}
disabled_device_pkg=$backup_root/device-downstream-device-xiaomi-lmi

if [ "${1:-}" = "--restore-downstream" ]; then
	rm -rf "$dst_root/device-xiaomi-lmi" \
		"$dst_root/firmware-xiaomi-lmi" \
		"$dst_root/linux-postmarketos-qcom-sm8250-lmi"
	if [ -d "$disabled_device_pkg" ]; then
		mkdir -p "$pmaports_root/device/downstream"
		rm -rf "$pmaports_root/device/downstream/device-xiaomi-lmi"
		mv "$disabled_device_pkg" "$pmaports_root/device/downstream/device-xiaomi-lmi"
		echo "restored downstream device-xiaomi-lmi"
	else
		echo "no disabled downstream device-xiaomi-lmi backup found"
	fi
	exit 0
fi

for pkg in device-xiaomi-lmi firmware-xiaomi-lmi linux-postmarketos-qcom-sm8250-lmi; do
	[ -d "$src/$pkg" ] || {
		echo "missing package source: $src/$pkg" >&2
		exit 1
	}
done

if [ -d "$pmaports_root/device/downstream/device-xiaomi-lmi" ]; then
	mkdir -p "$backup_root"
	rm -rf "$disabled_device_pkg"
	mv "$pmaports_root/device/downstream/device-xiaomi-lmi" "$disabled_device_pkg"
	echo "disabled duplicate downstream package: $disabled_device_pkg"
fi

mkdir -p "$dst_root"
for pkg in device-xiaomi-lmi firmware-xiaomi-lmi linux-postmarketos-qcom-sm8250-lmi; do
	rm -rf "$dst_root/$pkg"
	cp -a "$src/$pkg" "$dst_root/$pkg"
done

# Old local APKs can outrank the imported reference overlay. The downstream
# device package in this workspace has reached r18, while the imported
# mainline package starts at r1, so force a higher temporary revision and
# remove stale same-name APKs from the local package repository.
if [ -d "$package_root" ]; then
	for stale_apk in \
		"$package_root"/device-xiaomi-lmi-*.apk \
		"$package_root"/device-xiaomi-lmi-nonfree-firmware-*.apk \
		"$package_root"/device-xiaomi-lmi-nonfree-firmware-openrc-*.apk \
		"$package_root"/linux-xiaomi-lmi-*.apk
	do
		rm -f "$stale_apk" 2>/dev/null || sudo rm -f "$stale_apk"
	done
fi

sed -i 's/^pkgrel=.*/pkgrel=90/' "$dst_root/device-xiaomi-lmi/APKBUILD"

device_apkbuild="$dst_root/device-xiaomi-lmi/APKBUILD"

# The reference package expects a proprietary local zip for Cirrus/Focaltech
# blobs. Keep the committed reference intact, but disable that source and the
# extraction block in the temporary pmbootstrap cache copy for first RAM boots.
if grep -q 'firmware-xiaomi-lmi-Tag.zip' "$device_apkbuild"; then
	python3 - "$device_apkbuild" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text()

text = text.replace("\n\tfirmware-xiaomi-lmi-Tag.zip", "")
text = text.replace(
"""\

\t# Cirrus Logic audio DSP firmware (del zip local)
\tmkdir -p "$subpkgdir/lib/firmware/cirrus"
\tunzip -j -o "$srcdir/firmware-xiaomi-lmi-Tag.zip" \\
\t\t"firmware-xiaomi-lmi-Tag/lib/firmware/cirrus/*" \\
\t\t-d "$subpkgdir/lib/firmware/cirrus"

\t# Focaltech touch panel firmware (del zip local)
\tmkdir -p "$subpkgdir/lib/firmware/focaltech"
\tunzip -j -o "$srcdir/firmware-xiaomi-lmi-Tag.zip" \\
\t\t"firmware-xiaomi-lmi-Tag/lib/firmware/focaltech/*" \\
\t\t-d "$subpkgdir/lib/firmware/focaltech"
""",
"""\

\t# The proprietary Cirrus/Focaltech zip is intentionally not present in the
\t# local cache overlay used for first RAM-only boot experiments.
""")

lines = [
    line for line in text.splitlines()
    if "firmware-xiaomi-lmi-Tag.zip" not in line
]
path.write_text("\n".join(lines) + "\n")
PY
fi

echo "mainline lmi overlay prepared in $dst_root"
echo "temporary package set:"
find "$dst_root" -maxdepth 2 -type f \
	\( -path "*/device-xiaomi-lmi/*" \
	-o -path "*/firmware-xiaomi-lmi/*" \
	-o -path "*/linux-postmarketos-qcom-sm8250-lmi/*" \) \
	-printf "  %P\n" | sort
