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
debug_shell=false
android_cmdline=false
no_zboot=false
no_efi_stub=false
arm64_48bit=false

update_sha512_sum() {
	local apkbuild=$1
	local source_file=$2
	local source_name=$3
	local sum

	sum=$(sha512sum "$source_file")
	sum=${sum%% *}
	sed -i "s|^[0-9a-f]\\{128\\}  $source_name\$|$sum  $source_name|" "$apkbuild"
}

disable_kernel_config() {
	local config=$1
	local symbol=$2

	if grep -q "^$symbol=y$" "$config"; then
		sed -i "s/^$symbol=y$/# $symbol is not set/" "$config"
	elif ! grep -q "^# $symbol is not set$" "$config"; then
		echo "# $symbol is not set" >> "$config"
	fi
}

enable_kernel_config() {
	local config=$1
	local symbol=$2

	if grep -q "^# $symbol is not set$" "$config"; then
		sed -i "s/^# $symbol is not set$/$symbol=y/" "$config"
	elif ! grep -q "^$symbol=y$" "$config"; then
		echo "$symbol=y" >> "$config"
	fi
}

set_kernel_config_value() {
	local config=$1
	local symbol=$2
	local value=$3

	if grep -q "^$symbol=" "$config"; then
		sed -i "s/^$symbol=.*/$symbol=$value/" "$config"
	else
		echo "$symbol=$value" >> "$config"
	fi
}

case "${1:-}" in
--debug-shell)
	debug_shell=true
	;;
--debug-shell-android-cmdline)
	debug_shell=true
	android_cmdline=true
	;;
--debug-shell-android-cmdline-no-zboot)
	debug_shell=true
	android_cmdline=true
	no_zboot=true
	;;
--debug-shell-android-cmdline-no-efi-stub)
	debug_shell=true
	android_cmdline=true
	no_zboot=true
	no_efi_stub=true
	;;
--debug-shell-android-cmdline-no-efi-stub-48bit)
	debug_shell=true
	android_cmdline=true
	no_zboot=true
	no_efi_stub=true
	arm64_48bit=true
	;;
--restore-downstream)
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
	;;
"")
	;;
*)
	echo "usage: $0 [--debug-shell|--debug-shell-android-cmdline|--debug-shell-android-cmdline-no-zboot|--debug-shell-android-cmdline-no-efi-stub|--debug-shell-android-cmdline-no-efi-stub-48bit|--restore-downstream]" >&2
	exit 1
	;;
esac

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
sed -i 's/^pkgrel=.*/pkgrel=2/' "$dst_root/linux-postmarketos-qcom-sm8250-lmi/APKBUILD"
if ! grep -q '^deviceinfo_flash_fastboot_partition_rootfs=' "$dst_root/device-xiaomi-lmi/deviceinfo"; then
	sed -i '/^deviceinfo_flash_method="fastboot"$/a deviceinfo_flash_fastboot_partition_rootfs="userdata"' \
		"$dst_root/device-xiaomi-lmi/deviceinfo"
fi
if [ "$debug_shell" = true ]; then
	sed -i 's/^pkgrel=.*/pkgrel=91/' "$dst_root/device-xiaomi-lmi/APKBUILD"
	sed -i 's/^deviceinfo_kernel_cmdline="\(.*\)"/deviceinfo_kernel_cmdline="\1 pmos.debug-shell"/' \
		"$dst_root/device-xiaomi-lmi/deviceinfo"
fi
if [ "$android_cmdline" = true ]; then
	sed -i 's/^pkgrel=.*/pkgrel=92/' "$dst_root/device-xiaomi-lmi/APKBUILD"
	sed -i 's|^deviceinfo_kernel_cmdline=.*|deviceinfo_kernel_cmdline="androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 androidboot.usbcontroller=a600000.dwc3 swiotlb=2048 loop.max_part=7 cgroup.memory=nokmem,nosocket reboot=panic_warm androidboot.fstab_suffix=qcom androidboot.init_fatal_reboot_target=recovery pmos.debug-shell"|' \
		"$dst_root/device-xiaomi-lmi/deviceinfo"
fi
update_sha512_sum "$dst_root/device-xiaomi-lmi/APKBUILD" "$dst_root/device-xiaomi-lmi/deviceinfo" deviceinfo

kernel_apkbuild="$dst_root/linux-postmarketos-qcom-sm8250-lmi/APKBUILD"
kernel_config="$dst_root/linux-postmarketos-qcom-sm8250-lmi/config-postmarketos-qcom-sm8250-lmi.aarch64"
if [ "$no_zboot" = true ]; then
	sed -i 's/^pkgrel=.*/pkgrel=3/' "$kernel_apkbuild"
	disable_kernel_config "$kernel_config" CONFIG_EFI_ZBOOT
fi
if [ "$no_efi_stub" = true ]; then
	sed -i 's/^pkgrel=.*/pkgrel=4/' "$kernel_apkbuild"
	for symbol in \
		CONFIG_EFI_STUB \
		CONFIG_EFI \
		CONFIG_EFI_ESRT \
		CONFIG_EFI_VARS_PSTORE \
		CONFIG_EFI_SOFT_RESERVE \
		CONFIG_EFI_PARAMS_FROM_FDT \
		CONFIG_EFI_RUNTIME_WRAPPERS \
		CONFIG_EFI_GENERIC_STUB \
		CONFIG_EFI_ARMSTUB_DTB_LOADER \
		CONFIG_EFI_CAPSULE_LOADER \
		CONFIG_EFI_EARLYCON \
		CONFIG_EFI_CUSTOM_SSDT_OVERLAYS \
		CONFIG_EFIVAR_FS
	do
		disable_kernel_config "$kernel_config" "$symbol"
	done
fi
if [ "$arm64_48bit" = true ]; then
	sed -i 's/^pkgrel=.*/pkgrel=5/' "$kernel_apkbuild"
	disable_kernel_config "$kernel_config" CONFIG_ARM64_VA_BITS_39
	enable_kernel_config "$kernel_config" CONFIG_ARM64_VA_BITS_48
	disable_kernel_config "$kernel_config" CONFIG_ARM64_VA_BITS_52
	set_kernel_config_value "$kernel_config" CONFIG_ARM64_VA_BITS 48
	enable_kernel_config "$kernel_config" CONFIG_ARM64_PA_BITS_48
	disable_kernel_config "$kernel_config" CONFIG_ARM64_PA_BITS_52
	set_kernel_config_value "$kernel_config" CONFIG_ARM64_PA_BITS 48
	disable_kernel_config "$kernel_config" CONFIG_ARM64_LPA2
fi
update_sha512_sum "$kernel_apkbuild" "$kernel_config" config-postmarketos-qcom-sm8250-lmi.aarch64
perl -0pi -e 's/make zinstall modules_install dtbs_install \\\n\t\tARCH="\$_carch" \\\n\t\tINSTALL_PATH="\$pkgdir"\/boot\/ \\\n\t\tINSTALL_MOD_PATH="\$pkgdir" \\\n\t\tINSTALL_MOD_STRIP=1 \\\n\t\tINSTALL_DTBS_PATH="\$pkgdir\/boot\/dtbs"/make Image modules_install dtbs_install \\\n\t\tARCH="\$_carch" \\\n\t\tINSTALL_MOD_PATH="\$pkgdir" \\\n\t\tINSTALL_MOD_STRIP=1 \\\n\t\tINSTALL_DTBS_PATH="\$pkgdir\/boot\/dtbs"\n\tinstall -Dm755 "\$builddir"\/arch\/arm64\/boot\/Image "\$pkgdir"\/boot\/vmlinuz/s' \
	"$kernel_apkbuild"

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
