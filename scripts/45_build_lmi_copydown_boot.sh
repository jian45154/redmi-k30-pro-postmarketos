#!/usr/bin/env bash
set -euo pipefail

repo=${REPO:-$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}
boot_repo=${LMI_BOOT_REPO:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/sm8250-xiaomi-lmi-boot}
initramfs=${LMI_COPYDOWN_RAMDISK:-/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/sm8250-xiaomi-lmi-initramfs/out/initramfs-sm8250-xiaomi-lmi.cpio.gz}
export_dir=${PMOS_EXPORT_DIR:-/tmp/postmarketOS-export}
out_dir=${OUT_DIR:-/tmp/lmi-copydown-r5-20260624}

kernel=${LMI_COPYDOWN_KERNEL:-$export_dir/vmlinuz}
runtime_dtb=${LMI_COPYDOWN_RUNTIME_DTB:-$export_dir/dtbs/sm8250-xiaomi-lmi.dtb}
stock_dtb=${LMI_COPYDOWN_STOCK_DTB:-$boot_repo/out/bootimgsu19-6-unpacked/dtb}
stock_kernel_dtb=${LMI_COPYDOWN_STOCK_KERNEL_DTB:-$out_dir/stock-kernel-dtb.empty}

script_src=$boot_repo/scripts/mkboot-linux-copydown-lmi.sh
args_src=$boot_repo/locks/mkbootimg.args
script_tmp=$out_dir/mkboot-linux-copydown-lmi.sh
args_tmp=$out_dir/mkbootimg.args
kernel_copy=$out_dir/vmlinuz-for-copydown
kernel_gzip=$kernel_copy.gz

for path in "$script_src" "$args_src" "$kernel" "$runtime_dtb" "$initramfs" "$stock_dtb"; do
	[ -f "$path" ] || {
		echo "missing file: $path" >&2
		exit 2
	}
done

mkdir -p "$out_dir"
perl -pe 's/\r$//' "$script_src" > "$script_tmp"
perl -0pi -e 's|^REPO_DIR=.*$|REPO_DIR="'"$boot_repo"'"|m' "$script_tmp"
perl -pe 's/\r$//' "$args_src" > "$args_tmp"

if [ ! -f "$stock_kernel_dtb" ]; then
	: > "$stock_kernel_dtb"
fi

cp -f "$kernel" "$kernel_copy"
gzip -n -f "$kernel_copy"

OUT_DIR="$out_dir" \
LINUX_GZIP="$kernel_gzip" \
RUNTIME_DTB="$runtime_dtb" \
RAMDISK="$initramfs" \
STOCK_DTB="$stock_dtb" \
STOCK_KERNEL_DTB="$stock_kernel_dtb" \
MKBOOTIMG_ARGS_FILE="$args_tmp" \
bash "$script_tmp"

echo "copydown boot image: $out_dir/boot-linux-copydown-lmi.img"
echo "copydown manifest: $out_dir/boot-linux-copydown-lmi.manifest"
