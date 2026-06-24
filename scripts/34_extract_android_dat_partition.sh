#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 3 ]; then
	echo "usage: $0 <partition.new.dat.br> <partition.transfer.list> <out-dir>" >&2
	echo "example: $0 vendor.new.dat.br vendor.transfer.list /tmp/lmi-vendor" >&2
	exit 2
fi

dat_br=$1
transfer=$2
out_dir=$3

[ -f "$dat_br" ] || { echo "missing new.dat.br: $dat_br" >&2; exit 1; }
[ -f "$transfer" ] || { echo "missing transfer list: $transfer" >&2; exit 1; }

mkdir -p "$out_dir"
name=${dat_br##*/}
name=${name%.new.dat.br}
new_dat="$out_dir/$name.new.dat"
raw_img="$out_dir/$name.raw.img"
files_dir="$out_dir/$name.files"

echo "decompressing $dat_br"
brotli -d -f "$dat_br" -o "$new_dat"

echo "converting $new_dat with $transfer"
python3 - "$new_dat" "$transfer" "$raw_img" <<'PY'
import os
import sys

BLOCK_SIZE = 4096

new_dat, transfer_list, out_img = sys.argv[1:4]

def parse_ranges(spec):
    nums = [int(x) for x in spec.strip().split(",") if x]
    if not nums:
        return []
    count = nums[0]
    pairs = nums[1:]
    if count != len(pairs):
        raise ValueError(f"range count mismatch: {count} != {len(pairs)}")
    if count % 2:
        raise ValueError(f"range count is not even: {count}")
    return list(zip(pairs[0::2], pairs[1::2]))

with open(transfer_list, "r", encoding="utf-8") as f:
    lines = [line.strip() for line in f if line.strip()]

if len(lines) < 4:
    raise SystemExit("transfer list is too short")

version = int(lines[0])
total_blocks = int(lines[1])
if version < 2:
    raise SystemExit(f"unsupported transfer list version: {version}")

with open(new_dat, "rb") as src, open(out_img, "w+b") as dst:
    dst.truncate(total_blocks * BLOCK_SIZE)
    for line in lines[4:]:
        parts = line.split()
        command = parts[0]
        if command == "new":
            for start, end in parse_ranges(parts[1]):
                blocks = end - start
                data = src.read(blocks * BLOCK_SIZE)
                if len(data) != blocks * BLOCK_SIZE:
                    raise SystemExit("new.dat ended early")
                dst.seek(start * BLOCK_SIZE)
                dst.write(data)
        elif command in {"erase", "zero"}:
            # The output file is already sparse-zeroed.
            continue
        elif command in {"stash", "free", "move"}:
            raise SystemExit(f"unsupported transfer command: {command}")
        else:
            raise SystemExit(f"unknown transfer command: {command}")

print(f"wrote {out_img} ({os.path.getsize(out_img)} bytes)")
PY

if command -v 7z >/dev/null 2>&1; then
	echo "extracting filesystem with 7z into $files_dir"
	rm -rf "$files_dir"
	mkdir -p "$files_dir"
	if 7z x "$raw_img" -o"$files_dir" >/dev/null; then
		echo "files=$files_dir"
	else
		echo "7z could not extract $raw_img; this is expected for EROFS images with old p7zip." >&2
		echo "Use erofs-utils, erofsfuse, or a read-only kernel mount to inspect $raw_img." >&2
	fi
else
	echo "7z not found; raw image is ready at $raw_img"
fi

echo "raw_image=$raw_img"
