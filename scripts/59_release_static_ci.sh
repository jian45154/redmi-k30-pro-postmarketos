#!/usr/bin/env bash
set -euo pipefail

max_tracked_file_bytes=${LMI_MAX_TRACKED_FILE_BYTES:-10485760}

echo "release static CI: shell syntax"
while IFS= read -r script; do
	echo "  bash -n $script"
	bash -n "$script"
done < <(git ls-files 'scripts/*.sh' | sort)

echo "release static CI: python syntax"
while IFS= read -r script; do
	echo "  compile $script"
	python3 - "$script" <<'PY'
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
source = path.read_text()
compile(source, str(path), "exec")
PY
done < <(git ls-files 'scripts/*.py' | sort)

echo "release static CI: release docs"
manifest=docs/release/lmi-r6-bootmem-release-manifest-20260624.md
checklist=docs/release/lmi-r6-bootmem-execution-checklist-20260624.md

for path in "$manifest" "$checklist"; do
	[ -f "$path" ] || {
		echo "missing release doc: $path" >&2
		exit 1
	}
done

grep -q 'WAITING_FOR_RECOVERY_FASTBOOTD' "$manifest"
grep -q 'WAITING_FOR_RECOVERY_FASTBOOTD' "$checklist"
grep -q 'is-userspace: `no`' "$manifest"
grep -q 'is-userspace: `no`' "$checklist"
grep -q 'fastboot reboot fastboot' "$checklist"
grep -q 'scripts/60_stage_lmi_enter_fastbootd.sh --dry-run' "$checklist"
grep -q 'Do not touch `super`' "$manifest"
grep -q 'Do not write `super`' "$checklist"

echo "release static CI: tracked file size"
oversized=0
while IFS= read -r path; do
	size=$(stat -c '%s' "$path")
	if [ "$size" -gt "$max_tracked_file_bytes" ]; then
		echo "tracked file too large: $path ($size bytes > $max_tracked_file_bytes)" >&2
		oversized=1
	fi
done < <(git ls-files)

if [ "$oversized" -ne 0 ]; then
	exit 1
fi

echo "release static CI: no tracked release image payloads"
if git ls-files | grep -E '(^|/)(boot-linux-copydown-lmi-r6-bootmem\.img|xiaomi-lmi-r6-bootmem\.img|pmbootstrap-direct-boot-r6-bootmem\.img|vmlinuz-r6-bootmem|initramfs-r6-bootmem|sm8250-xiaomi-lmi-r6-bootmem\.dtb)$'; then
	echo "release payload file is tracked; keep large/generated payloads out of git" >&2
	exit 1
fi

echo "release static CI: OK"
