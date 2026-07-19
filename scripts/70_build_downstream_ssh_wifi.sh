#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(dirname "$script_dir")

printf '%s\n' \
	'deprecated: use python3 scripts/lmi_p1_cli.py build directly' >&2
cd "$repo"
exec python3 scripts/lmi_p1_cli.py build "$@"
