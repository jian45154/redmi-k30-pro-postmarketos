#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
	builtin printf '%s\n' \
		'usage: 70_build_downstream_ssh_wifi.sh POLICY_ID TAG' >&2
	exit 64
fi

policy_id=$1
tag=$2
if [[ ! $policy_id =~ ^[0-9a-f]{64}$ ]]; then
	builtin printf '%s\n' 'invalid lmi P1 policy id' >&2
	exit 64
fi
if [[ ! $tag =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
	builtin printf '%s\n' 'invalid lmi P1 build tag' >&2
	exit 64
fi

request_json=$(builtin printf \
	'{"policy_id":"%s","schema":"lmi-p1-build-request/v1","tag":"%s"}' \
	"$policy_id" "$tag")
request_length=$((${#request_json} + 1))
if ((request_length <= 0 || request_length > 4096)); then
	builtin printf '%s\n' 'lmi P1 request exceeds 4 KiB' >&2
	exit 64
fi

umask 077
request_file=$(/usr/bin/mktemp /tmp/lmi-p1-build-request.XXXXXXXX)
cleanup() {
	/bin/rm -f -- "$request_file"
}
trap cleanup EXIT HUP INT TERM

builtin printf -v request_length_escape \
	'\\x%02x\\x%02x\\x%02x\\x%02x' \
	$(((request_length >> 24) & 255)) \
	$(((request_length >> 16) & 255)) \
	$(((request_length >> 8) & 255)) \
	$((request_length & 255))
{
	builtin printf '%s' 'LMIR'
	builtin printf '%b' "$request_length_escape"
	builtin printf '%s\n' "$request_json"
} >"$request_file"
/bin/chmod 0600 "$request_file"
/usr/bin/sync -f "$request_file"

/usr/bin/sudo -n -- /usr/bin/python3 -I -S -B \
	/usr/local/sbin/lmi-p1-root-launcher <"$request_file"
