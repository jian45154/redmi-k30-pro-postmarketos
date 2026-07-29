#!/usr/bin/bash -p
set -euo pipefail
set +x

PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

readonly SSH=/usr/bin/ssh
readonly SFTP=/usr/bin/sftp
readonly SCP=/usr/bin/scp
readonly PYTHON=/usr/bin/python3
readonly TIMEOUT=/usr/bin/timeout
readonly STAT=/usr/bin/stat
readonly READLINK=/usr/bin/readlink
readonly RM=/usr/bin/rm
readonly RMDIR=/usr/bin/rmdir
readonly REMOTE_FILE=/etc/os-release
readonly OPERATION_TIMEOUT_SECONDS=30
readonly FORWARD_TIMEOUT_SECONDS=10

temp_dir=
sftp_batch=
sftp_output=
download_path=
auth_stderr=
command_stderr=
remote_hash_stdout=
scp_stderr=
forward_stdout=
forward_stderr=
forward_pid=

fail() {
	printf 'refused: %s\n' "$*" >&2
	exit 2
}

usage() {
	cat <<'EOF'
Usage:
  scripts/74_verify_lmi_ssh_full.sh \
    --host HOST --port PORT --user lmi \
    --identity-file PRIVATE_KEY --known-hosts PINNED_KNOWN_HOSTS \
    --local-forward-port UNUSED_HOST_PORT

Run the complete lmi SSH protocol acceptance suite without requesting an
explicit remote mutation:
  - a non-interactive remote command;
  - an explicitly allocated PTY;
  - an SFTP metadata-only query;
  - an SCP download whose client trace must select SFTP transport; and
  - a client-originated local TCP forward bound to 127.0.0.1.

The remote file is fixed at /etc/os-release. It must be readable and not
writable by lmi. All checks are mandatory; this helper has no implicit skips.
The known_hosts file and private key must be explicit, canonical regular files.
known_hosts must contain exactly one plain ED25519 pin for HOST and PORT.

A real SSH connection may still update sshd/PAM logs, PTY/login accounting, or
access metadata. Those incidental effects are not remote mutation commands.
Unit tests validate helper logic only; hardware claims require captured output
from a real-device run against the separately authorized exact image.
EOF
}

stop_forward() {
	local pid=${forward_pid:-}
	[ -n "$pid" ] || return 0
	forward_pid=
	if kill -0 "$pid" 2>/dev/null; then
		kill "$pid" 2>/dev/null || :
	fi
	wait "$pid" 2>/dev/null || :
}

remove_temp() {
	local failed=0 path
	stop_forward
	for path in \
		"$sftp_batch" "$sftp_output" "$download_path" \
		"$auth_stderr" "$command_stderr" \
		"$remote_hash_stdout" "$scp_stderr" \
		"$forward_stdout" "$forward_stderr"; do
		[ -n "$path" ] || continue
		"$RM" -f -- "$path" || failed=1
	done
	if [ -n "$temp_dir" ] && [ -d "$temp_dir" ]; then
		"$RMDIR" -- "$temp_dir" || failed=1
	fi
	temp_dir=
	return "$failed"
}

cleanup() {
	local status=$?
	trap - EXIT
	remove_temp || {
		if [ "$status" -eq 0 ]; then
			status=2
		fi
	}
	exit "$status"
}
trap cleanup EXIT

validate_port() {
	local value=$1 label=$2
	[[ $value =~ ^[1-9][0-9]{0,4}$ ]] ||
		fail "$label must be a decimal integer from 1 through 65535"
	[ "$((10#$value))" -le 65535 ] ||
		fail "$label must be a decimal integer from 1 through 65535"
}

validate_input_file() {
	local path=$1 label=$2 kind=$3 resolved owner links mode mode_value
	[[ $path == /* ]] || fail "$label must be an absolute path"
	[ -f "$path" ] && [ ! -L "$path" ] ||
		fail "$label must be a regular non-symlink"
	resolved=$("$READLINK" -f -- "$path") ||
		fail "$label could not be resolved"
	[ "$resolved" = "$path" ] ||
		fail "$label must be a canonical path"
	owner=$("$STAT" -Lc '%u' -- "$path") ||
		fail "$label ownership could not be read"
	links=$("$STAT" -Lc '%h' -- "$path") ||
		fail "$label link count could not be read"
	mode=$("$STAT" -Lc '%a' -- "$path") ||
		fail "$label mode could not be read"
	[ "$owner" = "$EUID" ] || fail "$label must be owned by the invoking user"
	[ "$links" = 1 ] || fail "$label must have exactly one hard link"
	[ -r "$path" ] && [ -s "$path" ] || fail "$label must be readable and nonempty"
	[[ $mode =~ ^[0-7]{3,4}$ ]] || fail "$label has an invalid mode"
	mode_value=$((8#$mode))
	case "$kind" in
		private)
			[ "$((mode_value & 077))" -eq 0 ] ||
				fail "$label must not grant group or other permissions"
			[ "$((mode_value & 0400))" -ne 0 ] ||
				fail "$label must be owner-readable"
			;;
		pins)
			[ "$((mode_value & 022))" -eq 0 ] ||
				fail "$label must not be group- or other-writable"
			;;
		*)
			fail "internal input-file policy error"
			;;
	esac
}

run_timed() {
	"$TIMEOUT" --foreground --kill-after=2s \
		"${OPERATION_TIMEOUT_SECONDS}s" "$@"
}

host=
port=
user=
identity_file=
known_hosts=
local_forward_port=

while [ "$#" -gt 0 ]; do
	case "$1" in
		--host)
			[ "$#" -ge 2 ] || fail "--host requires a value"
			[ -z "$host" ] || fail "--host may be supplied only once"
			host=$2
			shift 2
			;;
		--port)
			[ "$#" -ge 2 ] || fail "--port requires a value"
			[ -z "$port" ] || fail "--port may be supplied only once"
			port=$2
			shift 2
			;;
		--user)
			[ "$#" -ge 2 ] || fail "--user requires a value"
			[ -z "$user" ] || fail "--user may be supplied only once"
			user=$2
			shift 2
			;;
		--identity-file)
			[ "$#" -ge 2 ] || fail "--identity-file requires a value"
			[ -z "$identity_file" ] ||
				fail "--identity-file may be supplied only once"
			identity_file=$2
			shift 2
			;;
		--known-hosts)
			[ "$#" -ge 2 ] || fail "--known-hosts requires a value"
			[ -z "$known_hosts" ] ||
				fail "--known-hosts may be supplied only once"
			known_hosts=$2
			shift 2
			;;
		--local-forward-port)
			[ "$#" -ge 2 ] || fail "--local-forward-port requires a value"
			[ -z "$local_forward_port" ] ||
				fail "--local-forward-port may be supplied only once"
			local_forward_port=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			fail "unknown argument: $1"
			;;
	esac
done

[ -n "$host" ] || fail "--host is required"
[ -n "$port" ] || fail "--port is required"
[ -n "$user" ] || fail "--user is required"
[ -n "$identity_file" ] || fail "--identity-file is required"
[ -n "$known_hosts" ] || fail "--known-hosts is required"
[ -n "$local_forward_port" ] || fail "--local-forward-port is required"

[[ $host =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] &&
	[[ $host != *".."* ]] && [[ $host != *"." ]] && [[ $host != *"-" ]] ||
	fail "--host must be a plain IPv4 address or DNS hostname"
[[ $user =~ ^[A-Za-z_][A-Za-z0-9_.-]{0,31}$ ]] ||
	fail "--user has an invalid SSH account name"
[ "$user" = lmi ] || fail "--user must be exactly lmi"
validate_port "$port" "--port"
validate_port "$local_forward_port" "--local-forward-port"
validate_input_file "$identity_file" "private key" private
validate_input_file "$known_hosts" "known_hosts file" pins

if [ "$port" = 22 ]; then
	expected_known_host=$host
else
	expected_known_host="[$host]:$port"
fi
pin_fingerprint=
if ! pin_fingerprint=$(/usr/bin/python3 -I -S -B - \
	"$known_hosts" "$expected_known_host" <<'PY'
import base64
import binascii
import hashlib
from pathlib import Path
import re
import struct
import sys

path = Path(sys.argv[1])
expected_host = sys.argv[2]
try:
    data = path.read_bytes()
except OSError:
    raise SystemExit(1)
if not data or len(data) > 16 * 1024:
    raise SystemExit(1)
if data.count(b"\n") != 1 or not data.endswith(b"\n"):
    raise SystemExit(1)
try:
    line = data[:-1].decode("ascii")
except UnicodeDecodeError:
    raise SystemExit(1)
match = re.fullmatch(
    re.escape(expected_host) + r" ssh-ed25519 ([A-Za-z0-9+/]+={0,2})",
    line,
)
if match is None:
    raise SystemExit(1)
try:
    blob = base64.b64decode(match.group(1), validate=True)
except (binascii.Error, ValueError):
    raise SystemExit(1)

def take_string(value, offset):
    if offset + 4 > len(value):
        raise ValueError
    size = struct.unpack_from(">I", value, offset)[0]
    offset += 4
    if offset + size > len(value):
        raise ValueError
    return value[offset:offset + size], offset + size

try:
    algorithm, cursor = take_string(blob, 0)
    key, cursor = take_string(blob, cursor)
except ValueError:
    raise SystemExit(1)
if algorithm != b"ssh-ed25519" or len(key) != 32 or cursor != len(blob):
    raise SystemExit(1)
fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii")
print("SHA256:" + fingerprint.rstrip("="))
PY
); then
	fail "known_hosts must contain exactly one plain ED25519 pin for HOST and PORT"
fi
[[ $pin_fingerprint =~ ^SHA256:[A-Za-z0-9+/]+$ ]] ||
	fail "the ED25519 host-key fingerprint could not be validated"

version_output=
if ! version_output=$("$SSH" -V 2>&1); then
	fail "could not identify the pinned OpenSSH client"
fi
if [[ $version_output =~ OpenSSH_([0-9]+)\. ]]; then
	openssh_major=${BASH_REMATCH[1]}
else
	fail "the pinned SSH client did not report an OpenSSH version"
fi
[ "$openssh_major" -ge 9 ] ||
	fail "OpenSSH 9 or newer is required for SCP's default SFTP transport"

readonly -a CLIENT_POLICY=(
	-F /dev/null
	-o BatchMode=yes
	-o StrictHostKeyChecking=yes
	-o "UserKnownHostsFile=$known_hosts"
	-o GlobalKnownHostsFile=/dev/null
	-o UpdateHostKeys=no
	-o VerifyHostKeyDNS=no
	-o KnownHostsCommand=none
	-o PubkeyAuthentication=yes
	-o PreferredAuthentications=publickey
	-o PasswordAuthentication=no
	-o KbdInteractiveAuthentication=no
	-o GSSAPIAuthentication=no
	-o HostbasedAuthentication=no
	-o IdentitiesOnly=yes
	-o IdentityAgent=none
	-o NumberOfPasswordPrompts=0
	-o ForwardAgent=no
	-o ForwardX11=no
	-o PermitLocalCommand=no
	-o ControlMaster=no
	-o ControlPath=none
	-o ControlPersist=no
	-o ConnectionAttempts=1
	-o ConnectTimeout=10
	-o ServerAliveInterval=5
	-o ServerAliveCountMax=2
	-o EscapeChar=none
)

readonly target="${user}@${host}"
readonly remote_command="printf '%s\\n' lmi-ssh-command-ok"
readonly pty_command="test -t 0 && printf '%s\\n' lmi-ssh-pty-ok"
readonly file_command="test -f $REMOTE_FILE && test -r $REMOTE_FILE && test ! -w $REMOTE_FILE && sha256sum $REMOTE_FILE"

temp_dir=$(/usr/bin/mktemp -d /tmp/lmi-ssh-full.XXXXXXXXXX) ||
	fail "could not create the host temporary directory"
[ -d "$temp_dir" ] && [ ! -L "$temp_dir" ] ||
	fail "the host temporary path is unsafe"
[ "$("$STAT" -Lc '%u:%a' -- "$temp_dir")" = "$EUID:700" ] ||
	fail "the host temporary directory ownership or mode is unsafe"
sftp_batch=$temp_dir/sftp.batch
sftp_output=$temp_dir/sftp.out
download_path=$temp_dir/os-release.download
auth_stderr=$temp_dir/auth.stderr
command_stderr=$temp_dir/command.stderr
remote_hash_stdout=$temp_dir/remote-hash.stdout
scp_stderr=$temp_dir/scp.stderr
forward_stdout=$temp_dir/forward.stdout
forward_stderr=$temp_dir/forward.stderr

command_output=
if ! command_output=$(run_timed "$SSH" "${CLIENT_POLICY[@]}" \
	-v -E "$auth_stderr" -p "$port" -i "$identity_file" \
	-T "$target" "$remote_command" 2> "$command_stderr"); then
	fail "the non-interactive remote command failed"
fi
[ "$command_output" = lmi-ssh-command-ok ] ||
	fail "the non-interactive remote command returned unexpected output"
[ ! -s "$command_stderr" ] ||
	fail "the non-interactive remote command returned unexpected stderr"
authenticated_with_publickey=
while IFS= read -r auth_line; do
	# OpenSSH may terminate -E log lines with CRLF; the PTY check below strips
	# \r for the same reason.
	auth_line=${auth_line//$'\r'/}
	case "$auth_line" in
		'Authenticated to '*' using "publickey".')
			authenticated_with_publickey=yes
			;;
	esac
done < "$auth_stderr"
[ "$authenticated_with_publickey" = yes ] ||
	fail "the SSH client did not prove negotiated public-key authentication"
printf 'PASS remote-command\n'

pty_output=
if ! pty_output=$(run_timed "$SSH" "${CLIENT_POLICY[@]}" \
	-p "$port" -i "$identity_file" -tt "$target" "$pty_command"); then
	fail "the PTY check failed"
fi
pty_output=${pty_output//$'\r'/}
[ "$pty_output" = lmi-ssh-pty-ok ] ||
	fail "the PTY check returned unexpected output"
printf 'PASS pty\n'

if ! run_timed "$SSH" "${CLIENT_POLICY[@]}" \
	-p "$port" -i "$identity_file" -T "$target" "$file_command" \
	> "$remote_hash_stdout"; then
	fail "$REMOTE_FILE is not a readable, non-writable regular file"
fi
remote_hash=
if ! remote_hash=$(/usr/bin/python3 -I -S -B - \
	"$remote_hash_stdout" "$REMOTE_FILE" <<'PY'
from pathlib import Path
import re
import sys

try:
    data = Path(sys.argv[1]).read_bytes()
except OSError:
    raise SystemExit(1)
pattern = rb"([0-9a-f]{64})  " + re.escape(sys.argv[2].encode("ascii")) + rb"\n"
match = re.fullmatch(pattern, data)
if match is None:
    raise SystemExit(1)
print(match.group(1).decode("ascii"))
PY
); then
	fail "the remote file hash response was malformed"
fi
[[ $remote_hash =~ ^[0-9a-f]{64}$ ]] ||
	fail "the remote file hash response was malformed"
printf 'ls -l %s\n' "$REMOTE_FILE" > "$sftp_batch"

if ! run_timed "$SFTP" "${CLIENT_POLICY[@]}" -q \
	-P "$port" -i "$identity_file" -b "$sftp_batch" "$target" \
	> "$sftp_output"; then
	fail "the SFTP metadata-only query failed"
fi
[ -s "$sftp_output" ] ||
	fail "the SFTP metadata-only query returned no listing"
printf 'PASS sftp-metadata\n'

# OpenSSH 9 and newer uses SFTP by default. Deliberately do not pass -O,
# which would select the legacy SCP wire protocol.
if ! run_timed "$SCP" -B "${CLIENT_POLICY[@]}" -v \
	-P "$port" -i "$identity_file" \
	"${target}:${REMOTE_FILE}" "$download_path" 2> "$scp_stderr"; then
	fail "the modern SCP/SFTP download failed"
fi
scp_first_line=
IFS= read -r scp_first_line < "$scp_stderr" || :
case "$scp_first_line" in
	'Executing: program /usr/bin/ssh '*' command sftp') ;;
	*) fail "scp did not prove selection of the SFTP transport" ;;
esac
[ -n "$scp_first_line" ] ||
	fail "scp did not prove selection of the SFTP transport"
[ -f "$download_path" ] && [ ! -L "$download_path" ] ||
	fail "the downloaded host file is not a regular non-symlink"
download_hash=$(/usr/bin/sha256sum -- "$download_path")
download_hash=${download_hash%% *}
[ "$download_hash" = "$remote_hash" ] ||
	fail "the downloaded file does not match the remote non-writable file"
printf 'PASS scp-sftp-download\n'

if ! "$PYTHON" - "$local_forward_port" <<'PY'
import socket
import sys

port = int(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    listener.bind(("127.0.0.1", port))
PY
then
	fail "--local-forward-port is already in use on host loopback"
fi

"$SSH" "${CLIENT_POLICY[@]}" -p "$port" -i "$identity_file" \
	-N -T -o ExitOnForwardFailure=yes \
	-L "127.0.0.1:${local_forward_port}:127.0.0.1:${port}" "$target" \
	> "$forward_stdout" 2> "$forward_stderr" &
forward_pid=$!

if ! "$PYTHON" - "$local_forward_port" "$FORWARD_TIMEOUT_SECONDS" <<'PY'
import socket
import sys
import time

port = int(sys.argv[1])
deadline = time.monotonic() + int(sys.argv[2])
last_error = "no connection attempt completed"
while time.monotonic() < deadline:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5) as stream:
            stream.settimeout(1.0)
            banner = stream.recv(512)
        if banner.startswith(b"SSH-2.0-"):
            raise SystemExit(0)
        last_error = "the forwarded endpoint returned a non-SSH banner"
    except OSError as error:
        last_error = str(error)
    time.sleep(0.05)
raise SystemExit("local forwarding check failed: " + last_error)
PY
then
	fail "the client-originated local TCP forwarding check failed"
fi
stop_forward
printf 'PASS local-tcp-forward\n'

remove_temp || fail "could not remove the host temporary files"
trap - EXIT
printf 'accepted: SSH protocol suite passed with no explicit remote mutation\n'
