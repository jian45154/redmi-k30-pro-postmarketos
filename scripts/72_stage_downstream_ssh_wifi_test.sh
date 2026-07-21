#!/usr/bin/bash -p
set -euo pipefail
set +x

# This is a deliberately narrow D110/D114 recovery gate. Caller-selected
# artifacts, tools, UUIDs, products, and battery thresholds are not accepted.
PATH=/usr/bin:/bin
export PATH
LC_ALL=C
export LC_ALL
umask 077

readonly CLAIM='No explicit fastboot partition flash; the booted OS may mutate persisted userdata.'
readonly TRUSTED_POLICY_SHA256='18d3efc57152f297784e0b97af221789e4d508a73d5485e3fac3c5ba94c232cd'
readonly POLICY_REL='private/lmi-p1/recovery/d110-d114/d110-recovery-policy.json'
readonly POWERSHELL='/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
readonly WSLPATH='/usr/bin/wslpath'
readonly READ_ONLY_TIMEOUT=10
execute_deadline_epoch=
session_lock_fd=

fail() {
	printf 'refused: %s\n' "$*" >&2
	exit 2
}

usage() {
	cat <<'EOF'
Usage:
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --dry-run
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --preflight
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --authorize-session
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --execute
  scripts/72_stage_downstream_ssh_wifi_test.sh --stage ramboot --revoke-session

Preflight is read-only. Authorize-session performs the same complete read-only
preflight, then grants the current CODEX_THREAD_ID session ongoing authority for
this exact policy, helper, host boot, artifact, device, stage, operation, and
tool. The grant has no short chat-confirmation TTL; it remains valid within the
pinned session safety ceiling until explicit local revocation or any bound
input changes. The raw session ID is neither stored nor printed. It is a thread
scope discriminator, not an independent cryptographic authentication factor.

Execute needs no caller receipt or confirmation. It verifies the same session
grant under a non-blocking exclusive lock, repeats the complete preflight, then
creates and immediately consumes an internal 30-second one-shot attempt receipt
before rechecking and attempting exactly one pinned fastboot boot command. It
never retries. Only one execute may be in progress at a time.

No explicit fastboot partition flash; the booted OS may mutate persisted userdata.
EOF
}

script_input=${BASH_SOURCE[0]}
[ -n "$script_input" ] || fail "script path is unavailable"
[ ! -L "$script_input" ] || fail "the helper itself must not be a symlink"
script_path=$(/usr/bin/readlink -f -- "$script_input") || fail "could not resolve the helper"
[ -f "$script_path" ] && [ ! -L "$script_path" ] || fail "helper path is not a regular file"
script_dir=${script_path%/*}
repo=$(/usr/bin/readlink -f -- "$script_dir/..") || fail "could not resolve repository root"
policy_path=$repo/$POLICY_REL

mode=
stage=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--stage)
			[ "$#" -ge 2 ] || fail "--stage requires a value"
			stage=$2
			shift 2
			;;
		--dry-run|--preflight|--authorize-session|--execute|--revoke-session)
			[ -z "$mode" ] || fail "choose exactly one mode"
			mode=$1
			shift
			;;
		--receipt|--confirm|--session-id)
			fail "$1 is a retired caller-approval interface and is not accepted"
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			fail "unknown argument"
			;;
	esac
done

[ "$stage" = ramboot ] || fail "--stage ramboot is required; this gate cannot flash userdata"
case "$mode" in
	--dry-run|--preflight|--authorize-session|--execute|--revoke-session) ;;
	*) fail "choose exactly one documented mode" ;;
esac

# Refuse former caller-selectable trust and approval inputs instead of silently
# ignoring them. CODEX_THREAD_ID is the sole session identity input.
for legacy_name in \
	REPO FASTBOOT DOWNSTREAM_BOOT_IMG DOWNSTREAM_USERDATA_IMG \
	DOWNSTREAM_MANIFEST DOWNSTREAM_FASTBOOT_SHA256 \
	DOWNSTREAM_EXPECTED_BOOT_UUID DOWNSTREAM_EXPECTED_ROOT_UUID \
	DOWNSTREAM_MIN_BATTERY_MV DOWNSTREAM_FASTBOOT_TIMEOUT \
	DOWNSTREAM_FASTBOOT_ACTION_TIMEOUT DOWNSTREAM_RAMBOOT_CONFIRM \
	DOWNSTREAM_ROOTFS_CONFIRM; do
	if [[ -v $legacy_name ]]; then
		fail "$legacy_name is not accepted by the pinned D110 recovery gate"
	fi
done

capture_helper_identity() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B - "$script_path" <<'PY'
import hashlib
import os
from pathlib import Path
import stat
import sys

path = Path(sys.argv[1])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
try:
    fd = os.open(path, flags)
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_nlink != 1 or stat.S_IMODE(before.st_mode) & 0o111 == 0):
        raise OSError
    digest = hashlib.sha256()
    while True:
        chunk = os.read(fd, 1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
    after = os.fstat(fd)
finally:
    try:
        os.close(fd)
    except NameError:
        pass
identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
                       st.st_mtime_ns, st.st_ctime_ns)
if identity(before) != identity(after):
    raise SystemExit(1)
print(digest.hexdigest() + "\t" + ":".join(map(str, identity(before))))
PY
	)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the helper identity could not be captured safely"
	IFS=$'\t' read -r helper_sha helper_identity <<< "$output"
	[[ $helper_sha =~ ^[0-9a-f]{64}$ ]] && [ -n "$helper_identity" ] || fail "the helper identity record is invalid"
}

verify_helper_identity() {
	local captured_sha=$helper_sha captured_identity=$helper_identity
	capture_helper_identity
	[ "$helper_sha" = "$captured_sha" ] && [ "$helper_identity" = "$captured_identity" ] \
		|| fail "the helper changed during the gated operation"
}

# Verify the private policy, its historical D199/D200 identity evidence, both
# exact manifests, and the complete Android boot image semantics. The verifier
# emits only fixed policy fields; it never emits the raw serial or the private
# historical fingerprint.
capture_local_policy() {
	local output
	set +e
	output=$(/usr/bin/python3 -I -S -B - "$repo" "$policy_path" "$TRUSTED_POLICY_SHA256" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import uuid

repo = Path(sys.argv[1])
policy_path = Path(sys.argv[2])
trusted_sha = sys.argv[3]

def die():
    raise SystemExit("private D110 policy or pinned local evidence validation failed")

def pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            die()
        result[key] = value
    return result

def load_json(data):
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=pairs_no_duplicates)
    except (UnicodeError, json.JSONDecodeError):
        die()

def exact_keys(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        die()

def string(value, pattern=None):
    if not isinstance(value, str) or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
        die()
    if pattern is not None and re.fullmatch(pattern, value) is None:
        die()
    return value

def integer(value, minimum, maximum):
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        die()
    return value

def digest(value):
    return string(value, r"[0-9a-f]{64}")

def check_private_parents(path):
    private_root = repo / "private"
    try:
        relative = path.relative_to(private_root)
    except ValueError:
        die()
    try:
        root_st = private_root.lstat()
    except OSError:
        die()
    if not stat.S_ISDIR(root_st.st_mode) or stat.S_IMODE(root_st.st_mode) != 0o700 or root_st.st_uid != os.geteuid():
        die()
    current = private_root
    for part in relative.parts[:-1]:
        current = current / part
        try:
            st = current.lstat()
        except OSError:
            die()
        if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700 or st.st_uid != os.geteuid():
            die()

def private_file(path, wanted_sha=None, wanted_size=None):
    check_private_parents(path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        die()
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
                or before.st_uid != os.geteuid() or before.st_nlink != 1):
            die()
        chunks = []
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        after = os.fstat(fd)
        identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if identity(before) != identity(after):
            die()
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if len(data) != before.st_size:
        die()
    actual_sha = hashlib.sha256(data).hexdigest()
    if wanted_sha is not None and actual_sha != wanted_sha:
        die()
    if wanted_size is not None and len(data) != wanted_size:
        die()
    return data, actual_sha

def relative_private(value):
    rel = Path(string(value))
    if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
        die()
    path = repo / rel
    try:
        path.relative_to(repo / "private")
    except ValueError:
        die()
    return path

policy_data, policy_sha = private_file(policy_path)
if policy_sha != trusted_sha or policy_path != repo / "private/lmi-p1/recovery/d110-d114/d110-recovery-policy.json":
    die()
policy = load_json(policy_data)
exact_keys(policy, ("schema", "policy_id", "claim", "historical_identity", "artifact", "fastboot", "device", "approval", "execution"))
if policy["schema"] != "lmi-d110-recovery-policy/v2":
    die()
string(policy["policy_id"])
if policy["claim"] != "No explicit fastboot partition flash; the booted OS may mutate persisted userdata.":
    die()

history = policy["historical_identity"]
exact_keys(history, ("privacy_nonce", "expected_nonce_scoped_serial_sha256", "legacy_fingerprint", "d199_path", "d199_sha256", "d200_path", "d200_sha256"))
privacy_nonce = digest(history["privacy_nonce"])
expected_identity = digest(history["expected_nonce_scoped_serial_sha256"])
legacy_fingerprint = string(history["legacy_fingerprint"], r"[0-9a-f]{16}")
d199_path = relative_private(history["d199_path"])
d200_path = relative_private(history["d200_path"])
d199 = load_json(private_file(d199_path, digest(history["d199_sha256"]))[0])
d200 = load_json(private_file(d200_path, digest(history["d200_sha256"]))[0])
try:
    d199_fp = d199["gates"]["identity"]["expected_device_fingerprint"]
    d200_fp = d200["gates"]["identity"]["expected_device_fingerprint"]
    d199_product = d199["gates"]["identity"]["expected_product"]
    d200_product = d200["gates"]["identity"]["expected_product"]
    d200_boot = d200["execution_contract"]["artifact_sha256"]
    d200_manifest = d200["gates"]["artifact"]["manifest_sha256"]
except (KeyError, TypeError):
    die()
if d199_fp != legacy_fingerprint or d200_fp != legacy_fingerprint:
    die()

artifact = policy["artifact"]
exact_keys(artifact, ("boot_path", "boot_sha256", "boot_size", "boot_manifest_path", "boot_manifest_sha256", "pair_manifest_path", "pair_manifest_sha256", "kernel_sha256", "ramdisk_sha256", "dtb_sha256", "boot_uuid", "root_uuid", "historical_persisted_userdata_release", "historical_persisted_userdata_sha256"))
boot_sha = digest(artifact["boot_sha256"])
boot_size = integer(artifact["boot_size"], 4097, 128 * 1024 * 1024)
kernel_sha = digest(artifact["kernel_sha256"])
ramdisk_sha = digest(artifact["ramdisk_sha256"])
dtb_sha = digest(artifact["dtb_sha256"])
boot_uuid = string(artifact["boot_uuid"], r"[0-9a-f-]{36}")
root_uuid = string(artifact["root_uuid"], r"[0-9a-f-]{36}")
userdata_sha = digest(artifact["historical_persisted_userdata_sha256"])
if artifact["historical_persisted_userdata_release"] != "D114":
    die()
boot_path = relative_private(artifact["boot_path"])
boot_manifest_path = relative_private(artifact["boot_manifest_path"])
pair_manifest_path = relative_private(artifact["pair_manifest_path"])
boot_data = private_file(boot_path, boot_sha, boot_size)[0]
boot_manifest_data = private_file(boot_manifest_path, digest(artifact["boot_manifest_sha256"]))[0]
pair_manifest_data = private_file(pair_manifest_path, digest(artifact["pair_manifest_sha256"]))[0]

def manifest(data):
    try:
        text = data.decode("ascii")
    except UnicodeError:
        die()
    result = {}
    for line in text.splitlines():
        if not line:
            continue
        if "=" not in line:
            die()
        key, value = line.split("=", 1)
        if not key or key in result or not value or any(ord(c) < 32 or ord(c) == 127 for c in value):
            die()
        result[key] = value
    return result

bm = manifest(boot_manifest_data)
pm = manifest(pair_manifest_data)
expected_name = boot_path.name
if (bm.get("artifact_boot") != expected_name or bm.get("artifact_boot_sha256") != boot_sha
        or bm.get("artifact_boot_size") != str(boot_size) or bm.get("kernel_sha256") != kernel_sha
        or bm.get("source_ramdisk_sha256") != ramdisk_sha or bm.get("dtb_sha256") != dtb_sha):
    die()
if (pm.get("artifact_boot") != expected_name or pm.get("artifact_boot_sha256") != boot_sha
        or pm.get("artifact_boot_size") != str(boot_size)
        or pm.get("artifact_userdata_sha256") != userdata_sha):
    die()
if d200_boot != boot_sha or d200_manifest != artifact["pair_manifest_sha256"]:
    die()

if len(boot_data) <= 4096 or boot_data[:8] != b"ANDROID!":
    die()
u32 = lambda offset: struct.unpack_from("<I", boot_data, offset)[0]
kernel_size, kernel_addr = u32(8), u32(12)
ramdisk_size, ramdisk_addr = u32(16), u32(20)
second_size, second_addr = u32(24), u32(28)
tags_addr, page_size, header_version, os_version = u32(32), u32(36), u32(40), u32(44)
recovery_size, recovery_offset = u32(1632), struct.unpack_from("<Q", boot_data, 1636)[0]
header_size, dtb_size, dtb_addr = u32(1644), u32(1648), struct.unpack_from("<Q", boot_data, 1652)[0]
geometry = ((kernel_addr, 0x00008000), (ramdisk_addr, 0x01000000), (second_size, 0),
            (second_addr, 0), (tags_addr, 0x00000100), (page_size, 4096),
            (header_version, 2), (os_version, 0), (recovery_size, 0),
            (recovery_offset, 0), (header_size, 1660), (dtb_addr, 0x01F00000))
if any(a != b for a, b in geometry) or not kernel_size or not ramdisk_size or not dtb_size:
    die()
if kernel_size > 64 * 1024 * 1024 or ramdisk_size > 64 * 1024 * 1024 or dtb_size > 4 * 1024 * 1024:
    die()
if any(boot_data[48:64]) or any(boot_data[1660:page_size]):
    die()

def align(value):
    return (value + page_size - 1) // page_size * page_size

def region(offset, length):
    end = offset + length
    padded = offset + align(length)
    if end > len(boot_data) or padded > len(boot_data) or any(boot_data[end:padded]):
        die()
    return boot_data[offset:end], padded

kernel, cursor = region(page_size, kernel_size)
ramdisk, cursor = region(cursor, ramdisk_size)
dtb, cursor = region(cursor, dtb_size)
if any(boot_data[cursor:]):
    die()
image_id = hashlib.sha1(usedforsecurity=False)
for component in (kernel, ramdisk, b"", b"", dtb):
    image_id.update(component)
    image_id.update(struct.pack("<I", len(component)))
if boot_data[576:608] != image_id.digest() + b"\0" * 12:
    die()
if hashlib.sha256(kernel).hexdigest() != kernel_sha or hashlib.sha256(ramdisk).hexdigest() != ramdisk_sha or hashlib.sha256(dtb).hexdigest() != dtb_sha:
    die()
try:
    cmdline = (boot_data[64:576].split(b"\0", 1)[0] + boot_data[608:1632].split(b"\0", 1)[0]).decode("ascii")
except UnicodeError:
    die()
tokens = cmdline.split()
if "androidboot.hardware=qcom" not in tokens or "androidboot.usbcontroller=a600000.dwc3" not in tokens:
    die()
def one(name):
    values = [token.split("=", 1)[1] for token in tokens if token.startswith(name + "=")]
    if len(values) != 1:
        die()
    try:
        parsed = uuid.UUID(values[0])
    except ValueError:
        die()
    if str(parsed) != values[0] or parsed.version != 4 or parsed.variant != uuid.RFC_4122:
        die()
    return values[0]
if one("pmos_boot_uuid") != boot_uuid or one("pmos_root_uuid") != root_uuid:
    die()
manifest_tokens = bm.get("cmdline", "").split()
if f"pmos_boot_uuid={boot_uuid}" not in manifest_tokens or f"pmos_root_uuid={root_uuid}" not in manifest_tokens:
    die()

fastboot = policy["fastboot"]
exact_keys(fastboot, ("acquisition_attestation_path", "acquisition_attestation_sha256", "host_path_kind", "host_path", "sha256", "size"))
host_kind = string(fastboot["host_path_kind"])
if host_kind not in ("linux", "windows"):
    die()
host_path = string(fastboot["host_path"])
if "\t" in host_path or (host_kind == "linux" and not host_path.startswith("/")) or (host_kind == "windows" and re.fullmatch(r"[A-Za-z]:\\[^\r\n\t]+", host_path) is None):
    die()
fastboot_sha = digest(fastboot["sha256"])
fastboot_size = integer(fastboot["size"], 1, 128 * 1024 * 1024)
acquisition_path = relative_private(fastboot["acquisition_attestation_path"])
acquisition_sha = digest(fastboot["acquisition_attestation_sha256"])
acquisition = load_json(private_file(acquisition_path, acquisition_sha)[0])
exact_keys(acquisition, ("archive", "device_action_performed", "installed_copy", "member", "observed_local_date", "repository_metadata", "schema"))
if acquisition["schema"] != "lmi-d110-fastboot-official-acquisition/v1" or acquisition["device_action_performed"] is not False:
    die()
exact_keys(acquisition["archive"], ("filename", "sha1", "sha256", "size", "url"))
exact_keys(acquisition["member"], ("path", "sha256", "size"))
exact_keys(acquisition["installed_copy"], ("byte_identical_to_archive_member", "path", "sha256", "size"))
exact_keys(acquisition["repository_metadata"], ("package", "url"))
archive = acquisition["archive"]
member = acquisition["member"]
installed = acquisition["installed_copy"]
if (string(archive["filename"]) != "platform-tools_r37.0.0-win.zip"
        or re.fullmatch(r"[0-9a-f]{40}", string(archive["sha1"])) is None
        or re.fullmatch(r"[0-9a-f]{64}", string(archive["sha256"])) is None
        or integer(archive["size"], 1, 128 * 1024 * 1024) < fastboot_size
        or string(archive["url"]) != "https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip"
        or string(acquisition["repository_metadata"]["url"]) != "https://dl.google.com/android/repository/repository2-3.xml"
        or string(member["path"]) != "platform-tools/fastboot.exe"
        or digest(member["sha256"]) != fastboot_sha or integer(member["size"], 1, 128 * 1024 * 1024) != fastboot_size
        or installed["byte_identical_to_archive_member"] is not True
        or string(installed["path"]) != host_path or digest(installed["sha256"]) != fastboot_sha
        or integer(installed["size"], 1, 128 * 1024 * 1024) != fastboot_size):
    die()

device = policy["device"]
exact_keys(device, ("product", "unlocked", "is_userspace", "minimum_battery_mv", "battery_soc_ok", "minimum_max_download_size"))
product = string(device["product"], r"[a-z0-9._-]+")
unlocked = string(device["unlocked"])
is_userspace = string(device["is_userspace"])
battery_soc_ok = string(device["battery_soc_ok"])
minimum_battery = integer(device["minimum_battery_mv"], 3500, 5000)
minimum_download = integer(device["minimum_max_download_size"], boot_size, 2**63 - 1)
if d199_product != product or d200_product != product or unlocked != "yes" or is_userspace != "no" or battery_soc_ok != "yes":
    die()

approval = policy["approval"]
exact_keys(approval, ("mode", "session_id_environment", "grant_dir", "explicit_revocation", "session_max_seconds", "host_boot_id_path"))
if (approval["mode"] != "codex-thread-session"
        or approval["session_id_environment"] != "CODEX_THREAD_ID"
        or approval["explicit_revocation"] is not True
        or approval["host_boot_id_path"] != "/proc/sys/kernel/random/boot_id"):
    die()
session_max_seconds = integer(approval["session_max_seconds"], 60, 86400)
grant_dir = relative_private(approval["grant_dir"])
if grant_dir.parent != policy_path.parent:
    die()

execution = policy["execution"]
exact_keys(execution, ("operation", "explicit_fastboot_partition_flash", "booted_os_may_mutate_persisted_userdata", "receipt_ttl_seconds", "max_action_attempts", "automatic_retry", "action_timeout_seconds", "receipt_dir"))
if (execution["operation"] != "fastboot boot" or execution["explicit_fastboot_partition_flash"] is not False
        or execution["booted_os_may_mutate_persisted_userdata"] is not True
        or execution["max_action_attempts"] != 1 or execution["automatic_retry"] is not False):
    die()
ttl = integer(execution["receipt_ttl_seconds"], 30, 300)
action_timeout = integer(execution["action_timeout_seconds"], 1, 300)
receipt_dir = relative_private(execution["receipt_dir"])
if receipt_dir.parent != policy_path.parent or receipt_dir == grant_dir:
    die()

action_binding = {
    "policy_sha256": policy_sha,
    "claim": policy["claim"],
    "stage": "ramboot",
    "operation": "fastboot boot",
    "boot_sha256": boot_sha,
    "boot_size": boot_size,
    "boot_manifest_sha256": artifact["boot_manifest_sha256"],
    "pair_manifest_sha256": artifact["pair_manifest_sha256"],
    "kernel_sha256": kernel_sha,
    "ramdisk_sha256": ramdisk_sha,
    "dtb_sha256": dtb_sha,
    "boot_uuid": boot_uuid,
    "root_uuid": root_uuid,
    "fastboot_sha256": fastboot_sha,
    "fastboot_host_path": host_path,
    "fastboot_acquisition_attestation_sha256": acquisition_sha,
    "expected_device_identity_sha256": expected_identity,
    "device_policy": device,
    "approval_policy": approval,
    "execution_policy": {
        "explicit_fastboot_partition_flash": execution["explicit_fastboot_partition_flash"],
        "booted_os_may_mutate_persisted_userdata": execution["booted_os_may_mutate_persisted_userdata"],
        "receipt_ttl_seconds": ttl,
        "max_action_attempts": execution["max_action_attempts"],
        "automatic_retry": execution["automatic_retry"],
        "action_timeout_seconds": action_timeout,
    },
}
action_digest = hashlib.sha256(json.dumps(action_binding, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

fields = (privacy_nonce, expected_identity, legacy_fingerprint, str(boot_path), boot_sha,
          str(boot_size), str(boot_manifest_path), artifact["boot_manifest_sha256"],
          str(pair_manifest_path), artifact["pair_manifest_sha256"], boot_uuid, root_uuid,
          kernel_sha, ramdisk_sha, dtb_sha, host_kind, host_path, fastboot_sha,
          str(fastboot_size), product, unlocked, is_userspace, str(minimum_battery),
          battery_soc_ok, str(minimum_download), str(ttl), str(action_timeout),
          str(receipt_dir), str(grant_dir), str(session_max_seconds), action_digest, "END")
if any("\t" in field or "\n" in field or "\r" in field for field in fields):
    die()
print("\t".join(fields))
PY
	)
	local status=$?
	set -e
	[ "$status" -eq 0 ] || fail "private D110 policy or pinned local evidence validation failed"
	IFS=$'\t' read -r privacy_nonce expected_identity historical_fingerprint \
		boot_path boot_sha boot_size boot_manifest_path boot_manifest_sha \
		pair_manifest_path pair_manifest_sha boot_uuid root_uuid kernel_sha \
		ramdisk_sha dtb_sha fastboot_host_kind fastboot_host_path fastboot_sha \
		fastboot_size expected_product expected_unlocked expected_userspace \
		minimum_battery_mv expected_battery_soc minimum_max_download receipt_ttl \
		action_timeout receipt_dir grant_dir session_max_seconds action_digest output_end <<< "$output"
	[ "$output_end" = END ] || fail "local policy verifier returned an invalid record"
}

capture_fastboot_tool() {
	local before after actual_sha roundtrip
	case "$fastboot_host_kind" in
		linux) fastboot_bin=$fastboot_host_path ;;
		windows)
			[ -x "$WSLPATH" ] || fail "fixed wslpath is unavailable"
			fastboot_bin=$($WSLPATH -u "$fastboot_host_path" | /usr/bin/tr -d '\r') || fail "could not translate the pinned fastboot path"
			roundtrip=$($WSLPATH -w "$fastboot_bin" | /usr/bin/tr -d '\r') || fail "could not round-trip the pinned fastboot path"
			[ "$roundtrip" = "$fastboot_host_path" ] || fail "pinned fastboot path does not round-trip exactly"
			;;
		*) fail "invalid fastboot path kind" ;;
	esac
	case "$fastboot_bin" in /*) ;; *) fail "fastboot did not resolve to an absolute path" ;; esac
	[ ! -L "$fastboot_bin" ] && [ -f "$fastboot_bin" ] && [ -x "$fastboot_bin" ] || fail "pinned fastboot is not an executable regular non-symlink file"
	[ "$(/usr/bin/stat -c '%h' -- "$fastboot_bin")" = 1 ] || fail "pinned fastboot must have exactly one hard link"
	before=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not inspect pinned fastboot"
	[ "$(/usr/bin/stat -c '%s' -- "$fastboot_bin")" = "$fastboot_size" ] || fail "pinned fastboot size mismatch"
	actual_sha=$(/usr/bin/sha256sum -- "$fastboot_bin" | /usr/bin/awk 'NR == 1 { print $1 }')
	[ "$actual_sha" = "$fastboot_sha" ] || fail "pinned fastboot SHA-256 mismatch"
	after=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not reinspect pinned fastboot"
	[ "$before" = "$after" ] || fail "pinned fastboot changed while it was hashed"
	fastboot_identity=$before
}

verify_fastboot_tool() {
	local before after actual_sha
	[ ! -L "$fastboot_bin" ] && [ -f "$fastboot_bin" ] && [ -x "$fastboot_bin" ] || fail "pinned fastboot changed type"
	[ "$(/usr/bin/stat -c '%h' -- "$fastboot_bin")" = 1 ] || fail "pinned fastboot hard-link count changed"
	before=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not inspect pinned fastboot"
	[ "$before" = "$fastboot_identity" ] || fail "pinned fastboot identity changed"
	actual_sha=$(/usr/bin/sha256sum -- "$fastboot_bin" | /usr/bin/awk 'NR == 1 { print $1 }')
	[ "$actual_sha" = "$fastboot_sha" ] || fail "pinned fastboot SHA-256 changed"
	after=$(/usr/bin/stat -c '%d:%i:%f:%h:%s:%y:%z' -- "$fastboot_bin") || fail "could not reinspect pinned fastboot"
	[ "$after" = "$fastboot_identity" ] || fail "pinned fastboot changed during revalidation"
}

bound_timeout_to_execute_deadline() {
	local wanted=$1 now remaining
	bounded_timeout_seconds=$wanted
	[ -n "$execute_deadline_epoch" ] || return 0
	now=$(/usr/bin/date +%s) || fail "could not read the execute deadline clock"
	remaining=$((execute_deadline_epoch - now))
	[ "$remaining" -gt 0 ] || fail "the consumed receipt expired; no fastboot boot action was attempted"
	if [ "$remaining" -lt "$bounded_timeout_seconds" ]; then
		bounded_timeout_seconds=$remaining
	fi
}

require_action_deadline_margin() {
	local now remaining
	now=$(/usr/bin/date +%s) || fail "could not read the execute deadline clock"
	remaining=$((execute_deadline_epoch - now))
	# Keep a full second of margin between this check and process creation so an
	# action is never intentionally launched on the expiry boundary.
	[ "$remaining" -gt 1 ] || fail "the consumed receipt expired or is too close to expiry; no fastboot boot action was attempted"
	action_deadline_timeout=$((remaining - 1))
	if [ "$action_timeout" -lt "$action_deadline_timeout" ]; then
		action_deadline_timeout=$action_timeout
	fi
}

prepare_candidate_view() {
	fastboot_candidate_path=$boot_path
	if [ "$fastboot_host_kind" = windows ]; then
		case "${fastboot_bin,,}" in *.exe) ;; *) fail "pinned Windows fastboot path must end in .exe" ;; esac
		[ -x "$POWERSHELL" ] && [ -f "$POWERSHELL" ] && [ ! -L "$POWERSHELL" ] || fail "fixed Windows PowerShell is unavailable"
		fastboot_candidate_path=$($WSLPATH -w "$boot_path" | /usr/bin/tr -d '\r') || fail "could not translate the pinned boot image path"
		case "$fastboot_candidate_path" in
			\\\\wsl.localhost\\*|\\\\wsl\$\\*) ;;
			*) fail "the Windows boot image view must be an absolute WSL UNC path" ;;
		esac
		if printf '%s' "$fastboot_candidate_path" | /usr/bin/grep -q '[[:cntrl:]]'; then
			fail "the Windows boot image path contains a control character"
		fi
	fi
}

verify_candidate_view() {
	local output extra actual_size actual_sha
	[ "$fastboot_host_kind" = windows ] || return 0
	bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
	set +e
	output=$(/usr/bin/timeout "$bounded_timeout_seconds" "$POWERSHELL" -NoProfile -NonInteractive -Command \
		'& { param([string] $p) $i = Get-Item -LiteralPath $p; $h = (Get-FileHash -Algorithm SHA256 -LiteralPath $p).Hash.ToLowerInvariant(); Write-Output (("{0} {1}" -f $i.Length, $h)) }' \
		"$fastboot_candidate_path" | /usr/bin/tr -d '\r')
	local status=$?
	set -e
	[ "$status" -eq 0 ] || fail "Windows could not hash the pinned boot image"
	IFS=' ' read -r actual_size actual_sha extra <<< "$output"
	[ -z "${extra:-}" ] || fail "Windows boot image identity output is ambiguous"
	[ "$actual_size" = "$boot_size" ] || fail "Windows boot image size differs from the pinned Linux file"
	[ "$actual_sha" = "$boot_sha" ] || fail "Windows boot image SHA-256 differs from the pinned Linux file"
}

run_fastboot_capture() {
	local status
	verify_fastboot_tool
	bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
	set +e
	fastboot_output=$(/usr/bin/timeout "$bounded_timeout_seconds" "$fastboot_bin" "$@" 2>&1)
	status=$?
	set -e
	if [ "$status" -ne 0 ] && [ -n "$execute_deadline_epoch" ]; then
		bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
	fi
	[ "$status" -eq 0 ] || fail "a read-only fastboot query failed"
	fastboot_output=${fastboot_output//$'\r'/}
}

select_single_device() {
	local line only_line= count=0
	run_fastboot_capture devices
	while IFS= read -r line || [ -n "$line" ]; do
		[ -z "$line" ] && continue
		count=$((count + 1))
		only_line=$line
	done <<< "$fastboot_output"
	[ "$count" -eq 1 ] || fail "exactly one nonempty fastboot devices entry is required"
	if [[ $only_line =~ ^([A-Za-z0-9._:-]+)[[:space:]]+fastboot[[:space:]]*$ ]]; then
		device_serial=${BASH_REMATCH[1]}
	else
		fail "the sole fastboot devices entry is malformed or not in fastboot state"
	fi
}

read_getvar() {
	local key=$1 line value
	local -a values=()
	run_fastboot_capture -s "$device_serial" getvar "$key"
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in
			"$key: "*) value=${line#"$key: "}; values+=("$value") ;;
			"(bootloader) $key: "*) value=${line#"(bootloader) $key: "}; values+=("$value") ;;
		esac
	done <<< "$fastboot_output"
	[ "${#values[@]}" -eq 1 ] || fail "a pinned fastboot getvar was missing or ambiguous"
	getvar_value=${values[0]}
	[ -n "$getvar_value" ] || fail "a pinned fastboot getvar was empty"
	if printf '%s' "$getvar_value" | /usr/bin/grep -q '[[:cntrl:]]'; then
		fail "a pinned fastboot getvar contains a control character"
	fi
}

parse_uint() {
	local input=$1 output status
	set +e
	output=$(/usr/bin/python3 -I -S -B - "$input" <<'PY'
import re
import sys
value = sys.argv[1]
if re.fullmatch(r"(?:0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,19})", value) is None:
    raise SystemExit(1)
number = int(value, 0) if value.lower().startswith("0x") else int(value, 10)
if not 0 <= number <= 2**63 - 1:
    raise SystemExit(1)
print(number)
PY
	)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "a numeric fastboot property is invalid"
	parsed_uint=$output
}

verify_private_device_identity() {
	local status
	set +e
	/usr/bin/python3 -I -S -B - "$privacy_nonce" "$expected_identity" "$historical_fingerprint" 3<<< "$device_serial" <<'PY'
import hashlib
import hmac
import os
import re
import sys
nonce, expected, historical = sys.argv[1:]
serial = os.fdopen(3).read()
if serial.endswith("\n"):
    serial = serial[:-1]
if re.fullmatch(r"[A-Za-z0-9._:-]+", serial) is None:
    raise SystemExit(1)
scoped = hashlib.sha256(nonce.encode("ascii") + b"\0" + serial.encode("ascii")).hexdigest()
legacy = hashlib.sha256(serial.encode("ascii")).hexdigest()[:16]
if not hmac.compare_digest(scoped, expected) or not hmac.compare_digest(legacy, historical):
    raise SystemExit(1)
PY
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the connected handset does not match the private D199/D200 identity policy"
}

preflight_device() {
	local enumerated_serial number
	select_single_device
	enumerated_serial=$device_serial
	read_getvar serialno
	[ "$getvar_value" = "$enumerated_serial" ] || fail "fastboot devices and getvar serialno identify different handsets"
	verify_private_device_identity
	read_getvar product
	[ "$getvar_value" = "$expected_product" ] || fail "device product does not match the pinned policy"
	read_getvar unlocked
	[ "$getvar_value" = "$expected_unlocked" ] || fail "bootloader unlock state does not match the pinned policy"
	read_getvar is-userspace
	[ "$getvar_value" = "$expected_userspace" ] || fail "RAM boot requires the pinned non-userspace fastboot state"
	read_getvar battery-voltage
	parse_uint "$getvar_value"
	number=$parsed_uint
	[ "$number" -ge "$minimum_battery_mv" ] || fail "battery voltage is below the pinned minimum"
	device_battery_mv=$number
	read_getvar battery-soc-ok
	[ "$getvar_value" = "$expected_battery_soc" ] || fail "battery-soc-ok does not match the pinned policy"
	read_getvar max-download-size
	parse_uint "$getvar_value"
	number=$parsed_uint
	[ "$number" -ge "$minimum_max_download" ] || fail "max-download-size is below the pinned minimum"
	[ "$boot_size" -le "$number" ] || fail "pinned boot image exceeds max-download-size"
	device_max_download=$number
}

capture_session_scope() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B - <<'PY'
import hashlib
import os
import re
import sys

thread_id = os.environ.get("CODEX_THREAD_ID")
if thread_id is None or not 1 <= len(thread_id.encode("utf-8")) <= 512:
    raise SystemExit(1)
if any(ord(character) < 32 or ord(character) == 127 for character in thread_id):
    raise SystemExit(1)
try:
    with open("/proc/sys/kernel/random/boot_id", "r", encoding="ascii") as source:
        boot_id = source.read()
except OSError:
    raise SystemExit(1)
if boot_id.endswith("\n"):
    boot_id = boot_id[:-1]
if re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", boot_id) is None:
    raise SystemExit(1)
thread_binding = hashlib.sha256(
    b"lmi-d110-codex-thread-session/v1\0" + thread_id.encode("utf-8")
).hexdigest()
boot_binding = hashlib.sha256(
    b"lmi-d110-host-boot/v1\0" + boot_id.encode("ascii")
).hexdigest()
print(thread_binding + "\t" + boot_binding)
PY
	)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "a valid current CODEX_THREAD_ID session scope is required"
	IFS=$'\t' read -r thread_binding host_boot_id_sha <<< "$output"
	[[ $thread_binding =~ ^[0-9a-f]{64}$ ]] && [[ $host_boot_id_sha =~ ^[0-9a-f]{64}$ ]] \
		|| fail "the session scope binding is invalid"
	unset CODEX_THREAD_ID
}

prepare_session_storage() {
	local create=$1 status
	set +e
	/usr/bin/python3 -I -S -B - "$grant_dir" "$create" <<'PY'
import os
from pathlib import Path
import stat
import sys

base = Path(sys.argv[1])
create = sys.argv[2] == "create"

def good_dir(path):
    st = path.lstat()
    return (stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
            and st.st_uid == os.geteuid())

try:
    if not good_dir(base.parent):
        raise OSError
    if create:
        try:
            base.mkdir(mode=0o700)
        except FileExistsError:
            pass
    if not good_dir(base):
        raise OSError
    for child in (base / "active", base / "revoked"):
        if create:
            try:
                child.mkdir(mode=0o700)
            except FileExistsError:
                pass
        if not good_dir(child):
            raise OSError
    lock = base / "execute.lock"
    if create:
        flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
        try:
            fd = os.open(lock, flags, 0o600)
            os.fsync(fd)
            os.close(fd)
        except FileExistsError:
            pass
    fd = os.open(lock, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    st = os.fstat(fd)
    os.close(fd)
    if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_uid != os.geteuid() or st.st_nlink != 1):
        raise OSError
except OSError:
    raise SystemExit(1)
PY
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the private session grant storage is missing or unsafe"
}

acquire_session_lock() {
	local lock_path=$grant_dir/execute.lock expected actual
	[ ! -L "$lock_path" ] || fail "the session execution lock must not be a symlink"
	exec {session_lock_fd}<> "$lock_path" || fail "could not open the session execution lock"
	[ ! -L "$lock_path" ] || fail "the session execution lock changed type"
	[ "$(/usr/bin/stat -c '%a:%u:%h' -- "$lock_path")" = "600:$(/usr/bin/id -u):1" ] \
		|| fail "the session execution lock ownership, mode, or link count is unsafe"
	expected=$(/usr/bin/stat -c '%d:%i' -- "$lock_path") || fail "could not inspect the session execution lock"
	actual=$(/usr/bin/stat -Lc '%d:%i' -- "/proc/self/fd/$session_lock_fd") || fail "could not inspect the open session execution lock"
	[ "$expected" = "$actual" ] || fail "the session execution lock changed while it was opened"
	/usr/bin/flock -n "$session_lock_fd" || fail "another session execution or revocation is already in progress"
}

release_session_lock() {
	[ -n "$session_lock_fd" ] || return 0
	exec {session_lock_fd}>&-
	session_lock_fd=
}

create_session_grant() {
	local output status
	grant_path=$grant_dir/active/grant-$thread_binding.json
	if [ -e "$grant_path" ] || [ -L "$grant_path" ]; then
		# Reauthorization is deliberately idempotent: a valid existing grant is
		# retained with its original deadline. Invalid/expired state must first
		# be explicitly archived with --revoke-session.
		verify_session_grant
		grant_result=reused-with-original-deadline
		return 0
	fi
	set +e
	output=$(/usr/bin/python3 -I -S -B - "$grant_dir" "$thread_binding" \
		"$host_boot_id_sha" "$TRUSTED_POLICY_SHA256" "$action_digest" "$boot_sha" \
		"$expected_identity" "$fastboot_sha" "$fastboot_identity" "$stage" "$helper_sha" \
		"$session_max_seconds" <<'PY'
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time

base = Path(sys.argv[1])
(thread_binding, host_boot, policy_sha, action_digest, boot_sha, device_identity,
 fastboot_sha, fastboot_identity, stage, helper_sha) = sys.argv[2:12]
session_max = int(sys.argv[12])
active = base / "active"

def good_dir(path):
    st = path.lstat()
    return (stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
            and st.st_uid == os.geteuid())

try:
    if not all(good_dir(path) for path in (base, active, base / "revoked")):
        raise OSError
    now = int(time.time())
    record = {
        "schema": "lmi-d110-codex-session-grant/v1",
        "thread_binding_sha256": thread_binding,
        "host_boot_id_sha256": host_boot,
        "policy_sha256": policy_sha,
        "action_digest": action_digest,
        "boot_sha256": boot_sha,
        "device_identity_sha256": device_identity,
        "fastboot_sha256": fastboot_sha,
        "fastboot_identity": fastboot_identity,
        "stage": stage,
        "operation": "fastboot boot",
        "helper_sha256": helper_sha,
        "issued_at_epoch": now,
        "expires_at_epoch": now + session_max,
    }
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    name = "grant-" + thread_binding + ".json"
    final = active / name
    try:
        existing = final.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(existing.st_mode) or stat.S_IMODE(existing.st_mode) != 0o600
                or existing.st_uid != os.geteuid() or existing.st_nlink != 1):
            raise OSError
    temporary = active / ("." + name + "." + secrets.token_hex(16) + ".tmp")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                raise OSError
            view = view[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, final)
    directory_fd = os.open(active, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(directory_fd)
    os.close(directory_fd)
except (OSError, ValueError):
    raise SystemExit(1)
print(str(final))
PY
	)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "could not atomically create the private session grant"
	grant_path=$output
	grant_result=created
}

verify_session_grant() {
	local status
	grant_path=$grant_dir/active/grant-$thread_binding.json
	set +e
	/usr/bin/python3 -I -S -B - "$grant_path" "$thread_binding" "$host_boot_id_sha" \
		"$TRUSTED_POLICY_SHA256" "$action_digest" "$boot_sha" "$expected_identity" \
		"$fastboot_sha" "$fastboot_identity" "$stage" "$helper_sha" "$session_max_seconds" <<'PY'
import json
import os
from pathlib import Path
import stat
import sys
import time

path = Path(sys.argv[1])
(thread_binding, host_boot, policy_sha, action_digest, boot_sha, device_identity,
 fastboot_sha, fastboot_identity, stage, helper_sha) = sys.argv[2:12]
session_max = int(sys.argv[12])
required = {"schema", "thread_binding_sha256", "host_boot_id_sha256", "policy_sha256",
            "action_digest", "boot_sha256", "device_identity_sha256", "fastboot_sha256",
            "fastboot_identity", "stage", "operation", "helper_sha256",
            "issued_at_epoch", "expires_at_epoch"}

def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value

try:
    parent = path.parent
    for directory in (parent.parent, parent):
        st = directory.lstat()
        if (not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700
                or st.st_uid != os.geteuid()):
            raise OSError
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                 | getattr(os, "O_NOFOLLOW", 0))
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_size > 8192):
        raise OSError
    data = os.read(fd, 8193)
    after = os.fstat(fd)
    os.close(fd)
    identity = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_size,
                           st.st_mtime_ns, st.st_ctime_ns)
    if len(data) > 8192 or identity(before) != identity(after):
        raise OSError
    record = json.loads(data.decode("ascii"), object_pairs_hook=no_duplicates)
    expected = {
        "schema": "lmi-d110-codex-session-grant/v1",
        "thread_binding_sha256": thread_binding,
        "host_boot_id_sha256": host_boot,
        "policy_sha256": policy_sha,
        "action_digest": action_digest,
        "boot_sha256": boot_sha,
        "device_identity_sha256": device_identity,
        "fastboot_sha256": fastboot_sha,
        "fastboot_identity": fastboot_identity,
        "stage": stage,
        "operation": "fastboot boot",
        "helper_sha256": helper_sha,
    }
    if not isinstance(record, dict) or set(record) != required:
        raise ValueError
    if any(record[key] != value for key, value in expected.items()):
        raise ValueError
    issued, expires = record["issued_at_epoch"], record["expires_at_epoch"]
    now = int(time.time())
    if (isinstance(issued, bool) or isinstance(expires, bool)
            or not isinstance(issued, int) or not isinstance(expires, int)
            or expires - issued != session_max or issued > now + 2 or now >= expires
            or int(before.st_mtime) < issued - 2 or int(before.st_mtime) > issued + 2):
        raise ValueError
except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
PY
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the current Codex thread has no valid session grant for this exact operation"
}

revoke_session_grant() {
	local status
	set +e
	/usr/bin/python3 -I -S -B - "$grant_dir" "$thread_binding" <<'PY'
import os
from pathlib import Path
import stat
import sys

base = Path(sys.argv[1])
name = "grant-" + sys.argv[2] + ".json"
active = base / "active"
revoked = base / "revoked"
try:
    for directory in (base, active, revoked):
        st = directory.lstat()
        if (not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700
                or st.st_uid != os.geteuid()):
            raise OSError
    source = active / name
    st = source.lstat()
    if (not stat.S_ISREG(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o600
            or st.st_uid != os.geteuid() or st.st_nlink != 1):
        raise OSError
    target = revoked / name
    try:
        old = target.lstat()
    except FileNotFoundError:
        pass
    else:
        if (not stat.S_ISREG(old.st_mode) or stat.S_IMODE(old.st_mode) != 0o600
                or old.st_uid != os.geteuid() or old.st_nlink != 1):
            raise OSError
    os.replace(source, target)
    for directory in (active, revoked):
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        os.fsync(fd)
        os.close(fd)
except OSError:
    raise SystemExit(1)
PY
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the session grant could not be atomically revoked"
}

create_attempt_receipt() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B - "$receipt_dir" "$TRUSTED_POLICY_SHA256" \
		"$action_digest" "$boot_sha" "$expected_identity" "$thread_binding" \
		"$host_boot_id_sha" "$helper_sha" "$fastboot_identity" "$stage" "$device_battery_mv" \
		"$device_max_download" "$receipt_ttl" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import secrets
import stat
import sys
import time

receipt_dir = Path(sys.argv[1])
(policy_sha, action_digest, boot_sha, identity, thread_binding, host_boot,
 helper_sha, fastboot_identity, stage) = sys.argv[2:11]
battery, max_download, ttl = map(int, sys.argv[11:14])

def good_dir(path):
    st = path.lstat()
    return (stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
            and st.st_uid == os.geteuid())

try:
    if not good_dir(receipt_dir.parent):
        raise OSError
    try:
        receipt_dir.mkdir(mode=0o700)
    except FileExistsError:
        pass
    for directory in (receipt_dir, receipt_dir / "pending", receipt_dir / "consumed"):
        if directory != receipt_dir:
            try:
                directory.mkdir(mode=0o700)
            except FileExistsError:
                pass
        if not good_dir(directory):
            raise OSError
    now = int(time.time())
    nonce = secrets.token_hex(32)
    receipt_id = hashlib.sha256((policy_sha + "\0" + nonce).encode("ascii")).hexdigest()
    record = {
        "schema": "lmi-d110-internal-attempt-receipt/v1",
        "policy_sha256": policy_sha,
        "action_digest": action_digest,
        "boot_sha256": boot_sha,
        "device_identity_sha256": identity,
        "thread_binding_sha256": thread_binding,
        "host_boot_id_sha256": host_boot,
        "helper_sha256": helper_sha,
        "fastboot_identity": fastboot_identity,
        "stage": stage,
        "operation": "fastboot boot",
        "issued_at_epoch": now,
        "expires_at_epoch": now + ttl,
        "challenge_nonce": nonce,
        "preflight_battery_mv": battery,
        "preflight_max_download_size": max_download,
    }
    payload = (json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    pending = receipt_dir / "pending"
    temporary = pending / ("." + receipt_id + ".tmp")
    final = pending / ("receipt-" + receipt_id + ".json")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(temporary, flags, 0o600)
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError
        view = view[written:]
    os.fsync(fd)
    os.close(fd)
    os.link(temporary, final, follow_symlinks=False)
    os.unlink(temporary)
    directory_fd = os.open(pending, os.O_RDONLY | os.O_DIRECTORY)
    os.fsync(directory_fd)
    os.close(directory_fd)
except (OSError, ValueError):
    raise SystemExit(1)
print(str(final))
PY
	)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "could not create the private internal attempt receipt"
	pending_receipt=$output
}

consume_attempt_receipt() {
	local output status
	set +e
	output=$(/usr/bin/python3 -I -S -B - "$receipt_dir" "$pending_receipt" \
		"$TRUSTED_POLICY_SHA256" "$action_digest" "$boot_sha" "$expected_identity" \
		"$thread_binding" "$host_boot_id_sha" "$helper_sha" "$fastboot_identity" "$stage" "$receipt_ttl" <<'PY'
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

receipt_dir = Path(sys.argv[1])
requested = Path(sys.argv[2])
(policy_sha, action_digest, boot_sha, identity, thread_binding, host_boot,
 helper_sha, fastboot_identity, stage) = sys.argv[3:12]
ttl = int(sys.argv[12])
pending = receipt_dir / "pending"
consumed = receipt_dir / "consumed"

def no_duplicates(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError
        value[key] = item
    return value

try:
    if requested != pending / requested.name or requested.parent != pending:
        raise ValueError
    name = requested.name
    if re.fullmatch(r"receipt-[0-9a-f]{64}\.json", name) is None:
        raise ValueError
    for directory in (receipt_dir, pending, consumed):
        st = directory.lstat()
        if (not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) != 0o700
                or st.st_uid != os.geteuid()):
            raise OSError
    pending_fd = os.open(pending, os.O_RDONLY | os.O_DIRECTORY)
    consumed_fd = os.open(consumed, os.O_RDONLY | os.O_DIRECTORY)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(name, flags, dir_fd=pending_fd)
    before = os.fstat(fd)
    if (not stat.S_ISREG(before.st_mode) or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.geteuid() or before.st_nlink != 1 or before.st_size > 8192):
        raise OSError
    data = os.read(fd, 8193)
    after = os.fstat(fd)
    os.close(fd)
    identity_tuple = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
                                 st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    if len(data) > 8192 or identity_tuple(before) != identity_tuple(after):
        raise OSError
    record = json.loads(data.decode("ascii"), object_pairs_hook=no_duplicates)
    required = {"schema", "policy_sha256", "action_digest", "boot_sha256",
                "device_identity_sha256", "thread_binding_sha256", "host_boot_id_sha256",
                "helper_sha256", "fastboot_identity", "stage", "operation", "issued_at_epoch",
                "expires_at_epoch", "challenge_nonce", "preflight_battery_mv",
                "preflight_max_download_size"}
    if not isinstance(record, dict) or set(record) != required:
        raise ValueError
    nonce = record["challenge_nonce"]
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise ValueError
    receipt_id = hashlib.sha256((policy_sha + "\0" + nonce).encode("ascii")).hexdigest()
    if name != "receipt-" + receipt_id + ".json":
        raise ValueError
    expected = {
        "schema": "lmi-d110-internal-attempt-receipt/v1",
        "policy_sha256": policy_sha,
        "action_digest": action_digest,
        "boot_sha256": boot_sha,
        "device_identity_sha256": identity,
        "thread_binding_sha256": thread_binding,
        "host_boot_id_sha256": host_boot,
        "helper_sha256": helper_sha,
        "fastboot_identity": fastboot_identity,
        "stage": stage,
        "operation": "fastboot boot",
    }
    if any(record[key] != value for key, value in expected.items()):
        raise ValueError
    issued, expires = record["issued_at_epoch"], record["expires_at_epoch"]
    now = int(time.time())
    if (isinstance(issued, bool) or isinstance(expires, bool)
            or not isinstance(issued, int) or not isinstance(expires, int)
            or expires - issued != ttl or issued > now + 2 or now >= expires
            or int(before.st_mtime) < issued - 2 or int(before.st_mtime) > issued + 2):
        raise ValueError
    moved_name = name[:-5] + ".consumed.json"
    os.link(name, moved_name, src_dir_fd=pending_fd, dst_dir_fd=consumed_fd,
            follow_symlinks=False)
    moved = os.stat(moved_name, dir_fd=consumed_fd, follow_symlinks=False)
    if moved.st_dev != before.st_dev or moved.st_ino != before.st_ino:
        raise OSError
    os.fsync(consumed_fd)
    os.unlink(name, dir_fd=pending_fd)
    os.fsync(pending_fd)
    os.close(pending_fd)
    os.close(consumed_fd)
except (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError):
    raise SystemExit(1)
print(str(expires))
PY
	)
	status=$?
	set -e
	[ "$status" -eq 0 ] || fail "the internal attempt receipt is invalid, expired, renamed, replayed, or already consumed"
	consumed_expiry_epoch=$output
	[[ $consumed_expiry_epoch =~ ^[0-9]+$ ]] || fail "attempt receipt consumer returned an invalid expiry"
}

complete_read_only_preflight() {
	preflight_device
	capture_local_policy
	verify_helper_identity
	verify_fastboot_tool
	prepare_candidate_view
	verify_candidate_view
}

capture_helper_identity
capture_local_policy

case "$mode" in
	--authorize-session|--execute|--revoke-session) capture_session_scope ;;
	*) unset CODEX_THREAD_ID ;;
esac

printf 'claim=%s\n' "$CLAIM"
printf 'policy_sha256=%s\n' "$TRUSTED_POLICY_SHA256"
printf 'boot_sha256=%s\n' "$boot_sha"
printf 'boot_size=%s\n' "$boot_size"
printf 'boot_uuid=%s\n' "$boot_uuid"
printf 'root_uuid=%s\n' "$root_uuid"
printf 'kernel_sha256=%s\n' "$kernel_sha"
printf 'ramdisk_sha256=%s\n' "$ramdisk_sha"
printf 'dtb_sha256=%s\n' "$dtb_sha"
printf 'fastboot_sha256=%s\n' "$fastboot_sha"

case "$mode" in
	--dry-run)
		capture_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		printf 'dry-run=local-only; no phone query or hardware command\n'
		printf 'session_scope=CODEX_THREAD_ID is required only for authorize, execute, and revoke\n'
		;;
	--preflight)
		capture_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		complete_read_only_preflight
		printf 'preflight=passed-read-only\n'
		printf 'session_grant=not-created\n'
		printf 'No action was attempted. %s\n' "$CLAIM"
		;;
	--authorize-session)
		capture_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		complete_read_only_preflight
		# No state is created until the complete read-only preflight above passes.
		prepare_session_storage create
		acquire_session_lock
		verify_helper_identity
		create_session_grant
		release_session_lock
		printf 'authorization=session-grant-%s-after-complete-read-only-preflight\n' "$grant_result"
		printf 'session_scope=current-CODEX_THREAD_ID-hash; raw identifier not stored or printed\n'
		printf 'session_max_seconds=%s\n' "$session_max_seconds"
		printf 'No boot action was attempted. %s\n' "$CLAIM"
		;;
	--execute)
		prepare_session_storage validate
		acquire_session_lock
		capture_fastboot_tool
		verify_session_grant
		prepare_candidate_view
		verify_candidate_view
		complete_read_only_preflight
		verify_session_grant
		create_attempt_receipt
		consume_attempt_receipt
		execute_deadline_epoch=$consumed_expiry_epoch
		printf 'authorization=same-thread-session-grant-verified-under-exclusive-lock\n'
		printf 'attempt_receipt=created-and-consumed-internally-before-execution\n'
		# The internal receipt is already consumed. Every device and local gate is
		# now repeated within its 30-second deadline before the single action.
		complete_read_only_preflight
		bound_timeout_to_execute_deadline "$READ_ONLY_TIMEOUT"
		verify_session_grant
		require_action_deadline_margin
		set +e
		/usr/bin/timeout "$action_deadline_timeout" "$fastboot_bin" -s "$device_serial" boot "$fastboot_candidate_path" >/dev/null 2>&1
		action_status=$?
		set -e
		execute_deadline_epoch=
		# The output is intentionally withheld because a hostile or unexpected
		# fastboot build could echo a raw serial. The exit status is sufficient
		# for this one-shot gate, and no retry is made.
		capture_local_policy
		verify_helper_identity
		verify_fastboot_tool
		prepare_candidate_view
		verify_candidate_view
		verify_session_grant
		[ "$action_status" -eq 0 ] || fail "the single fastboot boot action failed; the internal attempt receipt remains consumed and no retry was attempted"
		release_session_lock
		printf 'fastboot_boot_attempts=1\n'
		printf 'result=single-pinned-fastboot-boot-command-accepted\n'
		printf 'No automatic retry. %s\n' "$CLAIM"
		;;
	--revoke-session)
		prepare_session_storage validate
		acquire_session_lock
		revoke_session_grant
		release_session_lock
		printf 'revocation=current-CODEX_THREAD_ID-session-grant-atomically-revoked\n'
		printf 'No phone query or boot action was attempted. %s\n' "$CLAIM"
		;;
esac

# Residual boundary: CODEX_THREAD_ID distinguishes the current Codex thread but
# is not itself a cryptographic authentication principal; user authority comes
# from the Codex session/tool approval boundary. A process already running as
# this same EUID can modify the helper or race private pathnames, and Windows
# consumes a pathname rather than a retained Linux file descriptor. Helper and
# host-boot binding, file-descriptor hashing, exact modes, one-link checks,
# before/after identity checks, fixed absolute interpreters, PowerShell
# re-hashing, atomic grant/receipt operations, and the global execution lock
# narrow but cannot remove that same-EUID/WSL-Windows pathname trust boundary.
