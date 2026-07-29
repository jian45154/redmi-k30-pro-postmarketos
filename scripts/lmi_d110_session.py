"""D110 session/gate primitives for scripts/72_stage_downstream_ssh_wifi_test.sh.

Each public function below is a verbatim lift of a formerly-embedded heredoc
from the guarded D110 RAM-boot helper. The observable protocol is unchanged:

- The helper still invokes this file with ``/usr/bin/python3 -I -S -B`` so no
  site customization, environment path injection, or bytecode caching applies.
- The device serial still travels only over file descriptor 3 (never argv).
- Output shapes (tab-joined fields, printed paths/epochs), exit codes, and
  error strings are identical to the heredoc originals.

The helper pins this file's SHA-256 (TRUSTED_SESSION_MODULE_SHA256) and
refuses to run if the on-disk module differs; see scripts/README.md for the
re-pin procedure. This module never executes fastboot or any device command;
it only validates local state and manages private grant/receipt records.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import stat
import struct
import sys
import time
import uuid


def capture_helper_identity(script_path):
    path = Path(script_path)
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
    return digest.hexdigest() + "\t" + ":".join(map(str, identity(before)))


def capture_local_policy(repo_argument, policy_argument, trusted_sha):
    repo = Path(repo_argument)
    policy_path = Path(policy_argument)

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
    return "\t".join(fields)


def parse_uint(value):
    if re.fullmatch(r"(?:0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,19})", value) is None:
        raise SystemExit(1)
    number = int(value, 0) if value.lower().startswith("0x") else int(value, 10)
    if not 0 <= number <= 2**63 - 1:
        raise SystemExit(1)
    return number


def verify_private_device_identity(nonce, expected, historical, serial):
    if serial.endswith("\n"):
        serial = serial[:-1]
    if re.fullmatch(r"[A-Za-z0-9._:-]+", serial) is None:
        raise SystemExit(1)
    scoped = hashlib.sha256(nonce.encode("ascii") + b"\0" + serial.encode("ascii")).hexdigest()
    legacy = hashlib.sha256(serial.encode("ascii")).hexdigest()[:16]
    if not hmac.compare_digest(scoped, expected) or not hmac.compare_digest(legacy, historical):
        raise SystemExit(1)


def capture_session_scope(environ=None, boot_id_path="/proc/sys/kernel/random/boot_id"):
    if environ is None:
        environ = os.environ
    thread_id = environ.get("CODEX_THREAD_ID")
    if thread_id is None or not 1 <= len(thread_id.encode("utf-8")) <= 512:
        raise SystemExit(1)
    if any(ord(character) < 32 or ord(character) == 127 for character in thread_id):
        raise SystemExit(1)
    try:
        with open(boot_id_path, "r", encoding="ascii") as source:
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
    return thread_binding + "\t" + boot_binding


def prepare_session_storage(grant_dir, create_argument):
    base = Path(grant_dir)
    create = create_argument == "create"

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


def create_session_grant(grant_dir, thread_binding, host_boot, policy_sha, action_digest,
                         boot_sha, device_identity, fastboot_sha, fastboot_identity, stage,
                         helper_sha, session_max_argument):
    base = Path(grant_dir)
    session_max = int(session_max_argument)
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
    return str(final)


def verify_session_grant(grant_path, thread_binding, host_boot, policy_sha, action_digest,
                         boot_sha, device_identity, fastboot_sha, fastboot_identity, stage,
                         helper_sha, session_max_argument):
    path = Path(grant_path)
    session_max = int(session_max_argument)
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


def revoke_session_grant(grant_dir, thread_binding):
    base = Path(grant_dir)
    name = "grant-" + thread_binding + ".json"
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


def create_attempt_receipt(receipt_dir_argument, policy_sha, action_digest, boot_sha, identity,
                           thread_binding, host_boot, helper_sha, fastboot_identity, stage,
                           battery_argument, max_download_argument, ttl_argument):
    receipt_dir = Path(receipt_dir_argument)
    battery, max_download, ttl = map(int, (battery_argument, max_download_argument, ttl_argument))

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
    return str(final)


def consume_attempt_receipt(receipt_dir_argument, requested_argument, policy_sha, action_digest,
                            boot_sha, identity, thread_binding, host_boot, helper_sha,
                            fastboot_identity, stage, ttl_argument):
    receipt_dir = Path(receipt_dir_argument)
    requested = Path(requested_argument)
    ttl = int(ttl_argument)
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
    return str(expires)


def main(argv):
    if not argv:
        print("refused: a session module verb is required", file=sys.stderr)
        raise SystemExit(2)
    verb, args = argv[0], argv[1:]
    if verb == "helper-identity":
        (script_path,) = args
        print(capture_helper_identity(script_path))
    elif verb == "local-policy":
        repo, policy_path, trusted_sha = args
        print(capture_local_policy(repo, policy_path, trusted_sha))
    elif verb == "parse-uint":
        (value,) = args
        print(parse_uint(value))
    elif verb == "device-identity":
        nonce, expected, historical = args
        serial = os.fdopen(3).read()
        verify_private_device_identity(nonce, expected, historical, serial)
    elif verb == "session-scope":
        () = args
        print(capture_session_scope())
    elif verb == "session-storage":
        grant_dir, create = args
        prepare_session_storage(grant_dir, create)
    elif verb == "grant-create":
        print(create_session_grant(*args))
    elif verb == "grant-verify":
        verify_session_grant(*args)
    elif verb == "grant-revoke":
        grant_dir, thread_binding = args
        revoke_session_grant(grant_dir, thread_binding)
    elif verb == "receipt-create":
        print(create_attempt_receipt(*args))
    elif verb == "receipt-consume":
        print(consume_attempt_receipt(*args))
    else:
        print("refused: unknown session module verb", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
