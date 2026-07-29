#!/usr/bin/env python3
"""Bringup governance engine (schema v4, lmi adaptation).

Layer contract (L3):
- owns: record schema, artifact hashing, policy scope resolution, receipt
  issue-and-claim, fail-closed claim replay guards, the append-only claims
  ledger, and archival;
- never touches the device. Device identity, battery, and fastboot argument
  gates belong to the executor that runs the returned exact_command.

Tier model (adapted for lmi, where the rootfs lives inside userdata):
- read_only:  observation only; no receipt, no ledger entry.
- volatile:   bare `fastboot reboot`; worst case is a power cycle.
- ram_rw:     `fastboot boot` / runtime handoff. The command itself writes no
  partition, but the booted OS mounts userdata read-write, so a claim requires
  a persistent-media acknowledgment naming how userdata can be rebuilt.
- persistent: partition writes. Requires a hash-bound authorized_profiles
  entry in policy.json (per-profile owner authorization; never standing),
  a distinct-hash rollback artifact, and a repeat guard on re-writes.

Every structural check lives in exactly one function here; claim re-verifies
artifact bytes once, inside the ledger lock.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import hashlib
import json
import os
import posixpath
import re
import secrets
import stat
import subprocess
import sys
import unicodedata
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = 4

# The only permitted duplicate of config/governance/constants.json
# forbidden_command_words. load_constants() asserts equality so editing the
# data file can never widen what the engine accepts.
FORBIDDEN_COMMAND_WORDS = frozenset(
    {
        "erase",
        "format",
        "repartition",
        "set_active",
        "--force",
        "--disable-verity",
        "--disable-verification",
        "oem lock",
        "flashing lock",
    }
)

TIERS = ("read_only", "volatile", "ram_rw", "persistent")
OUTCOMES = ("success", "failure", "timeout", "unknown")
EXPERIMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
ROUTE_STATUS_RE = re.compile(r"^route_status=\S+", re.MULTILINE)

# operation -> (tier, fixed target or None meaning constants.partition_targets,
#               artifact required?)
OPERATIONS = {
    "device_reboot": ("volatile", "device", False),
    "ram_boot": ("ram_rw", "ram", True),
    "runtime_handoff": ("ram_rw", "initramfs", False),
    "partition_write": ("persistent", None, True),
}

RECORD_FIELDS_READ_ONLY = frozenset(
    {
        "schema_version",
        "status",
        "experiment_id",
        "tier",
        "hypothesis",
        "discriminator",
        "next_if_positive",
        "next_if_negative",
        "timebox_seconds",
        "lanes",
        "observations",
        "result",
    }
)
RECORD_FIELDS_ACTION = frozenset(
    RECORD_FIELDS_READ_ONLY | {"action", "gates", "repeat_guard", "receipt"}
)
ACTION_FIELDS = frozenset(
    {
        "operation",
        "target",
        "profile",
        "profile_sha256",
        "artifact",
        "artifact_sha256",
        "artifact_size",
        "exact_command",
    }
)
GATES_FIELDS = frozenset({"identity", "persistent_media", "rollback"})
POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "enabled",
        "revision",
        "authorized_by",
        "authorization_note",
        "standing_scopes",
        "authorized_profiles",
        "manual_only",
    }
)
SCOPE_FIELDS = frozenset({"tier", "operation", "target"})
AUTHORIZED_PROFILE_FIELDS = frozenset(
    {"profile_path", "profile_sha256", "targets", "authorized_by", "note"}
)
REPEAT_GUARD_FIELDS = frozenset(
    {
        "prior_experiment_id",
        "changed_discriminator",
        "evidence_report",
        "evidence_report_sha256",
    }
)
ROLLBACK_FIELDS = frozenset({"target", "path", "sha256", "size"})
PROFILE_ARTIFACT_FIELDS = frozenset({"path", "sha256", "size"})
HASH_CHUNK_SIZE = 1024 * 1024
MAX_JSON_BYTES = 8 * 1024 * 1024
MAX_LEDGER_BYTES = 64 * 1024 * 1024
ENGINE_REL = "scripts/bringup_loop.py"


class Refusal(Exception):
    """Fail-closed governance refusal; message explains the single reason."""


class Paths:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.constants_rel = "config/governance/constants.json"
        self.policy_rel = "config/governance/policy.json"
        self.active_rel = "notes/bringup-active.json"
        self.claims_dir_rel = "notes/bringup-claims"
        self.ledger_rel = f"{self.claims_dir_rel}/claims.log"
        self.lock_rel = f"{self.claims_dir_rel}/.lock"
        self.completed_dir_rel = "notes/bringup-completed"
        self.logs_dir_rel = "logs"
        self.constants = root / self.constants_rel
        self.policy = root / self.policy_rel
        self.active = root / self.active_rel
        self.claims_dir = root / self.claims_dir_rel
        self.ledger = root / self.ledger_rel
        self.lock = root / self.lock_rel
        self.completed_dir = root / self.completed_dir_rel
        self.logs_dir = root / self.logs_dir_rel


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique_json_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise Refusal(f"JSON contains duplicate key: {key}")
        value[key] = item
    return value


def _decode_json_object(data: bytes, label: str, path: Path | None = None) -> dict:
    location = f": {path}" if path is not None else ""
    try:
        loaded = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_unique_json_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"{label} is not valid JSON{location}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise Refusal(f"{label} must be a JSON object{location}")
    return loaded


def _canonical_repo_relative_path(rel_path: str, label: str) -> str:
    if not isinstance(rel_path, str) or not rel_path:
        raise Refusal(f"{label} path must be a non-empty repo-relative path")
    if any(unicodedata.category(character).startswith("C") for character in rel_path):
        raise Refusal(f"{label} path contains a control or formatting character")
    if "\\" in rel_path:
        raise Refusal(f"{label} path must use canonical '/' separators: {rel_path}")
    if rel_path.startswith("/"):
        raise Refusal(f"{label} path must stay inside the repository: {rel_path}")
    components = rel_path.split("/")
    if ".." in components:
        raise Refusal(f"{label} path must stay inside the repository: {rel_path}")
    if (
        any(component in ("", ".") for component in components)
        or posixpath.normpath(rel_path) != rel_path
    ):
        raise Refusal(f"{label} path must use canonical repo-relative form: {rel_path}")
    return rel_path


def _validated_human_text(
    value: str, label: str, *, maximum: int = 4096
) -> str:
    if not isinstance(value, str) or not value:
        raise Refusal(f"{label} must be a non-empty string")
    if value != value.strip():
        raise Refusal(f"{label} must not have leading or trailing whitespace")
    if len(value) > maximum:
        raise Refusal(f"{label} exceeds the {maximum}-character safety limit")
    if any(unicodedata.category(character).startswith("C") for character in value):
        raise Refusal(f"{label} contains a control or formatting character")
    return value


def _validate_safe_owner_mode(
    item_stat: os.stat_result, canonical_path: str, label: str
) -> None:
    if item_stat.st_uid not in (0, os.geteuid()):
        raise Refusal(f"{label} has an untrusted owner: {canonical_path}")
    if stat.S_IMODE(item_stat.st_mode) & 0o022:
        raise Refusal(f"{label} is group/world writable: {canonical_path}")


def _classify_open_error(
    directory_fd: int, component: str, canonical_path: str, label: str, exc: OSError
) -> Refusal:
    try:
        entry = os.stat(component, dir_fd=directory_fd, follow_symlinks=False)
    except OSError:
        entry = None
    if entry is not None and stat.S_ISLNK(entry.st_mode):
        return Refusal(f"{label} path contains a symlink: {canonical_path}")
    if exc.errno == errno.ENOENT:
        return Refusal(f"{label} is not a regular file: {canonical_path}")
    return Refusal(
        f"{label} path component is not a safe directory/file: {canonical_path}"
    )


def _open_repo_parent(root: Path, rel_path: str, label: str) -> tuple[str, int, str]:
    canonical_path = _canonical_repo_relative_path(rel_path, label)
    components = canonical_path.split("/")
    try:
        directory_fd = os.open(
            root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
    except OSError as exc:
        raise Refusal(f"repository root is not a safe directory: {root}") from exc
    try:
        root_stat = os.fstat(directory_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise Refusal(f"repository root is not a directory: {root}")
        _validate_safe_owner_mode(root_stat, str(root), "repository root")
        for component in components[:-1]:
            try:
                next_fd = os.open(
                    component,
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | os.O_CLOEXEC,
                    dir_fd=directory_fd,
                )
            except OSError as exc:
                raise _classify_open_error(
                    directory_fd, component, canonical_path, label, exc
                ) from exc
            next_stat = os.fstat(next_fd)
            _validate_safe_owner_mode(
                next_stat, canonical_path, f"{label} directory ancestry"
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return canonical_path, directory_fd, components[-1]
    except BaseException:
        os.close(directory_fd)
        raise


def _validate_regular_stat(file_stat: os.stat_result, canonical_path: str, label: str) -> None:
    if not stat.S_ISREG(file_stat.st_mode):
        raise Refusal(f"{label} is not a regular file: {canonical_path}")
    if file_stat.st_nlink != 1:
        raise Refusal(f"{label} must not be hard-linked: {canonical_path}")
    _validate_safe_owner_mode(file_stat, canonical_path, label)


def _same_file_state(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


@contextmanager
def _open_repo_regular_file(root: Path, rel_path: str, label: str):
    canonical_path, directory_fd, leaf = _open_repo_parent(root, rel_path, label)
    try:
        try:
            file_fd = os.open(
                leaf,
                os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _classify_open_error(
                directory_fd, leaf, canonical_path, label, exc
            ) from exc
        try:
            file_stat = os.fstat(file_fd)
            _validate_regular_stat(file_stat, canonical_path, label)
            yield canonical_path, file_fd, file_stat
        finally:
            os.close(file_fd)
    finally:
        os.close(directory_fd)


def _read_fd_all(
    file_fd: int,
    file_stat: os.stat_result,
    canonical_path: str,
    label: str,
    maximum: int,
) -> bytes:
    if file_stat.st_size > maximum:
        raise Refusal(f"{label} exceeds the {maximum}-byte safety limit: {canonical_path}")
    chunks = []
    total = 0
    while True:
        chunk = os.read(file_fd, min(HASH_CHUNK_SIZE, maximum + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > maximum:
            raise Refusal(
                f"{label} exceeds the {maximum}-byte safety limit: {canonical_path}"
            )
    after = os.fstat(file_fd)
    if total != file_stat.st_size or not _same_file_state(file_stat, after):
        raise Refusal(f"{label} changed while it was being read: {canonical_path}")
    return b"".join(chunks)


def read_repo_regular_file(
    root: Path, rel_path: str, label: str, maximum: int = MAX_JSON_BYTES
) -> tuple[str, bytes]:
    with _open_repo_regular_file(root, rel_path, label) as (
        canonical_path,
        file_fd,
        file_stat,
    ):
        return (
            canonical_path,
            _read_fd_all(
                file_fd, file_stat, canonical_path, label, maximum
            ),
        )


def hash_repo_regular_file(
    root: Path, rel_path: str, label: str
) -> tuple[str, str, int]:
    with _open_repo_regular_file(root, rel_path, label) as (
        canonical_path,
        file_fd,
        file_stat,
    ):
        digest = hashlib.sha256()
        total = 0
        while True:
            chunk = os.read(file_fd, HASH_CHUNK_SIZE)
            if not chunk:
                break
            digest.update(chunk)
            total += len(chunk)
        after = os.fstat(file_fd)
        if total != file_stat.st_size or not _same_file_state(file_stat, after):
            raise Refusal(f"{label} changed while it was being hashed: {canonical_path}")
        return canonical_path, digest.hexdigest(), total


def load_repo_json(paths: Paths, rel_path: str, label: str) -> tuple[dict, bytes]:
    canonical_path, data = read_repo_regular_file(
        paths.root, rel_path, label, MAX_JSON_BYTES
    )
    return _decode_json_object(data, label, paths.root / canonical_path), data


def _write_all(file_fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(file_fd, view)
        if written <= 0:
            raise OSError("short write")
        view = view[written:]


def _open_existing_at(
    directory_fd: int, leaf: str, canonical_path: str, label: str
) -> tuple[int, os.stat_result]:
    try:
        file_fd = os.open(
            leaf,
            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
    except OSError as exc:
        raise _classify_open_error(
            directory_fd, leaf, canonical_path, label, exc
        ) from exc
    try:
        file_stat = os.fstat(file_fd)
        _validate_regular_stat(file_stat, canonical_path, label)
        return file_fd, file_stat
    except BaseException:
        os.close(file_fd)
        raise


def atomic_write_repo_json(
    paths: Paths,
    rel_path: str,
    value: dict,
    *,
    expected_sha256: str | None = None,
    must_not_exist: bool = False,
) -> None:
    canonical_path, directory_fd, leaf = _open_repo_parent(
        paths.root, rel_path, "JSON destination"
    )
    existing_fd = None
    existing_stat = None
    existing_mode = 0o600
    try:
        try:
            existing_fd, existing_stat = _open_existing_at(
                directory_fd, leaf, canonical_path, "JSON destination"
            )
        except Refusal as exc:
            try:
                os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise
            if "not a regular file" not in str(exc):
                raise
        if must_not_exist and existing_fd is not None:
            raise Refusal(f"destination already exists: {canonical_path}")
        if existing_fd is not None:
            existing_mode = stat.S_IMODE(existing_stat.st_mode)
            if expected_sha256 is not None:
                digest = hashlib.sha256()
                while True:
                    chunk = os.read(existing_fd, HASH_CHUNK_SIZE)
                    if not chunk:
                        break
                    digest.update(chunk)
                after = os.fstat(existing_fd)
                if (
                    not _same_file_state(existing_stat, after)
                    or digest.hexdigest() != expected_sha256
                ):
                    raise Refusal(
                        f"destination changed before atomic write: {canonical_path}"
                    )
                os.lseek(existing_fd, 0, os.SEEK_SET)
        elif expected_sha256 is not None:
            raise Refusal(f"destination disappeared before atomic write: {canonical_path}")

        encoded = (
            json.dumps(value, indent=2, sort_keys=False, ensure_ascii=True) + "\n"
        ).encode("utf-8")
        temporary = f".tmp-{os.getpid()}-{secrets.token_hex(16)}.json"
        temporary_fd = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | os.O_NOFOLLOW
            | os.O_CLOEXEC,
            existing_mode,
            dir_fd=directory_fd,
        )
        renamed = False
        try:
            if existing_stat is not None:
                try:
                    os.fchown(
                        temporary_fd, existing_stat.st_uid, existing_stat.st_gid
                    )
                except PermissionError as exc:
                    raise Refusal(
                        f"cannot preserve destination ownership: {canonical_path}"
                    ) from exc
            os.fchmod(temporary_fd, existing_mode)
            _write_all(temporary_fd, encoded)
            os.fsync(temporary_fd)
            os.close(temporary_fd)
            temporary_fd = -1

            if existing_stat is not None:
                verify_fd, verify_stat = _open_existing_at(
                    directory_fd, leaf, canonical_path, "JSON destination"
                )
                try:
                    if not _same_file_state(existing_stat, verify_stat):
                        raise Refusal(
                            f"destination changed before atomic replace: {canonical_path}"
                        )
                finally:
                    os.close(verify_fd)
            os.rename(
                temporary,
                leaf,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            renamed = True
            os.fsync(directory_fd)
        finally:
            if temporary_fd >= 0:
                os.close(temporary_fd)
            if not renamed:
                try:
                    os.unlink(temporary, dir_fd=directory_fd)
                except OSError:
                    pass
    finally:
        if existing_fd is not None:
            os.close(existing_fd)
        os.close(directory_fd)


def _ensure_repo_directory(root: Path, rel_path: str, label: str) -> None:
    canonical_path, directory_fd, leaf = _open_repo_parent(root, rel_path, label)
    try:
        try:
            os.mkdir(leaf, mode=0o700, dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileExistsError:
            pass
        try:
            opened = os.open(
                leaf,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _classify_open_error(
                directory_fd, leaf, canonical_path, label, exc
            ) from exc
        try:
            directory_stat = os.fstat(opened)
            if not stat.S_ISDIR(directory_stat.st_mode):
                raise Refusal(f"{label} is not a directory: {canonical_path}")
        finally:
            os.close(opened)
    finally:
        os.close(directory_fd)


def _repo_entry_exists(root: Path, rel_path: str, label: str) -> bool:
    canonical_path, directory_fd, leaf = _open_repo_parent(root, rel_path, label)
    try:
        try:
            entry = os.stat(leaf, dir_fd=directory_fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        if stat.S_ISLNK(entry.st_mode):
            raise Refusal(f"{label} is a symlink: {canonical_path}")
        return True
    finally:
        os.close(directory_fd)


def _unlink_repo_regular_file(root: Path, rel_path: str, label: str) -> None:
    canonical_path, directory_fd, leaf = _open_repo_parent(root, rel_path, label)
    try:
        file_fd, _ = _open_existing_at(directory_fd, leaf, canonical_path, label)
        os.close(file_fd)
        os.unlink(leaf, dir_fd=directory_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


@contextmanager
def governance_lock(paths: Paths):
    _ensure_repo_directory(paths.root, paths.claims_dir_rel, "claims directory")
    canonical_path, directory_fd, leaf = _open_repo_parent(
        paths.root, paths.lock_rel, "governance lock"
    )
    try:
        try:
            lock_fd = os.open(
                leaf,
                os.O_RDWR
                | os.O_CREAT
                | os.O_NONBLOCK
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _classify_open_error(
                directory_fd, leaf, canonical_path, "governance lock", exc
            ) from exc
        try:
            lock_stat = os.fstat(lock_fd)
            _validate_regular_stat(lock_stat, canonical_path, "governance lock")
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            verify_fd, verify_stat = _open_existing_at(
                directory_fd, leaf, canonical_path, "governance lock"
            )
            try:
                if (
                    lock_stat.st_dev,
                    lock_stat.st_ino,
                ) != (
                    verify_stat.st_dev,
                    verify_stat.st_ino,
                ):
                    raise Refusal(
                        "governance lock changed while acquiring it; refusing split lock"
                    )
            finally:
                os.close(verify_fd)
            yield
        finally:
            os.close(lock_fd)
    finally:
        os.close(directory_fd)


def _require_fields(obj: dict, fields: frozenset, label: str) -> None:
    actual = frozenset(obj)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise Refusal(f"{label} fields mismatch: missing={missing} unexpected={extra}")


def load_constants(paths: Paths) -> dict:
    constants, _ = load_repo_json(paths, paths.constants_rel, "constants")
    _require_fields(
        constants,
        frozenset(
            {
                "schema_version",
                "expected_product",
                "battery_floor_mv",
                "receipt_ttl_seconds",
                "partition_targets",
                "volatile_operations",
                "ram_rw_operations",
                "persistent_operations",
                "forbidden_command_words",
            }
        ),
        "constants",
    )
    if constants["schema_version"] != SCHEMA_VERSION:
        raise Refusal("constants schema_version mismatch")
    declared = constants["forbidden_command_words"]
    if not isinstance(declared, list) or frozenset(declared) != FORBIDDEN_COMMAND_WORDS:
        raise Refusal(
            "constants forbidden_command_words diverge from the engine's hardcoded "
            "copy; the data file cannot change the forbidden set"
        )
    partition_targets = constants["partition_targets"]
    if (
        not isinstance(partition_targets, list)
        or not all(isinstance(target, str) and target for target in partition_targets)
        or len(partition_targets) != len(set(partition_targets))
    ):
        raise Refusal("constants partition_targets must be a unique list of names")
    if not isinstance(constants["battery_floor_mv"], int) or constants["battery_floor_mv"] <= 0:
        raise Refusal("constants battery_floor_mv must be a positive integer")
    if (
        not isinstance(constants["receipt_ttl_seconds"], int)
        or constants["receipt_ttl_seconds"] <= 0
    ):
        raise Refusal("constants receipt_ttl_seconds must be a positive integer")
    for key, expected in (
        ("volatile_operations", {op for op, (tier, _, _) in OPERATIONS.items() if tier == "volatile"}),
        ("ram_rw_operations", {op for op, (tier, _, _) in OPERATIONS.items() if tier == "ram_rw"}),
        ("persistent_operations", {op for op, (tier, _, _) in OPERATIONS.items() if tier == "persistent"}),
    ):
        if not isinstance(constants[key], list) or frozenset(constants[key]) != frozenset(expected):
            raise Refusal(f"constants {key} diverge from the engine's operation table")
    return constants


def load_policy(paths: Paths, constants: dict) -> tuple[dict, str]:
    policy, raw = load_repo_json(paths, paths.policy_rel, "policy")
    policy_sha256 = sha256_bytes(raw)
    _require_fields(policy, POLICY_FIELDS, "policy")
    if policy["schema_version"] != SCHEMA_VERSION:
        raise Refusal("policy schema_version mismatch")
    if not isinstance(policy["enabled"], bool):
        raise Refusal("policy enabled must be a boolean")
    for key in ("revision", "authorized_by", "authorization_note"):
        _validated_human_text(policy[key], f"policy {key}")
    if not isinstance(policy["standing_scopes"], list):
        raise Refusal("policy standing_scopes must be a list")
    for scope in policy["standing_scopes"]:
        if not isinstance(scope, dict):
            raise Refusal("policy scope entries must be objects")
        _require_fields(scope, SCOPE_FIELDS, "policy scope")
        operation = scope["operation"]
        if operation not in OPERATIONS:
            raise Refusal(f"policy scope names unknown operation: {operation}")
        tier, fixed_target, _ = OPERATIONS[operation]
        if tier == "persistent":
            raise Refusal(
                "policy standing_scopes may not contain persistent operations; "
                "partition writes require authorized_profiles entries"
            )
        if scope["tier"] != tier:
            raise Refusal(f"policy scope tier mismatch for {operation}")
        if scope["target"] != fixed_target:
            raise Refusal(f"policy scope target mismatch for {operation}")
    if not isinstance(policy["authorized_profiles"], list):
        raise Refusal("policy authorized_profiles must be a list")
    authorized_paths = set()
    for entry in policy["authorized_profiles"]:
        if not isinstance(entry, dict):
            raise Refusal("policy authorized_profiles entries must be objects")
        _require_fields(entry, AUTHORIZED_PROFILE_FIELDS, "policy authorized profile")
        if not isinstance(entry["profile_path"], str) or not entry["profile_path"]:
            raise Refusal("authorized profile profile_path must be a non-empty string")
        profile_path = _canonical_repo_relative_path(
            entry["profile_path"], "authorized profile"
        )
        if profile_path != entry["profile_path"]:
            raise Refusal("authorized profile profile_path must use canonical form")
        if profile_path in authorized_paths:
            raise Refusal(
                f"policy contains duplicate authorized profile path: {profile_path}"
            )
        authorized_paths.add(profile_path)
        if not _is_sha256(entry["profile_sha256"]):
            raise Refusal("authorized profile profile_sha256 must be a SHA-256 hex digest")
        targets = entry["targets"]
        if (
            not isinstance(targets, list)
            or not targets
            or not all(isinstance(target, str) and target for target in targets)
            or len(targets) != len(set(targets))
            or not frozenset(targets) <= frozenset(constants["partition_targets"])
        ):
            raise Refusal(
                "authorized profile targets must be a unique subset of partition_targets"
            )
        for key in ("authorized_by", "note"):
            _validated_human_text(
                entry[key], f"authorized profile {key}", maximum=8192
            )
        if entry["authorized_by"] != policy["authorized_by"]:
            raise Refusal(
                "authorized profile authorized_by must equal policy authorized_by"
            )
    if policy["manual_only"] != ["bootloader-relock"]:
        raise Refusal("policy manual_only must remain [\"bootloader-relock\"]")
    return policy, policy_sha256


def _is_sha256(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def build_exact_command(operation: str, target, artifact) -> list:
    if operation == "device_reboot":
        return ["fastboot", "reboot"]
    if operation == "ram_boot":
        return ["fastboot", "boot", str(artifact)]
    if operation == "runtime_handoff":
        return ["telnet", "172.16.42.1", "23"]
    if operation == "partition_write":
        return ["fastboot", "flash", str(target), str(artifact)]
    raise Refusal(f"unknown operation: {operation}")


def _check_forbidden(exact_command: list) -> None:
    joined = " ".join(exact_command)
    for word in sorted(FORBIDDEN_COMMAND_WORDS):
        if word in joined:
            raise Refusal(f"exact_command contains forbidden word: {word}")


def validate_record(record: dict, constants: dict) -> None:
    """The single structural validator; every subcommand routes through it."""
    if not isinstance(record, dict):
        raise Refusal("record must be a JSON object")
    tier = record.get("tier")
    if tier not in TIERS:
        raise Refusal(f"record tier must be one of {list(TIERS)}")
    expected_fields = (
        RECORD_FIELDS_READ_ONLY if tier == "read_only" else RECORD_FIELDS_ACTION
    )
    _require_fields(record, expected_fields, "record")
    if record["schema_version"] != SCHEMA_VERSION:
        raise Refusal("record schema_version mismatch")
    if record["status"] not in ("ready", "claimed", "completed"):
        raise Refusal("record status must be ready, claimed, or completed")
    if not isinstance(record["experiment_id"], str) or not EXPERIMENT_ID_RE.fullmatch(
        record["experiment_id"]
    ):
        raise Refusal("record experiment_id must match ^[a-z0-9][a-z0-9-]{2,63}$")
    for key in ("hypothesis", "discriminator", "next_if_positive", "next_if_negative"):
        if not isinstance(record[key], str) or not record[key].strip():
            raise Refusal(f"record {key} must be a non-empty string")
    if record["next_if_positive"].strip() == record["next_if_negative"].strip():
        raise Refusal("next_if_positive and next_if_negative must differ")
    if not isinstance(record["timebox_seconds"], int) or record["timebox_seconds"] <= 0:
        raise Refusal("record timebox_seconds must be a positive integer")
    if not isinstance(record["lanes"], list) or not isinstance(record["observations"], list):
        raise Refusal("record lanes and observations must be lists")
    if tier == "read_only":
        return

    action = record["action"]
    if not isinstance(action, dict):
        raise Refusal("record action must be an object")
    _require_fields(action, ACTION_FIELDS, "record action")
    operation = action["operation"]
    if operation not in OPERATIONS:
        raise Refusal(f"record action operation unknown: {operation}")
    op_tier, fixed_target, needs_artifact = OPERATIONS[operation]
    if op_tier != tier:
        raise Refusal(f"record tier {tier} does not match operation tier {op_tier}")
    target = action["target"]
    if fixed_target is None:
        if target not in constants["partition_targets"]:
            raise Refusal(f"record action target must be one of {constants['partition_targets']}")
    elif target != fixed_target:
        raise Refusal(f"record action target must be {fixed_target}")
    if needs_artifact:
        if not isinstance(action["artifact"], str) or not action["artifact"]:
            raise Refusal("record action artifact path required for this operation")
        if not _is_sha256(action["artifact_sha256"]):
            raise Refusal("record action artifact_sha256 must be a SHA-256 hex digest")
        if not isinstance(action["artifact_size"], int) or action["artifact_size"] <= 0:
            raise Refusal("record action artifact_size must be a positive integer")
    else:
        if action["artifact"] is not None or action["artifact_sha256"] is not None:
            raise Refusal("record action artifact must be null for this operation")
        if action["artifact_size"] is not None:
            raise Refusal("record action artifact_size must be null for this operation")
    if operation == "partition_write":
        if not isinstance(action["profile"], str) or not action["profile"]:
            raise Refusal("partition_write requires a profile path")
        if not _is_sha256(action["profile_sha256"]):
            raise Refusal("partition_write requires profile_sha256")
    expected_command = build_exact_command(operation, target, action["artifact"])
    if action["exact_command"] != expected_command:
        raise Refusal(
            f"record exact_command must equal the engine builder output {expected_command}"
        )
    _check_forbidden(action["exact_command"])

    gates = record["gates"]
    if not isinstance(gates, dict):
        raise Refusal("record gates must be an object")
    _require_fields(gates, GATES_FIELDS, "record gates")
    identity = gates["identity"]
    if not isinstance(identity, dict) or identity.get("expected_product") != constants[
        "expected_product"
    ]:
        raise Refusal(
            f"record gates.identity.expected_product must be {constants['expected_product']}"
        )
    if tier == "ram_rw":
        media = gates["persistent_media"]
        if not isinstance(media, dict):
            raise Refusal(
                "ram_rw records must acknowledge persistent media exposure "
                "(the booted OS mounts userdata read-write)"
            )
        _require_fields(
            media, frozenset({"acknowledged", "rebuild_reference"}), "persistent_media"
        )
        if media["acknowledged"] is not True:
            raise Refusal("ram_rw persistent_media.acknowledged must be true")
        if not isinstance(media["rebuild_reference"], str) or not media[
            "rebuild_reference"
        ].strip():
            raise Refusal("ram_rw persistent_media.rebuild_reference must name how userdata is rebuilt")
    else:
        if gates["persistent_media"] is not None:
            raise Refusal("persistent_media gate only applies to ram_rw records")
    if tier == "persistent":
        rollback = gates["rollback"]
        if not isinstance(rollback, dict):
            raise Refusal("persistent records require a rollback gate")
        _require_fields(rollback, ROLLBACK_FIELDS, "rollback gate")
        if rollback["target"] != target:
            raise Refusal("rollback target must match the action target")
        if not isinstance(rollback["path"], str) or not rollback["path"]:
            raise Refusal("rollback path must be a non-empty string")
        if not _is_sha256(rollback["sha256"]):
            raise Refusal("rollback sha256 must be a SHA-256 hex digest")
        if rollback["sha256"] == action["artifact_sha256"]:
            raise Refusal("rollback artifact hash must differ from the deploy artifact hash")
        if not isinstance(rollback["size"], int) or rollback["size"] <= 0:
            raise Refusal("rollback size must be a positive integer")
    else:
        if gates["rollback"] is not None:
            raise Refusal("rollback gate only applies to persistent records")

    repeat_guard = record["repeat_guard"]
    if repeat_guard is not None:
        if tier != "persistent":
            raise Refusal("repeat_guard only applies to persistent records")
        _require_fields(repeat_guard, REPEAT_GUARD_FIELDS, "repeat_guard")
        if not EXPERIMENT_ID_RE.fullmatch(str(repeat_guard["prior_experiment_id"])):
            raise Refusal("repeat_guard prior_experiment_id must be a valid experiment id")
        if (
            not isinstance(repeat_guard["changed_discriminator"], str)
            or not repeat_guard["changed_discriminator"].strip()
        ):
            raise Refusal("repeat_guard changed_discriminator must be a non-empty string")
        if not isinstance(repeat_guard["evidence_report"], str) or not repeat_guard[
            "evidence_report"
        ]:
            raise Refusal("repeat_guard evidence_report must be a path")
        if not _is_sha256(repeat_guard["evidence_report_sha256"]):
            raise Refusal("repeat_guard evidence_report_sha256 must be a SHA-256 hex digest")

    receipt = record["receipt"]
    if record["status"] == "ready" and receipt is not None:
        raise Refusal("ready records must not carry a receipt")
    if record["status"] in ("claimed", "completed") and not isinstance(receipt, dict):
        raise Refusal("claimed records must carry the consumed receipt")


def action_digest(record: dict) -> str:
    action = record["action"]
    gates = record["gates"]
    return sha256_bytes(
        canonical(
            {
                "tier": record["tier"],
                "operation": action["operation"],
                "target": action["target"],
                "artifact_sha256": action["artifact_sha256"],
                "exact_command": action["exact_command"],
                "identity": gates["identity"],
                "rollback": gates["rollback"],
            }
        ).encode("ascii")
    )


def load_active(paths: Paths, constants: dict) -> dict:
    if not _repo_entry_exists(paths.root, paths.active_rel, "active record"):
        raise Refusal(f"no active experiment record: {paths.active}")
    record, _ = load_repo_json(paths, paths.active_rel, "active record")
    validate_record(record, constants)
    return record


def _verify_pinned_file(root: Path, rel_path: str, expected_sha256: str, expected_size, label: str) -> None:
    _, actual_sha256, actual_size = hash_repo_regular_file(root, rel_path, label)
    if expected_size is not None and actual_size != expected_size:
        raise Refusal(f"{label} size mismatch: {rel_path}")
    if actual_sha256 != expected_sha256:
        raise Refusal(f"{label} hash mismatch: {rel_path}")


def load_partition_profile(paths: Paths, profile_rel: str, target: str) -> dict:
    profile_rel, profile_bytes = read_repo_regular_file(
        paths.root, profile_rel, "profile"
    )
    profile = _decode_json_object(
        profile_bytes, "profile", paths.root / profile_rel
    )
    entry = profile.get(target)
    if not isinstance(entry, dict):
        raise Refusal(f"profile has no entry for target {target}")
    _require_fields(entry, PROFILE_ARTIFACT_FIELDS, f"profile {target} entry")
    artifact_rel = _canonical_repo_relative_path(entry["path"], "artifact")
    artifact_sha = entry["sha256"]
    artifact_size = entry["size"]
    if not _is_sha256(artifact_sha):
        raise Refusal("profile artifact sha256 must be a SHA-256 hex digest")
    if not isinstance(artifact_size, int) or artifact_size <= 0:
        raise Refusal("profile artifact size must be a positive integer")
    _verify_pinned_file(
        paths.root, artifact_rel, artifact_sha, artifact_size, "artifact"
    )

    rollback = profile.get("rollback")
    if not isinstance(rollback, dict):
        raise Refusal("profile has no rollback entry")
    _require_fields(rollback, ROLLBACK_FIELDS, "profile rollback entry")
    if rollback["target"] != target:
        raise Refusal("profile rollback target must match the authorized target")
    rollback_rel = _canonical_repo_relative_path(rollback["path"], "rollback artifact")
    rollback_sha = rollback["sha256"]
    rollback_size = rollback["size"]
    if not _is_sha256(rollback_sha):
        raise Refusal("profile rollback sha256 must be a SHA-256 hex digest")
    if not isinstance(rollback_size, int) or rollback_size <= 0:
        raise Refusal("profile rollback size must be a positive integer")
    if rollback_sha == artifact_sha:
        raise Refusal("rollback artifact hash must differ from the deploy artifact hash")
    _verify_pinned_file(
        paths.root,
        rollback_rel,
        rollback_sha,
        rollback_size,
        "rollback artifact",
    )

    return {
        "profile_path": profile_rel,
        "profile_sha256": sha256_bytes(profile_bytes),
        "artifact_path": artifact_rel,
        "artifact_sha256": artifact_sha,
        "artifact_size": artifact_size,
        "rollback_target": target,
        "rollback_path": rollback_rel,
        "rollback_sha256": rollback_sha,
        "rollback_size": rollback_size,
    }


def _next_policy_revision(current: str, now: datetime) -> str:
    match = re.fullmatch(r"(\d{4}-\d{2}-\d{2})\.([1-9][0-9]*)", current)
    if match is None:
        raise Refusal(
            "policy revision must match YYYY-MM-DD.N before automatic authorization"
        )
    today = now.date().isoformat()
    current_day, sequence = match.groups()
    if current_day > today:
        raise Refusal("policy revision date is in the future")
    if current_day == today:
        return f"{today}.{int(sequence) + 1}"
    return f"{today}.1"


def _find_authorized_profile(policy: dict, profile_path: str):
    for entry in policy["authorized_profiles"]:
        if entry["profile_path"] == profile_path:
            return entry
    return None


def _run_git(paths: Paths, *arguments: str) -> bytes:
    git_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": "/nonexistent",
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
    }
    try:
        completed = subprocess.run(
            [
                "/usr/bin/git",
                "-C",
                str(paths.root),
                "--no-optional-locks",
                *arguments,
            ],
            check=False,
            env=git_environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refusal("git is required for authorize-profile TCB verification") from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", errors="replace").strip()
        raise Refusal(f"git TCB verification failed: {detail or arguments[0]}")
    return completed.stdout


def _git_head_entry(paths: Paths, git_head: str, rel_path: str) -> tuple[str, str, bytes]:
    output = _run_git(
        paths, "ls-tree", "-z", "--full-tree", git_head, "--", rel_path
    )
    entries = [entry for entry in output.split(b"\0") if entry]
    if len(entries) != 1:
        raise Refusal(
            f"critical TCB file must be tracked at Git HEAD: {rel_path}"
        )
    try:
        metadata, encoded_path = entries[0].split(b"\t", 1)
        mode, object_type, object_id = metadata.decode("ascii").split()
        tree_path = encoded_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal(f"cannot parse Git HEAD entry for critical TCB file: {rel_path}") from exc
    if tree_path != rel_path or object_type != "blob" or mode == "120000":
        raise Refusal(
            f"critical TCB file must be a regular tracked blob at HEAD: {rel_path}"
        )
    blob = _run_git(paths, "cat-file", "blob", object_id)
    return mode, object_id, blob


def _git_index_entry(paths: Paths, rel_path: str) -> tuple[str, str]:
    output = _run_git(paths, "ls-files", "--stage", "-z", "--", rel_path)
    entries = [entry for entry in output.split(b"\0") if entry]
    if len(entries) != 1:
        raise Refusal(
            f"critical TCB file must be tracked exactly once in the Git index: {rel_path}"
        )
    try:
        metadata, encoded_path = entries[0].split(b"\t", 1)
        mode, object_id, stage = metadata.decode("ascii").split()
        index_path = encoded_path.decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal(f"cannot parse Git index entry for critical TCB file: {rel_path}") from exc
    if index_path != rel_path or stage != "0" or mode == "120000":
        raise Refusal(
            f"critical TCB file must be an ordinary stage-0 index entry: {rel_path}"
        )
    return mode, object_id


def _capture_authorization_tcb(paths: Paths, profile_rel: str) -> dict:
    profile_rel = _canonical_repo_relative_path(profile_rel, "profile")
    if not profile_rel.startswith("profiles/") or profile_rel == "profiles/":
        raise Refusal("authorize-profile requires a profile under profiles/")
    critical = {
        "engine": ENGINE_REL,
        "constants": paths.constants_rel,
        "policy": paths.policy_rel,
        "profile": profile_rel,
    }
    git_head = _run_git(paths, "rev-parse", "--verify", "HEAD^{commit}").decode(
        "ascii"
    ).strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", git_head):
        raise Refusal("Git HEAD did not resolve to a canonical commit object")

    snapshot = {"git_head": git_head}
    for name, rel_path in critical.items():
        _, current_sha256, current_size = hash_repo_regular_file(
            paths.root, rel_path, f"critical TCB {name}"
        )
        head_mode, head_object, head_blob = _git_head_entry(
            paths, git_head, rel_path
        )
        index_mode, index_object = _git_index_entry(paths, rel_path)
        if (index_mode, index_object) != (head_mode, head_object):
            raise Refusal(
                f"critical TCB file is staged and not exactly HEAD: {rel_path}"
            )
        if (
            current_size != len(head_blob)
            or current_sha256 != sha256_bytes(head_blob)
        ):
            raise Refusal(
                f"critical TCB file is dirty and not exactly HEAD: {rel_path}"
            )
        snapshot[f"{name}_sha256"] = current_sha256

    if (
        _run_git(paths, "rev-parse", "--verify", "HEAD^{commit}")
        .decode("ascii")
        .strip()
        != git_head
    ):
        raise Refusal("Git HEAD changed during TCB verification")
    return snapshot


def _authorization_payload(
    policy: dict,
    policy_sha256: str,
    tcb: dict,
    profile: dict,
    target: str,
    note: str,
    next_revision: str,
) -> dict:
    return {
        "kind": "persistent-profile-authorization",
        "schema_version": 1,
        "declared_owner": policy["authorized_by"],
        "authentication_method": "interactive-declaration",
        "base_policy_sha256": policy_sha256,
        "trusted_code_base": tcb,
        "next_policy_revision": next_revision,
        "profile_path": profile["profile_path"],
        "profile_sha256": profile["profile_sha256"],
        "target": target,
        "artifact_sha256": profile["artifact_sha256"],
        "artifact_size": profile["artifact_size"],
        "rollback_sha256": profile["rollback_sha256"],
        "rollback_size": profile["rollback_size"],
        "note": note,
    }


def _confirm_authorization(expected: str) -> None:
    if not sys.stdin.isatty():
        raise Refusal(
            "authorize-profile requires an interactive TTY; pipes and CI are refused"
        )
    print(f"Type exactly: {expected}")
    try:
        answer = input("> ")
    except EOFError as exc:
        raise Refusal("authorization confirmation ended before input") from exc
    if answer != expected:
        raise Refusal("authorization confirmation did not match exactly")


def cmd_authorize_profile(paths: Paths, args: argparse.Namespace) -> int:
    profile_rel = _canonical_repo_relative_path(args.profile, "profile")
    tcb = _capture_authorization_tcb(paths, profile_rel)
    constants = load_constants(paths)
    policy, policy_sha256 = load_policy(paths, constants)
    if policy_sha256 != tcb["policy_sha256"]:
        raise Refusal("policy changed during TCB verification")
    if not policy["enabled"]:
        raise Refusal("policy is disabled; no authorization can be added")
    if _repo_entry_exists(paths.root, paths.active_rel, "active record"):
        raise Refusal(
            "authorize-profile requires safe idle; complete and archive the active "
            "experiment first"
        )
    note = _validated_human_text(
        args.note, "authorize-profile --note", maximum=512
    )
    if args.target not in constants["partition_targets"]:
        raise Refusal(
            f"authorize-profile target must be one of {constants['partition_targets']}"
        )
    profile = load_partition_profile(paths, profile_rel, args.target)
    if profile["profile_sha256"] != tcb["profile_sha256"]:
        raise Refusal("profile changed during TCB verification")
    if _capture_authorization_tcb(paths, profile_rel) != tcb:
        raise Refusal("critical TCB changed while preparing authorization preview")
    existing = _find_authorized_profile(policy, profile["profile_path"])
    if existing is not None:
        if (
            existing["profile_sha256"] == profile["profile_sha256"]
            and args.target in existing["targets"]
        ):
            print("authorize-profile: already authorized (policy unchanged)")
            return 0
        raise Refusal(
            "profile_path already has a different authorization; replace or widen "
            "only through a separately reviewed revocation/update"
        )

    next_revision = _next_policy_revision(policy["revision"], _now())
    payload = _authorization_payload(
        policy,
        policy_sha256,
        tcb,
        profile,
        args.target,
        note,
        next_revision,
    )
    authorization_digest = sha256_bytes(canonical(payload).encode("ascii"))
    expected_confirmation = f"AUTHORIZE-PERSISTENT {authorization_digest}"

    print("authorize-profile: HOST-ONLY authorization preview")
    print(
        f"declared_owner={policy['authorized_by']} "
        "(interactive declaration; identity is not cryptographically authenticated)"
    )
    print(f"profile_path={profile['profile_path']}")
    print(f"profile_sha256={profile['profile_sha256']}")
    print(f"target={args.target}")
    print(
        f"artifact={profile['artifact_path']} "
        f"sha256={profile['artifact_sha256']} size={profile['artifact_size']}"
    )
    print(
        f"rollback={profile['rollback_path']} "
        f"sha256={profile['rollback_sha256']} size={profile['rollback_size']}"
    )
    print(f"base_policy_sha256={policy_sha256}")
    print(f"git_head={tcb['git_head']}")
    print(f"engine_sha256={tcb['engine_sha256']}")
    print(f"constants_sha256={tcb['constants_sha256']}")
    print(f"next_policy_revision={next_revision}")
    print(f"note={note}")
    print(f"authorization_digest={authorization_digest}")
    print("No experiment, claim, receipt, ledger entry, or device action will run.")
    _confirm_authorization(expected_confirmation)

    with governance_lock(paths):
        locked_tcb = _capture_authorization_tcb(paths, profile_rel)
        if locked_tcb != tcb:
            raise Refusal(
                "Git HEAD or critical TCB changed after confirmation; "
                "run the command again"
            )
        locked_constants = load_constants(paths)
        if canonical(locked_constants) != canonical(constants):
            raise Refusal("constants changed after confirmation; run the command again")
        locked_policy, locked_policy_sha256 = load_policy(paths, locked_constants)
        if locked_policy_sha256 != policy_sha256:
            raise Refusal("policy changed after confirmation; run the command again")
        if _repo_entry_exists(paths.root, paths.active_rel, "active record"):
            raise Refusal(
                "an active experiment appeared after confirmation; authorization not written"
            )
        locked_profile = load_partition_profile(paths, profile_rel, args.target)
        locked_payload = _authorization_payload(
            locked_policy,
            locked_policy_sha256,
            locked_tcb,
            locked_profile,
            args.target,
            note,
            next_revision,
        )
        if (
            locked_profile != profile
            or sha256_bytes(canonical(locked_payload).encode("ascii"))
            != authorization_digest
        ):
            raise Refusal(
                "profile or pinned artifacts changed after confirmation; "
                "run the command again"
            )
        if _find_authorized_profile(locked_policy, profile["profile_path"]) is not None:
            raise Refusal("authorization changed concurrently; run the command again")

        updated_policy = dict(locked_policy)
        updated_policy["revision"] = next_revision
        updated_policy["authorized_profiles"] = list(
            locked_policy["authorized_profiles"]
        ) + [
            {
                "profile_path": profile["profile_path"],
                "profile_sha256": profile["profile_sha256"],
                "targets": [args.target],
                "authorized_by": locked_policy["authorized_by"],
                "note": (
                    f"{note} [authorization_digest={authorization_digest}]"
                ),
            }
        ]
        atomic_write_repo_json(
            paths,
            paths.policy_rel,
            updated_policy,
            expected_sha256=locked_policy_sha256,
        )
        _, updated_policy_sha256 = load_policy(paths, locked_constants)

    print("authorize-profile: authorization recorded")
    print(f"policy_revision={next_revision}")
    print(f"policy_sha256={updated_policy_sha256}")
    print("No receipt issued; no claim or device action executed.")
    return 0


def _ledger_lines(paths: Paths) -> list:
    if not _repo_entry_exists(paths.root, paths.ledger_rel, "claims ledger"):
        return []
    _, raw = read_repo_regular_file(
        paths.root, paths.ledger_rel, "claims ledger", MAX_LEDGER_BYTES
    )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise Refusal("claims ledger is not valid UTF-8") from exc
    lines = []
    for line in text.splitlines():
        if not line.strip():
            continue
        entry = {}
        for token in line.split():
            if "=" in token:
                key, _, value = token.partition("=")
                entry[key] = value
        lines.append(entry)
    return lines


def _append_ledger_line(paths: Paths, line: str) -> None:
    canonical_path, directory_fd, leaf = _open_repo_parent(
        paths.root, paths.ledger_rel, "claims ledger"
    )
    try:
        try:
            ledger_fd = os.open(
                leaf,
                os.O_WRONLY
                | os.O_APPEND
                | os.O_CREAT
                | os.O_NONBLOCK
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
        except OSError as exc:
            raise _classify_open_error(
                directory_fd, leaf, canonical_path, "claims ledger", exc
            ) from exc
        try:
            ledger_stat = os.fstat(ledger_fd)
            _validate_regular_stat(ledger_stat, canonical_path, "claims ledger")
            _write_all(ledger_fd, (line + "\n").encode("utf-8"))
            os.fsync(ledger_fd)
            after = os.fstat(ledger_fd)
            if (
                ledger_stat.st_dev,
                ledger_stat.st_ino,
                ledger_stat.st_mode,
                ledger_stat.st_nlink,
            ) != (
                after.st_dev,
                after.st_ino,
                after.st_mode,
                after.st_nlink,
            ):
                raise Refusal("claims ledger changed while appending")
        finally:
            os.close(ledger_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _claim_guard_rel(experiment_id: str) -> str:
    if not EXPERIMENT_ID_RE.fullmatch(experiment_id):
        raise Refusal("cannot derive claim guard from invalid experiment id")
    return f"notes/bringup-claims/{experiment_id}.claim-guard.json"


def _claim_guard_exists(paths: Paths, experiment_id: str) -> bool:
    return _repo_entry_exists(
        paths.root, _claim_guard_rel(experiment_id), "claim replay guard"
    )


def _write_claim_guard(
    paths: Paths, record: dict, receipt: dict, action_digest_value: str
) -> None:
    guard_rel = _claim_guard_rel(record["experiment_id"])
    canonical_path, directory_fd, leaf = _open_repo_parent(
        paths.root, guard_rel, "claim replay guard"
    )
    encoded = (
        canonical(
            {
                "schema_version": 1,
                "experiment_id": record["experiment_id"],
                "action_digest": action_digest_value,
                "receipt": receipt,
            }
        )
        + "\n"
    ).encode("ascii")
    try:
        try:
            guard_fd = os.open(
                leaf,
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | os.O_NOFOLLOW
                | os.O_CLOEXEC,
                0o600,
                dir_fd=directory_fd,
            )
        except FileExistsError as exc:
            raise Refusal(
                "claim replay guard already exists; this experiment will not be reissued"
            ) from exc
        except OSError as exc:
            raise _classify_open_error(
                directory_fd, leaf, canonical_path, "claim replay guard", exc
            ) from exc
        try:
            _write_all(guard_fd, encoded)
            os.fsync(guard_fd)
        finally:
            os.close(guard_fd)
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def _check_repeat_guard(paths: Paths, record: dict) -> None:
    action = record["action"]
    prior = [
        entry
        for entry in _ledger_lines(paths)
        if entry.get("operation") == action["operation"]
        and entry.get("target") == action["target"]
        and entry.get("artifact_sha256") == action["artifact_sha256"]
    ]
    if not prior:
        return
    guard = record["repeat_guard"]
    if guard is None:
        raise Refusal(
            "this physical action was already claimed; a repeat requires a "
            "repeat_guard with a prior experiment, a changed discriminator, "
            "and new evidence"
        )
    archived_rel = (
        f"{paths.completed_dir_rel}/{guard['prior_experiment_id']}.json"
    )
    if not _repo_entry_exists(
        paths.root, archived_rel, "repeat_guard prior experiment"
    ):
        raise Refusal(
            "repeat_guard prior experiment is not archived: "
            f"{paths.root / archived_rel}"
        )
    hash_repo_regular_file(
        paths.root, archived_rel, "repeat_guard prior experiment"
    )
    _verify_pinned_file(
        paths.root,
        guard["evidence_report"],
        guard["evidence_report_sha256"],
        None,
        "repeat_guard evidence report",
    )


def _resolve_scope(policy: dict, record: dict, paths: Paths) -> None:
    tier = record["tier"]
    action = record["action"]
    if not policy["enabled"]:
        raise Refusal("policy is disabled; no standing authorization exists")
    if tier in ("volatile", "ram_rw"):
        for scope in policy["standing_scopes"]:
            if (
                scope["tier"] == tier
                and scope["operation"] == action["operation"]
                and scope["target"] == action["target"]
            ):
                return
        raise Refusal(
            f"no standing scope covers {tier}/{action['operation']}/{action['target']}"
        )
    if tier == "persistent":
        for entry in policy["authorized_profiles"]:
            if entry["profile_path"] != action["profile"]:
                continue
            if entry["profile_sha256"] != action["profile_sha256"]:
                raise Refusal(
                    "authorized profile hash does not match the record's profile pin"
                )
            if action["target"] not in entry["targets"]:
                raise Refusal(
                    f"authorized profile does not cover target {action['target']}"
                )
            _verify_pinned_file(
                paths.root, action["profile"], entry["profile_sha256"], None, "profile"
            )
            return
        raise Refusal(
            "persistent actions require a matching authorized_profiles entry in "
            "policy.json (per-profile owner authorization); none matches this profile"
        )
    raise Refusal(f"tier {tier} does not take claims")


def _claim_checks(paths: Paths, constants: dict, policy: dict, record: dict) -> None:
    if record["tier"] == "read_only":
        raise Refusal("read_only records are not claimed; record results directly")
    if record["status"] != "ready":
        raise Refusal(
            f"record status is {record['status']}; a second execution requires a "
            "new experiment and a new receipt"
        )
    _resolve_scope(policy, record, paths)
    action = record["action"]
    if action["artifact"] is not None:
        _verify_pinned_file(
            paths.root,
            action["artifact"],
            action["artifact_sha256"],
            action["artifact_size"],
            "artifact",
        )
    if record["tier"] == "persistent":
        rollback = record["gates"]["rollback"]
        _verify_pinned_file(
            paths.root, rollback["path"], rollback["sha256"], rollback["size"], "rollback artifact"
        )
        _check_repeat_guard(paths, record)


def cmd_claim(paths: Paths, dry_run: bool) -> int:
    with governance_lock(paths):
        constants = load_constants(paths)
        policy, policy_sha256 = load_policy(paths, constants)
        record = load_active(paths, constants)
        if record["tier"] == "read_only":
            _claim_checks(paths, constants, policy, record)
        digest = action_digest(record)
        if record["status"] != "ready":
            _claim_checks(paths, constants, policy, record)
        if _claim_guard_exists(paths, record["experiment_id"]):
            raise Refusal(
                "claim replay guard already exists for this experiment; a prior claim "
                "may have committed only partially, so the action will not be reissued"
            )
        _claim_checks(paths, constants, policy, record)
        if dry_run:
            print("preflight: ok (dry-run; no receipt issued, no state changed)")
            print(f"action_digest={digest}")
            return 0
        now = _now()
        receipt = {
            "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=constants["receipt_ttl_seconds"])),
            "consumed_at": _iso(now),
            "authority": "standing-policy",
            "policy_revision": policy["revision"],
            "policy_sha256": policy_sha256,
            "action_digest": digest,
        }
        action = record["action"]
        ledger_line = " ".join(
            [
                f"experiment_id={record['experiment_id']}",
                f"action_digest={digest}",
                f"ts={receipt['consumed_at']}",
                f"tier={record['tier']}",
                f"operation={action['operation']}",
                f"target={action['target']}",
                f"artifact_sha256={action['artifact_sha256']}",
                f"authority={receipt['authority']}",
                f"policy_revision={receipt['policy_revision']}",
                f"policy_sha256={receipt['policy_sha256']}",
            ]
        )
        _, active_sha256, _ = hash_repo_regular_file(
            paths.root, paths.active_rel, "active record"
        )
        _write_claim_guard(paths, record, receipt, digest)
        try:
            _append_ledger_line(paths, ledger_line)
            record["status"] = "claimed"
            record["receipt"] = receipt
            atomic_write_repo_json(
                paths,
                paths.active_rel,
                record,
                expected_sha256=active_sha256,
            )
        except Exception as exc:
            raise Refusal(
                "claim transaction did not fully commit; the persistent replay guard "
                "was retained and this action will not be reissued"
            ) from exc
    print("claim: consumed (replay guard, ledger, and active record committed)")
    print(f"action_digest={digest}")
    print("exact_command=" + " ".join(action["exact_command"]))
    return 0


def _cmd_new_locked(paths: Paths, args: argparse.Namespace) -> int:
    constants = load_constants(paths)
    load_policy(paths, constants)
    if _repo_entry_exists(paths.root, paths.active_rel, "active record"):
        raise Refusal(
            f"an active experiment already exists: {paths.active}; "
            "complete and archive it first (at most one active experiment)"
        )
    base = {
        "schema_version": SCHEMA_VERSION,
        "status": "ready",
        "experiment_id": args.experiment_id,
        "tier": None,
        "hypothesis": args.hypothesis,
        "discriminator": args.discriminator,
        "next_if_positive": args.next_if_positive,
        "next_if_negative": args.next_if_negative,
        "timebox_seconds": args.timebox_seconds,
        "lanes": [],
        "observations": [],
        "result": None,
    }
    if args.operation is None:
        base["tier"] = "read_only"
        record = base
    else:
        tier, fixed_target, needs_artifact = OPERATIONS[args.operation]
        base["tier"] = tier
        target = fixed_target if fixed_target is not None else args.target
        if target is None:
            raise Refusal("partition_write requires --target")
        artifact_rel = None
        artifact_sha = None
        artifact_size = None
        profile_rel = None
        profile_sha = None
        rollback = None
        if args.operation == "partition_write":
            if args.profile is None:
                raise Refusal("partition_write requires --profile")
            profile = load_partition_profile(paths, args.profile, target)
            profile_rel = profile["profile_path"]
            profile_sha = profile["profile_sha256"]
            artifact_rel = profile["artifact_path"]
            artifact_sha = profile["artifact_sha256"]
            artifact_size = profile["artifact_size"]
            rollback = {
                "target": profile["rollback_target"],
                "path": profile["rollback_path"],
                "sha256": profile["rollback_sha256"],
                "size": profile["rollback_size"],
            }
        elif needs_artifact:
            if args.artifact is None:
                raise Refusal(f"{args.operation} requires --artifact")
            artifact_rel, artifact_sha, artifact_size = hash_repo_regular_file(
                paths.root, args.artifact, "artifact"
            )
        persistent_media = None
        if tier == "ram_rw":
            if not args.acknowledge_persistent_media or not args.rebuild_reference:
                raise Refusal(
                    "ram_rw operations require --acknowledge-persistent-media and "
                    "--rebuild-reference: the booted OS mounts userdata read-write"
                )
            persistent_media = {
                "acknowledged": True,
                "rebuild_reference": args.rebuild_reference,
            }
        record = dict(base)
        record["action"] = {
            "operation": args.operation,
            "target": target,
            "profile": profile_rel,
            "profile_sha256": profile_sha,
            "artifact": artifact_rel,
            "artifact_sha256": artifact_sha,
            "artifact_size": artifact_size,
            "exact_command": build_exact_command(args.operation, target, artifact_rel),
        }
        record["gates"] = {
            "identity": {"expected_product": constants["expected_product"]},
            "persistent_media": persistent_media,
            "rollback": rollback,
        }
        record["repeat_guard"] = None
        if args.repeat_prior_experiment:
            record["repeat_guard"] = {
                "prior_experiment_id": args.repeat_prior_experiment,
                "changed_discriminator": args.repeat_changed_discriminator or "",
                "evidence_report": args.repeat_evidence_report or "",
                "evidence_report_sha256": (
                    hash_repo_regular_file(
                        paths.root,
                        args.repeat_evidence_report or "",
                        "repeat evidence report",
                    )[1]
                )
                if args.repeat_evidence_report
                else "",
            }
        record["receipt"] = None
    validate_record(record, constants)
    atomic_write_repo_json(
        paths, paths.active_rel, record, must_not_exist=True
    )
    print(f"new: {paths.active}")
    print(f"experiment_id={record['experiment_id']} tier={record['tier']}")
    return 0


def cmd_new(paths: Paths, args: argparse.Namespace) -> int:
    with governance_lock(paths):
        return _cmd_new_locked(paths, args)


def cmd_validate(paths: Paths) -> int:
    constants = load_constants(paths)
    load_policy(paths, constants)
    if _repo_entry_exists(paths.root, paths.active_rel, "active record"):
        record = load_active(paths, constants)
        print(
            f"validate: ok (active experiment {record['experiment_id']}, "
            f"tier {record['tier']}, status {record['status']})"
        )
    else:
        print("validate: ok (no active experiment; safe idle state)")
    return 0


def _cmd_result_locked(paths: Paths, args: argparse.Namespace) -> int:
    constants = load_constants(paths)
    record = load_active(paths, constants)
    if record["tier"] == "read_only":
        if record["status"] != "ready":
            raise Refusal("read_only record already carries a result")
    elif record["status"] != "claimed":
        raise Refusal("result requires a claimed record (or a ready read_only record)")
    evidence = _canonical_repo_relative_path(args.evidence, "evidence")
    evidence_parts = evidence.split("/")
    if (
        len(evidence_parts) != 2
        or evidence_parts[0] != paths.logs_dir_rel
        or not evidence_parts[1].endswith(".txt")
    ):
        raise Refusal("evidence must be a top-level .txt file under logs/")
    _, data = read_repo_regular_file(
        paths.root, evidence, "evidence", MAX_LEDGER_BYTES
    )
    if not ROUTE_STATUS_RE.search(data.decode("utf-8", errors="replace")):
        raise Refusal("evidence must contain a route_status=<value> line")
    _, active_sha256, _ = hash_repo_regular_file(
        paths.root, paths.active_rel, "active record"
    )
    record["result"] = {
        "outcome": args.outcome,
        "evidence": evidence,
        "evidence_sha256": sha256_bytes(data),
        "recorded_at": _iso(_now()),
        "note": args.note,
    }
    record["status"] = "completed"
    atomic_write_repo_json(
        paths,
        paths.active_rel,
        record,
        expected_sha256=active_sha256,
    )
    print(f"result: {args.outcome} recorded; no automatic retry is permitted")
    return 0


def cmd_result(paths: Paths, args: argparse.Namespace) -> int:
    with governance_lock(paths):
        return _cmd_result_locked(paths, args)


def _cmd_observe_locked(paths: Paths, note: str) -> int:
    constants = load_constants(paths)
    record = load_active(paths, constants)
    _, active_sha256, _ = hash_repo_regular_file(
        paths.root, paths.active_rel, "active record"
    )
    record["observations"].append({"at": _iso(_now()), "note": note})
    atomic_write_repo_json(
        paths,
        paths.active_rel,
        record,
        expected_sha256=active_sha256,
    )
    print(f"observe: recorded ({len(record['observations'])} total)")
    return 0


def cmd_observe(paths: Paths, note: str) -> int:
    with governance_lock(paths):
        return _cmd_observe_locked(paths, note)


def _cmd_archive_locked(paths: Paths) -> int:
    constants = load_constants(paths)
    record = load_active(paths, constants)
    if record["status"] != "completed":
        raise Refusal("archive requires a completed record")
    _ensure_repo_directory(
        paths.root, paths.completed_dir_rel, "completed records directory"
    )
    destination_rel = (
        f"{paths.completed_dir_rel}/{record['experiment_id']}.json"
    )
    if _repo_entry_exists(paths.root, destination_rel, "archive destination"):
        raise Refusal(
            f"archive destination already exists: {paths.root / destination_rel}"
        )
    atomic_write_repo_json(
        paths, destination_rel, record, must_not_exist=True
    )
    _unlink_repo_regular_file(paths.root, paths.active_rel, "active record")
    print(f"archive: {paths.root / destination_rel}")
    return 0


def cmd_archive(paths: Paths) -> int:
    with governance_lock(paths):
        return _cmd_archive_locked(paths)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bringup_loop.py", description="Bringup governance engine (schema v4)"
    )
    parser.add_argument(
        "--root",
        default=None,
        help="repository root (default: parent of scripts/)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="validate governance files and the active record")

    authorize_profile = sub.add_parser(
        "authorize-profile",
        help=(
            "interactive owner declaration for one persistent profile/target; "
            "never claims or executes"
        ),
    )
    authorize_profile.add_argument("--profile", required=True)
    authorize_profile.add_argument("--target", required=True)
    authorize_profile.add_argument("--note", required=True)

    new = sub.add_parser("new", help="scaffold the active experiment record")
    new.add_argument("--experiment-id", required=True)
    new.add_argument(
        "--operation",
        choices=sorted(OPERATIONS),
        default=None,
        help="omit for a read_only observation record",
    )
    new.add_argument("--target", default=None, help="partition target for partition_write")
    new.add_argument("--profile", default=None, help="repo-relative profile JSON")
    new.add_argument("--artifact", default=None, help="repo-relative artifact for ram_boot")
    new.add_argument("--hypothesis", required=True)
    new.add_argument("--discriminator", required=True)
    new.add_argument("--next-if-positive", required=True)
    new.add_argument("--next-if-negative", required=True)
    new.add_argument("--timebox-seconds", type=int, default=300)
    new.add_argument("--acknowledge-persistent-media", action="store_true")
    new.add_argument("--rebuild-reference", default=None)
    new.add_argument("--repeat-prior-experiment", default=None)
    new.add_argument("--repeat-changed-discriminator", default=None)
    new.add_argument("--repeat-evidence-report", default=None)

    sub.add_parser(
        "preflight",
        help="dry-run claim: verify every gate, change nothing",
    )
    sub.add_parser(
        "claim",
        help=(
            "issue-and-claim under the governance lock; a durable replay guard "
            "fails closed after any partial commit"
        ),
    )

    result = sub.add_parser("result", help="bind the outcome and evidence")
    result.add_argument("outcome", choices=OUTCOMES)
    result.add_argument("--evidence", required=True)
    result.add_argument("--note", default=None)

    observe = sub.add_parser("observe", help="append an observation sidecar entry")
    observe.add_argument("--note", required=True)

    sub.add_parser("archive", help="freeze the completed record into bringup-completed/")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    paths = Paths(root)
    try:
        if args.command == "validate":
            return cmd_validate(paths)
        if args.command == "authorize-profile":
            return cmd_authorize_profile(paths, args)
        if args.command == "new":
            return cmd_new(paths, args)
        if args.command == "preflight":
            return cmd_claim(paths, dry_run=True)
        if args.command == "claim":
            return cmd_claim(paths, dry_run=False)
        if args.command == "result":
            return cmd_result(paths, args)
        if args.command == "observe":
            return cmd_observe(paths, args.note)
        if args.command == "archive":
            return cmd_archive(paths)
        raise Refusal(f"unknown command: {args.command}")
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2
    except OSError as exc:
        print(f"refused: host filesystem operation failed: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
