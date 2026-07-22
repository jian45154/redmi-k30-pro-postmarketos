"""Root-owned, content-addressed input seals for the lmi P1 builder.

The manifest is deliberately independent of Git.  It inventories every physical
member consumed by the privileged build so that an activated policy binds the
exact project, pmbootstrap and pmaports trees as well as the two standalone
input files.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import sys
from typing import BinaryIO, Mapping

try:
    from .common import GateError
except ImportError:
    if __name__ != "__main__":
        raise

    class GateError(RuntimeError):
        """Standalone policy administrator failure."""


# V2 is accepted only as a pre-existing verifier/rollback format. New seals and
# ordinary activation targets must use V3.
LEGACY_SCHEMA = 2
SCHEMA = 3
READ_SCHEMAS = frozenset({LEGACY_SCHEMA, SCHEMA})
SEAL_POLICY_ABI_FINGERPRINT = (
    "96aea3fd68aeeba23cd9955cf5996cdc3e6ae14518e2dccdb4c902316696c729"
)
MANIFEST_NAME = "seal.manifest.json"
OFFLINE_CACHE_SCHEMA = "lmi-p1-offline-cache/v2"
OFFLINE_CACHE_MANIFEST_NAME = "offline-cache.manifest.json"
OFFLINE_WORK_VERSION = b"8\n"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
LAYOUT = {
    "authorized_key": "authorized_key.pub",
    "offline_cache": "offline-cache",
    "pmaports": "pmaports",
    "pmbootstrap": "pmbootstrap",
    "project": "project",
    "source_lock": "source-lock.json",
}
_DIRECTORY_INPUTS = frozenset(
    {"offline_cache", "project", "pmbootstrap", "pmaports"}
)
_POLICY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_BUILDER_SIGNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}$")
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_HASH_BLOCK_SIZE = 1024 * 1024
STREAM_MAGIC = b"LMI-P1-SEAL\x00V3\n"
_STREAM_LENGTH_BYTES = 8
_MAX_MEMBERS = 200_000
_MAX_PATH_BYTES = 1024
_MAX_DEPTH = 32
_MAX_SYMLINK_TARGET_BYTES = 1024
_MAX_SYMLINK_TARGET_DEPTH = 32
_MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_TOTAL_FILE_BYTES = 16 * 1024 * 1024 * 1024
_MAX_SOURCE_LOCK_BYTES = 1024 * 1024
_MAX_OFFLINE_CACHE_MANIFEST_BYTES = 16 * 1024 * 1024
_OFFLINE_WORK_DIRECTORIES = frozenset(
    {
        "work/cache_apk_aarch64",
        "work/cache_apk_x86_64",
        "work/cache_distfiles",
        "work/cache_http",
    }
)
_OFFLINE_ARCHITECTURES = frozenset({"aarch64", "x86_64"})
_PRODUCTION_REPOSITORY_URLS = frozenset(
    {
        "http://dl-cdn.alpinelinux.org/alpine/edge/community",
        "http://dl-cdn.alpinelinux.org/alpine/edge/main",
        "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
        "http://mirror.postmarketos.org/postmarketos/main",
    }
)
_EXPECTED_PMBOOTSTRAP_COMMIT = "ce76febabd983db6445fa9a8b75d601970b2f436"
_EXPECTED_PMBOOTSTRAP_VERSION = "3.11.1"
_EXPECTED_PMAPORTS_COMMIT = "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
_EXPECTED_PMAPORTS_TREE = "749f154b6f154f86133e7c7616074aa9eb876f2e"
POLICY_ADMIN_PATH = Path("/usr/local/sbin/lmi-p1-policy-admin")
PRODUCTION_ACTIVE_PATH = Path("/opt/lmi-p1/active-policy")
PRODUCTION_SEALS_ROOT = Path("/opt/lmi-p1/seals")
_EXPECTED_UNSET = object()
_SYMLINK_COMPONENTS = frozenset({"project", "pmbootstrap", "pmaports"})


@dataclass(frozen=True)
class SealSources:
    project: Path
    pmbootstrap: Path
    pmaports: Path
    authorized_key: Path
    source_lock: Path
    offline_cache: Path


@dataclass(frozen=True)
class GitProvenance:
    remote: str
    commit: str
    tree: str


@dataclass(frozen=True)
class PmbootstrapProvenance:
    remote: str
    commit: str
    tree: str
    version: str
    entrypoint_sha256: str


@dataclass(frozen=True)
class SealProvenance:
    generation: int
    project: GitProvenance
    pmbootstrap: PmbootstrapProvenance
    pmaports: GitProvenance


@dataclass(frozen=True)
class VerifiedSeal:
    root: Path
    policy_id: str
    project: Path
    pmbootstrap: Path
    pmaports: Path
    authorized_key: Path
    source_lock: Path
    offline_cache: Path
    manifest: Mapping[str, object]


def canonical_manifest_bytes(manifest: object) -> bytes:
    """Serialize a manifest using the one accepted policy-id representation."""

    try:
        rendered = json.dumps(
            manifest,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as error:
        raise GateError(f"manifest is not canonical JSON data: {error}") from None
    return (rendered + "\n").encode("ascii")


def policy_id_for_manifest(manifest: object) -> str:
    return hashlib.sha256(canonical_manifest_bytes(manifest)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise GateError(f"JSON contains duplicate key: {key!r}")
        value[key] = item
    return value


def _read_canonical_manifest(
    path: Path, expected: os.stat_result
) -> tuple[dict[str, object], bytes]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(_MAX_MANIFEST_BYTES + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not read seal manifest: {error}") from None
    if (
        _metadata_identity(expected) != _metadata_identity(opened)
        or _metadata_identity(finished) != _metadata_identity(opened)
        or _metadata_identity(after) != _metadata_identity(opened)
    ):
        raise GateError("seal manifest changed while reading")
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise GateError("seal manifest exceeds the size limit")
    try:
        text = payload.decode("ascii")
        parsed = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"seal manifest is not valid canonical JSON: {error}") from None
    if not isinstance(parsed, dict):
        raise GateError("seal manifest must be a JSON object")
    if canonical_manifest_bytes(parsed) != payload:
        raise GateError("seal manifest bytes are not canonical")
    return parsed, payload


def _safe_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise GateError("seal manifest contains an unsafe member path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise GateError("seal manifest member path contains a control character")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise GateError("seal manifest member path is not valid UTF-8") from None
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise GateError("seal manifest contains an unsafe member path")
    if relative.as_posix() != value:
        raise GateError("seal manifest member path is not normalized")
    return value


def _safe_symlink_target(relative: str, value: object) -> tuple[str, bytes, str]:
    """Validate and lexically resolve one repository-native symlink target."""

    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\0" in value
        or value.startswith("/")
    ):
        raise GateError(f"seal symlink target is unsafe: {relative}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise GateError(f"seal symlink target contains a control character: {relative}")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise GateError(f"seal symlink target is not valid UTF-8: {relative}") from None
    raw_parts = value.split("/")
    if (
        len(encoded) > _MAX_SYMLINK_TARGET_BYTES
        or len(raw_parts) > _MAX_SYMLINK_TARGET_DEPTH
        or any(part == "" for part in raw_parts)
    ):
        raise GateError(f"seal symlink target exceeds its limits: {relative}")

    member = PurePosixPath(relative)
    component = member.parts[0]
    if component not in _SYMLINK_COMPONENTS:
        raise GateError(f"seal symlink is outside a repository component: {relative}")
    resolved = list(member.parent.parts)
    for part in raw_parts:
        if part == ".":
            continue
        if part == "..":
            if len(resolved) <= 1:
                raise GateError(f"seal symlink target escapes its component: {relative}")
            resolved.pop()
        else:
            resolved.append(part)
        if len(resolved) > _MAX_DEPTH:
            raise GateError(f"seal symlink target resolves too deeply: {relative}")
    if not resolved or resolved[0] != component:
        raise GateError(f"seal symlink target escapes its component: {relative}")
    return value, encoded, PurePosixPath(*resolved).as_posix()


def _symlink_walk_paths(relative: str, target: str) -> list[str]:
    current = list(PurePosixPath(relative).parent.parts)
    walked: list[str] = []
    for part in target.split("/"):
        if part == "..":
            current.pop()
        elif part != ".":
            current.append(part)
        walked.append(PurePosixPath(*current).as_posix())
    return walked


def _validate_symlink_graph(members: list[dict[str, object]]) -> None:
    """Reject missing targets, link chains, and symlink-as-ancestor layouts."""

    by_path = {str(member["path"]): member for member in members}
    for member in members:
        relative = str(member["path"])
        parent = PurePosixPath(relative).parent.as_posix()
        if parent != ".":
            parent_member = by_path.get(parent)
            if parent_member is None or parent_member["type"] != "directory":
                raise GateError(
                    f"seal manifest member parent is absent or not a directory: {relative}"
                )
        if member["type"] != "symlink":
            continue
        target, _encoded, resolved = _safe_symlink_target(
            relative, member["target"]
        )
        for traversed in _symlink_walk_paths(relative, target)[:-1]:
            traversed_member = by_path.get(traversed)
            if traversed_member is None or traversed_member["type"] != "directory":
                raise GateError(
                    f"seal symlink traverses a missing or non-directory member: {relative}"
                )
        target_member = by_path.get(resolved)
        if target_member is None:
            raise GateError(f"seal symlink target is absent: {relative}")
        if target_member["type"] != "file":
            raise GateError(
                f"seal symlink target is not one regular file: {relative}"
            )


def _metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _xattrs(path: Path) -> list[str]:
    try:
        return list(os.listxattr(path, follow_symlinks=False))
    except (AttributeError, NotImplementedError):
        raise GateError("filesystem xattr inspection is unavailable") from None
    except OSError as error:
        raise GateError(f"could not inspect xattrs for {path}: {error}") from None


def _check_owner_and_mode(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
    symlink: bool = False,
) -> None:
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise GateError(f"seal member is not owned by the trusted account: {path}")
    if not symlink and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise GateError(f"seal member is group/world writable: {path}")
    if _xattrs(path):
        raise GateError(f"seal member has xattrs: {path}")


def _check_secure_ancestry(
    path: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if ".." in path.parts or ".." in trusted_root.parts:
        raise GateError("trusted ancestry path is not normalized")
    path = path.absolute()
    trusted_root = trusted_root.absolute()
    try:
        relative = path.relative_to(trusted_root)
    except ValueError:
        raise GateError(f"trusted path escapes its ancestry root: {path}") from None
    current = trusted_root
    candidates = [current]
    for part in relative.parts:
        current /= part
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise GateError(f"could not inspect trusted ancestry {candidate}: {error}") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise GateError(f"trusted ancestry is not a real directory: {candidate}")
        _check_owner_and_mode(
            candidate,
            metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )


def _hash_regular(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if _metadata_identity(opened) != _metadata_identity(expected):
                raise GateError(f"seal member changed while opening: {path}")
            for block in iter(lambda: stream.read(_HASH_BLOCK_SIZE), b""):
                digest.update(block)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not hash seal member {path}: {error}") from None
    if (
        _metadata_identity(finished) != _metadata_identity(opened)
        or _metadata_identity(after) != _metadata_identity(opened)
    ):
        raise GateError(f"seal member changed while hashing: {path}")
    return digest.hexdigest()


def _inventory_member(
    path: Path,
    relative: str,
    *,
    expected_uid: int,
    expected_gid: int,
    non_directory_inodes: dict[tuple[int, int], str],
) -> list[dict[str, object]]:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect seal member {path}: {error}") from None
    if stat.S_ISLNK(before.st_mode):
        if before.st_nlink != 1:
            raise GateError(f"seal contains a hardlinked symlink: {relative}")
        inode = (before.st_dev, before.st_ino)
        if inode in non_directory_inodes:
            raise GateError(
                "seal non-directory members share an inode: "
                f"{non_directory_inodes[inode]} and {relative}"
            )
        non_directory_inodes[inode] = relative
        _check_owner_and_mode(
            path,
            before,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            symlink=True,
        )
        try:
            first_target = os.readlink(path)
            second_target = os.readlink(path)
            after = path.lstat()
        except OSError as error:
            raise GateError(f"could not read seal symlink {path}: {error}") from None
        if (
            first_target != second_target
            or _metadata_identity(before) != _metadata_identity(after)
        ):
            raise GateError(f"seal symlink changed while reading: {path}")
        target, encoded, _resolved = _safe_symlink_target(relative, first_target)
        if before.st_size != len(encoded) or stat.S_IMODE(before.st_mode) != 0o777:
            raise GateError(f"seal symlink metadata is not canonical: {relative}")
        return [
            {
                "mode": 0o777,
                "path": relative,
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "size": len(encoded),
                "target": target,
                "type": "symlink",
            }
        ]
    _check_owner_and_mode(
        path,
        before,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    mode = stat.S_IMODE(before.st_mode)
    if stat.S_ISREG(before.st_mode):
        if before.st_nlink != 1:
            raise GateError(f"seal contains a hardlinked file: {relative}")
        inode = (before.st_dev, before.st_ino)
        if inode in non_directory_inodes:
            raise GateError(
                "seal non-directory members share an inode: "
                f"{non_directory_inodes[inode]} and {relative}"
            )
        non_directory_inodes[inode] = relative
        return [
            {
                "mode": mode,
                "path": relative,
                "sha256": _hash_regular(path, before),
                "size": before.st_size,
                "type": "file",
            }
        ]
    if not stat.S_ISDIR(before.st_mode):
        raise GateError(f"seal contains a special filesystem object: {relative}")

    record: dict[str, object] = {
        "mode": mode,
        "path": relative,
        "sha256": EMPTY_SHA256,
        "size": 0,
        "type": "directory",
    }
    try:
        children = sorted(os.scandir(path), key=lambda child: child.name)
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not enumerate seal directory {path}: {error}") from None
    records = [record]
    for child in children:
        child_name = child.name
        if not isinstance(child_name, str):
            raise GateError("seal member name is not text")
        child_relative = _safe_relative_path(f"{relative}/{child_name}")
        records.extend(
            _inventory_member(
                Path(child.path),
                child_relative,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                non_directory_inodes=non_directory_inodes,
            )
        )
    try:
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not re-inspect seal directory {path}: {error}") from None
    if _metadata_identity(before) != _metadata_identity(after):
        raise GateError(f"seal directory changed while enumerating: {path}")
    return records


def _inventory_layout(
    root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    non_directory_inodes: dict[tuple[int, int], str] = {}
    for label, relative in sorted(LAYOUT.items(), key=lambda item: item[1]):
        path = root / relative
        try:
            metadata = path.lstat()
        except OSError as error:
            raise GateError(f"seal is missing {label}: {error}") from None
        expected_directory = label in _DIRECTORY_INPUTS
        if expected_directory != stat.S_ISDIR(metadata.st_mode):
            expected_type = "directory" if expected_directory else "file"
            raise GateError(f"sealed {label} is not a {expected_type}")
        records.extend(
            _inventory_member(
                path,
                relative,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                non_directory_inodes=non_directory_inodes,
            )
        )
    records.sort(key=lambda record: str(record["path"]))
    _validate_symlink_graph(records)
    return records


def _validate_remote(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        )
    ):
        raise GateError(f"seal provenance {label} remote is invalid")
    return value


def _validate_git_provenance(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"commit", "remote", "tree"}:
        raise GateError(f"seal provenance {label} has an invalid shape")
    _validate_remote(value["remote"], label)
    for field in ("commit", "tree"):
        item = value[field]
        if not isinstance(item, str) or _GIT_OBJECT_RE.fullmatch(item) is None:
            raise GateError(f"seal provenance {label}.{field} is invalid")
    return dict(value)


def _validate_provenance(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "generation",
        "offline_cache",
        "pmaports",
        "pmbootstrap",
        "project",
    }:
        raise GateError("seal provenance has an invalid shape")
    generation = value["generation"]
    if type(generation) is not int or generation <= 0:
        raise GateError("seal provenance generation must be a positive integer")
    project = _validate_git_provenance(value["project"], "project")
    pmaports = _validate_git_provenance(value["pmaports"], "pmaports")
    offline_cache = value["offline_cache"]
    if not isinstance(offline_cache, dict) or set(offline_cache) != {
        "aggregate_sha256",
        "manifest_sha256",
        "schema",
    }:
        raise GateError("seal provenance offline_cache has an invalid shape")
    if offline_cache["schema"] != OFFLINE_CACHE_SCHEMA:
        raise GateError("seal provenance offline_cache schema is invalid")
    for field in ("aggregate_sha256", "manifest_sha256"):
        digest = offline_cache[field]
        if not isinstance(digest, str) or _POLICY_ID_RE.fullmatch(digest) is None:
            raise GateError(f"seal provenance offline_cache.{field} is invalid")
    pmbootstrap = value["pmbootstrap"]
    if not isinstance(pmbootstrap, dict) or set(pmbootstrap) != {
        "commit",
        "entrypoint_sha256",
        "remote",
        "tree",
        "version",
    }:
        raise GateError("seal provenance pmbootstrap has an invalid shape")
    _validate_remote(pmbootstrap["remote"], "pmbootstrap")
    for field in ("commit", "tree"):
        item = pmbootstrap[field]
        if not isinstance(item, str) or _GIT_OBJECT_RE.fullmatch(item) is None:
            raise GateError(f"seal provenance pmbootstrap.{field} is invalid")
    entrypoint_digest = pmbootstrap["entrypoint_sha256"]
    if (
        not isinstance(entrypoint_digest, str)
        or _POLICY_ID_RE.fullmatch(entrypoint_digest) is None
    ):
        raise GateError("seal provenance pmbootstrap.entrypoint_sha256 is invalid")
    version = pmbootstrap["version"]
    if not isinstance(version, str) or _VERSION_RE.fullmatch(version) is None:
        raise GateError("seal provenance pmbootstrap.version is invalid")
    return {
        "generation": generation,
        "offline_cache": dict(offline_cache),
        "pmaports": pmaports,
        "pmbootstrap": dict(pmbootstrap),
        "project": project,
    }


def _validate_manifest_shape(manifest: dict[str, object]) -> list[dict[str, object]]:
    if set(manifest) != {"inputs", "layout", "members", "provenance", "schema"}:
        raise GateError("seal manifest has unexpected or missing top-level fields")
    schema = manifest["schema"]
    if type(schema) is not int or schema not in READ_SCHEMAS:
        raise GateError("unsupported seal manifest schema")
    if manifest["layout"] != LAYOUT:
        raise GateError("seal manifest layout mismatch")
    _validate_provenance(manifest["provenance"])
    inputs = manifest["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "authorized_key_sha256",
        "source_lock_sha256",
    }:
        raise GateError("seal manifest inputs have an invalid shape")
    for label, digest in inputs.items():
        if not isinstance(digest, str) or _POLICY_ID_RE.fullmatch(digest) is None:
            raise GateError(f"seal manifest input digest is invalid: {label}")
    members = manifest["members"]
    if not isinstance(members, list) or not members or len(members) > _MAX_MEMBERS:
        raise GateError("seal manifest members must be a non-empty list")
    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    total_file_bytes = 0
    for item in members:
        if not isinstance(item, dict):
            raise GateError("seal manifest member has an invalid shape")
        member_type = item.get("type")
        expected_fields = {"mode", "path", "sha256", "size", "type"}
        if schema == SCHEMA and member_type == "symlink":
            expected_fields.add("target")
        if set(item) != expected_fields:
            raise GateError("seal manifest member has an invalid shape")
        relative = _safe_relative_path(item["path"])
        if len(relative.encode("utf-8")) > _MAX_PATH_BYTES:
            raise GateError(f"seal manifest member path is too long: {relative}")
        if len(PurePosixPath(relative).parts) > _MAX_DEPTH:
            raise GateError(f"seal manifest member path is too deep: {relative}")
        if relative in seen:
            raise GateError(f"seal manifest has duplicate member: {relative}")
        seen.add(relative)
        allowed_types = {"directory", "file"}
        if schema == SCHEMA:
            allowed_types.add("symlink")
        if not isinstance(member_type, str) or member_type not in allowed_types:
            raise GateError(f"seal manifest member has an invalid type: {relative}")
        mode = item["mode"]
        size = item["size"]
        digest = item["sha256"]
        if (
            type(mode) is not int
            or not 0 <= mode <= 0o777
            or (member_type != "symlink" and mode & 0o022)
        ):
            raise GateError(f"seal manifest member has an invalid mode: {relative}")
        if type(size) is not int or size < 0 or size > _MAX_FILE_BYTES:
            raise GateError(f"seal manifest member has an invalid size: {relative}")
        if (
            relative
            == f'{LAYOUT["offline_cache"]}/{OFFLINE_CACHE_MANIFEST_NAME}'
            and size > _MAX_OFFLINE_CACHE_MANIFEST_BYTES
        ):
            raise GateError("offline-cache manifest exceeds its size limit")
        if not isinstance(digest, str) or _POLICY_ID_RE.fullmatch(digest) is None:
            raise GateError(f"seal manifest member has an invalid digest: {relative}")
        if member_type == "directory" and (size != 0 or digest != EMPTY_SHA256):
            raise GateError(f"seal directory metadata is not canonical: {relative}")
        if member_type == "symlink":
            target, encoded, _resolved = _safe_symlink_target(
                relative, item["target"]
            )
            if (
                mode != 0o777
                or size != len(encoded)
                or digest != hashlib.sha256(encoded).hexdigest()
                or target != item["target"]
            ):
                raise GateError(f"seal symlink metadata is not canonical: {relative}")
        if member_type == "file":
            total_file_bytes += size
            if total_file_bytes > _MAX_TOTAL_FILE_BYTES:
                raise GateError("seal manifest total file size exceeds its limit")
        normalized.append(dict(item))
    paths = [str(member["path"]) for member in normalized]
    if paths != sorted(paths):
        raise GateError("seal manifest members are not path-sorted")
    _validate_symlink_graph(normalized)
    members_by_path = {str(member["path"]): member for member in normalized}
    for field, relative in {
        "authorized_key_sha256": LAYOUT["authorized_key"],
        "source_lock_sha256": LAYOUT["source_lock"],
    }.items():
        member = members_by_path.get(relative)
        if (
            member is None
            or member["type"] != "file"
            or inputs[field] != member["sha256"]
        ):
            raise GateError(f"seal manifest input digest does not match member: {field}")
    entrypoint = members_by_path.get("pmbootstrap/pmbootstrap.py")
    pmbootstrap = manifest["provenance"]["pmbootstrap"]
    if (
        entrypoint is None
        or entrypoint["type"] != "file"
        or pmbootstrap["entrypoint_sha256"] != entrypoint["sha256"]
    ):
        raise GateError(
            "seal provenance pmbootstrap.entrypoint_sha256 does not match its member"
        )
    return normalized


def _parse_source_lock(payload: bytes) -> dict[str, object]:
    if len(payload) > _MAX_SOURCE_LOCK_BYTES:
        raise GateError("source lock exceeds its size limit")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
        )
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"source lock is not valid JSON: {error}") from None
    if not isinstance(value, dict):
        raise GateError("source lock must be a JSON object")
    return value


def _validate_source_lock_binding(
    payload: bytes, provenance: Mapping[str, object]
) -> None:
    """Require the sealed lock to repeat every external-source provenance fact."""

    source_lock = _parse_source_lock(payload)
    if source_lock.get("schema") != "lmi-source-lock/v3":
        raise GateError("source lock schema must be lmi-source-lock/v3")
    for label, fields in {
        "pmbootstrap": ("remote", "commit", "tree", "version", "entrypoint_sha256"),
        "pmaports": ("remote", "commit", "tree"),
        "offline_cache": ("schema", "manifest_sha256", "aggregate_sha256"),
    }.items():
        locked = source_lock.get(label)
        sealed = provenance.get(label)
        if not isinstance(locked, dict) or not isinstance(sealed, dict):
            raise GateError(f"source lock is missing {label} provenance")
        for field in fields:
            if locked.get(field) != sealed.get(field):
                raise GateError(
                    f"source lock provenance mismatch: {label}.{field}"
                )


def _read_source_payload(path: Path, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect source file {path}: {error}") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise GateError(f"source is not one regular file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not read source file {path}: {error}") from None
    if len(payload) > maximum:
        raise GateError(f"source file exceeds its size limit: {path}")
    if not (
        _metadata_identity(before)
        == _metadata_identity(opened)
        == _metadata_identity(finished)
        == _metadata_identity(after)
    ):
        raise GateError(f"source file changed while reading: {path}")
    return payload


def offline_cache_aggregate_preimage(manifest: Mapping[str, object]) -> bytes:
    """Return the v1 aggregate preimage.

    The rule deliberately avoids a self-hash: copy the complete offline-cache
    manifest, remove only its top-level ``aggregate_sha256`` field, then encode
    the remaining object as sorted, compact, ASCII JSON followed by one LF.
    """

    if not isinstance(manifest, Mapping) or "aggregate_sha256" not in manifest:
        raise GateError("offline-cache aggregate preimage is missing its digest")
    value = dict(manifest)
    del value["aggregate_sha256"]
    return canonical_manifest_bytes(value)


def _offline_member_path(value: object, prefix: str | None = None) -> str:
    relative = _safe_relative_path(value)
    if relative == OFFLINE_CACHE_MANIFEST_NAME or not relative.startswith("work/"):
        raise GateError("offline-cache member path must be below work/")
    if prefix is not None and not relative.startswith(prefix + "/"):
        raise GateError(f"offline-cache member is outside {prefix}/: {relative}")
    return relative


def _sorted_unique_records(
    value: object,
    label: str,
    fields: frozenset[str],
    key_fields: tuple[str, ...],
) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise GateError(f"offline-cache {label} must be a list")
    result: list[dict[str, object]] = []
    keys: list[tuple[str, ...]] = []
    for item in value:
        if not isinstance(item, dict) or set(item) != fields:
            raise GateError(f"offline-cache {label} record has an invalid shape")
        record = dict(item)
        key = tuple(record[field] for field in key_fields)
        if not all(isinstance(part, str) for part in key):
            raise GateError(f"offline-cache {label} record has an invalid sort key")
        result.append(record)
        keys.append(key)
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        raise GateError(f"offline-cache {label} records are not sorted and unique")
    return result


def _validate_offline_cache_manifest(
    manifest: object,
    actual_members: Mapping[str, Mapping[str, object]],
    *,
    repository_urls: frozenset[str] = _PRODUCTION_REPOSITORY_URLS,
    expected_pmbootstrap_commit: str = _EXPECTED_PMBOOTSTRAP_COMMIT,
    expected_pmbootstrap_version: str = _EXPECTED_PMBOOTSTRAP_VERSION,
    expected_pmaports_commit: str = _EXPECTED_PMAPORTS_COMMIT,
    expected_pmaports_tree: str = _EXPECTED_PMAPORTS_TREE,
) -> dict[str, object]:
    """Validate the strict immutable v2 cache contract.

    Override parameters exist solely for explicit non-production fixtures.
    Production callers use the defaults and expose no override surface.
    """

    expected_top = {
        "aggregate_sha256",
        "distfiles",
        "external_apks",
        "http_artifacts",
        "members",
        "pins",
        "repositories",
        "schema",
    }
    if not isinstance(manifest, dict) or set(manifest) != expected_top:
        raise GateError("offline-cache manifest has an invalid top-level shape")
    if manifest["schema"] != OFFLINE_CACHE_SCHEMA:
        raise GateError("offline-cache manifest schema mismatch")
    aggregate = manifest["aggregate_sha256"]
    if not isinstance(aggregate, str) or _POLICY_ID_RE.fullmatch(aggregate) is None:
        raise GateError("offline-cache aggregate digest is invalid")
    if hashlib.sha256(offline_cache_aggregate_preimage(manifest)).hexdigest() != aggregate:
        raise GateError("offline-cache aggregate digest mismatch")

    pins = manifest["pins"]
    if not isinstance(pins, dict) or set(pins) != {"pmbootstrap", "pmaports"}:
        raise GateError("offline-cache pins have an invalid shape")
    pmbootstrap = pins["pmbootstrap"]
    pmaports = pins["pmaports"]
    if not isinstance(pmbootstrap, dict) or set(pmbootstrap) != {
        "commit",
        "version",
        "work_version",
    }:
        raise GateError("offline-cache pmbootstrap pin has an invalid shape")
    if pmbootstrap != {
        "commit": expected_pmbootstrap_commit,
        "version": expected_pmbootstrap_version,
        "work_version": 8,
    }:
        raise GateError("offline-cache pmbootstrap pin mismatch")
    if not isinstance(pmaports, dict) or set(pmaports) != {
        "channel",
        "commit",
        "tree",
    }:
        raise GateError("offline-cache pmaports pin has an invalid shape")
    if pmaports != {
        "channel": "edge",
        "commit": expected_pmaports_commit,
        "tree": expected_pmaports_tree,
    }:
        raise GateError("offline-cache pmaports pin mismatch")

    members = _sorted_unique_records(
        manifest["members"],
        "members",
        frozenset({"path", "sha256", "size"}),
        ("path",),
    )
    normalized_members: dict[str, dict[str, object]] = {}
    for member in members:
        relative = _offline_member_path(member["path"])
        size = member["size"]
        digest = member["sha256"]
        if (
            type(size) is not int
            or size < 0
            or size > _MAX_FILE_BYTES
            or not isinstance(digest, str)
            or _POLICY_ID_RE.fullmatch(digest) is None
        ):
            raise GateError(f"offline-cache member metadata is invalid: {relative}")
        if relative in normalized_members:
            raise GateError(f"offline-cache contains a duplicate member: {relative}")
        normalized_members[relative] = member
    if [str(item["path"]) for item in members] != sorted(normalized_members):
        raise GateError("offline-cache members are not path-sorted")
    if set(normalized_members) != set(actual_members):
        raise GateError("offline-cache work inventory does not match its manifest")
    for relative, member in normalized_members.items():
        actual = actual_members[relative]
        if member["size"] != actual["size"] or member["sha256"] != actual["sha256"]:
            raise GateError(f"offline-cache member digest mismatch: {relative}")
    version = normalized_members.get("work/version")
    if version is None or version["size"] != len(OFFLINE_WORK_VERSION) or version[
        "sha256"
    ] != hashlib.sha256(OFFLINE_WORK_VERSION).hexdigest():
        raise GateError("offline-cache work/version binding mismatch")

    repositories = _sorted_unique_records(
        manifest["repositories"],
        "repositories",
        frozenset(
            {
                "architecture",
                "index_path",
                "index_sha256",
                "index_size",
                "signer_key_path",
                "signer_key_sha256",
                "url",
            }
        ),
        ("architecture", "url"),
    )
    expected_pairs = {
        (url, architecture)
        for url in repository_urls
        for architecture in _OFFLINE_ARCHITECTURES
    }
    pairs: set[tuple[str, str]] = set()
    repository_bindings: dict[tuple[str, str], dict[str, object]] = {}
    repository_signers: dict[str, str] = {}
    classifications: dict[str, int] = {}
    signer_paths: set[str] = set()

    def member_binding(
        record: Mapping[str, object],
        path_field: str,
        size_field: str | None,
        digest_field: str,
        prefix: str | None = None,
        *,
        classify: bool,
    ) -> str:
        relative = _offline_member_path(record[path_field], prefix)
        member = normalized_members.get(relative)
        if member is None:
            raise GateError(f"offline-cache binding references a missing member: {relative}")
        if size_field is not None and record[size_field] != member["size"]:
            raise GateError(f"offline-cache size binding mismatch: {relative}")
        if record[digest_field] != member["sha256"]:
            raise GateError(f"offline-cache digest binding mismatch: {relative}")
        if classify:
            classifications[relative] = classifications.get(relative, 0) + 1
        return relative

    for record in repositories:
        architecture = record["architecture"]
        url = record["url"]
        if architecture not in _OFFLINE_ARCHITECTURES:
            raise GateError("offline-cache repository architecture is invalid")
        _validate_remote(url, "offline-cache repository")
        pair = (str(url), str(architecture))
        if pair in pairs:
            raise GateError("offline-cache contains a duplicate repository binding")
        pairs.add(pair)
        prefix = f"work/cache_apk_{architecture}"
        expected_index = (
            f"{prefix}/APKINDEX."
            f"{hashlib.sha1(str(url).encode('utf-8'), usedforsecurity=False).hexdigest()[:8]}"
            ".tar.gz"
        )
        if record["index_path"] != expected_index:
            raise GateError(
                "offline-cache repository index path does not match its URL"
            )
        member_binding(
            record,
            "index_path",
            "index_size",
            "index_sha256",
            prefix,
            classify=True,
        )
        signer_path = member_binding(
            record,
            "signer_key_path",
            None,
            "signer_key_sha256",
            prefix,
            classify=False,
        )
        signer_parts = PurePosixPath(signer_path).parts
        if (
            len(signer_parts) != 3
            or signer_parts[1] != f"cache_apk_{architecture}"
            or not signer_parts[2].endswith(".rsa.pub")
        ):
            raise GateError("offline-cache repository signer path is invalid")
        signer_paths.add(signer_path)
        previous_signer = repository_signers.setdefault(
            signer_path, str(record["signer_key_sha256"])
        )
        if previous_signer != record["signer_key_sha256"]:
            raise GateError("offline-cache repository signer path has conflicting bytes")
        repository_bindings[pair] = record
    if pairs != expected_pairs:
        raise GateError("offline-cache repository URL/architecture set mismatch")

    external_apks = _sorted_unique_records(
        manifest["external_apks"],
        "external_apks",
        frozenset(
            {
                "architecture",
                "apkindex_checksum",
                "builder_signer",
                "index_sha256",
                "index_signer_key_path",
                "index_signer_key_sha256",
                "name",
                "path",
                "repository_url",
                "sha256",
                "size",
                "version",
            }
        ),
        ("architecture", "name", "version", "path"),
    )
    for record in external_apks:
        architecture = record["architecture"]
        if architecture not in _OFFLINE_ARCHITECTURES:
            raise GateError("offline-cache external APK architecture is invalid")
        for field in ("name", "version"):
            value = record[field]
            if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
                raise GateError(f"offline-cache external APK {field} is invalid")
        builder_signer = record["builder_signer"]
        if (
            not isinstance(builder_signer, str)
            or _BUILDER_SIGNER_RE.fullmatch(builder_signer) is None
        ):
            raise GateError("offline-cache external APK builder provenance is invalid")
        checksum = record["apkindex_checksum"]
        try:
            checksum_bytes = base64.b64decode(str(checksum)[2:], validate=True)
        except (ValueError, base64.binascii.Error):
            checksum_bytes = b""
        if (
            not isinstance(checksum, str)
            or not checksum.startswith("Q1")
            or len(checksum_bytes) != hashlib.sha1().digest_size
            or checksum != "Q1" + base64.b64encode(checksum_bytes).decode("ascii")
        ):
            raise GateError("offline-cache external APK index checksum is invalid")
        _validate_remote(record["repository_url"], "offline-cache external APK")
        repository = repository_bindings.get(
            (str(record["repository_url"]), str(architecture))
        )
        if repository is None:
            raise GateError("offline-cache external APK repository binding is absent")
        if (
            record["index_sha256"] != repository["index_sha256"]
            or record["index_signer_key_path"] != repository["signer_key_path"]
            or record["index_signer_key_sha256"] != repository["signer_key_sha256"]
        ):
            raise GateError("offline-cache external APK index trust binding mismatch")
        apk_path = member_binding(
            record,
            "path",
            "size",
            "sha256",
            f"work/cache_apk_{architecture}",
            classify=True,
        )
        apk_parts = PurePosixPath(apk_path).parts
        if (
            len(apk_parts) != 3
            or apk_parts[1] != f"cache_apk_{architecture}"
            or not apk_parts[2].endswith(".apk")
        ):
            raise GateError("offline-cache external APK path is not a flat APK cache path")

    http_artifacts = _sorted_unique_records(
        manifest["http_artifacts"],
        "http_artifacts",
        frozenset(
            {
                "kind",
                "name",
                "path",
                "sha256",
                "signer_key_path",
                "signer_key_sha256",
                "size",
                "url",
                "version",
            }
        ),
        ("kind", "name", "version", "url", "path"),
    )
    if len(http_artifacts) != 1:
        raise GateError(
            "offline-cache manifest must contain exactly one apk-tools-static artifact"
        )
    for record in http_artifacts:
        for field in ("kind", "name", "version"):
            value = record[field]
            if not isinstance(value, str) or _VERSION_RE.fullmatch(value) is None:
                raise GateError(f"offline-cache HTTP artifact {field} is invalid")
        if record["kind"] != "apk-tools-static" or record["name"] != "apk-tools-static":
            raise GateError("offline-cache HTTP artifact is not apk-tools-static")
        _validate_remote(record["url"], "offline-cache HTTP artifact")
        http_path = member_binding(
            record,
            "path",
            "size",
            "sha256",
            "work/cache_http",
            classify=True,
        )
        http_parts = PurePosixPath(http_path).parts
        if (
            len(http_parts) != 3
            or http_parts[1] != "cache_http"
            or http_parts[2].startswith("APKINDEX_")
        ):
            raise GateError("offline-cache HTTP artifact path is invalid")
        http_signer = member_binding(
            record,
            "signer_key_path",
            None,
            "signer_key_sha256",
            classify=False,
        )
        if repository_signers.get(http_signer) != record["signer_key_sha256"]:
            raise GateError(
                "offline-cache HTTP signer is not an existing repository signer"
            )
        signer_paths.add(http_signer)

    distfiles = _sorted_unique_records(
        manifest["distfiles"],
        "distfiles",
        frozenset({"apkbuild_sha512", "path", "sha256", "size", "url"}),
        ("url", "path"),
    )
    if len(distfiles) != 1:
        raise GateError("offline-cache manifest must contain exactly one kernel distfile")
    for record in distfiles:
        _validate_remote(record["url"], "offline-cache distfile")
        apkbuild_digest = record["apkbuild_sha512"]
        if (
            not isinstance(apkbuild_digest, str)
            or re.fullmatch(r"[0-9a-f]{128}", apkbuild_digest) is None
        ):
            raise GateError("offline-cache distfile APKBUILD SHA512 is invalid")
        distfile_path = member_binding(
            record,
            "path",
            "size",
            "sha256",
            "work/cache_distfiles",
            classify=True,
        )
        distfile_parts = PurePosixPath(distfile_path).parts
        if len(distfile_parts) != 3 or distfile_parts[1] != "cache_distfiles":
            raise GateError("offline-cache distfile path is not flat")

    expected_classified = set(normalized_members) - {"work/version"}
    if set(classifications) & signer_paths:
        raise GateError("offline-cache member has conflicting classifications")
    if set(classifications) | signer_paths != expected_classified or any(
        count != 1 for count in classifications.values()
    ):
        raise GateError("offline-cache members are not classified exactly once")
    return dict(manifest)


def _validate_offline_signer_trust(
    manifest: Mapping[str, object],
    outer_members: list[dict[str, object]],
) -> None:
    """Bind every cache-local signer copy to the pinned pmbootstrap key tree."""

    by_path = {str(member["path"]): member for member in outer_members}
    signer_paths = {
        str(record["signer_key_path"])
        for collection in ("repositories", "http_artifacts")
        for record in manifest[collection]  # type: ignore[index,union-attr]
    }
    by_basename: dict[str, tuple[object, object]] = {}
    for signer_path in sorted(signer_paths):
        basename = PurePosixPath(signer_path).name
        if (
            not basename.endswith(".rsa.pub")
            or len(basename.encode("utf-8")) > 255
        ):
            raise GateError("offline-cache signer key has an invalid basename")
        cache_member = by_path.get(f"{LAYOUT['offline_cache']}/{signer_path}")
        trust_member = by_path.get(f"{LAYOUT['pmbootstrap']}/pmb/data/keys/{basename}")
        if (
            cache_member is None
            or trust_member is None
            or cache_member.get("type") != "file"
            or trust_member.get("type") != "file"
        ):
            raise GateError(
                "offline-cache signer key is absent from the pinned pmbootstrap trust root"
            )
        fingerprint = (cache_member.get("size"), cache_member.get("sha256"))
        if fingerprint != (trust_member.get("size"), trust_member.get("sha256")):
            raise GateError(
                "offline-cache signer key differs from the pinned pmbootstrap trust root"
            )
        previous = by_basename.setdefault(basename, fingerprint)
        if previous != fingerprint:
            raise GateError("offline-cache signer basename has conflicting key material")


def verify_offline_cache(
    cache_root: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[dict[str, object], bytes]:
    """Verify the fixed cache tree and return its canonical manifest and bytes."""

    cache_root = Path(cache_root).absolute()
    try:
        root_metadata = cache_root.lstat()
    except OSError as error:
        raise GateError(f"could not inspect offline-cache root: {error}") from None
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise GateError("offline-cache root is not one real directory")
    _check_owner_and_mode(
        cache_root,
        root_metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        top = {entry.name for entry in os.scandir(cache_root)}
    except OSError as error:
        raise GateError(f"could not enumerate offline-cache root: {error}") from None
    if top != {OFFLINE_CACHE_MANIFEST_NAME, "work"}:
        raise GateError("offline-cache has missing or extra top-level members")
    work = cache_root / "work"
    work_metadata = work.lstat()
    if not stat.S_ISDIR(work_metadata.st_mode) or stat.S_ISLNK(work_metadata.st_mode):
        raise GateError("offline-cache work is not one real directory")
    _check_owner_and_mode(
        work,
        work_metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    expected_work_children = {"version"} | {
        PurePosixPath(path).name for path in _OFFLINE_WORK_DIRECTORIES
    }
    if {entry.name for entry in os.scandir(work)} != expected_work_children:
        raise GateError("offline-cache work has missing or extra members")

    actual_members: dict[str, dict[str, object]] = {}
    regular_inodes: dict[tuple[int, int], str] = {}
    version_path = work / "version"
    files = [(version_path, "work/version")]
    for directory_relative in sorted(_OFFLINE_WORK_DIRECTORIES):
        directory = cache_root / directory_relative
        metadata = directory.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise GateError(f"offline-cache member is not a directory: {directory_relative}")
        _check_owner_and_mode(
            directory,
            metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        try:
            children = sorted(os.scandir(directory), key=lambda child: child.name)
        except (OSError, UnicodeError) as error:
            raise GateError(f"could not enumerate offline-cache directory: {error}") from None
        for child in children:
            relative = _safe_relative_path(f"{directory_relative}/{child.name}")
            files.append((Path(child.path), relative))
    for path, relative in files:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise GateError(f"offline-cache is missing {relative}: {error}") from None
        if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise GateError(f"offline-cache contains a directory or special member: {relative}")
        if metadata.st_nlink != 1:
            raise GateError(f"offline-cache contains a hardlinked member: {relative}")
        _check_owner_and_mode(
            path,
            metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        inode = (metadata.st_dev, metadata.st_ino)
        if inode in regular_inodes:
            raise GateError(
                f"offline-cache members share an inode: {regular_inodes[inode]} and {relative}"
            )
        regular_inodes[inode] = relative
        digest = _hash_regular(path, metadata)
        actual_members[relative] = {
            "path": relative,
            "sha256": digest,
            "size": metadata.st_size,
        }
    if _read_source_payload(version_path, len(OFFLINE_WORK_VERSION)) != OFFLINE_WORK_VERSION:
        raise GateError("offline-cache work/version must contain exact bytes b'8\\n'")

    manifest_path = cache_root / OFFLINE_CACHE_MANIFEST_NAME
    manifest_metadata = manifest_path.lstat()
    if not stat.S_ISREG(manifest_metadata.st_mode) or manifest_metadata.st_nlink != 1:
        raise GateError("offline-cache manifest is not one regular file")
    _check_owner_and_mode(
        manifest_path,
        manifest_metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    payload = _read_source_payload(
        manifest_path, _MAX_OFFLINE_CACHE_MANIFEST_BYTES
    )
    try:
        manifest = json.loads(
            payload.decode("ascii"), object_pairs_hook=_reject_duplicate_keys
        )
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"offline-cache manifest is invalid JSON: {error}") from None
    if canonical_manifest_bytes(manifest) != payload:
        raise GateError("offline-cache manifest bytes are not canonical")
    validated = _validate_offline_cache_manifest(manifest, actual_members)
    return validated, payload


def _provenance_value(
    provenance: SealProvenance,
    offline_cache: Mapping[str, object],
) -> dict[str, object]:
    if not isinstance(provenance, SealProvenance):
        raise GateError("seal provenance must be a SealProvenance value")
    value: dict[str, object] = {
        "generation": provenance.generation,
        "offline_cache": dict(offline_cache),
        "pmaports": {
            "commit": provenance.pmaports.commit,
            "remote": provenance.pmaports.remote,
            "tree": provenance.pmaports.tree,
        },
        "pmbootstrap": {
            "commit": provenance.pmbootstrap.commit,
            "entrypoint_sha256": provenance.pmbootstrap.entrypoint_sha256,
            "remote": provenance.pmbootstrap.remote,
            "tree": provenance.pmbootstrap.tree,
            "version": provenance.pmbootstrap.version,
        },
        "project": {
            "commit": provenance.project.commit,
            "remote": provenance.project.remote,
            "tree": provenance.project.tree,
        },
    }
    return _validate_provenance(value)


def verify_seal(
    seal_root: Path,
    policy_id: str | None = None,
    *,
    trusted_root: Path | None = None,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> VerifiedSeal:
    """Verify one exact V2/V3 seal against its canonical id, failing closed."""

    seal_root = Path(seal_root).absolute()
    if trusted_root is None:
        trusted_root = Path("/")
    _check_secure_ancestry(
        seal_root,
        trusted_root=Path(trusted_root),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    root_metadata = seal_root.lstat()
    if stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise GateError("seal root must have mode 0700")

    manifest_path = seal_root / MANIFEST_NAME
    try:
        manifest_metadata = manifest_path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect seal manifest: {error}") from None
    if not stat.S_ISREG(manifest_metadata.st_mode) or manifest_metadata.st_nlink != 1:
        raise GateError("seal manifest must be one real, unlinked regular file")
    _check_owner_and_mode(
        manifest_path,
        manifest_metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(manifest_metadata.st_mode) != 0o600:
        raise GateError("seal manifest must have mode 0600")
    manifest, payload = _read_canonical_manifest(manifest_path, manifest_metadata)
    members = _validate_manifest_shape(manifest)
    actual_policy_id = hashlib.sha256(payload).hexdigest()
    if policy_id is not None:
        if not isinstance(policy_id, str) or _POLICY_ID_RE.fullmatch(policy_id) is None:
            raise GateError("requested seal policy id is invalid")
        if policy_id != actual_policy_id:
            raise GateError("seal policy id does not match its exact manifest bytes")
    if seal_root.name != actual_policy_id:
        raise GateError("seal directory name does not match its policy id")

    expected_top_level = {MANIFEST_NAME, *LAYOUT.values()}
    try:
        actual_top_level = {entry.name for entry in os.scandir(seal_root)}
    except OSError as error:
        raise GateError(f"could not enumerate seal root: {error}") from None
    if actual_top_level != expected_top_level:
        missing = sorted(expected_top_level - actual_top_level)
        extra = sorted(actual_top_level - expected_top_level)
        raise GateError(f"seal top-level mismatch: missing={missing!r}, extra={extra!r}")
    actual_members = _inventory_layout(
        seal_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if actual_members != members:
        expected_by_path = {str(item["path"]): item for item in members}
        actual_by_path = {str(item["path"]): item for item in actual_members}
        missing = sorted(expected_by_path.keys() - actual_by_path.keys())
        extra = sorted(actual_by_path.keys() - expected_by_path.keys())
        changed = sorted(
            path
            for path in expected_by_path.keys() & actual_by_path.keys()
            if expected_by_path[path] != actual_by_path[path]
        )
        raise GateError(
            "seal inventory mismatch: "
            f"missing={missing!r}, extra={extra!r}, changed={changed!r}"
        )
    offline_cache_manifest, offline_cache_payload = verify_offline_cache(
        seal_root / LAYOUT["offline_cache"],
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    expected_offline_provenance = {
        "aggregate_sha256": offline_cache_manifest["aggregate_sha256"],
        "manifest_sha256": hashlib.sha256(offline_cache_payload).hexdigest(),
        "schema": OFFLINE_CACHE_SCHEMA,
    }
    if manifest["provenance"]["offline_cache"] != expected_offline_provenance:
        raise GateError("seal provenance offline_cache binding mismatch")
    _validate_offline_signer_trust(offline_cache_manifest, members)
    source_lock_payload = _read_source_payload(
        seal_root / LAYOUT["source_lock"], _MAX_SOURCE_LOCK_BYTES
    )
    _validate_source_lock_binding(source_lock_payload, manifest["provenance"])
    return VerifiedSeal(
        root=seal_root,
        policy_id=actual_policy_id,
        project=seal_root / LAYOUT["project"],
        pmbootstrap=seal_root / LAYOUT["pmbootstrap"],
        pmaports=seal_root / LAYOUT["pmaports"],
        authorized_key=seal_root / LAYOUT["authorized_key"],
        source_lock=seal_root / LAYOUT["source_lock"],
        offline_cache=seal_root / LAYOUT["offline_cache"],
        manifest=manifest,
    )


def _source_records(
    sources: SealSources,
    *,
    expected_uid: int,
    expected_gid: int,
) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    non_directory_inodes: dict[tuple[int, int], str] = {}
    for label, relative in sorted(LAYOUT.items(), key=lambda item: item[1]):
        source = Path(getattr(sources, label)).absolute()
        try:
            metadata = source.lstat()
        except OSError as error:
            raise GateError(f"could not inspect source {label}: {error}") from None
        expected_directory = label in _DIRECTORY_INPUTS
        if expected_directory != stat.S_ISDIR(metadata.st_mode):
            expected_type = "directory" if expected_directory else "file"
            raise GateError(f"source {label} is not a {expected_type}")
        records.extend(
            _inventory_member(
                source,
                relative,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                non_directory_inodes=non_directory_inodes,
            )
        )
    records.sort(key=lambda record: str(record["path"]))
    _validate_symlink_graph(records)
    return records


def _manifest_for_sources(
    sources: SealSources,
    provenance: SealProvenance,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[dict[str, object], bytes, list[dict[str, object]]]:
    offline_cache_manifest, offline_cache_payload = verify_offline_cache(
        Path(sources.offline_cache).absolute(),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    records = _source_records(
        sources,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    records_by_path = {str(record["path"]): record for record in records}
    _validate_offline_signer_trust(offline_cache_manifest, records)
    provenance_value = _provenance_value(
        provenance,
        {
            "aggregate_sha256": offline_cache_manifest["aggregate_sha256"],
            "manifest_sha256": hashlib.sha256(offline_cache_payload).hexdigest(),
            "schema": OFFLINE_CACHE_SCHEMA,
        },
    )
    source_lock_payload = _read_source_payload(
        Path(sources.source_lock).absolute(), _MAX_SOURCE_LOCK_BYTES
    )
    _validate_source_lock_binding(source_lock_payload, provenance_value)
    manifest: dict[str, object] = {
        "inputs": {
            "authorized_key_sha256": records_by_path[LAYOUT["authorized_key"]][
                "sha256"
            ],
            "source_lock_sha256": records_by_path[LAYOUT["source_lock"]]["sha256"],
        },
        "layout": dict(LAYOUT),
        "members": records,
        "provenance": provenance_value,
        "schema": SCHEMA,
    }
    payload = canonical_manifest_bytes(manifest)
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise GateError("seal manifest exceeds the size limit")
    _validate_manifest_shape(manifest)
    return manifest, payload, records


def _source_for_member(sources: SealSources, relative: str) -> Path:
    member = PurePosixPath(relative)
    top = member.parts[0]
    labels = {path: label for label, path in LAYOUT.items()}
    label = labels.get(top)
    if label is None:
        raise GateError(f"seal member is outside the fixed layout: {relative}")
    source = Path(getattr(sources, label)).absolute()
    for part in member.parts[1:]:
        source /= part
    return source


def _write_all(stream: BinaryIO, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = stream.write(view)
        except OSError as error:
            raise GateError(f"could not write seal stream: {error}") from None
        if not isinstance(written, int) or written <= 0:
            raise GateError("seal stream writer made no progress")
        view = view[written:]


def _write_stable_member(
    stream: BinaryIO,
    source: Path,
    record: Mapping[str, object],
) -> None:
    try:
        before = source.lstat()
    except OSError as error:
        raise GateError(f"could not inspect seal source {source}: {error}") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != record["mode"]
        or before.st_size != record["size"]
    ):
        raise GateError(f"seal source metadata changed before packing: {source}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    remaining = int(record["size"])
    try:
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as input_stream:
            opened = os.fstat(input_stream.fileno())
            if _metadata_identity(opened) != _metadata_identity(before):
                raise GateError(f"seal source changed while opening: {source}")
            while remaining:
                block = input_stream.read(min(_HASH_BLOCK_SIZE, remaining))
                if not block:
                    raise GateError(f"seal source was truncated while packing: {source}")
                remaining -= len(block)
                digest.update(block)
                _write_all(stream, block)
            if input_stream.read(1):
                raise GateError(f"seal source grew while packing: {source}")
            finished = os.fstat(input_stream.fileno())
        after = source.lstat()
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not pack seal source {source}: {error}") from None
    if not (
        _metadata_identity(before)
        == _metadata_identity(opened)
        == _metadata_identity(finished)
        == _metadata_identity(after)
    ):
        raise GateError(f"seal source changed while packing: {source}")
    if digest.hexdigest() != record["sha256"]:
        raise GateError(f"seal source digest changed while packing: {source}")


def _verify_stable_symlink(
    source: Path,
    record: Mapping[str, object],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    try:
        before = source.lstat()
        first_target = os.readlink(source)
        second_target = os.readlink(source)
        after = source.lstat()
    except OSError as error:
        raise GateError(f"could not inspect seal source symlink {source}: {error}") from None
    _check_owner_and_mode(
        source,
        before,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        symlink=True,
    )
    try:
        encoded = first_target.encode("utf-8", errors="strict")
    except UnicodeError:
        raise GateError(f"seal source symlink is not valid UTF-8: {source}") from None
    if (
        not stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o777
        or _metadata_identity(before) != _metadata_identity(after)
        or first_target != second_target
        or first_target != record["target"]
        or len(encoded) != record["size"]
        or hashlib.sha256(encoded).hexdigest() != record["sha256"]
    ):
        raise GateError(f"seal source symlink changed while packing: {source}")


def pack_seal_stream(
    stream: BinaryIO,
    sources: SealSources,
    provenance: SealProvenance,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> str:
    """Write the deterministic, bounded installer stream and return its policy id.

    This is the only supported user-workspace to root-boundary transition.  The
    caller should write to a new regular file and atomically publish that file;
    a rejected or changing source can leave a deliberately unusable partial
    output stream.
    """

    if expected_uid is None:
        expected_uid = os.getuid()
    if expected_gid is None:
        expected_gid = os.getgid()
    _manifest, payload, records = _manifest_for_sources(
        sources,
        provenance,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    _write_all(stream, STREAM_MAGIC)
    _write_all(stream, len(payload).to_bytes(_STREAM_LENGTH_BYTES, "big"))
    _write_all(stream, payload)
    for record in records:
        if record["type"] == "file":
            _write_stable_member(
                stream,
                _source_for_member(sources, str(record["path"])),
                record,
            )
        elif record["type"] == "symlink":
            _verify_stable_symlink(
                _source_for_member(sources, str(record["path"])),
                record,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
    try:
        flush = getattr(stream, "flush", None)
        if flush is not None:
            flush()
    except OSError as error:
        raise GateError(f"could not flush seal stream: {error}") from None
    return hashlib.sha256(payload).hexdigest()


def _set_owner(path: Path, expected_uid: int, expected_gid: int) -> None:
    try:
        os.chown(path, expected_uid, expected_gid, follow_symlinks=False)
    except OSError as error:
        raise GateError(f"could not set trusted ownership on {path}: {error}") from None


def _copy_regular(
    source: Path,
    destination: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        source_fd = os.open(source, read_flags)
        try:
            destination_fd = os.open(destination, write_flags, 0o600)
        except Exception:
            os.close(source_fd)
            raise
        with os.fdopen(source_fd, "rb") as input_stream, os.fdopen(
            destination_fd, "wb"
        ) as output_stream:
            opened = os.fstat(input_stream.fileno())
            if _metadata_identity(opened) != _metadata_identity(metadata):
                raise GateError(f"seal source changed while opening: {source}")
            for block in iter(lambda: input_stream.read(_HASH_BLOCK_SIZE), b""):
                output_stream.write(block)
            output_stream.flush()
            os.fsync(output_stream.fileno())
            finished = os.fstat(input_stream.fileno())
        after = source.lstat()
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not copy seal member {source}: {error}") from None
    if (
        _metadata_identity(finished) != _metadata_identity(opened)
        or _metadata_identity(after) != _metadata_identity(opened)
    ):
        raise GateError(f"seal source changed while copying: {source}")
    destination.chmod(stat.S_IMODE(metadata.st_mode))
    _set_owner(destination, expected_uid, expected_gid)


def _copy_member(
    source: Path,
    destination: Path,
    relative: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    metadata = source.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        if metadata.st_nlink != 1:
            raise GateError(f"cannot copy a hardlinked seal symlink: {source}")
        _check_owner_and_mode(
            source,
            metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
            symlink=True,
        )
        try:
            first_target = os.readlink(source)
            target, encoded, _resolved = _safe_symlink_target(
                relative, first_target
            )
            os.symlink(target, destination)
            os.chown(
                destination,
                expected_uid,
                expected_gid,
                follow_symlinks=False,
            )
            second_target = os.readlink(source)
            after = source.lstat()
            installed = destination.lstat()
        except GateError:
            raise
        except OSError as error:
            raise GateError(f"could not copy seal symlink {source}: {error}") from None
        if (
            first_target != second_target
            or _metadata_identity(metadata) != _metadata_identity(after)
            or not stat.S_ISLNK(installed.st_mode)
            or installed.st_uid != expected_uid
            or installed.st_gid != expected_gid
            or installed.st_nlink != 1
            or installed.st_size != len(encoded)
            or stat.S_IMODE(installed.st_mode) != 0o777
            or os.readlink(destination) != target
            or _xattrs(destination)
        ):
            raise GateError(f"seal symlink changed while copying: {source}")
        return
    if stat.S_ISREG(metadata.st_mode):
        _copy_regular(
            source,
            destination,
            metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        return
    if not stat.S_ISDIR(metadata.st_mode):
        raise GateError(f"cannot copy non-regular seal source: {source}")
    try:
        destination.mkdir(mode=0o700)
        _set_owner(destination, expected_uid, expected_gid)
        children = sorted(os.scandir(source), key=lambda child: child.name)
    except OSError as error:
        raise GateError(f"could not create sealed directory {destination}: {error}") from None
    for child in children:
        _copy_member(
            Path(child.path),
            destination / child.name,
            _safe_relative_path(f"{relative}/{child.name}"),
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    destination.chmod(stat.S_IMODE(metadata.st_mode))
    _set_owner(destination, expected_uid, expected_gid)
    if _metadata_identity(source.lstat()) != _metadata_identity(metadata):
        raise GateError(f"seal source directory changed while copying: {source}")


def create_seal(
    seals_root: Path,
    sources: SealSources,
    provenance: SealProvenance,
    *,
    trusted_root: Path | None = None,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> VerifiedSeal:
    """Create a same-owner seal without replacing an existing policy.

    This compatibility helper must not be used to cross from a user workspace
    into a root-owned store.  Production installation uses ``pack_seal_stream``
    and the separately installed standalone root installer.
    """

    seals_root = Path(seals_root).absolute()
    if trusted_root is None:
        trusted_root = Path("/")
    _check_secure_ancestry(
        seals_root,
        trusted_root=Path(trusted_root),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(seals_root.lstat().st_mode) != 0o700:
        raise GateError("seals root must have mode 0700")
    manifest, payload, _source_records_value = _manifest_for_sources(
        sources,
        provenance,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    policy_id = hashlib.sha256(payload).hexdigest()
    destination = seals_root / policy_id
    try:
        destination.mkdir(mode=0o700)
    except FileExistsError:
        return verify_seal(
            destination,
            policy_id,
            trusted_root=seals_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    created = True
    try:
        _set_owner(destination, expected_uid, expected_gid)
        for label, relative in LAYOUT.items():
            _copy_member(
                Path(getattr(sources, label)).absolute(),
                destination / relative,
                relative,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        manifest_path = destination / MANIFEST_NAME
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(manifest_path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        manifest_path.chmod(0o600)
        _set_owner(manifest_path, expected_uid, expected_gid)
        directory_fd = os.open(destination, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return verify_seal(
            destination,
            policy_id,
            trusted_root=seals_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
    except Exception:
        if created and destination.exists() and not destination.is_symlink():
            shutil.rmtree(destination)
        raise


def read_active_policy(
    active_path: Path,
    *,
    trusted_root: Path | None = None,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> str:
    active_path = Path(active_path).absolute()
    if trusted_root is None:
        trusted_root = Path("/")
    _check_secure_ancestry(
        active_path.parent,
        trusted_root=Path(trusted_root),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        metadata = active_path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect active policy: {error}") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GateError("active policy must be one real, unlinked regular file")
    _check_owner_and_mode(
        active_path,
        metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GateError("active policy must have mode 0600")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(active_path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(66)
            trailing = stream.read(1)
            finished = os.fstat(stream.fileno())
        after = active_path.lstat()
    except OSError as error:
        raise GateError(f"could not read active policy: {error}") from None
    if trailing or len(payload) != 65:
        raise GateError("active policy has an invalid size")
    if (
        _metadata_identity(metadata) != _metadata_identity(opened)
        or _metadata_identity(finished) != _metadata_identity(opened)
        or _metadata_identity(after) != _metadata_identity(opened)
    ):
        raise GateError("active policy changed while reading")
    try:
        value = payload.decode("ascii")
    except UnicodeError:
        raise GateError("active policy is not ASCII") from None
    policy_id = value[:-1]
    if value[-1:] != "\n" or _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise GateError("active policy has invalid content")
    return policy_id


def activate_policy(
    active_path: Path,
    policy_id: str,
    *,
    seals_root: Path,
    expected_current_policy: str | None | object = _EXPECTED_UNSET,
    trusted_root: Path | None = None,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    """Verify and atomically activate a strictly newer V3 seal generation."""

    _change_active_policy(
        active_path,
        policy_id,
        seals_root=seals_root,
        expected_current_policy=expected_current_policy,
        rollback=False,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def rollback_policy(
    active_path: Path,
    policy_id: str,
    *,
    seals_root: Path,
    expected_current_policy: str,
    trusted_root: Path | None = None,
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> None:
    """Explicitly roll back to a verified older V2 or V3 generation.

    Naming the policy believed to be active makes rollback a deliberate,
    compare-and-swap administration action instead of an override switch.
    """

    _change_active_policy(
        active_path,
        policy_id,
        seals_root=seals_root,
        expected_current_policy=expected_current_policy,
        rollback=True,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )


def _change_active_policy(
    active_path: Path,
    policy_id: str,
    *,
    seals_root: Path,
    expected_current_policy: str | None | object,
    rollback: bool,
    trusted_root: Path | None,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if not isinstance(policy_id, str) or _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise GateError("active policy id is invalid")
    active_path = Path(active_path).absolute()
    parent = active_path.parent
    seals_root = Path(seals_root).absolute()
    if trusted_root is None:
        trusted_root = Path("/")
    _check_secure_ancestry(
        parent,
        trusted_root=Path(trusted_root),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(parent.lstat().st_mode) != 0o700:
        raise GateError("active-policy parent must have mode 0700")
    _check_secure_ancestry(
        seals_root,
        trusted_root=Path(trusted_root),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(seals_root.lstat().st_mode) != 0o700:
        raise GateError("seals root must have mode 0700")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        parent_fd = os.open(parent, directory_flags)
    except OSError as error:
        raise GateError(f"could not open active-policy parent: {error}") from None
    temporary_name: str | None = None
    try:
        try:
            fcntl.flock(parent_fd, fcntl.LOCK_EX)
        except OSError as error:
            raise GateError(f"could not lock active-policy parent: {error}") from None
        target = verify_seal(
            seals_root / policy_id,
            policy_id,
            trusted_root=trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if not rollback and target.manifest["schema"] != SCHEMA:
            raise GateError("activation target must use the current seal schema")
        target_generation = int(target.manifest["provenance"]["generation"])
        try:
            os.stat(active_path.name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            current_policy = None
        except OSError as error:
            raise GateError(f"could not inspect active policy: {error}") from None
        else:
            current_policy = read_active_policy(
                active_path,
                trusted_root=trusted_root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        if (
            expected_current_policy is not _EXPECTED_UNSET
            and current_policy != expected_current_policy
        ):
            raise GateError("active policy changed from the expected policy")
        if rollback and current_policy is None:
            raise GateError("cannot roll back when no policy is active")
        if current_policy is not None:
            current = verify_seal(
                seals_root / current_policy,
                current_policy,
                trusted_root=trusted_root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            current_generation = int(current.manifest["provenance"]["generation"])
            if rollback:
                if target_generation >= current_generation:
                    raise GateError("rollback target is not an older verified generation")
            elif target_generation <= current_generation:
                raise GateError("activation target is not a newer verified generation")
        elif rollback:
            raise GateError("cannot roll back without a verified current generation")

        temporary_name = f".{active_path.name}.{secrets.token_hex(16)}.tmp"
        write_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(temporary_name, write_flags, 0o600, dir_fd=parent_fd)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((policy_id + "\n").encode("ascii"))
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            os.fchown(stream.fileno(), expected_uid, expected_gid)
            os.fsync(stream.fileno())
        os.rename(
            temporary_name,
            active_path.name,
            src_dir_fd=parent_fd,
            dst_dir_fd=parent_fd,
        )
        os.fsync(parent_fd)
        actual = read_active_policy(
            active_path,
            trusted_root=trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if actual != policy_id:
            raise GateError("active policy did not persist exactly")
    except Exception:
        if temporary_name is not None:
            try:
                os.unlink(temporary_name, dir_fd=parent_fd)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(parent_fd)


def _verify_policy_admin_runtime(argv: list[str]) -> tuple[str, str, str | None]:
    if len(argv) != 4 or argv[1] not in {"activate", "rollback"}:
        raise GateError(
            "usage: lmi-p1-policy-admin {activate|rollback} POLICY CURRENT|none"
        )
    if not (
        sys.flags.isolated
        and sys.flags.no_site
        and sys.flags.dont_write_bytecode
        and sys.flags.ignore_environment
    ):
        raise GateError("policy administrator requires Python flags -I -S -B")
    getresuid = getattr(os, "getresuid", None)
    getresgid = getattr(os, "getresgid", None)
    if (
        getresuid is None
        or getresgid is None
        or tuple(getresuid()) != (0, 0, 0)
        or tuple(getresgid()) != (0, 0, 0)
    ):
        raise GateError("policy administrator requires root real/effective/saved IDs")
    try:
        os.setgroups([])
    except OSError as error:
        raise GateError(f"could not clear supplementary groups: {error}") from None
    if os.getgroups():
        raise GateError("supplementary groups were not cleared")
    os.umask(0o077)
    executing = Path(__file__).absolute()
    if executing != POLICY_ADMIN_PATH:
        raise GateError("policy administrator is not running from its fixed install")
    _check_secure_ancestry(
        POLICY_ADMIN_PATH.parent,
        trusted_root=Path("/"),
        expected_uid=0,
        expected_gid=0,
    )
    metadata = POLICY_ADMIN_PATH.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise GateError("installed policy administrator must be one 0755 regular file")
    _check_owner_and_mode(
        POLICY_ADMIN_PATH,
        metadata,
        expected_uid=0,
        expected_gid=0,
    )
    policy_id = argv[2]
    if _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise GateError("policy administrator policy id is invalid")
    expected = None if argv[3] == "none" else argv[3]
    if expected is not None and _POLICY_ID_RE.fullmatch(expected) is None:
        raise GateError("policy administrator expected current id is invalid")
    if argv[1] == "rollback" and expected is None:
        raise GateError("rollback requires the exact current policy id")
    return argv[1], policy_id, expected


def _policy_admin_main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    try:
        action, policy_id, expected = _verify_policy_admin_runtime(argv)
        if action == "activate":
            activate_policy(
                PRODUCTION_ACTIVE_PATH,
                policy_id,
                seals_root=PRODUCTION_SEALS_ROOT,
                expected_current_policy=expected,
            )
        else:
            if expected is None:
                raise GateError("rollback requires the exact current policy id")
            rollback_policy(
                PRODUCTION_ACTIVE_PATH,
                policy_id,
                seals_root=PRODUCTION_SEALS_ROOT,
                expected_current_policy=expected,
            )
    except (GateError, OSError) as error:
        sys.stderr.write(f"lmi-p1 policy administrator rejected request: {error}\n")
        return 1
    sys.stdout.write(policy_id + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(_policy_admin_main())
