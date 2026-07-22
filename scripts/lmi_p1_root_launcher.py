#!/usr/bin/python3 -EsB
"""Standalone trust bootstrap for root-owned lmi P1 sealed builds.

This file intentionally imports only the Python standard library and duplicates
the small amount of seal verification needed before executing project code.
It must be installed as ``/usr/local/sbin/lmi-p1-root-launcher`` with root:root
ownership and mode 0755; running the repository copy directly fails closed.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import secrets
import signal
import stat
import sys
from typing import BinaryIO, Callable, Mapping, NoReturn


REQUEST_SCHEMA = "lmi-p1-build-request/v1"
REQUEST_MAGIC = b"LMIR"
REQUEST_LENGTH_BYTES = 4
# The launcher keeps exact V2 read compatibility through the V3 rollback window.
LEGACY_MANIFEST_SCHEMA = 2
MANIFEST_SCHEMA = 3
READ_MANIFEST_SCHEMAS = frozenset({LEGACY_MANIFEST_SCHEMA, MANIFEST_SCHEMA})
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
_DIRECTORY_INPUTS = frozenset({"offline_cache", "project", "pmbootstrap", "pmaports"})
_POLICY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_BUILDER_SIGNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_MAX_REQUEST_BYTES = 4096
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
_MAX_MANIFEST_BYTES = 64 * 1024 * 1024
_HASH_BLOCK_SIZE = 1024 * 1024
_MAX_MEMBERS = 200_000
_MAX_PATH_BYTES = 1024
_MAX_DEPTH = 32
_MAX_SYMLINK_TARGET_BYTES = 1024
_MAX_SYMLINK_TARGET_DEPTH = 32
_MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_TOTAL_FILE_BYTES = 16 * 1024 * 1024 * 1024
_REQUEST_FD = 0
_RETAIN_RUNS = 8
_SYMLINK_COMPONENTS = frozenset({"project", "pmbootstrap", "pmaports"})
_CLI_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "sys.argv[0]=sys.argv.pop(1);"
    "runpy.run_path(sys.argv[0],run_name='__main__')"
)


class LauncherError(RuntimeError):
    """The standalone root trust boundary failed closed."""


@dataclass(frozen=True)
class LauncherPaths:
    active: Path = Path("/opt/lmi-p1/active-policy")
    seals: Path = Path("/opt/lmi-p1/seals")
    runs: Path = Path("/var/lib/lmi-p1/runs")
    python: Path = Path("/usr/bin/python3")
    python_pin: Path = Path("/etc/lmi-p1-builder/python.pin.json")
    launcher: Path = Path("/usr/local/sbin/lmi-p1-root-launcher")
    trusted_root: Path = Path("/")


DEFAULT_PATHS = LauncherPaths()


def _duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise LauncherError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def canonical_json_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as error:
        raise LauncherError(f"value is not canonical JSON data: {error}") from None
    return (rendered + "\n").encode("ascii")


def encode_request(request: object) -> bytes:
    payload = canonical_json_bytes(request)
    if len(payload) > _MAX_REQUEST_BYTES:
        raise LauncherError("build request exceeds 4 KiB")
    return REQUEST_MAGIC + len(payload).to_bytes(REQUEST_LENGTH_BYTES, "big") + payload


def parse_request(stream: BinaryIO) -> dict[str, object]:
    """Parse the complete canonical frame from an already bounded stream."""

    try:
        header = stream.read(len(REQUEST_MAGIC) + REQUEST_LENGTH_BYTES)
        if not isinstance(header, bytes):
            raise LauncherError("build request input must be a binary stream")
        if len(header) != len(REQUEST_MAGIC) + REQUEST_LENGTH_BYTES:
            raise LauncherError("build request frame is truncated")
        if header[: len(REQUEST_MAGIC)] != REQUEST_MAGIC:
            raise LauncherError("build request frame magic is invalid")
        length = int.from_bytes(header[len(REQUEST_MAGIC) :], "big")
        if length <= 0 or length > _MAX_REQUEST_BYTES:
            raise LauncherError("build request frame length is invalid")
        payload = stream.read(length)
        trailing = stream.read(1)
    except OSError as error:
        raise LauncherError(f"could not read build request: {error}") from None
    if not isinstance(payload, bytes):
        raise LauncherError("build request input must be a binary stream")
    if len(payload) != length:
        raise LauncherError("build request frame is truncated")
    if trailing:
        raise LauncherError("build request frame has trailing bytes")
    try:
        request = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_object,
        )
    except LauncherError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LauncherError(f"build request is not valid JSON: {error}") from None
    if not isinstance(request, dict):
        raise LauncherError("build request must be a JSON object")
    if set(request) != {"policy_id", "schema", "tag"}:
        raise LauncherError("build request has unexpected or missing fields")
    if request["schema"] != REQUEST_SCHEMA:
        raise LauncherError("unsupported build request schema")
    policy_id = request["policy_id"]
    tag = request["tag"]
    if not isinstance(policy_id, str) or _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise LauncherError("build request policy_id is invalid")
    if not isinstance(tag, str) or _TAG_RE.fullmatch(tag) is None:
        raise LauncherError("build request tag is invalid")
    if canonical_json_bytes(request) != payload:
        raise LauncherError("build request JSON is not canonical")
    return request


def parse_request_fd(fd: int) -> dict[str, object]:
    """Read a finite regular-file FD with pread, so request input cannot block."""

    try:
        before = os.fstat(fd)
    except OSError as error:
        raise LauncherError(f"could not inspect build request fd: {error}") from None
    maximum = len(REQUEST_MAGIC) + REQUEST_LENGTH_BYTES + _MAX_REQUEST_BYTES
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= len(REQUEST_MAGIC) + REQUEST_LENGTH_BYTES
        or before.st_size > maximum
    ):
        raise LauncherError("build request fd must be a bounded regular file")
    try:
        payload = os.pread(fd, before.st_size + 1, 0)
        after = os.fstat(fd)
    except OSError as error:
        raise LauncherError(f"could not read build request fd: {error}") from None
    if _identity(before) != _identity(after) or len(payload) != before.st_size:
        raise LauncherError("build request file changed while reading")
    import io

    return parse_request(io.BytesIO(payload))


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
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
        raise LauncherError("filesystem xattr inspection is unavailable") from None
    except OSError as error:
        raise LauncherError(f"could not inspect xattrs for {path}: {error}") from None


def _secure_metadata(
    path: Path,
    metadata: os.stat_result,
    *,
    expected_uid: int,
    expected_gid: int,
    symlink: bool = False,
) -> None:
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise LauncherError(f"trusted path has the wrong owner: {path}")
    if not symlink and stat.S_IMODE(metadata.st_mode) & 0o022:
        raise LauncherError(f"trusted path is group/world writable: {path}")
    if _xattrs(path):
        raise LauncherError(f"trusted path has xattrs: {path}")


def _secure_ancestry(
    path: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    if ".." in path.parts or ".." in trusted_root.parts:
        raise LauncherError("trusted ancestry path is not normalized")
    path = path.absolute()
    trusted_root = trusted_root.absolute()
    try:
        relative = path.relative_to(trusted_root)
    except ValueError:
        raise LauncherError(f"trusted path escapes its configured root: {path}") from None
    current = trusted_root
    candidates = [current]
    for part in relative.parts:
        current /= part
        candidates.append(current)
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
        except OSError as error:
            raise LauncherError(f"could not inspect trusted ancestry {candidate}: {error}") from None
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise LauncherError(f"trusted ancestry is not a real directory: {candidate}")
        _secure_metadata(
            candidate,
            metadata,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )


def _secure_regular(
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
    exact_mode: int | None = None,
) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise LauncherError(f"could not inspect trusted file {path}: {error}") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LauncherError(f"trusted file is not one real, unlinked regular file: {path}")
    _secure_metadata(
        path,
        metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if exact_mode is not None and stat.S_IMODE(metadata.st_mode) != exact_mode:
        raise LauncherError(f"trusted file has the wrong mode: {path}")
    return metadata


def _resolve_secure_python(
    path: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> Path:
    """Resolve and verify every component of the fixed Python symlink chain."""

    current = path.absolute()
    seen: set[Path] = set()
    for _hop in range(17):
        if current in seen:
            raise LauncherError("fixed Python symlink chain contains a cycle")
        seen.add(current)
        _secure_ancestry(
            current.parent,
            trusted_root=trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        try:
            metadata = current.lstat()
        except OSError as error:
            raise LauncherError(f"could not inspect fixed Python: {error}") from None
        if not stat.S_ISLNK(metadata.st_mode):
            _secure_regular(
                current,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
            if not metadata.st_mode & stat.S_IXUSR:
                raise LauncherError("fixed Python target is not executable")
            return current
        if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
            raise LauncherError("fixed Python symlink has the wrong owner")
        if _xattrs(current):
            raise LauncherError("fixed Python symlink has xattrs")
        try:
            target_text = os.readlink(current)
        except OSError as error:
            raise LauncherError(f"could not read fixed Python symlink: {error}") from None
        if os.path.isabs(target_text):
            current = Path(os.path.normpath(target_text))
        else:
            current = Path(os.path.normpath(current.parent / target_text))
        try:
            current.relative_to(trusted_root.absolute())
        except ValueError:
            raise LauncherError("fixed Python symlink escapes the trusted root") from None
    raise LauncherError("fixed Python symlink chain is too deep")


def _pinned_python_target(
    path: Path,
    pin_path: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> Path:
    target = _resolve_secure_python(
        path,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    _secure_ancestry(
        pin_path.parent,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    pin_metadata = _secure_regular(
        pin_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        exact_mode=0o600,
    )
    payload = _read_stable(pin_path, pin_metadata, 512)
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_duplicate_object)
    except LauncherError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LauncherError(f"Python pin is invalid JSON: {error}") from None
    if (
        not isinstance(value, dict)
        or set(value) != {"path", "schema", "sha256"}
        or value["schema"] != "lmi-p1-python-pin/v1"
        or not isinstance(value["path"], str)
        or not isinstance(value["sha256"], str)
        or _POLICY_ID_RE.fullmatch(value["sha256"]) is None
        or canonical_json_bytes(value) != payload
    ):
        raise LauncherError("Python pin has an invalid shape or encoding")
    if Path(value["path"]) != target:
        raise LauncherError("resolved Python target does not match its pin")
    target_metadata = _secure_regular(
        target,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if _hash_file(target, target_metadata) != value["sha256"]:
        raise LauncherError("resolved Python target digest does not match its pin")
    return target


def _read_stable(path: Path, metadata: os.stat_result, maximum: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum + 1)
            trailing = stream.read(1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise LauncherError(f"could not read trusted file {path}: {error}") from None
    if len(payload) > maximum or trailing:
        raise LauncherError(f"trusted file exceeds its size limit: {path}")
    if (
        _identity(metadata) != _identity(opened)
        or _identity(finished) != _identity(opened)
        or _identity(after) != _identity(opened)
    ):
        raise LauncherError(f"trusted file changed while reading: {path}")
    return payload


def _read_active(
    path: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> str:
    _secure_ancestry(
        path.parent,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    metadata = _secure_regular(
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        exact_mode=0o600,
    )
    payload = _read_stable(path, metadata, 65)
    try:
        text = payload.decode("ascii")
    except UnicodeError:
        raise LauncherError("active policy is not ASCII") from None
    if len(text) != 65 or not text.endswith("\n"):
        raise LauncherError("active policy has an invalid size")
    policy_id = text[:-1]
    if _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise LauncherError("active policy id is invalid")
    return policy_id


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise LauncherError("manifest member path is unsafe")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise LauncherError("manifest member path contains a control character")
    try:
        value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise LauncherError("manifest member path is not UTF-8") from None
    relative = PurePosixPath(value)
    if relative.is_absolute() or any(part in {"", ".", ".."} for part in relative.parts):
        raise LauncherError("manifest member path is unsafe")
    if relative.as_posix() != value:
        raise LauncherError("manifest member path is not normalized")
    return value


def _safe_symlink_target(relative: str, value: object) -> tuple[str, bytes, str]:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\0" in value
        or value.startswith("/")
    ):
        raise LauncherError(f"seal symlink target is unsafe: {relative}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise LauncherError(
            f"seal symlink target contains a control character: {relative}"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise LauncherError(
            f"seal symlink target is not valid UTF-8: {relative}"
        ) from None
    raw_parts = value.split("/")
    if (
        len(encoded) > _MAX_SYMLINK_TARGET_BYTES
        or len(raw_parts) > _MAX_SYMLINK_TARGET_DEPTH
        or any(part == "" for part in raw_parts)
    ):
        raise LauncherError(f"seal symlink target exceeds its limits: {relative}")
    member = PurePosixPath(relative)
    component = member.parts[0]
    if component not in _SYMLINK_COMPONENTS:
        raise LauncherError(
            f"seal symlink is outside a repository component: {relative}"
        )
    resolved = list(member.parent.parts)
    for part in raw_parts:
        if part == ".":
            continue
        if part == "..":
            if len(resolved) <= 1:
                raise LauncherError(
                    f"seal symlink target escapes its component: {relative}"
                )
            resolved.pop()
        else:
            resolved.append(part)
        if len(resolved) > _MAX_DEPTH:
            raise LauncherError(
                f"seal symlink target resolves too deeply: {relative}"
            )
    if not resolved or resolved[0] != component:
        raise LauncherError(
            f"seal symlink target escapes its component: {relative}"
        )
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
    by_path = {str(member["path"]): member for member in members}
    for member in members:
        relative = str(member["path"])
        parent = PurePosixPath(relative).parent.as_posix()
        if parent != ".":
            parent_member = by_path.get(parent)
            if parent_member is None or parent_member["type"] != "directory":
                raise LauncherError(
                    "seal manifest member parent is absent or not a directory: "
                    f"{relative}"
                )
        if member["type"] != "symlink":
            continue
        target, _encoded, resolved = _safe_symlink_target(
            relative, member["target"]
        )
        for traversed in _symlink_walk_paths(relative, target)[:-1]:
            traversed_member = by_path.get(traversed)
            if traversed_member is None or traversed_member["type"] != "directory":
                raise LauncherError(
                    "seal symlink traverses a missing or non-directory member: "
                    f"{relative}"
                )
        target_member = by_path.get(resolved)
        if target_member is None:
            raise LauncherError(f"seal symlink target is absent: {relative}")
        if target_member["type"] != "file":
            raise LauncherError(
                f"seal symlink target is not one regular file: {relative}"
            )


def _hash_file(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if _identity(opened) != _identity(expected):
                raise LauncherError(f"sealed file changed while opening: {path}")
            for block in iter(lambda: stream.read(_HASH_BLOCK_SIZE), b""):
                digest.update(block)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except LauncherError:
        raise
    except OSError as error:
        raise LauncherError(f"could not hash sealed file {path}: {error}") from None
    if _identity(finished) != _identity(opened) or _identity(after) != _identity(opened):
        raise LauncherError(f"sealed file changed while hashing: {path}")
    return digest.hexdigest()


def _inventory(
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
        raise LauncherError(f"could not inspect sealed member {path}: {error}") from None
    if stat.S_ISLNK(before.st_mode):
        if before.st_nlink != 1:
            raise LauncherError(f"seal contains a hardlinked symlink: {relative}")
        inode = (before.st_dev, before.st_ino)
        if inode in non_directory_inodes:
            raise LauncherError(
                f"sealed non-directory members share an inode: {relative}"
            )
        non_directory_inodes[inode] = relative
        _secure_metadata(
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
            raise LauncherError(f"could not read sealed symlink {path}: {error}") from None
        if first_target != second_target or _identity(before) != _identity(after):
            raise LauncherError(f"sealed symlink changed while reading: {path}")
        target, encoded, _resolved = _safe_symlink_target(relative, first_target)
        if before.st_size != len(encoded) or stat.S_IMODE(before.st_mode) != 0o777:
            raise LauncherError(f"sealed symlink metadata is not canonical: {relative}")
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
    _secure_metadata(
        path,
        before,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    mode = stat.S_IMODE(before.st_mode)
    if stat.S_ISREG(before.st_mode):
        if before.st_nlink != 1:
            raise LauncherError(f"seal contains a hardlinked file: {relative}")
        inode = (before.st_dev, before.st_ino)
        if inode in non_directory_inodes:
            raise LauncherError(f"sealed files share an inode: {relative}")
        non_directory_inodes[inode] = relative
        return [
            {
                "mode": mode,
                "path": relative,
                "sha256": _hash_file(path, before),
                "size": before.st_size,
                "type": "file",
            }
        ]
    if not stat.S_ISDIR(before.st_mode):
        raise LauncherError(f"seal contains a special filesystem object: {relative}")
    records: list[dict[str, object]] = [
        {
            "mode": mode,
            "path": relative,
            "sha256": EMPTY_SHA256,
            "size": 0,
            "type": "directory",
        }
    ]
    try:
        children = sorted(os.scandir(path), key=lambda child: child.name)
    except (OSError, UnicodeError) as error:
        raise LauncherError(f"could not enumerate sealed directory {path}: {error}") from None
    for child in children:
        child_relative = _safe_relative(f"{relative}/{child.name}")
        records.extend(
            _inventory(
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
        raise LauncherError(f"could not re-inspect sealed directory {path}: {error}") from None
    if _identity(before) != _identity(after):
        raise LauncherError(f"sealed directory changed while enumerating: {path}")
    return records


def _valid_remote(value: object, label: str) -> None:
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
        raise LauncherError(f"seal provenance {label} remote is invalid")


def _valid_git_provenance(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"commit", "remote", "tree"}:
        raise LauncherError(f"seal provenance {label} has an invalid shape")
    _valid_remote(value["remote"], label)
    for field in ("commit", "tree"):
        item = value[field]
        if not isinstance(item, str) or _GIT_OBJECT_RE.fullmatch(item) is None:
            raise LauncherError(f"seal provenance {label}.{field} is invalid")


def _valid_provenance(value: object) -> None:
    if not isinstance(value, dict) or set(value) != {
        "generation",
        "offline_cache",
        "pmaports",
        "pmbootstrap",
        "project",
    }:
        raise LauncherError("seal provenance has an invalid shape")
    generation = value["generation"]
    if type(generation) is not int or generation <= 0:
        raise LauncherError("seal provenance generation must be a positive integer")
    _valid_git_provenance(value["project"], "project")
    _valid_git_provenance(value["pmaports"], "pmaports")
    offline_cache = value["offline_cache"]
    if not isinstance(offline_cache, dict) or set(offline_cache) != {
        "aggregate_sha256",
        "manifest_sha256",
        "schema",
    }:
        raise LauncherError("seal provenance offline_cache has an invalid shape")
    if offline_cache["schema"] != OFFLINE_CACHE_SCHEMA:
        raise LauncherError("seal provenance offline_cache schema is invalid")
    for field in ("aggregate_sha256", "manifest_sha256"):
        if (
            not isinstance(offline_cache[field], str)
            or _POLICY_ID_RE.fullmatch(offline_cache[field]) is None
        ):
            raise LauncherError(f"seal provenance offline_cache.{field} is invalid")
    pmbootstrap = value["pmbootstrap"]
    if not isinstance(pmbootstrap, dict) or set(pmbootstrap) != {
        "commit",
        "entrypoint_sha256",
        "remote",
        "tree",
        "version",
    }:
        raise LauncherError("seal provenance pmbootstrap has an invalid shape")
    _valid_remote(pmbootstrap["remote"], "pmbootstrap")
    for field in ("commit", "tree"):
        item = pmbootstrap[field]
        if not isinstance(item, str) or _GIT_OBJECT_RE.fullmatch(item) is None:
            raise LauncherError(f"seal provenance pmbootstrap.{field} is invalid")
    digest = pmbootstrap["entrypoint_sha256"]
    if not isinstance(digest, str) or _POLICY_ID_RE.fullmatch(digest) is None:
        raise LauncherError("seal provenance pmbootstrap.entrypoint_sha256 is invalid")
    version = pmbootstrap["version"]
    if not isinstance(version, str) or _VERSION_RE.fullmatch(version) is None:
        raise LauncherError("seal provenance pmbootstrap.version is invalid")


def _validated_manifest(payload: bytes) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        parsed = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_duplicate_object,
        )
    except LauncherError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LauncherError(f"seal manifest is invalid JSON: {error}") from None
    if not isinstance(parsed, dict) or set(parsed) != {
        "inputs",
        "layout",
        "members",
        "provenance",
        "schema",
    }:
        raise LauncherError("seal manifest has an invalid top-level shape")
    if canonical_json_bytes(parsed) != payload:
        raise LauncherError("seal manifest bytes are not canonical")
    schema = parsed["schema"]
    if type(schema) is not int or schema not in READ_MANIFEST_SCHEMAS:
        raise LauncherError("unsupported seal manifest schema")
    if parsed["layout"] != LAYOUT:
        raise LauncherError("seal manifest layout mismatch")
    _valid_provenance(parsed["provenance"])
    inputs = parsed["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "authorized_key_sha256",
        "source_lock_sha256",
    }:
        raise LauncherError("seal manifest inputs have an invalid shape")
    for label, digest in inputs.items():
        if not isinstance(digest, str) or _POLICY_ID_RE.fullmatch(digest) is None:
            raise LauncherError(f"seal manifest input digest is invalid: {label}")
    members = parsed["members"]
    if not isinstance(members, list) or not members or len(members) > _MAX_MEMBERS:
        raise LauncherError("seal manifest members must be a non-empty list")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    total_file_bytes = 0
    for item in members:
        if not isinstance(item, dict):
            raise LauncherError("seal manifest member has an invalid shape")
        member_type = item.get("type")
        expected_fields = {"mode", "path", "sha256", "size", "type"}
        if schema == MANIFEST_SCHEMA and member_type == "symlink":
            expected_fields.add("target")
        if set(item) != expected_fields:
            raise LauncherError("seal manifest member has an invalid shape")
        relative = _safe_relative(item["path"])
        if (
            len(relative.encode("utf-8")) > _MAX_PATH_BYTES
            or len(PurePosixPath(relative).parts) > _MAX_DEPTH
        ):
            raise LauncherError(f"seal manifest member path exceeds limits: {relative}")
        if relative in seen:
            raise LauncherError(f"seal manifest contains a duplicate member: {relative}")
        seen.add(relative)
        mode = item["mode"]
        size = item["size"]
        digest = item["sha256"]
        allowed_types = {"directory", "file"}
        if schema == MANIFEST_SCHEMA:
            allowed_types.add("symlink")
        if not isinstance(member_type, str) or member_type not in allowed_types:
            raise LauncherError(f"seal manifest member has an invalid type: {relative}")
        if (
            type(mode) is not int
            or not 0 <= mode <= 0o777
            or (member_type != "symlink" and mode & 0o022)
        ):
            raise LauncherError(f"seal manifest member has an invalid mode: {relative}")
        if type(size) is not int or size < 0 or size > _MAX_FILE_BYTES:
            raise LauncherError(f"seal manifest member has an invalid size: {relative}")
        if (
            relative
            == f'{LAYOUT["offline_cache"]}/{OFFLINE_CACHE_MANIFEST_NAME}'
            and size > _MAX_OFFLINE_CACHE_MANIFEST_BYTES
        ):
            raise LauncherError("offline-cache manifest exceeds its size limit")
        if not isinstance(digest, str) or _POLICY_ID_RE.fullmatch(digest) is None:
            raise LauncherError(f"seal manifest member has an invalid digest: {relative}")
        if member_type == "directory" and (size != 0 or digest != EMPTY_SHA256):
            raise LauncherError(f"seal directory record is not canonical: {relative}")
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
                raise LauncherError(
                    f"seal symlink record is not canonical: {relative}"
                )
        if member_type == "file":
            total_file_bytes += size
            if total_file_bytes > _MAX_TOTAL_FILE_BYTES:
                raise LauncherError("seal manifest total file size exceeds its limit")
        result.append(dict(item))
    paths = [str(item["path"]) for item in result]
    if paths != sorted(paths):
        raise LauncherError("seal manifest members are not path-sorted")
    _validate_symlink_graph(result)
    members_by_path = {str(item["path"]): item for item in result}
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
            raise LauncherError(f"seal manifest input digest does not match member: {field}")
    entrypoint = members_by_path.get("pmbootstrap/pmbootstrap.py")
    pmbootstrap = parsed["provenance"]["pmbootstrap"]
    if (
        entrypoint is None
        or entrypoint["type"] != "file"
        or pmbootstrap["entrypoint_sha256"] != entrypoint["sha256"]
    ):
        raise LauncherError(
            "seal provenance pmbootstrap.entrypoint_sha256 does not match its member"
        )
    return parsed, result


def _validate_source_lock(payload: bytes, provenance: Mapping[str, object]) -> None:
    if len(payload) > _MAX_SOURCE_LOCK_BYTES:
        raise LauncherError("sealed source lock exceeds its size limit")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_duplicate_object,
        )
    except LauncherError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LauncherError(f"sealed source lock is invalid JSON: {error}") from None
    if not isinstance(value, dict):
        raise LauncherError("sealed source lock must be an object")
    if value.get("schema") != "lmi-source-lock/v3":
        raise LauncherError("source lock schema must be lmi-source-lock/v3")
    for label, fields in {
        "pmbootstrap": ("remote", "commit", "tree", "version", "entrypoint_sha256"),
        "pmaports": ("remote", "commit", "tree"),
        "offline_cache": ("schema", "manifest_sha256", "aggregate_sha256"),
    }.items():
        locked = value.get(label)
        sealed = provenance.get(label)
        if not isinstance(locked, dict) or not isinstance(sealed, dict):
            raise LauncherError(f"source lock is missing {label} provenance")
        for field in fields:
            if locked.get(field) != sealed.get(field):
                raise LauncherError(f"source lock provenance mismatch: {label}.{field}")


def _validate_offline_contract(
    payload: bytes,
    outer_members: list[dict[str, object]],
    provenance: Mapping[str, object],
) -> None:
    """Mirror the standalone installer's strict offline-cache v1 contract."""

    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_duplicate_object)
    except LauncherError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise LauncherError(f"offline-cache manifest is invalid JSON: {error}") from None
    if canonical_json_bytes(value) != payload:
        raise LauncherError("offline-cache manifest bytes are not canonical")
    if not isinstance(value, dict) or set(value) != {
        "aggregate_sha256", "distfiles", "external_apks", "http_artifacts",
        "members", "pins", "repositories", "schema",
    }:
        raise LauncherError("offline-cache manifest has an invalid top-level shape")
    if value["schema"] != OFFLINE_CACHE_SCHEMA:
        raise LauncherError("offline-cache manifest schema mismatch")
    aggregate = value["aggregate_sha256"]
    preimage = dict(value)
    del preimage["aggregate_sha256"]
    if (
        not isinstance(aggregate, str)
        or _POLICY_ID_RE.fullmatch(aggregate) is None
        or hashlib.sha256(canonical_json_bytes(preimage)).hexdigest() != aggregate
    ):
        raise LauncherError("offline-cache aggregate digest mismatch")
    if provenance.get("offline_cache") != {
        "aggregate_sha256": aggregate,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "schema": OFFLINE_CACHE_SCHEMA,
    }:
        raise LauncherError("seal provenance offline_cache binding mismatch")
    if value["pins"] != {
        "pmbootstrap": {
            "commit": _EXPECTED_PMBOOTSTRAP_COMMIT,
            "version": _EXPECTED_PMBOOTSTRAP_VERSION,
            "work_version": 8,
        },
        "pmaports": {
            "channel": "edge",
            "commit": _EXPECTED_PMAPORTS_COMMIT,
            "tree": _EXPECTED_PMAPORTS_TREE,
        },
    }:
        raise LauncherError("offline-cache exact source pins mismatch")

    cache_prefix = LAYOUT["offline_cache"] + "/"
    directories = {
        str(item["path"])[len(cache_prefix):]
        for item in outer_members
        if item["type"] == "directory" and str(item["path"]).startswith(cache_prefix)
    }
    if directories != {"work", *_OFFLINE_WORK_DIRECTORIES}:
        raise LauncherError("offline-cache contains forbidden mutable directories")
    actual = {
        str(item["path"])[len(cache_prefix):]: {
            "path": str(item["path"])[len(cache_prefix):],
            "sha256": item["sha256"],
            "size": item["size"],
        }
        for item in outer_members
        if item["type"] == "file"
        and str(item["path"]).startswith(cache_prefix + "work/")
    }

    def records(
        name: str,
        fields: set[str],
        key_fields: tuple[str, ...],
    ) -> list[dict[str, object]]:
        items = value[name]
        if not isinstance(items, list):
            raise LauncherError(f"offline-cache {name} must be a list")
        result: list[dict[str, object]] = []
        keys: list[tuple[str, ...]] = []
        for item in items:
            if not isinstance(item, dict) or set(item) != fields:
                raise LauncherError(f"offline-cache {name} record has an invalid shape")
            key = tuple(item[field] for field in key_fields)
            if not all(isinstance(part, str) for part in key):
                raise LauncherError(f"offline-cache {name} record has an invalid sort key")
            result.append(dict(item))
            keys.append(key)
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise LauncherError(f"offline-cache {name} is not sorted and unique")
        return result

    declared = records("members", {"path", "sha256", "size"}, ("path",))
    declared_map: dict[str, dict[str, object]] = {}
    for item in declared:
        path = _safe_relative(item["path"])
        if (
            not path.startswith("work/")
            or type(item["size"]) is not int
            or item["size"] < 0
            or item["size"] > _MAX_FILE_BYTES
            or not isinstance(item["sha256"], str)
            or _POLICY_ID_RE.fullmatch(item["sha256"]) is None
            or path in declared_map
        ):
            raise LauncherError(f"offline-cache member metadata is invalid: {path}")
        declared_map[path] = item
    if [str(item["path"]) for item in declared] != sorted(declared_map):
        raise LauncherError("offline-cache members are not path-sorted")
    if declared_map != actual:
        raise LauncherError("offline-cache work inventory does not match its manifest")
    if actual.get("work/version") != {
        "path": "work/version",
        "sha256": hashlib.sha256(OFFLINE_WORK_VERSION).hexdigest(),
        "size": len(OFFLINE_WORK_VERSION),
    }:
        raise LauncherError("offline-cache work/version binding mismatch")

    classifications: dict[str, int] = {}
    signer_paths: set[str] = set()

    def bind(
        item: Mapping[str, object], path_field: str, size_field: str | None,
        digest_field: str, prefix: str | None, classify: bool,
    ) -> str:
        path = _safe_relative(item[path_field])
        if not path.startswith("work/") or (
            prefix is not None and not path.startswith(prefix + "/")
        ):
            raise LauncherError(f"offline-cache path is outside its cache: {path}")
        member = actual.get(path)
        if member is None or (
            size_field is not None and item[size_field] != member["size"]
        ) or item[digest_field] != member["sha256"]:
            raise LauncherError(f"offline-cache member binding mismatch: {path}")
        if classify:
            classifications[path] = classifications.get(path, 0) + 1
        return path

    repositories = records(
        "repositories",
        {"architecture", "index_path", "index_sha256", "index_size",
         "signer_key_path", "signer_key_sha256", "url"},
        ("architecture", "url"),
    )
    repo_map: dict[tuple[str, str], dict[str, object]] = {}
    repository_signers: dict[str, str] = {}
    for item in repositories:
        arch = item["architecture"]
        _valid_remote(item["url"], "offline-cache repository")
        if arch not in _OFFLINE_ARCHITECTURES:
            raise LauncherError("offline-cache repository architecture is invalid")
        pair = (str(item["url"]), str(arch))
        if pair in repo_map:
            raise LauncherError("offline-cache repository binding is duplicated")
        prefix = f"work/cache_apk_{arch}"
        expected_index = (
            f"{prefix}/APKINDEX."
            f"{hashlib.sha1(str(item['url']).encode('utf-8'), usedforsecurity=False).hexdigest()[:8]}"
            ".tar.gz"
        )
        if item["index_path"] != expected_index:
            raise LauncherError(
                "offline-cache repository index path does not match its URL"
            )
        bind(item, "index_path", "index_size", "index_sha256", prefix, True)
        signer_path = bind(
            item, "signer_key_path", None, "signer_key_sha256", prefix, False
        )
        signer_parts = PurePosixPath(signer_path).parts
        if (
            len(signer_parts) != 3
            or signer_parts[1] != f"cache_apk_{arch}"
            or not signer_parts[2].endswith(".rsa.pub")
        ):
            raise LauncherError("offline-cache repository signer path is invalid")
        signer_paths.add(signer_path)
        previous_signer = repository_signers.setdefault(
            signer_path, str(item["signer_key_sha256"])
        )
        if previous_signer != item["signer_key_sha256"]:
            raise LauncherError(
                "offline-cache repository signer path has conflicting bytes"
            )
        repo_map[pair] = item
    expected_pairs = {
        (url, arch) for url in _PRODUCTION_REPOSITORY_URLS
        for arch in _OFFLINE_ARCHITECTURES
    }
    if set(repo_map) != expected_pairs:
        raise LauncherError("offline-cache repository URL/architecture set mismatch")

    for item in records(
        "external_apks",
        {"architecture", "apkindex_checksum", "builder_signer", "index_sha256",
         "index_signer_key_path", "index_signer_key_sha256", "name", "path",
         "repository_url", "sha256", "size", "version"},
        ("architecture", "name", "version", "path"),
    ):
        arch = item["architecture"]
        for field in ("name", "version"):
            if not isinstance(item[field], str) or _VERSION_RE.fullmatch(item[field]) is None:
                raise LauncherError(f"offline-cache external APK {field} is invalid")
        if (
            not isinstance(item["builder_signer"], str)
            or _BUILDER_SIGNER_RE.fullmatch(item["builder_signer"]) is None
        ):
            raise LauncherError("offline-cache external APK builder provenance is invalid")
        checksum = item["apkindex_checksum"]
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
            raise LauncherError("offline-cache external APK index checksum is invalid")
        _valid_remote(item["repository_url"], "offline-cache external APK")
        repository = repo_map.get((str(item["repository_url"]), str(arch)))
        if repository is None or (
            item["index_sha256"] != repository["index_sha256"]
            or item["index_signer_key_path"] != repository["signer_key_path"]
            or item["index_signer_key_sha256"] != repository["signer_key_sha256"]
        ):
            raise LauncherError("offline-cache external APK index trust binding mismatch")
        apk_path = bind(
            item, "path", "size", "sha256", f"work/cache_apk_{arch}", True
        )
        apk_parts = PurePosixPath(apk_path).parts
        if (
            len(apk_parts) != 3
            or apk_parts[1] != f"cache_apk_{arch}"
            or not apk_parts[2].endswith(".apk")
        ):
            raise LauncherError(
                "offline-cache external APK path is not a flat APK cache path"
            )
    http_artifacts = records(
        "http_artifacts",
        {"kind", "name", "path", "sha256", "signer_key_path",
         "signer_key_sha256", "size", "url", "version"},
        ("kind", "name", "version", "url", "path"),
    )
    if len(http_artifacts) != 1:
        raise LauncherError(
            "offline-cache manifest must contain exactly one apk-tools-static artifact"
        )
    for item in http_artifacts:
        for field in ("kind", "name", "version"):
            if not isinstance(item[field], str) or _VERSION_RE.fullmatch(item[field]) is None:
                raise LauncherError(f"offline-cache HTTP artifact {field} is invalid")
        if item["kind"] != "apk-tools-static" or item["name"] != "apk-tools-static":
            raise LauncherError("offline-cache HTTP artifact is not apk-tools-static")
        _valid_remote(item["url"], "offline-cache HTTP artifact")
        http_path = bind(item, "path", "size", "sha256", "work/cache_http", True)
        http_parts = PurePosixPath(http_path).parts
        if (
            len(http_parts) != 3
            or http_parts[1] != "cache_http"
            or http_parts[2].startswith("APKINDEX_")
        ):
            raise LauncherError("offline-cache HTTP artifact path is invalid")
        http_signer = bind(
            item, "signer_key_path", None, "signer_key_sha256", None, False
        )
        if repository_signers.get(http_signer) != item["signer_key_sha256"]:
            raise LauncherError(
                "offline-cache HTTP signer is not an existing repository signer"
            )
        signer_paths.add(http_signer)
    distfiles = records(
        "distfiles", {"apkbuild_sha512", "path", "sha256", "size", "url"},
        ("url", "path"),
    )
    if len(distfiles) != 1:
        raise LauncherError(
            "offline-cache manifest must contain exactly one kernel distfile"
        )
    for item in distfiles:
        _valid_remote(item["url"], "offline-cache distfile")
        if not isinstance(item["apkbuild_sha512"], str) or re.fullmatch(
            r"[0-9a-f]{128}", item["apkbuild_sha512"]
        ) is None:
            raise LauncherError("offline-cache distfile APKBUILD SHA512 is invalid")
        distfile_path = bind(
            item, "path", "size", "sha256", "work/cache_distfiles", True
        )
        distfile_parts = PurePosixPath(distfile_path).parts
        if len(distfile_parts) != 3 or distfile_parts[1] != "cache_distfiles":
            raise LauncherError("offline-cache distfile path is not flat")
    if set(classifications) & signer_paths:
        raise LauncherError("offline-cache member has conflicting classifications")
    if set(classifications) | signer_paths != set(actual) - {"work/version"} or any(
        count != 1 for count in classifications.values()
    ):
        raise LauncherError("offline-cache members are not classified exactly once")

    outer_by_path = {str(item["path"]): item for item in outer_members}
    key_fingerprints: dict[str, tuple[object, object]] = {}
    for signer_path in sorted(signer_paths):
        basename = PurePosixPath(signer_path).name
        if not basename.endswith(".rsa.pub") or len(basename.encode("utf-8")) > 255:
            raise LauncherError("offline-cache signer key has an invalid basename")
        cache_member = outer_by_path.get(cache_prefix + signer_path)
        trust_member = outer_by_path.get(
            LAYOUT["pmbootstrap"] + "/pmb/data/keys/" + basename
        )
        if (
            cache_member is None
            or trust_member is None
            or cache_member.get("type") != "file"
            or trust_member.get("type") != "file"
        ):
            raise LauncherError(
                "offline-cache signer key is absent from the pinned pmbootstrap trust root"
            )
        fingerprint = (cache_member.get("size"), cache_member.get("sha256"))
        if fingerprint != (trust_member.get("size"), trust_member.get("sha256")):
            raise LauncherError(
                "offline-cache signer key differs from the pinned pmbootstrap trust root"
            )
        previous = key_fingerprints.setdefault(basename, fingerprint)
        if previous != fingerprint:
            raise LauncherError(
                "offline-cache signer basename has conflicting key material"
            )


def verify_seal_standalone(
    seal_root: Path,
    policy_id: str,
    *,
    seals_root: Path,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> Mapping[str, object]:
    """Verify an exact active V2/V3 seal without importing code from it."""

    seal_root = seal_root.absolute()
    expected_root = seals_root.absolute() / policy_id
    if seal_root != expected_root or _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise LauncherError("seal path is not derived from the active policy id")
    _secure_ancestry(
        seal_root,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    root_metadata = seal_root.lstat()
    if stat.S_IMODE(root_metadata.st_mode) != 0o700:
        raise LauncherError("seal root must have mode 0700")
    manifest_path = seal_root / MANIFEST_NAME
    metadata = _secure_regular(
        manifest_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        exact_mode=0o600,
    )
    payload = _read_stable(manifest_path, metadata, _MAX_MANIFEST_BYTES)
    if hashlib.sha256(payload).hexdigest() != policy_id:
        raise LauncherError("active policy does not match the exact manifest bytes")
    manifest, expected_members = _validated_manifest(payload)
    expected_top = {MANIFEST_NAME, *LAYOUT.values()}
    try:
        actual_top = {entry.name for entry in os.scandir(seal_root)}
    except OSError as error:
        raise LauncherError(f"could not enumerate seal root: {error}") from None
    if actual_top != expected_top:
        raise LauncherError("seal contains missing or extra top-level members")
    non_directory_inodes: dict[tuple[int, int], str] = {}
    actual_members: list[dict[str, object]] = []
    for label, relative in sorted(LAYOUT.items(), key=lambda item: item[1]):
        path = seal_root / relative
        try:
            item_metadata = path.lstat()
        except OSError as error:
            raise LauncherError(f"seal is missing {label}: {error}") from None
        if (label in _DIRECTORY_INPUTS) != stat.S_ISDIR(item_metadata.st_mode):
            raise LauncherError(f"sealed {label} has the wrong type")
        actual_members.extend(
            _inventory(
                path,
                relative,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
                non_directory_inodes=non_directory_inodes,
            )
        )
    actual_members.sort(key=lambda item: str(item["path"]))
    _validate_symlink_graph(actual_members)
    if actual_members != expected_members:
        raise LauncherError("seal inventory does not exactly match its manifest")
    source_lock_path = seal_root / LAYOUT["source_lock"]
    source_lock_metadata = _secure_regular(
        source_lock_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    source_lock_payload = _read_stable(
        source_lock_path, source_lock_metadata, _MAX_SOURCE_LOCK_BYTES
    )
    _validate_source_lock(source_lock_payload, manifest["provenance"])
    offline_manifest_path = (
        seal_root / LAYOUT["offline_cache"] / OFFLINE_CACHE_MANIFEST_NAME
    )
    offline_manifest_metadata = _secure_regular(
        offline_manifest_path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    offline_manifest_payload = _read_stable(
        offline_manifest_path,
        offline_manifest_metadata,
        _MAX_OFFLINE_CACHE_MANIFEST_BYTES,
    )
    _validate_offline_contract(
        offline_manifest_payload, expected_members, manifest["provenance"]
    )
    return manifest


def _verify_launcher_install(
    configured: Path,
    executing: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    configured = configured.absolute()
    executing = executing.absolute()
    if executing != configured:
        raise LauncherError("launcher is not running from its fixed installed path")
    _secure_ancestry(
        configured.parent,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    metadata = _secure_regular(
        configured,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
        exact_mode=0o755,
    )
    if not metadata.st_mode & stat.S_IXUSR:
        raise LauncherError("installed launcher is not executable")


def _secure_private_directory(
    path: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> None:
    _secure_ancestry(
        path,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(path.lstat().st_mode) != 0o700:
        raise LauncherError(f"private root must have mode 0700: {path}")


def _create_run(
    runs_root: Path,
    *,
    trusted_root: Path,
    expected_uid: int,
    expected_gid: int,
) -> Path:
    _secure_private_directory(
        runs_root,
        trusted_root=trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    for _attempt in range(32):
        candidate = runs_root / f"run-{secrets.token_hex(16)}"
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except OSError as error:
            raise LauncherError(f"could not create private build run: {error}") from None
        metadata = candidate.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or _xattrs(candidate)
        ):
            raise LauncherError("new build run is not a private trusted directory")
        return candidate
    raise LauncherError("could not allocate a unique build run")


def _write_request(
    path: Path,
    request: Mapping[str, object],
    *,
    expected_uid: int,
    expected_gid: int,
) -> None:
    payload = canonical_json_bytes(request)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        metadata = path.lstat()
    except OSError as error:
        raise LauncherError(f"could not persist root-owned request: {error}") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != expected_uid
        or metadata.st_gid != expected_gid
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or _xattrs(path)
    ):
        raise LauncherError("persisted build request is not a private trusted file")


def _exec_environment(run_root: Path) -> dict[str, str]:
    return {
        "GIT_ALLOW_PROTOCOL": "file",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(run_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "LOGNAME": "root",
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "SHELL": "/bin/sh",
        "TERM": "dumb",
        "TMPDIR": str(run_root / "tmp"),
        "TZ": "UTC",
        "USER": "root",
    }


def _close_inherited_fds() -> None:
    """Close every caller-supplied descriptor at or above 3."""

    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        soft, _hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if soft == resource.RLIM_INFINITY:
            soft = int(os.sysconf("SC_OPEN_MAX"))
        os.closerange(3, int(soft))
        return
    for name in names:
        try:
            descriptor = int(name)
        except ValueError:
            continue
        if descriptor >= 3:
            try:
                os.close(descriptor)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise LauncherError(
                        f"could not close inherited descriptor {descriptor}: {error}"
                    ) from None


def _normalize_signals() -> None:
    try:
        valid = signal.valid_signals()
        for number in valid:
            if number not in {signal.SIGKILL, signal.SIGSTOP}:
                signal.signal(number, signal.SIG_DFL)
        if hasattr(signal, "pthread_sigmask"):
            signal.pthread_sigmask(signal.SIG_SETMASK, [])
    except (OSError, ValueError) as error:
        raise LauncherError(f"could not normalize process signals: {error}") from None


def _normalize_rlimits() -> None:
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        desired = min(4096, hard) if hard != resource.RLIM_INFINITY else 4096
        resource.setrlimit(resource.RLIMIT_NOFILE, (desired, desired))
    except (OSError, ValueError) as error:
        raise LauncherError(f"could not apply launcher resource limits: {error}") from None


def _normalize_stdin() -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open("/dev/null", flags)
        try:
            os.dup2(descriptor, 0, inheritable=True)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise LauncherError(f"could not replace standard input: {error}") from None


def _fd_mount_id(descriptor: int) -> int:
    """Return Linux's mount ID for an already-open descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fdinfo = f"/proc/self/fdinfo/{descriptor}"
    try:
        info_fd = os.open(fdinfo, flags)
        try:
            payload = os.read(info_fd, 16 * 1024)
        finally:
            os.close(info_fd)
    except OSError as error:
        raise LauncherError(
            f"could not inspect mount identity for {fdinfo}: {error}"
        ) from None
    match = re.search(rb"^mnt_id:\s*([0-9]+)\s*$", payload, flags=re.MULTILINE)
    if match is None:
        raise LauncherError(f"mount identity is unavailable for {fdinfo}")
    return int(match.group(1))


def _same_inode(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _walk_run_tree(
    directory_fd: int,
    display_path: Path,
    *,
    root_device: int,
    root_mount_id: int,
    expected_uid: int,
    expected_gid: int,
    delete: bool,
) -> None:
    """Validate, and optionally delete, one already-open run directory tree."""

    if not hasattr(os, "O_PATH"):
        raise LauncherError("safe run cleanup requires Linux O_PATH support")
    if delete:
        directory_metadata = os.fstat(directory_fd)
        desired_mode = stat.S_IMODE(directory_metadata.st_mode) | 0o700
        if stat.S_IMODE(directory_metadata.st_mode) != desired_mode:
            os.fchmod(directory_fd, desired_mode)

    for name in sorted(os.listdir(directory_fd)):
        if not name or name in {".", ".."} or "/" in name:
            raise LauncherError(f"refusing to remove unsafe run member name: {name!r}")
        child_path = display_path / name
        inspect_flags = os.O_PATH | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        child_fd = os.open(name, inspect_flags, dir_fd=directory_fd)
        try:
            metadata = os.fstat(child_fd)
            if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
                raise LauncherError(
                    f"refusing to remove foreign-owned run member: {child_path}"
                )
            if (
                metadata.st_dev != root_device
                or _fd_mount_id(child_fd) != root_mount_id
            ):
                raise LauncherError(
                    f"refusing to cross a mount boundary at: {child_path}"
                )

            if stat.S_ISDIR(metadata.st_mode):
                flags = (
                    os.O_RDONLY
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW
                    | getattr(os, "O_CLOEXEC", 0)
                )
                nested_fd = os.open(name, flags, dir_fd=directory_fd)
                try:
                    nested_metadata = os.fstat(nested_fd)
                    if not _same_inode(metadata, nested_metadata):
                        raise LauncherError(
                            f"run member changed during cleanup: {child_path}"
                        )
                    if _fd_mount_id(nested_fd) != root_mount_id:
                        raise LauncherError(
                            f"refusing to cross a mount boundary at: {child_path}"
                        )
                    _walk_run_tree(
                        nested_fd,
                        child_path,
                        root_device=root_device,
                        root_mount_id=root_mount_id,
                        expected_uid=expected_uid,
                        expected_gid=expected_gid,
                        delete=delete,
                    )
                    if delete:
                        current = os.stat(
                            name,
                            dir_fd=directory_fd,
                            follow_symlinks=False,
                        )
                        if not stat.S_ISDIR(current.st_mode) or not _same_inode(
                            nested_metadata, current
                        ):
                            raise LauncherError(
                                f"run member changed during cleanup: {child_path}"
                            )
                        os.rmdir(name, dir_fd=directory_fd)
                finally:
                    os.close(nested_fd)
            elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                if metadata.st_nlink != 1:
                    raise LauncherError(
                        f"refusing to remove hardlinked run member: {child_path}"
                    )
                if delete:
                    current = os.stat(
                        name,
                        dir_fd=directory_fd,
                        follow_symlinks=False,
                    )
                    if _identity(metadata) != _identity(current):
                        raise LauncherError(
                            f"run member changed during cleanup: {child_path}"
                        )
                    os.unlink(name, dir_fd=directory_fd)
            else:
                raise LauncherError(
                    f"refusing to remove unsupported run member: {child_path}"
                )
        finally:
            os.close(child_fd)


def _remove_run(path: Path, *, expected_uid: int, expected_gid: int) -> None:
    """Safely remove a validated private run without following its members."""

    if re.fullmatch(r"run-[0-9a-f]{32}", path.name) is None:
        raise LauncherError(f"refusing to remove unsafe run path: {path}")
    parent_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    parent_fd: int | None = None
    run_fd: int | None = None
    try:
        parent_fd = os.open(path.parent, parent_flags)
        parent_metadata = os.fstat(parent_fd)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != expected_uid
            or parent_metadata.st_gid != expected_gid
            or stat.S_IMODE(parent_metadata.st_mode) != 0o700
        ):
            raise LauncherError(
                f"refusing to remove a run below an unsafe root: {path}"
            )
        parent_mount_id = _fd_mount_id(parent_fd)
        run_fd = os.open(path.name, parent_flags, dir_fd=parent_fd)
        metadata = os.fstat(run_fd)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != expected_uid
            or metadata.st_gid != expected_gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
            or metadata.st_dev != parent_metadata.st_dev
            or _fd_mount_id(run_fd) != parent_mount_id
        ):
            raise LauncherError(f"refusing to remove unsafe run path: {path}")

        walk_arguments = {
            "root_device": metadata.st_dev,
            "root_mount_id": parent_mount_id,
            "expected_uid": expected_uid,
            "expected_gid": expected_gid,
        }
        _walk_run_tree(run_fd, path, delete=False, **walk_arguments)
        _walk_run_tree(run_fd, path, delete=True, **walk_arguments)
        current = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or not _same_inode(metadata, current):
            raise LauncherError(f"run path changed during cleanup: {path}")
        os.rmdir(path.name, dir_fd=parent_fd)
    except LauncherError:
        raise
    except OSError as error:
        raise LauncherError(f"could not safely remove run {path}: {error}") from None
    finally:
        if run_fd is not None:
            os.close(run_fd)
        if parent_fd is not None:
            os.close(parent_fd)


def _prune_runs(runs_root: Path, *, expected_uid: int, expected_gid: int) -> None:
    candidates: list[tuple[int, Path]] = []
    for entry in os.scandir(runs_root):
        if not re.fullmatch(r"run-[0-9a-f]{32}", entry.name):
            raise LauncherError(f"runs root contains an unexpected member: {entry.name}")
        path = Path(entry.path)
        metadata = path.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise LauncherError(f"runs root member is not a real directory: {path}")
        candidates.append((metadata.st_mtime_ns, path))
    candidates.sort(key=lambda item: (item[0], item[1].name), reverse=True)
    for _timestamp, path in candidates[max(0, _RETAIN_RUNS - 1) :]:
        _remove_run(path, expected_uid=expected_uid, expected_gid=expected_gid)


def _acquire_run_lock(runs_root: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(runs_root, flags)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.set_inheritable(descriptor, True)
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        if error.errno in {errno.EACCES, errno.EAGAIN}:
            raise LauncherError("another sealed build is already running") from None
        raise LauncherError(f"could not acquire the sealed-build lock: {error}") from None
    return descriptor


def launch(
    *,
    request_fd: int = _REQUEST_FD,
    paths: LauncherPaths = DEFAULT_PATHS,
    expected_uid: int = 0,
    expected_gid: int = 0,
    executing_path: Path | None = None,
    executing_interpreter: Path | None = None,
    getresuid: Callable[[], tuple[int, int, int]] | None = None,
    getresgid: Callable[[], tuple[int, int, int]] | None = None,
    setgroups: Callable[[list[int]], object] = os.setgroups,
    getgroups: Callable[[], list[int]] = os.getgroups,
    set_umask: Callable[[int], int] = os.umask,
    read_request: Callable[[int], dict[str, object]] = parse_request_fd,
    close_fds: Callable[[], object] = _close_inherited_fds,
    normalize_signals: Callable[[], object] = _normalize_signals,
    normalize_rlimits: Callable[[], object] = _normalize_rlimits,
    normalize_stdin: Callable[[], object] = _normalize_stdin,
    change_directory: Callable[[str], object] = os.chdir,
    execve: Callable[[str, list[str], Mapping[str, str]], object] = os.execve,
) -> NoReturn:
    """Verify the root boundary, persist the request, and replace this process."""

    if getresuid is None:
        getresuid = getattr(os, "getresuid", None)
    if getresgid is None:
        getresgid = getattr(os, "getresgid", None)
    if getresuid is None or getresgid is None:
        raise LauncherError("platform cannot verify real/effective/saved IDs")
    try:
        uids = tuple(getresuid())
        gids = tuple(getresgid())
    except OSError as error:
        raise LauncherError(f"could not inspect process IDs: {error}") from None
    if uids != (expected_uid, expected_uid, expected_uid):
        raise LauncherError("launcher requires trusted real/effective/saved UIDs")
    if gids != (expected_gid, expected_gid, expected_gid):
        raise LauncherError("launcher requires trusted real/effective/saved GIDs")
    try:
        setgroups([])
    except OSError as error:
        raise LauncherError(f"could not clear supplementary groups: {error}") from None
    if getgroups():
        raise LauncherError("supplementary groups were not cleared")
    set_umask(0o077)
    if request_fd != _REQUEST_FD:
        raise LauncherError("launcher request must be supplied on fixed stdin fd 0")
    if executing_path is None:
        executing_path = Path(__file__)
    _verify_launcher_install(
        paths.launcher,
        executing_path,
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    request = read_request(request_fd)
    close_fds()
    _secure_private_directory(
        paths.active.parent,
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    active_policy = _read_active(
        paths.active,
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if request["policy_id"] != active_policy:
        raise LauncherError("request policy is not the active root-owned policy")
    _secure_private_directory(
        paths.runs,
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    lock_fd = _acquire_run_lock(paths.runs)
    try:
        _secure_private_directory(
            paths.seals,
            trusted_root=paths.trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        seal_root = paths.seals / active_policy
        manifest = verify_seal_standalone(
            seal_root,
            active_policy,
            seals_root=paths.seals,
            trusted_root=paths.trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if type(manifest["provenance"]["generation"]) is not int:
            raise LauncherError("active seal generation is not an integer")

        cli = seal_root / LAYOUT["project"] / "scripts/lmi_p1_cli.py"
        _secure_regular(
            cli,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        python_target = _pinned_python_target(
            paths.python,
            paths.python_pin,
            trusted_root=paths.trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        if executing_interpreter is None:
            executing_interpreter = Path(sys.executable)
        if executing_interpreter.absolute() != paths.python.absolute():
            raise LauncherError("launcher is not running under fixed /usr/bin/python3")
    except BaseException:
        os.close(lock_fd)
        raise
    run_root: Path | None = None
    try:
        _prune_runs(
            paths.runs,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        run_root = _create_run(
            paths.runs,
            trusted_root=paths.trusted_root,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        temporary = run_root / "tmp"
        temporary.mkdir(mode=0o700)
        home = run_root / "home"
        home.mkdir(mode=0o700)
        for private in (temporary, home):
            _secure_private_directory(
                private,
                trusted_root=run_root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        request_copy = run_root / "request.json"
        _write_request(
            request_copy,
            request,
            expected_uid=expected_uid,
            expected_gid=expected_gid,
        )
        change_directory(str(run_root))
        normalize_signals()
        normalize_rlimits()
        normalize_stdin()
        argv = [
            str(python_target),
            "-I",
            "-S",
            "-B",
            "-c",
            _CLI_BOOTSTRAP,
            str(cli.parent),
            str(cli),
            "build-sealed",
            "--request",
            str(request_copy),
        ]
        environment = _exec_environment(run_root)
        execve(str(python_target), argv, environment)
    except OSError as error:
        if run_root is not None:
            _remove_run(
                run_root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        os.close(lock_fd)
        raise LauncherError(f"could not prepare or execute sealed build: {error}") from None
    except LauncherError:
        if run_root is not None:
            _remove_run(
                run_root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        os.close(lock_fd)
        raise
    except BaseException:
        os.close(lock_fd)
        raise
    raise LauncherError("execve unexpectedly returned")


def main() -> int:
    try:
        if sys.argv[1:]:
            raise LauncherError("launcher accepts no command-line arguments")
        if not (
            sys.flags.isolated
            and sys.flags.no_site
            and sys.flags.dont_write_bytecode
            and sys.flags.ignore_environment
        ):
            raise LauncherError("launcher requires Python flags -I -S -B")
        launch(request_fd=_REQUEST_FD)
    except LauncherError as error:
        sys.stderr.write(f"lmi-p1 root launcher rejected request: {error}\n")
        return 1
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
