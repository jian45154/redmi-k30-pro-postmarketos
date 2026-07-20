"""Curate downloaded P1 material into a promotion-only offline acquisition.

This module never downloads, executes an APK, touches hardware, or publishes a
release cache.  Its output is the exact five-entry input layout consumed by
``offline_cache.promote_offline_cache``. Cryptographic index verification,
repository-package identity authentication against those verified indexes,
independent bootstrap-APK signature verification, and creation of
``offline-cache.manifest.json`` remain promotion responsibilities. Package
builder signer names are parsed for structural safety but are not repository
authorization.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tarfile
import tempfile
from typing import Mapping
import zlib

from .common import GateError
from .offline_cache import (
    ARCHITECTURES,
    PromotionProfile,
    canonical_json_bytes,
    load_promotion_profile,
)


_SOURCE_WORK = PurePosixPath("work-proot-chroot2")
_CLOSURE_DIRECTORIES = {
    "aarch64": PurePosixPath("fetched-aarch64-closure"),
    "x86_64": PurePosixPath("fetched-x86_64-closure"),
}
_OUTPUT_DIRECTORIES = (
    "cache_apk_aarch64",
    "cache_apk_x86_64",
    "cache_distfiles",
    "cache_http",
)
_EXCLUDED_AARCH64_PACKAGES = frozenset(
    {
        ("device-xiaomi-lmi", "1-r107"),
        ("linux-xiaomi-lmi", "4.19.325-r8"),
        ("postmarketos-initramfs", "3.12.0-r0"),
    }
)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}$")
_CACHE_APK_RE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}-"
    r"[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}\.([0-9a-f]{8})\.apk$"
)
_MAX_APK_BYTES = 512 * 1024 * 1024
_MAX_INDEXED_APK_BYTES = 4 * 1024 * 1024 * 1024
_MAX_INDEX_BYTES = 64 * 1024 * 1024
_MAX_INDEX_TEXT_BYTES = 64 * 1024 * 1024
_MAX_CONTROL_BYTES = 8 * 1024 * 1024
_MAX_CLOSURE_PACKAGES = 16_384
_MAX_INDEX_PACKAGES = 131_072
_MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
@dataclass(frozen=True, order=True)
class _PackageIdentity:
    name: str
    version: str
    architecture: str


@dataclass(frozen=True)
class _IndexPackage:
    identity: _PackageIdentity
    checksum: bytes
    size: int
    repository: Mapping[str, object]


@dataclass(frozen=True)
class _SourceRecord:
    path: Path
    identity: tuple[int, ...]
    size: int
    sha256: str


@dataclass(frozen=True)
class _CopyPlan:
    source: _SourceRecord
    destination: PurePosixPath


@dataclass(frozen=True)
class _StagingOutput:
    path: Path
    identity: tuple[int, int, int, int, int]


@dataclass(frozen=True)
class CuratedAcquisition:
    """A verified, promotion-only acquisition layout."""

    root: Path
    aarch64_packages: int
    x86_64_packages: int
    excluded_aarch64_packages: tuple[str, ...]
    members: int
    inventory_sha256: str


def _metadata_identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _directory_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _absolute_real_directory(
    path: Path, *, label: str, expected_uid: int, expected_gid: int
) -> Path:
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise GateError(f"{label} must be an explicit normalized absolute path")
    try:
        resolved = path.resolve(strict=True)
        metadata = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if resolved != path or not stat.S_ISDIR(metadata.st_mode):
        raise GateError(f"{label} must be one real directory without symlinks")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise GateError(f"{label} crosses the expected owner boundary")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise GateError(f"{label} must not be group/world writable")
    return path


def _require_secure_directory(
    path: Path, *, label: str, expected_uid: int, expected_gid: int
) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if not stat.S_ISDIR(metadata.st_mode):
        raise GateError(f"{label} must be a real directory")
    if metadata.st_uid != expected_uid or metadata.st_gid != expected_gid:
        raise GateError(f"{label} crosses the expected owner boundary")
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise GateError(f"{label} must not be group/world writable")


def _open_relative_parent(
    root: Path,
    path: Path,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[int, str]:
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise GateError(f"acquisition source escapes its root: {path}") from None
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise GateError(f"acquisition source has unsafe path components: {path}")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        current = os.open(root, flags)
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, flags, dir_fd=current)
            finally:
                os.close(current)
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != expected_uid
                or metadata.st_gid != expected_gid
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise GateError(f"acquisition source has an unsafe directory: {path}")
            current = child
        return current, relative.parts[-1]
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not open no-follow ancestry for {path}: {error}") from None


def _read_stable_regular(
    root: Path,
    path: Path,
    *,
    label: str,
    maximum: int,
    expected_uid: int,
    expected_gid: int,
) -> tuple[_SourceRecord, bytes]:
    parent_fd, name = _open_relative_parent(
        root,
        path,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        os.close(parent_fd)
        raise GateError(f"could not inspect {label}: {error}") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        os.close(parent_fd)
        raise GateError(f"{label} must be one real, single-link regular file")
    if before.st_uid != expected_uid or before.st_gid != expected_gid:
        os.close(parent_fd)
        raise GateError(f"{label} crosses the expected owner boundary")
    if stat.S_IMODE(before.st_mode) & 0o022:
        os.close(parent_fd)
        raise GateError(f"{label} must not be group/world writable")
    if before.st_size < 0 or before.st_size > maximum:
        os.close(parent_fd)
        raise GateError(f"{label} exceeds its size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum + 1)
            finished = os.fstat(stream.fileno())
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise GateError(f"could not read {label}: {error}") from None
    finally:
        os.close(parent_fd)
    expected = _metadata_identity(before)
    if not (
        expected
        == _metadata_identity(opened)
        == _metadata_identity(finished)
        == _metadata_identity(after)
    ):
        raise GateError(f"{label} changed while it was being validated")
    if len(payload) != before.st_size or len(payload) > maximum:
        raise GateError(f"{label} changed size while it was being validated")
    return (
        _SourceRecord(path, expected, before.st_size, hashlib.sha256(payload).hexdigest()),
        payload,
    )


def _register_inode(
    record: _SourceRecord,
    seen: dict[tuple[int, int], Path],
) -> None:
    inode = (record.identity[0], record.identity[1])
    previous = seen.setdefault(inode, record.path)
    if previous != record.path:
        raise GateError(f"acquisition source is hardlinked to {previous}: {record.path}")


def _safe_tar_name(name: str, *, label: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise GateError(f"{label} contains an unsafe archive path: {name!r}")


def _signature_basename(names: tuple[str, ...], *, label: str) -> str:
    signatures: list[str] = []
    for name in names:
        for prefix in (".SIGN.RSA.sha256.", ".SIGN.RSA."):
            if name.startswith(prefix):
                signatures.append(name[len(prefix) :])
                break
    if (
        len(signatures) != 1
        or not signatures[0]
        or "/" in signatures[0]
        or "\\" in signatures[0]
    ):
        raise GateError(f"{label} has an ambiguous signature member")
    return signatures[0]


def _tar_members(
    payload: bytes, *, mode: str, label: str, maximum_members: int
) -> tuple[tarfile.TarFile, list[tarfile.TarInfo]]:
    try:
        archive = tarfile.open(fileobj=io.BytesIO(payload), mode=mode)
        members = archive.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise GateError(f"could not parse {label}: {error}") from None
    if not members or len(members) > maximum_members:
        archive.close()
        raise GateError(f"{label} has an invalid archive member count")
    seen: set[str] = set()
    for member in members:
        _safe_tar_name(member.name, label=label)
        if member.name in seen:
            archive.close()
            raise GateError(f"{label} repeats archive member {member.name!r}")
        seen.add(member.name)
        if member.issym() or member.islnk() or member.isdev() or member.isfifo():
            archive.close()
            raise GateError(f"{label} contains a nonregular archive member")
    return archive, members


def _required_tar_payload(
    archive: tarfile.TarFile,
    members: list[tarfile.TarInfo],
    name: str,
    *,
    label: str,
    maximum: int,
) -> bytes:
    selected = [member for member in members if member.name == name]
    if len(selected) != 1 or not selected[0].isreg():
        raise GateError(f"{label} does not contain exactly one regular {name}")
    if selected[0].size < 0 or selected[0].size > maximum:
        raise GateError(f"{label} {name} exceeds its size limit")
    stream = archive.extractfile(selected[0])
    if stream is None:
        raise GateError(f"could not read {label} {name}")
    with stream:
        payload = stream.read(maximum + 1)
    if len(payload) != selected[0].size or len(payload) > maximum:
        raise GateError(f"{label} {name} is truncated or oversized")
    return payload


def _token(value: str, *, label: str) -> str:
    if _TOKEN_RE.fullmatch(value) is None:
        raise GateError(f"{label} is not a safe package token")
    return value


def _q1_checksum(value: str, *, label: str) -> bytes:
    if not value.startswith("Q1"):
        raise GateError(f"{label} is not an APK SHA1 data checksum")
    try:
        decoded = base64.b64decode(value[2:], validate=True)
    except (ValueError, base64.binascii.Error):
        raise GateError(f"{label} has invalid base64") from None
    if len(decoded) != hashlib.sha1().digest_size:
        raise GateError(f"{label} has an invalid SHA1 length")
    return decoded


def _parse_index(
    payload: bytes, repository: Mapping[str, object]
) -> tuple[_IndexPackage, ...]:
    label = f"pinned APKINDEX {repository['index_path']}"
    archive, members = _tar_members(
        payload, mode="r:*", label=label, maximum_members=16
    )
    try:
        expected_signer = PurePosixPath(str(repository["signer_key_path"])).name
        actual_signer = _signature_basename(
            tuple(member.name for member in members), label=label
        )
        if actual_signer != expected_signer:
            raise GateError(f"{label} signer basename differs from the canonical profile")
        index_payload = _required_tar_payload(
            archive,
            members,
            "APKINDEX",
            label=label,
            maximum=_MAX_INDEX_TEXT_BYTES,
        )
    finally:
        archive.close()
    try:
        text = index_payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise GateError(f"{label} metadata is not UTF-8: {error}") from None
    result: list[_IndexPackage] = []
    seen: set[_PackageIdentity] = set()
    for number, block in enumerate(text.split("\n\n"), 1):
        if not block:
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ":":
                raise GateError(f"{label} block {number} contains malformed metadata")
            key = line[0]
            if key not in {"A", "C", "P", "S", "V"}:
                continue
            if key in fields:
                raise GateError(f"{label} block {number} repeats field {key}")
            fields[key] = line[2:]
        if set(fields) != {"A", "C", "P", "S", "V"}:
            raise GateError(f"{label} block {number} lacks required package fields")
        identity = _PackageIdentity(
            _token(fields["P"], label=f"{label} package name"),
            _token(fields["V"], label=f"{label} package version"),
            _token(fields["A"], label=f"{label} package architecture"),
        )
        if identity.architecture not in {repository["architecture"], "noarch"}:
            raise GateError(f"{label} contains an architecture-mismatched package")
        if identity in seen:
            raise GateError(f"{label} contains a duplicate package identity: {identity}")
        seen.add(identity)
        try:
            size = int(fields["S"], 10)
        except ValueError:
            raise GateError(f"{label} block {number} has an invalid package size") from None
        if size <= 0 or size > _MAX_INDEXED_APK_BYTES or str(size) != fields["S"]:
            raise GateError(f"{label} block {number} has a noncanonical package size")
        result.append(
            _IndexPackage(
                identity,
                _q1_checksum(fields["C"], label=f"{label} block {number} C:Q1"),
                size,
                repository,
            )
        )
    if not result or len(result) > _MAX_INDEX_PACKAGES:
        raise GateError(f"{label} has an invalid package record count")
    return tuple(result)


def _gzip_member(
    payload: bytes, offset: int, *, label: str, maximum: int
) -> tuple[bytes, bytes, int]:
    if offset >= len(payload):
        raise GateError(f"{label} is missing a required gzip member")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    remaining = payload[offset:]
    try:
        expanded = decompressor.decompress(remaining, maximum + 1)
        if decompressor.unconsumed_tail or len(expanded) > maximum:
            raise GateError(f"{label} gzip member exceeds its expansion limit")
        expanded += decompressor.flush(maximum + 1 - len(expanded))
    except zlib.error as error:
        raise GateError(f"{label} has a malformed gzip member: {error}") from None
    if not decompressor.eof or len(expanded) > maximum:
        raise GateError(f"{label} has a truncated or oversized gzip member")
    consumed = len(remaining) - len(decompressor.unused_data)
    if consumed <= 0:
        raise GateError(f"{label} has an empty gzip member")
    return expanded, payload[offset : offset + consumed], offset + consumed


def _parse_apk(payload: bytes, *, label: str) -> tuple[_PackageIdentity, bytes, str]:
    signature_tar, _signature_raw, offset = _gzip_member(
        payload, 0, label=label, maximum=_MAX_CONTROL_BYTES
    )
    control_tar, control_raw, _offset = _gzip_member(
        payload, offset, label=label, maximum=_MAX_CONTROL_BYTES
    )
    signature_archive, signature_members = _tar_members(
        signature_tar, mode="r:", label=f"{label} signature", maximum_members=8
    )
    try:
        signer = _signature_basename(
            tuple(member.name for member in signature_members),
            label=f"{label} signature",
        )
        _token(signer, label=f"{label} builder signer")
    finally:
        signature_archive.close()
    control_archive, control_members = _tar_members(
        control_tar, mode="r:", label=f"{label} control", maximum_members=128
    )
    try:
        pkginfo = _required_tar_payload(
            control_archive,
            control_members,
            ".PKGINFO",
            label=f"{label} control",
            maximum=_MAX_CONTROL_BYTES,
        )
    finally:
        control_archive.close()
    try:
        text = pkginfo.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise GateError(f"{label} .PKGINFO is not UTF-8: {error}") from None
    fields: dict[str, str] = {}
    wanted = {"arch", "pkgname", "pkgver"}
    for line in text.splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key not in wanted:
            continue
        if key in fields:
            raise GateError(f"{label} repeats .PKGINFO field {key}")
        fields[key] = value
    if set(fields) != wanted:
        raise GateError(f"{label} lacks required .PKGINFO identity fields")
    identity = _PackageIdentity(
        _token(fields["pkgname"], label=f"{label} package name"),
        _token(fields["pkgver"], label=f"{label} package version"),
        _token(fields["arch"], label=f"{label} package architecture"),
    )
    return identity, hashlib.sha1(control_raw, usedforsecurity=False).digest(), signer


def _source_path_for_profile(root: Path, relative: object, *, label: str) -> Path:
    path = PurePosixPath(str(relative))
    if path.is_absolute() or len(path.parts) < 2 or path.parts[0] != "work":
        raise GateError(f"{label} is not a canonical work path")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise GateError(f"{label} contains path traversal")
    return root.joinpath(*_SOURCE_WORK.parts, *path.parts[1:])


def _profile_destination(relative: object, *, label: str) -> PurePosixPath:
    path = PurePosixPath(str(relative))
    if path.is_absolute() or len(path.parts) != 3 or path.parts[0] != "work":
        raise GateError(f"{label} is not a direct canonical cache member")
    if path.parts[1] not in _OUTPUT_DIRECTORIES:
        raise GateError(f"{label} names an unsupported cache directory")
    return PurePosixPath(*path.parts[1:])


def _closure_entries(
    root: Path,
    architecture: str,
    *,
    expected_uid: int,
    expected_gid: int,
) -> tuple[Path, ...]:
    directory = root.joinpath(*_CLOSURE_DIRECTORIES[architecture].parts)
    _require_secure_directory(
        directory,
        label=f"exact {architecture} closure directory",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    try:
        entries = sorted(os.scandir(directory), key=lambda item: item.name)
    except OSError as error:
        raise GateError(f"could not enumerate exact {architecture} closure: {error}") from None
    if not entries or len(entries) > _MAX_CLOSURE_PACKAGES:
        raise GateError(f"exact {architecture} closure has an invalid package count")
    result: list[Path] = []
    for entry in entries:
        if not entry.name.endswith(".apk") or "/" in entry.name or "\\" in entry.name:
            raise GateError(
                f"exact {architecture} closure contains an extra non-APK entry: {entry.name!r}"
            )
        try:
            metadata = entry.stat(follow_symlinks=False)
        except OSError as error:
            raise GateError(f"could not inspect exact closure entry {entry.name}: {error}") from None
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise GateError(
                f"exact {architecture} closure entry is not one single-link regular file: {entry.name}"
            )
        result.append(directory / entry.name)
    return tuple(result)


def _write_member(path: Path, payload: bytes) -> dict[str, object]:
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
        path.chmod(0o600)
        metadata = path.lstat()
    except OSError as error:
        raise GateError(f"could not write curated acquisition member {path}: {error}") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GateError(f"curated acquisition member is not a single-link regular file: {path}")
    return {
        "path": path,
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise GateError(f"could not fsync curated acquisition directory {path}: {error}") from None


def _prepare_output(
    output: Path, *, expected_uid: int, expected_gid: int
) -> _StagingOutput:
    output = Path(output)
    if not output.is_absolute() or output != Path(os.path.normpath(output)):
        raise GateError("curated acquisition output must be an explicit normalized absolute path")
    parent = _absolute_real_directory(
        output.parent,
        label="curated acquisition output parent",
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if output.exists() or output.is_symlink():
        raise GateError("curated acquisition output must be a new absent path")
    staging_output: _StagingOutput | None = None
    try:
        staging = Path(
            tempfile.mkdtemp(
                prefix=f".{output.name}.curation-",
                dir=parent,
            )
        )
        staging_output = _StagingOutput(
            staging, _directory_identity(staging.lstat())
        )
        staging.chmod(0o700)
        staging_output = _StagingOutput(
            staging, _directory_identity(staging.lstat())
        )
        for name in _OUTPUT_DIRECTORIES:
            directory = staging / name
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
    except OSError as error:
        if staging_output is not None:
            _discard_staging(staging_output)
        raise GateError(f"could not create curated acquisition output: {error}") from None
    return staging_output


def _discard_staging(staging: _StagingOutput) -> None:
    path = staging.path
    try:
        metadata = path.lstat()
        if (
            _directory_identity(metadata) != staging.identity
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise GateError("curated acquisition staging directory changed unexpectedly")
        shutil.rmtree(path)
    except FileNotFoundError:
        return
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not discard failed curated acquisition staging: {error}") from None


def curate_offline_cache_acquisition(
    acquisition_root: Path,
    output: Path,
    profile_path: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
) -> CuratedAcquisition:
    """Build a deterministic, promotion-only cache acquisition.

    The canonical profile is always read from ``profile_path``.  Both target
    architectures require independent ``fetched-*-closure`` directories; a
    mutable pmbootstrap cache is deliberately not accepted as closure proof.
    ``output`` must be absent and is created only after every input validates.
    """

    uid = os.geteuid() if expected_uid is None else expected_uid
    gid = os.getegid() if expected_gid is None else expected_gid
    profile: PromotionProfile = load_promotion_profile(Path(profile_path))
    root = _absolute_real_directory(
        Path(acquisition_root),
        label="offline acquisition source root",
        expected_uid=uid,
        expected_gid=gid,
    )

    missing_evidence: list[str] = []
    for architecture in sorted(ARCHITECTURES):
        path = root.joinpath(*_CLOSURE_DIRECTORIES[architecture].parts)
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            missing_evidence.append(
                f"{architecture} APK closure directory ({_CLOSURE_DIRECTORIES[architecture]})"
            )
            continue
        except OSError as error:
            raise GateError(f"could not inspect {architecture} closure evidence: {error}") from None
        if not stat.S_ISDIR(metadata.st_mode):
            missing_evidence.append(
                f"{architecture} APK closure directory ({_CLOSURE_DIRECTORIES[architecture]})"
            )
    if missing_evidence:
        raise GateError(
            "acquisition is missing exact closure evidence: " + "; ".join(missing_evidence)
        )

    seen_inodes: dict[tuple[int, int], Path] = {}
    plans: list[_CopyPlan] = []
    destinations: set[PurePosixPath] = set()
    indexes: dict[str, dict[tuple[str, str], list[_IndexPackage]]] = {
        architecture: {} for architecture in ARCHITECTURES
    }

    for repository in profile.repositories:
        source_path = _source_path_for_profile(
            root, repository["index_path"], label="repository index path"
        )
        source, payload = _read_stable_regular(
            root,
            source_path,
            label=f"pinned repository index {repository['index_path']}",
            maximum=_MAX_INDEX_BYTES,
            expected_uid=uid,
            expected_gid=gid,
        )
        _register_inode(source, seen_inodes)
        if source.size != repository["index_size"] or source.sha256 != repository["index_sha256"]:
            raise GateError(
                f"pinned repository index size/SHA-256 mismatch: {repository['index_path']}"
            )
        for package in _parse_index(payload, repository):
            indexes[str(repository["architecture"])].setdefault(
                (package.identity.name, package.identity.version), []
            ).append(package)
        destination = _profile_destination(
            repository["index_path"], label="repository index path"
        )
        if destination in destinations:
            raise GateError(f"duplicate curated destination: {destination}")
        destinations.add(destination)
        plans.append(_CopyPlan(source, destination))

    counts = {architecture: 0 for architecture in ARCHITECTURES}
    excluded: set[_PackageIdentity] = set()
    seen_identities: dict[tuple[str, _PackageIdentity], Path] = {}
    closure_inventories: dict[str, tuple[Path, ...]] = {}
    total = sum(plan.source.size for plan in plans)
    for architecture in sorted(ARCHITECTURES):
        closure_entries = _closure_entries(
            root,
            architecture,
            expected_uid=uid,
            expected_gid=gid,
        )
        closure_inventories[architecture] = closure_entries
        for source_path in closure_entries:
            source, payload = _read_stable_regular(
                root,
                source_path,
                label=f"{architecture} closure APK {source_path.name}",
                maximum=_MAX_APK_BYTES,
                expected_uid=uid,
                expected_gid=gid,
            )
            _register_inode(source, seen_inodes)
            identity, checksum, _builder_signer = _parse_apk(
                payload, label=f"{architecture} closure APK {source_path.name}"
            )
            expected_plain_name = f"{identity.name}-{identity.version}.apk"
            if source_path.name != expected_plain_name:
                raise GateError(
                    f"closure APK filename does not match authenticated metadata: {source_path.name!r}"
                )
            duplicate_key = (architecture, identity)
            if duplicate_key in seen_identities:
                raise GateError(
                    f"duplicate {architecture} closure package identity {identity}: "
                    f"{seen_identities[duplicate_key]} and {source_path}"
                )
            seen_identities[duplicate_key] = source_path

            if architecture == "aarch64" and (
                identity.name,
                identity.version,
            ) in _EXCLUDED_AARCH64_PACKAGES:
                if identity.architecture not in {"aarch64", "noarch"}:
                    raise GateError(
                        f"local-package exclusion has an invalid architecture: {source_path.name}"
                    )
                excluded.add(identity)
                continue
            if identity.architecture not in {architecture, "noarch"}:
                raise GateError(
                    f"closure APK architecture does not match {architecture}: {source_path.name}"
                )
            matches = indexes[architecture].get(
                (identity.name, identity.version), []
            )
            if len(matches) != 1:
                raise GateError(
                    f"closure APK does not bind uniquely to one pinned signed APKINDEX: "
                    f"{source_path.name} (matches={len(matches)})"
                )
            indexed = matches[0]
            if checksum != indexed.checksum:
                raise GateError(
                    f"closure APK SHA1 data checksum differs from signed APKINDEX C:Q1: "
                    f"{source_path.name}"
                )
            if source.size != indexed.size:
                raise GateError(
                    f"closure APK size differs from signed APKINDEX S field: {source_path.name}"
                )
            suffix = checksum.hex()[:8]
            destination_name = f"{identity.name}-{identity.version}.{suffix}.apk"
            if _CACHE_APK_RE.fullmatch(destination_name) is None:
                raise GateError(f"could not derive a canonical pmbootstrap APK cache name")
            destination = PurePosixPath(f"cache_apk_{architecture}", destination_name)
            if destination in destinations:
                raise GateError(f"duplicate curated destination: {destination}")
            destinations.add(destination)
            plans.append(_CopyPlan(source, destination))
            counts[architecture] += 1
            total += source.size
            if total > _MAX_TOTAL_BYTES:
                raise GateError("curated acquisition exceeds its total byte limit")

    missing_exclusions = sorted(
        _EXCLUDED_AARCH64_PACKAGES
        - {(item.name, item.version) for item in excluded}
    )
    if missing_exclusions:
        rendered = [f"{name}-{version}" for name, version in missing_exclusions]
        raise GateError(
            f"aarch64 closure is missing required local-package exclusion evidence: {rendered!r}"
        )

    for pinned in profile.http_artifacts:
        source_path = _source_path_for_profile(
            root, pinned["path"], label="HTTP artifact path"
        )
        source, payload = _read_stable_regular(
            root,
            source_path,
            label=f"pinned HTTPS/cache object {pinned['path']}",
            maximum=_MAX_APK_BYTES,
            expected_uid=uid,
            expected_gid=gid,
        )
        _register_inode(source, seen_inodes)
        if source.size != pinned["size"] or source.sha256 != pinned["sha256"]:
            raise GateError(f"pinned HTTPS/cache object size/SHA-256 mismatch: {pinned['path']}")
        identity, checksum, signer = _parse_apk(payload, label="pinned apk-tools-static object")
        expected_identity = _PackageIdentity(
            str(pinned["name"]), str(pinned["version"]), "x86_64"
        )
        if identity != expected_identity:
            raise GateError("pinned apk-tools-static identity differs from the canonical profile")
        matches = indexes["x86_64"].get((identity.name, identity.version), [])
        if len(matches) != 1 or matches[0].checksum != checksum or matches[0].size != source.size:
            raise GateError(
                "pinned apk-tools-static does not bind by size and C:Q1 checksum to one signed APKINDEX"
            )
        expected_signer = PurePosixPath(str(pinned["signer_key_path"])).name
        if signer != expected_signer:
            raise GateError("pinned apk-tools-static signer basename differs from its profile pin")
        destination = _profile_destination(pinned["path"], label="HTTP artifact path")
        if destination in destinations:
            raise GateError(f"duplicate curated destination: {destination}")
        destinations.add(destination)
        plans.append(_CopyPlan(source, destination))
        total += source.size

    for pinned in profile.distfiles:
        source_path = _source_path_for_profile(
            root, pinned["path"], label="distfile path"
        )
        source, _payload = _read_stable_regular(
            root,
            source_path,
            label=f"pinned kernel distfile {pinned['path']}",
            maximum=_MAX_APK_BYTES,
            expected_uid=uid,
            expected_gid=gid,
        )
        _register_inode(source, seen_inodes)
        if source.size != pinned["size"] or source.sha256 != pinned["sha256"]:
            raise GateError(f"pinned kernel distfile size/SHA-256 mismatch: {pinned['path']}")
        destination = _profile_destination(pinned["path"], label="distfile path")
        if destination in destinations:
            raise GateError(f"duplicate curated destination: {destination}")
        destinations.add(destination)
        plans.append(_CopyPlan(source, destination))
        total += source.size
    if total > _MAX_TOTAL_BYTES:
        raise GateError("curated acquisition exceeds its total byte limit")

    for architecture in sorted(ARCHITECTURES):
        current_inventory = _closure_entries(
            root,
            architecture,
            expected_uid=uid,
            expected_gid=gid,
        )
        if current_inventory != closure_inventories[architecture]:
            raise GateError(
                f"exact {architecture} closure inventory changed during validation"
            )

    requested_output = Path(output)
    staging_output = _prepare_output(
        requested_output, expected_uid=uid, expected_gid=gid
    )
    staging = staging_output.path
    published = False
    try:
        inventory: list[dict[str, object]] = []
        version_payload = f"{profile.pins['pmbootstrap']['work_version']}\n".encode("ascii")
        version_record = _write_member(staging / "version", version_payload)
        inventory.append(
            {
                "path": "version",
                "size": version_record["size"],
                "sha256": version_record["sha256"],
            }
        )
        for plan in sorted(plans, key=lambda item: item.destination.as_posix()):
            current, payload = _read_stable_regular(
                root,
                plan.source.path,
                label=f"acquisition source during copy {plan.source.path}",
                maximum=_MAX_APK_BYTES,
                expected_uid=uid,
                expected_gid=gid,
            )
            if current.identity != plan.source.identity or current.sha256 != plan.source.sha256:
                raise GateError(f"acquisition source changed before copying: {plan.source.path}")
            destination = staging.joinpath(*plan.destination.parts)
            written = _write_member(destination, payload)
            if written["size"] != plan.source.size or written["sha256"] != plan.source.sha256:
                raise GateError(f"curated copy differs from validated source: {plan.destination}")
            inventory.append(
                {
                    "path": plan.destination.as_posix(),
                    "size": written["size"],
                    "sha256": written["sha256"],
                }
            )
        for name in _OUTPUT_DIRECTORIES:
            _fsync_directory(staging / name)
        _fsync_directory(staging)
        inventory.sort(key=lambda item: str(item["path"]))
        inventory_sha256 = hashlib.sha256(canonical_json_bytes(inventory)).hexdigest()
        if requested_output.exists() or requested_output.is_symlink():
            raise GateError("curated acquisition output appeared during validation")
        renamed = False
        try:
            os.rename(staging, requested_output)
            renamed = True
            _fsync_directory(requested_output.parent)
        except (OSError, GateError) as error:
            if renamed:
                try:
                    os.rename(requested_output, staging)
                    _fsync_directory(requested_output.parent)
                except OSError as rollback_error:
                    raise GateError(
                        "curated acquisition publication and rollback both failed: "
                        f"{error}; rollback={rollback_error}"
                    ) from None
            raise GateError(f"could not atomically publish curated acquisition: {error}") from None
        published = True
    except BaseException:
        if not published:
            _discard_staging(staging_output)
        raise
    return CuratedAcquisition(
        root=requested_output,
        aarch64_packages=counts["aarch64"],
        x86_64_packages=counts["x86_64"],
        excluded_aarch64_packages=tuple(
            sorted(f"{item.name}-{item.version}" for item in excluded)
        ),
        members=len(inventory),
        inventory_sha256=inventory_sha256,
    )
