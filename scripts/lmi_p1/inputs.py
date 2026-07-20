"""Acquire and verify the P2-recovery inputs."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import tarfile
from typing import Mapping
import urllib.parse
import urllib.request

from .common import GateError, sha256_file


_COPY_BLOCK_SIZE = 1024 * 1024
_HTTPS_TIMEOUT_SECONDS = 60
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256SUM_LINE_RE = re.compile(r"^([0-9a-f]{64}) ([ *])(.+)$")
_REQUIRED_APK_NAMES = frozenset(
    {
        "device-xiaomi-lmi-1-r139.apk",
        "linux-xiaomi-lmi-4.19.325-r9.apk",
        "weston-14.0.2-r10.apk",
        "weston-backend-drm-14.0.2-r10.apk",
        "weston-clients-14.0.2-r10.apk",
        "weston-shell-desktop-14.0.2-r10.apk",
        "weston-terminal-14.0.2-r10.apk",
    }
)


def _member_parts(name: str, *, label: str) -> tuple[str, ...]:
    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise GateError(f"unsafe {label}: {name!r}")
    parts = tuple(name.split("/"))
    if name.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise GateError(f"unsafe {label}: {name!r}")
    return parts


def _member_destination(root: Path, name: str, *, label: str) -> Path:
    parts = _member_parts(name, label=label)
    resolved_root = root.resolve()
    destination = root.joinpath(*parts)
    try:
        destination.resolve(strict=False).relative_to(resolved_root)
    except ValueError:
        raise GateError(f"unsafe {label}: {name!r}") from None
    return destination


def safe_extract(archive_path: Path, output_dir: Path) -> None:
    """Extract only preflighted regular tar members beneath a clean root."""

    if output_dir.is_symlink() or (
        output_dir.exists()
        and (not output_dir.is_dir() or next(output_dir.iterdir(), None) is not None)
    ):
        raise GateError(f"extraction root is not empty: {output_dir}")

    try:
        with tarfile.open(archive_path, "r:*") as archive:
            members = archive.getmembers()
            destinations: dict[str, Path] = {}
            members_by_name: dict[str, tarfile.TarInfo] = {}
            for member in members:
                is_ordinary_file = member.type in (
                    tarfile.REGTYPE,
                    tarfile.AREGTYPE,
                )
                if not (is_ordinary_file or member.isdir()):
                    raise GateError(
                        f"non-regular archive member rejected: {member.name!r}"
                    )
                if member.name in destinations:
                    raise GateError(f"duplicate archive member: {member.name!r}")
                destinations[member.name] = _member_destination(
                    output_dir, member.name, label="archive member"
                )
                members_by_name[member.name] = member

            names = set(destinations)
            for name in names:
                parts = name.split("/")
                for length in range(1, len(parts)):
                    ancestor = members_by_name.get("/".join(parts[:length]))
                    if ancestor is not None and not ancestor.isdir():
                        raise GateError(f"unsafe archive member collision: {name!r}")

            output_dir.mkdir(parents=True, exist_ok=True)
            for member in members:
                destination = destinations[member.name]
                if member.isdir():
                    destination.mkdir(parents=True, exist_ok=True)
                    destination.chmod(0o700)
                    continue
                destination.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise GateError(
                        f"could not read regular archive member: {member.name!r}"
                    )
                try:
                    with source, destination.open("xb") as target:
                        shutil.copyfileobj(source, target, length=_COPY_BLOCK_SIZE)
                    if destination.stat().st_size != member.size:
                        raise GateError(
                            f"archive member size mismatch: {member.name!r}"
                        )
                    destination.chmod(0o600)
                except OSError as error:
                    raise GateError(
                        f"could not extract archive member {member.name!r}: {error}"
                    ) from None
    except GateError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise GateError(f"could not read D80 archive: {error}") from None


def _require_sha256(value: object, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GateError(f"invalid sha256 in source lock: {field}")
    return value


def _load_d80_lock(lock_path: Path) -> dict[str, object]:
    try:
        value = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"could not read source lock: {error}") from None
    if not isinstance(value, dict) or (
        (value.get("schema") != 1 and value.get("schema") != "lmi-source-lock/v2")
        or isinstance(value.get("schema"), bool)
    ):
        raise GateError("invalid source lock schema")
    d80 = value.get("d80")
    if not isinstance(d80, dict):
        raise GateError("source lock is missing d80")

    url = d80.get("url")
    size = d80.get("size")
    required = d80.get("required_members")
    if not isinstance(url, str) or not url:
        raise GateError("invalid d80.url in source lock")
    if not isinstance(size, int) or isinstance(size, bool) or size < 0:
        raise GateError("invalid d80.size in source lock")
    if not isinstance(required, dict) or set(required) != _REQUIRED_APK_NAMES:
        raise GateError("source lock required APK set mismatch")

    checked_required: dict[str, str] = {}
    for name, digest in required.items():
        _member_parts(name, label="required APK path")
        checked_required[name] = _require_sha256(
            digest, field=f"d80.required_members.{name}"
        )

    return {
        "url": url,
        "size": size,
        "sha256": _require_sha256(d80.get("sha256"), field="d80.sha256"),
        "inner_sha256sums_sha256": _require_sha256(
            d80.get("inner_sha256sums_sha256"),
            field="d80.inner_sha256sums_sha256",
        ),
        "required_members": checked_required,
    }


def _copy_local_source(source: Path, partial: Path) -> None:
    try:
        source_stat = source.stat()
        if not stat.S_ISREG(source_stat.st_mode):
            raise GateError(f"local D80 source is not a regular file: {source}")
        with source.open("rb") as input_stream, partial.open("xb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream, length=_COPY_BLOCK_SIZE)
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not copy local D80 source: {error}") from None


def _download_source(url: str, base_dir: Path, partial: Path) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme == "https":
        try:
            with urllib.request.urlopen(
                url, timeout=_HTTPS_TIMEOUT_SECONDS
            ) as response, partial.open("xb") as output_stream:
                final_scheme = urllib.parse.urlparse(response.geturl()).scheme
                if final_scheme != "https":
                    raise GateError("D80 HTTPS download redirected to a non-HTTPS URL")
                shutil.copyfileobj(response, output_stream, length=_COPY_BLOCK_SIZE)
        except GateError:
            raise
        except (OSError, urllib.error.URLError) as error:
            raise GateError(f"could not download D80 source: {error}") from None
        return

    if parsed.scheme == "file":
        if parsed.netloc not in {"", "localhost"}:
            raise GateError("unsupported D80 file URL host")
        source = Path(urllib.request.url2pathname(urllib.parse.unquote(parsed.path)))
        _copy_local_source(source, partial)
        return

    if parsed.scheme == "":
        source = Path(url)
        if not source.is_absolute():
            source = base_dir / source
        _copy_local_source(source, partial)
        return

    raise GateError(f"unsupported D80 URL scheme: {parsed.scheme!r}")


def _verify_outer_archive(path: Path, d80: Mapping[str, object]) -> None:
    try:
        path_stat = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect D80 archive: {error}") from None
    if not stat.S_ISREG(path_stat.st_mode):
        raise GateError("D80 archive is not a regular file")
    if path_stat.st_size != d80["size"]:
        raise GateError(
            f"outer size mismatch: expected {d80['size']}, got {path_stat.st_size}"
        )
    actual_sha256 = sha256_file(path)
    if actual_sha256 != d80["sha256"]:
        raise GateError(
            f"outer sha256 mismatch: expected {d80['sha256']}, got {actual_sha256}"
        )


def _acquire_archive(
    d80: Mapping[str, object], lock_dir: Path, cache_dir: Path
) -> Path:
    archive_path = cache_dir / "d80-source.tar.gz"
    if archive_path.exists() or archive_path.is_symlink():
        _verify_outer_archive(archive_path, d80)
        return archive_path

    partial = cache_dir / "d80-source.tar.gz.partial"
    if partial.exists() or partial.is_symlink():
        if partial.is_dir() and not partial.is_symlink():
            raise GateError("D80 download partial path is unexpectedly a directory")
        partial.unlink()

    try:
        _download_source(str(d80["url"]), lock_dir, partial)
        _verify_outer_archive(partial, d80)
        os.replace(partial, archive_path)
    except Exception:
        if partial.exists() or partial.is_symlink():
            if not partial.is_dir() or partial.is_symlink():
                partial.unlink()
        raise
    return archive_path


def _parse_sha256sums(path: Path, root: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read SHA256SUMS: {error}") from None
    if not lines:
        raise GateError("SHA256SUMS is empty")

    checksums: dict[str, str] = {}
    for line_number, line in enumerate(lines, start=1):
        match = _SHA256SUM_LINE_RE.fullmatch(line)
        if match is None:
            raise GateError(f"invalid SHA256SUMS line {line_number}")
        digest, _mode, name = match.groups()
        if name == "SHA256SUMS":
            raise GateError("SHA256SUMS must not list itself")
        _member_destination(root, name, label="SHA256SUMS member")
        if name in checksums:
            raise GateError(f"duplicate SHA256SUMS member: {name!r}")
        checksums[name] = digest
    return checksums


def _regular_member_set(root: Path) -> set[str]:
    if root.is_symlink() or not root.is_dir():
        raise GateError("verified extraction root is not a directory")
    members: set[str] = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise GateError(f"non-regular extracted path: {path}")
        if path.is_dir():
            continue
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise GateError(f"could not inspect extracted path: {error}") from None
        if not stat.S_ISREG(mode):
            raise GateError(f"non-regular extracted path: {path}")
        members.add(path.relative_to(root).as_posix())
    return members


def _verify_extracted(root: Path, d80: Mapping[str, object]) -> None:
    checksum_path = _member_destination(
        root, "SHA256SUMS", label="SHA256SUMS member"
    )
    if checksum_path.is_symlink() or not checksum_path.is_file():
        raise GateError("missing SHA256SUMS")
    actual_inner_sha256 = sha256_file(checksum_path)
    if actual_inner_sha256 != d80["inner_sha256sums_sha256"]:
        raise GateError(
            "inner SHA256SUMS sha256 mismatch: "
            f"expected {d80['inner_sha256sums_sha256']}, got {actual_inner_sha256}"
        )

    checksums = _parse_sha256sums(checksum_path, root)
    actual_members = _regular_member_set(root)
    expected_members = set(checksums) | {"SHA256SUMS"}
    if actual_members != expected_members:
        missing = sorted(expected_members - actual_members)
        extra = sorted(actual_members - expected_members)
        raise GateError(
            f"checksum member set mismatch: missing={missing!r}, extra={extra!r}"
        )

    verified: dict[str, str] = {}
    for name, expected_sha256 in checksums.items():
        member_path = _member_destination(root, name, label="SHA256SUMS member")
        if member_path.is_symlink() or not member_path.is_file():
            raise GateError(f"missing checksummed member: {name!r}")
        actual_sha256 = sha256_file(member_path)
        if actual_sha256 != expected_sha256:
            raise GateError(
                f"member sha256 mismatch for {name!r}: "
                f"expected {expected_sha256}, got {actual_sha256}"
            )
        verified[name] = actual_sha256

    required_members = d80["required_members"]
    if not isinstance(required_members, Mapping):
        raise GateError("invalid required APK mapping")
    for name, expected_sha256 in required_members.items():
        if name not in verified:
            raise GateError(f"missing required APK: {name!r}")
        if verified[name] != expected_sha256:
            raise GateError(
                f"required APK sha256 mismatch for {name!r}: "
                f"expected {expected_sha256}, got {verified[name]}"
            )


def _content_root(extraction_root: Path) -> Path:
    direct_checksum = extraction_root / "SHA256SUMS"
    if direct_checksum.is_symlink():
        raise GateError("SHA256SUMS must not be a symlink")
    if direct_checksum.is_file():
        return extraction_root

    try:
        top_level = list(extraction_root.iterdir())
    except OSError as error:
        raise GateError(f"could not inspect archive layout: {error}") from None
    if len(top_level) != 1:
        raise GateError("archive must be flat or have exactly one top-level wrapper")
    wrapper = top_level[0]
    if wrapper.is_symlink() or not wrapper.is_dir():
        raise GateError("archive must be flat or have exactly one top-level wrapper")
    wrapped_checksum = wrapper / "SHA256SUMS"
    if wrapped_checksum.is_symlink() or not wrapped_checksum.is_file():
        raise GateError("wrapper directory does not directly contain SHA256SUMS")
    return wrapper


def _remove_generated_path(path: Path) -> None:
    if path.is_symlink() or (path.exists() and not path.is_dir()):
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def prepare_inputs(lock_path: Path, cache_dir: Path) -> Path:
    """Return a fully verified extracted D80 directory, or fail closed."""

    d80 = _load_d80_lock(lock_path)
    cache_dir.mkdir(parents=True, exist_ok=True)
    archive_path = _acquire_archive(d80, lock_path.parent, cache_dir)

    extracted = cache_dir / "d80"
    if extracted.exists() or extracted.is_symlink():
        _verify_extracted(extracted, d80)
        return extracted

    partial = cache_dir / "d80.partial"
    _remove_generated_path(partial)
    try:
        safe_extract(archive_path, partial)
        content_root = _content_root(partial)
        _verify_extracted(content_root, d80)
        if content_root == partial:
            os.replace(partial, extracted)
        else:
            os.replace(content_root, extracted)
            try:
                partial.rmdir()
            except OSError as error:
                _remove_generated_path(extracted)
                raise GateError(
                    f"could not remove empty archive wrapper staging root: {error}"
                ) from None
    except Exception:
        _remove_generated_path(partial)
        raise
    return extracted
