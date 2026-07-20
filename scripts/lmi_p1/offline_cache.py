"""Fail-closed quarantine and promotion for the lmi P1 offline cache.

Production promotion is authorized by one canonical, reviewed attestation.
It binds the curated acquisition, producer code, promotion profile, trusted
pmbootstrap checkout and signing key, an isolated OpenSSL runtime closure, and
the exact output expected before the quarantine can be renamed.  Tests may
inject an :class:`ApkSignatureVerifier`; that fixture-only seam is not exposed
by the production command line.
"""

from __future__ import annotations

import base64
import ctypes
from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Mapping, Protocol, Sequence
import urllib.parse
import zlib

from .common import GateError


MANIFEST_SCHEMA = "lmi-p1-offline-cache/v2"
PROMOTION_PROFILE_SCHEMA = "lmi-p1-offline-cache-promotion/v1"
PROMOTION_ATTESTATION_SCHEMA = "lmi-p1-offline-cache-promotion-attestation/v3"
PROMOTION_REPLAY_SCHEMA = "lmi-p1-offline-cache-promotion-replay/v1"
MANIFEST_NAME = "offline-cache.manifest.json"
WORK_VERSION = 8
ARCHITECTURES = frozenset({"aarch64", "x86_64"})
PRODUCTION_REPOSITORY_URLS = frozenset(
    {
        "http://dl-cdn.alpinelinux.org/alpine/edge/community",
        "http://dl-cdn.alpinelinux.org/alpine/edge/main",
        "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
        "http://mirror.postmarketos.org/postmarketos/main",
    }
)

_TOP_LEVEL_FIELDS = frozenset(
    {
        "schema",
        "pins",
        "repositories",
        "external_apks",
        "http_artifacts",
        "distfiles",
        "members",
        "aggregate_sha256",
    }
)
_PROFILE_FIELDS = frozenset(
    {"schema", "pins", "repositories", "http_artifacts", "distfiles"}
)
_REPOSITORY_FIELDS = frozenset(
    {
        "architecture",
        "url",
        "index_path",
        "index_size",
        "index_sha256",
        "signer_key_path",
        "signer_key_sha256",
    }
)
_EXTERNAL_APK_FIELDS = frozenset(
    {
        "architecture",
        "name",
        "version",
        "path",
        "size",
        "sha256",
        "repository_url",
        "index_sha256",
        "apkindex_checksum",
        "index_signer_key_path",
        "index_signer_key_sha256",
        "builder_signer",
    }
)
_HTTP_ARTIFACT_FIELDS = frozenset(
    {
        "kind",
        "name",
        "version",
        "url",
        "path",
        "size",
        "sha256",
        "signer_key_path",
        "signer_key_sha256",
    }
)
_DISTFILE_FIELDS = frozenset(
    {"url", "path", "size", "sha256", "apkbuild_sha512"}
)
_MEMBER_FIELDS = frozenset({"path", "size", "sha256"})
_PIN_FIELDS = frozenset({"pmbootstrap", "pmaports"})
_PMBOOTSTRAP_PIN_FIELDS = frozenset({"commit", "version", "work_version"})
_PMAPORTS_PIN_FIELDS = frozenset({"commit", "tree", "channel"})
_ALLOWED_ACQUISITION_TOP_LEVEL = frozenset(
    {
        "version",
        "cache_apk_aarch64",
        "cache_apk_x86_64",
        "cache_http",
        "cache_distfiles",
    }
)
_ALLOWED_WORK_DIRECTORIES = frozenset(
    {
        "work/cache_apk_aarch64",
        "work/cache_apk_x86_64",
        "work/cache_http",
        "work/cache_distfiles",
    }
)
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
_GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:-]{0,255}$")
_PACKAGE_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}$")
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_INDEX_METADATA_BYTES = 64 * 1024 * 1024
_MAX_PACKAGE_METADATA_BYTES = 1024 * 1024
_MAX_SIGNATURE_BYTES = 1024 * 1024
_MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
_MAX_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
_COPY_BLOCK_SIZE = 1024 * 1024
_VERIFIER_TIMEOUT_SECONDS = 30
_CANONICAL_ATTESTATION_RELATIVE = PurePosixPath(
    "config/lmi-p1/offline-cache-promotion-attestation.json"
)
_CURATION_PRODUCER_PATHS = frozenset({"scripts/lmi_p1/acquisition.py"})
_REQUIRED_PROMOTION_RUNTIME_PATHS = frozenset(
    {
        "scripts/lmi_p1/__init__.py",
        "scripts/lmi_p1/common.py",
        "scripts/lmi_p1/offline_cache.py",
        "scripts/lmi_p1_cli.py",
    }
)
_RUNTIME_DESTINATIONS = {
    "openssl": "openssl",
    "loader": "ld-linux-x86-64.so.2",
    "libssl": "libssl.so.3",
    "libcrypto": "libcrypto.so.3",
    "libc": "libc.so.6",
    "libz": "libz.so.1",
    "libzstd": "libzstd.so.1",
}
_ATTESTATION_FIELDS = frozenset(
    {
        "schema",
        "profile",
        "trusted_pmbootstrap",
        "acquisition",
        "producer_code",
        "runtime_trust",
        "apk_static",
        "openssl_runtime",
        "published",
        "replay_report",
    }
)
_OUTPUT_FIELDS = frozenset(
    {"schema", "manifest_sha256", "aggregate_sha256", "member_count"}
)


@dataclass(frozen=True)
class PackageIdentity:
    """Identity read from authenticated APK or APKINDEX data."""

    name: str
    version: str
    architecture: str


@dataclass(frozen=True)
class IndexedPackage:
    """Package identity authenticated by a verified repository index."""

    identity: PackageIdentity
    size: int
    apkindex_checksum: str


@dataclass(frozen=True)
class VerifiedIndex:
    """Authenticated index result returned by a trusted verifier."""

    architecture: str
    packages: tuple[IndexedPackage, ...]


@dataclass(frozen=True)
class InspectedPackage:
    """Structurally valid APK v2 metadata; the signer is provenance only."""

    identity: PackageIdentity
    apkindex_checksum: str
    builder_signer: str


@dataclass(frozen=True)
class VerifiedPackage:
    """Standalone-signature-authenticated APK result for bootstrap artifacts."""

    identity: PackageIdentity
    signer_key_path: str


class ApkSignatureVerifier(Protocol):
    """Trust boundary for cryptographic APK and APKINDEX verification.

    Implementations must fail closed.  ``verify_index`` may return only after
    the index signature verifies with exactly ``signer_key_path``.
    ``verify_package`` is deliberately narrower: it verifies independently
    pinned bootstrap APKs by their package signature. Repository packages do
    not use it; they are authenticated against identity records returned from
    the already verified index, matching apk-tools' fetch/install trust path.
    Merely parsing tar members or pmbootstrap's raw APKINDEX text is not a
    conforming index implementation.
    """

    def verify_index(
        self,
        index_path: Path,
        *,
        repository_url: str,
        architecture: str,
        signer_key_path: str,
        trusted_key_root: Path,
    ) -> VerifiedIndex: ...

    def verify_package(
        self,
        package_path: Path,
        *,
        expected_cache_architecture: str | None,
        allowed_signer_key_paths: Sequence[str],
        trusted_key_root: Path,
    ) -> VerifiedPackage: ...


@dataclass(frozen=True)
class RuntimeClosureMember:
    """One attested source copied into the private OpenSSL runtime."""

    role: str
    source_path: Path
    destination_basename: str
    size: int
    sha256: str


@dataclass(frozen=True)
class OpenSslRuntimePins:
    """Complete dynamically linked OpenSSL runtime and review provenance."""

    version: str
    members: tuple[RuntimeClosureMember, ...]
    review_distribution: str
    review_packages: tuple[Mapping[str, str], ...]


@dataclass(frozen=True)
class ApkStaticBootstrapPins:
    """Attested isolated-runtime and apk.static bootstrap facts."""

    openssl_runtime: OpenSslRuntimePins
    apk_static_size: int
    apk_static_sha256: str
    apk_static_version: str


@dataclass(frozen=True)
class PromotionAuthorization:
    """Fully validated reviewed authorization for one production promotion."""

    project_root: Path
    profile: "PromotionProfile"
    profile_sha256: str
    trusted_pmbootstrap_commit: str
    trusted_pmbootstrap_tree: str
    signer_key_path: str
    signer_key_sha256: str
    acquisition_inventory_sha256: str
    acquisition_member_count: int
    producer_code: Mapping[str, tuple[Mapping[str, str], ...]]
    runtime_trust: Mapping[str, str]
    bootstrap_pins: ApkStaticBootstrapPins
    expected_output: Mapping[str, object]
    replay_report: Mapping[str, object]


def _run_command(
    argv: Sequence[str], *, cwd: Path, environment: Mapping[str, str]
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            close_fds=True,
            timeout=_VERIFIER_TIMEOUT_SECONDS,
            cwd=cwd,
            env=dict(environment),
        )
    except subprocess.TimeoutExpired:
        raise GateError(
            f"trusted verifier command timed out after {_VERIFIER_TIMEOUT_SECONDS} seconds"
        ) from None
    except OSError as error:
        raise GateError(f"trusted verifier command could not start: {error}") from None


def _command_failure(label: str, result: subprocess.CompletedProcess[str]) -> GateError:
    stdout = result.stdout[-4096:]
    stderr = result.stderr[-4096:]
    return GateError(
        f"{label} failed with status {result.returncode}; "
        f"stdout_tail={stdout!r}; stderr_tail={stderr!r}"
    )


def _verifier_environment(
    private_root: Path, *, openssl_modules: Path | None = None
) -> dict[str, str]:
    environment = {
        "HOME": str(private_root),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin",
        "TMPDIR": str(private_root),
    }
    if openssl_modules is not None:
        environment["OPENSSL_CONF"] = "/dev/null"
        environment["OPENSSL_MODULES"] = str(openssl_modules)
    return environment


def _validate_bootstrap_pins(pins: ApkStaticBootstrapPins) -> ApkStaticBootstrapPins:
    if not isinstance(pins, ApkStaticBootstrapPins):
        raise GateError("apk.static bootstrap pins have an invalid type")
    runtime = _validate_runtime_closure_pins(pins.openssl_runtime)
    _require_size(pins.apk_static_size, label="pinned apk.static size")
    _require_hash(
        pins.apk_static_sha256, _SHA256_RE, label="pinned apk.static sha256"
    )
    _require_token(pins.apk_static_version, label="pinned apk.static version")
    return ApkStaticBootstrapPins(
        openssl_runtime=runtime,
        apk_static_size=pins.apk_static_size,
        apk_static_sha256=pins.apk_static_sha256,
        apk_static_version=pins.apk_static_version,
    )


def _validate_runtime_closure_pins(value: object) -> OpenSslRuntimePins:
    if not isinstance(value, OpenSslRuntimePins):
        raise GateError("pinned OpenSSL runtime has an invalid type")
    version = _require_token(value.version, label="pinned OpenSSL version")
    if value.review_distribution != "Ubuntu":
        raise GateError("OpenSSL review package provenance must identify Ubuntu")
    if len(value.members) != len(_RUNTIME_DESTINATIONS):
        raise GateError("pinned OpenSSL runtime closure is incomplete")
    members: list[RuntimeClosureMember] = []
    roles: set[str] = set()
    sources: set[Path] = set()
    destinations: set[str] = set()
    for item in value.members:
        if not isinstance(item, RuntimeClosureMember):
            raise GateError("pinned OpenSSL runtime member has an invalid type")
        if item.role not in _RUNTIME_DESTINATIONS or item.role in roles:
            raise GateError("pinned OpenSSL runtime has a missing or duplicate role")
        source = Path(item.source_path)
        if not source.is_absolute() or source != Path(os.path.normpath(source)):
            raise GateError("pinned OpenSSL runtime source path must be normalized and absolute")
        if source in sources:
            raise GateError("pinned OpenSSL runtime repeats a source path")
        if (
            item.destination_basename != _RUNTIME_DESTINATIONS[item.role]
            or PurePosixPath(item.destination_basename).name
            != item.destination_basename
            or item.destination_basename in destinations
        ):
            raise GateError("pinned OpenSSL runtime has an invalid SONAME destination")
        _require_size(item.size, label=f"pinned {item.role} size")
        _require_hash(item.sha256, _SHA256_RE, label=f"pinned {item.role} sha256")
        roles.add(item.role)
        sources.add(source)
        destinations.add(item.destination_basename)
        members.append(
            RuntimeClosureMember(
                role=item.role,
                source_path=source,
                destination_basename=item.destination_basename,
                size=item.size,
                sha256=item.sha256,
            )
        )
    if roles != set(_RUNTIME_DESTINATIONS):
        raise GateError("pinned OpenSSL runtime closure is incomplete")
    packages: list[Mapping[str, str]] = []
    names: set[str] = set()
    for package in value.review_packages:
        if not isinstance(package, dict) or set(package) != {"name", "version"}:
            raise GateError("OpenSSL review package provenance has an invalid shape")
        name = _require_token(package["name"], label="review package name", package=True)
        package_version = _require_token(
            package["version"], label="review package version", package=True
        )
        if name in names:
            raise GateError("OpenSSL review package provenance repeats a package")
        names.add(name)
        packages.append({"name": name, "version": package_version})
    if not packages:
        raise GateError("OpenSSL review package provenance must not be empty")
    if tuple(packages) != tuple(sorted(packages, key=lambda item: item["name"])):
        raise GateError("OpenSSL review package provenance is not canonically sorted")
    return OpenSslRuntimePins(
        version,
        tuple(sorted(members, key=lambda item: item.role)),
        value.review_distribution,
        tuple(packages),
    )


def _check_pinned_executable(
    path: Path, *, expected_size: int, expected_sha256: str, label: str
) -> os.stat_result:
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve {label}: {error}") from None
    if resolved != path:
        raise GateError(f"{label} path must not contain symlinks")
    metadata, digest = _hash_stable_regular(path, label=label, maximum=64 * 1024 * 1024)
    if metadata.st_size != expected_size or digest != expected_sha256:
        raise GateError(f"{label} size or SHA-256 differs from its trust pin")
    if not metadata.st_mode & stat.S_IXUSR:
        raise GateError(f"{label} is not owner-executable")
    return metadata


def _copy_runtime_closure(
    runtime_root: Path, pins: OpenSslRuntimePins
) -> dict[str, tuple[int, ...]]:
    """Stable-copy the complete attested runtime into one private directory."""

    try:
        runtime_root.mkdir(mode=0o700)
        runtime_root.chmod(0o700)
        modules = runtime_root / "modules"
        modules.mkdir(mode=0o700)
        modules.chmod(0o700)
    except OSError as error:
        raise GateError(f"could not create private OpenSSL runtime: {error}") from None
    identities: dict[str, tuple[int, ...]] = {}
    for member in pins.members:
        source = member.source_path
        try:
            resolved = source.resolve(strict=True)
        except OSError as error:
            raise GateError(f"could not resolve pinned {member.role}: {error}") from None
        if resolved != source:
            raise GateError(f"pinned {member.role} path must not contain symlinks")
        before, digest = _hash_stable_regular(
            source,
            label=f"pinned {member.role} source",
            maximum=64 * 1024 * 1024,
        )
        if before.st_size != member.size or digest != member.sha256:
            raise GateError(
                f"pinned {member.role} source size or SHA-256 differs from its trust pin"
            )
        destination = runtime_root / member.destination_basename
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(destination, flags, 0o600)
            with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output:
                copied = 0
                copied_digest = hashlib.sha256()
                while True:
                    block = input_stream.read(_COPY_BLOCK_SIZE)
                    if not block:
                        break
                    copied += len(block)
                    if copied > member.size:
                        raise GateError(f"pinned {member.role} source grew while copying")
                    copied_digest.update(block)
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
        except GateError:
            raise
        except OSError as error:
            raise GateError(f"could not copy pinned {member.role}: {error}") from None
        after, after_digest = _hash_stable_regular(
            source,
            label=f"pinned {member.role} source",
            maximum=64 * 1024 * 1024,
        )
        if (
            _metadata_identity(before) != _metadata_identity(after)
            or digest != after_digest
            or copied != member.size
            or copied_digest.hexdigest() != member.sha256
        ):
            raise GateError(f"pinned {member.role} source changed while copying")
        mode = 0o700 if member.role in {"openssl", "loader"} else 0o600
        destination.chmod(mode)
        copied_metadata, copied_hash = _hash_stable_regular(
            destination,
            label=f"private {member.role}",
            maximum=64 * 1024 * 1024,
        )
        if copied_metadata.st_size != member.size or copied_hash != member.sha256:
            raise GateError(f"private {member.role} differs from its attested source")
        identities[member.role] = _metadata_identity(copied_metadata)
    _validate_runtime_closure(runtime_root, pins, expected_identities=identities)
    return identities


def _validate_runtime_closure(
    runtime_root: Path,
    pins: OpenSslRuntimePins,
    *,
    expected_identities: Mapping[str, tuple[int, ...]] | None = None,
) -> None:
    """Reject any missing, extra, swapped, linked, or changed runtime member."""

    try:
        root_metadata = runtime_root.lstat()
        entries = {entry.name for entry in os.scandir(runtime_root)}
    except OSError as error:
        raise GateError(f"could not inspect private OpenSSL runtime: {error}") from None
    expected_entries = {item.destination_basename for item in pins.members} | {"modules"}
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) != 0o700
        or entries != expected_entries
    ):
        raise GateError("private OpenSSL runtime closure has missing or extra entries")
    modules = runtime_root / "modules"
    try:
        modules_metadata = modules.lstat()
        module_entries = tuple(os.scandir(modules))
    except OSError as error:
        raise GateError(f"could not inspect private OpenSSL modules directory: {error}") from None
    if (
        not stat.S_ISDIR(modules_metadata.st_mode)
        or stat.S_IMODE(modules_metadata.st_mode) != 0o700
        or module_entries
    ):
        raise GateError("private OpenSSL modules directory must be empty and mode 0700")
    inodes: set[tuple[int, int]] = set()
    for member in pins.members:
        destination = runtime_root / member.destination_basename
        metadata, digest = _hash_stable_regular(
            destination,
            label=f"private {member.role}",
            maximum=64 * 1024 * 1024,
        )
        expected_mode = 0o700 if member.role in {"openssl", "loader"} else 0o600
        if (
            metadata.st_size != member.size
            or digest != member.sha256
            or stat.S_IMODE(metadata.st_mode) != expected_mode
        ):
            raise GateError(f"private {member.role} differs from its runtime pin")
        inode = (metadata.st_dev, metadata.st_ino)
        if metadata.st_nlink != 1 or inode in inodes:
            raise GateError("private OpenSSL runtime contains a duplicate or linked member")
        inodes.add(inode)
        if expected_identities is not None and _metadata_identity(metadata) != expected_identities.get(
            member.role
        ):
            raise GateError(f"private {member.role} changed during runtime use")


def _runtime_command(
    pins: OpenSslRuntimePins,
    runtime_root: Path,
    arguments: Sequence[str],
) -> tuple[str, ...]:
    by_role = {item.role: item for item in pins.members}
    return (
        str(runtime_root / by_role["loader"].destination_basename),
        "--inhibit-cache",
        "--library-path",
        str(runtime_root),
        str(runtime_root / by_role["openssl"].destination_basename),
        *arguments,
    )


def _runtime_list_command(
    pins: OpenSslRuntimePins, runtime_root: Path
) -> tuple[str, ...]:
    by_role = {item.role: item for item in pins.members}
    return (
        str(runtime_root / by_role["loader"].destination_basename),
        "--inhibit-cache",
        "--library-path",
        str(runtime_root),
        "--list",
        str(runtime_root / by_role["openssl"].destination_basename),
    )


def _validate_runtime_resolution(
    pins: OpenSslRuntimePins, runtime_root: Path, output: str
) -> None:
    """Require the copied loader to resolve every dependency inside closure."""

    expected = {
        runtime_root / member.destination_basename
        for member in pins.members
        if member.role != "openssl"
    }
    resolved: set[Path] = set()
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("linux-vdso.so.1 "):
            continue
        if "=>" not in line or "not found" in line:
            raise GateError("private OpenSSL loader returned an unexpected dependency")
        _requested, resolution = line.split("=>", 1)
        resolved_text = resolution.strip().split(" (", 1)[0]
        path = Path(resolved_text)
        if not path.is_absolute() or path.parent != runtime_root:
            raise GateError("private OpenSSL dependency resolved outside its closure")
        resolved.add(path)
    if resolved != expected:
        raise GateError("private OpenSSL dependency resolution is missing or extra")


def _stream_tar_member(
    archive: tarfile.TarFile,
    member: tarfile.TarInfo,
    destination: Path,
    *,
    maximum: int,
    label: str,
) -> tuple[int, str]:
    if not member.isreg() or member.size < 0 or member.size > maximum:
        raise GateError(f"{label} is not a bounded regular archive member")
    source = archive.extractfile(member)
    if source is None:
        raise GateError(f"could not read {label}")
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    digest = hashlib.sha256()
    written = 0
    try:
        descriptor = os.open(destination, flags, 0o600)
        with source, os.fdopen(descriptor, "wb") as output:
            while True:
                block = source.read(_COPY_BLOCK_SIZE)
                if not block:
                    break
                written += len(block)
                if written > member.size or written > maximum:
                    raise GateError(f"{label} exceeded its declared size")
                digest.update(block)
                output.write(block)
            output.flush()
            os.fsync(output.fileno())
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not extract {label}: {error}") from None
    if written != member.size:
        raise GateError(f"{label} was truncated during extraction")
    destination.chmod(0o600)
    return written, digest.hexdigest()


def _read_verified_tar_member(
    path: Path, name: str, *, maximum: int, label: str
) -> tuple[bytes, tuple[str, ...]]:
    before, before_digest = _hash_stable_regular(path, label=label)
    try:
        with tarfile.open(path, "r:*") as archive:
            members = archive.getmembers()
            selected = [item for item in members if item.name == name]
            if len(selected) != 1 or not selected[0].isreg():
                raise GateError(f"{label} does not contain exactly one regular {name}")
            if selected[0].size < 0 or selected[0].size > maximum:
                raise GateError(f"{label} metadata exceeds its size limit")
            stream = archive.extractfile(selected[0])
            if stream is None:
                raise GateError(f"could not read authenticated {label} metadata")
            with stream:
                payload = stream.read(maximum + 1)
            names = tuple(item.name for item in members)
    except GateError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise GateError(f"could not parse authenticated {label}: {error}") from None
    if len(payload) > maximum or len(payload) != selected[0].size:
        raise GateError(f"authenticated {label} metadata has an invalid size")
    after, after_digest = _hash_stable_regular(path, label=label)
    if _metadata_identity(before) != _metadata_identity(after) or before_digest != after_digest:
        raise GateError(f"authenticated {label} changed while parsing metadata")
    return payload, names


def _signature_basename(names: Sequence[str], *, label: str) -> str:
    # Test the specific v3-style prefix first: it is itself prefixed by the
    # legacy spelling and would otherwise be misread as basename "sha256.*".
    prefixes = (".SIGN.RSA.sha256.", ".SIGN.RSA.")
    signatures = []
    for name in names:
        for prefix in prefixes:
            if name.startswith(prefix):
                signatures.append(name[len(prefix) :])
                break
    if (
        len(signatures) != 1
        or not signatures[0]
        or "/" in signatures[0]
        or "\\" in signatures[0]
    ):
        raise GateError(f"authenticated {label} has an ambiguous signature member")
    return signatures[0]


def _apkindex_checksum(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.startswith("Q1"):
        raise GateError(f"{label} is not an APK SHA1 identity checksum")
    try:
        digest = base64.b64decode(value[2:], validate=True)
    except (ValueError, base64.binascii.Error):
        raise GateError(f"{label} has invalid base64") from None
    if len(digest) != hashlib.sha1().digest_size:
        raise GateError(f"{label} has an invalid SHA1 length")
    canonical = "Q1" + base64.b64encode(digest).decode("ascii")
    if value != canonical:
        raise GateError(f"{label} is not canonical")
    return value


def _parse_index_metadata(path: Path, *, signer_basename: str) -> tuple[IndexedPackage, ...]:
    payload, names = _read_verified_tar_member(
        path, "APKINDEX", maximum=_MAX_INDEX_METADATA_BYTES, label="APKINDEX"
    )
    if _signature_basename(names, label="APKINDEX") != signer_basename:
        raise GateError("authenticated APKINDEX signer basename mismatch")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise GateError(f"authenticated APKINDEX metadata is not UTF-8: {error}") from None
    packages: list[IndexedPackage] = []
    for number, block in enumerate(text.split("\n\n"), 1):
        if not block.strip():
            continue
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ":":
                continue
            key, value = line[0], line[2:]
            if key in {"C", "P", "V", "A", "S"}:
                if key in fields:
                    raise GateError(
                        f"authenticated APKINDEX block {number} repeats field {key}"
                    )
                fields[key] = value
        if set(fields) != {"C", "P", "V", "A", "S"}:
            raise GateError(
                f"authenticated APKINDEX block {number} lacks package identity fields"
            )
        identity = PackageIdentity(fields["P"], fields["V"], fields["A"])
        _validate_verifier_identity(identity, label="APKINDEX package")
        try:
            size = int(fields["S"], 10)
        except ValueError:
            raise GateError(
                f"authenticated APKINDEX block {number} has an invalid package size"
            ) from None
        if size <= 0 or size > _MAX_FILE_BYTES or str(size) != fields["S"]:
            raise GateError(
                f"authenticated APKINDEX block {number} has a noncanonical package size"
            )
        packages.append(
            IndexedPackage(
                identity,
                size,
                _apkindex_checksum(
                    fields["C"], label=f"authenticated APKINDEX block {number} C"
                ),
            )
        )
    if not packages:
        raise GateError("authenticated APKINDEX contains no package records")
    return tuple(packages)


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


def _tar_payload_and_names(
    payload: bytes, member_name: str, *, label: str, maximum: int
) -> tuple[bytes, tuple[str, ...]]:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
            names: list[str] = []
            seen: set[str] = set()
            for member in members:
                name = member.name
                pure = PurePosixPath(name)
                if (
                    not name
                    or "\\" in name
                    or pure.is_absolute()
                    or any(part in {"", ".", ".."} for part in pure.parts)
                ):
                    raise GateError(f"authenticated {label} has an unsafe archive path")
                if name in seen:
                    raise GateError(f"authenticated {label} repeats archive member {name!r}")
                seen.add(name)
                names.append(name)
                if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                    raise GateError(f"authenticated {label} contains a nonregular archive member")
            selected = [item for item in members if item.name == member_name]
            if len(selected) != 1 or not selected[0].isreg():
                raise GateError(
                    f"authenticated {label} does not contain exactly one regular {member_name}"
                )
            if selected[0].size < 0 or selected[0].size > maximum:
                raise GateError(f"authenticated {label} metadata exceeds its size limit")
            stream = archive.extractfile(selected[0])
            if stream is None:
                raise GateError(f"could not read authenticated {label} metadata")
            with stream:
                selected_payload = stream.read(maximum + 1)
    except GateError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise GateError(f"could not parse authenticated {label}: {error}") from None
    if len(selected_payload) > maximum or len(selected_payload) != selected[0].size:
        raise GateError(f"authenticated {label} metadata has an invalid size")
    return selected_payload, tuple(names)


def _signature_tar_names(payload: bytes, *, label: str) -> tuple[str, ...]:
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise GateError(f"could not parse authenticated {label}: {error}") from None
    if len(members) != 1 or not members[0].isreg():
        raise GateError(f"authenticated {label} has an ambiguous signature member")
    name = members[0].name
    pure = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        raise GateError(f"authenticated {label} has an unsafe archive path")
    if members[0].size < 0 or members[0].size > _MAX_SIGNATURE_BYTES:
        raise GateError(f"authenticated {label} signature exceeds its size limit")
    return (name,)


def _read_stable_regular_bytes(path: Path, *, label: str, maximum: int) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) & 0o022
    ):
        raise GateError(f"{label} must be one immutable regular file")
    if before.st_size <= 0 or before.st_size > maximum:
        raise GateError(f"{label} exceeds its size limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not read {label}: {error}") from None
    if not (
        _metadata_identity(before)
        == _metadata_identity(opened)
        == _metadata_identity(finished)
        == _metadata_identity(after)
    ):
        raise GateError(f"{label} changed while being inspected")
    if len(payload) != before.st_size or len(payload) > maximum:
        raise GateError(f"{label} changed size while being inspected")
    return payload


def _inspect_repository_apk(path: Path) -> InspectedPackage:
    """Inspect v2 package identity after (and only after) index authentication.

    This mirrors apk-tools' ``APK_SIGN_VERIFY_IDENTITY`` path: the SHA1 of the
    raw control gzip member is compared with APKINDEX ``C:Q1``, while the
    control member's ``datahash`` authenticates the raw data member. The
    package signature filename is retained solely as builder provenance.
    """

    payload = _read_stable_regular_bytes(path, label="repository APK", maximum=_MAX_FILE_BYTES)
    signature_tar, _signature_raw, offset = _gzip_member(
        payload, 0, label="repository APK signature", maximum=_MAX_SIGNATURE_BYTES
    )
    control_tar, control_raw, data_offset = _gzip_member(
        payload, offset, label="repository APK control", maximum=_MAX_PACKAGE_METADATA_BYTES
    )
    signature_names = _signature_tar_names(
        signature_tar, label="repository APK signature"
    )
    builder_signer = _signature_basename(signature_names, label="repository APK")
    _require_token(builder_signer, label="repository APK builder_signer", package=True)
    pkginfo, _control_names = _tar_payload_and_names(
        control_tar,
        ".PKGINFO",
        label="repository APK control",
        maximum=_MAX_PACKAGE_METADATA_BYTES,
    )
    try:
        text = pkginfo.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise GateError(f"authenticated repository APK metadata is not UTF-8: {error}") from None
    fields: dict[str, str] = {}
    wanted = {"pkgname", "pkgver", "arch", "datahash"}
    for line in text.splitlines():
        if " = " not in line:
            continue
        key, value = line.split(" = ", 1)
        if key in wanted:
            if key in fields:
                raise GateError(f"repository APK repeats metadata field {key}")
            fields[key] = value
    if set(fields) != wanted:
        raise GateError("repository APK lacks identity or datahash metadata")
    identity = PackageIdentity(fields["pkgname"], fields["pkgver"], fields["arch"])
    _validate_verifier_identity(identity, label="repository APK")
    if _SHA256_RE.fullmatch(fields["datahash"]) is None:
        raise GateError("repository APK datahash is malformed")
    data_member = payload[data_offset:]
    if not data_member or hashlib.sha256(data_member).hexdigest() != fields["datahash"]:
        raise GateError("repository APK datahash does not authenticate its data member")
    checksum = "Q1" + base64.b64encode(
        hashlib.sha1(control_raw, usedforsecurity=False).digest()
    ).decode("ascii")
    return InspectedPackage(identity, checksum, builder_signer)


class PinnedApkStaticVerifier:
    """Concrete verifier backed by an independently authenticated apk.static."""

    def __init__(
        self,
        apk_static_path: Path,
        *,
        apk_static_size: int,
        apk_static_sha256: str,
        apk_static_version: str,
        private_root: Path,
        openssl_runtime: OpenSslRuntimePins | None = None,
        runtime_identities: Mapping[str, tuple[int, ...]] | None = None,
    ) -> None:
        self.apk_static_path = Path(apk_static_path)
        self.apk_static_size = apk_static_size
        self.apk_static_sha256 = apk_static_sha256
        self.apk_static_version = apk_static_version
        self.private_root = Path(private_root)
        self.openssl_runtime = openssl_runtime
        self.runtime_identities = (
            dict(runtime_identities) if runtime_identities is not None else None
        )
        self._closed = False
        _check_pinned_executable(
            self.apk_static_path,
            expected_size=self.apk_static_size,
            expected_sha256=self.apk_static_sha256,
            label="authenticated apk.static",
        )

    def _run_apk(
        self, arguments: Sequence[str], *, cwd: Path
    ) -> subprocess.CompletedProcess[str]:
        if self._closed:
            raise GateError("authenticated apk.static verifier is closed")
        before = _check_pinned_executable(
            self.apk_static_path,
            expected_size=self.apk_static_size,
            expected_sha256=self.apk_static_sha256,
            label="authenticated apk.static",
        )
        result = _run_command(
            (str(self.apk_static_path), *arguments),
            cwd=cwd,
            environment=_verifier_environment(cwd),
        )
        after = _check_pinned_executable(
            self.apk_static_path,
            expected_size=self.apk_static_size,
            expected_sha256=self.apk_static_sha256,
            label="authenticated apk.static",
        )
        if _metadata_identity(before) != _metadata_identity(after):
            raise GateError("authenticated apk.static changed while executing")
        return result

    def _verify_with_key(
        self,
        target: Path,
        *,
        signer_key_path: str,
        trusted_key_root: Path,
    ) -> bool:
        target_before, target_digest = _hash_stable_regular(
            target, label="APK verification target"
        )
        with tempfile.TemporaryDirectory(
            dir=self.private_root, prefix=".apk-verify-"
        ) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            keys = root / "keys"
            keys.mkdir(mode=0o700)
            key_destination = keys / PurePosixPath(signer_key_path).name
            key_record = _copy_stable_regular(
                Path(trusted_key_root),
                PurePosixPath(signer_key_path),
                key_destination,
                seen_inodes={},
            )
            key_destination.chmod(0o600)
            result = self._run_apk(
                (
                    "--root",
                    str(root),
                    "--keys-dir",
                    str(keys),
                    "--no-network",
                    "verify",
                    str(target),
                ),
                cwd=root,
            )
            if key_record["sha256"] != _hash_stable_regular(
                key_destination, label="isolated APK verifier key", maximum=1024 * 1024
            )[1]:
                raise GateError("isolated APK verifier key changed")
        target_after, after_digest = _hash_stable_regular(
            target, label="APK verification target"
        )
        if (
            _metadata_identity(target_before) != _metadata_identity(target_after)
            or target_digest != after_digest
        ):
            raise GateError("APK verification target changed during signature verification")
        return result.returncode == 0

    def verify_index(
        self,
        index_path: Path,
        *,
        repository_url: str,
        architecture: str,
        signer_key_path: str,
        trusted_key_root: Path,
    ) -> VerifiedIndex:
        del repository_url
        if not self._verify_with_key(
            index_path,
            signer_key_path=signer_key_path,
            trusted_key_root=trusted_key_root,
        ):
            raise GateError("apk.static rejected the repository index signature")
        packages = _parse_index_metadata(
            index_path, signer_basename=PurePosixPath(signer_key_path).name
        )
        return VerifiedIndex(architecture, packages)

    def verify_package(
        self,
        package_path: Path,
        *,
        expected_cache_architecture: str | None,
        allowed_signer_key_paths: Sequence[str],
        trusted_key_root: Path,
    ) -> VerifiedPackage:
        signers = tuple(sorted(set(allowed_signer_key_paths)))
        if not signers:
            raise GateError("no pinned signer key was supplied for APK verification")

        # The same public key is normally installed under both architecture
        # caches. First reject a basename that unexpectedly resolves to
        # different key material, then select only the expected cache's copy;
        # otherwise one valid signature would look like two accepted signers.
        basenames: dict[str, str] = {}
        for signer in signers:
            _signer_path(signer, label="APK verifier signer key")
            key_path = Path(trusted_key_root).joinpath(
                *PurePosixPath(signer).parts
            )
            _metadata, key_digest = _hash_stable_regular(
                key_path,
                label=f"APK verifier signer key {signer}",
                maximum=1024 * 1024,
            )
            basename = PurePosixPath(signer).name
            previous = basenames.setdefault(basename, key_digest)
            if previous != key_digest:
                raise GateError(
                    "APK verifier signer paths reuse one basename with different key material"
                )
        if expected_cache_architecture is not None:
            if expected_cache_architecture not in ARCHITECTURES:
                raise GateError("APK verifier expected cache architecture is unsupported")
            directory = f"cache_apk_{expected_cache_architecture}"
            signers = tuple(
                signer
                for signer in signers
                if PurePosixPath(signer).parts[1] == directory
            )
            if not signers:
                raise GateError("no pinned signer key matches the expected APK cache")
        accepted = [
            signer
            for signer in signers
            if self._verify_with_key(
                package_path,
                signer_key_path=signer,
                trusted_key_root=trusted_key_root,
            )
        ]
        if len(accepted) != 1:
            raise GateError("APK signature did not select exactly one pinned signer key")
        signer = accepted[0]
        inspected = _inspect_repository_apk(package_path)
        if inspected.builder_signer != PurePosixPath(signer).name:
            raise GateError("authenticated bootstrap APK signer basename mismatch")
        return VerifiedPackage(inspected.identity, signer)

    def close(self) -> None:
        """Remove only the private bootstrap files created by this verifier."""

        if self._closed:
            return
        try:
            if self.openssl_runtime is not None:
                runtime_root = self.private_root / "openssl-runtime"
                _validate_runtime_closure(
                    runtime_root,
                    self.openssl_runtime,
                    expected_identities=self.runtime_identities,
                )
                for member in self.openssl_runtime.members:
                    (runtime_root / member.destination_basename).unlink()
                (runtime_root / "modules").rmdir()
                runtime_root.rmdir()
            for name in ("apk.static.signature", "apk.static"):
                path = self.private_root / name
                if path.exists() and not path.is_symlink():
                    path.unlink()
            self.private_root.rmdir()
        except OSError as error:
            raise GateError(f"could not remove private apk.static bootstrap: {error}") from None
        self._closed = True


def bootstrap_apk_static_verifier(
    apk_tools_package: Path,
    *,
    package_record: Mapping[str, object],
    trusted_key_root: Path,
    bootstrap_root: Path,
    pins: ApkStaticBootstrapPins,
) -> PinnedApkStaticVerifier:
    """Authenticate and instantiate apk.static using pmbootstrap's trust chain."""

    pins = _validate_bootstrap_pins(pins)
    record = _validate_http_artifact(package_record, label="apk.static bootstrap artifact")
    package_path = Path(apk_tools_package)
    package_metadata, package_digest = _hash_stable_regular(
        package_path, label="apk-tools-static bootstrap package"
    )
    if (
        package_metadata.st_size != record["size"]
        or package_digest != record["sha256"]
        or record["name"] != "apk-tools-static"
        or record["version"] != pins.apk_static_version
    ):
        raise GateError("apk-tools-static bootstrap package differs from its pins")

    bootstrap_root = Path(bootstrap_root)
    if (
        not bootstrap_root.is_absolute()
        or bootstrap_root != Path(os.path.normpath(bootstrap_root))
        or bootstrap_root.exists()
        or bootstrap_root.is_symlink()
    ):
        raise GateError("apk.static bootstrap root must be a new normalized absolute path")
    _absolute_real_directory(bootstrap_root.parent, label="apk.static bootstrap parent")
    try:
        bootstrap_root.mkdir(mode=0o700)
        bootstrap_root.chmod(0o700)
    except OSError as error:
        raise GateError(f"could not create private apk.static bootstrap: {error}") from None

    binary_path = bootstrap_root / "apk.static"
    signature_path = bootstrap_root / "apk.static.signature"
    expected_basename = PurePosixPath(str(record["signer_key_path"])).name
    signature_name = f"sbin/apk.static.SIGN.RSA.sha256.{expected_basename}"
    try:
        package_bytes = _read_stable_regular_bytes(
            package_path,
            label="apk-tools-static bootstrap package",
            maximum=_MAX_FILE_BYTES,
        )
        _signature_tar, _signature_raw, control_offset = _gzip_member(
            package_bytes,
            0,
            label="apk-tools-static signature",
            maximum=_MAX_SIGNATURE_BYTES,
        )
        _control_tar, _control_raw, data_offset = _gzip_member(
            package_bytes,
            control_offset,
            label="apk-tools-static control",
            maximum=_MAX_PACKAGE_METADATA_BYTES,
        )
        data_tar, _data_raw, end_offset = _gzip_member(
            package_bytes,
            data_offset,
            label="apk-tools-static data",
            maximum=128 * 1024 * 1024,
        )
        if end_offset != len(package_bytes):
            raise GateError("apk-tools-static has trailing data after its v2 APK members")
        with tarfile.open(fileobj=io.BytesIO(data_tar), mode="r:") as archive:
            members = archive.getmembers()
            binaries = [item for item in members if item.name == "sbin/apk.static"]
            signatures = [item for item in members if item.name == signature_name]
            embedded = [
                item.name
                for item in members
                if item.name.startswith("sbin/apk.static.SIGN.RSA.sha256.")
            ]
            if len(binaries) != 1 or len(signatures) != 1 or embedded != [signature_name]:
                raise GateError(
                    "apk-tools-static does not contain one unambiguous pinned apk.static signature"
                )
            binary_size, binary_digest = _stream_tar_member(
                archive,
                binaries[0],
                binary_path,
                maximum=64 * 1024 * 1024,
                label="embedded apk.static",
            )
            _stream_tar_member(
                archive,
                signatures[0],
                signature_path,
                maximum=_MAX_SIGNATURE_BYTES,
                label="embedded apk.static signature",
            )
    except GateError:
        raise
    except (OSError, tarfile.TarError) as error:
        raise GateError(f"could not inspect apk-tools-static bootstrap package: {error}") from None
    if binary_size != pins.apk_static_size or binary_digest != pins.apk_static_sha256:
        raise GateError("embedded apk.static size or SHA-256 differs from its trust pin")

    key_path = Path(trusted_key_root).joinpath(
        *PurePosixPath(str(record["signer_key_path"])).parts
    )
    key_before, key_digest = _hash_stable_regular(
        key_path, label="apk.static bootstrap signer key", maximum=1024 * 1024
    )
    if key_digest != record["signer_key_sha256"]:
        raise GateError("apk.static bootstrap signer key differs from its pin")
    runtime_root = bootstrap_root / "openssl-runtime"
    runtime_identities = _copy_runtime_closure(
        runtime_root, pins.openssl_runtime
    )
    modules_root = runtime_root / "modules"
    environment = _verifier_environment(
        bootstrap_root, openssl_modules=modules_root
    )
    list_result = _run_command(
        _runtime_list_command(pins.openssl_runtime, runtime_root),
        cwd=bootstrap_root,
        environment=environment,
    )
    if list_result.returncode != 0:
        raise _command_failure("pinned isolated OpenSSL dependency query", list_result)
    _validate_runtime_resolution(
        pins.openssl_runtime, runtime_root, list_result.stdout
    )
    _validate_runtime_closure(
        runtime_root,
        pins.openssl_runtime,
        expected_identities=runtime_identities,
    )
    version_command = _runtime_command(
        pins.openssl_runtime, runtime_root, ("version",)
    )
    version_result = _run_command(
        version_command,
        cwd=bootstrap_root,
        environment=environment,
    )
    if version_result.returncode != 0:
        raise _command_failure("pinned isolated OpenSSL version query", version_result)
    _validate_runtime_closure(
        runtime_root,
        pins.openssl_runtime,
        expected_identities=runtime_identities,
    )
    version_fields = version_result.stdout.strip().split()
    if len(version_fields) < 2 or version_fields[1] != pins.openssl_runtime.version:
        raise GateError("pinned isolated OpenSSL reported an unexpected version")
    verify_command = _runtime_command(
        pins.openssl_runtime,
        runtime_root,
        (
            "dgst",
            "-sha256",
            "-verify",
            str(key_path),
            "-signature",
            str(signature_path),
            str(binary_path),
        ),
    )
    verify_result = _run_command(
        verify_command,
        cwd=bootstrap_root,
        environment=environment,
    )
    if verify_result.returncode != 0:
        raise _command_failure("embedded apk.static signature verification", verify_result)
    _validate_runtime_closure(
        runtime_root,
        pins.openssl_runtime,
        expected_identities=runtime_identities,
    )
    key_after, after_key_digest = _hash_stable_regular(
        key_path, label="apk.static bootstrap signer key", maximum=1024 * 1024
    )
    if (
        _metadata_identity(key_before) != _metadata_identity(key_after)
        or key_digest != after_key_digest
    ):
        raise GateError("signer key changed during apk.static bootstrap")
    binary_path.chmod(0o700)
    verifier = PinnedApkStaticVerifier(
        binary_path,
        apk_static_size=pins.apk_static_size,
        apk_static_sha256=pins.apk_static_sha256,
        apk_static_version=pins.apk_static_version,
        private_root=bootstrap_root,
        openssl_runtime=pins.openssl_runtime,
        runtime_identities=runtime_identities,
    )
    apk_version = verifier._run_apk(("--version",), cwd=bootstrap_root)
    if apk_version.returncode != 0:
        raise _command_failure("authenticated apk.static version query", apk_version)
    match = re.match(r"^apk-tools ([^,\s]+),", apk_version.stdout.strip())
    if match is None or match.group(1) != pins.apk_static_version:
        raise GateError("authenticated apk.static reported an unexpected version")
    return verifier


@dataclass(frozen=True)
class PromotionProfile:
    """Preapproved immutable facts required before quarantine can promote."""

    pins: Mapping[str, object]
    repositories: tuple[Mapping[str, object], ...]
    http_artifacts: tuple[Mapping[str, object], ...]
    distfiles: tuple[Mapping[str, object], ...]

    def as_mapping(self) -> dict[str, object]:
        return {
            "schema": PROMOTION_PROFILE_SCHEMA,
            "pins": _json_copy(self.pins),
            "repositories": [_json_copy(item) for item in self.repositories],
            "http_artifacts": [_json_copy(item) for item in self.http_artifacts],
            "distfiles": [_json_copy(item) for item in self.distfiles],
        }


@dataclass(frozen=True)
class VerifiedOfflineCache:
    root: Path
    manifest: Mapping[str, object]
    manifest_sha256: str
    aggregate_sha256: str


def canonical_json_bytes(value: object) -> bytes:
    """Return the sole accepted sorted, compact, ASCII JSON representation."""

    try:
        rendered = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as error:
        raise GateError(f"offline cache data is not canonical JSON data: {error}") from None
    return (rendered + "\n").encode("ascii")


def aggregate_sha256(manifest: Mapping[str, object]) -> str:
    """Hash the canonical manifest with ``aggregate_sha256`` omitted."""

    preimage = dict(manifest)
    preimage.pop("aggregate_sha256", None)
    return hashlib.sha256(canonical_json_bytes(preimage)).hexdigest()


def _json_copy(value: object) -> object:
    return json.loads(json.dumps(value, ensure_ascii=True))


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise GateError(f"offline cache JSON contains duplicate key: {key!r}")
        result[key] = value
    return result


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


def _require_exact_fields(
    value: object, expected: frozenset[str], *, label: str
) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != expected:
        raise GateError(f"{label} has unexpected or missing fields")
    return value


def _require_hash(value: object, pattern: re.Pattern[str], *, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GateError(f"{label} is not a lowercase hexadecimal digest")
    return value


def _require_token(
    value: object, *, label: str, package: bool = False
) -> str:
    pattern = _PACKAGE_TOKEN_RE if package else _TOKEN_RE
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise GateError(f"{label} is invalid")
    return value


def _require_size(value: object, *, label: str) -> int:
    if type(value) is not int or value < 0 or value > _MAX_FILE_BYTES:
        raise GateError(f"{label} is not a bounded non-negative integer")
    return value


def _require_url(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(character.isspace() or ord(character) < 32 for character in value)
    ):
        raise GateError(f"{label} is invalid")
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise GateError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise GateError(f"{label} contains forbidden URL components")
    return value


def _safe_relative_path(value: object, *, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\x00" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GateError(f"{label} is unsafe")
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
    ):
        raise GateError(f"{label} is unsafe")
    if len(value.encode("utf-8")) > 1024 or len(relative.parts) > 8:
        raise GateError(f"{label} exceeds the path limits")
    return value


def _cache_path(value: object, *, label: str) -> str:
    path = _safe_relative_path(value, label=label)
    if not path.startswith("work/"):
        raise GateError(f"{label} must be below work/")
    return path


def _signer_path(
    value: object, *, label: str, architecture: str | None = None
) -> str:
    path = _cache_path(value, label=label)
    parts = PurePosixPath(path).parts
    if (
        len(parts) != 3
        or parts[1] not in {"cache_apk_aarch64", "cache_apk_x86_64"}
    ):
        raise GateError(f"{label} must name one cache-local APK public key")
    if architecture is not None and parts[1] != f"cache_apk_{architecture}":
        raise GateError(f"{label} must be in its repository architecture cache")
    if not parts[-1].endswith(".rsa.pub"):
        raise GateError(f"{label} is not an APK RSA public key")
    return path


def _apkindex_name(url: str) -> str:
    digest = hashlib.sha1(url.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"APKINDEX.{digest[:8]}.tar.gz"


def _validate_pins(value: object) -> dict[str, object]:
    pins = _require_exact_fields(value, _PIN_FIELDS, label="pins")
    pmbootstrap = _require_exact_fields(
        pins["pmbootstrap"], _PMBOOTSTRAP_PIN_FIELDS, label="pins.pmbootstrap"
    )
    pmaports = _require_exact_fields(
        pins["pmaports"], _PMAPORTS_PIN_FIELDS, label="pins.pmaports"
    )
    _require_hash(pmbootstrap["commit"], _GIT_OBJECT_RE, label="pins.pmbootstrap.commit")
    _require_token(pmbootstrap["version"], label="pins.pmbootstrap.version")
    if type(pmbootstrap["work_version"]) is not int or pmbootstrap["work_version"] != WORK_VERSION:
        raise GateError(f"pins.pmbootstrap.work_version must be {WORK_VERSION}")
    _require_hash(pmaports["commit"], _GIT_OBJECT_RE, label="pins.pmaports.commit")
    _require_hash(pmaports["tree"], _GIT_OBJECT_RE, label="pins.pmaports.tree")
    if pmaports["channel"] != "edge":
        raise GateError("pins.pmaports.channel must be edge")
    return _json_copy(pins)  # type: ignore[return-value]


def _validate_repository(value: object, *, label: str) -> dict[str, object]:
    record = _require_exact_fields(value, _REPOSITORY_FIELDS, label=label)
    architecture = record["architecture"]
    if architecture not in ARCHITECTURES:
        raise GateError(f"{label}.architecture is unsupported")
    url = _require_url(record["url"], label=f"{label}.url")
    if url not in PRODUCTION_REPOSITORY_URLS:
        raise GateError(f"{label}.url is outside the locked production repositories")
    index_path = _cache_path(record["index_path"], label=f"{label}.index_path")
    expected_path = f"work/cache_apk_{architecture}/{_apkindex_name(url)}"
    if index_path != expected_path:
        raise GateError(f"{label}.index_path does not match its repository URL")
    _require_size(record["index_size"], label=f"{label}.index_size")
    _require_hash(record["index_sha256"], _SHA256_RE, label=f"{label}.index_sha256")
    _signer_path(
        record["signer_key_path"],
        label=f"{label}.signer_key_path",
        architecture=str(architecture),
    )
    _require_hash(
        record["signer_key_sha256"],
        _SHA256_RE,
        label=f"{label}.signer_key_sha256",
    )
    return _json_copy(record)  # type: ignore[return-value]


def _validate_external_apk(value: object, *, label: str) -> dict[str, object]:
    record = _require_exact_fields(value, _EXTERNAL_APK_FIELDS, label=label)
    architecture = record["architecture"]
    if architecture not in ARCHITECTURES:
        raise GateError(f"{label}.architecture is unsupported")
    _require_token(record["name"], label=f"{label}.name", package=True)
    _require_token(record["version"], label=f"{label}.version", package=True)
    path = _cache_path(record["path"], label=f"{label}.path")
    parts = PurePosixPath(path).parts
    if (
        len(parts) != 3
        or parts[1] not in {"cache_apk_aarch64", "cache_apk_x86_64"}
        or not parts[2].endswith(".apk")
    ):
        raise GateError(f"{label}.path is not a flat APK cache path")
    cache_architecture = parts[1].removeprefix("cache_apk_")
    if architecture != cache_architecture:
        raise GateError(f"{label}.architecture does not match its APK cache")
    _require_size(record["size"], label=f"{label}.size")
    _require_hash(record["sha256"], _SHA256_RE, label=f"{label}.sha256")
    _require_url(record["repository_url"], label=f"{label}.repository_url")
    _require_hash(record["index_sha256"], _SHA256_RE, label=f"{label}.index_sha256")
    _apkindex_checksum(
        record["apkindex_checksum"], label=f"{label}.apkindex_checksum"
    )
    _signer_path(
        record["index_signer_key_path"],
        label=f"{label}.index_signer_key_path",
        architecture=str(architecture),
    )
    _require_hash(
        record["index_signer_key_sha256"],
        _SHA256_RE,
        label=f"{label}.index_signer_key_sha256",
    )
    _require_token(
        record["builder_signer"], label=f"{label}.builder_signer", package=True
    )
    return _json_copy(record)  # type: ignore[return-value]


def _validate_http_artifact(value: object, *, label: str) -> dict[str, object]:
    record = _require_exact_fields(value, _HTTP_ARTIFACT_FIELDS, label=label)
    _require_token(record["kind"], label=f"{label}.kind")
    _require_token(record["name"], label=f"{label}.name", package=True)
    if record["kind"] != "apk-tools-static" or record["name"] != "apk-tools-static":
        raise GateError(f"{label} must be the pinned apk-tools-static artifact")
    _require_token(record["version"], label=f"{label}.version", package=True)
    _require_url(record["url"], label=f"{label}.url")
    path = _cache_path(record["path"], label=f"{label}.path")
    parts = PurePosixPath(path).parts
    if len(parts) != 3 or parts[1] != "cache_http":
        raise GateError(f"{label}.path is not a flat HTTP cache path")
    if parts[2].startswith("APKINDEX_"):
        raise GateError(f"{label}.path is a forbidden duplicate APKINDEX download")
    _require_size(record["size"], label=f"{label}.size")
    _require_hash(record["sha256"], _SHA256_RE, label=f"{label}.sha256")
    _signer_path(record["signer_key_path"], label=f"{label}.signer_key_path")
    _require_hash(
        record["signer_key_sha256"],
        _SHA256_RE,
        label=f"{label}.signer_key_sha256",
    )
    return _json_copy(record)  # type: ignore[return-value]


def _validate_distfile(value: object, *, label: str) -> dict[str, object]:
    record = _require_exact_fields(value, _DISTFILE_FIELDS, label=label)
    _require_url(record["url"], label=f"{label}.url")
    path = _cache_path(record["path"], label=f"{label}.path")
    parts = PurePosixPath(path).parts
    if len(parts) != 3 or parts[1] != "cache_distfiles":
        raise GateError(f"{label}.path is not a flat distfiles cache path")
    _require_size(record["size"], label=f"{label}.size")
    _require_hash(record["sha256"], _SHA256_RE, label=f"{label}.sha256")
    _require_hash(
        record["apkbuild_sha512"], _SHA512_RE, label=f"{label}.apkbuild_sha512"
    )
    return _json_copy(record)  # type: ignore[return-value]


def _validate_member(value: object, *, label: str) -> dict[str, object]:
    record = _require_exact_fields(value, _MEMBER_FIELDS, label=label)
    _cache_path(record["path"], label=f"{label}.path")
    _require_size(record["size"], label=f"{label}.size")
    _require_hash(record["sha256"], _SHA256_RE, label=f"{label}.sha256")
    return _json_copy(record)  # type: ignore[return-value]


def load_promotion_profile(path: Path) -> PromotionProfile:
    """Read a strict canonical promotion profile from a single regular file."""

    value, _payload = _read_canonical_json(Path(path), _MAX_MANIFEST_BYTES, "promotion profile")
    return validate_promotion_profile(value)


def validate_promotion_profile(value: object) -> PromotionProfile:
    profile = _require_exact_fields(value, _PROFILE_FIELDS, label="promotion profile")
    if profile["schema"] != PROMOTION_PROFILE_SCHEMA:
        raise GateError("unsupported offline cache promotion profile schema")
    pins = _validate_pins(profile["pins"])
    repositories_value = profile["repositories"]
    http_value = profile["http_artifacts"]
    distfiles_value = profile["distfiles"]
    if not isinstance(repositories_value, list) or len(repositories_value) != 8:
        raise GateError("promotion profile must pin four repositories for each architecture")
    if not isinstance(http_value, list) or len(http_value) != 1:
        raise GateError("promotion profile must pin exactly one apk-tools-static HTTP artifact")
    if not isinstance(distfiles_value, list) or len(distfiles_value) != 1:
        raise GateError("promotion profile must pin exactly one kernel distfile")
    repositories = tuple(
        _validate_repository(item, label=f"repositories[{index}]")
        for index, item in enumerate(repositories_value)
    )
    http_artifacts = tuple(
        _validate_http_artifact(item, label=f"http_artifacts[{index}]")
        for index, item in enumerate(http_value)
    )
    distfiles = tuple(
        _validate_distfile(item, label=f"distfiles[{index}]")
        for index, item in enumerate(distfiles_value)
    )
    if list(repositories) != sorted(
        repositories, key=lambda item: (str(item["architecture"]), str(item["url"]))
    ):
        raise GateError("promotion profile repositories are not canonically sorted")
    pairs = {(str(item["architecture"]), str(item["url"])) for item in repositories}
    expected_pairs = {
        (architecture, url)
        for architecture in ARCHITECTURES
        for url in PRODUCTION_REPOSITORY_URLS
    }
    if pairs != expected_pairs:
        raise GateError("promotion profile repository URL/architecture matrix is incomplete")
    if list(http_artifacts) != sorted(
        http_artifacts,
        key=lambda item: (
            str(item["kind"]),
            str(item["name"]),
            str(item["version"]),
            str(item["url"]),
            str(item["path"]),
        ),
    ):
        raise GateError("promotion profile HTTP artifacts are not canonically sorted")
    if list(distfiles) != sorted(
        distfiles, key=lambda item: (str(item["url"]), str(item["path"]))
    ):
        raise GateError("promotion profile distfiles are not canonically sorted")
    signer_bindings: dict[str, str] = {}
    for item in repositories:
        signer = str(item["signer_key_path"])
        digest = str(item["signer_key_sha256"])
        previous = signer_bindings.setdefault(signer, digest)
        if previous != digest:
            raise GateError(f"promotion profile pins conflicting signer key bytes: {signer}")
    for item in http_artifacts:
        if signer_bindings.get(str(item["signer_key_path"])) != item["signer_key_sha256"]:
            raise GateError("promotion profile HTTP signer must reference a repository key")
    paths = [str(item["index_path"]) for item in repositories] + [
        str(item["path"]) for item in http_artifacts + distfiles
    ] + list(signer_bindings)
    if len(paths) != len(set(paths)):
        raise GateError("promotion profile has duplicate artifact paths")
    return PromotionProfile(pins, repositories, http_artifacts, distfiles)


def _project_regular_file(project_root: Path, relative: str, *, label: str) -> Path:
    safe = _safe_relative_path(relative, label=label)
    path = project_root.joinpath(*PurePosixPath(safe).parts)
    try:
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve {label}: {error}") from None
    if resolved != path:
        raise GateError(f"{label} must not contain symlinks")
    return path


def _validate_expected_output(value: object, *, label: str) -> dict[str, object]:
    output = _require_exact_fields(value, _OUTPUT_FIELDS, label=label)
    if output["schema"] != MANIFEST_SCHEMA:
        raise GateError(f"{label}.schema differs from the supported cache schema")
    _require_hash(
        output["manifest_sha256"], _SHA256_RE, label=f"{label}.manifest_sha256"
    )
    _require_hash(
        output["aggregate_sha256"], _SHA256_RE, label=f"{label}.aggregate_sha256"
    )
    _require_size(output["member_count"], label=f"{label}.member_count")
    return dict(output)


def _validate_replay_report(
    value: object,
    *,
    acquisition: Mapping[str, object],
    expected_output: Mapping[str, object],
) -> dict[str, object]:
    report = _require_exact_fields(
        value,
        frozenset(
            {
                "schema",
                "scope",
                "acquisition",
                "first_promotion",
                "replay_promotion",
                "comparison",
            }
        ),
        label="promotion replay report",
    )
    if report["schema"] != PROMOTION_REPLAY_SCHEMA:
        raise GateError("promotion replay report schema is unsupported")
    if report["scope"] != "same-curated-acquisition-reproducibility-replay":
        raise GateError(
            "promotion replay report must describe a same-acquisition reproducibility replay"
        )
    report_acquisition = _require_exact_fields(
        report["acquisition"],
        frozenset({"inventory_sha256", "member_count"}),
        label="promotion replay acquisition",
    )
    if dict(report_acquisition) != {
        "inventory_sha256": acquisition["inventory_sha256"],
        "member_count": acquisition["member_count"],
    }:
        raise GateError("promotion replay report acquisition binding differs from attestation")
    first = _validate_expected_output(
        report["first_promotion"], label="promotion replay first output"
    )
    replay = _validate_expected_output(
        report["replay_promotion"], label="promotion replay second output"
    )
    if first != dict(expected_output) or replay != dict(expected_output):
        raise GateError("promotion replay outputs differ from the attested published output")
    comparison = _require_exact_fields(
        report["comparison"],
        frozenset({"byte_identical"}),
        label="promotion replay comparison",
    )
    if comparison["byte_identical"] is not True:
        raise GateError("promotion replay must attest byte-identical output")
    return _json_copy(report)  # type: ignore[return-value]


def _loaded_project_runtime_files(project_root: Path) -> dict[str, Path]:
    """Discover every imported project module; attestation must match exactly."""

    discovered: dict[str, Path] = {}
    for module in tuple(sys.modules.values()):
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str):
            continue
        if module_file.startswith("<") and module_file.endswith(">"):
            continue
        lexical_path = Path(os.path.abspath(module_file))
        try:
            lexical_path.relative_to(project_root)
            lexically_local = True
        except ValueError:
            lexically_local = False
        try:
            path = Path(module_file).resolve(strict=True)
        except OSError as error:
            if lexically_local:
                raise GateError(
                    f"loaded project runtime file cannot be resolved: {module_file}: "
                    f"{error}"
                ) from None
            continue
        try:
            relative_to_project = path.relative_to(project_root)
        except ValueError:
            if lexically_local:
                raise GateError(
                    f"loaded project runtime file resolves outside the project: "
                    f"{module_file}"
                )
            continue
        relative = PurePosixPath(*relative_to_project.parts).as_posix()
        previous = discovered.setdefault(relative, path)
        if not os.path.samefile(previous, path):
            raise GateError(f"project runtime path resolves to multiple files: {relative}")
    if not _REQUIRED_PROMOTION_RUNTIME_PATHS.issubset(discovered):
        missing = sorted(_REQUIRED_PROMOTION_RUNTIME_PATHS - set(discovered))
        raise GateError(f"promotion runtime module discovery is incomplete: {missing!r}")
    return dict(sorted(discovered.items()))


def _executing_promotion_context() -> tuple[Path, Path, dict[str, Path]]:
    """Bind authorization to this loaded CLI, package, common, and producer."""

    cli_candidates: list[Path] = []
    for name in ("__main__", "scripts.lmi_p1_cli", "lmi_p1_cli"):
        module = sys.modules.get(name)
        module_file = getattr(module, "__file__", None)
        if not isinstance(module_file, str):
            continue
        try:
            candidate = Path(module_file).resolve(strict=True)
        except OSError:
            continue
        if candidate.name == "lmi_p1_cli.py":
            cli_candidates.append(candidate)
    if not cli_candidates:
        raise GateError("executing promotion CLI is not a loaded CLI module")
    cli = cli_candidates[0]
    try:
        different_cli_loaded = any(
            not os.path.samefile(candidate, cli) for candidate in cli_candidates[1:]
        )
    except OSError as error:
        raise GateError(f"could not bind loaded promotion CLI modules: {error}") from None
    if different_cli_loaded:
        raise GateError("multiple different promotion CLI modules are loaded")
    try:
        offline = Path(__file__).resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve executing promotion code: {error}") from None
    if len(cli.parents) < 2:
        raise GateError("executing promotion CLI path has an invalid layout")
    project_root = cli.parents[1]
    project_root = _absolute_real_directory(
        project_root, label="executing promotion project root"
    )
    expected_cli = project_root / "scripts/lmi_p1_cli.py"
    expected_offline = project_root / "scripts/lmi_p1/offline_cache.py"
    if cli != expected_cli or offline != expected_offline:
        raise GateError("promotion authorization is not executing from its project root")
    runtime_files = _loaded_project_runtime_files(project_root)
    attestation_path = project_root.joinpath(*_CANONICAL_ATTESTATION_RELATIVE.parts)
    return project_root, attestation_path, runtime_files


def load_promotion_authorization() -> PromotionAuthorization:
    """Load and cross-bind the sole reviewed production attestation.

    The attestation must occupy its canonical repository-relative path.  Every
    referenced project file is canonical, regular, symlink-free, and hashed;
    callers cannot replace any individual trust pin on the command line.
    """

    project_root, attestation_path, runtime_files = _executing_promotion_context()
    return _load_promotion_authorization_from_context(
        project_root=project_root,
        attestation_path=attestation_path,
        runtime_files=runtime_files,
    )


def _load_promotion_authorization_from_context(
    *,
    project_root: Path,
    attestation_path: Path,
    runtime_files: Mapping[str, Path],
) -> PromotionAuthorization:
    value, _payload = _read_canonical_json(
        attestation_path, _MAX_MANIFEST_BYTES, "promotion attestation"
    )
    attestation = _require_exact_fields(
        value, _ATTESTATION_FIELDS, label="promotion attestation"
    )
    if attestation["schema"] != PROMOTION_ATTESTATION_SCHEMA:
        raise GateError("unsupported offline cache promotion attestation schema")

    profile_record = _require_exact_fields(
        attestation["profile"],
        frozenset({"path", "sha256"}),
        label="promotion attestation profile",
    )
    profile_relative = _safe_relative_path(
        profile_record["path"], label="promotion attestation profile.path"
    )
    if profile_relative != "config/lmi-p1/offline-cache-promotion.json":
        raise GateError("promotion attestation references a noncanonical profile")
    profile_sha256 = _require_hash(
        profile_record["sha256"],
        _SHA256_RE,
        label="promotion attestation profile.sha256",
    )
    profile_path = _project_regular_file(
        project_root, profile_relative, label="attested promotion profile"
    )
    profile_value, profile_payload = _read_canonical_json(
        profile_path, _MAX_MANIFEST_BYTES, "attested promotion profile"
    )
    if hashlib.sha256(profile_payload).hexdigest() != profile_sha256:
        raise GateError("attested promotion profile SHA-256 mismatch")
    profile = validate_promotion_profile(profile_value)

    trusted = _require_exact_fields(
        attestation["trusted_pmbootstrap"],
        frozenset({"commit", "tree", "signer_key_path", "signer_key_sha256"}),
        label="promotion attestation trusted_pmbootstrap",
    )
    commit = _require_hash(
        trusted["commit"], _GIT_OBJECT_RE, label="trusted pmbootstrap commit"
    )
    tree = _require_hash(
        trusted["tree"], _GIT_OBJECT_RE, label="trusted pmbootstrap tree"
    )
    if commit != profile.pins["pmbootstrap"]["commit"]:
        raise GateError("attested pmbootstrap commit differs from promotion profile")
    signer_key_path = _safe_relative_path(
        trusted["signer_key_path"], label="trusted pmbootstrap signer key path"
    )
    signer_parts = PurePosixPath(signer_key_path).parts
    if (
        len(signer_parts) != 4
        or signer_parts[:3] != ("pmb", "data", "keys")
        or not signer_parts[-1].endswith(".rsa.pub")
    ):
        raise GateError("trusted pmbootstrap signer key path is invalid")
    signer_key_sha256 = _require_hash(
        trusted["signer_key_sha256"],
        _SHA256_RE,
        label="trusted pmbootstrap signer key SHA-256",
    )
    bootstrap_record = profile.http_artifacts[0]
    if (
        PurePosixPath(str(bootstrap_record["signer_key_path"])).name
        != signer_parts[-1]
        or bootstrap_record["signer_key_sha256"] != signer_key_sha256
    ):
        raise GateError("attested bootstrap signer key differs from promotion profile")

    acquisition = _require_exact_fields(
        attestation["acquisition"],
        frozenset({"schema", "inventory_sha256", "member_count"}),
        label="promotion attestation acquisition",
    )
    if acquisition["schema"] != "lmi-p1-curated-offline-acquisition/v1":
        raise GateError("attested acquisition schema is unsupported")
    acquisition_inventory = _require_hash(
        acquisition["inventory_sha256"],
        _SHA256_RE,
        label="attested acquisition inventory SHA-256",
    )
    acquisition_count = _require_size(
        acquisition["member_count"], label="attested acquisition member_count"
    )

    producers_value = _require_exact_fields(
        attestation["producer_code"],
        frozenset({"curation", "promotion_runtime"}),
        label="promotion attestation producer_code",
    )

    def validate_producer_inventory(
        value: object,
        *,
        label: str,
        expected_paths: set[str] | frozenset[str],
        executing_files: Mapping[str, Path] | None = None,
    ) -> tuple[Mapping[str, str], ...]:
        if not isinstance(value, list) or len(value) != len(expected_paths):
            raise GateError(f"{label} inventory is incomplete")
        records: list[Mapping[str, str]] = []
        for index, item in enumerate(value):
            record = _require_exact_fields(
                item,
                frozenset({"path", "sha256"}),
                label=f"{label}[{index}]",
            )
            relative = _safe_relative_path(
                record["path"], label=f"{label}[{index}].path"
            )
            digest = _require_hash(
                record["sha256"], _SHA256_RE, label=f"{label}[{index}].sha256"
            )
            producer_path = _project_regular_file(
                project_root, relative, label=f"attested producer {relative}"
            )
            if executing_files is not None:
                actual_file = executing_files.get(relative)
                try:
                    matches_executing_file = actual_file is not None and os.path.samefile(
                        actual_file, producer_path
                    )
                except OSError:
                    matches_executing_file = False
                if not matches_executing_file:
                    raise GateError(
                        f"attested runtime producer is not the executing file: {relative}"
                    )
            _metadata, actual_digest = _hash_stable_regular(
                producer_path,
                label=f"attested producer {relative}",
                maximum=16 * 1024 * 1024,
            )
            if actual_digest != digest:
                raise GateError(f"attested producer code SHA-256 mismatch: {relative}")
            records.append({"path": relative, "sha256": digest})
        if (
            {item["path"] for item in records} != set(expected_paths)
            or records != sorted(records, key=lambda item: item["path"])
        ):
            raise GateError(f"{label} paths are not exact and sorted")
        return tuple(records)

    curation_producers = validate_producer_inventory(
        producers_value["curation"],
        label="promotion attestation curation producer",
        expected_paths=_CURATION_PRODUCER_PATHS,
    )
    runtime_producers = validate_producer_inventory(
        producers_value["promotion_runtime"],
        label="promotion attestation runtime producer",
        expected_paths=set(runtime_files),
        executing_files=runtime_files,
    )
    runtime_trust_value = _require_exact_fields(
        attestation["runtime_trust"],
        frozenset({"implementation", "python_major_minor", "stdlib"}),
        label="promotion attestation runtime_trust",
    )
    runtime_trust = {
        "implementation": "CPython",
        "python_major_minor": f"{sys.version_info.major}.{sys.version_info.minor}",
        "stdlib": "host-interpreter-matched-stdlib-assumed-trusted",
    }
    if sys.implementation.name != "cpython" or dict(runtime_trust_value) != runtime_trust:
        raise GateError("executing interpreter/stdlib trust assumption differs from attestation")

    apk_static = _require_exact_fields(
        attestation["apk_static"],
        frozenset({"extracted_member", "size", "sha256", "version"}),
        label="promotion attestation apk_static",
    )
    if apk_static["extracted_member"] != "sbin/apk.static":
        raise GateError("promotion attestation pins an unexpected apk.static member")
    apk_size = _require_size(apk_static["size"], label="attested apk.static size")
    apk_sha256 = _require_hash(
        apk_static["sha256"], _SHA256_RE, label="attested apk.static SHA-256"
    )
    apk_version = _require_token(
        apk_static["version"], label="attested apk.static version", package=True
    )
    if apk_version != bootstrap_record["version"]:
        raise GateError("attested apk.static version differs from promotion profile")

    runtime_record = _require_exact_fields(
        attestation["openssl_runtime"],
        frozenset(
            {"version", "members", "review_distribution", "review_packages"}
        ),
        label="promotion attestation OpenSSL runtime",
    )
    runtime_version = _require_token(
        runtime_record["version"], label="attested OpenSSL version", package=True
    )
    runtime_members_value = runtime_record["members"]
    if not isinstance(runtime_members_value, list):
        raise GateError("attested OpenSSL runtime members must be a list")
    runtime_members: list[RuntimeClosureMember] = []
    for index, item in enumerate(runtime_members_value):
        member = _require_exact_fields(
            item,
            frozenset(
                {"role", "source_path", "destination_basename", "size", "sha256"}
            ),
            label=f"attested OpenSSL runtime members[{index}]",
        )
        role = _require_token(member["role"], label="OpenSSL runtime role")
        source_path = Path(str(member["source_path"]))
        destination = _require_token(
            member["destination_basename"], label="OpenSSL runtime destination"
        )
        runtime_members.append(
            RuntimeClosureMember(
                role,
                source_path,
                destination,
                _require_size(member["size"], label=f"attested {role} size"),
                _require_hash(
                    member["sha256"], _SHA256_RE, label=f"attested {role} SHA-256"
                ),
            )
        )
    packages_value = runtime_record["review_packages"]
    if not isinstance(packages_value, list):
        raise GateError("OpenSSL review package provenance must be a list")
    runtime = _validate_runtime_closure_pins(
        OpenSslRuntimePins(
            runtime_version,
            tuple(runtime_members),
            str(runtime_record["review_distribution"]),
            tuple(packages_value),  # type: ignore[arg-type]
        )
    )

    expected_output = _validate_expected_output(
        attestation["published"], label="promotion attestation published"
    )
    replay_record = _require_exact_fields(
        attestation["replay_report"],
        frozenset({"path", "sha256"}),
        label="promotion attestation replay_report",
    )
    replay_relative = _safe_relative_path(
        replay_record["path"], label="promotion attestation replay_report.path"
    )
    if replay_relative != "config/lmi-p1/offline-cache-promotion-replay.json":
        raise GateError("promotion attestation references a noncanonical replay report")
    replay_digest = _require_hash(
        replay_record["sha256"], _SHA256_RE, label="promotion replay report SHA-256"
    )
    replay_path = _project_regular_file(
        project_root, replay_relative, label="attested promotion replay report"
    )
    replay_value, replay_payload = _read_canonical_json(
        replay_path, _MAX_MANIFEST_BYTES, "promotion replay report"
    )
    if hashlib.sha256(replay_payload).hexdigest() != replay_digest:
        raise GateError("promotion replay report SHA-256 mismatch")
    replay_report = _validate_replay_report(
        replay_value,
        acquisition=acquisition,
        expected_output=expected_output,
    )
    return PromotionAuthorization(
        project_root=project_root,
        profile=profile,
        profile_sha256=profile_sha256,
        trusted_pmbootstrap_commit=commit,
        trusted_pmbootstrap_tree=tree,
        signer_key_path=signer_key_path,
        signer_key_sha256=signer_key_sha256,
        acquisition_inventory_sha256=acquisition_inventory,
        acquisition_member_count=acquisition_count,
        producer_code={
            "curation": curation_producers,
            "promotion_runtime": runtime_producers,
        },
        runtime_trust=runtime_trust,
        bootstrap_pins=ApkStaticBootstrapPins(
            openssl_runtime=runtime,
            apk_static_size=apk_size,
            apk_static_sha256=apk_sha256,
            apk_static_version=apk_version,
        ),
        expected_output=expected_output,
        replay_report=replay_report,
    )


def _validate_manifest(value: object) -> dict[str, object]:
    manifest = _require_exact_fields(value, _TOP_LEVEL_FIELDS, label="offline cache manifest")
    if manifest["schema"] != MANIFEST_SCHEMA:
        raise GateError("unsupported offline cache manifest schema")
    normalized: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "pins": _validate_pins(manifest["pins"]),
    }
    specs = (
        ("repositories", _validate_repository, lambda item: (item["architecture"], item["url"])),
        (
            "external_apks",
            _validate_external_apk,
            lambda item: (item["architecture"], item["name"], item["version"], item["path"]),
        ),
        (
            "http_artifacts",
            _validate_http_artifact,
            lambda item: (item["kind"], item["name"], item["version"], item["url"], item["path"]),
        ),
        ("distfiles", _validate_distfile, lambda item: (item["url"], item["path"])),
        ("members", _validate_member, lambda item: item["path"]),
    )
    for field, validator, sort_key in specs:
        values = manifest[field]
        if not isinstance(values, list):
            raise GateError(f"offline cache manifest {field} must be a list")
        records = [validator(item, label=f"{field}[{index}]") for index, item in enumerate(values)]
        if records != sorted(records, key=sort_key):
            raise GateError(f"offline cache manifest {field} is not canonically sorted")
        keys = [sort_key(item) for item in records]
        if len(keys) != len(set(keys)):
            raise GateError(f"offline cache manifest {field} contains duplicates")
        normalized[field] = records

    repositories = normalized["repositories"]
    if len(repositories) != 8:
        raise GateError("offline cache manifest does not contain eight repository indexes")
    if len(normalized["http_artifacts"]) != 1:
        raise GateError("offline cache manifest must contain one apk-tools-static artifact")
    if len(normalized["distfiles"]) != 1:
        raise GateError("offline cache manifest must contain one kernel distfile")
    repository_keys = {
        (item["architecture"], item["url"], item["index_sha256"]): item
        for item in repositories
    }
    expected_pairs = {
        (architecture, url)
        for architecture in ARCHITECTURES
        for url in PRODUCTION_REPOSITORY_URLS
    }
    if {(item["architecture"], item["url"]) for item in repositories} != expected_pairs:
        raise GateError("offline cache repository URL/architecture matrix is incomplete")

    classified: dict[str, tuple[int, str]] = {}

    def classify(path: str, size: int, digest: str) -> None:
        if path in classified:
            raise GateError(f"offline cache member is classified more than once: {path}")
        classified[path] = (size, digest)

    for record, path_field, size_field, digest_field in (
        *((item, "index_path", "index_size", "index_sha256") for item in repositories),
        *((item, "path", "size", "sha256") for item in normalized["external_apks"]),
        *((item, "path", "size", "sha256") for item in normalized["http_artifacts"]),
        *((item, "path", "size", "sha256") for item in normalized["distfiles"]),
    ):
        path = str(record[path_field])
        classify(path, int(record[size_field]), str(record[digest_field]))

    signer_bindings: dict[str, str] = {}
    for repository in repositories:
        path = str(repository["signer_key_path"])
        digest = str(repository["signer_key_sha256"])
        previous = signer_bindings.setdefault(path, digest)
        if previous != digest:
            raise GateError(f"offline cache signer path has conflicting digests: {path}")
    for path, digest in signer_bindings.items():
        classify(path, -1, digest)

    for item in normalized["external_apks"]:
        key = (item["architecture"], item["repository_url"], item["index_sha256"])
        repository = repository_keys.get(key)
        if repository is None:
            raise GateError(f"external APK is not bound to one declared repository index: {item['path']}")
        if (
            item["index_signer_key_path"] != repository["signer_key_path"]
            or item["index_signer_key_sha256"] != repository["signer_key_sha256"]
        ):
            raise GateError(
                f"external APK index trust key is not bound to its repository: {item['path']}"
            )
    for item in normalized["http_artifacts"]:
        path = str(item["signer_key_path"])
        if signer_bindings.get(path) != item["signer_key_sha256"]:
            raise GateError("HTTP artifact signer must reference an existing repository key")

    members = normalized["members"]
    members_by_path = {str(item["path"]): item for item in members}
    expected_paths = {"work/version", *classified}
    if set(members_by_path) != expected_paths:
        missing = sorted(expected_paths - set(members_by_path))
        extra = sorted(set(members_by_path) - expected_paths)
        raise GateError(f"offline cache member classification mismatch: missing={missing!r}, extra={extra!r}")
    version_member = members_by_path["work/version"]
    expected_version = f"{normalized['pins']['pmbootstrap']['work_version']}\n".encode("ascii")
    if version_member["size"] != len(expected_version) or version_member["sha256"] != hashlib.sha256(expected_version).hexdigest():
        raise GateError("offline cache work/version member does not match its pin")
    for path, (size, digest) in classified.items():
        member = members_by_path[path]
        if (size >= 0 and member["size"] != size) or member["sha256"] != digest:
            raise GateError(f"offline cache classified record does not match member: {path}")
    total = sum(int(item["size"]) for item in members)
    if total > _MAX_TOTAL_BYTES:
        raise GateError("offline cache total member bytes exceed the limit")
    digest = _require_hash(manifest["aggregate_sha256"], _SHA256_RE, label="aggregate_sha256")
    normalized["aggregate_sha256"] = digest
    if aggregate_sha256(normalized) != digest:
        raise GateError("offline cache aggregate_sha256 mismatch")
    return normalized


def _read_canonical_json(path: Path, maximum: int, label: str) -> tuple[dict[str, object], bytes]:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise GateError(f"{label} must be one real, single-link regular file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not read {label}: {error}") from None
    if len(payload) > maximum:
        raise GateError(f"{label} exceeds its size limit")
    if not (_metadata_identity(before) == _metadata_identity(opened) == _metadata_identity(finished) == _metadata_identity(after)):
        raise GateError(f"{label} changed while reading")
    try:
        parsed = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"{label} is not valid canonical JSON: {error}") from None
    if not isinstance(parsed, dict):
        raise GateError(f"{label} must be a JSON object")
    if canonical_json_bytes(parsed) != payload:
        raise GateError(f"{label} bytes are not canonical")
    return parsed, payload


def _absolute_real_directory(path: Path, *, label: str, exact_mode: int | None = None) -> Path:
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise GateError(f"{label} must be an explicit normalized absolute path")
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if resolved != path or not stat.S_ISDIR(metadata.st_mode):
        raise GateError(f"{label} must be a real directory with no symlink ancestry")
    mode = stat.S_IMODE(metadata.st_mode)
    if exact_mode is not None and mode != exact_mode:
        raise GateError(f"{label} must have mode {exact_mode:04o}")
    if mode & 0o022:
        raise GateError(f"{label} must not be group/world writable")
    return path


def _hash_stable_regular(path: Path, *, label: str, maximum: int = _MAX_FILE_BYTES) -> tuple[os.stat_result, str]:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise GateError(f"{label} must be one real, single-link regular file")
    if stat.S_IMODE(before.st_mode) & 0o022:
        raise GateError(f"{label} must not be group/world writable")
    if before.st_size > maximum:
        raise GateError(f"{label} exceeds its size limit")
    digest = hashlib.sha256()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(_COPY_BLOCK_SIZE), b""):
                digest.update(block)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not hash {label}: {error}") from None
    if not (_metadata_identity(before) == _metadata_identity(opened) == _metadata_identity(finished) == _metadata_identity(after)):
        raise GateError(f"{label} changed while hashing")
    return before, digest.hexdigest()


def _verify_signer_keys(profile: PromotionProfile, trusted_key_root: Path) -> dict[str, str]:
    trusted_key_root = _absolute_real_directory(trusted_key_root, label="trusted pmbootstrap root")
    expected: dict[str, str] = {}
    for record in (*profile.repositories, *profile.http_artifacts):
        path = str(record["signer_key_path"])
        digest = str(record["signer_key_sha256"])
        previous = expected.setdefault(path, digest)
        if previous != digest:
            raise GateError(f"promotion profile pins conflicting digests for signer key {path}")
    for relative, digest in expected.items():
        basename = PurePosixPath(relative).name
        key = trusted_key_root / "pmb" / "data" / "keys" / basename
        _metadata, actual = _hash_stable_regular(
            key, label=f"pmbootstrap signer key {basename}", maximum=1024 * 1024
        )
        if actual != digest:
            raise GateError(f"signer key digest mismatch: {relative}")
    return expected


def _require_directory_entry(path: Path, *, label: str) -> None:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise GateError(f"{label} must be a real, non-group/world-writable directory")


def _inventory_acquisition(acquisition_root: Path, profile: PromotionProfile) -> list[str]:
    try:
        top = {entry.name for entry in os.scandir(acquisition_root)}
    except OSError as error:
        raise GateError(f"could not enumerate acquisition root: {error}") from None
    if top != _ALLOWED_ACQUISITION_TOP_LEVEL:
        missing = sorted(_ALLOWED_ACQUISITION_TOP_LEVEL - top)
        extra = sorted(top - _ALLOWED_ACQUISITION_TOP_LEVEL)
        raise GateError(f"acquisition top-level mismatch: missing={missing!r}, extra={extra!r}")
    for directory in sorted(_ALLOWED_ACQUISITION_TOP_LEVEL - {"version"}):
        _require_directory_entry(acquisition_root / directory, label=f"acquisition {directory}")

    expected_indexes: dict[str, set[str]] = {architecture: set() for architecture in ARCHITECTURES}
    for record in profile.repositories:
        parts = PurePosixPath(str(record["index_path"])).parts
        expected_indexes[str(record["architecture"])].add(parts[-1])
    paths = ["work/version"]
    for architecture in sorted(ARCHITECTURES):
        directory = acquisition_root / f"cache_apk_{architecture}"
        actual_indexes: set[str] = set()
        try:
            entries = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise GateError(f"could not enumerate acquisition APK cache {architecture}: {error}") from None
        for entry in entries:
            if entry.name.startswith("APKINDEX"):
                actual_indexes.add(entry.name)
                paths.append(f"work/cache_apk_{architecture}/{entry.name}")
            elif entry.name.endswith(".apk"):
                paths.append(f"work/cache_apk_{architecture}/{entry.name}")
            else:
                raise GateError(f"forbidden mutable or extra APK cache content: {entry.path}")
        if actual_indexes != expected_indexes[architecture]:
            missing = sorted(expected_indexes[architecture] - actual_indexes)
            stale = sorted(actual_indexes - expected_indexes[architecture])
            raise GateError(f"APKINDEX set mismatch for {architecture}: missing={missing!r}, stale_or_duplicate={stale!r}")

    for records, dirname, label in (
        (profile.http_artifacts, "cache_http", "HTTP cache"),
        (profile.distfiles, "cache_distfiles", "distfiles cache"),
    ):
        expected = {PurePosixPath(str(item["path"])).parts[-1] for item in records}
        directory = acquisition_root / dirname
        try:
            actual = {entry.name for entry in os.scandir(directory)}
        except OSError as error:
            raise GateError(f"could not enumerate acquisition {label}: {error}") from None
        if actual != expected:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            raise GateError(f"{label} set mismatch: missing={missing!r}, extra={extra!r}")
        paths.extend(f"work/{dirname}/{name}" for name in sorted(actual))
    return sorted(paths)


def _acquisition_identity(
    acquisition_root: Path, source_paths: Sequence[str]
) -> tuple[int, str]:
    """Return the curation-compatible public inventory identity."""

    inventory: list[dict[str, object]] = []
    for cache_path in source_paths:
        if not cache_path.startswith("work/"):
            raise GateError("acquisition inventory contains a non-work path")
        relative = cache_path.removeprefix("work/")
        metadata, digest = _hash_stable_regular(
            acquisition_root.joinpath(*PurePosixPath(relative).parts),
            label=f"attested acquisition member {relative}",
        )
        if stat.S_IMODE(metadata.st_mode) != 0o600:
            raise GateError(f"attested acquisition member must have mode 0600: {relative}")
        inventory.append(
            {"path": relative, "size": metadata.st_size, "sha256": digest}
        )
    inventory.sort(key=lambda item: str(item["path"]))
    return len(inventory), hashlib.sha256(canonical_json_bytes(inventory)).hexdigest()


def _trusted_pmbootstrap_identity(trusted_root: Path) -> tuple[str, str]:
    environment = _verifier_environment(trusted_root)
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    result = _run_command(
        (
            "/usr/bin/git",
            "--no-pager",
            "--no-replace-objects",
            "-c",
            "core.hooksPath=/dev/null",
            "-C",
            str(trusted_root),
            "rev-parse",
            "HEAD^{commit}",
            "HEAD^{tree}",
        ),
        cwd=trusted_root,
        environment=environment,
    )
    if result.returncode != 0:
        raise _command_failure("trusted pmbootstrap identity query", result)
    lines = result.stdout.splitlines()
    if len(lines) != 2 or any(_GIT_OBJECT_RE.fullmatch(line) is None for line in lines):
        raise GateError("trusted pmbootstrap identity query returned malformed output")
    return lines[0], lines[1]


def _validate_authorized_pmbootstrap(
    authorization: PromotionAuthorization, trusted_root: Path
) -> None:
    commit, tree = _trusted_pmbootstrap_identity(trusted_root)
    if (
        commit != authorization.trusted_pmbootstrap_commit
        or tree != authorization.trusted_pmbootstrap_tree
    ):
        raise GateError("trusted pmbootstrap commit or tree differs from attestation")
    key = trusted_root.joinpath(
        *PurePosixPath(authorization.signer_key_path).parts
    )
    _metadata, digest = _hash_stable_regular(
        key, label="attested pmbootstrap bootstrap signer key", maximum=1024 * 1024
    )
    if digest != authorization.signer_key_sha256:
        raise GateError("trusted pmbootstrap bootstrap signer key differs from attestation")


def _open_relative_parent(
    root: Path, relative: PurePosixPath, *, label: str
) -> tuple[int, str]:
    if relative.is_absolute() or not relative.parts:
        raise GateError(f"{label} has an invalid relative source path")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        current = os.open(root, directory_flags)
        for part in relative.parts[:-1]:
            try:
                child = os.open(part, directory_flags, dir_fd=current)
            finally:
                os.close(current)
            metadata = os.fstat(child)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                os.close(child)
                raise GateError(f"{label} has an unsafe source directory")
            current = child
        return current, relative.parts[-1]
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not open no-follow ancestry for {label}: {error}") from None


def _copy_stable_regular(
    source_root: Path,
    source_relative: PurePosixPath,
    destination: Path,
    *,
    seen_inodes: dict[tuple[int, int], str],
) -> dict[str, object]:
    source = source_root.joinpath(*source_relative.parts)
    parent_fd, source_name = _open_relative_parent(
        source_root, source_relative, label=f"acquisition member {source}"
    )
    try:
        before = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        os.close(parent_fd)
        raise GateError(f"could not inspect acquisition member {source}: {error}") from None
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        os.close(parent_fd)
        raise GateError(f"acquisition member is not one real, single-link regular file: {source}")
    if stat.S_IMODE(before.st_mode) & 0o022:
        os.close(parent_fd)
        raise GateError(f"acquisition member is group/world writable: {source}")
    if before.st_size > _MAX_FILE_BYTES:
        os.close(parent_fd)
        raise GateError(f"acquisition member exceeds the size limit: {source}")
    inode = (before.st_dev, before.st_ino)
    if inode in seen_inodes:
        os.close(parent_fd)
        raise GateError(f"acquisition member is hardlinked to {seen_inodes[inode]}: {source}")
    seen_inodes[inode] = str(source)
    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    copied = hashlib.sha256()
    try:
        source_fd = os.open(source_name, source_flags, dir_fd=parent_fd)
        try:
            destination_fd = os.open(destination, destination_flags, 0o600)
        except Exception:
            os.close(source_fd)
            raise
        with os.fdopen(source_fd, "rb") as input_stream, os.fdopen(destination_fd, "wb") as output_stream:
            opened = os.fstat(input_stream.fileno())
            if _metadata_identity(opened) != _metadata_identity(before):
                raise GateError(f"acquisition member changed while opening: {source}")
            for block in iter(lambda: input_stream.read(_COPY_BLOCK_SIZE), b""):
                copied.update(block)
                output_stream.write(block)
            output_stream.flush()
            os.fsync(output_stream.fileno())
            finished = os.fstat(input_stream.fileno())
        after = os.stat(source_name, dir_fd=parent_fd, follow_symlinks=False)
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not stream acquisition member {source}: {error}") from None
    finally:
        os.close(parent_fd)
    if not (_metadata_identity(before) == _metadata_identity(opened) == _metadata_identity(finished) == _metadata_identity(after)):
        raise GateError(f"acquisition member changed while copying: {source}")
    destination.chmod(0o600)
    copied_digest = copied.hexdigest()
    copied_metadata, rehashed = _hash_stable_regular(destination, label=f"quarantined member {destination}")
    if copied_metadata.st_size != before.st_size or rehashed != copied_digest:
        raise GateError(f"quarantined copy did not rehash to its source bytes: {destination}")
    return {"path": "", "size": before.st_size, "sha256": rehashed}


def _write_manifest(path: Path, manifest: Mapping[str, object]) -> bytes:
    payload = canonical_json_bytes(manifest)
    if len(payload) > _MAX_MANIFEST_BYTES:
        raise GateError("offline cache manifest exceeds its size limit")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
    except OSError as error:
        raise GateError(f"could not write quarantine manifest: {error}") from None
    return payload


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as error:
        raise GateError(f"could not fsync directory {path}: {error}") from None


def _directory_binding(metadata: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _open_promotion_parent(parent: Path) -> tuple[int, tuple[int, int, int, int, int]]:
    try:
        before = parent.lstat()
    except OSError as error:
        raise GateError(f"could not inspect promotion parent: {error}") from None
    if (
        not stat.S_ISDIR(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o700
        or before.st_uid != os.geteuid()
    ):
        raise GateError("promotion parent must be owner-controlled mode 0700")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(parent, flags)
    except OSError as error:
        raise GateError(f"could not open promotion parent: {error}") from None
    try:
        opened = os.fstat(descriptor)
        after = parent.lstat()
    except OSError as error:
        os.close(descriptor)
        raise GateError(f"could not bind promotion parent: {error}") from None
    binding = _directory_binding(before)
    if binding != _directory_binding(opened) or binding != _directory_binding(after):
        os.close(descriptor)
        raise GateError("promotion parent changed while opening")
    return descriptor, binding


def _validate_parent_path_binding(
    parent: Path,
    parent_fd: int,
    expected: tuple[int, int, int, int, int],
) -> None:
    try:
        path_metadata = parent.lstat()
        opened = os.fstat(parent_fd)
    except OSError as error:
        raise GateError(f"could not revalidate promotion parent: {error}") from None
    if (
        _directory_binding(path_metadata) != expected
        or _directory_binding(opened) != expected
    ):
        raise GateError("promotion parent pathname changed before publication")


def _open_bound_quarantine(
    parent_fd: int, name: str
) -> tuple[int, tuple[int, int, int, int, int]]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
        metadata = os.fstat(descriptor)
    except OSError as error:
        raise GateError(f"could not bind validated quarantine directory: {error}") from None
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o700:
        os.close(descriptor)
        raise GateError("validated quarantine directory must have mode 0700")
    return descriptor, _directory_binding(metadata)


def _validate_bound_directory_entry(
    parent_fd: int,
    name: str,
    held_fd: int,
    expected: tuple[int, int, int, int, int],
    *,
    label: str,
) -> None:
    try:
        pathname = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        held = os.fstat(held_fd)
    except OSError as error:
        raise GateError(f"could not revalidate {label}: {error}") from None
    if (
        not stat.S_ISDIR(pathname.st_mode)
        or _directory_binding(pathname) != expected
        or _directory_binding(held) != expected
    ):
        raise GateError(f"{label} pathname no longer names the validated directory inode")


def _renameat2_noreplace(
    source_dir_fd: int,
    source_name: str,
    destination_dir_fd: int,
    destination_name: str,
) -> None:
    """Linux atomic no-replace rename relative to held directory descriptors."""

    if (
        PurePosixPath(source_name).name != source_name
        or PurePosixPath(destination_name).name != destination_name
        or "\x00" in source_name
        or "\x00" in destination_name
    ):
        raise GateError("publication entry name is unsafe")
    libc = ctypes.CDLL(None, use_errno=True)
    function = getattr(libc, "renameat2", None)
    if function is None:
        raise GateError("renameat2(RENAME_NOREPLACE) is unavailable")
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    result = function(
        source_dir_fd,
        os.fsencode(source_name),
        destination_dir_fd,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    )
    if result != 0:
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number))


def _publish_bound_quarantine(
    *,
    parent: Path,
    parent_fd: int,
    parent_binding: tuple[int, int, int, int, int],
    quarantine_name: str,
    published_name: str,
    quarantine_fd: int,
    quarantine_binding: tuple[int, int, int, int, int],
) -> None:
    _validate_parent_path_binding(parent, parent_fd, parent_binding)
    _validate_bound_directory_entry(
        parent_fd,
        quarantine_name,
        quarantine_fd,
        quarantine_binding,
        label="quarantine",
    )
    try:
        os.stat(published_name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        pass
    except OSError as error:
        raise GateError(f"could not inspect publication destination: {error}") from None
    else:
        raise GateError("published root appeared before no-replace publication")
    try:
        _renameat2_noreplace(
            parent_fd, quarantine_name, parent_fd, published_name
        )
    except OSError as error:
        raise GateError(f"could not atomically publish offline cache: {error}") from None
    try:
        _validate_bound_directory_entry(
            parent_fd,
            published_name,
            quarantine_fd,
            quarantine_binding,
            label="published root",
        )
        _validate_parent_path_binding(parent, parent_fd, parent_binding)
        os.fsync(parent_fd)
        _validate_bound_directory_entry(
            parent_fd,
            published_name,
            quarantine_fd,
            quarantine_binding,
            label="published root after fsync",
        )
        _validate_parent_path_binding(parent, parent_fd, parent_binding)
    except (GateError, OSError) as validation_error:
        try:
            _renameat2_noreplace(
                parent_fd, published_name, parent_fd, quarantine_name
            )
            os.fsync(parent_fd)
        except (GateError, OSError) as rollback_error:
            raise GateError(
                "published inode mismatch and no-replace rollback failed: "
                f"{validation_error}; rollback={rollback_error}"
            ) from None
        if "published root pathname" in str(validation_error):
            label = "publication source inode substitution"
        else:
            label = "post-publication binding validation"
        raise GateError(f"{label} was rejected and rolled back: {validation_error}") from None


def _validate_verifier_identity(identity: PackageIdentity, *, label: str) -> None:
    if not isinstance(identity, PackageIdentity):
        raise GateError(f"trusted verifier returned an invalid {label} identity")
    _require_token(identity.name, label=f"{label}.name", package=True)
    _require_token(identity.version, label=f"{label}.version", package=True)
    _require_token(identity.architecture, label=f"{label}.architecture", package=True)


def _validate_indexed_package(package: IndexedPackage, *, label: str) -> None:
    if not isinstance(package, IndexedPackage):
        raise GateError(f"trusted verifier returned invalid {label} metadata")
    _validate_verifier_identity(package.identity, label=f"{label} identity")
    _require_size(package.size, label=f"{label}.size")
    _apkindex_checksum(package.apkindex_checksum, label=f"{label}.apkindex_checksum")


def _verify_quarantined_artifacts(
    quarantine_root: Path,
    profile: PromotionProfile,
    verifier: ApkSignatureVerifier,
    trusted_key_root: Path,
    members_by_path: Mapping[str, Mapping[str, object]],
    signer_keys: Mapping[str, str],
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    package_bindings: dict[
        tuple[str, str, str],
        list[tuple[Mapping[str, object], IndexedPackage]],
    ] = {}
    for repository in profile.repositories:
        path = quarantine_root.joinpath(*PurePosixPath(str(repository["index_path"])).parts)
        result = verifier.verify_index(
            path,
            repository_url=str(repository["url"]),
            architecture=str(repository["architecture"]),
            signer_key_path=str(repository["signer_key_path"]),
            trusted_key_root=trusted_key_root,
        )
        if not isinstance(result, VerifiedIndex) or result.architecture != repository["architecture"]:
            raise GateError(f"trusted verifier returned invalid index metadata for {repository['index_path']}")
        seen: set[PackageIdentity] = set()
        for package in result.packages:
            _validate_indexed_package(package, label="index package")
            identity = package.identity
            if identity.architecture not in {str(repository["architecture"]), "noarch"}:
                raise GateError(f"signed index contains an architecture-mismatched package: {package}")
            if identity in seen:
                raise GateError(f"signed index contains duplicate package identity: {identity}")
            seen.add(identity)
            binding_key = (
                str(repository["architecture"]),
                identity.name,
                identity.version,
            )
            package_bindings.setdefault(binding_key, []).append((repository, package))
    external: list[dict[str, object]] = []
    index_paths = {str(item["index_path"]) for item in profile.repositories}
    apk_paths = sorted(
        path for path in members_by_path
        if path.startswith("work/cache_apk_") and path.endswith(".apk") and path not in index_paths
    )
    seen_external: set[tuple[str, str, str]] = set()
    for relative in apk_paths:
        parts = PurePosixPath(relative).parts
        cache_architecture = parts[1].removeprefix("cache_apk_")
        path = quarantine_root.joinpath(*parts)
        inspected = _inspect_repository_apk(path)
        if inspected.identity.architecture not in {cache_architecture, "noarch"}:
            raise GateError(f"authenticated APK architecture does not match its cache: {relative}")
        cache_identity = (
            cache_architecture,
            inspected.identity.name,
            inspected.identity.version,
        )
        if cache_identity in seen_external:
            raise GateError(f"stale duplicate authenticated APK identity: {inspected.identity}")
        seen_external.add(cache_identity)
        matches = package_bindings.get(cache_identity, [])
        if len(matches) != 1:
            raise GateError(f"authenticated APK does not bind uniquely to one signed index: {relative}")
        repository, indexed = matches[0]
        member = members_by_path[relative]
        if member["size"] != indexed.size:
            raise GateError(f"authenticated APK size differs from signed APKINDEX S: {relative}")
        if inspected.apkindex_checksum != indexed.apkindex_checksum:
            raise GateError(
                f"authenticated APK control identity differs from signed APKINDEX C:Q1: {relative}"
            )
        index_signer = str(repository["signer_key_path"])
        external.append(
            {
                "architecture": cache_architecture,
                "name": inspected.identity.name,
                "version": inspected.identity.version,
                "path": relative,
                "size": member["size"],
                "sha256": member["sha256"],
                "repository_url": repository["url"],
                "index_sha256": repository["index_sha256"],
                "apkindex_checksum": indexed.apkindex_checksum,
                "index_signer_key_path": index_signer,
                "index_signer_key_sha256": signer_keys[index_signer],
                "builder_signer": inspected.builder_signer,
            }
        )

    http_records: list[dict[str, object]] = []
    for pinned in profile.http_artifacts:
        relative = str(pinned["path"])
        result = verifier.verify_package(
            quarantine_root.joinpath(*PurePosixPath(relative).parts),
            expected_cache_architecture=None,
            allowed_signer_key_paths=(str(pinned["signer_key_path"]),),
            trusted_key_root=trusted_key_root,
        )
        if not isinstance(result, VerifiedPackage):
            raise GateError(f"trusted verifier returned invalid HTTP APK metadata for {relative}")
        _validate_verifier_identity(result.identity, label="HTTP APK")
        if result.identity.name != pinned["name"] or result.identity.version != pinned["version"]:
            raise GateError("authenticated apk-tools-static identity differs from its promotion pin")
        if result.signer_key_path != pinned["signer_key_path"]:
            raise GateError("authenticated apk-tools-static signer differs from its promotion pin")
        http_records.append(dict(pinned))
    external.sort(key=lambda item: (item["architecture"], item["name"], item["version"], item["path"]))
    http_records.sort(
        key=lambda item: (
            item["kind"],
            item["name"],
            item["version"],
            item["url"],
            item["path"],
        )
    )
    return external, http_records


def promote_offline_cache(
    acquisition_root: Path,
    quarantine_root: Path,
    published_root: Path,
    profile: PromotionProfile | Mapping[str, object],
    *,
    trusted_key_root: Path,
    verifier: ApkSignatureVerifier | None = None,
    authorization: PromotionAuthorization | None = None,
) -> VerifiedOfflineCache:
    """Copy an exact acquisition into quarantine and atomically publish it.

    ``quarantine_root`` must be a new path in the same real, private parent as
    ``published_root``.  A failure leaves the quarantine unpublished for
    forensic inspection.  This function never downloads, invokes sudo, or
    touches hardware.
    """

    if verifier is None and authorization is None:
        raise GateError(
            "offline cache promotion is blocked: production requires the reviewed "
            "promotion attestation; a raw APKINDEX parser is not a verifier"
        )
    if verifier is not None and authorization is not None:
        raise GateError(
            "a fixture APK verifier cannot be combined with production authorization"
        )
    if isinstance(profile, PromotionProfile):
        profile = validate_promotion_profile(profile.as_mapping())
    else:
        profile = validate_promotion_profile(profile)
    if authorization is not None:
        if not isinstance(authorization, PromotionAuthorization):
            raise GateError("promotion authorization has an invalid type")
        authorized_profile = validate_promotion_profile(
            authorization.profile.as_mapping()
        )
        if profile.as_mapping() != authorized_profile.as_mapping():
            raise GateError("promotion profile differs from reviewed attestation")
    acquisition_root = _absolute_real_directory(Path(acquisition_root), label="acquisition root")
    trusted_key_root = _absolute_real_directory(Path(trusted_key_root), label="trusted pmbootstrap root")
    quarantine_root = Path(quarantine_root)
    published_root = Path(published_root)
    for path, label in ((quarantine_root, "quarantine root"), (published_root, "published root")):
        if not path.is_absolute() or path != Path(os.path.normpath(path)):
            raise GateError(f"{label} must be an explicit normalized absolute path")
    if quarantine_root.parent != published_root.parent or quarantine_root == published_root:
        raise GateError("quarantine and published roots must be distinct siblings for atomic promotion")
    parent = _absolute_real_directory(
        quarantine_root.parent, label="promotion parent", exact_mode=0o700
    )
    if parent.lstat().st_uid != os.geteuid():
        raise GateError("promotion parent must be owned by the effective user")
    if quarantine_root.exists() or quarantine_root.is_symlink() or published_root.exists() or published_root.is_symlink():
        raise GateError("quarantine and published roots must both be absent")

    source_paths = _inventory_acquisition(acquisition_root, profile)
    if authorization is not None:
        acquisition_count, acquisition_digest = _acquisition_identity(
            acquisition_root, source_paths
        )
        if (
            acquisition_count != authorization.acquisition_member_count
            or acquisition_digest != authorization.acquisition_inventory_sha256
        ):
            raise GateError("curated acquisition identity differs from reviewed attestation")
        _validate_authorized_pmbootstrap(authorization, trusted_key_root)
    signer_keys = _verify_signer_keys(profile, trusted_key_root)
    try:
        quarantine_root.mkdir(mode=0o700)
        quarantine_root.chmod(0o700)
        (quarantine_root / "work").mkdir(mode=0o700)
        (quarantine_root / "work").chmod(0o700)
        for relative in sorted(_ALLOWED_WORK_DIRECTORIES):
            directory = quarantine_root.joinpath(*PurePosixPath(relative).parts)
            directory.mkdir(mode=0o700)
            directory.chmod(0o700)
    except OSError as error:
        raise GateError(f"could not create new quarantine: {error}") from None

    seen_inodes: dict[tuple[int, int], str] = {}
    members: list[dict[str, object]] = []
    total = 0
    for relative in source_paths:
        destination = quarantine_root.joinpath(*PurePosixPath(relative).parts)
        source_relative = PurePosixPath(*PurePosixPath(relative).parts[1:])
        record = _copy_stable_regular(
            acquisition_root,
            source_relative,
            destination,
            seen_inodes=seen_inodes,
        )
        record["path"] = relative
        members.append(record)
        total += int(record["size"])
        if total > _MAX_TOTAL_BYTES:
            raise GateError("offline cache total member bytes exceed the limit")
    for relative in sorted(signer_keys):
        basename = PurePosixPath(relative).name
        destination = quarantine_root.joinpath(*PurePosixPath(relative).parts)
        record = _copy_stable_regular(
            trusted_key_root,
            PurePosixPath("pmb", "data", "keys", basename),
            destination,
            seen_inodes={},
        )
        record["path"] = relative
        if record["sha256"] != signer_keys[relative]:
            raise GateError(f"copied signer key digest mismatch: {relative}")
        members.append(record)
        total += int(record["size"])
        if total > _MAX_TOTAL_BYTES:
            raise GateError("offline cache total member bytes exceed the limit")
    members.sort(key=lambda item: str(item["path"]))
    members_by_path = {str(item["path"]): item for item in members}

    expected_version = f"{profile.pins['pmbootstrap']['work_version']}\n".encode("ascii")
    version = members_by_path["work/version"]
    if version["size"] != len(expected_version) or version["sha256"] != hashlib.sha256(expected_version).hexdigest():
        raise GateError("acquisition work version differs from its promotion pin")
    for record in profile.repositories:
        member = members_by_path[str(record["index_path"])]
        if member["size"] != record["index_size"] or member["sha256"] != record["index_sha256"]:
            raise GateError(f"pinned repository index bytes mismatch: {record['index_path']}")
    for record in (*profile.http_artifacts, *profile.distfiles):
        member = members_by_path[str(record["path"])]
        if member["size"] != record["size"] or member["sha256"] != record["sha256"]:
            raise GateError(f"pinned artifact bytes mismatch: {record['path']}")

    bootstrapped_verifier: PinnedApkStaticVerifier | None = None
    if verifier is None:
        if authorization is None:  # pragma: no cover - guarded above
            raise GateError("reviewed promotion authorization is missing")
        http_record = profile.http_artifacts[0]
        bootstrapped_verifier = bootstrap_apk_static_verifier(
            quarantine_root.joinpath(*PurePosixPath(str(http_record["path"])).parts),
            package_record=http_record,
            trusted_key_root=quarantine_root,
            bootstrap_root=quarantine_root / ".verifier-bootstrap",
            pins=authorization.bootstrap_pins,
        )
        verifier = bootstrapped_verifier
    external, http_artifacts = _verify_quarantined_artifacts(
        quarantine_root,
        profile,
        verifier,
        quarantine_root,
        members_by_path,
        signer_keys,
    )
    if bootstrapped_verifier is not None:
        bootstrapped_verifier.close()
    _verify_signer_keys(profile, trusted_key_root)
    manifest: dict[str, object] = {
        "schema": MANIFEST_SCHEMA,
        "pins": _json_copy(profile.pins),
        "repositories": [_json_copy(item) for item in profile.repositories],
        "external_apks": external,
        "http_artifacts": http_artifacts,
        "distfiles": [_json_copy(item) for item in profile.distfiles],
        "members": members,
    }
    manifest["aggregate_sha256"] = aggregate_sha256(manifest)
    normalized = _validate_manifest(manifest)
    payload = _write_manifest(quarantine_root / MANIFEST_NAME, normalized)
    for directory in sorted(_ALLOWED_WORK_DIRECTORIES, reverse=True):
        _fsync_directory(quarantine_root.joinpath(*PurePosixPath(directory).parts))
    _fsync_directory(quarantine_root / "work")
    _fsync_directory(quarantine_root)
    parent_fd, parent_binding = _open_promotion_parent(parent)
    quarantine_fd = -1
    try:
        quarantine_fd, quarantine_binding = _open_bound_quarantine(
            parent_fd, quarantine_root.name
        )
        _validate_bound_directory_entry(
            parent_fd,
            quarantine_root.name,
            quarantine_fd,
            quarantine_binding,
            label="quarantine",
        )
        verified = read_offline_cache_manifest(
            quarantine_root,
            expected_profile=profile,
            trusted_key_root=trusted_key_root,
        )
        _validate_bound_directory_entry(
            parent_fd,
            quarantine_root.name,
            quarantine_fd,
            quarantine_binding,
            label="validated quarantine",
        )
        if verified.manifest_sha256 != hashlib.sha256(payload).hexdigest():
            raise GateError("quarantine manifest changed before promotion")
        if authorization is not None:
            actual_output = {
                "schema": verified.manifest["schema"],
                "manifest_sha256": verified.manifest_sha256,
                "aggregate_sha256": verified.aggregate_sha256,
                "member_count": len(verified.manifest["members"]),
            }
            if actual_output != dict(authorization.expected_output):
                raise GateError("quarantine output differs from reviewed attestation")
            _validate_authorized_pmbootstrap(authorization, trusted_key_root)
            _verify_signer_keys(profile, trusted_key_root)
        _publish_bound_quarantine(
            parent=parent,
            parent_fd=parent_fd,
            parent_binding=parent_binding,
            quarantine_name=quarantine_root.name,
            published_name=published_root.name,
            quarantine_fd=quarantine_fd,
            quarantine_binding=quarantine_binding,
        )
    finally:
        if quarantine_fd >= 0:
            os.close(quarantine_fd)
        os.close(parent_fd)
    return VerifiedOfflineCache(
        root=published_root,
        manifest=verified.manifest,
        manifest_sha256=verified.manifest_sha256,
        aggregate_sha256=verified.aggregate_sha256,
    )


def read_offline_cache_manifest(
    cache_root: Path,
    *,
    expected_profile: PromotionProfile | Mapping[str, object] | None = None,
    trusted_key_root: Path | None = None,
) -> VerifiedOfflineCache:
    """Validate a canonical manifest and every physical cache member."""

    cache_root = _absolute_real_directory(Path(cache_root), label="offline cache root", exact_mode=0o700)
    try:
        top = {entry.name for entry in os.scandir(cache_root)}
    except OSError as error:
        raise GateError(f"could not enumerate offline cache root: {error}") from None
    if top != {"work", MANIFEST_NAME}:
        raise GateError(f"offline cache top-level mismatch: {sorted(top)!r}")
    _require_directory_entry(cache_root / "work", label="offline cache work directory")
    if stat.S_IMODE((cache_root / "work").lstat().st_mode) != 0o700:
        raise GateError("offline cache work directory must have mode 0700")
    parsed, payload = _read_canonical_json(cache_root / MANIFEST_NAME, _MAX_MANIFEST_BYTES, "offline cache manifest")
    manifest = _validate_manifest(parsed)
    if stat.S_IMODE((cache_root / MANIFEST_NAME).lstat().st_mode) != 0o600:
        raise GateError("offline cache manifest must have mode 0600")

    if expected_profile is not None:
        if isinstance(expected_profile, PromotionProfile):
            profile = validate_promotion_profile(expected_profile.as_mapping())
        else:
            profile = validate_promotion_profile(expected_profile)
        for field in ("pins", "repositories", "http_artifacts", "distfiles"):
            expected_value = profile.as_mapping()[field]
            if manifest[field] != expected_value:
                raise GateError(f"offline cache manifest differs from promotion profile: {field}")
        if trusted_key_root is None:
            raise GateError("trusted_key_root is required when binding a promotion profile")
        _verify_signer_keys(profile, Path(trusted_key_root))

    expected_files = {str(item["path"]): item for item in manifest["members"]}
    expected_dirs = {"work", *_ALLOWED_WORK_DIRECTORIES}
    actual_files: set[str] = set()
    actual_dirs: set[str] = set()
    regular_inodes: dict[tuple[int, int], str] = {}
    for current, dirnames, filenames in os.walk(cache_root / "work", topdown=True, followlinks=False):
        current_path = Path(current)
        current_relative = current_path.relative_to(cache_root).as_posix()
        actual_dirs.add(current_relative)
        for name in list(dirnames):
            child = current_path / name
            metadata = child.lstat()
            if not stat.S_ISDIR(metadata.st_mode):
                raise GateError(f"offline cache contains a symlink or special directory entry: {child}")
            if stat.S_IMODE(metadata.st_mode) != 0o700:
                raise GateError(f"offline cache directory must have mode 0700: {child}")
        for name in filenames:
            child = current_path / name
            relative = child.relative_to(cache_root).as_posix()
            metadata, digest = _hash_stable_regular(child, label=f"offline cache member {relative}")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise GateError(f"offline cache member must have mode 0600: {relative}")
            inode = (metadata.st_dev, metadata.st_ino)
            if inode in regular_inodes:
                raise GateError(f"offline cache member is hardlinked to {regular_inodes[inode]}: {relative}")
            regular_inodes[inode] = relative
            record = expected_files.get(relative)
            if record is None or record["size"] != metadata.st_size or record["sha256"] != digest:
                raise GateError(f"offline cache member inventory mismatch: {relative}")
            actual_files.add(relative)
    if actual_dirs != expected_dirs:
        raise GateError(f"offline cache directory layout mismatch: {sorted(actual_dirs)!r}")
    if actual_files != set(expected_files):
        missing = sorted(set(expected_files) - actual_files)
        extra = sorted(actual_files - set(expected_files))
        raise GateError(f"offline cache file inventory mismatch: missing={missing!r}, extra={extra!r}")
    return VerifiedOfflineCache(
        root=cache_root,
        manifest=manifest,
        manifest_sha256=hashlib.sha256(payload).hexdigest(),
        aggregate_sha256=str(manifest["aggregate_sha256"]),
    )


__all__ = [
    "ARCHITECTURES",
    "ApkStaticBootstrapPins",
    "ApkSignatureVerifier",
    "MANIFEST_NAME",
    "MANIFEST_SCHEMA",
    "PROMOTION_ATTESTATION_SCHEMA",
    "PROMOTION_PROFILE_SCHEMA",
    "PROMOTION_REPLAY_SCHEMA",
    "PRODUCTION_REPOSITORY_URLS",
    "IndexedPackage",
    "InspectedPackage",
    "PackageIdentity",
    "PinnedApkStaticVerifier",
    "OpenSslRuntimePins",
    "PromotionAuthorization",
    "PromotionProfile",
    "RuntimeClosureMember",
    "VerifiedIndex",
    "VerifiedOfflineCache",
    "VerifiedPackage",
    "aggregate_sha256",
    "bootstrap_apk_static_verifier",
    "canonical_json_bytes",
    "load_promotion_profile",
    "load_promotion_authorization",
    "promote_offline_cache",
    "read_offline_cache_manifest",
    "validate_promotion_profile",
]
