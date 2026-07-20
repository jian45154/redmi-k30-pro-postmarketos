"""Isolated, fail-closed construction of the lmi P1 SSH candidate."""

from __future__ import annotations

import base64
import binascii
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import stat
import sys
import tarfile
from threading import RLock
from typing import Mapping, Sequence

from . import pmaports as _pmaports_module
from .artifact_semantics import (
    ArtifactExpectations,
    PartitionLimits,
    RootfsBindings,
    load_initramfs_manifest,
    recheck_input_identities,
    validate_artifact_pair,
)
from .common import GateError, run, sha256_file, write_json
from .known_good_kernel import (
    APK_STATIC_SHA256 as _KNOWN_GOOD_APK_STATIC_SHA256,
    PACKAGE_ARCH as _KNOWN_GOOD_ARCH,
    PACKAGE_DESCRIPTION as _KNOWN_GOOD_DESCRIPTION,
    PACKAGE_NAME as _KNOWN_GOOD_NAME,
    PACKAGE_ORIGIN as _KNOWN_GOOD_ORIGIN,
    PACKAGE_VERSION as _KNOWN_GOOD_VERSION,
    PACKAGE_WORLD_CHECKSUM as _KNOWN_GOOD_WORLD_CHECKSUM,
    PAYLOAD as _KNOWN_GOOD_PAYLOAD,
    SCHEMA as _KNOWN_GOOD_SCHEMA,
    SOURCE_APK_SHA256 as _KNOWN_GOOD_SOURCE_APK_SHA256,
    SOURCE_APK_SIZE as _KNOWN_GOOD_SOURCE_APK_SIZE,
    SOURCE_DATE_EPOCH as _KNOWN_GOOD_SOURCE_DATE_EPOCH,
)
from .pmaports import (
    _compare_physical_trees,
    _reject_promisor_and_alternates,
    _reject_replace_refs,
    _reject_special_index_flags,
    _require_local_object_closure,
    _secure_checkout,
    prepare_pmaports,
    validate_staged_pmaports,
)
from .seal import (
    OFFLINE_CACHE_SCHEMA,
    VerifiedSeal,
    offline_cache_aggregate_preimage,
    read_active_policy,
    verify_offline_cache,
)


_EXPECTED_PMBOOTSTRAP_VERSION = "3.11.1"
_EXPECTED_PMBOOTSTRAP_COMMIT = "ce76febabd983db6445fa9a8b75d601970b2f436"
_EXPECTED_PMAPORTS_COMMIT = "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
_IDENTITY_SCHEMA = "lmi-p1-release-identity/v2"
_ARTIFACT_MANIFEST_SCHEMA = "lmi-p1-artifact-manifest/v1"
_PRIVILEGE_UNSEALED = "unsealed-development"
_PRIVILEGE_SEALED = "root-owned-sealed-production"
_UNSEALED_POLICY_ID = "none"
_ARTIFACT_CLASSIFICATION = "owner-test-private"
_ARTIFACT_PUBLICATION = "never-publish"
_ARTIFACT_CREDENTIAL_STATE = "owner-key-provisioned"
_EXPECTED_SOURCE_REPOSITORY = "jian45154/redmi-k30-pro-postmarketos"
_EXPECTED_KERNEL_COMMIT = "a5b3099017ae581aae8bf597b2f9c8c765026af1"
_EXPECTED_KERNEL_REMOTE = "https://github.com/LineageOS/android_kernel_xiaomi_sm8250"
_EXPECTED_KERNEL_TARBALL_SHA512 = (
    "b9d00e0efcb88d613bd65b1f2cd6b75e2b5f0d79b23def0b9c14eb397265e582"
    "a580e93cb365d81e7aa167b027920845ff8db798bbf781bbd9e7845e796bd923"
)
_EXPECTED_KERNEL_APKBUILD_SHA256 = (
    "dd61bde546ef99db0c734f79876b21155910c6b3583c91f2b696dcb3043f80ff"
)
_EXPECTED_VMLINUZ_SHA256 = (
    "38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e"
)
_KNOWN_GOOD_APK_PATH = (
    "artifacts/lmi-p1/known-good-kernel/"
    "linux-xiaomi-lmi-4.19.325-r8-p1-known-good.apk"
)
_KNOWN_GOOD_APK_SHA256 = (
    "01b199611407c100c621599bd3060084c19e1fd90f8e9df64cc10966f6949eb0"
)
_KNOWN_GOOD_APK_SIZE = 17418891
_KNOWN_GOOD_STATUS_INDEX_PATH = (
    "artifacts/lmi-p1/known-good-kernel/pmbootstrap-status-APKINDEX.tar.gz"
)
_KNOWN_GOOD_STATUS_INDEX_SHA256 = (
    "62578fea929f40c9b8ee8a66d96eefb2daaf6b77fb86be52a240d2979d76fe3b"
)
_KNOWN_GOOD_STATUS_INDEX_SIZE = 332
_KNOWN_GOOD_PUBLIC_KEY_PATH = (
    "artifacts/lmi-p1/known-good-kernel/lmi-p1-known-good-kernel.rsa.pub"
)
_KNOWN_GOOD_PUBLIC_KEY_SHA256 = (
    "c42ba833751ab9ca164c506cd72c2c3b9a6079db09ebe2cf52838ae79e936736"
)
_KNOWN_GOOD_PUBLIC_KEY_SIZE = 800
_KNOWN_GOOD_INSTALL_APK_NAME = (
    "linux-xiaomi-lmi-4.19.325-r8-p1-known-good.apk"
)
_EXPECTED_KNOWN_GOOD_KERNEL_PIN: dict[str, object] = {
    "apk_tools": {
        "sha256": _KNOWN_GOOD_APK_STATIC_SHA256,
        "version": "3.0.6-r0",
    },
    "artifact": {
        "format": "apk-v3",
        "path": _KNOWN_GOOD_APK_PATH,
        "sha256": _KNOWN_GOOD_APK_SHA256,
        "size": _KNOWN_GOOD_APK_SIZE,
        "world_checksum": _KNOWN_GOOD_WORLD_CHECKSUM,
    },
    "historical_installed_db_sha256": (
        "0cb29b13383b606e443ff803a3b5ceb55a8ce266951ff0b1ccd1600ecfc595c5"
    ),
    "identity": {
        "architecture": _KNOWN_GOOD_ARCH,
        "description": _KNOWN_GOOD_DESCRIPTION,
        "name": _KNOWN_GOOD_NAME,
        "origin": _KNOWN_GOOD_ORIGIN,
        "version": _KNOWN_GOOD_VERSION,
    },
    "payload": {
        path: {
            "historical_q1": historical_q1,
            "mode": f"{mode:04o}",
            "sha256": sha256,
        }
        for path, (sha256, historical_q1, mode) in _KNOWN_GOOD_PAYLOAD.items()
    },
    "pmbootstrap_status_index": {
        "install_trust": False,
        "path": _KNOWN_GOOD_STATUS_INDEX_PATH,
        "sha256": _KNOWN_GOOD_STATUS_INDEX_SHA256,
        "size": _KNOWN_GOOD_STATUS_INDEX_SIZE,
    },
    "schema": _KNOWN_GOOD_SCHEMA,
    "selection": {
        "sealed_build": "signed-apkv3-direct-path",
        "unsealed_build": "normal-source-build",
    },
    "signer_public_key": {
        "path": _KNOWN_GOOD_PUBLIC_KEY_PATH,
        "sha256": _KNOWN_GOOD_PUBLIC_KEY_SHA256,
        "size": _KNOWN_GOOD_PUBLIC_KEY_SIZE,
    },
    "source_apk": {
        "acquisition_provenance": "unavailable",
        "format": "apk-v2",
        "sha256": _KNOWN_GOOD_SOURCE_APK_SHA256,
        "signature_verification": {
            "apk_tools_sha256": _KNOWN_GOOD_APK_STATIC_SHA256,
            "result": "untrusted-signature",
            "signer_provenance": "unavailable",
        },
        "size": _KNOWN_GOOD_SOURCE_APK_SIZE,
    },
    "source_date_epoch": _KNOWN_GOOD_SOURCE_DATE_EPOCH,
}
_EXPECTED_KERNEL_LOCAL_SHA512 = {
    "config-xiaomi-lmi.aarch64": (
        "77d20ff63c11cd412a8daae4d5cc8d633b5e6adea06d606a80e1d43034c54b9fc"
        "41b521cc3a81503f9063a986c914ef85cb413ae5ae0907f5353cf9323661521"
    ),
    "lmi-vfs-mount-diagnostic.patch": (
        "615d7118a9053a776f9121ba74b8f847ed436d8e9eebdb9cb265ee7e73efc5cb8"
        "44159ab34891ac3014169e7b2894a78e8d2ce68f0f3d6bd2fc064cc30a7bd2d"
    ),
    "lmi-rmtfs-mem-node.patch": (
        "7d868893515778256b85a87f30adbe085588d3ae288fb8ec56b8a936a8e6e6b1d"
        "fa643dc086283da6d7d0747b90d1b6b9aa94aff65de693e8ebe0b676052be79"
    ),
}
_COMMAND_TIMEOUT = 4 * 60 * 60
_GIT = "/usr/bin/git"
_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_PACKAGES = (
    "postmarketos-initramfs",
    "linux-xiaomi-lmi",
    "device-xiaomi-lmi",
)
_REQUIRED_PACKAGE_VERSIONS = {
    "device-xiaomi-lmi": "1-r107",
    "linux-xiaomi-lmi": "4.19.325-r8",
}
_DHCP_PACKAGE_NAMES = ("unudhcpd", "unudhcpd-openrc")
_FORBIDDEN_DHCP_PACKAGE_NAMES = {
    "dhcp",
    "dhcp-server",
    "dnsmasq",
    "dnsmasq-dnssec",
    "dnsmasq-dnssec-dbus",
    "kea-dhcp4",
    "networkmanager-dnsmasq",
    "udhcpd",
}
_FORBIDDEN_PACKAGE_IDS = {
    "device-xiaomi-lmi-1-r139",
    "linux-xiaomi-lmi-4.19.325-r9",
}
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA512_RE = re.compile(r"^[0-9a-f]{128}$")
_UUID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_EXPECTED_DTB_STEM = "qcom/kona-v2.1-lmi"
_STANDARD_EXPORT_TARGETS = {
    "boot.img": ("rootfs", "boot/boot.img"),
    "vendor_boot.img": ("rootfs", "boot/vendor_boot.img"),
    "uInitrd": ("rootfs", "boot/uInitrd"),
    "uImage": ("rootfs", "boot/uImage"),
    "dtbo.img": ("rootfs", "boot/dtbo.img"),
    "xiaomi-lmi.img": ("native", "home/pmos/rootfs/xiaomi-lmi.img"),
    "xiaomi-lmi-boot.img": ("native", "home/pmos/rootfs/xiaomi-lmi-boot.img"),
    "xiaomi-lmi-root.img": ("native", "home/pmos/rootfs/xiaomi-lmi-root.img"),
    "pmos-xiaomi-lmi.zip": (
        "buildroot",
        "var/lib/postmarketos-android-recovery-installer/pmos-xiaomi-lmi.zip",
    ),
    "lk2nd.img": ("rootfs", "boot/lk2nd.img"),
}
_REQUIRED_STANDARD_EXPORTS = {"boot.img", "xiaomi-lmi.img"}
_PRIVATE_ENVIRONMENT_ROOT: ContextVar[Path | None] = ContextVar(
    "lmi_p1_private_environment_root", default=None
)
_PMAPORTS_ENVIRONMENT_LOCK = RLock()


@dataclass(frozen=True)
class BuildContext:
    repo: Path
    tag: str
    privilege_model: str
    policy_id: str
    source_commit: str
    work: Path
    pmaports: Path
    pmbootstrap: Path
    public_key: Path
    public_key_fingerprint: str


_SEALED_AUTHORIZATION_MARKER = object()


@dataclass(frozen=True)
class _SealedBuildAuthorization:
    context: BuildContext
    seal: VerifiedSeal
    run_root: Path
    source_lock: Mapping[str, object]
    offline_cache: Path
    offline_cache_manifest: Mapping[str, object]
    marker: object


@dataclass(frozen=True)
class BuildResult:
    boot_img: Path
    userdata_img: Path
    vmlinuz: Path
    initramfs: Path
    dtb_dir: Path
    packages: Path
    world: Path
    sshd_pam: Path
    semantics: Path
    build_log: Path
    identity: Path
    manifest: Path
    manifest_sha256: str
    artifact_set_id: str


@dataclass(frozen=True)
class _ApkPackageRecord:
    name: str
    version: str
    architecture: str | None
    origin: str | None
    files: tuple[tuple[str, str | None], ...]


@dataclass
class _VerifiedExport:
    link: Path
    target: Path
    source_fd: int
    source_identity: tuple[int, int, int, int, int, int]
    source_parent_fd: int
    source_name: str
    destination_parent_fd: int
    destination_name: str
    link_identity: tuple[int, int, int, int, int, int]

    def close(self) -> None:
        for descriptor in (
            self.source_fd,
            self.source_parent_fd,
            self.destination_parent_fd,
        ):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _overlaps(left: Path, right: Path) -> bool:
    return left == right or _is_within(left, right) or _is_within(right, left)


def _real_directory(path: Path, label: str) -> Path:
    if path.is_symlink() or not path.is_dir():
        raise GateError(f"{label} must be a real directory: {path}")
    try:
        return path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve {label}: {error}") from None


def _real_file(path: Path, label: str, *, executable: bool = False) -> Path:
    try:
        mode = path.resolve(strict=True).stat().st_mode
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve {label}: {error}") from None
    if not stat.S_ISREG(mode):
        raise GateError(f"{label} must resolve to a regular file: {path}")
    if executable and not os.access(resolved, os.X_OK):
        raise GateError(f"{label} is not executable: {path}")
    return resolved


def _prepare_empty_root(path: Path) -> Path:
    if os.path.lexists(path):
        raise GateError(f"candidate work must not already exist: {path}")
    parent = path.parent
    effective_uid = os.geteuid()
    current = Path(path.anchor)
    for component in parent.parts[1:]:
        current /= component
        try:
            metadata = current.lstat()
        except OSError as error:
            raise GateError(f"cannot inspect candidate work ancestry: {error}") from None
        permission = stat.S_IMODE(metadata.st_mode)
        writable = bool(permission & 0o022)
        sticky_safe = bool(metadata.st_mode & stat.S_ISVTX) and (
            effective_uid != 0 or metadata.st_uid == 0
        )
        owner_safe = metadata.st_uid in {0, effective_uid}
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISDIR(metadata.st_mode)
            or (writable and not sticky_safe)
            or (not writable and not owner_safe)
        ):
            raise GateError(f"unsafe candidate work ancestry: {current}")
    try:
        path.mkdir(mode=0o700)
        created = path.lstat()
    except OSError as error:
        raise GateError(f"could not create candidate work: {error}") from None
    if (
        not stat.S_ISDIR(created.st_mode)
        or created.st_uid != effective_uid
        or stat.S_IMODE(created.st_mode) != 0o700
    ):
        raise GateError("candidate work is not a private current-euid directory")
    return path.resolve(strict=True)


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"could not read {label}: {error}") from None


def _private_runtime_directory(path: Path, label: str) -> Path:
    """Create or verify one current-euid-only subprocess directory."""

    try:
        path.mkdir(mode=0o700, parents=False, exist_ok=True)
        metadata = path.lstat()
    except OSError as error:
        raise GateError(
            f"could not prepare private {label}: errno {error.errno or 'unknown'}"
        ) from None
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise GateError(f"private {label} has unsafe ownership or mode")
    return path.resolve(strict=True)


def _private_subprocess_directories() -> dict[str, Path]:
    root = _PRIVATE_ENVIRONMENT_ROOT.get()
    if root is None:
        raise GateError("private subprocess environment is not initialized")
    root = _private_runtime_directory(Path(root), "subprocess root")
    return {
        name: _private_runtime_directory(root / name, f"subprocess {name}")
        for name in ("home", "tmp", "cache", "config", "data")
    }


def _git_environment(*, allow_file_protocol: bool = False) -> dict[str, str]:
    private = _private_subprocess_directories()
    return {
        "HOME": str(private["home"]),
        "USER": "root",
        "LOGNAME": "root",
        "SHELL": "/bin/sh",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": str(private["tmp"]),
        "XDG_CACHE_HOME": str(private["cache"]),
        "XDG_CONFIG_HOME": str(private["config"]),
        "XDG_DATA_HOME": str(private["data"]),
        "TERM": "dumb",
        "PATH": _SYSTEM_PATH,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "file" if allow_file_protocol else "",
    }


def _pmbootstrap_environment() -> dict[str, str]:
    return _git_environment()


@contextmanager
def _pmaports_private_environment():
    """Force imported pmaports Git helpers into this build's private runtime."""

    with _PMAPORTS_ENVIRONMENT_LOCK:
        original = _pmaports_module._git_environment
        _pmaports_module._git_environment = _git_environment
        try:
            yield
        finally:
            _pmaports_module._git_environment = original


def _git_repository(repository: Path) -> Path:
    try:
        resolved = repository.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve Git repository: {error}") from None
    if not resolved.is_dir():
        raise GateError(f"Git repository is not a directory: {resolved}")
    return resolved


def _git_prefix(repository: Path) -> tuple[Path, list[str]]:
    resolved = _git_repository(repository)
    return resolved, [
        _GIT,
        "-c",
        f"safe.directory={resolved}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "diff.external=/usr/bin/false",
    ]


def _git_output(repository: Path, *arguments: str, check: bool = True) -> str:
    resolved, prefix = _git_prefix(repository)
    completed = run(
        [*prefix, "-C", str(resolved), *arguments],
        timeout=60,
        env=_git_environment(),
        check=check,
    )
    return completed.stdout


def _nul_paths(value: str) -> list[str]:
    if not value:
        return []
    if not value.endswith("\0"):
        raise GateError("Git path inventory was not NUL terminated")
    paths = value[:-1].split("\0")
    if any(
        not relative
        or relative.startswith("/")
        or any(part in {"", ".", ".."} for part in relative.split("/"))
        for relative in paths
    ):
        raise GateError("Git path inventory contains an unsafe path")
    return paths


def _duplicate_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise GateError(f"source lock contains duplicate field: {name!r}")
        result[name] = value
    return result


def _json_value_is_exact(actual: object, expected: object) -> bool:
    """Compare JSON values without Python's bool/int equality ambiguity."""

    if type(actual) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(actual) == set(expected) and all(
            _json_value_is_exact(actual[name], value)
            for name, value in expected.items()
        )
    if isinstance(expected, list):
        return len(actual) == len(expected) and all(
            _json_value_is_exact(actual_item, expected_item)
            for actual_item, expected_item in zip(actual, expected)
        )
    return actual == expected


def _read_source_lock(path: Path) -> dict[str, object]:
    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_duplicate_json_object,
        )
    except GateError:
        raise
    except OSError as error:
        raise GateError(
            f"could not read sealed source lock: errno {error.errno or 'unknown'}"
        ) from None
    except (UnicodeError, json.JSONDecodeError):
        raise GateError("sealed source lock is not valid UTF-8 JSON") from None
    if not isinstance(value, dict) or set(value) != {
        "kernel",
        "known_good_kernel_package",
        "offline_cache",
        "pmaports",
        "pmbootstrap",
        "public_credential_policy",
        "release",
        "schema",
    }:
        raise GateError("sealed source lock has an invalid top-level shape")
    if value["schema"] != "lmi-source-lock/v3":
        raise GateError("sealed source lock schema mismatch")

    offline_cache = value["offline_cache"]
    if not isinstance(offline_cache, dict) or set(offline_cache) != {
        "aggregate_sha256",
        "manifest_sha256",
        "schema",
    }:
        raise GateError("sealed source lock offline_cache pin has an invalid shape")
    if offline_cache["schema"] != OFFLINE_CACHE_SCHEMA:
        raise GateError("sealed source lock offline_cache schema mismatch")
    for field in ("aggregate_sha256", "manifest_sha256"):
        if (
            not isinstance(offline_cache[field], str)
            or _SHA256_RE.fullmatch(offline_cache[field]) is None
        ):
            raise GateError(f"sealed source lock offline_cache.{field} is invalid")

    pmbootstrap = value["pmbootstrap"]
    if not isinstance(pmbootstrap, dict) or set(pmbootstrap) != {
        "commit",
        "entrypoint_sha256",
        "remote",
        "tree",
        "version",
    }:
        raise GateError("sealed source lock pmbootstrap pin has an invalid shape")
    pmaports = value["pmaports"]
    if not isinstance(pmaports, dict) or set(pmaports) != {
        "commit",
        "remote",
        "tree",
    }:
        raise GateError("sealed source lock pmaports pin has an invalid shape")
    kernel = value["kernel"]
    if not isinstance(kernel, dict) or set(kernel) != {
        "commit",
        "package",
        "remote",
        "sha512",
        "version",
    }:
        raise GateError("sealed source lock kernel pin has an invalid shape")
    known_good_kernel = value["known_good_kernel_package"]
    if not _json_value_is_exact(
        known_good_kernel, _EXPECTED_KNOWN_GOOD_KERNEL_PIN
    ):
        raise GateError("sealed source lock known-good kernel pin does not match P1")
    credentials = value["public_credential_policy"]
    if not isinstance(credentials, dict) or set(credentials) != {
        "boot_state",
        "credential_state",
        "owner_test_artifact",
        "personalization_required",
        "ssh_ready",
    }:
        raise GateError("sealed source lock credential policy has an invalid shape")
    release = value["release"]
    if not isinstance(release, dict) or set(release) != {
        "public_allowed",
        "source_repo",
        "visibility",
    }:
        raise GateError("sealed source lock release policy has an invalid shape")

    def git_pin(pin: Mapping[str, object], label: str) -> None:
        for field in ("commit", "tree"):
            item = pin[field]
            if not isinstance(item, str) or _COMMIT_RE.fullmatch(item) is None:
                raise GateError(f"sealed source lock {label}.{field} is invalid")
        remote = pin["remote"]
        if (
            not isinstance(remote, str)
            or not remote
            or len(remote) > 2048
            or any(character.isspace() for character in remote)
        ):
            raise GateError(f"sealed source lock {label}.remote is invalid")

    git_pin(pmbootstrap, "pmbootstrap")
    git_pin(pmaports, "pmaports")
    entrypoint_digest = pmbootstrap["entrypoint_sha256"]
    if (
        not isinstance(entrypoint_digest, str)
        or _SHA256_RE.fullmatch(entrypoint_digest) is None
    ):
        raise GateError("sealed source lock pmbootstrap entrypoint digest is invalid")
    if pmbootstrap["commit"] != _EXPECTED_PMBOOTSTRAP_COMMIT:
        raise GateError("sealed source lock pmbootstrap commit does not match builder")
    if pmbootstrap["version"] != _EXPECTED_PMBOOTSTRAP_VERSION:
        raise GateError("sealed source lock pmbootstrap version does not match builder")
    if pmaports["commit"] != _EXPECTED_PMAPORTS_COMMIT:
        raise GateError("sealed source lock pmaports commit does not match builder")
    if (
        kernel["package"] != "linux-xiaomi-lmi"
        or kernel["version"]
        != _REQUIRED_PACKAGE_VERSIONS["linux-xiaomi-lmi"]
        or kernel["commit"] != _EXPECTED_KERNEL_COMMIT
        or kernel["remote"] != _EXPECTED_KERNEL_REMOTE
        or kernel["sha512"] != _EXPECTED_KERNEL_TARBALL_SHA512
    ):
        raise GateError("sealed source lock kernel pin does not match P1")
    expected_credentials = {
        "boot_state": "never_booted",
        "credential_state": "unprovisioned",
        "owner_test_artifact": "never-publish",
        "personalization_required": True,
        "ssh_ready": False,
    }
    expected_release = {
        "source_repo": _EXPECTED_SOURCE_REPOSITORY,
        "public_allowed": True,
        "visibility": "public",
    }
    if any(
        type(credentials[field]) is not bool
        for field in ("personalization_required", "ssh_ready")
    ) or credentials != expected_credentials:
        raise GateError("sealed source lock public credential policy mismatch")
    if (
        type(release["public_allowed"]) is not bool
        or release != expected_release
    ):
        raise GateError("sealed source lock release policy mismatch")
    return value


def _copy_locked_project_file(
    project: Path,
    pin: Mapping[str, object],
    destination: Path,
    label: str,
) -> Path:
    """Copy one source-locked project file without following its final name."""

    relative_text = pin.get("path")
    expected_sha256 = pin.get("sha256")
    expected_size = pin.get("size")
    if (
        not isinstance(relative_text, str)
        or not isinstance(expected_sha256, str)
        or _SHA256_RE.fullmatch(expected_sha256) is None
        or type(expected_size) is not int
        or expected_size < 1
    ):
        raise GateError(f"{label} source-lock file pin is malformed")
    relative = PurePosixPath(relative_text)
    if (
        relative.is_absolute()
        or not relative.parts
        or any(part in {"", ".", ".."} for part in relative.parts)
    ):
        raise GateError(f"{label} source-lock path is unsafe")
    project_root = project.resolve(strict=True)
    source = project.joinpath(*relative.parts)
    try:
        resolved = source.resolve(strict=True)
        before = source.lstat()
    except OSError as error:
        raise GateError(f"could not inspect {label}: {error}") from None
    if (
        not _is_within(resolved, project_root)
        or source.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size != expected_size
    ):
        raise GateError(f"{label} is not one source-locked regular file")
    if os.path.lexists(destination):
        raise GateError(f"refusing to replace staged {label}")

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    source_flags |= getattr(os, "O_NOFOLLOW", 0)
    destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    destination_flags |= getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    copied = 0
    source_descriptor: int | None = None
    destination_descriptor: int | None = None
    try:
        source_descriptor = os.open(source, source_flags)
        destination_descriptor = os.open(destination, destination_flags, 0o600)
        opened = os.fstat(source_descriptor)
        if _stat_identity(opened) != _stat_identity(before):
            raise GateError(f"{label} changed before it was copied")
        while True:
            block = os.read(source_descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            copied += len(block)
            offset = 0
            while offset < len(block):
                offset += os.write(destination_descriptor, block[offset:])
        if _stat_identity(os.fstat(source_descriptor)) != _stat_identity(before):
            raise GateError(f"{label} changed while it was copied")
        os.fsync(destination_descriptor)
        after = source.lstat()
    except GateError:
        destination.unlink(missing_ok=True)
        raise
    except OSError as error:
        destination.unlink(missing_ok=True)
        raise GateError(f"could not copy {label}: {error}") from None
    finally:
        if destination_descriptor is not None:
            os.close(destination_descriptor)
        if source_descriptor is not None:
            os.close(source_descriptor)
    if (
        _stat_identity(after) != _stat_identity(before)
        or copied != expected_size
        or digest.hexdigest() != expected_sha256
    ):
        destination.unlink(missing_ok=True)
        raise GateError(f"{label} does not match its source-lock identity")
    destination.chmod(0o644)
    if (
        destination.is_symlink()
        or not destination.is_file()
        or destination.stat().st_size != expected_size
        or sha256_file(destination) != expected_sha256
    ):
        raise GateError(f"staged {label} failed post-copy verification")
    return destination


def _apkindex_records(path: Path, label: str) -> tuple[dict[str, str], ...]:
    try:
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise GateError(f"{label} is not a regular file")
        with tarfile.open(path, mode="r:gz") as archive:
            members = [member for member in archive.getmembers() if member.name == "APKINDEX"]
            if len(members) != 1 or not members[0].isfile() or members[0].size > 8 * 1024 * 1024:
                raise GateError(f"{label} has an invalid APKINDEX member")
            stream = archive.extractfile(members[0])
            if stream is None:
                raise GateError(f"{label} APKINDEX member is unreadable")
            text = stream.read().decode("utf-8")
    except GateError:
        raise
    except (OSError, tarfile.TarError, UnicodeError) as error:
        raise GateError(f"could not parse {label}: {error}") from None
    records: list[dict[str, str]] = []
    for block in re.split(r"\n\s*\n", text.strip()):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) < 2 or line[1] != ":":
                raise GateError(f"{label} contains a malformed APKINDEX line")
            if line[0] in {"P", "V", "A", "o"}:
                if line[0] in fields:
                    raise GateError(f"{label} contains a duplicate APKINDEX identity field")
                fields[line[0]] = line[2:]
        if not {"P", "V", "A"}.issubset(fields):
            raise GateError(f"{label} contains an incomplete APKINDEX record")
        records.append(fields)
    if not records:
        raise GateError(f"{label} contains no APKINDEX records")
    return tuple(records)


def _stage_known_good_kernel_status(
    project: Path,
    work: Path,
    pin: Mapping[str, object],
) -> Path:
    """Expose only a status index so pmbootstrap skips the sealed kernel build."""

    repository = work / "packages/edge/aarch64"
    repository.mkdir(parents=True, mode=0o755, exist_ok=True)
    if repository.is_symlink() or not repository.is_dir():
        raise GateError("sealed local APK repository is not one real directory")
    index_pin = pin["pmbootstrap_status_index"]
    if not isinstance(index_pin, Mapping) or index_pin.get("install_trust") is not False:
        raise GateError("known-good status index is not explicitly non-install trust")
    destination = _copy_locked_project_file(
        project,
        index_pin,
        repository / "APKINDEX.tar.gz",
        "known-good kernel status index",
    )
    records = _apkindex_records(destination, "known-good kernel status index")
    if len(records) != 1 or records[0] != {
        "P": _KNOWN_GOOD_NAME,
        "V": _KNOWN_GOOD_VERSION,
        "A": _KNOWN_GOOD_ARCH,
        "o": "linux-xiaomi-lmi",
    }:
        raise GateError("known-good kernel status index identity mismatch")
    return destination


def _stage_known_good_kernel_install(
    project: Path,
    work: Path,
    pin: Mapping[str, object],
) -> Path:
    """Stage the signed APK only after pmbootstrap has rebuilt its v2 index."""

    repository = work / "packages/edge/aarch64"
    index = repository / "APKINDEX.tar.gz"
    records = _apkindex_records(index, "sealed local APK repository index")
    names = {record["P"] for record in records}
    if _KNOWN_GOOD_NAME in names:
        raise GateError("sealed local APK index still advertises a kernel package")
    if not {"postmarketos-initramfs", "device-xiaomi-lmi"}.issubset(names):
        raise GateError("sealed local APK index is missing freshly built P1 packages")
    if any(repository.glob("linux-xiaomi-lmi-*.apk")):
        raise GateError("sealed local APK repository contains an unpinned kernel APK")

    artifact_pin = pin["artifact"]
    if not isinstance(artifact_pin, Mapping):
        raise GateError("known-good kernel artifact pin is malformed")
    destination = _copy_locked_project_file(
        project,
        artifact_pin,
        repository / _KNOWN_GOOD_INSTALL_APK_NAME,
        "known-good kernel APK",
    )
    keys = work / "config_apk_keys"
    keys.mkdir(parents=True, mode=0o755, exist_ok=True)
    if keys.is_symlink() or not keys.is_dir():
        raise GateError("pmbootstrap APK key directory is not one real directory")
    key_pin = pin["signer_public_key"]
    if not isinstance(key_pin, Mapping):
        raise GateError("known-good kernel public-key pin is malformed")
    _copy_locked_project_file(
        project,
        key_pin,
        keys / "lmi-p1-known-good-kernel.rsa.pub",
        "known-good kernel signer public key",
    )
    return destination


def _known_good_install_add(package: Path) -> str:
    """Return the exact pmb add list using its host-visible package path."""

    if not package.is_absolute() or package.name != _KNOWN_GOOD_INSTALL_APK_NAME:
        raise GateError("known-good kernel install path is not canonical")
    return (
        "unudhcpd-openrc,"
        f"{_KNOWN_GOOD_NAME}={_KNOWN_GOOD_VERSION},"
        + str(package)
    )


def _apkbuild_scalar(text: str, name: str) -> str:
    assignments = re.findall(
        rf'^[ \t]*{re.escape(name)}(?:\+)?=', text, flags=re.MULTILINE
    )
    if len(assignments) != 1:
        raise GateError(f"kernel APKBUILD must assign {name} exactly once")
    pattern = re.compile(
        rf'^{re.escape(name)}=(?:"([^"\n]*)"|([^\s#"\n]+))$',
        flags=re.MULTILINE,
    )
    matches = pattern.findall(text)
    if len(matches) != 1:
        raise GateError(f"kernel APKBUILD must define {name} exactly once")
    quoted, bare = matches[0]
    return quoted if quoted else bare


def _apkbuild_block(text: str, name: str) -> tuple[str, ...]:
    assignments = re.findall(
        rf'^[ \t]*{re.escape(name)}(?:\+)?=', text, flags=re.MULTILINE
    )
    if len(assignments) != 1:
        raise GateError(f"kernel APKBUILD must assign {name} exactly once")
    matches = re.findall(
        rf'^{re.escape(name)}="\n(.*?)^"$',
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    if len(matches) != 1:
        raise GateError(f"kernel APKBUILD must define {name} as one static block")
    lines = tuple(line.strip() for line in matches[0].splitlines() if line.strip())
    if not lines:
        raise GateError(f"kernel APKBUILD {name} block is empty")
    return lines


def _sha512_file(path: Path, label: str) -> str:
    digest = hashlib.sha512()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(
            f"could not read kernel {label}: errno {error.errno or 'unknown'}"
        ) from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or _stat_identity(opened) != _stat_identity(finished)
        or _stat_identity(opened) != _stat_identity(after)
    ):
        raise GateError(f"kernel {label} changed or is not one regular file")
    return digest.hexdigest()


def _validate_kernel_apkbuild(
    package_directory: Path,
    kernel_pin: object,
) -> None:
    """Bind the staged downstream kernel recipe to the exact P1 source lock."""

    if not isinstance(kernel_pin, Mapping):
        raise GateError("kernel source-lock pin is unavailable")
    apkbuild = package_directory / "APKBUILD"
    try:
        metadata = apkbuild.lstat()
        payload = apkbuild.read_bytes()
        text = payload.decode("utf-8", errors="strict")
        after = apkbuild.lstat()
    except (OSError, UnicodeError) as error:
        error_number = error.errno if isinstance(error, OSError) else None
        raise GateError(
            "could not read staged kernel APKBUILD: "
            f"errno {error_number or 'unknown'}"
        ) from None
    if (
        apkbuild.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or _stat_identity(metadata) != _stat_identity(after)
    ):
        raise GateError("staged kernel APKBUILD is not one stable regular file")
    if hashlib.sha256(payload).hexdigest() != _EXPECTED_KERNEL_APKBUILD_SHA256:
        raise GateError("staged kernel APKBUILD does not match the pinned recipe")

    expected_scalars = {
        "pkgname": "linux-xiaomi-lmi",
        "pkgver": "4.19.325",
        "pkgrel": "8",
        "arch": "aarch64",
        "_carch": "arm64",
        "_flavor": "xiaomi-lmi",
        "url": str(kernel_pin.get("remote", "")),
        "_repository": "android_kernel_xiaomi_sm8250",
        "_commit": str(kernel_pin.get("commit", "")),
        "_config": "config-$_flavor.$arch",
    }
    actual_scalars = {
        name: _apkbuild_scalar(text, name) for name in expected_scalars
    }
    if actual_scalars != expected_scalars:
        raise GateError("staged kernel APKBUILD scalar provenance mismatch")
    if actual_scalars["url"].rstrip("/").removesuffix(".git") != (
        _EXPECTED_KERNEL_REMOTE.rstrip("/").removesuffix(".git")
    ):
        raise GateError("staged kernel APKBUILD remote mismatch")

    expected_sources = (
        "$pkgname-$_commit.tar.gz::https://github.com/LineageOS/"
        "$_repository/archive/$_commit.tar.gz",
        "$_config",
        "lmi-vfs-mount-diagnostic.patch",
        "lmi-rmtfs-mem-node.patch",
    )
    if _apkbuild_block(text, "source") != expected_sources:
        raise GateError("staged kernel APKBUILD source members mismatch")

    checksum_lines = _apkbuild_block(text, "sha512sums")
    checksums: dict[str, str] = {}
    for line in checksum_lines:
        match = re.fullmatch(r"([0-9a-f]{128}|SKIP)  ([A-Za-z0-9._+-]+)", line)
        if match is None or match.group(1) == "SKIP" or match.group(2) in checksums:
            raise GateError("staged kernel APKBUILD has unsafe SHA512 entries")
        checksums[match.group(2)] = match.group(1)
    tarball = f"linux-xiaomi-lmi-{kernel_pin.get('commit', '')}.tar.gz"
    expected_checksums = {
        tarball: str(kernel_pin.get("sha512", "")),
        **_EXPECTED_KERNEL_LOCAL_SHA512,
    }
    if checksums != expected_checksums:
        raise GateError("staged kernel APKBUILD SHA512 provenance mismatch")
    for member, expected_digest in _EXPECTED_KERNEL_LOCAL_SHA512.items():
        if _sha512_file(package_directory / member, member) != expected_digest:
            raise GateError(f"staged kernel local source checksum mismatch: {member}")


def _actual_git_provenance(
    repository: Path,
    label: str,
    *,
    require_clean: bool,
) -> dict[str, str]:
    _reject_promisor_and_alternates(repository, f"sealed {label} repository")
    _reject_replace_refs(repository, f"sealed {label} repository")
    _reject_special_index_flags(repository, f"sealed {label} repository")
    top = _git_output(repository, "rev-parse", "--show-toplevel").strip()
    if Path(top).resolve(strict=True) != repository.resolve(strict=True):
        raise GateError(f"sealed {label} path is not its Git worktree root")
    commit = _git_output(repository, "rev-parse", "HEAD").strip()
    tree = _git_output(repository, "rev-parse", "HEAD^{tree}").strip()
    remotes = [
        line
        for line in _git_output(
            repository, "config", "--get-all", "remote.origin.url"
        ).splitlines()
        if line
    ]
    if (
        _COMMIT_RE.fullmatch(commit) is None
        or _COMMIT_RE.fullmatch(tree) is None
        or len(remotes) != 1
    ):
        raise GateError(f"sealed {label} Git provenance is incomplete")
    if require_clean and _git_output(
        repository, "status", "--porcelain", "--untracked-files=all"
    ):
        raise GateError(f"sealed {label} Git worktree is not clean")
    return {"commit": commit, "remote": remotes[0], "tree": tree}


def _require_verified_offline_cache(
    verified: VerifiedSeal,
) -> tuple[Path, Mapping[str, object]]:
    """Require seal verification to expose a private immutable cache member."""

    value = getattr(verified, "offline_cache", None)
    if not isinstance(value, Path):
        raise GateError("sealed production requires a verified offline cache")
    cache = _real_directory(value, "verified offline cache")
    seal_root = verified.root.resolve(strict=True)
    if not _is_within(cache, seal_root):
        raise GateError("verified offline cache is outside the active seal")
    try:
        seal_metadata = verified.root.lstat()
    except OSError as error:
        raise GateError(f"could not inspect verified seal root: {error}") from None
    manifest, payload = verify_offline_cache(
        cache,
        expected_uid=seal_metadata.st_uid,
        expected_gid=seal_metadata.st_gid,
    )
    binding = {
        "aggregate_sha256": manifest["aggregate_sha256"],
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "schema": OFFLINE_CACHE_SCHEMA,
    }
    provenance = verified.manifest.get("provenance")
    sealed_binding = (
        provenance.get("offline_cache") if isinstance(provenance, Mapping) else None
    )
    if sealed_binding != binding:
        raise GateError("verified offline cache does not match seal provenance")
    return cache, manifest


def _cache_file_identity(metadata: os.stat_result) -> tuple[int, ...]:
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


def _rehash_seeded_regular(path: Path, label: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not rehash {label}: {error}") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or not (
            _cache_file_identity(before)
            == _cache_file_identity(opened)
            == _cache_file_identity(finished)
            == _cache_file_identity(after)
        )
    ):
        raise GateError(f"{label} changed during rehash")
    return digest.hexdigest()


def _seed_verified_offline_cache(
    source: Path,
    destination: Path,
    expected_manifest: Mapping[str, object],
) -> None:
    """Copy verified cache bytes into a new private pmbootstrap work tree.

    Files are opened without following links and copied through userspace reads
    and writes.  No link, reflink, mount, or shared writable cache is accepted.
    """

    try:
        source_root = source.lstat()
    except OSError as error:
        raise GateError(f"could not inspect sealed offline cache: {error}") from None
    current_manifest, _payload = verify_offline_cache(
        source,
        expected_uid=source_root.st_uid,
        expected_gid=source_root.st_gid,
    )
    if current_manifest != dict(expected_manifest):
        raise GateError("sealed offline-cache manifest changed before seeding")
    aggregate = current_manifest.get("aggregate_sha256")
    if (
        not isinstance(aggregate, str)
        or hashlib.sha256(
            offline_cache_aggregate_preimage(current_manifest)
        ).hexdigest()
        != aggregate
    ):
        raise GateError("sealed offline-cache aggregate changed before seeding")
    if os.path.lexists(destination):
        raise GateError("candidate pmbootstrap work already exists before cache seeding")
    try:
        destination.mkdir(mode=0o700)
    except OSError as error:
        raise GateError(f"could not create private seeded work: {error}") from None
    if (
        destination.is_symlink()
        or not destination.is_dir()
        or destination.stat().st_uid != os.geteuid()
        or stat.S_IMODE(destination.stat().st_mode) != 0o700
    ):
        raise GateError("seeded pmbootstrap work is not a private directory")
    for name in (
        "cache_apk_aarch64",
        "cache_apk_x86_64",
        "cache_distfiles",
        "cache_http",
    ):
        (destination / name).mkdir(mode=0o700)

    members = current_manifest.get("members")
    if not isinstance(members, list):
        raise GateError("sealed offline-cache members are unavailable")
    source_inodes: set[tuple[int, int]] = set()
    destination_inodes: set[tuple[int, int]] = set()
    read_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    write_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for item in members:
        if not isinstance(item, Mapping):
            raise GateError("sealed offline-cache member is malformed")
        relative = str(item["path"])
        try:
            work_relative = PurePosixPath(relative).relative_to("work")
        except ValueError:
            raise GateError("sealed offline-cache member escapes work") from None
        source_path = source / relative
        destination_path = destination.joinpath(*work_relative.parts)
        try:
            before = source_path.lstat()
        except OSError as error:
            raise GateError(f"could not inspect sealed cache member: {error}") from None
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
        ):
            raise GateError(f"sealed cache member is mutable or non-regular: {relative}")
        try:
            if os.listxattr(source_path, follow_symlinks=False):
                raise GateError(f"sealed cache member has xattrs: {relative}")
        except (AttributeError, NotImplementedError):
            raise GateError("filesystem xattr inspection is unavailable") from None
        except OSError as error:
            raise GateError(f"could not inspect sealed cache xattrs: {error}") from None
        source_inode = (before.st_dev, before.st_ino)
        if source_inode in source_inodes:
            raise GateError("sealed cache contains shared file inodes")
        source_inodes.add(source_inode)
        digest = hashlib.sha256()
        try:
            source_fd = os.open(source_path, read_flags)
            try:
                opened = os.fstat(source_fd)
                if _cache_file_identity(opened) != _cache_file_identity(before):
                    raise GateError(f"sealed cache member changed while opening: {relative}")
                destination_fd = os.open(destination_path, write_flags, 0o600)
                try:
                    remaining = int(item["size"])
                    while remaining:
                        block = os.read(source_fd, min(1024 * 1024, remaining))
                        if not block:
                            raise GateError(f"sealed cache member was truncated: {relative}")
                        remaining -= len(block)
                        digest.update(block)
                        view = memoryview(block)
                        while view:
                            written = os.write(destination_fd, view)
                            if written <= 0:
                                raise GateError("seeded cache write made no progress")
                            view = view[written:]
                    if os.read(source_fd, 1):
                        raise GateError(f"sealed cache member grew while copying: {relative}")
                    os.fsync(destination_fd)
                    copied = os.fstat(destination_fd)
                finally:
                    os.close(destination_fd)
                finished = os.fstat(source_fd)
            finally:
                os.close(source_fd)
            after = source_path.lstat()
        except GateError:
            raise
        except OSError as error:
            raise GateError(f"could not copy sealed cache member: {error}") from None
        if not (
            _cache_file_identity(before)
            == _cache_file_identity(opened)
            == _cache_file_identity(finished)
            == _cache_file_identity(after)
        ):
            raise GateError(f"sealed cache member changed while copying: {relative}")
        if (
            digest.hexdigest() != item["sha256"]
            or copied.st_size != item["size"]
            or not stat.S_ISREG(copied.st_mode)
            or copied.st_nlink != 1
        ):
            raise GateError(f"seeded cache member digest/metadata mismatch: {relative}")
        destination_inode = (copied.st_dev, copied.st_ino)
        if destination_inode in destination_inodes or destination_inode == source_inode:
            raise GateError("seeded cache does not have isolated file inodes")
        destination_inodes.add(destination_inode)

    expected_files = {
        str(PurePosixPath(str(item["path"])).relative_to("work")): item
        for item in members
    }
    actual_files: dict[str, dict[str, object]] = {}
    expected_directories = {
        ".",
        "cache_apk_aarch64",
        "cache_apk_x86_64",
        "cache_distfiles",
        "cache_http",
    }
    actual_directories: set[str] = set()
    for root, directories, files in os.walk(destination, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(destination).as_posix()
        actual_directories.add("." if relative_root == "." else relative_root)
        for name in directories:
            path = root_path / name
            metadata = path.lstat()
            if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
                raise GateError("seeded cache contains a non-directory tree member")
        for name in files:
            path = root_path / name
            relative = path.relative_to(destination).as_posix()
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise GateError(f"seeded cache contains a non-regular member: {relative}")
            actual_files[relative] = {
                "path": "work/" + relative,
                "sha256": _rehash_seeded_regular(path, f"seeded cache {relative}"),
                "size": metadata.st_size,
            }
    if actual_directories != expected_directories or set(actual_files) != set(expected_files):
        raise GateError("seeded cache has missing, extra, or forbidden mutable state")
    for relative, expected in expected_files.items():
        if actual_files[relative] != dict(expected):
            raise GateError(f"seeded cache revalidation failed: {relative}")
    final_manifest, _final_payload = verify_offline_cache(
        source,
        expected_uid=source_root.st_uid,
        expected_gid=source_root.st_gid,
    )
    if final_manifest != current_manifest:
        raise GateError("sealed offline cache changed during seeding")


def _prepare_sealed_build_context(
    verified: VerifiedSeal,
    *,
    tag: str,
    run_root: Path,
) -> tuple[BuildContext, _SealedBuildAuthorization]:
    """Derive the only root-build context from one already verified seal."""

    if not isinstance(verified, VerifiedSeal):
        raise GateError("sealed build authorization requires a VerifiedSeal")
    if _TAG_RE.fullmatch(tag) is None:
        raise GateError(f"invalid candidate tag: {tag!r}")
    if _SHA256_RE.fullmatch(verified.policy_id) is None:
        raise GateError("verified seal policy id is invalid")
    run_root = Path(run_root).absolute()
    if run_root.is_symlink() or not run_root.is_dir():
        raise GateError("sealed build run root must be one real directory")
    if _overlaps(run_root.resolve(strict=True), verified.root.resolve(strict=True)):
        raise GateError("sealed build run root overlaps its verified inputs")

    manifest_provenance = verified.manifest.get("provenance")
    if not isinstance(manifest_provenance, Mapping):
        raise GateError("verified seal provenance is unavailable")
    project_manifest = manifest_provenance.get("project")
    pmbootstrap_manifest = manifest_provenance.get("pmbootstrap")
    pmaports_manifest = manifest_provenance.get("pmaports")
    if not all(
        isinstance(item, Mapping)
        for item in (project_manifest, pmbootstrap_manifest, pmaports_manifest)
    ):
        raise GateError("verified seal provenance is malformed")

    source_lock = _read_source_lock(verified.source_lock)
    if dict(pmbootstrap_manifest) != source_lock["pmbootstrap"]:
        raise GateError("seal manifest pmbootstrap provenance mismatches source lock")
    if dict(pmaports_manifest) != source_lock["pmaports"]:
        raise GateError("seal manifest pmaports provenance mismatches source lock")

    _validate_kernel_apkbuild(
        verified.project / "artifacts/wsl-pmaports/linux-xiaomi-lmi",
        source_lock["kernel"],
    )

    environment_token = _PRIVATE_ENVIRONMENT_ROOT.set(
        run_root / ".verification-runtime"
    )
    try:
        with _pmaports_private_environment():
            project_actual = _actual_git_provenance(
                verified.project, "project", require_clean=True
            )
            pmbootstrap_actual = _actual_git_provenance(
                verified.pmbootstrap, "pmbootstrap", require_clean=True
            )
            pmaports_actual = _actual_git_provenance(
                verified.pmaports, "pmaports", require_clean=False
            )
    finally:
        _PRIVATE_ENVIRONMENT_ROOT.reset(environment_token)
    if project_actual != dict(project_manifest):
        raise GateError("sealed project Git provenance mismatch")
    if pmbootstrap_actual != {
        name: pmbootstrap_manifest[name]
        for name in ("commit", "remote", "tree")
    }:
        raise GateError("sealed pmbootstrap Git provenance mismatch")
    if pmaports_actual != dict(pmaports_manifest):
        raise GateError("sealed pmaports Git provenance mismatch")

    entrypoint = verified.pmbootstrap / "pmbootstrap.py"
    if sha256_file(entrypoint) != pmbootstrap_manifest["entrypoint_sha256"]:
        raise GateError("sealed pmbootstrap entrypoint digest mismatch")
    if pmbootstrap_manifest["version"] != _EXPECTED_PMBOOTSTRAP_VERSION:
        raise GateError("sealed pmbootstrap version mismatch")

    offline_cache, offline_cache_manifest = _require_verified_offline_cache(verified)
    if source_lock["offline_cache"] != manifest_provenance.get("offline_cache"):
        raise GateError("sealed source lock offline-cache binding mismatch")

    fingerprint, _public_key_text = _read_public_key_once(verified.authorized_key)
    context = BuildContext(
        repo=verified.project,
        tag=tag,
        privilege_model=_PRIVILEGE_SEALED,
        policy_id=verified.policy_id,
        source_commit=str(project_manifest["commit"]),
        work=run_root / "candidate",
        pmaports=verified.pmaports,
        pmbootstrap=entrypoint,
        public_key=verified.authorized_key,
        public_key_fingerprint=fingerprint,
    )
    authorization = _SealedBuildAuthorization(
        context=context,
        seal=verified,
        run_root=run_root,
        source_lock=source_lock,
        offline_cache=offline_cache,
        offline_cache_manifest=offline_cache_manifest,
        marker=_SEALED_AUTHORIZATION_MARKER,
    )
    return context, authorization


def _validate_staged_pmaports_self(path: Path) -> dict[str, object]:
    return validate_staged_pmaports(
        path,
        _EXPECTED_PMAPORTS_COMMIT,
        git_output=_git_output,
    )


def _validate_staged_pmaports(path: Path, expected: Path) -> None:
    stage = _validate_staged_pmaports_self(path)
    expected_stage = _validate_staged_pmaports_self(expected)
    if stage != expected_stage:
        raise GateError("pmaports stage manifest does not match reconstructed inputs")
    _compare_physical_trees(path, expected, "pmaports stage")


def _pmbootstrap_entrypoint_blob(repository: Path, entrypoint: Path) -> str:
    expected_entrypoint = repository / "pmbootstrap.py"
    try:
        expected_resolved = expected_entrypoint.resolve(strict=True)
    except OSError as error:
        raise GateError(f"missing tracked pmbootstrap.py: {error}") from None
    if entrypoint != expected_resolved:
        raise GateError("pmbootstrap executable must resolve to tracked pmbootstrap.py")
    tracked = _git_output(repository, "ls-files", "--stage", "--", "pmbootstrap.py")
    fields = tracked.strip().split()
    if len(fields) != 4 or fields[0] != "100755" or fields[2] != "0":
        raise GateError("pmbootstrap.py is not one executable stage-0 tracked file")
    expected_blob = _git_output(
        repository,
        "rev-parse",
        f"{_EXPECTED_PMBOOTSTRAP_COMMIT}:pmbootstrap.py",
    ).strip()
    actual_blob = _git_output(
        repository,
        "hash-object",
        "--no-filters",
        "--",
        "pmbootstrap.py",
    ).strip()
    if fields[1] != expected_blob or actual_blob != expected_blob:
        raise GateError("pmbootstrap.py blob does not match the pinned commit")
    return expected_blob


def _reject_pmbootstrap_checkout_filters(repository: Path) -> None:
    attributes = sorted(
        relative
        for relative in _nul_paths(
            _git_output(
                repository,
                "ls-tree",
                "-r",
                "--name-only",
                "-z",
                _EXPECTED_PMBOOTSTRAP_COMMIT,
            )
        )
        if relative == ".gitattributes" or relative.endswith("/.gitattributes")
    )
    for relative in attributes:
        content = _git_output(
            repository,
            "show",
            f"{_EXPECTED_PMBOOTSTRAP_COMMIT}:{relative}",
        )
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            fields = stripped.split()
            for attribute in fields[1:]:
                name = attribute.lstrip("-!").split("=", 1)[0]
                if name == "filter":
                    raise GateError(
                        "pmbootstrap pinned tree uses checkout filter attributes: "
                        f"{relative}:{line_number}"
                    )


def _validate_pmbootstrap_checkout(
    repository: Path, entrypoint: Path, expected_blob: str
) -> None:
    head = _git_output(repository, "rev-parse", "--verify", "HEAD").strip()
    if head != _EXPECTED_PMBOOTSTRAP_COMMIT:
        raise GateError(
            "pmbootstrap commit mismatch: "
            f"expected {_EXPECTED_PMBOOTSTRAP_COMMIT}, got {head}"
        )
    status = _git_output(
        repository, "status", "--porcelain", "--untracked-files=all"
    ).strip()
    if status:
        raise GateError("pmbootstrap repository is dirty; use the exact pinned checkout")
    _reject_pmbootstrap_checkout_filters(repository)
    if _pmbootstrap_entrypoint_blob(repository, entrypoint) != expected_blob:
        raise GateError("isolated pmbootstrap.py blob changed after checkout")


def _prepare_pmbootstrap(source_entrypoint: Path, candidate: Path) -> tuple[Path, Path]:
    _reject_promisor_and_alternates(
        source_entrypoint.parent, "pmbootstrap source repository"
    )
    source_repository_text = _git_output(
        source_entrypoint.parent, "rev-parse", "--show-toplevel"
    ).strip()
    source_repository = _real_directory(
        Path(source_repository_text), "pmbootstrap repository"
    )
    head = _git_output(source_repository, "rev-parse", "--verify", "HEAD").strip()
    if head != _EXPECTED_PMBOOTSTRAP_COMMIT:
        raise GateError(
            "pmbootstrap commit mismatch: "
            f"expected {_EXPECTED_PMBOOTSTRAP_COMMIT}, got {head}"
        )
    _require_local_object_closure(
        source_repository,
        _EXPECTED_PMBOOTSTRAP_COMMIT,
        "pmbootstrap source repository",
    )
    expected_blob = _pmbootstrap_entrypoint_blob(source_repository, source_entrypoint)
    status = _git_output(
        source_repository, "status", "--porcelain", "--untracked-files=all"
    ).strip()
    if status:
        raise GateError("pmbootstrap repository is dirty; use the exact pinned checkout")
    _reject_pmbootstrap_checkout_filters(source_repository)

    isolated_repository = candidate / "pmbootstrap"
    _source_repository, clone_prefix = _git_prefix(source_repository)
    run(
        [
            *clone_prefix,
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            str(source_repository),
            str(isolated_repository),
        ],
        timeout=60,
        env=_git_environment(allow_file_protocol=True),
    )
    _reject_promisor_and_alternates(
        isolated_repository, "isolated pmbootstrap repository"
    )
    _require_local_object_closure(
        isolated_repository,
        _EXPECTED_PMBOOTSTRAP_COMMIT,
        "isolated pmbootstrap repository",
    )
    _reject_pmbootstrap_checkout_filters(isolated_repository)
    _git_output(
        isolated_repository,
        "checkout",
        "--detach",
        _EXPECTED_PMBOOTSTRAP_COMMIT,
    )
    isolated_entrypoint = _real_file(
        isolated_repository / "pmbootstrap.py",
        "isolated pmbootstrap entrypoint",
        executable=True,
    )
    _validate_pmbootstrap_checkout(
        isolated_repository, isolated_entrypoint, expected_blob
    )
    return isolated_repository, isolated_entrypoint


def _public_key_fingerprint(text: str) -> tuple[str, str]:
    """Validate already-captured public-key text without reopening its source."""

    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) != 1:
        raise GateError("SSH public key file must contain exactly one non-empty line")
    fields = lines[0].split()
    if len(fields) not in {2, 3} or fields[0] != "ssh-ed25519":
        raise GateError("SSH public key must be one Ed25519 key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, base64.binascii.Error):
        raise GateError("SSH public key has invalid base64") from None
    key_type = b"ssh-ed25519"
    expected_prefix = len(key_type).to_bytes(4, "big") + key_type
    if not blob.startswith(expected_prefix) or len(blob) != len(expected_prefix) + 4 + 32:
        raise GateError("SSH public key is not a valid Ed25519 public blob")
    key_length = int.from_bytes(blob[len(expected_prefix) : len(expected_prefix) + 4], "big")
    if key_length != 32:
        raise GateError("SSH Ed25519 public key has the wrong length")
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}", lines[0] + "\n"


def _read_public_key_once(path: Path) -> tuple[str, str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read()
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(f"could not read SSH public key: {error}") from None
    try:
        text = payload.decode("utf-8")
    except UnicodeError as error:
        raise GateError(f"could not read SSH public key: {error}") from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or _stat_identity(before) != _stat_identity(opened)
        or _stat_identity(finished) != _stat_identity(opened)
        or _stat_identity(after) != _stat_identity(opened)
    ):
        raise GateError("SSH public key changed while it was being read")
    return _public_key_fingerprint(text)


def _write_config(path: Path, public_key: Path) -> None:
    values = {
        "device": "xiaomi-lmi",
        "ui": "shelli",
        "user": "lmi",
        "hostname": "lmi",
        "ssh_keys": "True",
        "ssh_key_glob": str(public_key),
        "service_manager": "openrc",
        "extra_packages": "none",
        "build_pkgs_on_install": "False",
    }
    if any(
        any(ord(character) < 32 or ord(character) == 127 for character in value)
        for value in values.values()
    ):
        raise GateError("pmbootstrap configuration value contains a control character")
    text = (
        "[pmbootstrap]\n"
        + "".join(f"{name} = {value}\n" for name, value in values.items())
        + "\n[providers]\n"
        + "\n[mirrors]\n"
    )
    path.write_text(text, encoding="utf-8")
    path.chmod(0o600)


def _redact_password(value: str, password: str) -> str:
    return value.replace(password, "[REDACTED_EPHEMERAL_PASSWORD]")


def _write_log(path: Path, records: Sequence[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(records).rstrip() + "\n", encoding="utf-8")
    path.chmod(0o600)


def _tree_hashes(path: Path) -> tuple[tuple[str, str], ...]:
    if path.is_symlink() or not path.is_dir():
        raise GateError(f"APK key directory is not a real directory: {path}")
    values: list[tuple[str, str]] = []
    for entry in sorted(path.rglob("*")):
        if entry.is_symlink() or not entry.is_file():
            if entry.is_dir() and not entry.is_symlink():
                continue
            raise GateError(f"unsupported APK key directory entry: {entry}")
        values.append((entry.relative_to(path).as_posix(), sha256_file(entry)))
    return tuple(values)


def _all_key_hashes(work: Path, rootfs: Path) -> tuple[tuple[str, tuple[tuple[str, str], ...]], ...]:
    return (
        ("pmbootstrap", _tree_hashes(work / "config_apk_keys")),
        ("rootfs", _tree_hashes(rootfs / "etc/apk/keys")),
    )


def _parse_apk_records(path: Path) -> tuple[_ApkPackageRecord, ...]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read installed package database: {error}") from None
    packages: dict[str, _ApkPackageRecord] = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        scalar_fields: dict[str, list[str]] = {
            "P": [],
            "V": [],
            "A": [],
            "o": [],
        }
        files: list[list[str | None]] = []
        current_directory: PurePosixPath | None = None
        last_file: int | None = None
        for line in block.splitlines():
            if len(line) >= 2 and line[1] == ":":
                field = line[0]
                value = line[2:]
                if field in scalar_fields:
                    scalar_fields[field].append(value)
                elif field == "F":
                    directory = PurePosixPath(value) if value else PurePosixPath()
                    if (
                        directory.is_absolute()
                        or any(part in {"", ".", ".."} for part in directory.parts)
                    ):
                        raise GateError("installed package database contains an unsafe directory")
                    current_directory = directory
                    last_file = None
                elif field == "R":
                    name = PurePosixPath(value)
                    if (
                        current_directory is None
                        or not value
                        or name.is_absolute()
                        or len(name.parts) != 1
                        or name.name in {"", ".", ".."}
                    ):
                        raise GateError("installed package database contains an unsafe file")
                    files.append(
                        ["/" + (current_directory / name).as_posix(), None]
                    )
                    last_file = len(files) - 1
                elif field == "Z":
                    if last_file is None or files[last_file][1] is not None:
                        raise GateError(
                            "installed package database contains an orphan or duplicate checksum"
                        )
                    files[last_file][1] = value
        names = scalar_fields["P"]
        versions = scalar_fields["V"]
        architectures = scalar_fields["A"]
        origins = scalar_fields["o"]
        if len(names) != 1 or len(versions) != 1:
            raise GateError("installed package database contains a malformed package record")
        name = names[0]
        version = versions[0]
        if name in packages:
            raise GateError(f"duplicate installed package database entry: {name}")
        if len(architectures) > 1:
            raise GateError(f"duplicate installed package architecture entry: {name}")
        if len(origins) > 1:
            raise GateError(f"duplicate installed package origin entry: {name}")
        file_paths = [str(file[0]) for file in files]
        if len(file_paths) != len(set(file_paths)):
            raise GateError(f"duplicate installed package file entry: {name}")
        packages[name] = _ApkPackageRecord(
            name=name,
            version=version,
            architecture=architectures[0] if architectures else None,
            origin=origins[0] if origins else None,
            files=tuple((str(file[0]), file[1]) for file in files),
        )
    if not packages:
        raise GateError("installed package database contains no package records")
    return tuple(packages[name] for name in sorted(packages))


def _parse_apk_database(path: Path) -> list[str]:
    return [f"{record.name}-{record.version}" for record in _parse_apk_records(path)]


def _known_good_installed_checksum(sha256: str) -> str:
    digest = bytes.fromhex(sha256)[:20]
    return "Q1" + base64.b64encode(digest).decode("ascii")


def _verify_known_good_kernel_install(rootfs: Path, database: Path) -> None:
    """Attest exact sealed APK identity, unique ownership, and installed bytes."""

    records = _parse_apk_records(database)
    matches = [record for record in records if record.name == _KNOWN_GOOD_NAME]
    if len(matches) != 1:
        raise GateError("known-good kernel does not have one installed package owner")
    package = matches[0]
    if (
        package.version != _KNOWN_GOOD_VERSION
        or package.architecture != _KNOWN_GOOD_ARCH
        or package.origin != _KNOWN_GOOD_ORIGIN
    ):
        raise GateError("installed known-good kernel package identity mismatch")

    expected_files = {
        "/" + relative: _known_good_installed_checksum(values[0])
        for relative, values in _KNOWN_GOOD_PAYLOAD.items()
    }
    package_files = dict(package.files)
    if package_files != expected_files:
        raise GateError("installed known-good kernel checksum inventory mismatch")
    ownership: dict[str, list[tuple[str, str | None]]] = {}
    for record in records:
        for path, checksum in record.files:
            ownership.setdefault(path, []).append((record.name, checksum))
    for path, checksum in expected_files.items():
        if ownership.get(path) != [(_KNOWN_GOOD_NAME, checksum)]:
            raise GateError(f"known-good kernel payload is not uniquely owned: {path}")

    payload_directories = {
        rootfs.joinpath(*PurePosixPath(relative).parts[:depth])
        for relative in _KNOWN_GOOD_PAYLOAD
        for depth in range(1, len(PurePosixPath(relative).parts))
    }
    for directory in payload_directories:
        try:
            metadata = directory.lstat()
        except OSError as error:
            raise GateError(
                f"could not verify known-good kernel directory: {error}"
            ) from None
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o755
            or metadata.st_uid != 0
            or metadata.st_gid != 0
        ):
            raise GateError("installed known-good kernel directory metadata mismatch")

    for relative, (expected_sha256, _historical_q1, expected_mode) in (
        _KNOWN_GOOD_PAYLOAD.items()
    ):
        path = rootfs.joinpath(*PurePosixPath(relative).parts)
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        digest = hashlib.sha256()
        try:
            before = path.lstat()
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as stream:
                opened = os.fstat(stream.fileno())
                for block in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(block)
                finished = os.fstat(stream.fileno())
            after = path.lstat()
        except OSError as error:
            raise GateError(
                f"could not verify known-good kernel payload {relative}: {error}"
            ) from None
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or stat.S_IMODE(opened.st_mode) != expected_mode
            or opened.st_uid != 0
            or opened.st_gid != 0
            or not (
                _stat_identity(before)
                == _stat_identity(opened)
                == _stat_identity(finished)
                == _stat_identity(after)
            )
            or digest.hexdigest() != expected_sha256
        ):
            raise GateError(
                f"installed known-good kernel payload mismatch: {relative}"
            )


def _sshd_pam_package_record(
    path: Path,
) -> tuple[_ApkPackageRecord, str]:
    records = _parse_apk_records(path)
    matches = [record for record in records if record.name == "openssh-server-pam"]
    if len(matches) != 1:
        raise GateError("missing installed package: openssh-server-pam")
    package = matches[0]
    if package.architecture != "aarch64":
        raise GateError("openssh-server-pam architecture is not exactly aarch64")
    ownership = [
        (record.name, checksum)
        for record in records
        for file_path, checksum in record.files
        if file_path == "/usr/sbin/sshd.pam"
    ]
    if len(ownership) != 1 or ownership[0][0] != package.name:
        raise GateError(
            "openssh-server-pam does not uniquely own /usr/sbin/sshd.pam"
        )
    checksum = ownership[0][1]
    if checksum is None:
        raise GateError("sshd.pam has no APK database checksum")
    return package, checksum


def _dhcp_package_records(
    path: Path,
) -> tuple[dict[str, _ApkPackageRecord], str, str]:
    records = _parse_apk_records(path)
    by_name = {record.name: record for record in records}
    missing = sorted(set(_DHCP_PACKAGE_NAMES) - set(by_name))
    if missing:
        raise GateError(f"missing installed DHCP package: {missing!r}")
    packages = {name: by_name[name] for name in _DHCP_PACKAGE_NAMES}
    if packages["unudhcpd"].architecture != "aarch64":
        raise GateError("unudhcpd architecture is not exactly aarch64")
    if packages["unudhcpd-openrc"].version != packages["unudhcpd"].version:
        raise GateError("unudhcpd-openrc version does not match unudhcpd")
    ownership = [
        (record.name, checksum)
        for record in records
        for file_path, checksum in record.files
        if file_path == "/usr/bin/unudhcpd"
    ]
    if len(ownership) != 1 or ownership[0][0] != "unudhcpd":
        raise GateError("unudhcpd does not uniquely own /usr/bin/unudhcpd")
    checksum = ownership[0][1]
    if checksum is None:
        raise GateError("unudhcpd has no APK database checksum")
    service_owners = [
        (record.name, checksum)
        for record in records
        for file_path, checksum in record.files
        if file_path == "/etc/init.d/unudhcpd"
    ]
    if len(service_owners) != 1 or service_owners[0][0] != "unudhcpd-openrc":
        raise GateError("unudhcpd-openrc does not uniquely own /etc/init.d/unudhcpd")
    service_checksum = service_owners[0][1]
    if service_checksum is None:
        raise GateError("unudhcpd OpenRC service has no APK database checksum")
    forbidden = sorted(_FORBIDDEN_DHCP_PACKAGE_NAMES & set(by_name))
    if forbidden:
        raise GateError(f"second full-userland DHCP owner is installed: {forbidden!r}")
    return packages, checksum, service_checksum


def _apk_checksum(checksum: str, label: str = "sshd.pam") -> tuple[str, bytes]:
    algorithms = {
        "Q1": ("sha1", hashlib.sha1().digest_size),
        "Q2": ("sha256", hashlib.sha256().digest_size),
    }
    prefix = checksum[:2]
    if prefix not in algorithms or len(checksum) <= 2:
        raise GateError(f"{label} has an unsupported APK database checksum")
    encoded = checksum[2:]
    encoded += "=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise GateError(f"{label} has a malformed APK database checksum") from None
    algorithm, size = algorithms[prefix]
    if len(decoded) != size:
        raise GateError(f"{label} has a malformed APK database checksum")
    return algorithm, decoded


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stable_sha256(path: Path, label: str) -> str:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    digest = hashlib.sha256()
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(
            f"could not recheck frozen {label}: errno {error.errno or 'unknown'}"
        ) from None
    if (
        not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o444
        or not (
            _stat_identity(before)
            == _stat_identity(opened)
            == _stat_identity(finished)
            == _stat_identity(after)
        )
    ):
        raise GateError(f"frozen {label} changed during final recheck")
    return digest.hexdigest()


def _semantic_digest(
    report: Mapping[str, object],
    path: tuple[str, ...],
) -> str:
    value: object = report
    for component in path:
        if not isinstance(value, Mapping) or component not in value:
            raise GateError("artifact semantic report is missing a publication digest")
        value = value[component]
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise GateError("artifact semantic report has an invalid publication digest")
    return value


def _artifact_set_id(build_id: str, files: Sequence[Mapping[str, object]]) -> str:
    if _SHA256_RE.fullmatch(build_id) is None:
        raise GateError("artifact manifest build id is invalid")
    digest = hashlib.sha256()
    digest.update(
        b"\0".join(
            (
                _ARTIFACT_MANIFEST_SCHEMA.encode("ascii"),
                b"artifact-set",
                build_id.encode("ascii"),
                _ARTIFACT_CLASSIFICATION.encode("ascii"),
                _ARTIFACT_PUBLICATION.encode("ascii"),
                _ARTIFACT_CREDENTIAL_STATE.encode("ascii"),
            )
        )
    )
    for entry in sorted(files, key=lambda item: str(item.get("path", ""))):
        path = entry.get("path")
        size = entry.get("size")
        sha256 = entry.get("sha256")
        if (
            not isinstance(path, str)
            or not isinstance(size, int)
            or isinstance(size, bool)
            or size < 0
            or not isinstance(sha256, str)
            or _SHA256_RE.fullmatch(sha256) is None
        ):
            raise GateError("artifact manifest file evidence is invalid")
        digest.update(b"\0")
        digest.update(path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(sha256.encode("ascii"))
    return digest.hexdigest()


def _export_file_inventory(export: Path) -> dict[str, Path]:
    files: dict[str, Path] = {}
    try:
        entries = sorted(export.rglob("*"), key=lambda item: item.as_posix())
    except OSError as error:
        raise GateError(
            f"could not enumerate artifact set: errno {error.errno or 'unknown'}"
        ) from None
    for entry in entries:
        relative = entry.relative_to(export).as_posix()
        try:
            metadata = entry.lstat()
        except OSError as error:
            raise GateError(
                f"could not inspect artifact set: errno {error.errno or 'unknown'}"
            ) from None
        if stat.S_ISLNK(metadata.st_mode):
            raise GateError("artifact set contains a symbolic link")
        if stat.S_ISDIR(metadata.st_mode):
            continue
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise GateError("artifact set contains a special or linked file")
        if relative in files:
            raise GateError("artifact set contains a duplicate path")
        files[relative] = entry
    return files


def _canonical_artifact_manifest_bytes(value: object) -> bytes:
    try:
        return (
            json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeError) as error:
        raise GateError(f"artifact manifest is not canonical JSON data: {error}") from None


def _read_artifact_manifest(path: Path) -> tuple[dict[str, object], str]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(16 * 1024 * 1024 + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(
            f"could not read artifact manifest: errno {error.errno or 'unknown'}"
        ) from None
    if (
        len(payload) > 16 * 1024 * 1024
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or stat.S_IMODE(opened.st_mode) != 0o444
        or not (
            _stat_identity(before)
            == _stat_identity(opened)
            == _stat_identity(finished)
            == _stat_identity(after)
        )
    ):
        raise GateError("artifact manifest changed or is not one frozen file")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        parsed: dict[str, object] = {}
        for name, item in pairs:
            if name in parsed:
                raise GateError("artifact manifest contains a duplicate field")
            parsed[name] = item
        return parsed

    try:
        value = json.loads(
            payload.decode("ascii"), object_pairs_hook=reject_duplicates
        )
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError):
        raise GateError("artifact manifest is not valid canonical JSON") from None
    if not isinstance(value, dict) or _canonical_artifact_manifest_bytes(value) != payload:
        raise GateError("artifact manifest bytes are not canonical")
    return value, hashlib.sha256(payload).hexdigest()


def _revalidate_artifact_manifest(
    manifest_path: Path,
    *,
    expected_manifest_sha256: str | None,
    expected_artifact_set_id: str | None,
    require_frozen_directories: bool,
) -> dict[str, object]:
    export = manifest_path.parent
    if manifest_path != export / "artifact-manifest.json":
        raise GateError("artifact manifest is not at the export root")
    manifest, manifest_sha256 = _read_artifact_manifest(manifest_path)
    if expected_manifest_sha256 is not None and manifest_sha256 != expected_manifest_sha256:
        raise GateError("artifact manifest digest changed")
    if set(manifest) != {
        "artifact_classification",
        "artifact_set_id",
        "build_id",
        "credential_state",
        "files",
        "policy_id",
        "privilege_model",
        "publication",
        "release_eligible",
        "schema",
    }:
        raise GateError("artifact manifest field set mismatch")
    if (
        manifest["schema"] != _ARTIFACT_MANIFEST_SCHEMA
        or manifest["artifact_classification"] != _ARTIFACT_CLASSIFICATION
        or manifest["publication"] != _ARTIFACT_PUBLICATION
        or manifest["credential_state"] != _ARTIFACT_CREDENTIAL_STATE
        or manifest["release_eligible"] is not False
        or not isinstance(manifest["build_id"], str)
        or _SHA256_RE.fullmatch(manifest["build_id"]) is None
        or not isinstance(manifest["policy_id"], str)
        or not isinstance(manifest["privilege_model"], str)
    ):
        raise GateError("artifact manifest owner-private classification mismatch")
    values = manifest["files"]
    if not isinstance(values, list) or not values:
        raise GateError("artifact manifest file inventory is empty")
    files: list[dict[str, object]] = []
    paths: set[str] = set()
    for value in values:
        if not isinstance(value, dict) or set(value) != {"path", "sha256", "size"}:
            raise GateError("artifact manifest file entry has an invalid shape")
        relative = value["path"]
        if not isinstance(relative, str):
            raise GateError("artifact manifest path is invalid")
        pure = PurePosixPath(relative)
        if (
            not relative
            or pure.is_absolute()
            or pure.as_posix() != relative
            or any(part in {"", ".", ".."} for part in pure.parts)
            or relative == "artifact-manifest.json"
            or relative in paths
        ):
            raise GateError("artifact manifest path is unsafe or duplicated")
        if (
            not isinstance(value["sha256"], str)
            or _SHA256_RE.fullmatch(value["sha256"]) is None
            or not isinstance(value["size"], int)
            or isinstance(value["size"], bool)
            or value["size"] < 0
        ):
            raise GateError("artifact manifest digest or size is invalid")
        paths.add(relative)
        files.append(value)
    if files != sorted(files, key=lambda entry: str(entry["path"])):
        raise GateError("artifact manifest file inventory is not sorted")

    inventory = _export_file_inventory(export)
    inventory.pop("artifact-manifest.json", None)
    if set(inventory) != paths:
        raise GateError("artifact manifest does not cover the exact export inventory")
    for value in files:
        relative = str(value["path"])
        path = inventory[relative]
        if _stable_sha256(path, f"artifact {relative}") != value["sha256"]:
            raise GateError("artifact file digest changed")
        try:
            size = path.lstat().st_size
        except OSError as error:
            raise GateError(
                f"could not inspect frozen artifact: errno {error.errno or 'unknown'}"
            ) from None
        if size != value["size"]:
            raise GateError("artifact file size changed")
    calculated_set_id = _artifact_set_id(str(manifest["build_id"]), files)
    if (
        calculated_set_id == manifest["build_id"]
        or manifest["artifact_set_id"] != calculated_set_id
    ):
        raise GateError("artifact set id does not match the final file digests")
    if (
        expected_artifact_set_id is not None
        and calculated_set_id != expected_artifact_set_id
    ):
        raise GateError("artifact set id changed")
    if require_frozen_directories:
        directories = [export, *(path for path in export.rglob("*") if path.is_dir())]
        for directory in directories:
            try:
                metadata = directory.lstat()
            except OSError as error:
                raise GateError(
                    "could not inspect frozen artifact directory: "
                    f"errno {error.errno or 'unknown'}"
                ) from None
            if (
                directory.is_symlink()
                or not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o555
            ):
                raise GateError("artifact directory is not frozen")
    return manifest


def _freeze_and_recheck_outputs(
    export: Path,
    outputs: Sequence[Path],
    semantics_report: Mapping[str, object],
    *,
    boot_img: Path,
    userdata_img: Path,
    vmlinuz: Path,
    initramfs: Path,
    dtb: Path,
    build_id: str,
    privilege_model: str,
    policy_id: str,
) -> tuple[Path, str, str]:
    """Make outputs read-only and bind final bytes back to semantic evidence."""

    unique_outputs = sorted(set(outputs), key=lambda item: item.as_posix())
    for output in unique_outputs:
        try:
            metadata = output.lstat()
            if (
                output.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
            ):
                raise GateError(f"publication output is not one real file: {output.name}")
            output.chmod(0o444)
        except GateError:
            raise
        except OSError as error:
            raise GateError(
                "could not freeze publication output: "
                f"errno {error.errno or 'unknown'}"
            ) from None

    checks = (
        (boot_img, "boot image", ("boot", "sha256")),
        (userdata_img, "userdata image", ("userdata", "sha256")),
        (vmlinuz, "vmlinuz", ("boot", "kernel", "sha256")),
        (
            initramfs,
            "initramfs",
            ("boot", "initramfs", "compressed_sha256"),
        ),
        (dtb, "DTB", ("boot", "dtb", "sha256")),
    )
    for output, label, report_path in checks:
        expected = _semantic_digest(semantics_report, report_path)
        actual = _stable_sha256(output, label)
        if actual != expected:
            raise GateError(f"frozen {label} no longer matches semantic evidence")
        if label == "vmlinuz" and actual != _EXPECTED_VMLINUZ_SHA256:
            raise GateError("frozen vmlinuz does not match the pinned P1 kernel")

    inventory = _export_file_inventory(export)
    if set(inventory.values()) != set(unique_outputs):
        raise GateError("publication output list does not cover the exact export inventory")
    files = [
        {
            "path": relative,
            "sha256": _stable_sha256(path, f"artifact {relative}"),
            "size": path.lstat().st_size,
        }
        for relative, path in sorted(inventory.items())
    ]
    artifact_set_id = _artifact_set_id(build_id, files)
    if artifact_set_id == build_id:
        raise GateError("artifact set id is not distinct from the build id")
    manifest_value = {
        "artifact_classification": _ARTIFACT_CLASSIFICATION,
        "artifact_set_id": artifact_set_id,
        "build_id": build_id,
        "credential_state": _ARTIFACT_CREDENTIAL_STATE,
        "files": files,
        "policy_id": policy_id,
        "privilege_model": privilege_model,
        "publication": _ARTIFACT_PUBLICATION,
        "release_eligible": False,
        "schema": _ARTIFACT_MANIFEST_SCHEMA,
    }
    manifest_path = (export / "artifact-manifest.json").absolute()
    write_json(manifest_path, manifest_value)
    manifest_path.chmod(0o444)
    _manifest, manifest_sha256 = _read_artifact_manifest(manifest_path)
    _revalidate_artifact_manifest(
        manifest_path,
        expected_manifest_sha256=manifest_sha256,
        expected_artifact_set_id=artifact_set_id,
        require_frozen_directories=False,
    )

    directories = sorted(
        {path for path in export.rglob("*") if path.is_dir()},
        key=lambda item: len(item.parts),
        reverse=True,
    )
    try:
        for directory in directories:
            directory.chmod(0o555)
        export.chmod(0o555)
    except OSError as error:
        raise GateError(
            "could not freeze publication directories: "
            f"errno {error.errno or 'unknown'}"
        ) from None
    _revalidate_artifact_manifest(
        manifest_path,
        expected_manifest_sha256=manifest_sha256,
        expected_artifact_set_id=artifact_set_id,
        require_frozen_directories=True,
    )
    return manifest_path, manifest_sha256, artifact_set_id


def _verify_aarch64_elf(
    descriptor: int, file_size: int, label: str = "sshd.pam"
) -> None:
    message = f"{label} is not a valid little-endian 64-bit AArch64 ELF"
    try:
        header = os.pread(descriptor, 64, 0)
    except OSError:
        raise GateError(message) from None
    if (
        len(header) != 64
        or header[:4] != b"\x7fELF"
        or header[4] != 2
        or header[5] != 1
        or header[6] != 1
        or int.from_bytes(header[16:18], "little") not in {2, 3}
        or int.from_bytes(header[18:20], "little") != 183
        or int.from_bytes(header[20:24], "little") != 1
        or int.from_bytes(header[52:54], "little") != 64
        or int.from_bytes(header[54:56], "little") != 56
    ):
        raise GateError(message)

    program_offset = int.from_bytes(header[32:40], "little")
    entry_point = int.from_bytes(header[24:32], "little")
    program_entry_size = int.from_bytes(header[54:56], "little")
    program_count = int.from_bytes(header[56:58], "little")
    program_size = program_entry_size * program_count
    if (
        program_count == 0
        or program_offset < 64
        or program_offset > file_size
        or program_size > file_size - program_offset
    ):
        raise GateError(message)
    try:
        program_table = os.pread(descriptor, program_size, program_offset)
    except OSError:
        raise GateError(message) from None
    if len(program_table) != program_size:
        raise GateError(message)

    load_segment = False
    entry_in_executable_load_segment = False
    for index in range(program_count):
        start = index * program_entry_size
        entry = program_table[start : start + program_entry_size]
        segment_type = int.from_bytes(entry[0:4], "little")
        flags = int.from_bytes(entry[4:8], "little")
        offset = int.from_bytes(entry[8:16], "little")
        virtual_address = int.from_bytes(entry[16:24], "little")
        file_bytes = int.from_bytes(entry[32:40], "little")
        memory_bytes = int.from_bytes(entry[40:48], "little")
        alignment = int.from_bytes(entry[48:56], "little")
        if (
            (file_bytes and (offset > file_size or file_bytes > file_size - offset))
            or (alignment > 1 and alignment & (alignment - 1) != 0)
        ):
            raise GateError(message)
        if segment_type == 1:
            load_segment = True
            if (
                memory_bytes < file_bytes
                or virtual_address > (1 << 64) - 1 - memory_bytes
                or (
                    alignment > 1
                    and offset % alignment != virtual_address % alignment
                )
            ):
                raise GateError(message)
            segment_end = virtual_address + memory_bytes
            if (
                flags & 1
                and memory_bytes > 0
                and virtual_address <= entry_point < segment_end
            ):
                entry_in_executable_load_segment = True
    if not load_segment or entry_point == 0 or not entry_in_executable_load_segment:
        raise GateError(message)


def _verify_sshd_pam(
    rootfs: Path, installed_db: Path, expected_version: str
) -> dict[str, object]:
    package, apk_checksum = _sshd_pam_package_record(installed_db)
    if package.version != expected_version:
        raise GateError("openssh-server-pam version changed during final install")

    target = rootfs / "usr/sbin/sshd.pam"
    for parent in (rootfs / "usr", rootfs / "usr/sbin"):
        try:
            parent_mode = parent.lstat().st_mode
        except OSError:
            raise GateError("sshd.pam parent path must be a real directory") from None
        if parent.is_symlink() or not stat.S_ISDIR(parent_mode):
            raise GateError("sshd.pam parent path must be a real directory")
    try:
        before = target.lstat()
    except OSError:
        raise GateError("sshd.pam must be a regular non-symlink") from None
    if target.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise GateError("sshd.pam must be a regular non-symlink")
    if before.st_mode & 0o111 == 0:
        raise GateError("sshd.pam is not executable")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise GateError(f"could not securely open sshd.pam: {error}") from None
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    try:
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise GateError("sshd.pam must be a regular non-symlink")
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                sha1.update(block)
                sha256.update(block)
            _verify_aarch64_elf(stream.fileno(), opened.st_size)
    except OSError as error:
        raise GateError(f"could not read sshd.pam: {error}") from None
    try:
        after = target.lstat()
    except OSError:
        raise GateError("sshd.pam changed while it was being verified") from None
    if not (
        _stat_identity(before)
        == _stat_identity(opened)
        == _stat_identity(after)
    ):
        raise GateError("sshd.pam changed while it was being verified")

    checksum_algorithm, expected_checksum = _apk_checksum(apk_checksum)
    actual_checksum = sha1.digest() if checksum_algorithm == "sha1" else sha256.digest()
    if actual_checksum != expected_checksum:
        raise GateError("sshd.pam does not match its APK database checksum")
    return {
        "schema": "lmi-sshd-pam-attestation/v1",
        "package": package.name,
        "version": package.version,
        "package_id": f"{package.name}-{package.version}",
        "architecture": package.architecture,
        "path": "/usr/sbin/sshd.pam",
        "apk_database_checksum": apk_checksum,
        "sha256": sha256.hexdigest(),
        "size": opened.st_size,
    }


def _verify_unudhcpd(
    rootfs: Path,
    installed_db: Path,
    expected_versions: Mapping[str, str],
) -> None:
    packages, apk_checksum, service_apk_checksum = _dhcp_package_records(installed_db)
    actual_versions = {name: package.version for name, package in packages.items()}
    if actual_versions != dict(expected_versions):
        raise GateError("unudhcpd package versions changed during final install")

    target = rootfs / "usr/bin/unudhcpd"
    try:
        before = target.lstat()
    except OSError:
        raise GateError("unudhcpd must be a regular non-symlink") from None
    if target.is_symlink() or not stat.S_ISREG(before.st_mode):
        raise GateError("unudhcpd must be a regular non-symlink")
    if before.st_mode & 0o111 == 0:
        raise GateError("unudhcpd is not executable")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    try:
        descriptor = os.open(target, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise GateError("unudhcpd must be a regular non-symlink")
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                sha1.update(block)
                sha256.update(block)
            _verify_aarch64_elf(stream.fileno(), opened.st_size, "unudhcpd")
    except OSError as error:
        raise GateError(f"could not securely read unudhcpd: {error}") from None
    try:
        after = target.lstat()
    except OSError:
        raise GateError("unudhcpd changed while it was being verified") from None
    if not (_stat_identity(before) == _stat_identity(opened) == _stat_identity(after)):
        raise GateError("unudhcpd changed while it was being verified")

    checksum_algorithm, expected_checksum = _apk_checksum(apk_checksum, "unudhcpd")
    actual_checksum = sha1.digest() if checksum_algorithm == "sha1" else sha256.digest()
    if actual_checksum != expected_checksum:
        raise GateError("unudhcpd does not match its APK database checksum")

    service = rootfs / "etc/init.d/unudhcpd"
    try:
        service_metadata = service.lstat()
        service_value = service.read_bytes()
    except OSError as error:
        raise GateError(f"could not securely read unudhcpd OpenRC service: {error}") from None
    if (
        service.is_symlink()
        or not stat.S_ISREG(service_metadata.st_mode)
        or stat.S_IMODE(service_metadata.st_mode) != 0o755
    ):
        raise GateError("unudhcpd OpenRC service type or mode is not canonical")
    service_algorithm, service_expected = _apk_checksum(
        service_apk_checksum, "unudhcpd OpenRC service"
    )
    service_digest = (
        hashlib.sha1(service_value, usedforsecurity=False).digest()
        if service_algorithm == "sha1"
        else hashlib.sha256(service_value).digest()
    )
    if service_digest != service_expected:
        raise GateError("unudhcpd OpenRC service does not match its APK database checksum")


def _verify_package_policy(
    packages: Sequence[str], extra_versions: Mapping[str, str] | None = None
) -> None:
    actual = set(packages)
    required = dict(_REQUIRED_PACKAGE_VERSIONS)
    if extra_versions is not None:
        overlap = set(required) & set(extra_versions)
        if overlap:
            raise GateError(f"duplicate required package policy: {sorted(overlap)!r}")
        required.update(extra_versions)
    expected = {f"{name}-{version}" for name, version in required.items()}
    missing = expected - actual
    forbidden = _FORBIDDEN_PACKAGE_IDS & actual
    forbidden_dhcp = sorted(
        package
        for package in actual
        if any(
            package == name or package.startswith(name + "-")
            for name in _FORBIDDEN_DHCP_PACKAGE_NAMES
        )
    )
    if missing or forbidden or forbidden_dhcp:
        raise GateError(
            "P1 package policy mismatch: "
            f"missing {sorted(missing)!r}, "
            f"forbidden {sorted(forbidden)!r}, "
            f"second DHCP owner {forbidden_dhcp!r}"
        )


def _world_lines(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read apk world: {error}") from None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != len(set(lines)):
        raise GateError("apk world contains duplicate entries")
    if any(line.startswith("/") or line.endswith(".apk") for line in lines):
        raise GateError("apk world contains a local APK file path")
    return lines


def _world_specs(lines: Sequence[str], name: str) -> list[str]:
    return [
        line
        for line in lines
        if line == name
        or line.startswith(name + "@")
        or any(line.startswith(name + operator) for operator in ("=", "<", ">", "~"))
    ]


def _pin_exact_world_package(
    path: Path,
    name: str,
    version: str,
    *,
    allowed_current: Sequence[str] = (),
) -> None:
    lines = _world_lines(path)
    expected = f"{name}={version}"
    matches = _world_specs(lines, name)
    allowed = {name, expected, *allowed_current}
    conflicting = [line for line in matches if line not in allowed]
    if conflicting or len(matches) > 1:
        raise GateError(f"conflicting world constraint for {name}: {matches!r}")
    retained = [line for line in lines if line not in matches]
    retained.append(expected)
    try:
        path.write_text("\n".join(sorted(retained)) + "\n", encoding="utf-8")
    except OSError as error:
        raise GateError(f"could not pin apk world package: {error}") from None


def _read_world(
    path: Path, extra_versions: Mapping[str, str] | None = None
) -> str:
    lines = _world_lines(path)
    required = dict(_REQUIRED_PACKAGE_VERSIONS)
    if extra_versions is not None:
        overlap = set(required) & set(extra_versions)
        if overlap:
            raise GateError(f"duplicate required world package: {sorted(overlap)!r}")
        required.update(extra_versions)
    for name, version in required.items():
        expected = f"{name}={version}"
        matches = _world_specs(lines, name)
        if matches != [expected]:
            raise GateError(
                f"P1 world constraint mismatch for {name}: "
                f"expected {[expected]!r}, got {matches!r}"
            )
    return "\n".join(sorted(lines)) + "\n"


def _parse_fstab(path: Path) -> tuple[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read generated fstab: {error}") from None
    found: dict[str, str] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if len(fields) < 2 or not fields[0].startswith("UUID="):
            continue
        if fields[1] in {"/", "/boot"}:
            if fields[1] in found:
                raise GateError(f"duplicate generated fstab mount: {fields[1]}")
            found[fields[1]] = fields[0][5:]
    if set(found) != {"/", "/boot"}:
        raise GateError("generated fstab does not contain unique boot and root UUIDs")
    root_uuid = found["/"]
    boot_uuid = found["/boot"]
    if _UUID_RE.fullmatch(root_uuid) is None or _UUID_RE.fullmatch(boot_uuid) is None:
        raise GateError("generated fstab contains an unsafe UUID")
    return boot_uuid, root_uuid


def _candidate_id(
    tag: str,
    policy_id: str,
    project_commit: str,
    pmbootstrap_commit: str,
    pmaports_commit: str,
    boot_uuid: str,
    root_uuid: str,
    package_manifest_sha256: str,
) -> str:
    digest = hashlib.sha256()
    digest.update(
        b"\0".join(
            value.encode("utf-8")
            for value in (
                _IDENTITY_SCHEMA,
                tag,
                policy_id,
                project_commit,
                pmbootstrap_commit,
                pmaports_commit,
                boot_uuid,
                root_uuid,
                package_manifest_sha256,
            )
        )
    )
    return digest.hexdigest()


def _render_identity(
    template_path: Path,
    *,
    tag: str,
    privilege_model: str,
    policy_id: str,
    source_commit: str,
    boot_uuid: str,
    root_uuid: str,
    package_manifest_sha256: str,
) -> str:
    try:
        template = template_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read release identity template: {error}") from None
    candidate = _candidate_id(
        tag,
        policy_id,
        source_commit,
        _EXPECTED_PMBOOTSTRAP_COMMIT,
        _EXPECTED_PMAPORTS_COMMIT,
        boot_uuid,
        root_uuid,
        package_manifest_sha256,
    )
    build_utc = (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    try:
        rendered = template.format(
            tag=tag,
            privilege_model=privilege_model,
            policy_id=policy_id,
            source_commit=source_commit,
            pmbootstrap_commit=_EXPECTED_PMBOOTSTRAP_COMMIT,
            pmaports_commit=_EXPECTED_PMAPORTS_COMMIT,
            artifact_classification=_ARTIFACT_CLASSIFICATION,
            release_eligible="false",
            publication=_ARTIFACT_PUBLICATION,
            credential_state=_ARTIFACT_CREDENTIAL_STATE,
            candidate_id=candidate,
            boot_uuid=boot_uuid,
            root_uuid=root_uuid,
            package_manifest_sha256=package_manifest_sha256,
            build_utc=build_utc,
        )
    except (KeyError, ValueError) as error:
        raise GateError(f"invalid release identity template: {error}") from None
    values = dict(line.split("=", 1) for line in rendered.splitlines())
    if set(values) != {
        "schema",
        "scope",
        "tag",
        "privilege_model",
        "policy_id",
        "source_commit",
        "pmbootstrap_commit",
        "pmaports_commit",
        "artifact_classification",
        "release_eligible",
        "publication",
        "credential_state",
        "candidate_id",
        "boot_uuid",
        "root_uuid",
        "package_manifest_sha256",
        "device_xiaomi_lmi",
        "linux_xiaomi_lmi",
        "build_utc",
    }:
        raise GateError("release identity template field set mismatch")
    expected_policy = {
        "schema": _IDENTITY_SCHEMA,
        "scope": "lmi-p1-ssh",
        "privilege_model": privilege_model,
        "policy_id": policy_id,
        "source_commit": source_commit,
        "pmbootstrap_commit": _EXPECTED_PMBOOTSTRAP_COMMIT,
        "pmaports_commit": _EXPECTED_PMAPORTS_COMMIT,
        "artifact_classification": _ARTIFACT_CLASSIFICATION,
        "release_eligible": "false",
        "publication": _ARTIFACT_PUBLICATION,
        "credential_state": _ARTIFACT_CREDENTIAL_STATE,
        "device_xiaomi_lmi": _REQUIRED_PACKAGE_VERSIONS["device-xiaomi-lmi"],
        "linux_xiaomi_lmi": _REQUIRED_PACKAGE_VERSIONS["linux-xiaomi-lmi"],
    }
    mismatched = {
        name: values[name]
        for name, expected in expected_policy.items()
        if values[name] != expected
    }
    if mismatched:
        raise GateError(
            "release identity template P1 policy mismatch: "
            f"expected {expected_policy!r}, got {mismatched!r}"
        )
    return rendered


def _finalizer_script() -> str:
    return """#!/bin/sh
set -eu

stage=/mnt/pmbootstrap/packages/lmi-p1-finalize

/bin/mkdir -p /etc/ssh /usr/sbin /etc/sudoers.d /etc/doas.d /etc/apk \
	/etc/NetworkManager/conf.d /etc/NetworkManager/system-connections \
	/etc/conf.d /etc/init.d /home/lmi/.ssh
/bin/cp "$stage/sshd_config" /etc/ssh/sshd_config
/bin/cp "$stage/lmi-rootctl" /usr/sbin/lmi-rootctl
/bin/cp "$stage/lmi-release-identity" /etc/lmi-release-identity
/bin/cp "$stage/world" /etc/apk/world
/bin/cp "$stage/lmi-usb0.nmconnection" \
	/etc/NetworkManager/system-connections/lmi-usb0.nmconnection
/bin/cp "$stage/90-lmi-usb0-takeover.conf" \
	/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf
/bin/cp "$stage/lmi-usb0-dhcp" /usr/sbin/lmi-usb0-dhcp
/bin/cp "$stage/lmi-usb0-dhcp.initd" /etc/init.d/lmi-usb0-dhcp
/bin/cp "$stage/unudhcpd.usb0.confd" /etc/conf.d/unudhcpd.usb0
/bin/cp "$stage/authorized_keys" /home/lmi/.ssh/authorized_keys
/bin/chown root:root /etc/ssh/sshd_config
/bin/chown root:root /usr/sbin/lmi-rootctl
/bin/chown root:root /etc/lmi-release-identity
/bin/chown root:root /etc/apk/world
/bin/chown root:root \
	/etc/NetworkManager/system-connections/lmi-usb0.nmconnection
/bin/chown root:root /etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf
/bin/chown root:root /usr/sbin/lmi-usb0-dhcp
/bin/chown root:root /etc/init.d/lmi-usb0-dhcp
/bin/chown root:root /etc/conf.d/unudhcpd.usb0
/bin/chmod 0600 /etc/ssh/sshd_config
/bin/chmod 0755 /usr/sbin/lmi-rootctl
/bin/chmod 0644 /etc/lmi-release-identity
/bin/chmod 0644 /etc/apk/world
/bin/chmod 0600 /etc/NetworkManager/system-connections/lmi-usb0.nmconnection
/bin/chmod 0644 /etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf
/bin/chmod 0755 /usr/sbin/lmi-usb0-dhcp
/bin/chmod 0755 /etc/init.d/lmi-usb0-dhcp
/bin/chmod 0644 /etc/conf.d/unudhcpd.usb0
/bin/chmod 0700 /home/lmi/.ssh
/bin/chmod 0600 /home/lmi/.ssh/authorized_keys
/bin/chown -R lmi:lmi /home/lmi/.ssh

/bin/rm -f /etc/ssh/ssh_host_*
for host_key in /etc/ssh/ssh_host_*; do
	[ ! -e "$host_key" ] || exit 31
done

/usr/bin/awk -F: 'BEGIN { OFS=FS; root=0; lmi=0 }
$1 == "root" { $2="!"; root++ }
$1 == "lmi" { $2="!"; lmi++ }
{ print }
END { if (root != 1 || lmi != 1) exit 32 }' /etc/shadow > /etc/shadow.lmi-p1
/bin/chown root:shadow /etc/shadow.lmi-p1
/bin/chmod 0640 /etc/shadow.lmi-p1
/bin/mv /etc/shadow.lmi-p1 /etc/shadow
[ "$(/usr/bin/awk -F: '$1 == "root" { print $2 }' /etc/shadow)" = '!' ] || exit 33
[ "$(/usr/bin/awk -F: '$1 == "lmi" { print $2 }' /etc/shadow)" = '!' ] || exit 34

/usr/bin/cmp -s "$stage/authorized_keys" /home/lmi/.ssh/authorized_keys || exit 35
key_lines=$(/usr/bin/awk 'NF { count++ } END { print count+0 }' /home/lmi/.ssh/authorized_keys)
[ "$key_lines" -eq 1 ] || exit 36
actual_fingerprint=$(/usr/bin/ssh-keygen -lf /home/lmi/.ssh/authorized_keys | /usr/bin/awk 'NR == 1 { print $2 }')
expected_fingerprint=$(/bin/cat "$stage/expected-fingerprint")
[ "$actual_fingerprint" = "$expected_fingerprint" ] || exit 37

/usr/bin/cmp -s "$stage/world" /etc/apk/world || exit 38
/usr/bin/cmp -s "$stage/lmi-usb0.nmconnection" \
	/etc/NetworkManager/system-connections/lmi-usb0.nmconnection || exit 39
/usr/bin/cmp -s "$stage/90-lmi-usb0-takeover.conf" \
	/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf || exit 48
/usr/bin/cmp -s "$stage/lmi-usb0-dhcp" /usr/sbin/lmi-usb0-dhcp || exit 49
/usr/bin/cmp -s "$stage/lmi-usb0-dhcp.initd" /etc/init.d/lmi-usb0-dhcp || exit 50
/usr/bin/cmp -s "$stage/unudhcpd.usb0.confd" /etc/conf.d/unudhcpd.usb0 || exit 51
[ -f /etc/init.d/unudhcpd ] && [ ! -L /etc/init.d/unudhcpd ] || exit 52
[ "$(/usr/bin/stat -c '%U:%G:%a' /etc/init.d/unudhcpd)" = root:root:755 ] || exit 53
/bin/rm -f /etc/init.d/unudhcpd.usb0
/bin/ln -s unudhcpd /etc/init.d/unudhcpd.usb0
[ "$(/usr/bin/readlink /etc/init.d/unudhcpd.usb0)" = unudhcpd ] || exit 54

if /usr/bin/id -nG lmi | /bin/grep -Eq '(^|[[:space:]])wheel([[:space:]]|$)'; then
	/usr/sbin/delgroup lmi wheel
fi
if /usr/bin/id -nG lmi | /bin/grep -Eq '(^|[[:space:]])wheel([[:space:]]|$)'; then
	exit 40
fi

/bin/rm -f /etc/doas.conf /etc/doas.d/* /etc/doas.d/.[!.]* /etc/doas.d/..?*
for doas_rule in /etc/doas.conf /etc/doas.d/* /etc/doas.d/.[!.]* /etc/doas.d/..?*; do
	[ ! -e "$doas_rule" ] || exit 41
done

/bin/rm -f /etc/sudoers.d/* /etc/sudoers.d/.[!.]* /etc/sudoers.d/..?*
/bin/cp "$stage/sudoers" /etc/sudoers
/bin/cp "$stage/90-lmi-rootctl" /etc/sudoers.d/90-lmi-rootctl
/bin/chown root:root /etc/sudoers
/bin/chown root:root /etc/sudoers.d/90-lmi-rootctl
/bin/chmod 0440 /etc/sudoers
/bin/chmod 0440 /etc/sudoers.d/90-lmi-rootctl
/usr/bin/cmp -s "$stage/sudoers" /etc/sudoers || exit 42
/usr/bin/cmp -s "$stage/90-lmi-rootctl" /etc/sudoers.d/90-lmi-rootctl || exit 43
sudoers_entries=0
for sudoers_rule in /etc/sudoers.d/* /etc/sudoers.d/.[!.]* /etc/sudoers.d/..?*; do
	[ -e "$sudoers_rule" ] || continue
	[ "$sudoers_rule" = /etc/sudoers.d/90-lmi-rootctl ] || exit 44
	sudoers_entries=$((sudoers_entries + 1))
done
[ "$sudoers_entries" -eq 1 ] || exit 45
/usr/bin/visudo -cf /etc/sudoers

/sbin/rc-update add sshd default
/sbin/rc-update add networkmanager default
/sbin/rc-update add lmi-usb0-dhcp default
/bin/rm -f /etc/runlevels/default/unudhcpd /etc/runlevels/default/unudhcpd.*
[ -L /etc/runlevels/default/sshd ] || exit 46
[ -L /etc/runlevels/default/networkmanager ] || exit 47
[ "$(/usr/bin/readlink /etc/runlevels/default/sshd)" = /etc/init.d/sshd ] || exit 55
[ "$(/usr/bin/readlink /etc/runlevels/default/networkmanager)" = /etc/init.d/networkmanager ] || exit 56
[ "$(/usr/bin/readlink /etc/runlevels/default/lmi-usb0-dhcp)" = /etc/init.d/lmi-usb0-dhcp ] || exit 57

/bin/echo 'lmi-p1-finalize=ok'
"""


def _stage_finalizer(
    root: Path,
    payload: Path,
    public_key_text: str,
    fingerprint: str,
    identity: str,
    world: str,
) -> Path:
    destination = root / "packages/lmi-p1-finalize"
    if destination.exists() or destination.is_symlink():
        raise GateError(f"finalizer staging path already exists: {destination}")
    destination.mkdir(parents=True)
    modes = {
        "sshd_config": 0o600,
        "lmi-rootctl": 0o755,
        "90-lmi-rootctl": 0o440,
        "sudoers": 0o440,
        "lmi-usb0.nmconnection": 0o600,
        "90-lmi-usb0-takeover.conf": 0o644,
        "lmi-usb0-dhcp": 0o755,
        "lmi-usb0-dhcp.initd": 0o755,
        "unudhcpd.usb0.confd": 0o644,
    }
    for name, mode in modes.items():
        source = payload / name
        if source.is_symlink() or not source.is_file():
            raise GateError(f"missing real rootfs payload: {source}")
        shutil.copyfile(source, destination / name)
        (destination / name).chmod(mode)
    (destination / "authorized_keys").write_text(public_key_text, encoding="utf-8")
    (destination / "authorized_keys").chmod(0o600)
    (destination / "expected-fingerprint").write_text(fingerprint + "\n", encoding="utf-8")
    (destination / "expected-fingerprint").chmod(0o600)
    (destination / "lmi-release-identity").write_text(identity, encoding="utf-8")
    (destination / "lmi-release-identity").chmod(0o644)
    (destination / "world").write_text(world, encoding="utf-8")
    (destination / "world").chmod(0o644)
    (destination / "finalize.sh").write_text(_finalizer_script(), encoding="utf-8")
    (destination / "finalize.sh").chmod(0o755)
    return destination


def _deviceinfo_dtb(path: Path) -> Path:
    deviceinfo = path / "device/downstream/device-xiaomi-lmi/deviceinfo"
    try:
        text = deviceinfo.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read staged DTB policy: {error}") from None
    matches = re.findall(
        r'^deviceinfo_dtb=["\']?([^"\'\n]+)["\']?$',
        text,
        flags=re.MULTILINE,
    )
    if matches != [_EXPECTED_DTB_STEM]:
        raise GateError(
            "staged lmi deviceinfo does not select the exact nested DTB: "
            f"{matches!r}"
        )
    return Path(*(_EXPECTED_DTB_STEM + ".dtb").split("/"))


def _expected_export_target(candidate: Path, scope: str, relative: str) -> Path:
    roots = {
        "rootfs": candidate / "work/chroot_rootfs_xiaomi-lmi",
        "native": candidate / "work/chroot_native",
        "buildroot": candidate / "work/chroot_buildroot_aarch64",
    }
    return (roots[scope] / relative).absolute()


def _open_directory_chain(root_fd: int, parts: tuple[str, ...]) -> int:
    descriptor = os.dup(root_fd)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    try:
        for component in parts:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_candidate_regular(candidate_fd: int, relative: Path) -> tuple[int, int]:
    parent_fd = _open_directory_chain(candidate_fd, relative.parts[:-1])
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(relative.name, flags, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    opened = os.fstat(source_fd)
    if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
        os.close(source_fd)
        os.close(parent_fd)
        raise GateError("export target is not one regular inode")
    return source_fd, parent_fd


def _export_link_target(
    path: Path,
    expected_target: Path,
    candidate: Path,
    candidate_fd: int,
    export: Path,
    export_fd: int,
    *,
    required: bool,
) -> _VerifiedExport | None:
    if not path.is_symlink():
        raise GateError(f"export entry is not an absolute symlink: {path}")
    try:
        raw_target = Path(os.readlink(path))
    except OSError as error:
        raise GateError(f"could not read export symlink {path}: {error}") from None
    if not raw_target.is_absolute():
        raise GateError(f"export entry is not an absolute symlink: {path}")
    if not _is_within(raw_target, candidate):
        raise GateError(f"export target escapes candidate: {path} -> {raw_target}")
    if required and not os.path.lexists(raw_target):
        raise GateError(f"dangling export target: {path}")
    if raw_target != expected_target:
        raise GateError(
            f"export target mismatch: {path.name} -> {raw_target}, "
            f"expected {expected_target}"
        )
    try:
        relative_target = expected_target.relative_to(candidate)
        source_fd, source_parent_fd = _open_candidate_regular(
            candidate_fd, relative_target
        )
    except FileNotFoundError:
        if required:
            raise GateError(f"dangling export target: {path}") from None
        return None
    except (OSError, ValueError, GateError) as error:
        if isinstance(error, GateError):
            raise GateError(f"export target is not a real file: {path}") from None
        raise GateError(f"export target is not a real file: {path}: {error}") from None
    try:
        destination_parent_fd = _open_directory_chain(
            export_fd, path.parent.relative_to(export).parts
        )
    except BaseException:
        os.close(source_fd)
        os.close(source_parent_fd)
        raise
    try:
        link_stat = os.stat(
            path.name, dir_fd=destination_parent_fd, follow_symlinks=False
        )
        descriptor_target = os.readlink(path.name, dir_fd=destination_parent_fd)
    except OSError:
        os.close(source_fd)
        os.close(source_parent_fd)
        os.close(destination_parent_fd)
        raise GateError(f"export link changed during validation: {path}") from None
    if not stat.S_ISLNK(link_stat.st_mode) or descriptor_target != str(raw_target):
        os.close(source_fd)
        os.close(source_parent_fd)
        os.close(destination_parent_fd)
        raise GateError(f"export link changed during validation: {path}")
    opened = os.fstat(source_fd)
    return _VerifiedExport(
        link=path,
        target=expected_target,
        source_fd=source_fd,
        source_identity=_stat_identity(opened),
        source_parent_fd=source_parent_fd,
        source_name=relative_target.name,
        destination_parent_fd=destination_parent_fd,
        destination_name=path.name,
        link_identity=_stat_identity(link_stat),
    )


def _stage_selected_dtb(export: Path, candidate: Path, relative: Path) -> None:
    rootfs = (candidate / "work/chroot_rootfs_xiaomi-lmi").absolute()
    source = (rootfs / "boot/dtbs" / relative).absolute()
    if not os.path.lexists(source):
        raise GateError(f"selected DTB is missing: {source}")
    try:
        resolved = source.resolve(strict=True)
    except (OSError, RuntimeError):
        raise GateError(f"selected DTB must be a real file: {source}") from None
    if (
        source.is_symlink()
        or not source.is_file()
        or resolved != source
        or not _is_within(resolved, rootfs)
    ):
        raise GateError(f"selected DTB must be a real file: {source}")
    dtb_root = export / "dtbs"
    if os.path.lexists(dtb_root):
        raise GateError("unexpected export inventory: pmbootstrap exported a DTB directory")
    destination = dtb_root / relative
    destination.parent.mkdir(parents=True)
    destination.symlink_to(source)


def _validate_export_links(
    export: Path, candidate: Path, selected_dtb: Path
) -> tuple[dict[str, _VerifiedExport], list[Path]]:
    if export.is_symlink() or not export.is_dir():
        raise GateError(f"export root is not a real directory: {export}")
    entries = {entry.name: entry for entry in export.iterdir()}
    kernels = sorted(name for name in entries if name.startswith("vmlinuz"))
    initramfs_all = sorted(name for name in entries if name.startswith("initramfs"))
    allowed_initramfs = {"initramfs", "initramfs-extra"}
    if kernels != ["vmlinuz"] or not (
        set(initramfs_all) <= allowed_initramfs and "initramfs" in initramfs_all
    ):
        raise GateError(
            "unexpected export inventory: expected exact vmlinuz/initramfs names, "
            f"got kernels={kernels!r}, initramfs={initramfs_all!r}"
        )
    dynamic = kernels + initramfs_all
    expected_top = set(_STANDARD_EXPORT_TARGETS) | set(dynamic) | {"dtbs"}
    if set(entries) != expected_top:
        raise GateError(
            "unexpected export inventory: "
            f"expected {sorted(expected_top)!r}, got {sorted(entries)!r}"
        )
    dtb_root = entries["dtbs"]
    if dtb_root.is_symlink() or not dtb_root.is_dir():
        raise GateError("exported DTB inventory is not a real directory")
    dtb_link = dtb_root / selected_dtb
    expected_dtb_directories = {
        dtb_root.joinpath(*selected_dtb.parts[:index])
        for index in range(1, len(selected_dtb.parts))
    }
    actual_dtb_entries = set(dtb_root.rglob("*"))
    if actual_dtb_entries != expected_dtb_directories | {dtb_link}:
        raise GateError(
            "unexpected export inventory: invalid DTB entries "
            f"{sorted(str(entry.relative_to(dtb_root)) for entry in actual_dtb_entries)!r}"
        )

    open_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_DIRECTORY", 0)
    )
    candidate_fd = os.open(candidate, open_flags)
    try:
        export_fd = os.open(export, open_flags)
    except BaseException:
        os.close(candidate_fd)
        raise
    result: dict[str, _VerifiedExport] = {}
    dangling_optional: list[Path] = []
    try:
        for name, (scope, target_relative) in _STANDARD_EXPORT_TARGETS.items():
            link = entries[name]
            target = _export_link_target(
                link,
                _expected_export_target(candidate, scope, target_relative),
                candidate,
                candidate_fd,
                export,
                export_fd,
                required=name in _REQUIRED_STANDARD_EXPORTS,
            )
            if target is None:
                dangling_optional.append(link)
            else:
                result[name] = target
        rootfs_boot = (candidate / "work/chroot_rootfs_xiaomi-lmi/boot").absolute()
        for name in dynamic:
            link = entries[name]
            target = _export_link_target(
                link,
                rootfs_boot / name,
                candidate,
                candidate_fd,
                export,
                export_fd,
                required=True,
            )
            if target is None:
                raise GateError(f"required dynamic export is dangling: {link}")
            result[name] = target
        dtb_target = _export_link_target(
            dtb_link,
            (
                candidate
                / "work/chroot_rootfs_xiaomi-lmi/boot/dtbs"
                / selected_dtb
            ).absolute(),
            candidate,
            candidate_fd,
            export,
            export_fd,
            required=True,
        )
        if dtb_target is None:
            raise GateError(f"required selected DTB export is dangling: {dtb_link}")
        result[dtb_link.relative_to(export).as_posix()] = dtb_target
        return result, dangling_optional
    except BaseException:
        for verified in result.values():
            verified.close()
        raise
    finally:
        os.close(candidate_fd)
        os.close(export_fd)


def _materialize_export_link(verified: _VerifiedExport) -> None:
    temporary_name = f".{verified.destination_name}.{secrets.token_hex(12)}.materializing"
    temporary_created = False
    try:
        if (
            _stat_identity(os.fstat(verified.source_fd)) != verified.source_identity
            or _stat_identity(
                os.stat(
                    verified.source_name,
                    dir_fd=verified.source_parent_fd,
                    follow_symlinks=False,
                )
            )
            != verified.source_identity
            or _stat_identity(verified.target.lstat()) != verified.source_identity
            or _stat_identity(
                os.stat(
                    verified.destination_name,
                    dir_fd=verified.destination_parent_fd,
                    follow_symlinks=False,
                )
            )
            != verified.link_identity
            or _stat_identity(verified.link.lstat()) != verified.link_identity
        ):
            raise GateError(f"export source or parent identity changed: {verified.link}")
        destination_fd = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o600,
            dir_fd=verified.destination_parent_fd,
        )
        temporary_created = True
        with os.fdopen(os.dup(verified.source_fd), "rb") as source, os.fdopen(
            destination_fd, "wb"
        ) as destination:
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        if (
            _stat_identity(os.fstat(verified.source_fd)) != verified.source_identity
            or _stat_identity(
                os.stat(
                    verified.source_name,
                    dir_fd=verified.source_parent_fd,
                    follow_symlinks=False,
                )
            )
            != verified.source_identity
            or _stat_identity(verified.target.lstat()) != verified.source_identity
        ):
            raise GateError(f"export source identity changed while copying: {verified.link}")
        os.chmod(temporary_name, 0o644, dir_fd=verified.destination_parent_fd)
        os.replace(
            temporary_name,
            verified.destination_name,
            src_dir_fd=verified.destination_parent_fd,
            dst_dir_fd=verified.destination_parent_fd,
        )
        temporary_created = False
    except GateError:
        raise
    except OSError as error:
        raise GateError(
            f"export source or parent identity changed: {verified.link}: {error}"
        ) from None
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=verified.destination_parent_fd)
            except OSError:
                pass


def _materialize_export(
    export: Path, candidate: Path, selected_dtb: Path
) -> dict[str, Path]:
    _stage_selected_dtb(export, candidate, selected_dtb)
    approved, dangling_optional = _validate_export_links(
        export, candidate, selected_dtb
    )
    try:
        for verified in approved.values():
            _materialize_export_link(verified)
    finally:
        for verified in approved.values():
            verified.close()
    for link in dangling_optional:
        try:
            link.unlink()
        except OSError as error:
            raise GateError(f"could not remove dangling optional export {link}: {error}") from None
    result = {relative: verified.link for relative, verified in approved.items()}
    for relative, output in result.items():
        try:
            mode = output.lstat().st_mode
            links = output.stat().st_nlink
        except OSError as error:
            raise GateError(f"could not verify materialized export {relative}: {error}") from None
        if not stat.S_ISREG(mode) or output.is_symlink() or links != 1:
            raise GateError(f"materialized export is not one regular inode: {relative}")
    return result


def _sealed_build_mode(
    ctx: BuildContext,
    authorization: _SealedBuildAuthorization | None,
) -> bool:
    """Validate privilege from an unforgeable verified-seal capability."""

    effective_uid = os.geteuid()
    if authorization is None:
        if (
            ctx.privilege_model != _PRIVILEGE_UNSEALED
            or ctx.policy_id != _UNSEALED_POLICY_ID
        ):
            raise GateError(
                "sealed production privilege requires verified internal authorization"
            )
        if effective_uid == 0:
            raise GateError(
                "unsealed-development builder must run as an unprivileged user; "
                "it is ineligible for hardware or release use"
            )
        return False

    if (
        not isinstance(authorization, _SealedBuildAuthorization)
        or authorization.marker is not _SEALED_AUTHORIZATION_MARKER
        or authorization.context != ctx
    ):
        raise GateError("sealed production authorization is invalid")
    if ctx.privilege_model != _PRIVILEGE_SEALED:
        raise GateError("sealed production privilege model mismatch")
    if _SHA256_RE.fullmatch(ctx.policy_id) is None:
        raise GateError("sealed production policy id must be 64 lowercase hex")
    if effective_uid != 0:
        raise GateError("sealed production builder requires effective UID 0")

    verified = authorization.seal
    expected_paths = {
        "repo": verified.project,
        "pmaports": verified.pmaports,
        "pmbootstrap": verified.pmbootstrap / "pmbootstrap.py",
        "public_key": verified.authorized_key,
        "work": authorization.run_root / "candidate",
    }
    for field, expected in expected_paths.items():
        if Path(getattr(ctx, field)).absolute() != expected.absolute():
            raise GateError(f"sealed production {field} is not seal-derived")
    provenance = verified.manifest.get("provenance")
    project = provenance.get("project") if isinstance(provenance, Mapping) else None
    if (
        ctx.policy_id != verified.policy_id
        or not isinstance(project, Mapping)
        or ctx.source_commit != project.get("commit")
    ):
        raise GateError("sealed production context provenance mismatch")
    return True


def _pmbootstrap_argv(
    pmbootstrap: Path,
    config_path: Path,
    work: Path,
    pmaports: Path,
    arguments: Sequence[str],
    *,
    sealed: bool,
) -> list[str]:
    command = [sys.executable, "-E", "-B", str(pmbootstrap)]
    if sealed:
        command.extend(("--as-root", "--offline"))
    command.extend(
        [
            "-c",
            str(config_path.absolute()),
            "-w",
            str(work.absolute()),
            "-p",
            str(pmaports.absolute()),
            *arguments,
        ]
    )
    return command


def _build_candidate(
    ctx: BuildContext,
    authorization: _SealedBuildAuthorization | None,
) -> BuildResult:
    """Build one isolated P1 candidate without phone, network-policy, or flash actions."""

    sealed = _sealed_build_mode(ctx, authorization)
    if _TAG_RE.fullmatch(ctx.tag) is None:
        raise GateError(f"invalid candidate tag: {ctx.tag!r}")
    if _COMMIT_RE.fullmatch(ctx.source_commit) is None:
        raise GateError("source commit must be a lowercase 40-character Git object ID")

    repo = _real_directory(Path(ctx.repo), "repository")
    source_pmaports = _real_directory(Path(ctx.pmaports), "staged pmaports")
    actual_fingerprint, public_key_text = _read_public_key_once(Path(ctx.public_key))
    if actual_fingerprint != ctx.public_key_fingerprint:
        raise GateError(
            "SSH public key fingerprint mismatch: "
            f"expected {ctx.public_key_fingerprint}, got {actual_fingerprint}"
        )
    pmbootstrap_source = _real_file(
        Path(ctx.pmbootstrap), "pmbootstrap executable", executable=True
    )

    work_requested = Path(ctx.work).absolute()
    unresolved_inputs = (source_pmaports, pmbootstrap_source)
    unresolved_work = work_requested.resolve(strict=False)
    for input_path in unresolved_inputs:
        if _overlaps(unresolved_work, input_path):
            raise GateError(f"candidate work overlaps an input path: {input_path}")
    candidate = _prepare_empty_root(work_requested)

    config_dir = candidate / "config"
    pmb_work = candidate / "work"
    isolated_pmaports = candidate / "pmaports"
    source_checkout = candidate / "source"
    export_dir = candidate / "export"
    config_dir.mkdir()
    if sealed:
        if authorization is None:
            raise GateError("sealed cache seeding requires internal authorization")
        _seed_verified_offline_cache(
            authorization.offline_cache,
            pmb_work,
            authorization.offline_cache_manifest,
        )
    else:
        pmb_work.mkdir()
    export_dir.mkdir()
    private_public_key = config_dir / "authorized_key.pub"
    private_public_key.write_text(public_key_text, encoding="utf-8")
    private_public_key.chmod(0o600)
    _secure_checkout(
        repo,
        source_checkout,
        ctx.source_commit,
        "source checkout",
        require_clean_source=False,
        reject_source_index_flags=False,
    )
    source_lock = _read_source_lock(
        source_checkout / "config/lmi-p1/source-lock.json"
    )
    known_good_kernel_pin = source_lock["known_good_kernel_package"]
    if not isinstance(known_good_kernel_pin, Mapping):
        raise GateError("sealed source lock known-good kernel pin is malformed")
    if authorization is not None and source_lock != dict(authorization.source_lock):
        raise GateError("sealed source lock changed in the pinned project checkout")
    _validate_kernel_apkbuild(
        source_checkout / "artifacts/wsl-pmaports/linux-xiaomi-lmi",
        source_lock["kernel"],
    )
    pmaports_base = candidate / "pmaports-base"
    _secure_checkout(
        source_pmaports,
        pmaports_base,
        _EXPECTED_PMAPORTS_COMMIT,
        "pmaports base",
        require_clean_source=False,
        reject_source_index_flags=True,
    )
    prepare_pmaports(
        source=pmaports_base,
        destination=isolated_pmaports,
        commit=_EXPECTED_PMAPORTS_COMMIT,
        overlay=source_checkout / "artifacts/wsl-pmaports",
        patch=(
            source_checkout
            / "patches/postmarketos-initramfs/0001-lmi-handle-4096-sector-loop-partitions.patch"
        ),
    )
    shutil.rmtree(pmaports_base)
    _validate_staged_pmaports(isolated_pmaports, isolated_pmaports)
    _validate_staged_pmaports(source_pmaports, isolated_pmaports)
    _validate_kernel_apkbuild(
        isolated_pmaports / "device/downstream/linux-xiaomi-lmi",
        source_lock["kernel"],
    )
    _validate_kernel_apkbuild(
        source_pmaports / "device/downstream/linux-xiaomi-lmi",
        source_lock["kernel"],
    )
    selected_dtb = _deviceinfo_dtb(isolated_pmaports)
    pmbootstrap_repository, pmbootstrap = _prepare_pmbootstrap(
        pmbootstrap_source, candidate
    )

    payload = source_checkout / "files/lmi-p1"
    if payload.is_symlink() or not payload.is_dir():
        raise GateError(f"missing real lmi P1 payload directory: {payload}")
    config_path = config_dir / "pmbootstrap.cfg"
    _write_config(config_path, private_public_key)
    failure_log = config_dir / "build.log"
    log_records: list[str] = [
        f"tag={ctx.tag}",
        f"privilege_model={ctx.privilege_model}",
        f"policy_id={ctx.policy_id}",
        f"source_commit={ctx.source_commit}",
        "project_source=[PROJECT_INPUT]",
        "pmbootstrap_source=[PMBOOTSTRAP_INPUT]",
        "pmbootstrap=[CANDIDATE]/pmbootstrap/pmbootstrap.py",
        "pmaports_source=[PMAPORTS_INPUT]",
        "pmaports=[CANDIDATE]/pmaports",
        (
            "kernel_source=sealed-known-good-signed-apkv3"
            if sealed
            else "kernel_source=normal-source-build"
        ),
    ]
    pmbootstrap_environment = _pmbootstrap_environment()
    password = secrets.token_urlsafe(32)
    private_path_labels = tuple(
        sorted(
            (
                (str(candidate), "[CANDIDATE]"),
                (str(pmbootstrap_source), "[PMBOOTSTRAP_INPUT]"),
                (str(source_pmaports), "[PMAPORTS_INPUT]"),
                (str(repo), "[PROJECT_INPUT]"),
                *(
                    ((str(authorization.seal.root), "[SEALED_INPUT]"),)
                    if authorization is not None
                    else ()
                ),
            ),
            key=lambda item: len(item[0]),
            reverse=True,
        )
    )

    def redact_log_value(value: str) -> str:
        redacted = _redact_password(value, password)
        for private_path, label in private_path_labels:
            redacted = redacted.replace(private_path, label)
        return redacted

    pmb_started = False
    clean_shutdown = False
    finalizer: Path | None = None
    result: BuildResult | None = None
    pending_error: BaseException | None = None

    def invoke(*arguments: str, check: bool = True):
        nonlocal pmb_started
        command = _pmbootstrap_argv(
            pmbootstrap,
            config_path,
            pmb_work,
            isolated_pmaports,
            arguments,
            sealed=sealed,
        )
        pmb_started = True
        log_records.append("argv=" + redact_log_value(repr(command)))
        try:
            completed = run(
                command,
                timeout=_COMMAND_TIMEOUT,
                check=False,
                env=pmbootstrap_environment,
            )
        except GateError as error:
            redacted = redact_log_value(str(error))
            log_records.append("gate_error=" + redacted)
            raise GateError(redacted) from None
        log_records.append(f"returncode={completed.returncode}")
        if completed.stdout:
            log_records.append("stdout=" + redact_log_value(completed.stdout).rstrip())
        if completed.stderr:
            log_records.append("stderr=" + redact_log_value(completed.stderr).rstrip())
        if check and completed.returncode != 0:
            raise GateError(
                "pmbootstrap command failed with exit status "
                f"{completed.returncode}; see redacted build log"
            )
        return completed

    try:
        version = invoke("--version").stdout.strip()
        if version != _EXPECTED_PMBOOTSTRAP_VERSION:
            raise GateError(
                "pmbootstrap version mismatch: "
                f"expected {_EXPECTED_PMBOOTSTRAP_VERSION}, got {version}"
            )

        invoke("checksum", "--verify", *_PACKAGES)
        build_packages = _PACKAGES
        install_add = "unudhcpd-openrc"
        if sealed:
            _stage_known_good_kernel_status(
                source_checkout,
                pmb_work,
                known_good_kernel_pin,
            )
            build_packages = tuple(
                package for package in _PACKAGES if package != _KNOWN_GOOD_NAME
            )
        invoke("build", *build_packages)
        if sealed:
            # apk-tools v2 cannot index the signed APKv3 package. Rebuild and
            # sign the normal local v2 repository first, then install the v3
            # package by its explicit sealed path and signer trust root.
            invoke("index")
            known_good_kernel_apk = _stage_known_good_kernel_install(
                source_checkout,
                pmb_work,
                known_good_kernel_pin,
            )
            install_add = _known_good_install_add(known_good_kernel_apk)
        invoke(
            "install",
            "--no-image",
            "--no-fde",
            "--add",
            install_add,
            "--password",
            password,
        )

        rootfs = pmb_work / "chroot_rootfs_xiaomi-lmi"
        installed_db = rootfs / "lib/apk/db/installed"
        if installed_db.is_symlink() or not installed_db.is_file():
            raise GateError("missing rootfs installed package database")
        if sealed:
            _verify_known_good_kernel_install(rootfs, installed_db)
        keys_before = _all_key_hashes(pmb_work, rootfs)
        packages = _parse_apk_database(installed_db)
        sshd_package, _ = _sshd_pam_package_record(installed_db)
        dhcp_packages, _, _ = _dhcp_package_records(installed_db)
        dhcp_versions = {
            name: package.version for name, package in dhcp_packages.items()
        }
        _verify_package_policy(
            packages,
            {sshd_package.name: sshd_package.version, **dhcp_versions},
        )
        for name, version in _REQUIRED_PACKAGE_VERSIONS.items():
            allowed_current: tuple[str, ...] = ()
            if sealed and name == _KNOWN_GOOD_NAME:
                allowed_current = (
                    f"{_KNOWN_GOOD_NAME}><{_KNOWN_GOOD_WORLD_CHECKSUM}",
                )
            _pin_exact_world_package(
                rootfs / "etc/apk/world",
                name,
                version,
                allowed_current=allowed_current,
            )
        _pin_exact_world_package(
            rootfs / "etc/apk/world", sshd_package.name, sshd_package.version
        )
        _pin_exact_world_package(
            rootfs / "etc/apk/world",
            "unudhcpd-openrc",
            dhcp_versions["unudhcpd-openrc"],
        )
        _read_world(
            rootfs / "etc/apk/world",
            {
                sshd_package.name: sshd_package.version,
                "unudhcpd-openrc": dhcp_versions["unudhcpd-openrc"],
            },
        )

        invoke(
            "install",
            "--no-fde",
            "--sector-size",
            "4096",
            "--no-sparse",
            "--add",
            install_add,
            "--password",
            password,
        )
        packages = _parse_apk_database(installed_db)
        sshd_pam_attestation = _verify_sshd_pam(
            rootfs, installed_db, sshd_package.version
        )
        _verify_unudhcpd(rootfs, installed_db, dhcp_versions)
        if sealed:
            _verify_known_good_kernel_install(rootfs, installed_db)
            _pin_exact_world_package(
                rootfs / "etc/apk/world",
                _KNOWN_GOOD_NAME,
                _KNOWN_GOOD_VERSION,
                allowed_current=(
                    f"{_KNOWN_GOOD_NAME}><{_KNOWN_GOOD_WORLD_CHECKSUM}",
                ),
            )
        _verify_package_policy(
            packages,
            {sshd_package.name: sshd_package.version, **dhcp_versions},
        )
        world_text = _read_world(
            rootfs / "etc/apk/world",
            {
                sshd_package.name: sshd_package.version,
                "unudhcpd-openrc": dhcp_versions["unudhcpd-openrc"],
            },
        )
        if _all_key_hashes(pmb_work, rootfs) != keys_before:
            raise GateError("final install changed the pinned APK key inventory")
        boot_uuid, root_uuid = _parse_fstab(rootfs / "etc/fstab")

        packages_text = "\n".join(packages) + "\n"
        package_manifest_sha256 = hashlib.sha256(packages_text.encode("utf-8")).hexdigest()
        identity_text = _render_identity(
            payload / "lmi-release-identity",
            tag=ctx.tag,
            privilege_model=ctx.privilege_model,
            policy_id=ctx.policy_id,
            source_commit=ctx.source_commit,
            boot_uuid=boot_uuid,
            root_uuid=root_uuid,
            package_manifest_sha256=package_manifest_sha256,
        )
        identity_values = dict(
            line.split("=", 1) for line in identity_text.splitlines()
        )
        build_id = identity_values["candidate_id"]
        finalizer = _stage_finalizer(
            pmb_work,
            payload,
            public_key_text,
            actual_fingerprint,
            identity_text,
            world_text,
        )

        try:
            finalized = invoke(
                "chroot",
                "-r",
                "--image",
                "--",
                "/bin/sh",
                "/mnt/pmbootstrap/packages/lmi-p1-finalize/finalize.sh",
            )
            if "lmi-p1-finalize=ok" not in finalized.stdout.splitlines():
                raise GateError("image finalizer did not emit its success marker")
        finally:
            invoke("shutdown")
            clean_shutdown = True
        shutil.rmtree(finalizer)
        finalizer = None

        if next(export_dir.iterdir(), None) is not None:
            raise GateError("export directory was not empty before export")
        invoke("export", str(export_dir.absolute()), "--no-install")
        expected_pmbootstrap_blob = _git_output(
            pmbootstrap_repository,
            "rev-parse",
            f"{_EXPECTED_PMBOOTSTRAP_COMMIT}:pmbootstrap.py",
        ).strip()
        _validate_pmbootstrap_checkout(
            pmbootstrap_repository, pmbootstrap, expected_pmbootstrap_blob
        )

        materialized = _materialize_export(export_dir, candidate, selected_dtb)
        boot_img = materialized["boot.img"].absolute()
        userdata_img = materialized["xiaomi-lmi.img"].absolute()
        kernel_name = next(
            relative
            for relative in materialized
            if "/" not in relative and relative.startswith("vmlinuz")
        )
        initramfs_name = next(
            relative
            for relative in materialized
            if "/" not in relative
            and relative.startswith("initramfs")
            and "extra" not in relative
        )
        vmlinuz = materialized[kernel_name].absolute()
        initramfs = materialized[initramfs_name].absolute()
        dtb_dir = (export_dir / "dtbs").absolute()
        dtbs = sorted(
            path.absolute()
            for relative, path in materialized.items()
            if relative.startswith("dtbs/")
        )
        if len(dtbs) != 1:
            raise GateError(
                "P1 export must contain exactly one selected DTB, "
                f"got {len(dtbs)}"
            )

        rootfs_bindings = RootfsBindings(
            apk_installed=installed_db,
            sshd_config=rootfs / "etc/ssh/sshd_config",
            sshd_service=rootfs / "etc/init.d/sshd",
            sshd_pam=rootfs / "usr/sbin/sshd.pam",
            authorized_keys=rootfs / "home/lmi/.ssh/authorized_keys",
            release_identity=rootfs / "etc/lmi-release-identity",
            networkmanager_profile=rootfs
            / "etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
            networkmanager_takeover=rootfs
            / "etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
            unudhcpd=rootfs / "usr/bin/unudhcpd",
            unudhcpd_service=rootfs / "etc/init.d/unudhcpd",
            unudhcpd_config=rootfs / "etc/conf.d/unudhcpd.usb0",
            usb_dhcp_wrapper=rootfs / "usr/sbin/lmi-usb0-dhcp",
            usb_dhcp_service=rootfs / "etc/init.d/lmi-usb0-dhcp",
        )
        semantic_input_paths = {
            "boot_img": boot_img,
            "userdata_img": userdata_img,
            "vmlinuz": vmlinuz,
            "initramfs": initramfs,
            "dtb": dtbs[0],
            "deviceinfo": rootfs / "usr/share/deviceinfo/device-xiaomi-lmi",
            "staged_deviceinfo": isolated_pmaports
            / "device/downstream/device-xiaomi-lmi/deviceinfo",
            "staged_init_functions": isolated_pmaports
            / "main/postmarketos-initramfs/init_functions.sh",
            "staged_init_2nd": isolated_pmaports
            / "main/postmarketos-initramfs/init_2nd.sh",
            "fstab": rootfs / "etc/fstab",
            "rootfs_apk_installed": rootfs_bindings.apk_installed,
            "rootfs_sshd_config": rootfs_bindings.sshd_config,
            "rootfs_sshd_service": rootfs_bindings.sshd_service,
            "rootfs_sshd_pam": rootfs_bindings.sshd_pam,
            "rootfs_authorized_keys": rootfs_bindings.authorized_keys,
            "rootfs_release_identity": rootfs_bindings.release_identity,
            "rootfs_networkmanager_profile": rootfs_bindings.networkmanager_profile,
            "rootfs_networkmanager_takeover": rootfs_bindings.networkmanager_takeover,
            "rootfs_unudhcpd": rootfs_bindings.unudhcpd,
            "rootfs_unudhcpd_service": rootfs_bindings.unudhcpd_service,
            "rootfs_unudhcpd_config": rootfs_bindings.unudhcpd_config,
            "rootfs_usb_dhcp_wrapper": rootfs_bindings.usb_dhcp_wrapper,
            "rootfs_usb_dhcp_service": rootfs_bindings.usb_dhcp_service,
        }
        semantics_report = validate_artifact_pair(
            boot_img,
            userdata_img,
            vmlinuz,
            initramfs,
            dtbs[0],
            rootfs / "usr/share/deviceinfo/device-xiaomi-lmi",
            isolated_pmaports
            / "device/downstream/device-xiaomi-lmi/deviceinfo",
            isolated_pmaports / "main/postmarketos-initramfs/init_functions.sh",
            isolated_pmaports / "main/postmarketos-initramfs/init_2nd.sh",
            rootfs / "etc/fstab",
            rootfs_bindings=rootfs_bindings,
            limits=PartitionLimits(),
            expectations=ArtifactExpectations(
                initramfs_manifest=load_initramfs_manifest(
                    source_checkout / "config/lmi-p1/initramfs-manifest.json"
                )
            ),
            calibration=False,
        )
        try:
            if semantics_report["release"]["eligible"] is not True:
                raise GateError("artifact semantic report is not release eligible")
        except (KeyError, TypeError):
            raise GateError("artifact semantic report is not release eligible") from None
        recheck_input_identities(semantics_report["inputs"], semantic_input_paths)

        packages_path = (export_dir / "packages.txt").absolute()
        packages_path.write_text(packages_text, encoding="utf-8")
        world_path = (export_dir / "world").absolute()
        world_path.write_text(world_text, encoding="utf-8")
        sshd_pam_path = (export_dir / "sshd-pam.json").absolute()
        write_json(sshd_pam_path, sshd_pam_attestation)
        sshd_pam_path.chmod(0o644)
        semantics_path = (export_dir / "artifact-semantics.json").absolute()
        write_json(semantics_path, semantics_report)
        semantics_path.chmod(0o644)
        identity_path = (export_dir / "lmi-release-identity").absolute()
        identity_path.write_text(identity_text, encoding="utf-8")
        identity_path.chmod(0o644)
        materialized_outputs = sorted(
            set(materialized.values()), key=lambda path: path.relative_to(export_dir).as_posix()
        )
        for output in (
            *materialized_outputs,
            packages_path,
            world_path,
            sshd_pam_path,
            semantics_path,
            identity_path,
        ):
            relative = output.relative_to(export_dir).as_posix()
            log_records.append(f"sha256 {sha256_file(output)} {relative}")
        build_log = (export_dir / "build.log").absolute()
        _write_log(build_log, log_records)
        publication_outputs = (
            *materialized_outputs,
            packages_path,
            world_path,
            sshd_pam_path,
            semantics_path,
            identity_path,
            build_log,
        )
        manifest_path, manifest_sha256, artifact_set_id = _freeze_and_recheck_outputs(
            export_dir,
            publication_outputs,
            semantics_report,
            boot_img=boot_img,
            userdata_img=userdata_img,
            vmlinuz=vmlinuz,
            initramfs=initramfs,
            dtb=dtbs[0],
            build_id=build_id,
            privilege_model=ctx.privilege_model,
            policy_id=ctx.policy_id,
        )
        result = BuildResult(
            boot_img=boot_img,
            userdata_img=userdata_img,
            vmlinuz=vmlinuz,
            initramfs=initramfs,
            dtb_dir=dtb_dir,
            packages=packages_path,
            world=world_path,
            sshd_pam=sshd_pam_path,
            semantics=semantics_path,
            build_log=build_log,
            identity=identity_path,
            manifest=manifest_path,
            manifest_sha256=manifest_sha256,
            artifact_set_id=artifact_set_id,
        )
    except BaseException as error:
        pending_error = error
    finally:
        if pmb_started and not clean_shutdown:
            try:
                invoke("shutdown")
                clean_shutdown = True
            except BaseException as cleanup_error:
                log_records.append(
                    "cleanup_error=" + redact_log_value(str(cleanup_error))
                )
                if pending_error is None:
                    pending_error = cleanup_error
        if finalizer is not None and finalizer.exists():
            shutil.rmtree(finalizer)
        if pending_error is not None:
            _write_log(failure_log, log_records)

    if pending_error is not None:
        if isinstance(pending_error, GateError):
            raise pending_error
        raise GateError(
            "candidate build failed: "
            + redact_log_value(str(pending_error))
        ) from None
    if result is None:
        raise GateError("candidate build ended without a result")
    return result


def revalidate_sealed_build_result(
    result: BuildResult,
    *,
    expected_policy_id: str,
    active_path: Path,
    trusted_root: Path = Path("/"),
    expected_uid: int = 0,
    expected_gid: int = 0,
) -> BuildResult:
    """Return *result* only after the final production publication gates pass.

    The sealed CLI must call this after :func:`build_candidate` and immediately
    before serializing or returning paths.  ``active_path`` and ``trusted_root``
    are the same fixed launcher policy paths used to authorize the request.
    """

    if not isinstance(result, BuildResult):
        raise GateError("sealed build result has an invalid type")
    if _SHA256_RE.fullmatch(expected_policy_id) is None:
        raise GateError("sealed result policy id is invalid")

    def active_policy() -> str:
        try:
            return read_active_policy(
                active_path,
                trusted_root=trusted_root,
                expected_uid=expected_uid,
                expected_gid=expected_gid,
            )
        except GateError:
            raise GateError("could not revalidate the active production policy") from None

    if active_policy() != expected_policy_id:
        raise GateError("active production policy changed before result return")
    if (
        _SHA256_RE.fullmatch(result.manifest_sha256) is None
        or _SHA256_RE.fullmatch(result.artifact_set_id) is None
    ):
        raise GateError("sealed result manifest evidence is invalid")
    manifest_path = Path(result.manifest).absolute()
    manifest = _revalidate_artifact_manifest(
        manifest_path,
        expected_manifest_sha256=result.manifest_sha256,
        expected_artifact_set_id=result.artifact_set_id,
        require_frozen_directories=True,
    )
    if (
        manifest["policy_id"] != expected_policy_id
        or manifest["privilege_model"] != _PRIVILEGE_SEALED
    ):
        raise GateError("sealed result manifest policy binding mismatch")

    export = manifest_path.parent
    inventory = _export_file_inventory(export)
    inventory.pop("artifact-manifest.json", None)
    result_files = {
        Path(getattr(result, field)).absolute()
        for field in (
            "boot_img",
            "userdata_img",
            "vmlinuz",
            "initramfs",
            "packages",
            "world",
            "sshd_pam",
            "semantics",
            "build_log",
            "identity",
        )
    }
    if not result_files.issubset(set(inventory.values())):
        raise GateError("sealed result paths are not covered by its artifact manifest")
    dtb_dir = Path(result.dtb_dir).absolute()
    try:
        dtb_metadata = dtb_dir.lstat()
    except OSError:
        raise GateError("sealed result DTB directory is unavailable") from None
    if (
        dtb_dir.is_symlink()
        or not stat.S_ISDIR(dtb_metadata.st_mode)
        or stat.S_IMODE(dtb_metadata.st_mode) != 0o555
        or not _is_within(dtb_dir, export)
        or not any(_is_within(path, dtb_dir) for path in inventory.values())
    ):
        raise GateError("sealed result DTB directory binding mismatch")

    try:
        identity_text = Path(result.identity).read_text(encoding="utf-8")
        identity = dict(
            line.split("=", 1) for line in identity_text.splitlines()
        )
    except (OSError, UnicodeError, ValueError):
        raise GateError("sealed result identity is malformed") from None
    if (
        identity.get("candidate_id") != manifest["build_id"]
        or identity.get("policy_id") != expected_policy_id
        or identity.get("privilege_model") != _PRIVILEGE_SEALED
        or identity.get("artifact_classification") != _ARTIFACT_CLASSIFICATION
        or identity.get("release_eligible") != "false"
        or identity.get("publication") != _ARTIFACT_PUBLICATION
        or identity.get("credential_state") != _ARTIFACT_CREDENTIAL_STATE
    ):
        raise GateError("sealed result identity policy binding mismatch")

    _revalidate_artifact_manifest(
        manifest_path,
        expected_manifest_sha256=result.manifest_sha256,
        expected_artifact_set_id=result.artifact_set_id,
        require_frozen_directories=True,
    )
    if active_policy() != expected_policy_id:
        raise GateError("active production policy changed before result return")
    return result


def build_candidate(
    ctx: BuildContext,
    *,
    _sealed_authorization: _SealedBuildAuthorization | None = None,
) -> BuildResult:
    """Build with a restrictive process umask for every candidate-created member."""

    previous_umask = os.umask(0o077)
    environment_token = _PRIVATE_ENVIRONMENT_ROOT.set(
        Path(ctx.work).absolute() / ".runtime"
    )
    try:
        with _pmaports_private_environment():
            return _build_candidate(ctx, _sealed_authorization)
    finally:
        _PRIVATE_ENVIRONMENT_ROOT.reset(environment_token)
        os.umask(previous_umask)
