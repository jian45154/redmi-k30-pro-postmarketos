"""Isolated, fail-closed construction of the lmi P1 replay candidate."""

from __future__ import annotations

import base64
import binascii
import configparser
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
import tempfile
from typing import Mapping, Sequence

from .common import GateError, run, sha256_file, write_json
from .pmaports import (
    _compare_physical_trees,
    _reject_replace_refs,
    _reject_special_index_flags,
    _secure_checkout,
    prepare_pmaports,
)


_EXPECTED_PMBOOTSTRAP_VERSION = "3.11.1"
_EXPECTED_PMBOOTSTRAP_COMMIT = "ce76febabd983db6445fa9a8b75d601970b2f436"
_EXPECTED_PMAPORTS_COMMIT = "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
_COMMAND_TIMEOUT = 4 * 60 * 60
_GIT = "/usr/bin/git"
_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_PACKAGES = (
    "postmarketos-initramfs",
    "linux-xiaomi-lmi",
    "device-xiaomi-lmi",
)
_FIXED_ADD = (
    "evtest,pd-mapper,pd-mapper-openrc,seatd,seatd-openrc,"
    "weston-backend-drm,weston-clients,weston-shell-desktop,weston-terminal"
)
_REPLAY_APK_HASHES: Mapping[str, str] = {
    "device-xiaomi-lmi-1-r139.apk": (
        "ac00f22751607ae736cc26fbe72c1ede9c7d4d26f3af887ab0af800d5d9a3934"
    ),
    "linux-xiaomi-lmi-4.19.325-r9.apk": (
        "678a94cb0d309c69e56e697533ad7f6fe9e9cbfc7dea5a5109ca55b36ee72f50"
    ),
    "weston-14.0.2-r10.apk": (
        "d62a5b63fb1d4a35cec06dedf62c86d7da67b4d796ea7c973ea92035622bf2e7"
    ),
    "weston-backend-drm-14.0.2-r10.apk": (
        "53e95028082b3ddecb5460aa100557971b368451f1f51f0b92b9484a6b76bc1b"
    ),
    "weston-clients-14.0.2-r10.apk": (
        "1301346e110d7363a5fbe611f3ee282a3074ec2c52d884485ca961bb63835476"
    ),
    "weston-shell-desktop-14.0.2-r10.apk": (
        "b7bd061487f7ede3ebd102a3552d5596c87091146cf1d60a1a93c6ada847083e"
    ),
    "weston-terminal-14.0.2-r10.apk": (
        "868eadb0171214945a34cec73da00a6b78d4a4e3e115611545f56bdb25a3d877"
    ),
}
_REQUIRED_PACKAGE_VERSIONS = {
    "device-xiaomi-lmi": "1-r139",
    "linux-xiaomi-lmi": "4.19.325-r9",
    "weston": "14.0.2-r10",
    "weston-backend-drm": "14.0.2-r10",
    "weston-clients": "14.0.2-r10",
    "weston-shell-desktop": "14.0.2-r10",
    "weston-terminal": "14.0.2-r10",
}
_OLD_APKS = (
    "device-xiaomi-lmi-1-r107.apk",
    "linux-xiaomi-lmi-4.19.325-r8.apk",
)
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
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


@dataclass(frozen=True)
class BuildContext:
    repo: Path
    tag: str
    source_commit: str
    work: Path
    pmaports: Path
    d80: Path
    pmbootstrap: Path
    public_key: Path
    public_key_fingerprint: str


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
    build_log: Path
    identity: Path


@dataclass(frozen=True)
class _ApkPackageRecord:
    name: str
    version: str
    architecture: str | None
    files: tuple[tuple[str, str | None], ...]


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
    if os.path.lexists(path) and path.is_symlink():
        raise GateError(f"candidate work must not be a symlink: {path}")
    if path.exists():
        if not path.is_dir():
            raise GateError(f"candidate work is not a directory: {path}")
        try:
            if next(path.iterdir(), None) is not None:
                raise GateError(f"candidate work is not empty: {path}")
        except OSError as error:
            raise GateError(f"cannot inspect candidate work: {error}") from None
    else:
        path.mkdir(parents=True)
    return path.resolve(strict=True)


def _read_json(path: Path, label: str) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"could not read {label}: {error}") from None


def _git_environment() -> dict[str, str]:
    return {
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "SHELL": "/bin/sh",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": "/tmp",
        "TERM": "dumb",
        "PATH": _SYSTEM_PATH,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _pmbootstrap_environment() -> dict[str, str]:
    return _git_environment()


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


def _nul_paths(value: str) -> set[str]:
    if not value:
        return set()
    if not value.endswith("\0"):
        raise GateError("git path inventory was not NUL terminated")
    return set(value[:-1].split("\0"))


def _nul_name_status(value: str) -> set[tuple[str, str]]:
    if not value:
        return set()
    if not value.endswith("\0"):
        raise GateError("git status inventory was not NUL terminated")
    fields = value[:-1].split("\0")
    if len(fields) % 2:
        raise GateError("git status inventory had an invalid field count")
    return {(fields[index], fields[index + 1]) for index in range(0, len(fields), 2)}


def _validate_staged_pmaports_self(path: Path) -> dict[str, object]:
    _reject_replace_refs(path, "pmaports stage")
    _reject_special_index_flags(path, "pmaports stage")
    manifest_path = path / ".lmi-p1-stage.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise GateError("pmaports stage manifest must be a real file")
    stage = _read_json(manifest_path, "pmaports stage manifest")
    if not isinstance(stage, dict) or stage.get("commit") != _EXPECTED_PMAPORTS_COMMIT:
        raise GateError("pmaports stage commit mismatch")
    members = {relative: digest for relative, digest in stage.items() if relative != "commit"}
    if not members:
        raise GateError("pmaports stage manifest has no hashed members")
    for relative, expected_digest in members.items():
        if (
            not isinstance(relative, str)
            or not isinstance(expected_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", expected_digest) is None
            or relative.startswith("/")
            or "\\" in relative
            or "\0" in relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
        ):
            raise GateError("pmaports stage manifest contains an unsafe member")
        member = path.joinpath(*relative.split("/"))
        try:
            mode = member.lstat().st_mode
            if stat.S_ISLNK(mode):
                target = os.readlink(member).encode("utf-8", errors="surrogateescape")
                actual_digest = hashlib.sha256(target).hexdigest()
            elif stat.S_ISREG(mode):
                actual_digest = sha256_file(member)
            else:
                raise GateError(f"pmaports stage member is not a file: {relative}")
        except (OSError, UnicodeError) as error:
            raise GateError(f"could not hash pmaports stage member {relative}: {error}") from None
        if actual_digest != expected_digest:
            raise GateError(f"pmaports stage hash mismatch: {relative}")

    head = _git_output(path, "rev-parse", "--verify", "HEAD").strip()
    if head != _EXPECTED_PMAPORTS_COMMIT:
        raise GateError(
            "pmaports stage HEAD mismatch: "
            f"expected {_EXPECTED_PMAPORTS_COMMIT}, got {head}"
        )
    if _git_output(path, "diff", "--cached", "--name-status", "-z", "--no-renames"):
        raise GateError("pmaports stage index is not clean")

    tracked = _nul_paths(_git_output(path, "ls-files", "-z"))
    expected_tracked = {
        ("M", relative) for relative in members if relative in tracked
    }
    actual_tracked = _nul_name_status(
        _git_output(path, "diff", "--name-status", "-z", "--no-renames")
    )
    expected_untracked = {
        relative for relative in members if relative not in tracked
    } | {".lmi-p1-stage.json"}
    ordinary_untracked = _nul_paths(
        _git_output(path, "ls-files", "--others", "--exclude-standard", "-z")
    )
    ignored_untracked = _nul_paths(
        _git_output(
            path,
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "-z",
        )
    )
    actual_untracked = ordinary_untracked | ignored_untracked
    if actual_tracked != expected_tracked or actual_untracked != expected_untracked:
        raise GateError(
            "pmaports stage inventory mismatch: "
            f"tracked expected {sorted(expected_tracked)!r}, "
            f"got {sorted(actual_tracked)!r}; "
            f"untracked expected {sorted(expected_untracked)!r}, "
            f"got {sorted(actual_untracked)!r}"
        )
    _git_output(path, "diff", "--check")

    deviceinfo = path / "device/downstream/device-xiaomi-lmi/deviceinfo"
    try:
        text = deviceinfo.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read staged lmi deviceinfo: {error}") from None
    matches = re.findall(
        r'^deviceinfo_rootfs_image_sector_size=["\']?([^"\'\n]+)["\']?$',
        text,
        flags=re.MULTILINE,
    )
    if matches != ["4096"]:
        raise GateError("staged lmi deviceinfo does not pin rootfs sector size 4096")
    return stage


def _validate_staged_pmaports(path: Path, expected: Path) -> None:
    stage = _validate_staged_pmaports_self(path)
    expected_stage = _validate_staged_pmaports_self(expected)
    if stage != expected_stage:
        raise GateError("pmaports stage manifest does not match reconstructed inputs")
    _compare_physical_trees(path, expected, "pmaports stage")


def _pmaports_channel(path: Path) -> str:
    parser = configparser.ConfigParser()
    try:
        with (path / "pmaports.cfg").open(encoding="utf-8") as stream:
            parser.read_file(stream)
        channel = parser["pmaports"]["channel"]
    except (OSError, UnicodeError, KeyError, configparser.Error) as error:
        raise GateError(f"could not read pmaports channel: {error}") from None
    if re.fullmatch(r"[A-Za-z0-9._-]+", channel) is None:
        raise GateError(f"unsafe pmaports channel: {channel!r}")
    return channel


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
        env=_git_environment(),
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


def _public_key_fingerprint(path: Path) -> tuple[str, str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read SSH public key: {error}") from None
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


def _write_config(path: Path, public_key: Path) -> None:
    text = (
        "[pmbootstrap]\n"
        "device = xiaomi-lmi\n"
        "ui = shelli\n"
        "user = lmi\n"
        "hostname = lmi\n"
        "ssh_keys = True\n"
        f"ssh_key_glob = {public_key}\n"
        "service_manager = openrc\n"
        "extra_packages = none\n"
        "build_pkgs_on_install = False\n"
        "\n[providers]\n"
        "\n[mirrors]\n"
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
        scalar_fields: dict[str, list[str]] = {"P": [], "V": [], "A": []}
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
        if len(names) != 1 or len(versions) != 1:
            raise GateError("installed package database contains a malformed package record")
        name = names[0]
        version = versions[0]
        if name in packages:
            raise GateError(f"duplicate installed package database entry: {name}")
        if len(architectures) > 1:
            raise GateError(f"duplicate installed package architecture entry: {name}")
        file_paths = [str(file[0]) for file in files]
        if len(file_paths) != len(set(file_paths)):
            raise GateError(f"duplicate installed package file entry: {name}")
        packages[name] = _ApkPackageRecord(
            name=name,
            version=version,
            architecture=architectures[0] if architectures else None,
            files=tuple((str(file[0]), file[1]) for file in files),
        )
    if not packages:
        raise GateError("installed package database contains no package records")
    return tuple(packages[name] for name in sorted(packages))


def _parse_apk_database(path: Path) -> list[str]:
    return [f"{record.name}-{record.version}" for record in _parse_apk_records(path)]


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


def _apk_checksum(checksum: str) -> tuple[str, bytes]:
    algorithms = {
        "Q1": ("sha1", hashlib.sha1().digest_size),
        "Q2": ("sha256", hashlib.sha256().digest_size),
    }
    prefix = checksum[:2]
    if prefix not in algorithms or len(checksum) <= 2:
        raise GateError("sshd.pam has an unsupported APK database checksum")
    encoded = checksum[2:]
    encoded += "=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise GateError("sshd.pam has a malformed APK database checksum") from None
    algorithm, size = algorithms[prefix]
    if len(decoded) != size:
        raise GateError("sshd.pam has a malformed APK database checksum")
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


def _verify_aarch64_elf(descriptor: int, file_size: int) -> None:
    message = "sshd.pam is not a valid little-endian 64-bit AArch64 ELF"
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
    executable_load_segment = False
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
                or (
                    alignment > 1
                    and offset % alignment != virtual_address % alignment
                )
            ):
                raise GateError(message)
            if flags & 1:
                executable_load_segment = True
    if not load_segment or not executable_load_segment:
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


def _verify_package_policy(packages: Sequence[str]) -> None:
    actual = set(packages)
    expected = {
        f"{name}-{version}"
        for name, version in _REQUIRED_PACKAGE_VERSIONS.items()
    }
    missing = expected - actual
    forbidden = {
        "device-xiaomi-lmi-1-r107",
        "linux-xiaomi-lmi-4.19.325-r8",
    } & actual
    if missing or forbidden:
        raise GateError(
            "replay package policy mismatch: "
            f"missing {sorted(missing)!r}, forbidden {sorted(forbidden)!r}"
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
        raise GateError("apk world contains a replay file path")
    return lines


def _world_specs(lines: Sequence[str], name: str) -> list[str]:
    return [
        line
        for line in lines
        if line == name
        or line.startswith(name + "@")
        or any(line.startswith(name + operator) for operator in ("=", "<", ">", "~"))
    ]


def _pin_replay_world(path: Path) -> None:
    lines = _world_lines(path)
    retained = list(lines)
    for name, version in _REQUIRED_PACKAGE_VERSIONS.items():
        expected = f"{name}={version}"
        matches = _world_specs(lines, name)
        conflicting = [line for line in matches if line not in {name, expected}]
        if conflicting:
            raise GateError(
                f"conflicting replay world constraint for {name}: {conflicting!r}"
            )
        if len(matches) != 1:
            raise GateError(
                f"replay world must contain one normalizable entry for {name}: {matches!r}"
            )
        retained = [line for line in retained if line not in matches]
        retained.append(expected)
    try:
        path.write_text("\n".join(sorted(retained)) + "\n", encoding="utf-8")
    except OSError as error:
        raise GateError(f"could not pin apk world: {error}") from None


def _pin_exact_world_package(path: Path, name: str, version: str) -> None:
    lines = _world_lines(path)
    expected = f"{name}={version}"
    matches = _world_specs(lines, name)
    conflicting = [line for line in matches if line not in {name, expected}]
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
                f"replay world constraint mismatch for {name}: "
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
    source_commit: str,
    boot_uuid: str,
    root_uuid: str,
    package_manifest_sha256: str,
) -> str:
    digest = hashlib.sha256()
    digest.update(
        b"\0".join(
            value.encode("utf-8")
            for value in (
                tag,
                source_commit,
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
        tag, source_commit, boot_uuid, root_uuid, package_manifest_sha256
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
            source_commit=source_commit,
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
        "tag",
        "source_commit",
        "candidate_id",
        "boot_uuid",
        "root_uuid",
        "package_manifest_sha256",
        "device_xiaomi_lmi",
        "linux_xiaomi_lmi",
        "weston",
        "weston_backend_drm",
        "weston_clients",
        "weston_shell_desktop",
        "weston_terminal",
        "build_utc",
    }:
        raise GateError("release identity template field set mismatch")
    return rendered


def _finalizer_script() -> str:
    return """#!/bin/sh
set -eu

stage=/mnt/pmbootstrap/packages/lmi-p1-finalize

/bin/mkdir -p /etc/ssh /usr/sbin /etc/sudoers.d /etc/doas.d /etc/apk \
	/etc/NetworkManager/conf.d /etc/NetworkManager/system-connections /home/lmi/.ssh
/bin/cp "$stage/sshd_config" /etc/ssh/sshd_config
/bin/cp "$stage/lmi-rootctl" /usr/sbin/lmi-rootctl
/bin/cp "$stage/lmi-release-identity" /etc/lmi-release-identity
/bin/cp "$stage/world" /etc/apk/world
/bin/cp "$stage/lmi-usb0.nmconnection" \
	/etc/NetworkManager/system-connections/lmi-usb0.nmconnection
/bin/cp "$stage/90-lmi-usb0-takeover.conf" \
	/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf
/bin/cp "$stage/authorized_keys" /home/lmi/.ssh/authorized_keys
/bin/chown root:root /etc/ssh/sshd_config
/bin/chown root:root /usr/sbin/lmi-rootctl
/bin/chown root:root /etc/lmi-release-identity
/bin/chown root:root /etc/apk/world
/bin/chown root:root \
	/etc/NetworkManager/system-connections/lmi-usb0.nmconnection
/bin/chown root:root /etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf
/bin/chmod 0600 /etc/ssh/sshd_config
/bin/chmod 0755 /usr/sbin/lmi-rootctl
/bin/chmod 0644 /etc/lmi-release-identity
/bin/chmod 0644 /etc/apk/world
/bin/chmod 0600 /etc/NetworkManager/system-connections/lmi-usb0.nmconnection
/bin/chmod 0644 /etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf
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
[ -L /etc/runlevels/default/sshd ] || exit 46
[ -L /etc/runlevels/default/networkmanager ] || exit 47

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


def _export_link_target(
    path: Path,
    expected_target: Path,
    candidate: Path,
    *,
    required: bool,
) -> Path | None:
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
    if not os.path.lexists(raw_target) and required:
        raise GateError(f"dangling export target: {path}")
    if raw_target != expected_target:
        raise GateError(
            f"export target mismatch: {path.name} -> {raw_target}, "
            f"expected {expected_target}"
        )
    if not os.path.lexists(expected_target):
        if required:
            raise GateError(f"dangling export target: {path}")
        return None
    if expected_target.is_symlink() or not expected_target.is_file():
        raise GateError(f"export target is not a real file: {path} -> {expected_target}")
    try:
        target = path.resolve(strict=True)
    except (OSError, RuntimeError):
        raise GateError(f"dangling export target: {path}") from None
    if not _is_within(target, candidate):
        raise GateError(f"export target escapes candidate: {path} -> {target}")
    if target != expected_target or target.is_symlink() or not target.is_file():
        raise GateError(f"export target is not a real file: {path} -> {target}")
    return target


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
) -> tuple[dict[str, tuple[Path, Path]], list[Path]]:
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

    result: dict[str, tuple[Path, Path]] = {}
    dangling_optional: list[Path] = []
    for name, (scope, target_relative) in _STANDARD_EXPORT_TARGETS.items():
        link = entries[name]
        target = _export_link_target(
            link,
            _expected_export_target(candidate, scope, target_relative),
            candidate,
            required=name in _REQUIRED_STANDARD_EXPORTS,
        )
        if target is None:
            dangling_optional.append(link)
        else:
            result[name] = (link, target)
    rootfs_boot = (candidate / "work/chroot_rootfs_xiaomi-lmi/boot").absolute()
    for name in dynamic:
        link = entries[name]
        target = _export_link_target(
            link,
            rootfs_boot / name,
            candidate,
            required=True,
        )
        if target is None:
            raise GateError(f"required dynamic export is dangling: {link}")
        result[name] = (link, target)
    dtb_target = _export_link_target(
        dtb_link,
        (candidate / "work/chroot_rootfs_xiaomi-lmi/boot/dtbs" / selected_dtb).absolute(),
        candidate,
        required=True,
    )
    if dtb_target is None:
        raise GateError(f"required selected DTB export is dangling: {dtb_link}")
    result[dtb_link.relative_to(export).as_posix()] = (dtb_link, dtb_target)
    return result, dangling_optional


def _materialize_export_link(link: Path, target: Path) -> None:
    temporary_name: str | None = None
    try:
        with target.open("rb") as source, tempfile.NamedTemporaryFile(
            mode="wb",
            dir=link.parent,
            prefix=f".{link.name}.",
            suffix=".materializing",
            delete=False,
        ) as destination:
            temporary_name = destination.name
            shutil.copyfileobj(source, destination, length=1024 * 1024)
            destination.flush()
            os.fsync(destination.fileno())
        temporary = Path(temporary_name)
        temporary.chmod(0o644)
        os.replace(temporary, link)
        temporary_name = None
    except OSError as error:
        raise GateError(f"could not materialize export {link}: {error}") from None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def _materialize_export(
    export: Path, candidate: Path, selected_dtb: Path
) -> dict[str, Path]:
    _stage_selected_dtb(export, candidate, selected_dtb)
    approved, dangling_optional = _validate_export_links(
        export, candidate, selected_dtb
    )
    for link in dangling_optional:
        try:
            link.unlink()
        except OSError as error:
            raise GateError(f"could not remove dangling optional export {link}: {error}") from None
    for link, target in approved.values():
        _materialize_export_link(link, target)
    result = {relative: link for relative, (link, _target) in approved.items()}
    for relative, output in result.items():
        try:
            mode = output.lstat().st_mode
            links = output.stat().st_nlink
        except OSError as error:
            raise GateError(f"could not verify materialized export {relative}: {error}") from None
        if not stat.S_ISREG(mode) or output.is_symlink() or links != 1:
            raise GateError(f"materialized export is not one regular inode: {relative}")
    return result


def build_candidate(ctx: BuildContext) -> BuildResult:
    """Build one isolated P1 candidate without phone, network-policy, or flash actions."""

    if _TAG_RE.fullmatch(ctx.tag) is None:
        raise GateError(f"invalid candidate tag: {ctx.tag!r}")
    if _COMMIT_RE.fullmatch(ctx.source_commit) is None:
        raise GateError("source commit must be a lowercase 40-character Git object ID")

    repo = _real_directory(Path(ctx.repo), "repository")
    source_pmaports = _real_directory(Path(ctx.pmaports), "staged pmaports")
    d80 = _real_directory(Path(ctx.d80), "verified D80 directory")
    public_key = _real_file(Path(ctx.public_key), "SSH public key")
    pmbootstrap_source = _real_file(
        Path(ctx.pmbootstrap), "pmbootstrap executable", executable=True
    )

    work_requested = Path(ctx.work).absolute()
    unresolved_inputs = (source_pmaports, d80, public_key, pmbootstrap_source)
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
    pmb_work.mkdir()
    export_dir.mkdir()
    _secure_checkout(
        repo,
        source_checkout,
        ctx.source_commit,
        "source checkout",
        require_clean_source=False,
        reject_source_index_flags=False,
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
    selected_dtb = _deviceinfo_dtb(isolated_pmaports)
    pmbootstrap_repository, pmbootstrap = _prepare_pmbootstrap(
        pmbootstrap_source, candidate
    )

    payload = source_checkout / "files/lmi-p1"
    if payload.is_symlink() or not payload.is_dir():
        raise GateError(f"missing real lmi P1 payload directory: {payload}")
    actual_fingerprint, public_key_text = _public_key_fingerprint(public_key)
    if actual_fingerprint != ctx.public_key_fingerprint:
        raise GateError(
            "SSH public key fingerprint mismatch: "
            f"expected {ctx.public_key_fingerprint}, got {actual_fingerprint}"
        )

    config_path = config_dir / "pmbootstrap.cfg"
    _write_config(config_path, public_key)
    failure_log = config_dir / "build.log"
    log_records: list[str] = [
        f"tag={ctx.tag}",
        f"source_commit={ctx.source_commit}",
        f"pmbootstrap_source={pmbootstrap_source}",
        f"pmbootstrap={pmbootstrap}",
        f"pmaports={isolated_pmaports}",
    ]
    pmbootstrap_environment = _pmbootstrap_environment()
    password = secrets.token_urlsafe(32)
    pmb_started = False
    clean_shutdown = False
    finalizer: Path | None = None
    result: BuildResult | None = None
    pending_error: BaseException | None = None

    def invoke(*arguments: str, check: bool = True):
        nonlocal pmb_started
        command = [
            sys.executable,
            "-E",
            "-B",
            str(pmbootstrap),
            "--as-root",
            "-c",
            str(config_path.absolute()),
            "-w",
            str(pmb_work.absolute()),
            "-p",
            str(isolated_pmaports.absolute()),
            *arguments,
        ]
        pmb_started = True
        log_records.append("argv=" + _redact_password(repr(command), password))
        try:
            completed = run(
                command,
                timeout=_COMMAND_TIMEOUT,
                check=False,
                env=pmbootstrap_environment,
            )
        except GateError as error:
            redacted = _redact_password(str(error), password)
            log_records.append("gate_error=" + redacted)
            raise GateError(redacted) from None
        log_records.append(f"returncode={completed.returncode}")
        if completed.stdout:
            log_records.append("stdout=" + _redact_password(completed.stdout, password).rstrip())
        if completed.stderr:
            log_records.append("stderr=" + _redact_password(completed.stderr, password).rstrip())
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
        invoke("build", *_PACKAGES)
        invoke(
            "install",
            "--no-image",
            "--no-fde",
            "--add",
            _FIXED_ADD,
            "--password",
            password,
        )

        channel = _pmaports_channel(isolated_pmaports)
        normal_repository = pmb_work / "packages" / channel / "aarch64"
        if normal_repository.is_symlink() or not normal_repository.is_dir():
            raise GateError(f"missing normal local aarch64 repository: {normal_repository}")
        quarantine = pmb_work / "packages/bootstrap-quarantine"
        quarantine.mkdir(parents=True)
        for name in _OLD_APKS:
            source = normal_repository / name
            if source.is_symlink() or not source.is_file():
                raise GateError(f"missing exact bootstrap APK to quarantine: {source}")
            os.replace(source, quarantine / name)
        invoke("index")

        replay_host = pmb_work / "packages/replay/aarch64"
        replay_host.mkdir(parents=True)
        replay_chroot_paths: list[str] = []
        for name, expected_hash in _REPLAY_APK_HASHES.items():
            source = d80 / name
            if source.is_symlink() or not source.is_file():
                raise GateError(f"missing real D80 replay APK: {source}")
            if sha256_file(source) != expected_hash:
                raise GateError(f"D80 replay APK hash mismatch before copy: {name}")
            destination = replay_host / name
            shutil.copyfile(source, destination)
            destination.chmod(0o644)
            if sha256_file(destination) != expected_hash:
                raise GateError(f"D80 replay APK hash mismatch after copy: {name}")
            replay_chroot_paths.append(
                f"/mnt/pmbootstrap/packages/replay/aarch64/{name}"
            )

        rootfs = pmb_work / "chroot_rootfs_xiaomi-lmi"
        installed_db = rootfs / "lib/apk/db/installed"
        if installed_db.is_symlink() or not installed_db.is_file():
            raise GateError("missing rootfs installed package database")
        database_before = sha256_file(installed_db)
        keys_before = _all_key_hashes(pmb_work, rootfs)
        unsigned = invoke(
            "chroot",
            "-r",
            "--output",
            "stdout",
            "--",
            "apk",
            "--no-network",
            "add",
            *replay_chroot_paths,
            check=False,
        )
        combined = (unsigned.stdout + "\n" + unsigned.stderr).lower()
        if unsigned.returncode == 0:
            raise GateError("unsigned replay probe unexpectedly succeeded")
        if "untrusted" not in combined or "signature" not in combined:
            raise GateError("unsigned replay probe did not identify an untrusted signature")
        if sha256_file(installed_db) != database_before:
            raise GateError("rejected replay probe changed installed package database")
        if _all_key_hashes(pmb_work, rootfs) != keys_before:
            raise GateError("rejected replay probe changed APK keys")

        invoke(
            "chroot",
            "-r",
            "--output",
            "stdout",
            "--",
            "apk",
            "--no-network",
            "--allow-untrusted",
            "add",
            *replay_chroot_paths,
        )
        if _all_key_hashes(pmb_work, rootfs) != keys_before:
            raise GateError("replay introduced an APK signing key")
        packages = _parse_apk_database(installed_db)
        _verify_package_policy(packages)
        sshd_package, _ = _sshd_pam_package_record(installed_db)
        _pin_replay_world(rootfs / "etc/apk/world")
        _pin_exact_world_package(
            rootfs / "etc/apk/world", sshd_package.name, sshd_package.version
        )
        _read_world(
            rootfs / "etc/apk/world",
            {sshd_package.name: sshd_package.version},
        )

        invoke(
            "install",
            "--no-fde",
            "--sector-size",
            "4096",
            "--no-sparse",
            "--password",
            password,
        )
        packages = _parse_apk_database(installed_db)
        _verify_package_policy(packages)
        sshd_pam_attestation = _verify_sshd_pam(
            rootfs, installed_db, sshd_package.version
        )
        world_text = _read_world(
            rootfs / "etc/apk/world",
            {sshd_package.name: sshd_package.version},
        )
        if _all_key_hashes(pmb_work, rootfs) != keys_before:
            raise GateError("final install changed the pinned APK key inventory")
        boot_uuid, root_uuid = _parse_fstab(rootfs / "etc/fstab")

        packages_text = "\n".join(packages) + "\n"
        package_manifest_sha256 = hashlib.sha256(packages_text.encode("utf-8")).hexdigest()
        identity_text = _render_identity(
            payload / "lmi-release-identity",
            tag=ctx.tag,
            source_commit=ctx.source_commit,
            boot_uuid=boot_uuid,
            root_uuid=root_uuid,
            package_manifest_sha256=package_manifest_sha256,
        )
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

        packages_path = (export_dir / "packages.txt").absolute()
        packages_path.write_text(packages_text, encoding="utf-8")
        world_path = (export_dir / "world").absolute()
        world_path.write_text(world_text, encoding="utf-8")
        sshd_pam_path = (export_dir / "sshd-pam.json").absolute()
        write_json(sshd_pam_path, sshd_pam_attestation)
        sshd_pam_path.chmod(0o644)
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
            identity_path,
        ):
            relative = output.relative_to(export_dir).as_posix()
            log_records.append(f"sha256 {sha256_file(output)} {relative}")
        build_log = (export_dir / "build.log").absolute()
        _write_log(build_log, log_records)
        result = BuildResult(
            boot_img=boot_img,
            userdata_img=userdata_img,
            vmlinuz=vmlinuz,
            initramfs=initramfs,
            dtb_dir=dtb_dir,
            packages=packages_path,
            world=world_path,
            sshd_pam=sshd_pam_path,
            build_log=build_log,
            identity=identity_path,
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
                    "cleanup_error=" + _redact_password(str(cleanup_error), password)
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
            + _redact_password(str(pending_error), password)
        ) from None
    if result is None:
        raise GateError("candidate build ended without a result")
    return result
