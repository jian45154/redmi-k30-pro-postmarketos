"""Isolated, fail-closed construction of the lmi P1 replay candidate."""

from __future__ import annotations

import base64
import configparser
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
from typing import Mapping, Sequence

from .common import GateError, run, sha256_file


_EXPECTED_PMBOOTSTRAP_VERSION = "3.11.1"
_EXPECTED_PMBOOTSTRAP_COMMIT = "ce76febabd983db6445fa9a8b75d601970b2f436"
_EXPECTED_PMAPORTS_COMMIT = "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
_COMMAND_TIMEOUT = 4 * 60 * 60
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
    build_log: Path
    identity: Path


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


def _validate_staged_pmaports(path: Path) -> None:
    stage = _read_json(path / ".lmi-p1-stage.json", "pmaports stage manifest")
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


def _copy_pmaports(source: Path, destination: Path) -> None:
    try:
        shutil.copytree(source, destination, symlinks=True)
    except OSError as error:
        raise GateError(f"could not copy staged pmaports: {error}") from None


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


def _parse_apk_database(path: Path) -> list[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read installed package database: {error}") from None
    packages: dict[str, str] = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) >= 3 and line[1] == ":":
                fields.setdefault(line[0], line[2:])
        name = fields.get("P")
        version = fields.get("V")
        if name is None or version is None:
            continue
        if name in packages:
            raise GateError(f"duplicate installed package database entry: {name}")
        packages[name] = version
    if not packages:
        raise GateError("installed package database contains no package records")
    return [f"{name}-{packages[name]}" for name in sorted(packages)]


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


def _read_world(path: Path) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise GateError(f"could not read apk world: {error}") from None
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) != len(set(lines)):
        raise GateError("apk world contains duplicate entries")
    required = set(_REQUIRED_PACKAGE_VERSIONS)
    if not required.issubset(lines):
        raise GateError(f"apk world is missing replay packages: {sorted(required - set(lines))!r}")
    if any(line.startswith("/") or line.endswith(".apk") for line in lines):
        raise GateError("apk world contains a replay file path")
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

/bin/mkdir -p /etc/ssh /usr/sbin /etc/sudoers.d /home/lmi/.ssh
/bin/cp "$stage/sshd_config" /etc/ssh/sshd_config
/bin/cp "$stage/lmi-rootctl" /usr/sbin/lmi-rootctl
/bin/cp "$stage/90-lmi-rootctl" /etc/sudoers.d/90-lmi-rootctl
/bin/cp "$stage/lmi-release-identity" /etc/lmi-release-identity
/bin/cp "$stage/authorized_keys" /home/lmi/.ssh/authorized_keys
/bin/chmod 0600 /etc/ssh/sshd_config
/bin/chmod 0755 /usr/sbin/lmi-rootctl
/bin/chmod 0440 /etc/sudoers.d/90-lmi-rootctl
/bin/chmod 0644 /etc/lmi-release-identity
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

/bin/rm -f /etc/sudoers.d/*
/bin/cp "$stage/90-lmi-rootctl" /etc/sudoers.d/90-lmi-rootctl
/bin/chown root:root /etc/sudoers.d/90-lmi-rootctl
/bin/chmod 0440 /etc/sudoers.d/90-lmi-rootctl
/usr/bin/cmp -s "$stage/90-lmi-rootctl" /etc/sudoers.d/90-lmi-rootctl || exit 38
if /bin/grep -Eq '(^|[[:space:]])NOPASSWD:' /etc/sudoers; then
	exit 39
fi

/sbin/rc-update add sshd default
/sbin/rc-update add networkmanager default
[ -L /etc/runlevels/default/sshd ] || exit 40
[ -L /etc/runlevels/default/networkmanager ] || exit 41

/bin/echo 'lmi-p1-finalize=ok'
"""


def _stage_finalizer(
    root: Path,
    payload: Path,
    public_key_text: str,
    fingerprint: str,
    identity: str,
) -> Path:
    destination = root / "packages/lmi-p1-finalize"
    if destination.exists() or destination.is_symlink():
        raise GateError(f"finalizer staging path already exists: {destination}")
    destination.mkdir(parents=True)
    modes = {
        "sshd_config": 0o600,
        "lmi-rootctl": 0o755,
        "90-lmi-rootctl": 0o440,
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
    (destination / "finalize.sh").write_text(_finalizer_script(), encoding="utf-8")
    (destination / "finalize.sh").chmod(0o755)
    return destination


def _unique_export_file(export: Path, pattern: str, label: str) -> Path:
    matches = sorted(path for path in export.glob(pattern) if path.is_file())
    if len(matches) != 1:
        raise GateError(f"expected one exported {label}, got {[path.name for path in matches]!r}")
    return matches[0].absolute()


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
    pmbootstrap = _real_file(Path(ctx.pmbootstrap), "pmbootstrap executable", executable=True)
    _validate_staged_pmaports(source_pmaports)

    head = run(
        ["git", "-C", str(repo), "rev-parse", "--verify", "HEAD"],
        timeout=60,
    ).stdout.strip()
    if head != ctx.source_commit:
        raise GateError(
            f"repository HEAD mismatch: expected {ctx.source_commit}, got {head}"
        )
    repository_status = run(
        [
            "git",
            "-C",
            str(repo),
            "status",
            "--porcelain",
            "--untracked-files=all",
        ],
        timeout=60,
    ).stdout.strip()
    if repository_status:
        raise GateError("repository is dirty; commit the exact build inputs first")

    work_requested = Path(ctx.work).absolute()
    unresolved_inputs = (source_pmaports, d80, public_key, pmbootstrap)
    unresolved_work = work_requested.resolve(strict=False)
    for input_path in unresolved_inputs:
        if _overlaps(unresolved_work, input_path):
            raise GateError(f"candidate work overlaps an input path: {input_path}")
    candidate = _prepare_empty_root(work_requested)

    config_dir = candidate / "config"
    pmb_work = candidate / "work"
    isolated_pmaports = candidate / "pmaports"
    export_dir = candidate / "export"
    config_dir.mkdir()
    pmb_work.mkdir()
    export_dir.mkdir()
    _copy_pmaports(source_pmaports, isolated_pmaports)

    payload = repo / "files/lmi-p1"
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
        f"pmbootstrap={pmbootstrap}",
        f"pmaports={isolated_pmaports}",
    ]
    password = secrets.token_urlsafe(32)
    pmb_started = False
    clean_shutdown = False
    finalizer: Path | None = None
    result: BuildResult | None = None
    pending_error: BaseException | None = None

    def invoke(*arguments: str, check: bool = True):
        nonlocal pmb_started
        command = [
            str(pmbootstrap),
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
            completed = run(command, timeout=_COMMAND_TIMEOUT, check=False)
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
        pmb_repository = run(
            ["git", "-C", str(pmbootstrap.parent), "rev-parse", "--show-toplevel"],
            timeout=60,
        ).stdout.strip()
        pmb_commit = run(
            ["git", "-C", pmb_repository, "rev-parse", "--verify", "HEAD"],
            timeout=60,
        ).stdout.strip()
        if pmb_commit != _EXPECTED_PMBOOTSTRAP_COMMIT:
            raise GateError(
                "pmbootstrap commit mismatch: "
                f"expected {_EXPECTED_PMBOOTSTRAP_COMMIT}, got {pmb_commit}"
            )
        pmb_status = run(
            [
                "git",
                "-C",
                pmb_repository,
                "status",
                "--porcelain",
                "--untracked-files=all",
            ],
            timeout=60,
        ).stdout.strip()
        if pmb_status:
            raise GateError("pmbootstrap repository is dirty; use the exact pinned checkout")
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
        _read_world(rootfs / "etc/apk/world")

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
        world_text = _read_world(rootfs / "etc/apk/world")
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
            pmb_work, payload, public_key_text, actual_fingerprint, identity_text
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

        boot_img = _unique_export_file(export_dir, "boot.img", "boot image")
        userdata_img = _unique_export_file(
            export_dir, "xiaomi-lmi.img", "combined userdata image"
        )
        vmlinuz = _unique_export_file(export_dir, "vmlinuz*", "kernel")
        initramfs_matches = [
            path
            for path in sorted(export_dir.glob("initramfs*"))
            if path.is_file() and "extra" not in path.name
        ]
        if len(initramfs_matches) != 1:
            raise GateError(
                "expected one exported initramfs, got "
                f"{[path.name for path in initramfs_matches]!r}"
            )
        initramfs = initramfs_matches[0].absolute()
        dtb_dir = (export_dir / "dtbs").absolute()
        if dtb_dir.is_symlink() or not dtb_dir.is_dir():
            raise GateError("missing real exported DTB directory")
        dtbs = sorted(path for path in dtb_dir.rglob("*") if path.is_file())
        if not dtbs:
            raise GateError("exported DTB directory is empty")

        packages_path = (export_dir / "packages.txt").absolute()
        packages_path.write_text(packages_text, encoding="utf-8")
        world_path = (export_dir / "world").absolute()
        world_path.write_text(world_text, encoding="utf-8")
        identity_path = (export_dir / "lmi-release-identity").absolute()
        identity_path.write_text(identity_text, encoding="utf-8")
        identity_path.chmod(0o644)
        for output in (boot_img, userdata_img, vmlinuz, initramfs, *dtbs):
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
