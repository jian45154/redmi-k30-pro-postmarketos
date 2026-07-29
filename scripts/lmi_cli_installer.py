#!/usr/bin/env python3
"""Portable verification-only Linux/WSL2 preview for Xiaomi lmi bundles."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import time
from typing import Any


VERSION = "0.1.0-alpha.1"
SCHEMA = "lmi-cli-installer/v1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
SPARSE_HEADER = struct.Struct("<I4H4I")
SPARSE_CHUNK = struct.Struct("<2H2I")
SPARSE_MAGIC = 0xED26FF3A
SPARSE_TYPES = {0xCAC1, 0xCAC2, 0xCAC3, 0xCAC4}
HASH_BLOCK_SIZE = 4 * 1024 * 1024
DEFAULT_QUERY_TIMEOUT = 10
DEFAULT_PROFILE = Path(__file__).resolve().parent / "installer-profile.json"
READ_ONLY_GETVARS = {
    "battery-voltage",
    "is-userspace",
    "partition-size:boot",
    "partition-size:userdata",
    "product",
    "unlocked",
}


class InstallerError(RuntimeError):
    """The installer rejected an input, device state, or command."""


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise InstallerError(f"duplicate JSON field: {key}")
        value[key] = item
    return value


def _exact_keys(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise InstallerError(f"{label} fields mismatch")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InstallerError(f"{label} must be a nonempty string")
    return value


def _positive_integer(value: Any, label: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise InstallerError(f"{label} must be an integer >= {minimum}")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(HASH_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative_path(value: Any, label: str) -> PurePosixPath:
    raw = _string(value, label)
    if "\\" in raw or "\0" in raw:
        raise InstallerError(f"{label} is not a canonical relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise InstallerError(f"{label} is not a canonical relative path")
    if path.as_posix() != raw:
        raise InstallerError(f"{label} is not canonical")
    return path


@dataclass(frozen=True)
class Artifact:
    name: str
    path: Path
    sha256: str
    size: int
    kind: str
    logical_size: int | None = None


@dataclass(frozen=True)
class Profile:
    path: Path
    root: Path
    release_id: str
    channel: str
    source_commit: str
    release_eligible: bool
    product: str
    minimum_battery_mv: int
    require_unlocked: bool
    require_userspace: bool
    sparse_limit: str
    artifacts: dict[str, Artifact]
    profile_sha256: str


@dataclass(frozen=True)
class Device:
    serial: str
    product: str
    unlocked: str
    userspace: str
    battery_mv: int
    boot_size: int
    userdata_size: int

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.serial.encode("utf-8")).hexdigest()[:12]


def _artifact(root: Path, name: str, value: Any) -> Artifact:
    record = _exact_keys(
        value,
        {"kind", "logical_size", "path", "sha256", "size"},
        f"artifacts.{name}",
    )
    relative = _relative_path(record["path"], f"artifacts.{name}.path")
    digest = _string(record["sha256"], f"artifacts.{name}.sha256")
    if SHA256_RE.fullmatch(digest) is None:
        raise InstallerError(f"artifacts.{name}.sha256 is invalid")
    size = _positive_integer(record["size"], f"artifacts.{name}.size")
    logical_raw = record["logical_size"]
    logical_size = None
    if logical_raw is not None:
        logical_size = _positive_integer(
            logical_raw, f"artifacts.{name}.logical_size"
        )
    kind = _string(record["kind"], f"artifacts.{name}.kind")
    allowed_kinds = {
        "boot": "android-boot",
        "rootfs": "android-sparse",
        "build_manifest": "text",
        "recovery_guide": "text",
    }
    if kind != allowed_kinds[name]:
        raise InstallerError(f"artifacts.{name}.kind must be {allowed_kinds[name]}")
    return Artifact(name, root.joinpath(*relative.parts), digest, size, kind, logical_size)


def load_profile(path: Path) -> Profile:
    try:
        resolved = path.resolve(strict=True)
        payload = resolved.read_bytes()
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_duplicates)
    except InstallerError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise InstallerError(f"cannot load installer profile: {error}") from None
    top = _exact_keys(value, {"artifacts", "device", "execution", "release", "schema"}, "profile")
    if top["schema"] != SCHEMA:
        raise InstallerError("unsupported installer profile schema")

    release = _exact_keys(
        top["release"],
        {"channel", "id", "release_eligible", "source_commit"},
        "release",
    )
    release_id = _string(release["id"], "release.id")
    if ID_RE.fullmatch(release_id) is None:
        raise InstallerError("release.id is invalid")
    channel = _string(release["channel"], "release.channel")
    if channel not in {"experimental", "beta", "stable"}:
        raise InstallerError("release.channel is invalid")
    source_commit = _string(release["source_commit"], "release.source_commit")
    if re.fullmatch(r"[0-9a-f]{40}", source_commit) is None:
        raise InstallerError("release.source_commit must be a full Git commit")
    if release["release_eligible"] is not False:
        raise InstallerError(
            "this verification-only preview requires release.release_eligible=false"
        )

    device = _exact_keys(
        top["device"],
        {"minimum_battery_mv", "product", "require_unlocked", "require_userspace"},
        "device",
    )
    product = _string(device["product"], "device.product")
    if product != "lmi":
        raise InstallerError("this installer build only permits product lmi")
    for field in ("require_unlocked", "require_userspace"):
        if device[field] is not True:
            raise InstallerError(f"device.{field} must be true")
    minimum_battery_mv = _positive_integer(
        device["minimum_battery_mv"], "device.minimum_battery_mv", allow_zero=True
    )

    execution = _exact_keys(
        top["execution"],
        {"allowed_partitions", "automatic_retry", "fastboot_sparse_limit", "steps"},
        "execution",
    )
    if execution["allowed_partitions"] != ["userdata", "boot"]:
        raise InstallerError("execution.allowed_partitions must be ['userdata', 'boot']")
    if execution["steps"] != ["userdata", "boot", "reboot"]:
        raise InstallerError("execution.steps must be ['userdata', 'boot', 'reboot']")
    if execution["automatic_retry"] is not False:
        raise InstallerError("execution.automatic_retry must be false")
    sparse_limit = _string(execution["fastboot_sparse_limit"], "execution.fastboot_sparse_limit")
    if re.fullmatch(r"[1-9][0-9]{0,3}M", sparse_limit) is None:
        raise InstallerError("execution.fastboot_sparse_limit is invalid")

    root = resolved.parent
    artifacts_value = _exact_keys(
        top["artifacts"],
        {"boot", "build_manifest", "recovery_guide", "rootfs"},
        "artifacts",
    )
    artifacts = {
        name: _artifact(root, name, artifacts_value[name])
        for name in ("boot", "rootfs", "build_manifest", "recovery_guide")
    }
    if artifacts["boot"].logical_size is not None:
        raise InstallerError("boot logical_size must be null")
    if artifacts["rootfs"].logical_size is None:
        raise InstallerError("rootfs logical_size is required")
    if artifacts["build_manifest"].logical_size is not None or artifacts["recovery_guide"].logical_size is not None:
        raise InstallerError("text artifact logical_size must be null")
    return Profile(
        resolved,
        root,
        release_id,
        channel,
        source_commit,
        release["release_eligible"],
        product,
        minimum_battery_mv,
        True,
        True,
        sparse_limit,
        artifacts,
        hashlib.sha256(payload).hexdigest(),
    )


def _verify_regular_file(artifact: Artifact) -> None:
    try:
        metadata = artifact.path.lstat()
    except OSError as error:
        raise InstallerError(f"cannot inspect {artifact.name}: {error}") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_mode & 0o022
    ):
        raise InstallerError(
            f"{artifact.name} must be a single-link regular file not writable by group/other"
        )
    if metadata.st_size != artifact.size:
        raise InstallerError(f"{artifact.name} size mismatch")
    if _sha256_file(artifact.path) != artifact.sha256:
        raise InstallerError(f"{artifact.name} SHA-256 mismatch")


def _verify_boot(path: Path) -> None:
    with path.open("rb") as stream:
        head = stream.read(4096)
    if len(head) < 48 or head[:8] != b"ANDROID!":
        raise InstallerError("boot artifact is not an Android boot image")
    kernel_size = struct.unpack_from("<I", head, 8)[0]
    ramdisk_size = struct.unpack_from("<I", head, 16)[0]
    if kernel_size == 0 or ramdisk_size == 0:
        raise InstallerError("boot artifact has an empty kernel or ramdisk")


def _verify_sparse(path: Path, expected_logical_size: int) -> None:
    file_size = path.stat().st_size
    with path.open("rb") as stream:
        header = stream.read(SPARSE_HEADER.size)
        if len(header) != SPARSE_HEADER.size:
            raise InstallerError("rootfs sparse header is truncated")
        magic, major, minor, file_hdr, chunk_hdr, block_size, total_blocks, total_chunks, _ = SPARSE_HEADER.unpack(header)
        if magic != SPARSE_MAGIC or major != 1 or minor != 0:
            raise InstallerError("rootfs is not a supported Android sparse image")
        if file_hdr < SPARSE_HEADER.size or chunk_hdr < SPARSE_CHUNK.size:
            raise InstallerError("rootfs sparse header sizes are invalid")
        if block_size == 0 or block_size % 4 != 0 or total_blocks == 0 or total_chunks == 0:
            raise InstallerError("rootfs sparse geometry is invalid")
        logical_size = block_size * total_blocks
        if logical_size != expected_logical_size:
            raise InstallerError("rootfs sparse logical size mismatch")
        stream.seek(file_hdr)
        output_blocks = 0
        for _index in range(total_chunks):
            raw_header = stream.read(chunk_hdr)
            if len(raw_header) != chunk_hdr:
                raise InstallerError("rootfs sparse chunk header is truncated")
            chunk_type, _reserved, chunk_blocks, total_size = SPARSE_CHUNK.unpack(
                raw_header[: SPARSE_CHUNK.size]
            )
            if (
                chunk_type not in SPARSE_TYPES
                or (chunk_type == 0xCAC4 and chunk_blocks != 0)
                or (chunk_type != 0xCAC4 and chunk_blocks == 0)
                or total_size < chunk_hdr
            ):
                raise InstallerError("rootfs sparse chunk is invalid")
            payload_size = total_size - chunk_hdr
            expected_payload = {
                0xCAC1: chunk_blocks * block_size,
                0xCAC2: 4,
                0xCAC3: 0,
                0xCAC4: 4,
            }[chunk_type]
            if payload_size != expected_payload:
                raise InstallerError("rootfs sparse chunk size is invalid")
            if stream.tell() + payload_size > file_size:
                raise InstallerError("rootfs sparse chunk payload is truncated")
            stream.seek(payload_size, os.SEEK_CUR)
            if chunk_type != 0xCAC4:
                output_blocks += chunk_blocks
        if output_blocks != total_blocks or stream.tell() != file_size:
            raise InstallerError("rootfs sparse output size or trailing data is invalid")


def verify_bundle(profile: Profile) -> None:
    for artifact in profile.artifacts.values():
        _verify_regular_file(artifact)
    _verify_boot(profile.artifacts["boot"].path)
    logical_size = profile.artifacts["rootfs"].logical_size
    assert logical_size is not None
    _verify_sparse(profile.artifacts["rootfs"].path, logical_size)


def _host_kind() -> str:
    if platform.system() != "Linux":
        raise InstallerError("the installer supports Linux and WSL2 only")
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="ascii").lower()
    except OSError:
        release = platform.release().lower()
    return "wsl2" if "microsoft" in release else "linux"


class Fastboot:
    def __init__(self, executable: str, query_timeout: int = DEFAULT_QUERY_TIMEOUT) -> None:
        resolved = shutil.which(executable) if "/" not in executable else executable
        if not resolved:
            raise InstallerError(f"fastboot executable not found: {executable}")
        self.executable = str(Path(resolved).expanduser())
        self.query_timeout = query_timeout

    def run(
        self,
        arguments: list[str],
        *,
        timeout: int | None = None,
        check: bool = True,
    ) -> subprocess.CompletedProcess[str]:
        standalone_query = arguments in (["--version"], ["devices"])
        device_query = (
            len(arguments) == 4
            and arguments[0] == "-s"
            and bool(arguments[1])
            and arguments[2] == "getvar"
            and arguments[3] in READ_ONLY_GETVARS
        )
        if not standalone_query and not device_query:
            raise InstallerError(
                "verification-only preview permits read-only fastboot queries only"
            )
        try:
            result = subprocess.run(
                [self.executable, *arguments],
                text=True,
                capture_output=True,
                timeout=timeout or self.query_timeout,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise InstallerError("fastboot query timed out") from None
        except OSError:
            raise InstallerError("fastboot query could not be started") from None
        if check and result.returncode != 0:
            # Captured output is device-controlled and can contain a raw serial.
            # Never reflect it into user-visible errors.
            raise InstallerError(f"fastboot query failed with status {result.returncode}")
        return result

    def one_device(self) -> str:
        result = self.run(["devices"])
        rows = [line.split() for line in result.stdout.replace("\r", "").splitlines() if line.strip()]
        rows = [row for row in rows if len(row) >= 2 and row[1] == "fastboot"]
        if len(rows) != 1:
            raise InstallerError(f"exactly one fastboot device is required; found {len(rows)}")
        return rows[0][0]

    def getvar(self, serial: str, key: str, *, required: bool = True) -> str:
        result = self.run(["-s", serial, "getvar", key], check=required)
        output = (result.stdout + "\n" + result.stderr).replace("\r", "")
        value = ""
        for raw in output.splitlines():
            line = raw.strip()
            if line.startswith("(bootloader) "):
                line = line[len("(bootloader) ") :]
            if line.startswith(f"{key}:"):
                value = line[len(key) + 1 :].strip()
        if required and not value:
            raise InstallerError(f"fastboot did not report {key}")
        return value


def _number(value: str, label: str) -> int:
    try:
        return int(value, 0)
    except ValueError:
        raise InstallerError(f"fastboot reported an invalid {label}") from None


def inspect_device(fastboot: Fastboot, profile: Profile, *, require_userspace: bool = True) -> Device:
    serial = fastboot.one_device()
    product = fastboot.getvar(serial, "product")
    unlocked = fastboot.getvar(serial, "unlocked")
    userspace = fastboot.getvar(serial, "is-userspace")
    boot_size = _number(fastboot.getvar(serial, "partition-size:boot"), "boot partition size")
    userdata_size = _number(
        fastboot.getvar(serial, "partition-size:userdata"), "userdata partition size"
    )
    battery_raw = fastboot.getvar(
        serial, "battery-voltage", required=profile.minimum_battery_mv > 0
    )
    battery_mv = _number(battery_raw, "battery voltage") if battery_raw else 0
    errors: list[str] = []
    if product != profile.product:
        errors.append(f"product must be {profile.product}")
    if unlocked != "yes":
        errors.append("bootloader must be unlocked")
    if require_userspace and userspace != "yes":
        errors.append("recovery fastbootd is required (is-userspace must be yes)")
    if profile.minimum_battery_mv and battery_mv < profile.minimum_battery_mv:
        errors.append(
            f"battery voltage {battery_mv} mV is below {profile.minimum_battery_mv} mV"
        )
    boot = profile.artifacts["boot"]
    rootfs = profile.artifacts["rootfs"]
    assert rootfs.logical_size is not None
    if boot.size >= boot_size:
        errors.append(f"boot image {boot.size} bytes does not fit boot partition {boot_size}")
    if rootfs.logical_size >= userdata_size:
        errors.append(
            f"rootfs logical size {rootfs.logical_size} does not fit userdata {userdata_size}"
        )
    if errors:
        raise InstallerError("device preflight failed:\n- " + "\n- ".join(errors))
    return Device(serial, product, unlocked, userspace, battery_mv, boot_size, userdata_size)


def _print_device(device: Device) -> None:
    print(f"device_fingerprint={device.fingerprint}")
    print(f"product={device.product}")
    print(f"unlocked={device.unlocked}")
    print(f"is_userspace={device.userspace}")
    print(f"battery_mv={device.battery_mv}")
    print(f"boot_partition_size={device.boot_size}")
    print(f"userdata_partition_size={device.userdata_size}")


def _lock() -> Any:
    path = Path("/tmp") / f"lmi-installer-{os.getuid()}.lock"
    descriptor = path.open("a+")
    try:
        fcntl.flock(descriptor.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        descriptor.close()
        raise InstallerError("another lmi-installer process is running") from None
    return descriptor


def _show_plan(profile: Profile) -> None:
    print(f"installer_version={VERSION}")
    print(f"release={profile.release_id}")
    print(f"channel={profile.channel}")
    print(f"release_eligible={str(profile.release_eligible).lower()}")
    print(f"source_commit={profile.source_commit}")
    print("mode=verification-only-source-preview")
    print("steps=verify bundle; optionally run read-only device queries")
    print("device_state_change=false")


def command_main(arguments: argparse.Namespace) -> int:
    profile = load_profile(arguments.profile)
    if arguments.command in {"info", "plan"}:
        _show_plan(profile)
        return 0
    verify_bundle(profile)
    print("bundle_verify=OK")
    if arguments.command == "verify":
        return 0
    if arguments.command == "install":
        _show_plan(profile)
        print("dry_run=OK; no device was accessed and no device-state command was executed")
        return 0
    host = _host_kind()
    fastboot = Fastboot(arguments.fastboot)
    print(f"host={host}")
    if arguments.command == "doctor":
        fastboot.run(["--version"])
        print("fastboot_version_query=OK")
        return 0
    if arguments.command == "preflight":
        device = inspect_device(fastboot, profile)
        _print_device(device)
        print("preflight=OK")
        return 0
    if arguments.command == "wait-fastbootd":
        deadline = time.monotonic() + arguments.timeout
        while time.monotonic() <= deadline:
            try:
                device = inspect_device(fastboot, profile)
            except InstallerError:
                time.sleep(2)
                continue
            _print_device(device)
            print("wait_fastbootd=OK")
            return 0
        raise InstallerError("timed out waiting for recovery fastbootd")
    raise InstallerError("unsupported command")


def _artifact_record(path: Path, root: Path, kind: str, logical_size: int | None) -> dict[str, Any]:
    return {
        "kind": kind,
        "logical_size": logical_size,
        "path": path.relative_to(root).as_posix(),
        "sha256": _sha256_file(path),
        "size": path.stat().st_size,
    }


def _sparse_logical_size(path: Path) -> int:
    with path.open("rb") as stream:
        header = stream.read(SPARSE_HEADER.size)
    if len(header) != SPARSE_HEADER.size:
        raise InstallerError("rootfs sparse header is truncated")
    magic, major, minor, _file_hdr, _chunk_hdr, block_size, total_blocks, _chunks, _checksum = SPARSE_HEADER.unpack(header)
    if magic != SPARSE_MAGIC or major != 1 or minor != 0:
        raise InstallerError("rootfs must be an Android sparse image")
    return block_size * total_blocks


def build_bundle(arguments: argparse.Namespace) -> int:
    output = arguments.output.absolute()
    if output.exists() or output.is_symlink():
        raise InstallerError(f"refusing to overwrite output: {output}")
    inputs = {
        "boot": arguments.boot.resolve(strict=True),
        "rootfs": arguments.rootfs.resolve(strict=True),
        "build_manifest": arguments.build_manifest.resolve(strict=True),
        "recovery_guide": arguments.recovery_guide.resolve(strict=True),
    }
    output.mkdir(parents=True, mode=0o755)
    try:
        images = output / "images"
        metadata = output / "metadata"
        images.mkdir(mode=0o755)
        metadata.mkdir(mode=0o755)
        destinations = {
            "boot": images / "boot-lmi.img",
            "rootfs": images / "userdata-lmi.img",
            "build_manifest": metadata / "build.manifest",
            "recovery_guide": output / "RECOVERY.md",
        }
        for name, source in inputs.items():
            shutil.copyfile(source, destinations[name])
            destinations[name].chmod(0o644)
        launcher_source = Path(__file__).with_name("lmi-installer")
        shutil.copyfile(Path(__file__), output / "lmi_cli_installer.py")
        shutil.copyfile(launcher_source, output / "lmi-installer")
        (output / "lmi_cli_installer.py").chmod(0o644)
        (output / "lmi-installer").chmod(0o755)
        logical_size = _sparse_logical_size(destinations["rootfs"])
        profile = {
            "artifacts": {
                "boot": _artifact_record(destinations["boot"], output, "android-boot", None),
                "build_manifest": _artifact_record(destinations["build_manifest"], output, "text", None),
                "recovery_guide": _artifact_record(destinations["recovery_guide"], output, "text", None),
                "rootfs": _artifact_record(destinations["rootfs"], output, "android-sparse", logical_size),
            },
            "device": {
                "minimum_battery_mv": arguments.minimum_battery_mv,
                "product": "lmi",
                "require_unlocked": True,
                "require_userspace": True,
            },
            "execution": {
                "allowed_partitions": ["userdata", "boot"],
                "automatic_retry": False,
                "fastboot_sparse_limit": arguments.sparse_limit,
                "steps": ["userdata", "boot", "reboot"],
            },
            "release": {
                "channel": arguments.channel,
                "id": arguments.release_id,
                "release_eligible": False,
                "source_commit": arguments.source_commit,
            },
            "schema": SCHEMA,
        }
        profile_path = output / "installer-profile.json"
        profile_path.write_text(
            json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="ascii"
        )
        profile_path.chmod(0o644)
        loaded = load_profile(profile_path)
        verify_bundle(loaded)
        sums = output / "SHA256SUMS"
        members = sorted(
            path for path in output.rglob("*") if path.is_file() and path != sums
        )
        sums.write_text(
            "".join(f"{_sha256_file(path)}  {path.relative_to(output).as_posix()}\n" for path in members),
            encoding="ascii",
        )
        sums.chmod(0o644)
    except BaseException:
        shutil.rmtree(output, ignore_errors=True)
        raise
    print(output)
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="lmi-installer", description=__doc__)
    result.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = result.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build-bundle", help="create a self-contained installer bundle")
    build.add_argument("--boot", type=Path, required=True)
    build.add_argument("--rootfs", type=Path, required=True)
    build.add_argument("--build-manifest", type=Path, required=True)
    build.add_argument("--recovery-guide", type=Path, required=True)
    build.add_argument("--release-id", required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--channel", choices=("experimental", "beta", "stable"), default="experimental")
    build.add_argument("--minimum-battery-mv", type=int, default=3800)
    build.add_argument("--sparse-limit", default="256M")
    build.add_argument("--output", type=Path, required=True)

    for name in ("info", "plan", "verify"):
        command = subparsers.add_parser(name)
        command.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    for name in ("doctor", "preflight", "wait-fastbootd"):
        command = subparsers.add_parser(name)
        command.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
        command.add_argument("--fastboot", default=os.environ.get("FASTBOOT", "fastboot"))
        if name == "wait-fastbootd":
            command.add_argument("--timeout", type=int, default=120)
    install = subparsers.add_parser("install")
    install.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    return result


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "build-bundle":
            return build_bundle(arguments)
        with _lock():
            return command_main(arguments)
    except InstallerError as error:
        print(f"lmi-installer: REFUSED: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
