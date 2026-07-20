"""Create and verify the sealed P1 known-good kernel APK.

The package is intentionally an APKv3 package produced by apk-tools ``mkpkg``.
It keeps the solver identity required by ``device-xiaomi-lmi`` while using an
explicitly different origin and description, and is never confused with the
historical/source r8 APK by the P1 source lock.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import subprocess
import tempfile
from typing import Mapping, Sequence


SCHEMA = "lmi-p1-known-good-kernel-package/v2"
PACKAGE_NAME = "linux-xiaomi-lmi"
PACKAGE_VERSION = "4.19.325-r8"
PACKAGE_ARCH = "aarch64"
PACKAGE_ORIGIN = "linux-xiaomi-lmi-p1-known-good"
PACKAGE_DESCRIPTION = (
    "P1 reconstructed known-good v46 kernel; not the upstream r8 binary"
)
PACKAGE_HASH = "ec27fc0dc554214c369ffc4335fecfafd58aaa95"
PACKAGE_WORLD_CHECKSUM = "Q17Cf8DcVUIUw2n/xDNf7Pr9WKqpU="
SOURCE_DATE_EPOCH = 1782292186
SOURCE_APK_SHA256 = "67cbc5a543b425d3602ffa33b722fbf0379dcdbf184c5996c960576f16c91610"
SOURCE_APK_SIZE = 17418119
APK_STATIC_SHA256 = "a6542dc1fdb6214be1ef462668241bfe91f301e9249c99c0c6c327269d5e5ce4"
VMLINUX_SHA256 = "38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e"
OUTPUT_APK_NAME = "linux-xiaomi-lmi-4.19.325-r8-p1-known-good.apk"
OUTPUT_INDEX_NAME = "pmbootstrap-status-APKINDEX.tar.gz"
OUTPUT_KEY_NAME = "lmi-p1-known-good-kernel.rsa.pub"
UNSHARE = "/usr/bin/unshare"
ENV = "/usr/bin/env"

COMMAND_ENVIRONMENT: Mapping[str, str] = {
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin",
    "SOURCE_DATE_EPOCH": str(SOURCE_DATE_EPOCH),
    "TZ": "UTC",
}

PAYLOAD: Mapping[str, tuple[str, str, int]] = {
    "boot/vmlinuz": (
        VMLINUX_SHA256,
        "Q1MXqTOyS9LVwxr/gPYkPfCoE9eqo=",
        0o644,
    ),
    "boot/dtbs/qcom/kona-v2.1-lmi.dtb": (
        "aee89cc172734de955a11ec335b16d3a1b5da51667083b919271c2b6902d57a6",
        "Q19O3+WS3OUPq8gHC5WtdsTruzGFU=",
        0o644,
    ),
    "boot/dtbs/qcom/kona-v2.1.dtb": (
        "0ba04a2de0fe16688f19a42c88380b55684766a7ba404f782a51a2089a9c1de9",
        "Q16bz92+wp31OHZsQ+W9A23MuaTBE=",
        0o644,
    ),
    "boot/dtbs/qcom/kona-v2.dtb": (
        "f2fc300b0f34728b44e8faf0d35c08eaaced1feff1751a1761c2af64a655ccb3",
        "Q1s/8EKbW0JdVcqbDlcvIF+2AIU/4=",
        0o644,
    ),
    "boot/dtbs/qcom/kona.dtb": (
        "6308344e8922c615dadcc638002d90e0623729f077f199d99f0a0b881c918c7a",
        "Q1SYl9MN1glz+DnlMhT5nlWaStDrM=",
        0o644,
    ),
    "boot/dtbs/qcom/lmi-sm8250-overlay.dtbo": (
        "c432876c7f32b3daa8c4158135bc711548d1279744bafcb633f09a771dec96d2",
        "Q1E1/Yc9/BLSOaQHO8yL3QQBAEX5s=",
        0o644,
    ),
    "usr/share/kernel/xiaomi-lmi/kernel.release": (
        "57e559636bd29f68002ebf08a425e10ffdbe8b6ce9c2d19d0d2230635b1ba691",
        "Q1QUCgtJmw5tqsyQOGAFhlkwz7y1k=",
        0o755,
    ),
}


class PackageError(RuntimeError):
    """A fail-closed package construction or verification error."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _q1(path: Path) -> str:
    digest = hashlib.sha1(path.read_bytes(), usedforsecurity=False).digest()
    return "Q1" + base64.b64encode(digest).decode("ascii")


def _v3_installed_q1(sha256: str) -> str:
    """Return apk-tools' v2-installed-db encoding of one APKv3 SHA-256."""

    return "Q1" + base64.b64encode(bytes.fromhex(sha256)[:20]).decode("ascii")


def _regular(path: Path, label: str, expected_sha256: str | None = None) -> Path:
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
        after = path.lstat()
    except OSError as error:
        raise PackageError(f"could not inspect {label}: {error}") from None
    if (
        path.is_symlink()
        or not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise PackageError(f"{label} is not one stable regular file")
    if expected_sha256 is not None and _sha256(resolved) != expected_sha256:
        raise PackageError(f"{label} SHA-256 mismatch")
    return resolved


def _run(arguments: Sequence[str]) -> str:
    completed = subprocess.run(
        list(arguments),
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(COMMAND_ENVIRONMENT),
    )
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip()
        raise PackageError(
            f"command failed ({Path(arguments[0]).name} {arguments[1]}): {message}"
        )
    return completed.stdout


def _payload_inventory(
    root: Path,
    *,
    exact: bool = True,
    normalize: bool = False,
) -> None:
    actual_files: set[str] = set()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories:
            path = current_path / name
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise PackageError("payload contains a non-directory tree member")
            if normalize:
                path.chmod(0o755)
        for name in files:
            path = current_path / name
            relative = path.relative_to(root).as_posix()
            metadata = path.lstat()
            if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
                raise PackageError(f"payload member is not regular: {relative}")
            actual_files.add(relative)
    if exact and actual_files != set(PAYLOAD):
        raise PackageError("kernel payload has missing or extra files")
    if not set(PAYLOAD).issubset(actual_files):
        raise PackageError("kernel payload has missing files")
    if normalize:
        root.chmod(0o755)
    payload_directories = {
        root.joinpath(*PurePosixPath(relative).parts[:depth])
        for relative in PAYLOAD
        for depth in range(1, len(PurePosixPath(relative).parts))
    }
    for directory in payload_directories:
        metadata = directory.lstat()
        if (
            directory.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o755
        ):
            raise PackageError("kernel payload directory mode mismatch")
    for relative, (expected_sha256, expected_q1, mode) in PAYLOAD.items():
        path = root.joinpath(*PurePosixPath(relative).parts)
        if normalize:
            path.chmod(mode)
        if _sha256(path) != expected_sha256 or _q1(path) != expected_q1:
            raise PackageError(f"kernel payload checksum mismatch: {relative}")
        if stat.S_IMODE(path.stat().st_mode) != mode:
            raise PackageError(f"kernel payload mode mismatch: {relative}")


def _stage_payload(apk_static: Path, source_apk: Path, vmlinuz: Path, root: Path) -> None:
    _run(
        [
            str(apk_static),
            "--allow-untrusted",
            "extract",
            "--no-chown",
            "--destination",
            str(root),
            str(source_apk),
        ]
    )
    destination = root / "boot/vmlinuz"
    with vmlinuz.open("rb") as source, destination.open("wb") as target:
        shutil.copyfileobj(source, target, length=1024 * 1024)
    _payload_inventory(root, normalize=True)


def _mkpkg(
    apk_static: Path,
    signing_key: Path,
    signer_public_key: Path,
    source_apk: Path,
    vmlinuz: Path,
    output: Path,
    workspace: Path,
) -> None:
    stage = workspace / "payload"
    stage.mkdir(mode=0o700)
    _stage_payload(apk_static, source_apk, vmlinuz, stage)
    _run(
        [
            UNSHARE,
            "--user",
            "--map-root-user",
            "--",
            ENV,
            f"SOURCE_DATE_EPOCH={SOURCE_DATE_EPOCH}",
            "LC_ALL=C",
            "TZ=UTC",
            str(apk_static),
            "mkpkg",
            "--sign-key",
            str(signing_key),
            "--info",
            f"name:{PACKAGE_NAME}",
            "--info",
            f"version:{PACKAGE_VERSION}",
            "--info",
            f"arch:{PACKAGE_ARCH}",
            "--info",
            f"origin:{PACKAGE_ORIGIN}",
            "--info",
            f"description:{PACKAGE_DESCRIPTION}",
            "--info",
            "license:GPL-2.0-only",
            "--info",
            "url:https://github.com/jian45154/redmi-k30-pro-postmarketos",
            "--info",
            f"build-time:{SOURCE_DATE_EPOCH}",
            "--files",
            str(stage),
            "--output",
            str(output),
        ],
    )
    _verify_package(apk_static, output, signer_public_key, workspace / "verify")


def _one_kernel_record(installed: Path) -> str:
    records = installed.read_text(encoding="utf-8").strip().split("\n\n")
    matches = [record for record in records if f"P:{PACKAGE_NAME}\n" in record + "\n"]
    if len(matches) != 1:
        raise PackageError("installed database does not contain one unique kernel owner")
    return matches[0]


def _verify_installed_record(record: str) -> None:
    if f"V:{PACKAGE_VERSION}\n" not in record + "\n":
        raise PackageError("installed kernel version mismatch")
    if f"o:{PACKAGE_ORIGIN}\n" not in record + "\n":
        raise PackageError("installed kernel origin mismatch")
    directory = ""
    checksums: dict[str, str] = {}
    owners: dict[str, str] = {}
    current_file: str | None = None
    for line in record.splitlines():
        if line.startswith("F:"):
            directory = line[2:]
        elif line.startswith("R:"):
            current_file = f"{directory}/{line[2:]}" if directory else line[2:]
        elif line.startswith("a:") and current_file is not None:
            owners[current_file] = line[2:]
        elif line.startswith("Z:") and current_file is not None:
            checksums[current_file] = line[2:]
            current_file = None
    expected_checksums = {
        path: _v3_installed_q1(value[0]) for path, value in PAYLOAD.items()
    }
    if checksums != expected_checksums:
        raise PackageError(
            "installed database kernel checksum inventory mismatch: "
            f"{checksums!r}"
        )
    for path, (_sha, _q1_value, mode) in PAYLOAD.items():
        expected_owner = f"0:0:{mode:o}"
        # apk omits the default root:root:0644 ACL from the v2 installed DB.
        if mode == 0o644:
            if path in owners and owners[path] != expected_owner:
                raise PackageError(f"installed database owner mismatch: {path}")
        elif owners.get(path) != expected_owner:
            raise PackageError(f"installed database owner/mode mismatch: {path}")


def _verify_package(apk_static: Path, package: Path, public_key: Path, root: Path) -> None:
    if root.exists():
        raise PackageError("verification root already exists")
    keys = root / "keys"
    install_root = root / "root"
    keys.mkdir(parents=True, mode=0o700)
    install_root.mkdir(mode=0o700)
    copied_key = keys / OUTPUT_KEY_NAME
    shutil.copyfile(public_key, copied_key)
    copied_key.chmod(0o600)
    _run([str(apk_static), "--keys-dir", str(keys), "verify", str(package)])
    dump = _run([str(apk_static), "--keys-dir", str(keys), "adbdump", str(package)])
    required = (
        f"name: {PACKAGE_NAME}",
        f"version: {PACKAGE_VERSION}",
        f"description: {PACKAGE_DESCRIPTION}",
        f"arch: {PACKAGE_ARCH}",
        f"origin: {PACKAGE_ORIGIN}",
        f"hashes: {PACKAGE_HASH}",
        "build-time: 1782292186",
    )
    if any(item not in dump for item in required):
        raise PackageError("APKv3 metadata identity mismatch")
    derived_world_checksum = "Q1" + base64.b64encode(
        bytes.fromhex(PACKAGE_HASH)
    ).decode("ascii")
    if derived_world_checksum != PACKAGE_WORLD_CHECKSUM:
        raise PackageError("APKv3 package hash/world checksum binding mismatch")
    payload_directories = {
        PurePosixPath(relative).parts[:depth]
        for relative in PAYLOAD
        for depth in range(1, len(PurePosixPath(relative).parts))
    }
    expected_acls = 1 + len(payload_directories) + len(PAYLOAD)
    if (
        dump.count("user: root") != expected_acls
        or dump.count("group: root") != expected_acls
        or dump.count("mode: 0644")
        != sum(mode == 0o644 for _sha, _q1_value, mode in PAYLOAD.values())
        or dump.count("mode: 0755")
        != 1
        + len(payload_directories)
        + sum(mode == 0o755 for _sha, _q1_value, mode in PAYLOAD.values())
    ):
        raise PackageError("APKv3 ownership inventory is not entirely root:root")
    for relative, (sha256, _historical_q1, _mode) in PAYLOAD.items():
        if dump.count(f"hash: {sha256}") != 1:
            raise PackageError(f"APKv3 payload hash inventory mismatch: {relative}")
    raw = package.read_bytes()
    if b"BEGIN PRIVATE KEY" in raw or b"BEGIN RSA PRIVATE KEY" in raw:
        raise PackageError("APKv3 artifact contains private-key material")
    _run(
        [
            str(apk_static),
            "--usermode",
            "--root",
            str(install_root),
            "--arch",
            PACKAGE_ARCH,
            "--keys-dir",
            str(keys),
            "--force-non-repository",
            "--initdb",
            "add",
            str(package),
        ]
    )
    _payload_inventory(install_root, exact=False)
    _verify_installed_record(_one_kernel_record(install_root / "lib/apk/db/installed"))


def _build_status_index(apk_static: Path, source_apk: Path, output: Path) -> None:
    _run(
        [
            str(apk_static),
            "--allow-untrusted",
            "index",
            "--output",
            str(output),
            "--description",
            "lmi-p1-known-good-kernel-status-only",
            str(source_apk),
        ],
    )


def build(arguments: argparse.Namespace) -> dict[str, object]:
    apk_static = _regular(arguments.apk_static, "apk.static", APK_STATIC_SHA256)
    source_apk = _regular(arguments.source_apk, "source r8 APK", SOURCE_APK_SHA256)
    vmlinuz = _regular(arguments.vmlinuz, "recovered vmlinuz", VMLINUX_SHA256)
    signing_key = _regular(arguments.signing_key, "package signing key")
    public_key = _regular(arguments.signer_public_key, "package signer public key")
    version = _run([str(apk_static), "--version"]).strip()
    if version != "apk-tools 3.0.6-r0, compiled for x86_64.":
        raise PackageError("apk.static version mismatch")
    output_directory = Path(arguments.output_directory).absolute()
    output_directory.mkdir(parents=True, exist_ok=True)
    if output_directory.is_symlink() or not output_directory.is_dir():
        raise PackageError("output directory is not one real directory")
    final_apk = output_directory / OUTPUT_APK_NAME
    final_index = output_directory / OUTPUT_INDEX_NAME
    final_key = output_directory / OUTPUT_KEY_NAME
    for path in (final_apk, final_index, final_key):
        if os.path.lexists(path):
            raise PackageError(f"output already exists: {path.name}")

    with tempfile.TemporaryDirectory(prefix="lmi-p1-known-good-kernel.") as temporary:
        temporary_root = Path(temporary)
        built: list[Path] = []
        indexes: list[Path] = []
        for number in (1, 2):
            workspace = temporary_root / f"build-{number}"
            workspace.mkdir(mode=0o700)
            package = workspace / OUTPUT_APK_NAME
            index = workspace / OUTPUT_INDEX_NAME
            _mkpkg(
                apk_static,
                signing_key,
                public_key,
                source_apk,
                vmlinuz,
                package,
                workspace,
            )
            _build_status_index(apk_static, source_apk, index)
            built.append(package)
            indexes.append(index)
        if built[0].read_bytes() != built[1].read_bytes():
            raise PackageError("two apk mkpkg builds did not produce identical bytes")
        if indexes[0].read_bytes() != indexes[1].read_bytes():
            raise PackageError("two status-index builds did not produce identical bytes")
        shutil.copyfile(built[0], final_apk)
        shutil.copyfile(indexes[0], final_index)
    shutil.copyfile(public_key, final_key)
    for path in (final_apk, final_index, final_key):
        path.chmod(0o644)
    return {
        "schema": SCHEMA,
        "apk": {
            "path": final_apk.name,
            "sha256": _sha256(final_apk),
            "size": final_apk.stat().st_size,
            "world_checksum": PACKAGE_WORLD_CHECKSUM,
        },
        "pmbootstrap_status_index": {
            "path": final_index.name,
            "sha256": _sha256(final_index),
            "size": final_index.stat().st_size,
        },
        "signer_public_key": {
            "path": final_key.name,
            "sha256": _sha256(final_key),
            "size": final_key.stat().st_size,
        },
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk-static", type=Path, required=True)
    parser.add_argument("--source-apk", type=Path, required=True)
    parser.add_argument("--vmlinuz", type=Path, required=True)
    parser.add_argument("--signing-key", type=Path, required=True)
    parser.add_argument("--signer-public-key", type=Path, required=True)
    parser.add_argument("--output-directory", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        result = build(arguments)
    except PackageError as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
