"""Deterministically generate the contained lmi P3 pmaports overlay."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
from typing import Any

from .source_lock import LockError, SourceLock, load_source_lock


PACKAGE_RELATIVE = Path("device/downstream/device-xiaomi-lmi-audio")


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _sha512(payload: bytes) -> str:
    return hashlib.sha512(payload).hexdigest()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _read_sources(source_lock: SourceLock, source_root: Path) -> dict[str, bytes]:
    source_directory = source_root / "files/lmi-p3"
    try:
        directory_metadata = source_directory.lstat()
        entries = {entry.name for entry in source_directory.iterdir()}
    except OSError as error:
        raise LockError(f"could not enumerate P3 sources: {error}") from None
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o755
    ):
        raise LockError("P3 source directory must be one real mode-755 directory")
    expected_names = set(source_lock.value["source_files"])
    if entries != expected_names:
        raise LockError("P3 source directory must contain exactly the locked source set")

    result: dict[str, bytes] = {}
    for name, expected_digest in sorted(source_lock.value["source_files"].items()):
        path = source_directory / name
        try:
            before = path.lstat()
            payload = path.read_bytes()
            after = path.lstat()
        except OSError as error:
            raise LockError(f"could not read P3 source file {name}: {error}") from None
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_ino != after.st_ino
            or before.st_dev != after.st_dev
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
        ):
            raise LockError(f"unsafe, unstable, or non-mode-644 P3 source file: {name}")
        if b"\0" in payload:
            raise LockError(f"binary payloads are forbidden in the P3 source package: {name}")
        actual_digest = _sha256(payload)
        if actual_digest != expected_digest:
            raise LockError(
                f"P3 source digest mismatch for {name}: {actual_digest} != {expected_digest}"
            )
        result[name] = payload
    return result


def render_apkbuild(source_lock: SourceLock, sources: dict[str, bytes]) -> bytes:
    package = source_lock.value["package"]
    dependencies = source_lock.value["dependencies"]
    lines = [
        "# Generated from config/lmi-p3/source-lock.json; do not edit.",
        "# Host/source-only candidate: no firmware, UCM, kernel, or runlevel payload.",
        f"pkgname={package['name']}",
        f"pkgver={package['pkgver']}",
        f"pkgrel={package['pkgrel']}",
        'pkgdesc="Guarded downstream ADSP boot candidate and passive audio inventory for Xiaomi lmi"',
        'url="https://postmarketos.org"',
        f"arch=\"{package['arch']}\"",
        'license="MIT"',
        'options="!check"',
        'install="$pkgname.post-install"',
        'depends="',
        *[f"\t{dependency}" for dependency in dependencies],
        '"',
        'source="',
        *[f"\t{name}" for name in sorted(sources)],
        '"',
        "",
        "package() {",
        '\tinstall -Dm755 "$srcdir"/lmi-adsp-control \\',
        '\t\t"$pkgdir"/usr/sbin/lmi-adsp-control',
        '\tinstall -Dm755 "$srcdir"/lmi-audio-probe \\',
        '\t\t"$pkgdir"/usr/sbin/lmi-audio-probe',
        '\tinstall -Dm755 "$srcdir"/lmi-p3-route-guard \\',
        '\t\t"$pkgdir"/usr/libexec/lmi-p3-route-guard',
        '\tinstall -Dm755 "$srcdir"/lmi-adsp-boot.initd \\',
        '\t\t"$pkgdir"/etc/init.d/lmi-adsp-boot',
        '\tinstall -Dm600 "$srcdir"/lmi-adsp-boot.confd \\',
        '\t\t"$pkgdir"/etc/conf.d/lmi-adsp-boot',
        '\tinstall -dm700 "$pkgdir"/etc/lmi-p3',
        "}",
        "",
        'sha512sums="',
        *[f"{_sha512(payload)}  {name}" for name, payload in sorted(sources.items())],
        '"',
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def generate_overlay(
    lock_path: Path, output: Path, *, source_root: Path | None = None
) -> Path:
    """Generate into a new directory; never merge with or replace an old tree."""

    source_lock = load_source_lock(lock_path)
    if source_root is None:
        source_root = Path(__file__).resolve().parents[2]
    try:
        source_root = source_root.resolve(strict=True)
    except OSError as error:
        raise LockError(f"P3 source root is unavailable: {error}") from None

    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise LockError(f"refusing to overwrite existing output: {output}")
    parent = output.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise LockError(f"output parent is unavailable: {error}") from None
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(parent_metadata.st_mode):
        raise LockError("output parent must be one real directory")

    sources = _read_sources(source_lock, source_root)
    apkbuild = render_apkbuild(source_lock, sources)
    outputs = {**sources, "APKBUILD": apkbuild}
    temporary = Path(tempfile.mkdtemp(prefix=".lmi-p3-overlay-", dir=parent))
    try:
        package_directory = temporary / PACKAGE_RELATIVE
        package_directory.mkdir(parents=True, mode=0o755)
        current = temporary
        for component in PACKAGE_RELATIVE.parts:
            current = current / component
            current.chmod(0o755)
        for name, payload in sorted(outputs.items()):
            destination = package_directory / name
            destination.write_bytes(payload)
            destination.chmod(0o644)
        manifest = {
            "distribution": {
                "proprietary_firmware_included": False,
                "ucm_profile_included": False,
            },
            "files": {
                f"{PACKAGE_RELATIVE.as_posix()}/{name}": {
                    "sha256": _sha256(payload),
                    "size": len(payload),
                }
                for name, payload in sorted(outputs.items())
            },
            "release_eligible": False,
            "schema": "lmi-p3-generated-overlay/v1",
            "source_lock_sha256": source_lock.sha256,
            "status": source_lock.value["package"]["status"],
        }
        manifest_path = temporary / ".lmi-p3-overlay.json"
        manifest_path.write_bytes(_canonical_json(manifest))
        manifest_path.chmod(0o644)
        temporary.chmod(0o755)
        os.rename(temporary, output)
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return output / PACKAGE_RELATIVE


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--require-release-ready",
        action="store_true",
        help="fail while real-device P3 evidence and approvals remain unresolved",
    )
    arguments = parser.parse_args(argv)
    try:
        source_lock = load_source_lock(arguments.lock)
        if arguments.require_release_ready:
            source_lock.require_release_ready()
        package = generate_overlay(arguments.lock, arguments.output)
    except LockError as error:
        parser.error(str(error))
    print(package)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
