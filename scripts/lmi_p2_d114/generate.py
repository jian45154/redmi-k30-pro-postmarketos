"""Deterministically generate the contained D114 terminal pmaports overlay."""

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


PACKAGE_RELATIVE = Path("device/downstream/device-xiaomi-lmi-terminal")


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
    source_directory = source_root / "files/lmi-p2-d114"
    try:
        directory_metadata = source_directory.lstat()
        entries = {entry.name for entry in source_directory.iterdir()}
    except OSError as error:
        raise LockError(f"could not enumerate D114 P2 sources: {error}") from None
    if (
        not stat.S_ISDIR(directory_metadata.st_mode)
        or stat.S_ISLNK(directory_metadata.st_mode)
        or stat.S_IMODE(directory_metadata.st_mode) != 0o755
    ):
        raise LockError("D114 P2 source directory must be one real mode-755 directory")
    expected_names = set(source_lock.value["source_files"])
    if entries != expected_names:
        raise LockError("D114 P2 source directory must contain exactly the locked source set")

    result: dict[str, bytes] = {}
    for name, expected_digest in sorted(source_lock.value["source_files"].items()):
        path = source_directory / name
        try:
            before = path.lstat()
            payload = path.read_bytes()
            after = path.lstat()
        except OSError as error:
            raise LockError(f"could not read D114 P2 source file {name}: {error}") from None
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_ino != after.st_ino
            or before.st_dev != after.st_dev
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o644
        ):
            raise LockError(
                f"unsafe, unstable, or non-mode-644 D114 P2 source file: {name}"
            )
        if b"\0" in payload:
            raise LockError(f"binary payloads are forbidden in D114 P2 sources: {name}")
        actual_digest = _sha256(payload)
        if actual_digest != expected_digest:
            raise LockError(
                f"D114 P2 source digest mismatch for {name}: "
                f"{actual_digest} != {expected_digest}"
            )
        result[name] = payload
    return result


def render_apkbuild(source_lock: SourceLock, sources: dict[str, bytes]) -> bytes:
    package = source_lock.value["package"]
    dependencies = source_lock.value["dependencies"]
    lines = [
        "# Generated from config/lmi-p2-d114/source-lock.json; do not edit.",
        "# Private D110/D114 hardware-test candidate; not a release package.",
        f"pkgname={package['name']}",
        f"pkgver={package['pkgver']}",
        f"pkgrel={package['pkgrel']}",
        'pkgdesc="Pinned non-root Weston terminal session for Xiaomi lmi D114"',
        'url="https://postmarketos.org"',
        'arch="noarch"',
        'license="MIT"',
        f'maintainer="{package["maintainer"]}"',
        'options="!check"',
        f'export PACKAGER="{package["packager"]}"',
        f'export ABUILD_LAST_COMMIT="{package["abuild_last_commit"]}"',
        f"export SOURCE_DATE_EPOCH={package['source_date_epoch']}",
        'install="$pkgname.post-install $pkgname.post-upgrade $pkgname.pre-deinstall"',
        'depends="',
        *[f"\t{dependency}" for dependency in dependencies],
        '"',
        'source="',
        *[f"\t{name}" for name in sorted(sources)],
        '"',
        "",
        "package() {",
        '\tinstall -Dm755 "$srcdir"/lmi-p2-d114-session \\',
        '\t\t"$pkgdir"/usr/libexec/lmi-p2-d114/session',
        '\tinstall -Dm755 "$srcdir"/lmi-p2-d114-config-lifecycle \\',
        '\t\t"$pkgdir"/usr/libexec/lmi-p2-d114/config-lifecycle',
        '\tinstall -Dm644 "$srcdir"/lmi-p2-d114-weston.ini \\',
        '\t\t"$pkgdir"/etc/lmi-p2-d114/weston.ini',
        '\tinstall -Dm644 "$srcdir"/lmi-p2-d114-greetd.toml \\',
        '\t\t"$pkgdir"/etc/lmi-p2-d114/greetd.toml',
        '\tinstall -Dm644 "$srcdir"/lmi-p2-d114-greetd.confd \\',
        '\t\t"$pkgdir"/usr/share/lmi-p2-d114/greetd.confd',
        "}",
        "",
        'sha512sums="',
        *[
            f"{_sha512(payload)}  {name}"
            for name, payload in sorted(sources.items())
        ],
        '"',
        "",
    ]
    return "\n".join(lines).encode("utf-8")


def generate_overlay(
    lock_path: Path, output: Path, *, source_root: Path | None = None
) -> Path:
    """Generate into one absent directory and never merge with an old tree."""

    source_lock = load_source_lock(lock_path)
    if source_root is None:
        source_root = Path(__file__).resolve().parents[2]
    try:
        source_root = source_root.resolve(strict=True)
    except OSError as error:
        raise LockError(f"D114 P2 source root is unavailable: {error}") from None

    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise LockError(f"refusing to overwrite existing output: {output}")
    parent = output.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as error:
        raise LockError(f"output parent is unavailable: {error}") from None
    if not stat.S_ISDIR(parent_metadata.st_mode) or stat.S_ISLNK(
        parent_metadata.st_mode
    ):
        raise LockError("output parent must be one real directory")

    sources = _read_sources(source_lock, source_root)
    apkbuild = render_apkbuild(source_lock, sources)
    outputs = {**sources, "APKBUILD": apkbuild}
    temporary = Path(tempfile.mkdtemp(prefix=".lmi-p2-d114-overlay-", dir=parent))
    try:
        package_directory = temporary / PACKAGE_RELATIVE
        package_directory.mkdir(parents=True, mode=0o755)
        current = temporary
        for component in PACKAGE_RELATIVE.parts:
            current /= component
            current.chmod(0o755)
        for name, payload in sorted(outputs.items()):
            destination = package_directory / name
            destination.write_bytes(payload)
            destination.chmod(0o644)
        manifest = {
            "files": {
                f"{PACKAGE_RELATIVE.as_posix()}/{name}": {
                    "sha256": _sha256(payload),
                    "size": len(payload),
                }
                for name, payload in sorted(outputs.items())
            },
            "release_eligible": False,
            "schema": "lmi-p2-d114-generated-overlay/v1",
            "source_lock_sha256": source_lock.sha256,
            "status": source_lock.value["package"]["status"],
        }
        manifest_path = temporary / ".lmi-p2-d114-overlay.json"
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
        help="fail while persistent-image and physical-input evidence remain pending",
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
