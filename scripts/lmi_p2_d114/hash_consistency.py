#!/usr/bin/env python3
"""Declarative SHA-256 consistency governance for the D114 P2 pipeline.

Why this exists
---------------
The P2 injection/deploy chain pins ~150 SHA-256 values. Many are the *same*
logical value hand-copied into several files (a lock JSON's digest pinned in a
script, a built binary's digest written into both source-lock.json and the
session script, ...). Nothing cross-checked those copies, so a stale copy
compiled cleanly, passed every test, and still black-screened the device
(2026-07-23: source-lock got the r2 keyboard SHA, the session script kept the
r1 one -> the session gate rejected the live keyboard child on SHA mismatch).

This module does not remove the SHAs -- they are load-bearing for the sealed,
offline, tamper-evident pipeline. It makes the design's implicit invariant
("every copy of a value agrees with its single source of truth") a machine
-checked fact. Two invariant classes:

- DERIVED (class A): the value is exactly sha256(some repo file). The file is
  the source of truth; every literal site must equal its recomputed digest.
  Catches a missed re-pin anywhere in the lock chain.
- MIRRORED (class B): the value comes from a built artifact / external input
  (a compiled binary, an apk, a signing key) and is written verbatim into
  several files. One site is declared canonical; every other must contain it.
  Catches the keyboard-SHA class of drift.

Run ``verify`` (also wired into scripts/59_release_static_ci.sh and
tests/lmi_p2_d114/test_hash_consistency.py); it exits non-zero and prints an
exact drift report if any copy disagrees with its source of truth.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CONFIG = REPO / "config/lmi-p2-d114"
SCRIPTS = REPO / "scripts/lmi_p2_d114"
FILES = REPO / "files/lmi-p2-d114"

SHA_RE = re.compile(r"[0-9a-f]{64}")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def json_at(path: Path, dotted: str) -> str:
    """Read a value from a JSON file by a '/'-free dotted path.

    Keys may themselves contain dots or slashes, so the locator uses '\\x1f'
    (unit separator) between segments in the registry to stay unambiguous.
    """
    value = json.loads(path.read_text(encoding="utf-8"))
    for segment in dotted.split("\x1f"):
        if not isinstance(value, dict) or segment not in value:
            raise KeyError(f"{path}: no key {segment!r} in {dotted!r}")
        value = value[segment]
    if not isinstance(value, str):
        raise TypeError(f"{path}: {dotted!r} is not a string")
    return value


@dataclass(frozen=True)
class Derived:
    """Class A: value == sha256(source_file); mirrored as a literal elsewhere."""

    label: str
    source_file: Path
    mirrors: tuple[Path, ...]


@dataclass(frozen=True)
class Mirrored:
    """Class B: a built-artifact value; canonical site + files that must copy it."""

    label: str
    canonical_file: Path
    canonical_locator: str  # JSON dotted path (unit-separated segments)
    mirrors: tuple[Path, ...]


@dataclass
class Report:
    checked: int = 0
    failures: list[str] = field(default_factory=list)

    def ok(self) -> bool:
        return not self.failures


def _occurs(path: Path, value: str) -> bool:
    try:
        return value in path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeDecodeError):
        return False


def verify_derived(entry: Derived, report: Report) -> None:
    if not entry.source_file.is_file():
        report.failures.append(f"[derived] {entry.label}: missing source {entry.source_file}")
        return
    truth = sha256_file(entry.source_file)
    for mirror in entry.mirrors:
        report.checked += 1
        if not mirror.is_file():
            report.failures.append(f"[derived] {entry.label}: missing mirror {mirror}")
            continue
        if not _occurs(mirror, truth):
            # Surface which stale digest is present instead, if any obvious one.
            report.failures.append(
                f"[derived] {entry.label}: {mirror.relative_to(REPO)} does not pin "
                f"sha256({entry.source_file.relative_to(REPO)})={truth[:12]}…"
            )


def verify_mirrored(entry: Mirrored, report: Report) -> None:
    try:
        truth = json_at(entry.canonical_file, entry.canonical_locator)
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        report.failures.append(f"[mirrored] {entry.label}: canonical read failed: {error}")
        return
    if not SHA_RE.fullmatch(truth):
        report.failures.append(f"[mirrored] {entry.label}: canonical value is not a sha256")
        return
    for mirror in entry.mirrors:
        report.checked += 1
        if not mirror.is_file():
            report.failures.append(f"[mirrored] {entry.label}: missing mirror {mirror}")
            continue
        if not _occurs(mirror, truth):
            report.failures.append(
                f"[mirrored] {entry.label}: {mirror.relative_to(REPO)} does not contain the "
                f"canonical value {truth[:12]}… from "
                f"{entry.canonical_file.relative_to(REPO)}"
            )


def registry() -> tuple[list[Derived], list[Mirrored]]:
    us = "\x1f"

    derived = [
        # files/* payloads -> source-lock is the first consumer; the injector and
        # the generated overlay copy the same digests.
        Derived("session script", FILES / "lmi-p2-d114-session",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("weston.ini", FILES / "lmi-p2-d114-weston.ini",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("greetd.toml", FILES / "lmi-p2-d114-greetd.toml",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("greetd.confd", FILES / "lmi-p2-d114-greetd.confd",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("config-lifecycle", FILES / "lmi-p2-d114-config-lifecycle",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("post-install", FILES / "device-xiaomi-lmi-terminal.post-install",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("post-upgrade", FILES / "device-xiaomi-lmi-terminal.post-upgrade",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        Derived("pre-deinstall", FILES / "device-xiaomi-lmi-terminal.pre-deinstall",
                (CONFIG / "source-lock.json", CONFIG / "generated-overlay.json",
                 SCRIPTS / "inject_rootfs_candidate.sh")),
        # lock-chain: each lock JSON's digest is pinned in the next stage.
        Derived("source-lock.json", CONFIG / "source-lock.json",
                (SCRIPTS / "assemble_userdata_image.py", SCRIPTS / "deploy_userdata.py")),
        Derived("candidate-rebuild-lock.json", CONFIG / "candidate-rebuild-lock.json",
                (SCRIPTS / "inject_rootfs_candidate.sh", CONFIG / "injection-policy-lock.json")),
        Derived("injector-runtime-lock.json", CONFIG / "injector-runtime-lock.json",
                (SCRIPTS / "inject_rootfs_candidate.sh", CONFIG / "injection-policy-lock.json")),
        Derived("apk-build-attestation.json", CONFIG / "apk-build-attestation.json",
                (SCRIPTS / "inject_rootfs_candidate.sh", CONFIG / "injection-policy-lock.json")),
        Derived("injection-policy-lock.json", CONFIG / "injection-policy-lock.json",
                (SCRIPTS / "assemble_userdata_image.py",)),
        Derived("sparse-tools-lock.json", CONFIG / "sparse-tools-lock.json",
                (SCRIPTS / "assemble_userdata_image.py",)),
        Derived("physical-userdata-mapping.json", CONFIG / "physical-userdata-mapping.json",
                (SCRIPTS / "deploy_userdata.py", SCRIPTS / "deploy_userdata_wsl.py",
                 SCRIPTS / "postwrite_revalidate.py")),
        Derived("userdata-deploy-policy-lock-r1.json", CONFIG / "userdata-deploy-policy-lock-r1.json",
                (SCRIPTS / "deploy_userdata.py",)),
        Derived("injector script", SCRIPTS / "inject_rootfs_candidate.sh",
                (SCRIPTS / "launch_inject_rootfs_candidate.sh", CONFIG / "injection-policy-lock.json")),
        Derived("deploy_userdata_helper.ps1", SCRIPTS / "deploy_userdata_helper.ps1",
                (SCRIPTS / "deploy_userdata.py", SCRIPTS / "postwrite_revalidate.py")),
    ]

    kbd = f"runtime{us}component_sha256{us}/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"
    term = f"runtime{us}component_sha256{us}/usr/libexec/lmi-p2-d114/weston-terminal-sixrow"
    weston = f"runtime{us}component_sha256{us}/usr/bin/weston"
    libweston = f"runtime{us}component_sha256{us}/usr/lib/libweston-14.so.0.0.2"
    sl = CONFIG / "source-lock.json"

    mirrored = [
        # The exact drift that black-screened the device: the session script
        # sha256-validates its live keyboard/terminal children against these.
        Mirrored("keyboard binary", sl, kbd,
                 (FILES / "lmi-p2-d114-session", SCRIPTS / "inject_rootfs_candidate.sh",
                  SCRIPTS / "source_lock.py")),
        Mirrored("terminal binary", sl, term,
                 (FILES / "lmi-p2-d114-session", SCRIPTS / "inject_rootfs_candidate.sh",
                  SCRIPTS / "source_lock.py")),
        Mirrored("weston binary", sl, weston, (SCRIPTS / "source_lock.py",)),
        Mirrored("libweston", sl, libweston, (SCRIPTS / "source_lock.py",)),
        # Built apks + signing key hand-copied across the injection attestation chain.
        Mirrored("P2 apk", CONFIG / "apk-build-attestation.json",
                 f"artifact{us}apk_sha256",
                 (SCRIPTS / "inject_rootfs_candidate.sh", CONFIG / "injection-policy-lock.json")),
        Mirrored("apk signing key", CONFIG / "injection-policy-lock.json",
                 f"input{us}keys{us}p2_sha256",
                 (SCRIPTS / "inject_rootfs_candidate.sh", CONFIG / "apk-build-attestation.json")),
    ]
    return derived, mirrored


def verify() -> Report:
    derived, mirrored = registry()
    report = Report()
    for entry in derived:
        verify_derived(entry, report)
    for entry in mirrored:
        verify_mirrored(entry, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("verify",), nargs="?", default="verify")
    parser.parse_args(argv)
    report = verify()
    if report.ok():
        print(f"hash consistency: OK ({report.checked} cross-file pins verified)")
        return 0
    print(f"hash consistency: FAILED ({len(report.failures)} drift(s))", file=sys.stderr)
    for failure in report.failures:
        print(f"  - {failure}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
