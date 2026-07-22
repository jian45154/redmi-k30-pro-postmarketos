"""Strict parser for the D110/D114 persistent terminal source lock."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any


SCHEMA = "lmi-p2-d114-terminal-source-lock/v1"
STATUS = "private-d114-hardware-test-candidate"

EXPECTED_BASELINE = {
    "authority": "current-wsl-project-only",
    "boot_sha256": "2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487",
    "boot_size": 52944896,
    "boot_uuid": "d4f78f7d-f5b5-4edc-94d5-ba5e6c877888",
    "device_package": "device-xiaomi-lmi=1-r144",
    "frozen_installed_db_sha256": "bfd4503236d82deb0fafdd6c483ba19d1a2217d977b6a9b05536888053f3a1b7",
    "frozen_world_sha256": "d2db0f373a095db97676afe6c088ba98cc9ebdf78c3576cae6a3d17b053d02eb",
    "gpt_logical_sector_size": 4096,
    "installed_kernel_package": "linux-xiaomi-lmi=4.19.325-r15",
    "project_head_at_review": "4059e3a1ff4b04257b257feb8357d3b0d1b00006",
    "root_partition_sector_count": 713728,
    "root_partition_start_sector": 124928,
    "root_uuid": "f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f",
    "running_kernel_release": "4.19.325-cip128-st12-perf",
    "transfer_manifest_sha256": "3b68dbcbb00c43ebf0560a89e542ac20a90e6b2a1b888d50fe9cb45ef9b46fe7",
    "userdata_raw_sha256": "b108f581426c644319396fe5d5cdafd2f490151f2ac2b63bd2ef5275567d0721",
    "userdata_raw_size": 3436183552,
    "userdata_sparse_sha256": "79276015be7d79ed77494b4bd3aec9e8a0f09325c53c4802eef54fede1022cbc",
    "userdata_sparse_size": 2269399372,
}

EXPECTED_DEPENDENCIES = [
    "device-xiaomi-lmi=1-r144",
    "greetd=0.10.3-r11",
    "greetd-openrc=0.10.3-r11",
    "greetd-phrog=0.53.0-r0",
    "libseat=0.9.3-r1",
    "libweston=14.0.2-r5",
    "linux-xiaomi-lmi=4.19.325-r15",
    "lmi-weston-sixrow-clients=14.0.2-r2",
    "openrc=0.63.2-r0",
    "seatd=0.9.3-r1",
    "seatd-openrc=0.9.3-r1",
    "weston=14.0.2-r5",
    "weston-backend-drm=14.0.2-r5",
    "weston-shell-desktop=14.0.2-r5",
    "weston-terminal=14.0.2-r5",
]

EXPECTED_PACKAGE = {
    "abuild_last_commit": "uncommitted-p2-d114-source-lock-v4",
    "arch": "noarch",
    "maintainer": "lmi P2 maintainers <noreply@example.invalid>",
    "name": "device-xiaomi-lmi-terminal",
    "packager": "lmi P2 private builder <noreply@example.invalid>",
    "pkgrel": 2,
    "pkgver": "0.1.0",
    "release_eligible": False,
    "source_date_epoch": 1784522705,
    "status": STATUS,
}

EXPECTED_RUNTIME = {
    "account": "lmi",
    "account_gid": 10000,
    "account_home": "/home/lmi",
    "account_shell": "/bin/ash",
    "account_uid": 10000,
    "backend": "drm-backend.so",
    "component_sha256": {
        "/usr/bin/seatd": "64d9099f9c7974e4a08b93f9f117eeaacbfebd0d75d6810ed80f8c4f38761be8",
        "/usr/bin/weston": "191703aa8da1d965fe7a2e7b4ec7ad7316c484cdc26ac77f31c015d6ee4bd45e",
        "/usr/lib/libweston-14.so.0.0.2": "2c7565771a3e4097cdaf3e240d5e1dece2cdff78227967153df6088164bde9cd",
        "/usr/lib/libweston-14/drm-backend.so": "72bdbdda9850f92dc56178075eda9be28ddad0867da1d0b50db22bb304aa64ba",
        "/usr/lib/weston/desktop-shell.so": "8411118894008448b2d18875c069b7e79588e1ed6526dc49e4831e2cb20caf3f",
        "/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow": "d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a",
        "/usr/libexec/lmi-p2-d114/weston-terminal-sixrow": "6602f7ac8e0c11892eec1d9db0411397e95f704a1655b94e0885a1220962a8cf",
        "/usr/sbin/greetd": "91aa06de3923cd0c77b95331bce869d7e7e073d09548d9974e725713fabf9497",
    },
    "connector": "DSI-1",
    "greetd_active_confd_sha256": "5be125043d60ff2d3b98624191769efd06320b81262b5552489d93076e85e6a4",
    "greetd_baseline_confd_sha256": "6523d36fa3490b4f518184bb0d5a1dd025f14e93ead2b0f9a80f82d685a953f0",
    "greetd_config": "/etc/lmi-p2-d114/greetd.toml",
    "greetd_config_sha256": "d576c1f5398bc3820a0ce2361e2b0b187d5c6263b1cf42c8f121d262309de899",
    "greetd_initd_sha256": "94148320f8dfaa4e20bb056994f346f12c0b94065a910abe3ee6be68580eb981",
    "greetd_rc_need": "lmi-seatd",
    "greetd_runfile": "/run/greetd-lmi-p2-d114.run",
    "greetd_source_profile": False,
    "keyboard_child_required": True,
    "keyboard_path": "/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow",
    "power_panel_initd_sha256": "7ac8bde1651001200e141db0c21c30404a45fdd04ea525e452ea3760aedc8bd9",
    "readiness_timeout_seconds": 15,
    "renderer": "pixman",
    "runlevel_links_modified": False,
    "seat_service": "lmi-seatd",
    "seatd_socket_mode": 770,
    "seatd_wrapper_sha256": "a61240ce2629f80e58b86653f77061c0f739e6eadd4cc6e6eb3726932001eced",
    "session_backoff_seconds": 5,
    "session_lock": "/run/user/10000/lmi-p2-d114-session.lock",
    "shell": "desktop-shell.so",
    "socket": "wayland-lmi-p2-d114",
    "system_takeover_lock": "/run/lmi-display-takeover.lock",
    "terminal_child_required": True,
    "terminal_path": "/usr/libexec/lmi-p2-d114/weston-terminal-sixrow",
    "tty": 7,
    "weston_config_sha256": "b54d838ccf435ee41dbd55f5aab245fd68bb65ab19c784a694375f001a9763a2",
}

EXPECTED_SOURCE_FILES = {
    "device-xiaomi-lmi-terminal.post-install",
    "device-xiaomi-lmi-terminal.post-upgrade",
    "device-xiaomi-lmi-terminal.pre-deinstall",
    "lmi-p2-d114-config-lifecycle",
    "lmi-p2-d114-greetd.confd",
    "lmi-p2-d114-greetd.toml",
    "lmi-p2-d114-session",
    "lmi-p2-d114-weston.ini",
}

_TOP_FIELDS = {
    "baseline",
    "dependencies",
    "package",
    "runtime",
    "schema",
    "source_files",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class LockError(ValueError):
    """A D114 P2 input or generation policy violation."""


@dataclass(frozen=True)
class SourceLock:
    """A validated source lock and the digest of its exact bytes."""

    path: Path
    value: dict[str, Any]
    sha256: str

    @property
    def release_eligible(self) -> bool:
        return False

    def require_release_ready(self) -> None:
        raise LockError(
            "D114 P2 remains a private hardware-test candidate; persistent-image and physical-input evidence are pending"
        )


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LockError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _same_json_value(value: Any, expected: Any) -> bool:
    if type(value) is not type(expected):
        return False
    if isinstance(expected, dict):
        return set(value) == set(expected) and all(
            _same_json_value(value[key], expected[key]) for key in expected
        )
    if isinstance(expected, list):
        return len(value) == len(expected) and all(
            _same_json_value(item, wanted)
            for item, wanted in zip(value, expected, strict=True)
        )
    return bool(value == expected)


def _exact_object(value: Any, expected: dict[str, Any], label: str) -> None:
    if not _same_json_value(value, expected):
        raise LockError(f"{label} does not match the reviewed D114 P2 contract")


def _read_stable_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise LockError(f"could not read D114 P2 source lock: {error}") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_ino != after.st_ino
        or before.st_dev != after.st_dev
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_nlink != 1
        or before.st_mode & 0o022
    ):
        raise LockError("D114 P2 source lock must be one stable, non-writable regular file")
    return payload


def load_source_lock(path: Path) -> SourceLock:
    """Load only the exact reviewed D110/D114 terminal contract."""

    payload = _read_stable_regular(path)
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LockError(f"invalid D114 P2 source lock JSON: {error}") from None
    if not isinstance(value, dict) or set(value) != _TOP_FIELDS:
        raise LockError("D114 P2 source lock top-level fields mismatch")
    if value["schema"] != SCHEMA:
        raise LockError(f"unsupported D114 P2 source lock schema: {value['schema']!r}")
    _exact_object(value["baseline"], EXPECTED_BASELINE, "baseline")
    if not _same_json_value(value["dependencies"], EXPECTED_DEPENDENCIES):
        raise LockError("dependencies do not match the reviewed D114 package set")
    _exact_object(value["package"], EXPECTED_PACKAGE, "package")
    _exact_object(value["runtime"], EXPECTED_RUNTIME, "runtime")

    sources = value["source_files"]
    if not isinstance(sources, dict) or set(sources) != EXPECTED_SOURCE_FILES:
        raise LockError("source_files must be the exact D114 P2 source set")
    for name, digest in sources.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise LockError(f"unsafe D114 P2 source filename: {name!r}")
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise LockError(f"invalid sha256 for D114 P2 source file: {name}")

    return SourceLock(
        path=path,
        value=value,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
