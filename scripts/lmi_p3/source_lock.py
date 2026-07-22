"""Strict, fail-closed parser for the lmi P3 source-only input lock."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import stat
from typing import Any


SCHEMA = "lmi-p3-audio-source-lock/v2"
STATUS = "host-source-only-candidate"

EXPECTED_BASELINE = {
    "audio_implementation": "built-in-vendor-techpack-apr-kona-tfa9874",
    "device_dependency": "device-xiaomi-lmi=1-r107",
    "kernel_change_policy": "no-kernel-changes",
    "kernel_dependency": "linux-xiaomi-lmi=4.19.325-r8",
    "kernel_apk_sha256": "67cbc5a543b425d3602ffa33b722fbf0379dcdbf184c5996c960576f16c91610",
    "pmaports_commit": "6fb3a1e5eb21c809891645a2ba5ae11fa788e032",
    "rootctl_sha256": "0a9ad28b21dd5adc66304f54f1ebaf6b0fd1876cf206f7583cd8fa1465e3f239",
    "rootctl_sudoers_sha256": "8b74be55d83c2e77723911aaf65216c68bbb829d99a73167295577147d19f02d",
    "running_kernel_release": "4.19.325-cip128-st12-perf",
    "sudoers_sha256": "1bca048389b53b5d6ca5690eabe05580a334f05d793684fad37c8b6840fcd303",
    "track": "p1-p2-composable-source",
}
EXPECTED_DEPENDENCIES = [
    "!adsp-audio",
    "!adsp-audio-openrc",
    "alsa-utils",
    "device-xiaomi-lmi=1-r107",
    "linux-xiaomi-lmi=4.19.325-r8",
    "openrc",
    "pd-mapper",
    "rmtfs",
    "tqftpserv",
]
EXPECTED_PACKAGE = {
    "arch": "aarch64",
    "name": "device-xiaomi-lmi-audio",
    "pkgrel": 0,
    "pkgver": "0.2.0",
    "status": STATUS,
}
EXPECTED_RUNTIME = {
    "allowed_subsystem_names": [
        "a650_zap",
        "adsp",
        "cdsp",
        "cvpss",
        "esoc0",
        "ipa_fws",
        "ipa_uc",
        "npu",
        "slpi",
        "spss",
        "venus",
        "wlan",
    ],
    "attempt_latch": "/run/lmi-p3/adsp-boot-attempted",
    "boot_control": "/sys/kernel/boot_adsp/boot",
    "boot_control_metadata": "0:0:220:regular file",
    "confirmation": "lmi-p3:boot-adsp=1",
    "deviceinfo_codename": "xiaomi-lmi",
    "deviceinfo_dtb": "qcom/kona-v2.1-lmi",
    "dt_compatible": ["qcom,kona-mtp", "qcom,kona", "qcom,mtp"],
    "dt_model": "Qualcomm Technologies, Inc. xiaomi lmi",
    "firmware_inventory": "/etc/lmi-p3/adsp-firmware.inventory",
    "firmware_manifest_schema": "lmi-p3-adsp-firmware-inventory/v1",
    "firmware_provenance": "/etc/lmi-p3/adsp-firmware.provenance",
    "firmware_provenance_schema": "lmi-p3-adsp-firmware-provenance/v1",
    "firmware_review_status": "unverified-blocked",
    "firmware_source_root": "/mnt/vendor/firmware_mnt/image",
    "ordering_directive": "need",
    "postcheck_attempts": 50,
    "postcheck_interval_seconds": "0.1",
    "postcheck_state": "ONLINE",
    "prewrite_state": "OFFLINE",
    "probe_default": "readonly-static-only",
    "probe_private_archive_directory": "/var/log/lmi-p3",
    "probe_private_file_mode": "0600",
    "probe_shareable_suffix": ".redacted",
    "probe_stdout": "redacted-only",
    "required_started_services": [
        "lmi-firmware-mount",
        "lmi-qrtr-ns",
        "pd-mapper",
        "rmtfs",
        "tqftpserv",
    ],
    "route_guard": "/usr/libexec/lmi-p3-route-guard",
    "runlevel_enablement": False,
    "runtime_directory": "/run/lmi-p3",
    "subsystem_bus": "/sys/bus/msm_subsys/devices",
    "subsystem_firmware_name": "adsp",
    "subsystem_name": "adsp",
    "transition_lock": "/run/lmi-p3/adsp-transition.lock",
}
EXPECTED_DISTRIBUTION = {
    "proprietary_firmware_included": False,
    "ucm_profile_included": False,
}
EXPECTED_SOURCE_FILES = {
    "device-xiaomi-lmi-audio.post-install",
    "lmi-adsp-boot.confd",
    "lmi-adsp-boot.initd",
    "lmi-adsp-control",
    "lmi-audio-probe",
    "lmi-p3-route-guard",
}

_TOP_FIELDS = {
    "baseline",
    "dependencies",
    "distribution",
    "package",
    "runtime",
    "schema",
    "source_files",
}
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class LockError(ValueError):
    """A P3 input or generation policy violation."""


@dataclass(frozen=True)
class SourceLock:
    """A validated P3 lock plus the digest of its exact serialized bytes."""

    path: Path
    value: dict[str, Any]
    sha256: str

    @property
    def release_eligible(self) -> bool:
        return False

    def require_release_ready(self) -> None:
        raise LockError(
            "P3 is a host/source-only candidate; hardware evidence and approvals are unresolved"
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
        raise LockError(f"{label} does not match the reviewed P3 contract")


def _read_stable_regular(path: Path) -> bytes:
    try:
        before = path.lstat()
        payload = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise LockError(f"could not read P3 source lock: {error}") from None
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_ino != after.st_ino
        or before.st_dev != after.st_dev
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
        or before.st_nlink != 1
        or before.st_mode & 0o022
    ):
        raise LockError("P3 source lock must be one stable, non-writable regular file")
    return payload


def load_source_lock(path: Path) -> SourceLock:
    """Load only the exact reviewed P3 schema; reject every ambiguous input."""

    payload = _read_stable_regular(path)
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise LockError(f"invalid P3 source lock JSON: {error}") from None
    if not isinstance(value, dict) or set(value) != _TOP_FIELDS:
        raise LockError("P3 source lock top-level fields mismatch")
    if value["schema"] != SCHEMA:
        raise LockError(f"unsupported P3 source lock schema: {value['schema']!r}")
    _exact_object(value["baseline"], EXPECTED_BASELINE, "baseline")
    if not _same_json_value(value["dependencies"], EXPECTED_DEPENDENCIES):
        raise LockError("dependencies do not match the reviewed P3 package set")
    _exact_object(value["package"], EXPECTED_PACKAGE, "package")
    _exact_object(value["runtime"], EXPECTED_RUNTIME, "runtime")
    _exact_object(value["distribution"], EXPECTED_DISTRIBUTION, "distribution")

    sources = value["source_files"]
    if not isinstance(sources, dict) or set(sources) != EXPECTED_SOURCE_FILES:
        raise LockError("source_files must be the exact P3 source set")
    for name, digest in sources.items():
        if not isinstance(name, str) or Path(name).name != name:
            raise LockError(f"unsafe P3 source filename: {name!r}")
        if not isinstance(digest, str) or _SHA256_RE.fullmatch(digest) is None:
            raise LockError(f"invalid sha256 for P3 source file: {name}")

    return SourceLock(
        path=path,
        value=value,
        sha256=hashlib.sha256(payload).hexdigest(),
    )
