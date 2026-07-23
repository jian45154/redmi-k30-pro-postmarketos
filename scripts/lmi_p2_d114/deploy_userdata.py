#!/usr/bin/env python3
"""Fail-closed D114 P2 userdata-only deployment gate.

``local-audit`` never starts PowerShell.  ``preflight`` and ``postwrite`` are
read-only device checks.  ``preflight`` performs the heavy Windows-side input
audit and prepares a hash-bound NTFS candidate.  ``execute`` permits one fixed
command while Python continues to hold every approved repository input and the
PowerShell helper locks the small Windows contract plus that prepared candidate.
``approve`` creates a short-lived claim from a fresh
preflight; ``execute`` durably consumes that claim before invoking the helper.

No mode boots, reboots, erases, formats, forces, converts, or selects any
partition other than physical ``userdata``.  There is no automatic or
same-claim retry path.  Any later attempt requires review of the unresolved
result, a new exact approval, and a new one-use claim.
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import subprocess
import tempfile
import time
from typing import Any, BinaryIO, Callable, Mapping
import zipfile


REPO = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("deploy_userdata_helper.ps1")

PROFILE_SCHEMA = "lmi-p2-d114-userdata-deploy-profile/v2"
ASSEMBLY_SCHEMA = "lmi-p2-d114-userdata-assembly-attestation/v1"
MAPPING_SCHEMA = "lmi-d114-physical-userdata-mapping/v2"
REPORT_SCHEMA = "lmi-p2-d114-userdata-deploy-report/v6"
HELPER_SCHEMA = "lmi-p2-d114-userdata-powershell-result/v5"
DEPLOY_POLICY_SCHEMA = "lmi-p2-d114-userdata-deploy-policy-lock/v4"
APPROVAL_SCHEMA = "lmi-p2-d114-userdata-one-use-approval/v4"
INTENT_SCHEMA = "lmi-p2-d114-userdata-preattempt-intent/v5"
INTENT_TRANSITION_SCHEMA = "lmi-p2-d114-userdata-intent-transition/v1"
INTENT_TERMINAL_SCHEMA = "lmi-p2-d114-userdata-intent-terminal/v1"
RESULT_PREFIX = b"LMI_P2_D114_RESULT_JSON_BASE64="
OUTER_TIMEOUT_SECONDS = 1800
APPROVAL_TTL_SECONDS = 120
RETRY_SCOPE = "no-automatic-or-same-claim-retry"
UNKNOWN_FOLLOWUP = (
    "review-unknown-then-require-new-exact-immediate-user-approval-and-new-claim"
)

FASTBOOT_PATH = "localappdata/lmi-p2-d114/fastboot-r37.0.0/fastboot.exe"
FASTBOOT_SIZE = 2_199_704
FASTBOOT_SHA256 = "dd55fef77ab2753b6423f37f39d91cb00ce53ab4539a2431577f07c4abcaa32a"
FASTBOOT_DLLS = (
    ("AdbWinApi.dll", 108_184, "120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965"),
    ("AdbWinUsbApi.dll", 73_368, "6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60"),
)
FASTBOOT_ARCHIVE_SHA256 = "4fe305812db074cea32903a489d061eb4454cbc90a49e8fea677f4b7af764918"
FASTBOOT_ARCHIVE_OFFICIAL_SHA1 = "f29bfb58d0d6f9a57d7dbcba6cc259f9ca6f58f1"
FASTBOOT_ARCHIVE_SIZE = 8_092_164
FASTBOOT_ARCHIVE_URL = "https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip"
FASTBOOT_ARCHIVE_PATH = (
    "private/lmi-p1/recovery/d110-d114/third-party/platform-tools-r37.0.0/"
    "platform-tools_r37.0.0-win.zip"
)
FASTBOOT_ARCHIVE_ENTRY_COUNT = 15

D110_BOOT_SHA256 = "2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487"
D110_BOOT_SIZE = 52_944_896
D110_BOOT_UUID = "d4f78f7d-f5b5-4edc-94d5-ba5e6c877888"
D114_ROOT_UUID = "f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f"
D114_RAW_SHA256 = "61ca69e6c241a92ad86539ffeebc0d4ef296572709445604ce26a78648f27bf6"
D114_RAW_SIZE = 3_339_714_560
D114_SPARSE_SHA256 = "e8a30dc37cb4b75508d89725a9603bc15a985f4e51af77384e8d43c2928f8d68"
D114_SPARSE_SIZE = 2_192_400_084
P2_EXT4_SIZE = 2_826_960_896
SOURCE_LOCK_SHA256 = "0046a432b961fef3f1c5900ee9b4e26351e87d87bd058ed4824f897a2def04fb"
MAPPING_SHA256 = "59f27854ac595a9b615bddeb91aa72e6bf1e0dacd9341cda2783a19bb050014f"
MAPPING_SIZE = 3879
DEPLOY_POLICY_SHA256 = "314b05a264107cc7dcbbbdb5e539f1075786a424a90707389a9010675a62ddc6"
DEPLOY_POLICY_SIZE = 6667
HELPER_SHA256 = "759aa7e6f336cb9c3fcf9aff45a224886654b5f77d5fa6a139640e9a19969339"
HELPER_SIZE = 94_276
USERDATA_CAPACITY = 114_898_743_296
MIN_BATTERY_MV = 3800
MIN_MAX_DOWNLOAD_SIZE = D110_BOOT_SIZE

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
SPARSE_MAGIC = 0xED26FF3A
SPARSE_HEADER = struct.Struct("<I4H4I")
CHUNK_HEADER = struct.Struct("<2H2I")
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4


class DeployError(RuntimeError):
    """A deployment input, device gate, or evidence publication failure."""


class ExecuteIntentIndeterminate(DeployError):
    """A durable execute intent exists but no trustworthy outcome can be reported."""


class IntentJournalUntrusted(DeployError):
    """The durable initial intent record cannot be authenticated."""

    def __init__(
        self,
        message: str,
        *,
        observed_sha256: str | None = None,
        observed_size: int | None = None,
    ) -> None:
        super().__init__(message)
        self.observed_sha256 = observed_sha256
        self.observed_size = observed_size


@dataclass(frozen=True)
class Contract:
    """Pinned production contract; tests may inject a smaller in-memory one."""

    source_lock_sha256: str = SOURCE_LOCK_SHA256
    mapping_sha256: str = MAPPING_SHA256
    mapping_size: int = MAPPING_SIZE
    deploy_policy_sha256: str = DEPLOY_POLICY_SHA256
    deploy_policy_size: int = DEPLOY_POLICY_SIZE
    helper_sha256: str = HELPER_SHA256
    helper_size: int = HELPER_SIZE
    d110_boot_sha256: str = D110_BOOT_SHA256
    d110_boot_size: int = D110_BOOT_SIZE
    d110_boot_uuid: str = D110_BOOT_UUID
    root_uuid: str = D114_ROOT_UUID
    baseline_raw_sha256: str = D114_RAW_SHA256
    baseline_raw_size: int = D114_RAW_SIZE
    rollback_sparse_sha256: str = D114_SPARSE_SHA256
    rollback_sparse_size: int = D114_SPARSE_SIZE
    p2_ext4_size: int = P2_EXT4_SIZE
    logical_sector_size: int = 4096
    disk_lbas: int = 815_360
    p1_lbas: tuple[int, int] = (2048, 124_927)
    p2_lbas: tuple[int, int] = (124_928, 815_103)
    p2_byte_range: tuple[int, int] = (511_705_088, 3_338_665_984)
    suffix_bytes: int = 1_048_576
    userdata_capacity: int = USERDATA_CAPACITY


PRODUCTION = Contract()


@dataclass
class HeldFile:
    path: Path
    descriptor: int
    identity: tuple[int, ...]
    size: int
    sha256: str

    def close(self) -> None:
        os.close(self.descriptor)


@dataclass
class Audit:
    repo_root: Path
    profile_path: Path
    profile: dict[str, Any]
    profile_sha256: str
    held: dict[str, HeldFile]
    source_lock: dict[str, Any]
    assembly: dict[str, Any]
    mapping: dict[str, Any]
    identity_policy: dict[str, Any]
    deploy_policy: dict[str, Any]

    def close(self) -> None:
        for item in reversed(tuple(self.held.values())):
            item.close()


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DeployError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeployError(f"invalid {label} JSON: {error}") from None
    if not isinstance(value, dict):
        raise DeployError(f"{label} must be a JSON object")
    return value


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise DeployError(f"{label} fields mismatch")
    return value


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise DeployError(f"{label} must be a nonempty string")
    return value


def _integer(value: Any, label: str, *, minimum: int = 1) -> int:
    if type(value) is not int or value < minimum:
        raise DeployError(f"{label} must be an integer >= {minimum}")
    return value


def _sha(value: Any, label: str) -> str:
    result = _string(value, label)
    if SHA256_RE.fullmatch(result) is None:
        raise DeployError(f"{label} is not a lowercase SHA-256")
    return result


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_nlink,
        st.st_uid,
        st.st_gid,
        st.st_size,
        st.st_mtime_ns,
        st.st_ctime_ns,
    )


def _check_real_ancestors(path: Path, root: Path, label: str) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        raise DeployError(f"{label} escapes the repository root") from None
    current = root
    for component in relative.parts[:-1]:
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise DeployError(f"cannot inspect {label} ancestor") from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise DeployError(f"{label} has a symlink or non-directory ancestor")


def _open_held(path: Path, root: Path, label: str) -> HeldFile:
    path = path.absolute()
    root = root.absolute()
    _check_real_ancestors(path, root, label)
    try:
        before = path.lstat()
    except OSError as error:
        raise DeployError(f"cannot inspect {label}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or before.st_uid != os.geteuid()
        or before.st_size <= 0
    ):
        raise DeployError(
            f"{label} must be a user-owned, single-link, non-writable regular file"
        )
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DeployError(f"cannot safely open {label}") from error
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise DeployError(f"{label} changed while opening")
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(4 * 1024 * 1024, remaining))
            if not chunk:
                raise DeployError(f"{label} was truncated while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise DeployError(f"{label} grew while hashing")
        if _identity(os.fstat(descriptor)) != _identity(opened):
            raise DeployError(f"{label} changed while hashing")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return HeldFile(path, descriptor, _identity(opened), opened.st_size, digest.hexdigest())
    except BaseException:
        os.close(descriptor)
        raise


def _held_bytes(item: HeldFile, maximum: int, label: str) -> bytes:
    if item.size > maximum:
        raise DeployError(f"{label} is too large")
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    value = bytearray()
    while len(value) < item.size:
        chunk = os.read(item.descriptor, item.size - len(value))
        if not chunk:
            raise DeployError(f"{label} became unreadable")
        value.extend(chunk)
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    return bytes(value)


def _relative_path(value: Any, label: str) -> PurePosixPath:
    raw = _string(value, label)
    if "\\" in raw or "\0" in raw:
        raise DeployError(f"{label} is not a canonical repository-relative path")
    path = PurePosixPath(raw)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise DeployError(f"{label} is not a canonical repository-relative path")
    if path.as_posix() != raw:
        raise DeployError(f"{label} is not canonical")
    return path


def _artifact(value: Any, label: str, *, sparse: bool = False) -> dict[str, Any]:
    keys = {"path", "sha256", "size"}
    if sparse:
        keys |= {"logical_size", "roundtrip_raw_sha256", "representation"}
    result = _exact_keys(value, keys, label)
    _relative_path(result["path"], f"{label}.path")
    _sha(result["sha256"], f"{label}.sha256")
    _integer(result["size"], f"{label}.size")
    if sparse:
        _integer(result["logical_size"], f"{label}.logical_size")
        _sha(result["roundtrip_raw_sha256"], f"{label}.roundtrip_raw_sha256")
        if result["representation"] != "android-sparse":
            raise DeployError(f"{label} must be a prebuilt Android sparse image")
    return result


def _parse_profile(value: dict[str, Any], contract: Contract) -> None:
    top = _exact_keys(
        value,
        {"artifacts", "compatibility", "device", "execution", "fastboot", "profile_id", "schema"},
        "deployment profile",
    )
    if top["schema"] != PROFILE_SCHEMA:
        raise DeployError("unsupported deployment profile schema")
    if not isinstance(top["profile_id"], str) or ID_RE.fullmatch(top["profile_id"]) is None:
        raise DeployError("invalid deployment profile id")

    artifacts = _exact_keys(
        top["artifacts"],
        {
            "assembly_attestation",
            "candidate",
            "candidate_raw",
            "deploy_policy_lock",
            "p2_injection_attestation",
            "physical_mapping_evidence",
            "rollback",
            "source_lock",
        },
        "artifacts",
    )
    _artifact(artifacts["candidate"], "candidate", sparse=True)
    candidate_raw = _artifact(artifacts["candidate_raw"], "candidate_raw")
    _artifact(artifacts["rollback"], "rollback", sparse=True)
    _artifact(artifacts["source_lock"], "source_lock")
    assembly = _artifact(artifacts["assembly_attestation"], "assembly_attestation")
    injection = _artifact(
        artifacts["p2_injection_attestation"], "p2_injection_attestation"
    )
    mapping = _artifact(artifacts["physical_mapping_evidence"], "physical_mapping_evidence")
    deploy_policy = _artifact(artifacts["deploy_policy_lock"], "deploy_policy_lock")
    if artifacts["source_lock"]["sha256"] != contract.source_lock_sha256:
        raise DeployError("source lock is not the reviewed D114 contract")
    if mapping["sha256"] != contract.mapping_sha256 or mapping["size"] != contract.mapping_size:
        raise DeployError("physical userdata mapping evidence identity mismatch")
    if (
        deploy_policy["sha256"] != contract.deploy_policy_sha256
        or deploy_policy["size"] != contract.deploy_policy_size
    ):
        raise DeployError("deploy policy lock identity mismatch")
    if assembly["size"] > 4 * 1024 * 1024:
        raise DeployError("assembly attestation is unexpectedly large")
    if injection["size"] > 4 * 1024 * 1024:
        raise DeployError("P2 injection attestation is unexpectedly large")
    candidate = artifacts["candidate"]
    if (
        candidate["logical_size"] != contract.baseline_raw_size
        or
        candidate_raw["size"] != candidate["logical_size"]
        or candidate_raw["sha256"] != candidate["roundtrip_raw_sha256"]
    ):
        raise DeployError("candidate raw and sparse roundtrip identities differ")
    rollback = artifacts["rollback"]
    if (
        rollback["sha256"] != contract.rollback_sparse_sha256
        or rollback["size"] != contract.rollback_sparse_size
        or rollback["logical_size"] != contract.baseline_raw_size
        or rollback["roundtrip_raw_sha256"] != contract.baseline_raw_sha256
    ):
        raise DeployError("rollback is not the exact reviewed D114 sparse baseline")

    compatibility = _exact_keys(top["compatibility"], {"d110", "d114", "p2"}, "compatibility")
    d110 = _exact_keys(compatibility["d110"], {"boot_sha256", "boot_size", "boot_uuid", "root_uuid"}, "compatibility.d110")
    if d110 != {
        "boot_sha256": contract.d110_boot_sha256,
        "boot_size": contract.d110_boot_size,
        "boot_uuid": contract.d110_boot_uuid,
        "root_uuid": contract.root_uuid,
    }:
        raise DeployError("D110 compatibility identity mismatch")
    d114 = _exact_keys(
        compatibility["d114"],
        {"baseline_raw_sha256", "baseline_raw_size", "logical_sector_size", "root_uuid"},
        "compatibility.d114",
    )
    if d114 != {
        "baseline_raw_sha256": contract.baseline_raw_sha256,
        "baseline_raw_size": contract.baseline_raw_size,
        "logical_sector_size": contract.logical_sector_size,
        "root_uuid": contract.root_uuid,
    }:
        raise DeployError("D114 baseline compatibility mismatch")
    p2 = _exact_keys(compatibility["p2"], {"injected_ext4_sha256", "injected_ext4_size", "root_uuid"}, "compatibility.p2")
    _sha(p2["injected_ext4_sha256"], "compatibility.p2.injected_ext4_sha256")
    if p2["injected_ext4_size"] != contract.p2_ext4_size or p2["root_uuid"] != contract.root_uuid:
        raise DeployError("P2 injected ext4 compatibility mismatch")

    device = _exact_keys(
        top["device"],
        {"expected_product", "expected_userdata_capacity", "minimum_battery_mv", "minimum_max_download_size", "partition_type", "require_soc_ok"},
        "device",
    )
    if device != {
        "expected_product": "lmi",
        "expected_userdata_capacity": contract.userdata_capacity,
        "minimum_battery_mv": MIN_BATTERY_MV,
        "minimum_max_download_size": MIN_MAX_DOWNLOAD_SIZE,
        "partition_type": "f2fs",
        "require_soc_ok": True,
    }:
        raise DeployError("device gate policy mismatch")

    execution = _exact_keys(
        top["execution"],
        {"automatic_retry", "command", "max_attempts", "operation", "partition", "write_timeout_seconds"},
        "execution",
    )
    if execution != {
        "automatic_retry": False,
        "command": ["-s", "<identity-policy-matched-device>", "flash", "userdata", "<candidate-path>"],
        "max_attempts": 1,
        "operation": "flash",
        "partition": "userdata",
        "write_timeout_seconds": 300,
    }:
        raise DeployError("execution is not the one fixed userdata command")
    fastboot = _exact_keys(top["fastboot"], {"path", "sha256", "size"}, "fastboot")
    if fastboot != {"path": FASTBOOT_PATH, "sha256": FASTBOOT_SHA256, "size": FASTBOOT_SIZE}:
        raise DeployError("fastboot is not the locked runtime-extracted Windows binary")


def _hash_zeros(digest: Any, length: int) -> None:
    zeros = bytes(1024 * 1024)
    while length:
        amount = min(length, len(zeros))
        digest.update(zeros[:amount])
        length -= amount


def _hash_fill(digest: Any, pattern: bytes, length: int) -> None:
    block = pattern * (1024 * 1024 // 4)
    while length:
        amount = min(length, len(block))
        digest.update(block[:amount])
        length -= amount


def _read_exact(stream: BinaryIO, length: int, label: str) -> bytes:
    value = stream.read(length)
    if len(value) != length:
        raise DeployError(f"sparse {label} is truncated")
    return value


def inspect_sparse(item: HeldFile, expected_logical: int, expected_roundtrip: str, label: str) -> dict[str, Any]:
    """Strictly decode and hash an Android sparse file without materializing raw."""

    stream = os.fdopen(os.dup(item.descriptor), "rb", closefd=True)
    try:
        stream.seek(0)
        header = _read_exact(stream, SPARSE_HEADER.size, f"{label} header")
        magic, major, minor, file_hdr_sz, chunk_hdr_sz, block_size, total_blocks, total_chunks, _checksum = SPARSE_HEADER.unpack(header)
        if (
            magic != SPARSE_MAGIC
            or major != 1
            or minor != 0
            or file_hdr_sz != SPARSE_HEADER.size
            or chunk_hdr_sz != CHUNK_HEADER.size
            or block_size != 4096
            or total_blocks <= 0
            or total_chunks <= 0
            or total_blocks * block_size != expected_logical
        ):
            raise DeployError(f"{label} Android sparse header mismatch")
        digest = hashlib.sha256()
        produced = 0
        counts = {"raw": 0, "fill": 0, "dont_care": 0, "crc32": 0}
        for _index in range(total_chunks):
            chunk = _read_exact(stream, CHUNK_HEADER.size, f"{label} chunk header")
            kind, reserved, chunk_blocks, total_size = CHUNK_HEADER.unpack(chunk)
            if reserved != 0 or chunk_blocks < 0 or total_size < CHUNK_HEADER.size:
                raise DeployError(f"{label} sparse chunk header mismatch")
            output_size = chunk_blocks * block_size
            data_size = total_size - CHUNK_HEADER.size
            if kind == CHUNK_RAW:
                if not chunk_blocks or data_size != output_size:
                    raise DeployError(f"{label} raw sparse chunk size mismatch")
                remaining = data_size
                while remaining:
                    payload = _read_exact(stream, min(4 * 1024 * 1024, remaining), f"{label} raw chunk")
                    digest.update(payload)
                    remaining -= len(payload)
                counts["raw"] += 1
            elif kind == CHUNK_FILL:
                if not chunk_blocks or data_size != 4:
                    raise DeployError(f"{label} fill sparse chunk size mismatch")
                _hash_fill(digest, _read_exact(stream, 4, f"{label} fill value"), output_size)
                counts["fill"] += 1
            elif kind == CHUNK_DONT_CARE:
                if not chunk_blocks or data_size != 0:
                    raise DeployError(f"{label} don't-care sparse chunk mismatch")
                _hash_zeros(digest, output_size)
                counts["dont_care"] += 1
            elif kind == CHUNK_CRC32:
                if chunk_blocks != 0 or data_size != 4:
                    raise DeployError(f"{label} CRC32 sparse chunk mismatch")
                _read_exact(stream, 4, f"{label} CRC32 value")
                counts["crc32"] += 1
            else:
                raise DeployError(f"{label} has an unknown sparse chunk type")
            produced += output_size
            if produced > expected_logical:
                raise DeployError(f"{label} sparse output exceeds the logical size")
        if produced != expected_logical or stream.read(1):
            raise DeployError(f"{label} sparse stream size mismatch")
        if stream.tell() != item.size:
            raise DeployError(f"{label} sparse stored size mismatch")
        roundtrip = digest.hexdigest()
        if roundtrip != expected_roundtrip:
            raise DeployError(f"{label} sparse roundtrip hash mismatch")
        return {"block_size": block_size, "chunks": counts, "logical_size": produced, "roundtrip_raw_sha256": roundtrip}
    finally:
        stream.close()


def _check_source_lock(value: dict[str, Any], contract: Contract) -> None:
    if value.get("schema") != "lmi-p2-d114-terminal-source-lock/v1":
        raise DeployError("source lock schema mismatch")
    baseline = value.get("baseline")
    if not isinstance(baseline, dict):
        raise DeployError("source lock baseline is missing")
    wanted = {
        "boot_sha256": contract.d110_boot_sha256,
        "boot_size": contract.d110_boot_size,
        "boot_uuid": contract.d110_boot_uuid,
        "gpt_logical_sector_size": contract.logical_sector_size,
        "root_uuid": contract.root_uuid,
        "userdata_raw_sha256": contract.baseline_raw_sha256,
        "userdata_raw_size": contract.baseline_raw_size,
        "userdata_sparse_sha256": contract.rollback_sparse_sha256,
        "userdata_sparse_size": contract.rollback_sparse_size,
    }
    if any(baseline.get(key) != expected for key, expected in wanted.items()):
        raise DeployError("source lock D110/D114 baseline mismatch")


def _check_assembly(value: dict[str, Any], profile: dict[str, Any], contract: Contract) -> None:
    if value.get("schema") != ASSEMBLY_SCHEMA:
        raise DeployError("assembly attestation schema mismatch")
    candidate = profile["artifacts"]["candidate"]
    compatibility = profile["compatibility"]
    bindings = value.get("bindings")
    if not isinstance(bindings, dict):
        raise DeployError("assembly bindings are missing")
    for field in ("source_lock_sha256", "p2_injection_attestation_sha256", "sparse_tools_lock_sha256"):
        _sha(bindings.get(field), f"assembly.bindings.{field}")
    if bindings["source_lock_sha256"] != profile["artifacts"]["source_lock"]["sha256"]:
        raise DeployError("assembly does not bind the selected source lock")
    if (
        bindings["p2_injection_attestation_sha256"]
        != profile["artifacts"]["p2_injection_attestation"]["sha256"]
    ):
        raise DeployError("assembly does not bind the selected P2 injection attestation")

    d110 = value.get("compatibility", {}).get("d110") if isinstance(value.get("compatibility"), dict) else None
    if not isinstance(d110, dict) or any(d110.get(key) != expected for key, expected in compatibility["d110"].items()):
        raise DeployError("assembly D110 compatibility mismatch")

    output = value.get("output")
    if not isinstance(output, dict) or not isinstance(output.get("raw"), dict) or not isinstance(output.get("sparse"), dict):
        raise DeployError("assembly output identities are missing")
    raw = output["raw"]
    sparse = output["sparse"]
    candidate_raw = profile["artifacts"]["candidate_raw"]
    if (
        raw.get("filename") != PurePosixPath(candidate_raw["path"]).name
        or raw.get("path") != PurePosixPath(candidate_raw["path"]).name
        or raw.get("size") != candidate_raw["size"]
        or raw.get("sha256") != candidate_raw["sha256"]
        or sparse.get("filename") != PurePosixPath(candidate["path"]).name
        or sparse.get("path") != PurePosixPath(candidate["path"]).name
        or sparse.get("size") != candidate["size"]
        or sparse.get("sha256") != candidate["sha256"]
        or sparse.get("logical_size") != candidate["logical_size"]
    ):
        raise DeployError("assembly output does not match the selected candidate")

    input_value = value.get("input")
    if not isinstance(input_value, dict) or not isinstance(input_value.get("baseline"), dict) or not isinstance(input_value.get("p2"), dict):
        raise DeployError("assembly input identities are missing")
    baseline, p2 = input_value["baseline"], input_value["p2"]
    if baseline.get("size") != contract.baseline_raw_size or baseline.get("sha256") != contract.baseline_raw_sha256:
        raise DeployError("assembly baseline identity mismatch")
    filesystem = p2.get("filesystem")
    filesystem_blocks = (
        filesystem.get("block_count") if isinstance(filesystem, dict) else None
    )
    if (
        p2.get("size") != contract.p2_ext4_size
        or p2.get("sha256") != compatibility["p2"]["injected_ext4_sha256"]
        or p2.get("uuid") != contract.root_uuid
        or not isinstance(filesystem, dict)
        or filesystem.get("block_size") != 4096
        or type(filesystem_blocks) is not int
        or filesystem_blocks * 4096 != contract.p2_ext4_size
        or filesystem.get("size") != contract.p2_ext4_size
        or filesystem.get("uuid") != contract.root_uuid
    ):
        raise DeployError("assembly P2 input identity mismatch")

    geometry = value.get("geometry")
    if not isinstance(geometry, dict):
        raise DeployError("assembly geometry is missing")
    expected_geometry = {
        "logical_sector_size": contract.logical_sector_size,
        "disk_lbas": contract.disk_lbas,
        "p1_lbas": list(contract.p1_lbas),
        "p2_lbas": list(contract.p2_lbas),
        "p2_byte_range": list(contract.p2_byte_range),
        "suffix_bytes": contract.suffix_bytes,
    }
    if any(geometry.get(key) != expected for key, expected in expected_geometry.items()):
        raise DeployError("assembly geometry mismatch")

    verification = value.get("verification")
    if not isinstance(verification, dict):
        raise DeployError("assembly verification is missing")
    gates = verification.get("gates")
    required_gates = {
        "expanded",
        "geometry",
        "gpt",
        "injection_attestation",
        "p2_range",
        "prefix",
        "roundtrip",
        "suffix",
    }
    if not isinstance(gates, dict) or set(gates) != required_gates or any(gates[key] is not True for key in required_gates):
        raise DeployError("assembly verification gates did not all pass")
    if verification.get("roundtrip_raw_sha256") != candidate["roundtrip_raw_sha256"] or verification.get("expanded_byte_identical") is not True:
        raise DeployError("assembly roundtrip verification mismatch")
    for field in ("raw", "expanded", "sparse_static"):
        if not isinstance(verification.get(field), dict):
            raise DeployError(f"assembly verification.{field} is missing")
    output_blocks = _integer(
        verification["sparse_static"].get("output_blocks"),
        "assembly verification.sparse_static.output_blocks",
    )
    if (
        verification["raw"].get("raw_size") != candidate["logical_size"]
        or verification["raw"].get("raw_sha256") != candidate["roundtrip_raw_sha256"]
        or verification["expanded"].get("raw_size") != candidate["logical_size"]
        or verification["expanded"].get("raw_sha256") != candidate["roundtrip_raw_sha256"]
        or verification["sparse_static"].get("block_size") != 4096
        or output_blocks * 4096 != candidate["logical_size"]
        or verification["sparse_static"].get("decoded_sha256") != candidate["roundtrip_raw_sha256"]
        or verification["sparse_static"].get("file_sha256") != candidate["sha256"]
        or verification["sparse_static"].get("file_size") != candidate["size"]
    ):
        raise DeployError("assembly expanded or sparse verification mismatch")
    tools = value.get("tools")
    if (
        not isinstance(tools, dict)
        or tools.get("lock_sha256") != bindings["sparse_tools_lock_sha256"]
    ):
        raise DeployError("assembly sparse tool lock binding mismatch")


def _check_candidate_bundle(audit: Audit) -> None:
    names = (
        "candidate_raw",
        "candidate",
        "assembly_attestation",
        "p2_injection_attestation",
    )
    parents = {audit.held[name].path.parent for name in names}
    if len(parents) != 1:
        raise DeployError("candidate raw, sparse, and attestations must share one bundle")
    bundle = parents.pop()
    info = bundle.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.geteuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DeployError("candidate bundle must be a user-owned canonical mode-0700 directory")
    expected_by_role = {
        "candidate_raw": "userdata.raw",
        "candidate": "userdata.android-sparse.img",
        "assembly_attestation": "assembly-attestation.json",
        "p2_injection_attestation": "injection-attestation.json",
    }
    if any(audit.held[name].path.name != leaf for name, leaf in expected_by_role.items()):
        raise DeployError("candidate bundle filenames do not match the fixed assembly contract")
    expected = set(expected_by_role.values())
    if {entry.name for entry in os.scandir(bundle)} != expected:
        raise DeployError("candidate bundle must contain exactly the four bound files")
    for name in names:
        file_info = audit.held[name].path.lstat()
        if stat.S_IMODE(file_info.st_mode) != 0o600 or file_info.st_nlink != 1:
            raise DeployError("candidate bundle files must be mode 0600 and single-link")


def _check_injection_attestation(value: dict[str, Any], profile: dict[str, Any]) -> None:
    top = _exact_keys(
        value,
        {
            "claims",
            "commands",
            "input",
            "normalization",
            "output",
            "runtime",
            "sanitization",
            "schema",
            "tools",
        },
        "P2 injection attestation",
    )
    if top["schema"] != "lmi-p2-d114-rootfs-injection-attestation/v3":
        raise DeployError("P2 injection attestation schema mismatch")
    if top["claims"] != {
        "hardware_test_only": True,
        "production": False,
        "release_eligible": False,
    }:
        raise DeployError("P2 injection attestation claims mismatch")
    normalization = _exact_keys(
        top["normalization"],
        {
            "allocated_only_command",
            "all_free_blocks_zero",
            "inactive_journal",
            "journal_extent",
            "pre_normalization_sha256",
            "proof",
            "proof_sha256",
            "reviewed_freed_blocks",
            "sparse_st_blocks",
            "tree_identity_sha256",
        },
        "P2 injection normalization",
    )
    if (
        normalization["allocated_only_command"] != ["e2image", "-r", "-a", "-p"]
        or normalization["all_free_blocks_zero"] is not True
        or normalization["inactive_journal"]
        != {
            "block_count": 16_383,
            "first_block": 327_681,
            "sha256": "40b4947fd669bcb849e47705c797e2484a4d406a596017fa889987d2614008b3",
        }
        or normalization["journal_extent"]
        != {"block_count": 16_384, "first_block": 327_680}
        or normalization["proof"] != "second-e2image-byte-identical"
        or normalization["reviewed_freed_blocks"] != [586_227, 661_606]
        or not isinstance(normalization["sparse_st_blocks"], int)
        or isinstance(normalization["sparse_st_blocks"], bool)
        or normalization["sparse_st_blocks"] <= 0
        or any(
            not isinstance(normalization[field], str)
            or SHA256_RE.fullmatch(normalization[field]) is None
            for field in (
                "pre_normalization_sha256",
                "proof_sha256",
                "tree_identity_sha256",
            )
        )
    ):
        raise DeployError("P2 injection normalization proof mismatch")
    output = top["output"]
    p2 = profile["compatibility"]["p2"]
    if (
        not isinstance(output, dict)
        or output.get("sha256") != p2["injected_ext4_sha256"]
        or output.get("size") != p2["injected_ext4_size"]
        or output.get("uuid") != p2["root_uuid"]
    ):
        raise DeployError("P2 injection attestation output identity mismatch")
    if normalization["proof_sha256"] != output["sha256"]:
        raise DeployError("P2 injection normalization output proof mismatch")


def _check_fastboot_archive(item: HeldFile) -> None:
    """Verify the retained ZIP and the three extracted-member identities."""

    required = {
        "platform-tools/fastboot.exe": (FASTBOOT_SIZE, FASTBOOT_SHA256),
        **{
            f"platform-tools/{name}": (size, digest)
            for name, size, digest in FASTBOOT_DLLS
        },
    }
    stream = os.fdopen(os.dup(item.descriptor), "rb", closefd=True)
    try:
        with zipfile.ZipFile(stream, "r") as archive:
            entries = archive.infolist()
            if len(entries) != FASTBOOT_ARCHIVE_ENTRY_COUNT:
                raise DeployError("retained fastboot ZIP entry count mismatch")
            names: set[str] = set()
            folded: set[str] = set()
            found: dict[str, zipfile.ZipInfo] = {}
            for entry in entries:
                name = entry.filename
                try:
                    name.encode("ascii")
                except UnicodeEncodeError:
                    raise DeployError("retained fastboot ZIP has a non-ASCII path") from None
                if (
                    not name
                    or "\\" in name
                    or ":" in name
                    or name.startswith("/")
                    or "//" in name
                    or any(part in {"", ".", ".."} for part in name.rstrip("/").split("/"))
                ):
                    raise DeployError("retained fastboot ZIP has an unsafe path")
                lowered = name.casefold()
                if name in names or lowered in folded:
                    raise DeployError("retained fastboot ZIP has a duplicate or case-colliding path")
                names.add(name)
                folded.add(lowered)
                if entry.flag_bits != 0:
                    raise DeployError("retained fastboot ZIP has encryption or unsupported flags")
                if entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                    raise DeployError("retained fastboot ZIP has unsupported compression")
                if name in required:
                    found[name] = entry
            if set(found) != set(required):
                raise DeployError("retained fastboot ZIP required-member set mismatch")
            for name, (expected_size, expected_sha256) in required.items():
                entry = found[name]
                if entry.is_dir() or entry.file_size != expected_size:
                    raise DeployError("retained fastboot ZIP required-member size mismatch")
                digest = hashlib.sha256()
                with archive.open(entry, "r") as member:
                    while True:
                        block = member.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                if digest.hexdigest() != expected_sha256:
                    raise DeployError("retained fastboot ZIP required-member hash mismatch")
    except (OSError, zipfile.BadZipFile, RuntimeError) as error:
        raise DeployError(f"retained fastboot ZIP validation failed: {error}") from None
    finally:
        stream.close()


def _check_deploy_policy(
    value: dict[str, Any], repo_root: Path, contract: Contract, held: dict[str, HeldFile]
) -> None:
    top = _exact_keys(
        value,
        {
            "acquisition",
            "fastboot",
            "hardware_test_only",
            "hardware_test_readiness",
            "helper",
            "native_staging",
            "repo_bindings",
            "schema",
            "tool_staging",
        },
        "deploy policy lock",
    )
    if top["schema"] != DEPLOY_POLICY_SCHEMA or top["hardware_test_only"] is not True:
        raise DeployError("deploy policy is not the reviewed hardware-test-only contract")
    helper = _artifact(top["helper"], "deploy policy helper")
    if helper != {
        "path": "scripts/lmi_p2_d114/deploy_userdata_helper.ps1",
        "sha256": contract.helper_sha256,
        "size": contract.helper_size,
    }:
        raise DeployError("deploy policy helper identity mismatch")
    fastboot = _exact_keys(
        top["fastboot"],
        {"authenticode", "bundled_android_dll_closure", "closure_scope", "executable"},
        "deploy policy fastboot",
    )
    if fastboot["authenticode"] != {
        "applies_to": "all-three-extracted-members",
        "revocation_policy": "online-entire-chain-no-ignore-flags-for-signer-and-timestamp",
        "runtime_gate": "require-windows-status-valid-before-any-device-query",
        "signer_leaf_certificate_sha256": "2029505d14baf18af60a0d1a7d8b56447db643b32faa849d4c08d2ab1ff3a4fd",
        "signer_subject_cn": "Google LLC",
    }:
        raise DeployError("deploy policy Authenticode gate mismatch")
    if fastboot["closure_scope"] != "application-local-non-system-payload-only":
        raise DeployError("deploy policy fastboot closure scope mismatch")
    executable = _exact_keys(
        fastboot["executable"], {"path", "sha256", "size"}, "deploy policy fastboot executable"
    )
    if executable != {"path": FASTBOOT_PATH, "sha256": FASTBOOT_SHA256, "size": FASTBOOT_SIZE}:
        raise DeployError("deploy policy fastboot executable mismatch")
    closure = fastboot["bundled_android_dll_closure"]
    if not isinstance(closure, list) or closure != [
        {
            "archive_member": f"platform-tools/{name}",
            "filename": name,
            "sha256": digest,
            "size": size,
        }
        for name, size, digest in FASTBOOT_DLLS
    ]:
        raise DeployError("deploy policy bundled Android DLL closure mismatch")
    acquisition = _exact_keys(
        top["acquisition"],
        {"archive", "evidence", "evidence_scope", "schema"},
        "deploy policy acquisition",
    )
    if (
        acquisition["schema"] != "lmi-d110-fastboot-official-acquisition/v1"
        or acquisition["evidence_scope"]
        != "fastboot-exe-member-only-does-not-attest-the-two-dll-members"
    ):
        raise DeployError("deploy policy acquisition scope mismatch")
    archive = _exact_keys(
        acquisition["archive"],
        {"official_sha1", "path", "sha256", "size", "url"},
        "deploy policy archive",
    )
    if archive != {
        "official_sha1": FASTBOOT_ARCHIVE_OFFICIAL_SHA1,
        "path": FASTBOOT_ARCHIVE_PATH,
        "sha256": FASTBOOT_ARCHIVE_SHA256,
        "size": FASTBOOT_ARCHIVE_SIZE,
        "url": FASTBOOT_ARCHIVE_URL,
    }:
        raise DeployError("deploy policy retained archive mismatch")
    if top["native_staging"] != {
        "acl_policy": "protected-current-user-and-local-system-full-control-only",
        "filename": "userdata.android-sparse.img",
        "identity_semantics": "profile-sha256/candidate-sha256/fixed-filename",
        "lifecycle": "preflight-prepare-or-reuse-execute-revalidate-only",
        "report_path_policy": "semantic-only-no-absolute-user-path",
        "root_semantics": "localappdata/lmi-p2-d114/userdata-staging",
        "volume_policy": "fixed-ntfs-without-reparse-directory-ancestors",
    }:
        raise DeployError("deploy policy native staging mismatch")
    if top["tool_staging"] != {
        "acl_policy": "protected-current-user-and-local-system-full-control-only",
        "contents": ["AdbWinApi.dll", "AdbWinUsbApi.dll", "fastboot.exe"],
        "reuse_policy": "reuse-only-after-full-revalidation-and-read-lock",
        "root_semantics": "localappdata/lmi-p2-d114/fastboot-r37.0.0",
        "volume_policy": "fixed-ntfs-without-reparse-directory-ancestors",
    }:
        raise DeployError("deploy policy tool staging mismatch")
    readiness = _exact_keys(
        top["hardware_test_readiness"],
        {
            "accepted_residual_risks",
            "blocking_gates",
            "closure_scope",
            "production_claim",
            "reproducibility_claim",
            "status",
        },
        "deploy policy hardware-test readiness",
    )
    expected_residuals = [
        "official-exact-r37-source-commit-and-build-manifest-unavailable",
        "windows-system-and-runtime-module-closure-not-attested",
        "d110-is-an-operator-owned-external-compatibility-prerequisite-not-a-release-asset",
        "d110-boot-is-separately-approved-ram-boot-only-never-flash-boot",
    ]
    gates = readiness["blocking_gates"]
    if (
        readiness["accepted_residual_risks"] != expected_residuals
        or not isinstance(gates, list)
        or any(not isinstance(item, str) or not item for item in gates)
        or readiness["closure_scope"] != "application-local-non-system-payload-only"
        or readiness["production_claim"] is not False
        or readiness["reproducibility_claim"] is not False
        or readiness["status"]
        not in {"blocked", "ready-for-explicitly-approved-hardware-test-only"}
        or (readiness["status"] == "blocked") is not bool(gates)
    ):
        raise DeployError("deploy policy hardware-test readiness mismatch")
    evidence = _artifact(acquisition["evidence"], "deploy policy fastboot-only acquisition evidence")
    bindings = _exact_keys(
        top["repo_bindings"],
        {
            "apk_build_attestation", "assembler", "candidate_rebuild_lock",
            "fastboot_windows_provenance_lock", "injection_policy_lock", "injector", "injector_launcher", "injector_runtime_lock",
            "physical_userdata_mapping", "public_key", "sixrow_apk_build_attestation",
            "sixrow_public_key", "sparse_tools_lock",
            "userdata_deploy_profile_template",
        },
        "deploy policy repo bindings",
    )
    physical_mapping_binding = _artifact(
        bindings["physical_userdata_mapping"],
        "deploy policy physical userdata mapping binding",
    )
    if physical_mapping_binding != {
        "path": "config/lmi-p2-d114/physical-userdata-mapping.json",
        "sha256": contract.mapping_sha256,
        "size": contract.mapping_size,
    }:
        raise DeployError("deploy policy physical userdata mapping identity mismatch")
    profile_template_binding = _artifact(
        bindings["userdata_deploy_profile_template"],
        "deploy policy profile template binding",
    )
    if (
        profile_template_binding["path"]
        != "config/lmi-p2-d114/userdata-deploy-profile.template.json"
    ):
        raise DeployError("deploy policy profile template path mismatch")
    specs = {"acquisition": evidence, "helper": helper, **bindings}
    for name, spec in specs.items():
        _artifact(spec, f"deploy policy binding {name}")
        path = repo_root / _relative_path(spec["path"], f"deploy policy binding {name}.path")
        item = _open_held(path, repo_root, f"deploy policy binding {name}")
        if item.size != spec["size"] or item.sha256 != spec["sha256"]:
            item.close()
            raise DeployError(f"deploy policy binding {name} identity mismatch")
        held[f"policy:{name}"] = item
    archive_path = repo_root / _relative_path(archive["path"], "deploy policy archive path")
    archive_item = _open_held(archive_path, repo_root, "retained fastboot archive")
    if archive_item.size != archive["size"] or archive_item.sha256 != archive["sha256"]:
        archive_item.close()
        raise DeployError("retained fastboot archive identity mismatch")
    held["policy:fastboot_archive"] = archive_item
    _check_fastboot_archive(archive_item)
    provenance = _json_bytes(
        _held_bytes(
            held["policy:fastboot_windows_provenance_lock"],
            256 * 1024,
            "fastboot Windows provenance lock",
        ),
        "fastboot Windows provenance lock",
    )
    provenance_top = _exact_keys(
        provenance,
        {
            "accepted_residual_risks",
            "archive",
            "authenticode",
            "closure_scope",
            "limitations",
            "members",
            "official_repository_metadata",
            "pe_closure",
            "schema",
        },
        "fastboot Windows provenance lock",
    )
    provenance_archive = _exact_keys(
        provenance_top["archive"],
        {"filename", "locally_derived_sha256", "retained_path", "size", "url", "zip_validation"},
        "fastboot provenance archive",
    )
    repository_metadata = _exact_keys(
        provenance_top["official_repository_metadata"],
        {
            "archive_checksum",
            "archive_checksum_type",
            "archive_size",
            "detached_archive_signature_found",
            "official_sha256_found",
            "package",
            "revision",
            "url",
        },
        "fastboot official repository metadata",
    )
    provenance_authenticode = _exact_keys(
        provenance_top["authenticode"],
        {
            "all_three_files_embed_pkcs7",
            "runtime_revocation_policy",
            "runtime_gate",
            "signer_leaf_certificate_sha256",
            "signer_subject_cn",
            "static_validation_status",
        },
        "fastboot provenance Authenticode",
    )
    expected_members = [
        {"path": "platform-tools/fastboot.exe", "sha256": FASTBOOT_SHA256, "size": FASTBOOT_SIZE},
        *[
            {
                "path": f"platform-tools/{name}",
                "sha256": digest,
                "size": size,
            }
            for name, size, digest in FASTBOOT_DLLS
        ],
    ]
    members = provenance_top["members"]
    if not isinstance(members, list) or len(members) != len(expected_members):
        raise DeployError("fastboot provenance archive member count mismatch")
    for index, expected in enumerate(expected_members):
        if _exact_keys(members[index], {"path", "sha256", "size"}, "fastboot provenance member") != expected:
            raise DeployError("fastboot provenance archive member identity mismatch")
    pe = _exact_keys(
        provenance_top["pe_closure"],
        {
            "AdbWinApi.dll",
            "AdbWinUsbApi.dll",
            "fastboot.exe",
            "runtime_bundled_dll_closure",
            "tool",
        },
        "fastboot PE closure",
    )
    fastboot_pe = _exact_keys(
        pe["fastboot.exe"], {"delay_imports", "non_system_static_imports"}, "fastboot PE imports"
    )
    api_pe = _exact_keys(
        pe["AdbWinApi.dll"], {"delay_imports", "dynamic_edge", "static_imports"}, "AdbWinApi PE imports"
    )
    usb_pe = _exact_keys(
        pe["AdbWinUsbApi.dll"], {"delay_imports", "static_imports"}, "AdbWinUsbApi PE imports"
    )
    dynamic_edge = _exact_keys(
        api_pe["dynamic_edge"],
        {"binary_evidence", "source_corroboration", "source_is_exact_r37_build_attestation", "target"},
        "AdbWinApi dynamic import edge",
    )
    zip_validation = _exact_keys(
        provenance_archive["zip_validation"],
        {
            "allowed_compression_methods",
            "case_collisions",
            "duplicate_paths",
            "encrypted_entries",
            "entry_count",
            "path_traversal_entries",
            "unsupported_entries",
        },
        "fastboot provenance ZIP validation",
    )
    limitations = provenance_top["limitations"]
    if (
        provenance_top["schema"] != "lmi-p2-d114-fastboot-windows-provenance/v2"
        or provenance_archive
        != {
            "filename": "platform-tools_r37.0.0-win.zip",
            "locally_derived_sha256": FASTBOOT_ARCHIVE_SHA256,
            "retained_path": FASTBOOT_ARCHIVE_PATH,
            "size": FASTBOOT_ARCHIVE_SIZE,
            "url": FASTBOOT_ARCHIVE_URL,
            "zip_validation": {
                "allowed_compression_methods": ["store", "deflate"],
                "case_collisions": False,
                "duplicate_paths": False,
                "encrypted_entries": False,
                "entry_count": FASTBOOT_ARCHIVE_ENTRY_COUNT,
                "path_traversal_entries": False,
                "unsupported_entries": False,
            },
        }
        or repository_metadata
        != {
            "archive_checksum": FASTBOOT_ARCHIVE_OFFICIAL_SHA1,
            "archive_checksum_type": "sha1",
            "archive_size": FASTBOOT_ARCHIVE_SIZE,
            "detached_archive_signature_found": False,
            "official_sha256_found": False,
            "package": "platform-tools",
            "revision": "37.0.0",
            "url": "https://dl.google.com/android/repository/repository2-3.xml",
        }
        or provenance_authenticode
        != {
            "all_three_files_embed_pkcs7": True,
            "runtime_revocation_policy": "online-entire-chain-no-ignore-flags-for-signer-and-timestamp",
            "runtime_gate": "require-windows-status-valid-before-any-device-query",
            "signer_leaf_certificate_sha256": "2029505d14baf18af60a0d1a7d8b56447db643b32faa849d4c08d2ab1ff3a4fd",
            "signer_subject_cn": "Google LLC",
            "static_validation_status": "unverified",
        }
        or provenance_top["closure_scope"]
        != {
            "asserted": "application-local-non-system-payload-only",
            "production_claim": False,
            "reproducibility_claim": False,
            "windows_system_modules_in_scope": False,
        }
        or provenance_top["accepted_residual_risks"]
        != [
            "official-exact-r37-source-commit-and-build-manifest-unavailable",
            "windows-system-and-runtime-module-closure-not-attested",
        ]
        or fastboot_pe != {"delay_imports": [], "non_system_static_imports": ["AdbWinApi.dll"]}
        or api_pe["delay_imports"] != []
        or api_pe["static_imports"] != ["KERNEL32.dll", "ole32.dll", "SETUPAPI.dll"]
        or dynamic_edge["binary_evidence"]
        != ["UTF-16 string AdbWinUsbApi.dll", "imports GetProcAddress", "imports LoadLibraryW"]
        or dynamic_edge["source_corroboration"]
        != "https://android.googlesource.com/platform/development/+/main/host/windows/usb/api/AdbWinApi.cpp"
        or dynamic_edge["source_is_exact_r37_build_attestation"] is not False
        or dynamic_edge["target"] != "AdbWinUsbApi.dll"
        or usb_pe
        != {
            "delay_imports": [],
            "static_imports": ["AdbWinApi.DLL", "KERNEL32.dll", "ole32.dll", "WINUSB.DLL"],
        }
        or pe["runtime_bundled_dll_closure"] != ["AdbWinApi.dll", "AdbWinUsbApi.dll"]
        or pe["tool"] != "GNU objdump -p on exact archive-identical installed PE files"
        or zip_validation["entry_count"] != FASTBOOT_ARCHIVE_ENTRY_COUNT
        or not isinstance(limitations, list)
        or len(limitations) != 3
        or any(not isinstance(item, str) or not item for item in limitations)
    ):
        raise DeployError("fastboot provenance or PE closure evidence mismatch")


def _key_value_report(payload: bytes, label: str) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise DeployError(f"invalid {label} encoding") from error
    for line in lines:
        if not line or "=" not in line:
            continue
        key, item = line.split("=", 1)
        result.setdefault(key, []).append(item)
    return result


def _single_report_value(value: dict[str, list[str]], key: str, label: str) -> str | None:
    items = value.get(key, [])
    if len(items) > 1:
        raise DeployError(f"duplicate binding field in {label}: {key}")
    return items[0] if items else None


def _check_mapping(value: dict[str, Any], repo_root: Path, contract: Contract, held: dict[str, HeldFile]) -> dict[str, Any]:
    top = _exact_keys(value, {"cross_bindings", "evidence", "identity_binding", "override", "schema", "userdata"}, "physical mapping evidence")
    if top["schema"] != MAPPING_SCHEMA:
        raise DeployError("physical mapping schema mismatch")
    if top["identity_binding"] != {"current_device_must_match_nonce_scoped_private_policy": True, "public_stable_fingerprint_forbidden": True}:
        raise DeployError("physical mapping identity policy mismatch")
    if top["override"] != {
        "allowed_getvar_result": "unsupported",
        "fastboot_mode": "bootloader",
        "partition": "userdata",
        "partition_type": "f2fs",
        "super_or_fastbootd_fallback_allowed": False,
    }:
        raise DeployError("physical mapping override scope mismatch")
    userdata = _exact_keys(
        top["userdata"],
        {
            "backup_gpt_entries",
            "backup_gpt_header_lba",
            "block_device",
            "block_major",
            "block_minor",
            "by_name_path",
            "by_name_target",
            "by_partlabel_path",
            "by_partlabel_target",
            "capacity_bytes",
            "disk_sector_count",
            "gpt_logical_sector_size",
            "last_lba",
            "loop_backing_device",
            "partlabel",
            "partition_entry_count",
            "partition_entry_size",
            "reported_512_byte_sectors",
        },
        "physical userdata mapping",
    )
    backup_gpt_entries = _exact_keys(
        userdata["backup_gpt_entries"],
        {"first_lba", "last_lba", "sector_count"},
        "physical userdata backup GPT entries",
    )
    integer_geometry = (
        userdata["capacity_bytes"],
        userdata["disk_sector_count"],
        userdata["gpt_logical_sector_size"],
        userdata["last_lba"],
        userdata["backup_gpt_header_lba"],
        userdata["partition_entry_count"],
        userdata["partition_entry_size"],
        userdata["reported_512_byte_sectors"],
        backup_gpt_entries["first_lba"],
        backup_gpt_entries["last_lba"],
        backup_gpt_entries["sector_count"],
    )
    if any(type(item) is not int or item <= 0 for item in integer_geometry):
        raise DeployError("physical userdata GPT geometry must contain positive integers")
    sector_size = userdata["gpt_logical_sector_size"]
    capacity = userdata["capacity_bytes"]
    entry_bytes = userdata["partition_entry_count"] * userdata["partition_entry_size"]
    entry_sectors = (entry_bytes + sector_size - 1) // sector_size
    if (
        capacity % sector_size != 0
        or userdata["disk_sector_count"] != capacity // sector_size
        or userdata["last_lba"] != userdata["disk_sector_count"] - 1
        or userdata["backup_gpt_header_lba"] != userdata["last_lba"]
        or backup_gpt_entries["sector_count"] != entry_sectors
        or backup_gpt_entries["last_lba"] != userdata["backup_gpt_header_lba"] - 1
        or backup_gpt_entries["first_lba"]
        != userdata["backup_gpt_header_lba"] - entry_sectors
        or backup_gpt_entries["last_lba"] - backup_gpt_entries["first_lba"] + 1
        != backup_gpt_entries["sector_count"]
        or userdata["reported_512_byte_sectors"] * 512 != capacity
    ):
        raise DeployError("physical userdata GPT geometry relationship mismatch")
    expected_userdata = {
        "backup_gpt_entries": {
            "first_lba": 28_051_446,
            "last_lba": 28_051_449,
            "sector_count": 4,
        },
        "backup_gpt_header_lba": 28_051_450,
        "block_device": "/dev/sda34",
        "block_major": 259,
        "block_minor": 61,
        "by_name_path": "/dev/block/by-name/userdata",
        "by_name_target": "../../sda34",
        "by_partlabel_path": "/dev/disk/by-partlabel/userdata",
        "by_partlabel_target": "../../sda34",
        "capacity_bytes": contract.userdata_capacity,
        "disk_sector_count": 28_051_451,
        "gpt_logical_sector_size": 4096,
        "last_lba": 28_051_450,
        "loop_backing_device": "/dev/sda34",
        "partlabel": "userdata",
        "partition_entry_count": 128,
        "partition_entry_size": 128,
        "reported_512_byte_sectors": 224_411_608,
    }
    if userdata != expected_userdata:
        raise DeployError("physical userdata mapping mismatch")
    evidence = _exact_keys(
        top["evidence"],
        {"d198_contract", "d198_write_report", "d199_preflight_report", "d199_replug_attestation", "private_identity_policy", "runtime_storage_log"},
        "physical mapping evidence files",
    )
    loaded: dict[str, HeldFile] = {}
    for name, spec in evidence.items():
        _artifact(spec, f"mapping evidence {name}")
        path = repo_root / _relative_path(spec["path"], f"mapping evidence {name}.path")
        item = _open_held(path, repo_root, f"mapping evidence {name}")
        if item.size != spec["size"] or item.sha256 != spec["sha256"]:
            item.close()
            raise DeployError(f"mapping evidence {name} identity mismatch")
        held[f"mapping:{name}"] = item
        loaded[name] = item

    runtime = _held_bytes(loaded["runtime_storage_log"], 128 * 1024, "runtime storage log").decode("utf-8")
    exact_lines = (
        "/dev/block/by-name/userdata -> ../../sda34",
        "/dev/disk/by-partlabel/userdata -> ../../sda34",
        "brw-r--r--    1 0        0         259,  61 Nov 27 17:27 /dev/sda34",
        "Disk /dev/sda34: 224411608 sectors, 63.8M",
        "Logical sector size: 4096",
        "Mount subpartitions of /dev/sda34",
        "SUBPARTITION_DEV=/dev/sda34",
        "/dev/loop0: [0002]:570 (/dev/sda34)",
    )
    if any(line not in runtime for line in exact_lines) or not re.search(r"^/dev/sda34: .*PTTYPE=\"gpt\" PARTLABEL=\"userdata\"", runtime, re.MULTILINE):
        raise DeployError("runtime storage log does not prove the physical userdata mapping")
    d198 = _json_bytes(_held_bytes(loaded["d198_contract"], 64 * 1024, "D198 contract"), "D198 contract")
    if (
        d198.get("experiment_id") != "d198-userdata-d114-splash-recursion-fix"
        or d198.get("status") != "completed"
        or d198.get("attempt", {}).get("result") != "success"
        or d198.get("execution_contract", {}).get("target") != "userdata"
    ):
        raise DeployError("D198 contract does not bind the successful userdata-only write")
    bindings = _exact_keys(top["cross_bindings"], {"d198", "d199", "runtime"}, "mapping cross bindings")
    d198_binding = _exact_keys(bindings["d198"], {"artifact_sha256", "evidence_report_path", "evidence_report_sha256", "evidence_route_status", "experiment_id", "target"}, "mapping D198 binding")
    d199_binding = _exact_keys(bindings["d199"], {"evidence_report_path", "evidence_report_sha256", "evidence_route_status", "execution_profile_sha256", "experiment_id", "prior_d198_write_report_sha256"}, "mapping D199 binding")
    if bindings["runtime"] != {
        "block_device": "/dev/sda34", "block_major": 259, "block_minor": 61,
        "capacity_bytes": contract.userdata_capacity, "logical_sector_size": 4096,
        "partlabel": "userdata",
    }:
        raise DeployError("mapping runtime cross binding mismatch")
    if d198_binding != {
        "artifact_sha256": d198.get("execution_contract", {}).get("artifact_sha256"),
        "evidence_report_path": d198.get("evidence_report"),
        "evidence_report_sha256": evidence["d198_write_report"]["sha256"],
        "evidence_route_status": d198.get("evidence_route_status"),
        "experiment_id": d198.get("experiment_id"),
        "target": d198.get("execution_contract", {}).get("target"),
    }:
        raise DeployError("D198 cross binding mismatch")
    d198_report = _key_value_report(_held_bytes(loaded["d198_write_report"], 16 * 1024, "D198 write report"), "D198 write report")
    if _single_report_value(d198_report, "write_command_started", "D198 write report") != "1" or _single_report_value(d198_report, "write_command_exit", "D198 write report") != "0" or _single_report_value(d198_report, "route_status", "D198 write report") != d198_binding["evidence_route_status"]:
        raise DeployError("D198 write report completion evidence mismatch")
    d199_attestation = _json_bytes(_held_bytes(loaded["d199_replug_attestation"], 64 * 1024, "D199 replug attestation"), "D199 replug attestation")
    expected_d199 = {
        "evidence_report_path": d199_attestation.get("evidence_report"),
        "evidence_report_sha256": evidence["d199_preflight_report"]["sha256"],
        "evidence_route_status": d199_attestation.get("evidence_route_status"),
        "execution_profile_sha256": d199_attestation.get("execution_contract", {}).get("profile_sha256"),
        "experiment_id": d199_attestation.get("experiment_id"),
        "prior_d198_write_report_sha256": d199_attestation.get("gates", {}).get("rollback", {}).get("evidence_sha256"),
    }
    if d199_attestation.get("status") != "completed" or d199_attestation.get("outcome") != "positive" or d199_binding != expected_d199 or d199_binding["prior_d198_write_report_sha256"] != d198_binding["evidence_report_sha256"]:
        raise DeployError("D199 cross binding mismatch")
    d199_report = _key_value_report(_held_bytes(loaded["d199_preflight_report"], 16 * 1024, "D199 preflight report"), "D199 preflight report")
    if _single_report_value(d199_report, "product", "D199 preflight report") != "lmi" or _single_report_value(d199_report, "userdata_capacity_bytes", "D199 preflight report") != str(contract.userdata_capacity) or _single_report_value(d199_report, "route_status", "D199 preflight report") != d199_binding["evidence_route_status"] or _single_report_value(d199_report, "postwrite_userdata_write_sha256", "D199 preflight report") != d199_binding["prior_d198_write_report_sha256"]:
        raise DeployError("D199 post-replug evidence mismatch")
    policy = _json_bytes(_held_bytes(loaded["private_identity_policy"], 64 * 1024, "private identity policy"), "private identity policy")
    historical = policy.get("historical_identity")
    if (
        policy.get("schema") != "lmi-d110-recovery-policy/v2"
        or policy.get("device", {}).get("product") != "lmi"
        or not isinstance(historical, dict)
        or SHA256_RE.fullmatch(str(historical.get("privacy_nonce", ""))) is None
        or SHA256_RE.fullmatch(str(historical.get("expected_nonce_scoped_serial_sha256", ""))) is None
    ):
        raise DeployError("private nonce-scoped identity policy mismatch")
    return policy


def local_audit(profile_path: Path, *, repo_root: Path = REPO, contract: Contract = PRODUCTION) -> Audit:
    repo_root = repo_root.absolute()
    profile_item = _open_held(profile_path.absolute(), repo_root, "deployment profile")
    held = {"profile": profile_item}
    try:
        profile = _json_bytes(_held_bytes(profile_item, 256 * 1024, "deployment profile"), "deployment profile")
        _parse_profile(profile, contract)
        for name, spec in profile["artifacts"].items():
            path = repo_root / _relative_path(spec["path"], f"{name}.path")
            item = _open_held(path, repo_root, name.replace("_", " "))
            if item.size != spec["size"] or item.sha256 != spec["sha256"]:
                item.close()
                raise DeployError(f"{name} identity mismatch")
            held[name] = item
        source_lock = _json_bytes(_held_bytes(held["source_lock"], 256 * 1024, "source lock"), "source lock")
        _check_source_lock(source_lock, contract)
        assembly = _json_bytes(_held_bytes(held["assembly_attestation"], 4 * 1024 * 1024, "assembly attestation"), "assembly attestation")
        _check_assembly(assembly, profile, contract)
        injection = _json_bytes(
            _held_bytes(
                held["p2_injection_attestation"],
                4 * 1024 * 1024,
                "P2 injection attestation",
            ),
            "P2 injection attestation",
        )
        _check_injection_attestation(injection, profile)
        deploy_policy = _json_bytes(
            _held_bytes(held["deploy_policy_lock"], 256 * 1024, "deploy policy lock"),
            "deploy policy lock",
        )
        _check_deploy_policy(deploy_policy, repo_root, contract, held)
        mapping = _json_bytes(_held_bytes(held["physical_mapping_evidence"], 256 * 1024, "physical mapping evidence"), "physical mapping evidence")
        identity_policy = _check_mapping(mapping, repo_root, contract, held)
        audit = Audit(repo_root, profile_path.absolute(), profile, profile_item.sha256, held, source_lock, assembly, mapping, identity_policy, deploy_policy)
        _check_candidate_bundle(audit)
        for name in ("candidate", "rollback"):
            spec = profile["artifacts"][name]
            inspect_sparse(held[name], spec["logical_size"], spec["roundtrip_raw_sha256"], name)
        return audit
    except BaseException:
        for item in reversed(tuple(held.values())):
            item.close()
        raise


def _recheck(audit: Audit) -> None:
    for label, item in audit.held.items():
        try:
            path_stat = item.path.lstat()
            opened = os.fstat(item.descriptor)
        except OSError as error:
            raise DeployError(f"{label} became unavailable") from error
        if _identity(path_stat) != item.identity or _identity(opened) != item.identity:
            raise DeployError(f"{label} identity changed while held")
        os.lseek(item.descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = item.size
        while remaining:
            chunk = os.read(item.descriptor, min(4 * 1024 * 1024, remaining))
            if not chunk:
                raise DeployError(f"{label} became truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        if digest.hexdigest() != item.sha256:
            raise DeployError(f"{label} content changed while held")
        os.lseek(item.descriptor, 0, os.SEEK_SET)


def _windows_path(path: Path) -> str:
    result = subprocess.run(
        ["wslpath", "-w", str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode or not result.stdout.strip() or "\n" in result.stdout.strip():
        raise DeployError("could not convert a locked path for Windows PowerShell")
    return result.stdout.strip()


@dataclass(frozen=True)
class RunContext:
    journal_path: Path
    approval_claim_sha256: str | None = None
    intent_initial_sha256: str | None = None
    native_stage_path: str | None = None


@dataclass(frozen=True)
class IntentJournalSnapshot:
    intent: dict[str, Any]
    transition: dict[str, Any] | None
    terminal: dict[str, Any] | None
    outcome_malformed: bool
    sha256: str
    size: int


PowerShellRunner = Callable[[str, Audit, RunContext], dict[str, Any]]


POWERSHELL_BOOTSTRAP = r"""
$ErrorActionPreference='Stop';$p=$args[0];$expected=$args[1];$hashes=[Text.Encoding]::ASCII.GetString([Convert]::FromBase64String($args[8]));$approval=if($args[9]-ceq '__EMPTY__') {''} else {$args[9]};$intent=if($args[10]-ceq '__EMPTY__') {''} else {$args[10]};$stage=if($args[11]-ceq '__EMPTY__') {''} else {$args[11]};$s=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($s))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($actual-cne $expected){throw 'HELPER_HASH_MISMATCH'};$s.Position=0;$b=New-Object byte[] $s.Length;$n=0;while($n-lt $b.Length){$r=$s.Read($b,$n,$b.Length-$n);if($r-le 0){throw 'HELPER_SHORT_READ'};$n+=$r};$t=[Text.UTF8Encoding]::new($false,$true).GetString($b);$sb=[ScriptBlock]::Create($t);& $sb -Mode $args[2] -RepoRoot $args[3] -ProfilePath $args[4] -ResultPath $args[5] -JournalPath $args[6] -ExpectedHelperSha256 $expected -ExpectedProfileSha256 $args[7] -ExpectedArtifactHashesJson $hashes -ExpectedApprovalClaimSha256 $approval -ExpectedIntentInitialSha256 $intent -ExpectedNativeStagePath $stage}finally{$s.Dispose()}
""".strip()


def _validate_dual_result(stdout: bytes, result_bytes: bytes) -> None:
    lines = [line for line in stdout.splitlines() if line]
    if len(lines) != 1 or not lines[0].startswith(RESULT_PREFIX):
        raise DeployError("PowerShell helper stdout result channel mismatch")
    try:
        stdout_bytes = base64.b64decode(lines[0][len(RESULT_PREFIX):], validate=True)
    except (ValueError, base64.binascii.Error) as error:
        raise DeployError("PowerShell helper stdout result is invalid") from error
    if stdout_bytes != result_bytes:
        raise DeployError("PowerShell helper dual result channels disagree")


def _recover_helper_from_intent(
    mode: str, audit: Audit, context: RunContext, reason: str
) -> dict[str, Any]:
    if mode != "Execute" or context.intent_initial_sha256 is None:
        raise DeployError("PowerShell helper failed before a recoverable execute intent")
    journal = _read_intent_journal(
        context.journal_path,
        audit.repo_root,
        expected_initial_sha256=context.intent_initial_sha256,
    )
    _validate_intent_binding(
        journal.intent,
        audit,
        context.journal_path,
        expected_approval_sha256=context.approval_claim_sha256,
        expected_native_stage_path=context.native_stage_path,
    )
    candidate = audit.profile["artifacts"]["candidate"]
    if (
        journal.intent.get("approval_claim_sha256") != context.approval_claim_sha256
        or journal.intent.get("profile")
        != {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256}
        or journal.intent.get("candidate_source")
        != {"path": candidate["path"], "sha256": candidate["sha256"], "size": candidate["size"]}
        or journal.intent.get("native_stage", {}).get("path") != context.native_stage_path
    ):
        raise DeployError("recoverable execute intent binding mismatch")
    expected_transition = {
        "approval_claim_sha256": context.approval_claim_sha256,
        "containment_confirmed": True,
        "identity_match": True,
        "native_stage_path_semantics": context.native_stage_path,
        "schema": INTENT_TRANSITION_SCHEMA,
        "snapshot_identity_confirmed": True,
        "state": "ATTEMPT_STARTING_CONSERVATIVE",
    }
    transition_verified = journal.transition == expected_transition
    outcome_malformed = journal.outcome_malformed or (
        journal.transition is not None and not transition_verified
    )
    terminal = journal.terminal
    if terminal is not None:
        try:
            _validate_intent_terminal(
                terminal,
                audit,
                context.approval_claim_sha256,
                context.intent_initial_sha256,
            )
        except DeployError:
            terminal = None
            outcome_malformed = True
    # An initial-only record is an outstanding authorization, not evidence that
    # the Windows helper stopped.  Conservatively consume the sole attempt
    # budget until a transition or helper-authenticated terminal record exists.
    attempted = terminal is None
    device = {
        "battery_mv": None,
        "identity_match": transition_verified,
        "is_logical_userdata": None,
        "max_download_size": None,
        "partition_size": None,
        "partition_type": None,
        "physical_mapping_evidence_override": False,
        "product": None,
        "soc_ok": None,
        "unlocked": None,
        "userspace": None,
    }
    stage = (
        {
            "acl_verified": True,
            "deny_write_delete_handle_held": False,
            "path_semantics": context.native_stage_path,
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        }
        if transition_verified
        else None
    )
    return {
        "approval_claim_sha256": context.approval_claim_sha256,
        "artifact_hashes": {
            "profile": audit.profile_sha256,
            **{name: audit.held[name].sha256 for name in audit.profile["artifacts"]},
        },
        "attempt_journal_durable": transition_verified,
        "device": device,
        "flash": {
            "assignment_confirmed": transition_verified,
            "attempts": 1 if attempted else 0,
            "exit_code": None,
            "sending_okay": 0,
            "started": False,
            "timed_out": reason == "HELPER_OUTER_TIMEOUT_INTENT_RECOVERY",
            "transport_completed": False,
            "tree_quiescent": False,
            "writing_okay": 0,
        },
        "intent_initial_sha256": context.intent_initial_sha256,
        "locked_inputs_intact": False,
        "mode": mode,
        "native_stage": stage,
        "reason": (
            "HELPER_TERMINAL_NO_ATTEMPT_INTENT_RECOVERY"
            if terminal is not None
            else (
                "INTENT_OUTCOME_MALFORMED_WRITE_STATE_UNKNOWN_CLAIM_CONSUMED"
                if outcome_malformed
                else (
                    reason
                    if transition_verified
                    else "HELPER_MAY_STILL_START_OR_WRITE_STATE_UNKNOWN_CLAIM_CONSUMED"
                )
            )
        ),
        "recovered_from_intent_journal": True,
        "route_status": (
            "WRITE_ATTEMPTED_RESULT_UNKNOWN" if attempted else "REFUSED_NO_STATE_CHANGE"
        ),
        "schema": HELPER_SCHEMA,
        "windows_validation_scope": "small-repository-contract-and-prepared-candidate",
    }


def _untrusted_intent_unknown_helper(
    audit: Audit, context: RunContext, reason: str
) -> dict[str, Any]:
    """Consume the attempt budget without trusting any journal/helper claims."""

    return {
        "approval_claim_sha256": context.approval_claim_sha256,
        "artifact_hashes": {
            "profile": audit.profile_sha256,
            **{name: audit.held[name].sha256 for name in audit.profile["artifacts"]},
        },
        "attempt_journal_durable": False,
        "device": {
            "battery_mv": None,
            "identity_match": False,
            "is_logical_userdata": None,
            "max_download_size": None,
            "partition_size": None,
            "partition_type": None,
            "physical_mapping_evidence_override": False,
            "product": None,
            "soc_ok": None,
            "unlocked": None,
            "userspace": None,
        },
        "flash": {
            "assignment_confirmed": False,
            "attempts": 1,
            "exit_code": None,
            "sending_okay": 0,
            "started": False,
            "timed_out": False,
            "transport_completed": False,
            "tree_quiescent": False,
            "writing_okay": 0,
        },
        "intent_initial_sha256": context.intent_initial_sha256,
        "locked_inputs_intact": False,
        "mode": "Execute",
        "native_stage": None,
        "reason": reason,
        "recovered_from_intent_journal": True,
        "route_status": "WRITE_ATTEMPTED_RESULT_UNKNOWN",
        "schema": HELPER_SCHEMA,
        "windows_validation_scope": "small-repository-contract-and-prepared-candidate",
    }


def run_powershell(mode: str, audit: Audit, context: RunContext) -> dict[str, Any]:
    """Hash, stage, and execute the exact helper bytes; never relay its streams."""

    with tempfile.TemporaryDirectory(prefix="lmi-d114-deploy-") as temporary:
        temporary_path = Path(temporary)
        result_path = temporary_path / "result.json"
        staged_bootstrap = temporary_path / "bootstrap.ps1"
        staged_helper = temporary_path / "helper.ps1"
        helper_item = audit.held["policy:helper"]
        helper_bytes = _held_bytes(helper_item, 1024 * 1024, "PowerShell helper")
        descriptor = os.open(staged_helper, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        try:
            cursor = 0
            while cursor < len(helper_bytes):
                written = os.write(descriptor, helper_bytes[cursor:])
                if written <= 0:
                    raise DeployError("short write while staging PowerShell helper")
                cursor += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if hashlib.sha256(staged_helper.read_bytes()).hexdigest() != helper_item.sha256:
            raise DeployError("staged PowerShell helper hash mismatch")
        bootstrap_bytes = (POWERSHELL_BOOTSTRAP + "\n").encode("ascii")
        descriptor = os.open(
            staged_bootstrap,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            0o600,
        )
        try:
            cursor = 0
            while cursor < len(bootstrap_bytes):
                written = os.write(descriptor, bootstrap_bytes[cursor:])
                if written <= 0:
                    raise DeployError("short write while staging PowerShell bootstrap")
                cursor += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if staged_bootstrap.read_bytes() != bootstrap_bytes:
            raise DeployError("staged PowerShell bootstrap identity mismatch")
        expected_hashes = {
            "profile": audit.profile_sha256,
            **{name: audit.held[name].sha256 for name in audit.profile["artifacts"]},
        }
        command = [
            "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            _windows_path(staged_bootstrap),
            _windows_path(staged_helper),
            helper_item.sha256,
            mode,
            _windows_path(audit.repo_root),
            _windows_path(audit.profile_path),
            _windows_path(result_path),
            _windows_path(context.journal_path),
            audit.profile_sha256,
            base64.b64encode(json.dumps(expected_hashes, sort_keys=True, separators=(",", ":")).encode("ascii")).decode("ascii"),
            context.approval_claim_sha256 or "__EMPTY__",
            context.intent_initial_sha256 or "__EMPTY__",
            context.native_stage_path or "__EMPTY__",
        ]
        try:
            try:
                process = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    timeout=OUTER_TIMEOUT_SECONDS,
                )
            except subprocess.TimeoutExpired:
                return _recover_helper_from_intent(
                    mode, audit, context, "HELPER_OUTER_TIMEOUT_INTENT_RECOVERY"
                )
            if not result_path.exists():
                return _recover_helper_from_intent(
                    mode, audit, context, "HELPER_EXITED_WITHOUT_RESULT_INTENT_RECOVERY"
                )
            result_item = _open_held(result_path, temporary_path, "PowerShell result")
            try:
                result_bytes = _held_bytes(
                    result_item, 256 * 1024, "PowerShell result"
                )
                value = _json_bytes(result_bytes, "PowerShell result")
            finally:
                result_item.close()
            _validate_dual_result(process.stdout, result_bytes)
            if process.returncode not in {0, 2, 3, 4}:
                raise DeployError(
                    f"PowerShell helper returned unexpected status {process.returncode}"
                )
            return value
        except (DeployError, OSError, ValueError):
            if mode == "Execute" and context.intent_initial_sha256 is not None:
                return _recover_helper_from_intent(
                    mode,
                    audit,
                    context,
                    "HELPER_RESULT_CHANNEL_INVALID_CLAIM_CONSUMED",
                )
            raise


def _validate_helper(
    value: dict[str, Any],
    mode: str,
    audit: Audit,
    context: RunContext,
    *,
    allow_recovered: bool = False,
) -> dict[str, Any]:
    result = _exact_keys(value, {"approval_claim_sha256", "artifact_hashes", "attempt_journal_durable", "device", "flash", "intent_initial_sha256", "locked_inputs_intact", "mode", "native_stage", "reason", "recovered_from_intent_journal", "route_status", "schema", "windows_validation_scope"}, "PowerShell result")
    if result["schema"] != HELPER_SCHEMA or result["mode"] != mode:
        raise DeployError("PowerShell result schema or mode mismatch")
    expected_scope = (
        "small-repository-contract-and-prepared-candidate"
        if mode == "Execute"
        else "full-repository-artifacts-and-prepared-candidate"
        if mode == "Preflight"
        else "full-repository-artifacts"
    )
    if result["windows_validation_scope"] != expected_scope:
        raise DeployError("PowerShell Windows validation scope mismatch")
    if result["reason"] is not None and (not isinstance(result["reason"], str) or not re.fullmatch(r"[A-Z0-9_]{1,96}", result["reason"])):
        raise DeployError("PowerShell result reason is unsafe")
    if type(result["locked_inputs_intact"]) is not bool:
        raise DeployError("PowerShell locked-input verdict is not boolean")
    if type(result["recovered_from_intent_journal"]) is not bool:
        raise DeployError("PowerShell recovery verdict is not boolean")
    if result["recovered_from_intent_journal"] is True and not allow_recovered:
        raise DeployError("live PowerShell helper forged a journal-recovery result")
    if allow_recovered and result["recovered_from_intent_journal"] is not True:
        raise DeployError("internal journal recovery lacks its provenance marker")
    hashes = _exact_keys(result["artifact_hashes"], set(audit.profile["artifacts"]) | {"profile"}, "PowerShell artifact hashes")
    expected_hashes = {
        "profile": audit.profile_sha256,
        **{
            name: audit.profile["artifacts"][name]["sha256"]
            for name in audit.profile["artifacts"]
        },
    }
    if hashes != expected_hashes:
        raise DeployError("PowerShell post-hashes do not bind every deployment input")
    device = _exact_keys(
        result["device"],
        {"battery_mv", "identity_match", "is_logical_userdata", "max_download_size", "partition_size", "partition_type", "physical_mapping_evidence_override", "product", "soc_ok", "unlocked", "userspace"},
        "PowerShell device result",
    )
    if type(device["identity_match"]) is not bool:
        raise DeployError("PowerShell result identity verdict is not boolean")
    flash = _exact_keys(result["flash"], {"assignment_confirmed", "attempts", "exit_code", "sending_okay", "started", "timed_out", "transport_completed", "tree_quiescent", "writing_okay"}, "PowerShell flash result")
    if type(flash["attempts"]) is not int or flash["attempts"] not in {0, 1}:
        raise DeployError("PowerShell result has an invalid flash attempt count")
    if mode != "Execute" and flash["attempts"] != 0:
        raise DeployError("a read-only mode reported a flash attempt")
    if mode == "Execute" and flash["attempts"] > 1:
        raise DeployError("execute exceeded its one allowed flash attempt")
    if (
        type(flash["assignment_confirmed"]) is not bool
        or type(flash["started"]) is not bool
        or type(flash["timed_out"]) is not bool
        or type(flash["transport_completed"]) is not bool
        or type(flash["tree_quiescent"]) is not bool
        or type(flash["sending_okay"]) is not int
        or flash["sending_okay"] < 0
        or type(flash["writing_okay"]) is not int
        or flash["writing_okay"] < 0
        or (flash["exit_code"] is not None and type(flash["exit_code"]) is not int)
    ):
        raise DeployError("PowerShell flash evidence types mismatch")
    allowed_routes = {
        "LocalAudit": set(),
        "Preflight": {"PREFLIGHT_PASSED_NO_STATE_CHANGE", "REFUSED_NO_STATE_CHANGE"},
        "Execute": {"USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED", "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING", "WRITE_ATTEMPTED_RESULT_UNKNOWN", "REFUSED_NO_STATE_CHANGE"},
        "Postwrite": {"POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE", "REFUSED_NO_STATE_CHANGE"},
    }
    if result["route_status"] not in allowed_routes[mode]:
        raise DeployError("PowerShell result route is impossible for this mode")
    if result["route_status"] == "REFUSED_NO_STATE_CHANGE" and flash["attempts"] != 0:
        raise DeployError("a refusal followed a state-change attempt")
    if mode == "Execute":
        if result["approval_claim_sha256"] != context.approval_claim_sha256:
            raise DeployError("PowerShell result approval binding mismatch")
        if result["intent_initial_sha256"] != context.intent_initial_sha256:
            raise DeployError("PowerShell result intent binding mismatch")
        indeterminate_recovery = (
            result["recovered_from_intent_journal"] is True
            and result["route_status"] == "WRITE_ATTEMPTED_RESULT_UNKNOWN"
            and flash["attempts"] == 1
            and flash["started"] is False
            and flash["assignment_confirmed"] is False
            and result["attempt_journal_durable"] is False
        )
        if (
            flash["attempts"] == 1
            and result["attempt_journal_durable"] is not True
            and not indeterminate_recovery
        ):
            raise DeployError("write attempt lacks its durable preattempt journal")
        if flash["attempts"] == 1 and result["route_status"] == "REFUSED_NO_STATE_CHANGE":
            raise DeployError("write attempt was incorrectly reported as refused")
    if mode in {"Preflight", "Execute"} and result["native_stage"] is not None:
        stage = _exact_keys(result["native_stage"], {"acl_verified", "deny_write_delete_handle_held", "path_semantics", "sha256", "size"}, "PowerShell native stage")
        candidate = audit.profile["artifacts"]["candidate"]
        if stage != {
            "acl_verified": True,
            "deny_write_delete_handle_held": not result["recovered_from_intent_journal"],
            "path_semantics": context.native_stage_path,
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        }:
            raise DeployError("PowerShell native staged snapshot mismatch")
    elif (mode == "Preflight" and result["route_status"] == "PREFLIGHT_PASSED_NO_STATE_CHANGE") or (
        mode == "Execute" and flash["attempts"] == 1 and not indeterminate_recovery
    ):
        raise DeployError("helper lacks its prepared native candidate")
    elif mode == "Postwrite" and result["native_stage"] is not None:
        raise DeployError("postwrite helper unexpectedly reported a prepared candidate")
    if mode != "Execute" and (
        result["approval_claim_sha256"] is not None
        or result["intent_initial_sha256"] is not None
        or result["attempt_journal_durable"] is not False
    ):
        raise DeployError("read-only helper result contains write approval state")
    if result["route_status"] == "WRITE_ATTEMPTED_RESULT_UNKNOWN" and flash["attempts"] != 1:
        raise DeployError("unknown-write route lacks one attempt")
    if result["locked_inputs_intact"] is False and (
        (flash["attempts"] == 0 and result["route_status"] != "REFUSED_NO_STATE_CHANGE")
        or (flash["attempts"] == 1 and result["route_status"] not in {"USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING", "WRITE_ATTEMPTED_RESULT_UNKNOWN"})
    ):
        raise DeployError("locked-input drift has an unsafe route")
    passed_device_routes = {
        "PREFLIGHT_PASSED_NO_STATE_CHANGE",
        "POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE",
        "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED",
        "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING",
        "WRITE_ATTEMPTED_RESULT_UNKNOWN",
    }
    if result["route_status"] in passed_device_routes and not (
        result["recovered_from_intent_journal"] is True
        and result["route_status"] == "WRITE_ATTEMPTED_RESULT_UNKNOWN"
    ):
        profile_device = audit.profile["device"]
        logical = device["is_logical_userdata"]
        if (
            device["identity_match"] is not True
            or device["product"] != "lmi"
            or device["unlocked"] != "yes"
            or device["userspace"] != "no"
            or logical not in {"no", "unsupported"}
            or device["physical_mapping_evidence_override"]
            is not (logical == "unsupported")
            or device["partition_type"] != "f2fs"
            or type(device["partition_size"]) is not int
            or device["partition_size"]
            != profile_device["expected_userdata_capacity"]
            or device["partition_size"]
            < audit.profile["artifacts"]["candidate"]["logical_size"]
            or device["partition_size"]
            < audit.profile["artifacts"]["rollback"]["logical_size"]
            or type(device["battery_mv"]) is not int
            or device["battery_mv"] < profile_device["minimum_battery_mv"]
            or device["soc_ok"] != "yes"
            or type(device["max_download_size"]) is not int
            or device["max_download_size"]
            < profile_device["minimum_max_download_size"]
        ):
            raise DeployError("PowerShell passed route does not satisfy device gates")
    if result["route_status"].startswith("USERDATA_TRANSPORT_COMPLETED") and not (
        flash["attempts"] == 1
        and flash["exit_code"] == 0
        and flash["started"] is True
        and flash["assignment_confirmed"] is True
        and flash["tree_quiescent"] is True
        and flash["transport_completed"] is True
        and flash["timed_out"] is False
        and flash["writing_okay"] >= 1
    ):
        raise DeployError("completed-write route lacks complete Finished evidence")
    return result


def _load_prior_report(path: Path, expected_sha256: str, audit: Audit) -> dict[str, Any]:
    item = _open_held(path.absolute(), audit.repo_root, "prior write report")
    try:
        if item.sha256 != expected_sha256:
            raise DeployError("prior write report hash mismatch")
        value = _json_bytes(_held_bytes(item, 256 * 1024, "prior write report"), "prior write report")
    finally:
        item.close()
    _exact_keys(value, {"artifacts", "created_at_unix", "mode", "profile", "result", "route_status", "safety", "schema"}, "prior write report")
    _validate_report_safety(value["safety"], audit)
    if (
        value["schema"] != REPORT_SCHEMA
        or value["mode"] != "execute"
        or value["profile"] != {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256}
        or value["route_status"] not in {"USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING", "WRITE_ATTEMPTED_RESULT_UNKNOWN"}
        or value["result"].get("flash", {}).get("attempts") != 1
    ):
        raise DeployError("prior report is not a pending or unknown write for this profile")
    return value


def _private_output_parent(path: Path, repo_root: Path, label: str) -> Path:
    path = path.absolute()
    parent = path.parent
    _check_real_ancestors(path, repo_root.absolute(), label)
    try:
        parent_stat = parent.lstat()
    except OSError as error:
        raise DeployError(f"cannot inspect {label} directory") from error
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_ISLNK(parent_stat.st_mode)
        or parent_stat.st_uid != os.geteuid()
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
    ):
        raise DeployError(f"{label} directory must be user-owned canonical mode-0700")
    return parent


def _publish_private_json(path: Path, value: dict[str, Any], repo_root: Path, label: str) -> str:
    path = path.absolute()
    parent = _private_output_parent(path, repo_root, label)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise DeployError(f"{label} target already exists; overwrite is forbidden")
    payload = _canonical_json(value)
    digest = hashlib.sha256(payload).hexdigest()
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=".lmi-d114-private-", dir=parent)
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        cursor = 0
        while cursor < len(payload):
            written = os.write(descriptor, payload[cursor:])
            if written <= 0:
                raise DeployError(f"short write while publishing {label}")
            cursor += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path, follow_symlinks=False)
        temporary.unlink()
        temporary = None
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass
    final = path.lstat()
    if not stat.S_ISREG(final.st_mode) or final.st_nlink != 1 or stat.S_IMODE(final.st_mode) != 0o600 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise DeployError(f"published {label} identity mismatch")
    return digest


def _publish_report(path: Path, value: dict[str, Any], repo_root: Path) -> str:
    return _publish_private_json(path, value, repo_root, "report")


def _report_safety(audit: Audit) -> dict[str, Any]:
    return {
        "automatic_retry": False,
        "boot_partition_write_attempted": False,
        "command_attempt_limit": 1,
        "current_boot_sha256_measured": False,
        "d110_boot_preservation": "inferred-from-no-boot-write-not-freshly-measured",
        "expected_d110_boot_sha256": audit.profile["compatibility"]["d110"]["boot_sha256"],
        "partition": "userdata",
        "retry_scope": RETRY_SCOPE,
        "serial_disclosed": False,
        "unknown_followup": UNKNOWN_FOLLOWUP,
        "userdata_content_readback_verified": False,
    }


def _validate_report_safety(value: Any, audit: Audit) -> None:
    expected = _report_safety(audit)
    if _exact_keys(value, set(expected), "report safety") != expected:
        raise DeployError("report safety contract mismatch")


def _native_stage_path(audit: Audit) -> str:
    staging = audit.deploy_policy.get("native_staging")
    if not isinstance(staging, dict):
        raise DeployError("deploy policy native staging contract is missing")
    root = _string(staging.get("root_semantics"), "native staging root semantics").rstrip("/")
    filename = _string(staging.get("filename"), "native staging filename")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,96}", filename):
        raise DeployError("native staging filename is unsafe")
    candidate_sha256 = audit.profile["artifacts"]["candidate"]["sha256"]
    return f"{root}/{audit.profile_sha256}/{candidate_sha256}/{filename}"


def _approval_binding(
    audit: Audit, preflight_sha256: str
) -> dict[str, Any]:
    stage_path = _native_stage_path(audit)
    return {
        "candidate_sha256": audit.profile["artifacts"]["candidate"]["sha256"],
        "command": [
            "-s", "<identity-policy-matched-device>", "flash", "userdata",
            stage_path,
        ],
        "identity_policy_sha256": audit.held["mapping:private_identity_policy"].sha256,
        "preflight_report_sha256": preflight_sha256,
        "profile_sha256": audit.profile_sha256,
        "staged_candidate_path": stage_path,
    }


def _require_hardware_test_ready(audit: Audit) -> None:
    readiness = audit.deploy_policy.get("hardware_test_readiness")
    if (
        not isinstance(readiness, dict)
        or readiness.get("status") != "ready-for-explicitly-approved-hardware-test-only"
        or readiness.get("blocking_gates") != []
        or readiness.get("production_claim") is not False
        or readiness.get("reproducibility_claim") is not False
    ):
        gates = readiness.get("blocking_gates") if isinstance(readiness, dict) else None
        raise DeployError(f"hardware-test readiness is blocked: {gates!r}")


def _load_fresh_preflight(
    path: Path, expected_sha256: str, audit: Audit, now_unix: int
) -> dict[str, Any]:
    _private_output_parent(path.absolute(), audit.repo_root, "preflight report")
    item = _open_held(path.absolute(), audit.repo_root, "preflight report")
    try:
        if item.sha256 != expected_sha256:
            raise DeployError("preflight report hash mismatch")
        value = _json_bytes(_held_bytes(item, 256 * 1024, "preflight report"), "preflight report")
    finally:
        item.close()
    _exact_keys(value, {"artifacts", "created_at_unix", "mode", "profile", "result", "route_status", "safety", "schema"}, "preflight report")
    _validate_report_safety(value["safety"], audit)
    created = _integer(value["created_at_unix"], "preflight report creation time", minimum=0)
    if created > now_unix + 5 or now_unix - created > APPROVAL_TTL_SECONDS:
        raise DeployError("preflight report is not fresh")
    if (
        value["schema"] != REPORT_SCHEMA
        or value["mode"] != "preflight"
        or value["profile"] != {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256}
        or value["route_status"] != "PREFLIGHT_PASSED_NO_STATE_CHANGE"
        or value.get("result", {}).get("device", {}).get("identity_match") is not True
        or value.get("artifacts", {}).get("candidate", {}).get("sha256") != audit.profile["artifacts"]["candidate"]["sha256"]
        or value.get("result", {}).get("native_stage")
        != {
            "acl_verified": True,
            "deny_write_delete_handle_held": True,
            "path_semantics": _native_stage_path(audit),
            "sha256": audit.profile["artifacts"]["candidate"]["sha256"],
            "size": audit.profile["artifacts"]["candidate"]["size"],
        }
        or value.get("result", {}).get("windows_validation_scope")
        != "full-repository-artifacts-and-prepared-candidate"
    ):
        raise DeployError("preflight report is not an approved fresh device gate")
    return value


def create_approval(
    profile_path: Path,
    preflight_report: Path,
    preflight_report_sha256: str,
    claim_path: Path,
    *,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
    now_unix: int | None = None,
) -> str:
    _sha(preflight_report_sha256, "preflight report SHA-256")
    if claim_path.absolute() == preflight_report.absolute():
        raise DeployError("approval claim must not replace its preflight report")
    audit = local_audit(profile_path, repo_root=repo_root, contract=contract)
    try:
        now = int(time.time()) if now_unix is None else now_unix
        _require_hardware_test_ready(audit)
        _load_fresh_preflight(preflight_report, preflight_report_sha256, audit, now)
        nonce = os.urandom(32).hex()
        claim = {
            "binding": _approval_binding(audit, preflight_report_sha256),
            "expires_at_unix": now + APPROVAL_TTL_SECONDS,
            "issued_at_unix": now,
            "nonce": nonce,
            "schema": APPROVAL_SCHEMA,
        }
        return _publish_private_json(claim_path, claim, audit.repo_root, "approval claim")
    finally:
        audit.close()


def _consume_approval(
    path: Path,
    expected_preflight_sha256: str,
    audit: Audit,
    now_unix: int,
) -> tuple[str, dict[str, Any]]:
    path = path.absolute()
    parent = _private_output_parent(path, audit.repo_root, "approval claim")
    consumed_path = path.with_name(path.name + ".consumed.json")
    if consumed_path.exists():
        raise DeployError("approval claim was already consumed")
    item = _open_held(path, audit.repo_root, "approval claim")
    try:
        claim_sha256 = item.sha256
        claim = _json_bytes(_held_bytes(item, 64 * 1024, "approval claim"), "approval claim")
    finally:
        item.close()
    _exact_keys(claim, {"binding", "expires_at_unix", "issued_at_unix", "nonce", "schema"}, "approval claim")
    _exact_keys(claim["binding"], {"candidate_sha256", "command", "identity_policy_sha256", "preflight_report_sha256", "profile_sha256", "staged_candidate_path"}, "approval binding")
    issued = _integer(claim["issued_at_unix"], "approval issue time", minimum=0)
    expires = _integer(claim["expires_at_unix"], "approval expiry time", minimum=0)
    if claim["schema"] != APPROVAL_SCHEMA or SHA256_RE.fullmatch(str(claim["nonce"])) is None:
        raise DeployError("approval claim schema or nonce mismatch")
    if expires - issued != APPROVAL_TTL_SECONDS or now_unix < issued - 5 or now_unix > expires:
        raise DeployError("approval claim is expired or has an invalid lifetime")
    if claim["binding"] != _approval_binding(audit, expected_preflight_sha256):
        raise DeployError("approval claim binding mismatch")
    marker = {
        "approval_claim_sha256": claim_sha256,
        "consumed_at_unix": now_unix,
        "schema": "lmi-p2-d114-userdata-consumed-approval/v1",
    }
    _publish_private_json(consumed_path, marker, audit.repo_root, "consumed approval marker")
    try:
        path.unlink()
        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as error:
        raise DeployError("approval claim consumption could not be made durable") from error
    return claim_sha256, claim


def _intent_value(
    audit: Audit,
    claim_sha256: str,
    claim: dict[str, Any],
    preflight_sha256: str,
    preflight_created_at_unix: int,
    now_unix: int,
) -> dict[str, Any]:
    candidate = audit.profile["artifacts"]["candidate"]
    stage_path = claim["binding"]["staged_candidate_path"]
    return {
        "approval_window": {
            "expires_at_unix": claim["expires_at_unix"],
            "issued_at_unix": claim["issued_at_unix"],
        },
        "approval_claim_sha256": claim_sha256,
        "candidate_source": {
            "path": candidate["path"],
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        },
        "command": list(claim["binding"]["command"]),
        "created_at_unix": now_unix,
        "identity_policy_sha256": audit.held["mapping:private_identity_policy"].sha256,
        "native_stage": {
            "acl_policy": audit.deploy_policy["native_staging"]["acl_policy"],
            "path": stage_path,
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        },
        "preflight_created_at_unix": preflight_created_at_unix,
        "preflight_report_sha256": preflight_sha256,
        "profile": {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256},
        "schema": INTENT_SCHEMA,
        "state": "PREAUTHORIZED_HELPER_MAY_START_ONCE",
    }


def _publish_intent(
    path: Path,
    audit: Audit,
    claim_sha256: str,
    claim: dict[str, Any],
    preflight_sha256: str,
    preflight_created_at_unix: int,
    now_unix: int,
) -> str:
    return _publish_private_json(
        path,
        _intent_value(
            audit,
            claim_sha256,
            claim,
            preflight_sha256,
            preflight_created_at_unix,
            now_unix,
        ),
        audit.repo_root,
        "preattempt intent journal",
    )


def _read_intent_journal(
    path: Path,
    repo_root: Path,
    *,
    expected_initial_sha256: str | None = None,
) -> IntentJournalSnapshot:
    path = path.absolute()
    repo_root = repo_root.absolute()
    try:
        _check_real_ancestors(path, repo_root, "preattempt intent journal")
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & 0o022
            or before.st_uid != os.geteuid()
            or before.st_size <= 0
        ):
            raise DeployError("preattempt intent journal has an unsafe identity")
        flags = os.O_RDONLY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)

            def stable_identity(value: os.stat_result) -> tuple[int, ...]:
                return (
                    value.st_dev,
                    value.st_ino,
                    value.st_mode,
                    value.st_nlink,
                    value.st_uid,
                    value.st_gid,
                )

            if stable_identity(opened) != stable_identity(before):
                raise DeployError("preattempt intent journal changed while opening")
            payload = bytearray()
            while True:
                chunk = os.read(descriptor, 64 * 1024)
                if not chunk:
                    break
                payload.extend(chunk)
                if len(payload) > 128 * 1024:
                    raise DeployError("preattempt intent journal is too large")
            if stable_identity(os.fstat(descriptor)) != stable_identity(opened):
                raise DeployError("preattempt intent journal identity changed while reading")
        finally:
            os.close(descriptor)
    except (DeployError, OSError) as error:
        raise IntentJournalUntrusted(
            f"preattempt intent journal cannot be safely observed: {error}"
        ) from error
    observed = bytes(payload)
    observed_sha256 = hashlib.sha256(observed).hexdigest()
    observed_size = len(observed)
    first_end = observed.find(b"\n")
    if first_end < 0:
        raise IntentJournalUntrusted(
            "preattempt intent initial record is incomplete",
            observed_sha256=observed_sha256,
            observed_size=observed_size,
        )
    initial_bytes = observed[: first_end + 1]
    try:
        intent = _json_bytes(initial_bytes, "preattempt intent")
        if _canonical_json(intent) != initial_bytes:
            raise DeployError("preattempt intent is not canonical JSON")
    except DeployError as error:
        raise IntentJournalUntrusted(
            str(error),
            observed_sha256=observed_sha256,
            observed_size=observed_size,
        ) from error
    initial_sha256 = hashlib.sha256(initial_bytes).hexdigest()
    if expected_initial_sha256 is not None and initial_sha256 != expected_initial_sha256:
        raise IntentJournalUntrusted(
            "preattempt intent initial hash mismatch",
            observed_sha256=observed_sha256,
            observed_size=observed_size,
        )
    transition: dict[str, Any] | None = None
    terminal: dict[str, Any] | None = None
    outcome_malformed = False
    outcome_bytes = observed[first_end + 1 :]
    if outcome_bytes:
        if not outcome_bytes.endswith(b"\n") or b"\n" in outcome_bytes[:-1]:
            outcome_malformed = True
        else:
            try:
                record = _json_bytes(outcome_bytes, "preattempt intent outcome")
                if _canonical_json(record) != outcome_bytes:
                    raise DeployError("preattempt intent outcome is not canonical JSON")
                if record.get("schema") == INTENT_TRANSITION_SCHEMA:
                    transition = record
                elif record.get("schema") == INTENT_TERMINAL_SCHEMA:
                    terminal = record
                else:
                    raise DeployError("preattempt intent outcome schema mismatch")
            except DeployError:
                outcome_malformed = True
    return IntentJournalSnapshot(
        intent=intent,
        transition=transition,
        terminal=terminal,
        outcome_malformed=outcome_malformed,
        sha256=observed_sha256,
        size=observed_size,
    )


def _validate_intent_terminal(
    terminal: dict[str, Any],
    audit: Audit,
    approval_sha256: str | None,
    intent_initial_sha256: str | None,
) -> None:
    value = _exact_keys(
        terminal,
        {
            "approval_claim_sha256",
            "helper_sha256",
            "intent_initial_sha256",
            "reason",
            "schema",
            "state",
        },
        "preattempt intent terminal",
    )
    if (
        value["schema"] != INTENT_TERMINAL_SCHEMA
        or value["state"] != "HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY"
        or value["approval_claim_sha256"] != approval_sha256
        or value["intent_initial_sha256"] != intent_initial_sha256
        or value["helper_sha256"] != audit.held["policy:helper"].sha256
        or not isinstance(value["reason"], str)
        or re.fullmatch(r"[A-Z0-9_]{1,96}", value["reason"]) is None
    ):
        raise DeployError("preattempt intent terminal binding mismatch")


def _validate_intent_binding(
    intent: dict[str, Any],
    audit: Audit,
    journal_path: Path,
    *,
    expected_approval_sha256: str | None = None,
    expected_native_stage_path: str | None = None,
) -> tuple[str, str]:
    top = _exact_keys(
        intent,
        {
            "approval_window",
            "approval_claim_sha256",
            "candidate_source",
            "command",
            "created_at_unix",
            "identity_policy_sha256",
            "native_stage",
            "preflight_created_at_unix",
            "preflight_report_sha256",
            "profile",
            "schema",
            "state",
        },
        "preattempt intent",
    )
    candidate_source = _exact_keys(
        top["candidate_source"], {"path", "sha256", "size"}, "intent candidate source"
    )
    native_stage = _exact_keys(
        top["native_stage"], {"acl_policy", "path", "sha256", "size"}, "intent native stage"
    )
    profile = _exact_keys(top["profile"], {"id", "sha256"}, "intent profile")
    approval_window = _exact_keys(
        top["approval_window"],
        {"expires_at_unix", "issued_at_unix"},
        "intent approval window",
    )
    approval_sha256 = _sha(top["approval_claim_sha256"], "intent approval claim SHA-256")
    _sha(top["preflight_report_sha256"], "intent preflight report SHA-256")
    created = _integer(top["created_at_unix"], "intent creation time", minimum=0)
    issued = _integer(
        approval_window["issued_at_unix"], "intent approval issue time", minimum=0
    )
    expires = _integer(
        approval_window["expires_at_unix"], "intent approval expiry time", minimum=0
    )
    preflight_created = _integer(
        top["preflight_created_at_unix"],
        "intent preflight creation time",
        minimum=0,
    )
    stage_path = _string(native_stage["path"], "intent native stage path")
    root = audit.deploy_policy["native_staging"]["root_semantics"].rstrip("/")
    prefix = root + "/"
    relative = stage_path[len(prefix) :] if stage_path.startswith(prefix) else ""
    parts = relative.split("/")
    if (
        len(parts) != 3
        or SHA256_RE.fullmatch(parts[0]) is None
        or SHA256_RE.fullmatch(parts[1]) is None
        or parts[2] != audit.deploy_policy["native_staging"]["filename"]
        or parts[0] != audit.profile_sha256
        or parts[1] != audit.profile["artifacts"]["candidate"]["sha256"]
        or _native_stage_path(audit) != stage_path
    ):
        raise DeployError("preattempt intent native stage path mismatch")
    candidate = audit.profile["artifacts"]["candidate"]
    if (
        top["schema"] != INTENT_SCHEMA
        or top["state"] != "PREAUTHORIZED_HELPER_MAY_START_ONCE"
        or expires - issued != APPROVAL_TTL_SECONDS
        or created < issued - 5
        or created > expires
        or preflight_created > created + 5
        or created - preflight_created > APPROVAL_TTL_SECONDS
        or candidate_source
        != {"path": candidate["path"], "sha256": candidate["sha256"], "size": candidate["size"]}
        or top["identity_policy_sha256"]
        != audit.held["mapping:private_identity_policy"].sha256
        or native_stage
        != {
            "acl_policy": audit.deploy_policy["native_staging"]["acl_policy"],
            "path": stage_path,
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        }
        or profile != {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256}
        or top["command"]
        != ["-s", "<identity-policy-matched-device>", "flash", "userdata", stage_path]
        or journal_path.name
        != f".lmi-p2-d114-preattempt-{approval_sha256}.json"
    ):
        raise DeployError("preattempt intent binding mismatch")
    if expected_approval_sha256 is not None and approval_sha256 != expected_approval_sha256:
        raise DeployError("preattempt intent approval binding mismatch")
    if expected_native_stage_path is not None and stage_path != expected_native_stage_path:
        raise DeployError("preattempt intent native stage binding mismatch")
    return approval_sha256, stage_path


def recover_intent(
    profile_path: Path,
    journal_path: Path,
    intent_initial_sha256: str,
    report_path: Path,
    *,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
    now_unix: int | None = None,
) -> tuple[str, str]:
    now = int(time.time()) if now_unix is None else now_unix
    _sha(intent_initial_sha256, "intent initial SHA-256")
    _private_output_parent(report_path.absolute(), repo_root.absolute(), "report")
    if report_path.absolute() == journal_path.absolute():
        raise DeployError("recovery report must not replace its intent journal")
    audit = local_audit(profile_path, repo_root=repo_root, contract=contract)
    try:
        journal = _read_intent_journal(
            journal_path,
            audit.repo_root,
            expected_initial_sha256=intent_initial_sha256,
        )
        approval_sha256, stage_path = _validate_intent_binding(
            journal.intent, audit, journal_path.absolute()
        )
        context = RunContext(
            journal_path.absolute(), approval_sha256, intent_initial_sha256, stage_path
        )
        helper = _validate_helper(
            _recover_helper_from_intent(
                "Execute", audit, context, "PROCESS_RESTART_INTENT_RECOVERY"
            ),
            "Execute",
            audit,
            context,
            allow_recovered=True,
        )
        route = helper["route_status"]
        final_journal = _read_intent_journal(
            journal_path,
            audit.repo_root,
            expected_initial_sha256=intent_initial_sha256,
        )
        if route == "REFUSED_NO_STATE_CHANGE":
            if final_journal.terminal is None or final_journal.outcome_malformed:
                raise DeployError("terminal recovery evidence is no longer complete")
            _validate_intent_terminal(
                final_journal.terminal,
                audit,
                approval_sha256,
                intent_initial_sha256,
            )
        result = {
            "approval_claim_sha256": context.approval_claim_sha256,
            "artifact_hashes": helper["artifact_hashes"],
            "attempt_journal": {
                "initial_sha256": intent_initial_sha256,
                "path": str(journal_path.absolute().relative_to(audit.repo_root)),
                "sha256": final_journal.sha256,
                "size": final_journal.size,
            },
            "device": helper["device"],
            "flash": helper["flash"],
            "locked_inputs_intact": helper["locked_inputs_intact"],
            "native_stage": helper["native_stage"],
            "post_helper_input_recheck": False,
            "prior_write": None,
            "reason": helper["reason"],
            "windows_validation_scope": helper["windows_validation_scope"],
        }
        report = {
            "artifacts": {
                name: {
                    "path": audit.profile["artifacts"][name]["path"],
                    "sha256": audit.held[name].sha256,
                    "size": audit.held[name].size,
                }
                for name in audit.profile["artifacts"]
            },
            "created_at_unix": now,
            "mode": "execute",
            "profile": {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256},
            "result": result,
            "route_status": route,
            "safety": _report_safety(audit),
            "schema": REPORT_SCHEMA,
        }
        return route, _publish_report(report_path, report, audit.repo_root)
    except ExecuteIntentIndeterminate:
        raise
    except Exception as error:
        raise ExecuteIntentIndeterminate(
            "execute intent recovery remains indeterminate; no same-claim retry"
        ) from error
    finally:
        audit.close()


def _safe_execute_recovery_helper(
    audit: Audit, context: RunContext, reason: str
) -> dict[str, Any]:
    try:
        recovered = _recover_helper_from_intent("Execute", audit, context, reason)
    except Exception:
        recovered = _untrusted_intent_unknown_helper(
            audit,
            context,
            "EXECUTE_INITIAL_INTENT_UNTRUSTED_CLAIM_CONSUMED",
        )
    return _validate_helper(
        recovered, "Execute", audit, context, allow_recovered=True
    )


def _execute_journal_result(
    audit: Audit,
    context: RunContext,
    expected_intent: dict[str, Any],
    helper: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    relative_path = str(context.journal_path.relative_to(audit.repo_root))
    try:
        journal = _read_intent_journal(
            context.journal_path,
            audit.repo_root,
            expected_initial_sha256=context.intent_initial_sha256,
        )
    except IntentJournalUntrusted as error:
        return (
            _safe_execute_recovery_helper(
                audit, context, "EXECUTE_INITIAL_INTENT_UNTRUSTED_CLAIM_CONSUMED"
            ),
            {
                "initial_sha256": context.intent_initial_sha256,
                "path": relative_path,
                "sha256": error.observed_sha256,
                "size": error.observed_size,
            },
        )

    binding = {
        "initial_sha256": context.intent_initial_sha256,
        "path": relative_path,
        "sha256": journal.sha256,
        "size": journal.size,
    }
    if journal.intent != expected_intent or journal.outcome_malformed:
        return (
            _safe_execute_recovery_helper(
                audit, context, "INTENT_OUTCOME_MALFORMED_CLAIM_CONSUMED"
            ),
            binding,
        )
    expected_transition = {
        "approval_claim_sha256": context.approval_claim_sha256,
        "containment_confirmed": True,
        "identity_match": True,
        "native_stage_path_semantics": context.native_stage_path,
        "schema": INTENT_TRANSITION_SCHEMA,
        "snapshot_identity_confirmed": True,
        "state": "ATTEMPT_STARTING_CONSERVATIVE",
    }
    try:
        if journal.terminal is not None:
            _validate_intent_terminal(
                journal.terminal,
                audit,
                context.approval_claim_sha256,
                context.intent_initial_sha256,
            )
            expected_reason = (
                "HELPER_TERMINAL_NO_ATTEMPT_INTENT_RECOVERY"
                if helper["recovered_from_intent_journal"] is True
                else journal.terminal["reason"]
            )
            if (
                helper["flash"]["attempts"] != 0
                or helper["route_status"] != "REFUSED_NO_STATE_CHANGE"
                or helper["reason"] != expected_reason
            ):
                raise DeployError("preattempt intent terminal result mismatch")
        else:
            if helper["route_status"] == "REFUSED_NO_STATE_CHANGE":
                raise DeployError("execute refusal lacks a durable terminal record")
            indeterminate_recovery = (
                helper["recovered_from_intent_journal"] is True
                and helper["route_status"] == "WRITE_ATTEMPTED_RESULT_UNKNOWN"
                and helper["flash"]["attempts"] == 1
                and journal.transition is None
            )
            if (
                helper["flash"]["attempts"] == 1
                and journal.transition != expected_transition
                and not indeterminate_recovery
            ):
                raise DeployError("preattempt intent transition mismatch")
            if helper["flash"]["attempts"] == 0:
                raise DeployError("execute no-attempt result lacks terminal evidence")
        return helper, binding
    except Exception:
        return (
            _safe_execute_recovery_helper(
                audit, context, "HELPER_OR_JOURNAL_VALIDATION_FAILED_CLAIM_CONSUMED"
            ),
            binding,
        )


def operate(
    mode: str,
    profile_path: Path,
    report_path: Path,
    *,
    prior_report: Path | None = None,
    prior_report_sha256: str | None = None,
    replug_confirmed: bool = False,
    preflight_report: Path | None = None,
    preflight_report_sha256: str | None = None,
    approval_claim: Path | None = None,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
    powershell_runner: PowerShellRunner = run_powershell,
    now_unix: int | None = None,
) -> tuple[str, str]:
    _private_output_parent(report_path.absolute(), repo_root.absolute(), "report")
    audit = local_audit(profile_path, repo_root=repo_root, contract=contract)
    try:
        now = int(time.time()) if now_unix is None else now_unix
        prior_binding: dict[str, Any] | None = None
        approval_sha256: str | None = None
        approval_value: dict[str, Any] | None = None
        preflight_value: dict[str, Any] | None = None
        intent_initial_sha256: str | None = None
        journal_path: Path | None = None
        prior_route: str | None = None
        if mode == "postwrite":
            if prior_report is None or prior_report_sha256 is None or not replug_confirmed:
                raise DeployError("postwrite requires the exact prior report hash and confirmed physical replug")
            _sha(prior_report_sha256, "prior report SHA-256")
            if report_path.absolute() == prior_report.absolute():
                raise DeployError("postwrite report must not replace its prior report")
            prior_value = _load_prior_report(prior_report, prior_report_sha256, audit)
            prior_route = prior_value["route_status"]
            prior_binding = {"route_status": prior_route, "sha256": prior_report_sha256, "replug_confirmed": True}
        elif prior_report is not None or prior_report_sha256 is not None or replug_confirmed:
            raise DeployError("prior-report and replug arguments are postwrite-only")

        if mode == "execute":
            if preflight_report is None or preflight_report_sha256 is None or approval_claim is None:
                raise DeployError("execute requires a fresh preflight report and one-use approval claim")
            _require_hardware_test_ready(audit)
            if report_path.absolute() in {
                preflight_report.absolute(), approval_claim.absolute()
            }:
                raise DeployError("execute report, preflight report, and approval claim must be distinct")
            _sha(preflight_report_sha256, "preflight report SHA-256")
            preflight_value = _load_fresh_preflight(
                preflight_report, preflight_report_sha256, audit, now
            )
            approval_sha256, approval_value = _consume_approval(
                approval_claim, preflight_report_sha256, audit, now
            )
            journal_path = report_path.absolute().parent / (
                f".lmi-p2-d114-preattempt-{approval_sha256}.json"
            )
            intent_initial_sha256 = _publish_intent(
                journal_path,
                audit,
                approval_sha256,
                approval_value,
                preflight_report_sha256,
                preflight_value["created_at_unix"],
                now,
            )
        elif preflight_report is not None or preflight_report_sha256 is not None or approval_claim is not None:
            raise DeployError("preflight report and approval claim are execute-only")

        if mode == "local-audit":
            result: dict[str, Any] = {
                "artifact_hashes": {
                    "profile": audit.profile_sha256,
                    **{
                        name: audit.held[name].sha256
                        for name in audit.profile["artifacts"]
                    },
                },
                "device": None,
                "flash": {"attempts": 0},
                "locked_inputs_intact": True,
                "post_helper_input_recheck": True,
                "prior_write": None,
            }
            route = "LOCAL_AUDIT_PASSED_NO_DEVICE_ACCESS"
        else:
            helper_mode = {"preflight": "Preflight", "execute": "Execute", "postwrite": "Postwrite"}[mode]
            effective_journal = (
                journal_path
                if journal_path is not None
                else report_path.absolute().parent
                / ".lmi-p2-d114-no-write-journal-unused.json"
            )
            context = RunContext(
                effective_journal,
                approval_sha256,
                intent_initial_sha256,
                (
                    approval_value["binding"]["staged_candidate_path"]
                    if approval_value is not None
                    else (_native_stage_path(audit) if mode == "preflight" else None)
                ),
            )
            try:
                helper = _validate_helper(
                    powershell_runner(helper_mode, audit, context),
                    helper_mode,
                    audit,
                    context,
                )
            except Exception:
                if mode != "execute":
                    raise
                helper = _safe_execute_recovery_helper(
                    audit,
                    context,
                    "HELPER_OR_RESULT_VALIDATION_FAILED_CLAIM_CONSUMED",
                )
            journal_binding: dict[str, Any] | None = None
            if mode == "execute":
                if approval_value is None or preflight_value is None:
                    raise ExecuteIntentIndeterminate(
                        "durable execute intent lost its in-memory approval binding"
                    )
                helper, journal_binding = _execute_journal_result(
                    audit,
                    context,
                    _intent_value(
                        audit,
                        approval_sha256,
                        approval_value,
                        preflight_report_sha256,
                        preflight_value["created_at_unix"],
                        now,
                    ),
                    helper,
                )
            result = {"approval_claim_sha256": approval_sha256, "artifact_hashes": helper["artifact_hashes"], "attempt_journal": journal_binding, "device": helper["device"], "flash": helper["flash"], "locked_inputs_intact": helper["locked_inputs_intact"], "native_stage": helper["native_stage"], "post_helper_input_recheck": True, "prior_write": prior_binding, "reason": helper["reason"], "windows_validation_scope": helper["windows_validation_scope"]}
            route = helper["route_status"]
            if mode == "postwrite" and route == "POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE":
                route = (
                    "POSTWRITE_REVALIDATED_PRIOR_COMPLETED_NO_STATE_CHANGE"
                    if prior_route == "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING"
                    else "POSTWRITE_REVALIDATED_PRIOR_UNKNOWN_NO_STATE_CHANGE"
                )
            elif mode == "postwrite" and route == "REFUSED_NO_STATE_CHANGE":
                route = (
                    "POSTWRITE_REVALIDATION_FAILED_PRIOR_COMPLETED_NO_STATE_CHANGE"
                    if prior_route == "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING"
                    else "POSTWRITE_REVALIDATION_FAILED_PRIOR_UNKNOWN_NO_STATE_CHANGE"
                )
        try:
            _recheck(audit)
        except DeployError:
            if mode != "execute" or result.get("flash", {}).get("attempts") != 1:
                raise
            result["post_helper_input_recheck"] = False
            result["reason"] = "POST_HELPER_INPUT_IDENTITY_MISMATCH"
            route = (
                "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING"
                if result["flash"].get("transport_completed") is True
                else "WRITE_ATTEMPTED_RESULT_UNKNOWN"
            )
        report_created_at = int(time.time()) if now_unix is None else now
        report = {
            "artifacts": {
                name: {"path": audit.profile["artifacts"][name]["path"], "sha256": audit.held[name].sha256, "size": audit.held[name].size}
                for name in audit.profile["artifacts"]
            },
            "created_at_unix": report_created_at,
            "mode": mode,
            "profile": {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256},
            "result": result,
            "route_status": route,
            "safety": _report_safety(audit),
            "schema": REPORT_SCHEMA,
        }
        digest = _publish_report(report_path, report, audit.repo_root)
        return route, digest
    except ExecuteIntentIndeterminate:
        raise
    except Exception as error:
        if mode == "execute" and approval_sha256 is not None:
            raise ExecuteIntentIndeterminate(
                "durable execute intent outcome is indeterminate; claim consumed"
            ) from error
        raise
    finally:
        audit.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    for mode in ("local-audit", "preflight", "execute", "postwrite"):
        selected = sub.add_parser(mode)
        selected.add_argument("--profile", required=True, type=Path)
        selected.add_argument("--report", required=True, type=Path)
        if mode == "postwrite":
            selected.add_argument("--write-report", required=True, type=Path)
            selected.add_argument("--write-report-sha256", required=True)
            selected.add_argument("--replug-confirmed", required=True, action="store_true")
        if mode == "execute":
            selected.add_argument("--preflight-report", required=True, type=Path)
            selected.add_argument("--preflight-report-sha256", required=True)
            selected.add_argument("--approval-claim", required=True, type=Path)
    approve = sub.add_parser("approve")
    approve.add_argument("--profile", required=True, type=Path)
    approve.add_argument("--preflight-report", required=True, type=Path)
    approve.add_argument("--preflight-report-sha256", required=True)
    approve.add_argument("--approval-claim", required=True, type=Path)
    approve.add_argument("--acknowledge-userdata-write", required=True, action="store_true")
    recover = sub.add_parser("recover-intent")
    recover.add_argument("--profile", required=True, type=Path)
    recover.add_argument("--intent-journal", required=True, type=Path)
    recover.add_argument("--intent-initial-sha256", required=True)
    recover.add_argument("--report", required=True, type=Path)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.mode == "approve":
            digest = create_approval(
                arguments.profile,
                arguments.preflight_report,
                arguments.preflight_report_sha256,
                arguments.approval_claim,
            )
            print("approval_status=ONE_USE_CLAIM_CREATED")
            print(f"approval_claim_sha256={digest}")
            return 0
        if arguments.mode == "recover-intent":
            route, digest = recover_intent(
                arguments.profile,
                arguments.intent_journal,
                arguments.intent_initial_sha256,
                arguments.report,
            )
            print(f"route_status={route}")
            print(f"report_sha256={digest}")
            return 3 if route == "WRITE_ATTEMPTED_RESULT_UNKNOWN" else 2
        route, digest = operate(
            arguments.mode,
            arguments.profile,
            arguments.report,
            prior_report=getattr(arguments, "write_report", None),
            prior_report_sha256=getattr(arguments, "write_report_sha256", None),
            replug_confirmed=getattr(arguments, "replug_confirmed", False),
            preflight_report=getattr(arguments, "preflight_report", None),
            preflight_report_sha256=getattr(arguments, "preflight_report_sha256", None),
            approval_claim=getattr(arguments, "approval_claim", None),
        )
    except ExecuteIntentIndeterminate as error:
        print("route_status=WRITE_ATTEMPTED_RESULT_UNKNOWN")
        print(f"indeterminate_no_same_claim_retry: {error}", file=os.sys.stderr)
        return 3
    except (DeployError, OSError, ValueError) as error:
        if arguments.mode == "recover-intent":
            print("route_status=WRITE_ATTEMPTED_RESULT_UNKNOWN")
            print(f"indeterminate_no_same_claim_retry: {error}", file=os.sys.stderr)
            return 3
        print(f"refused: {error}", file=os.sys.stderr)
        return 2
    print(f"route_status={route}")
    print(f"report_sha256={digest}")
    if route in {"USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING", "WRITE_ATTEMPTED_RESULT_UNKNOWN"}:
        return 3
    if route == "REFUSED_NO_STATE_CHANGE":
        return 2
    if route.startswith("POSTWRITE_REVALIDATION_FAILED_"):
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
