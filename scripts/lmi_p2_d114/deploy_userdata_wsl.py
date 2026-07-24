#!/usr/bin/env python3
"""Fail-closed, WSL-native, one-use D114 physical-userdata deployment gate.

``local-audit`` is host-only.  ``preflight`` uses fixed read-only fastboot
queries.  ``approve`` creates a 120-second, one-use claim from an exact fresh
preflight.  ``execute`` consumes the claim, repeats the complete device gate,
fsyncs a pre-attempt intent, and can issue exactly one physical, unsuffixed
``userdata`` flash using the already-open candidate file descriptor.

Nothing in this module boots, reboots, erases, formats, selects fastbootd,
falls back to ``super``, or writes a slotted partition.  There is no automatic
or same-claim retry.  A timeout or incomplete result is conservatively an
attempt with unknown outcome.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import signal
import stat
import struct
import subprocess
import tempfile
import time
from typing import Any, BinaryIO, Callable, Mapping, Sequence


REPO = Path(__file__).resolve().parents[2]
PROFILE_SCHEMA = "lmi-p2-d114-userdata-deploy-profile-wsl/v1"
POLICY_SCHEMA = "lmi-p2-d114-userdata-deploy-policy-lock-wsl/v1"
RUNTIME_SCHEMA = "lmi-p2-d114-fastboot-wsl-runtime-lock/v2"
COMPLETED_SCHEMA = "lmi-p2-d114-completed-userdata-actions-lock/v1"
MAPPING_SCHEMA = "lmi-d114-physical-userdata-mapping/v2"
PREFLIGHT_SCHEMA = "lmi-p2-d114-userdata-wsl-preflight/v1"
APPROVAL_SCHEMA = "lmi-p2-d114-userdata-wsl-one-use-approval/v1"
CONSUMED_SCHEMA = "lmi-p2-d114-userdata-wsl-consumed-claim/v1"
INTENT_SCHEMA = "lmi-p2-d114-userdata-wsl-preattempt-intent/v1"
REPORT_SCHEMA = "lmi-p2-d114-userdata-wsl-deploy-report/v1"

APPROVAL_TTL_SECONDS = 120
PREFLIGHT_MAX_AGE_SECONDS = 120
WRITE_TIMEOUT_SECONDS = 1800
QUERY_TIMEOUT_SECONDS = 20
MAX_OUTPUT_BYTES = 64 * 1024

PREFLIGHT_ROUTE = "PREFLIGHT_PASSED_NO_STATE_CHANGE"
COMPLETED_ROUTE = "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING"
UNKNOWN_ROUTE = "USERDATA_WRITE_OUTCOME_UNKNOWN_NO_RETRY"

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
SERIAL_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
SAFE_REASON_RE = re.compile(r"^[A-Z0-9_]{1,96}$")

SPARSE_HEADER = struct.Struct("<I4H4I")
CHUNK_HEADER = struct.Struct("<2H2I")
SPARSE_MAGIC = 0xED26FF3A
CHUNK_RAW = 0xCAC1
CHUNK_FILL = 0xCAC2
CHUNK_DONT_CARE = 0xCAC3
CHUNK_CRC32 = 0xCAC4

QUERY_NAMES = (
    "devices",
    "getvar:serialno",
    "getvar:product",
    "getvar:unlocked",
    "getvar:is-userspace",
    "getvar:is-logical:userdata",
    "getvar:partition-type:userdata",
    "getvar:partition-size:userdata",
    "getvar:battery-voltage",
    "getvar:battery-soc-ok",
    "getvar:max-download-size",
)

SAFE_ENV = {"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"}
LOADER_ENV_NAMES = frozenset(
    {"LD_AUDIT", "LD_DEBUG", "LD_LIBRARY_PATH", "LD_PRELOAD", "LD_PROFILE"}
)


class DeployError(RuntimeError):
    """A local input, runtime, device, claim, or publication gate failed."""


@dataclass(frozen=True)
class Contract:
    assembly_sha256: str = "cfcf2cc4a1b9ad149ce0a303ab6b49b570c5e2cd78a988b06b8ca4a72c90b4da"
    assembly_size: int = 7_232
    injection_sha256: str = "ad14a24791e8b60d72787c756ea91a00fb3325491f5d6d62592ae44e2a352a9a"
    injection_size: int = 7_190
    rootfs_sha256: str = "a91a2090aea6a1d7338a7f51ba66590472cbb395386765d9e5a199856afba134"
    rootfs_size: int = 2_923_429_888
    raw_sha256: str = "c3c3a51376417aeba94c3fbd536df7d68b3ab4559ca5ba19f0dd18d1e157a8de"
    raw_size: int = 3_436_183_552
    sparse_sha256: str = "77ff199311f71b3f3e4fdf3e3251138abc0f46664567b2deae409a79c960b2a1"
    sparse_size: int = 2_236_696_908
    mapping_sha256: str = "59f27854ac595a9b615bddeb91aa72e6bf1e0dacd9341cda2783a19bb050014f"
    mapping_size: int = 3_879
    runtime_sha256: str = "a2db2d343aeeead7400da9b0487de536ba0842d20a3861fdde23ca647d71c65d"
    runtime_size: int = 8_066
    completed_sha256: str = "5c7c9b79baf58366167bf5d58bc65554d4e54a9f1e07b160d705d2cf58a837df"
    completed_size: int = 1_160
    template_sha256: str = "cd6a071425309a83442f4de3dbd71c68b7261cfb1deaac16686271757ac70800"
    template_size: int = 2_653
    old_sparse_sha256: str = "39d45c6de7d2708f59154b1dd9352573849fc0a51434ebfd9d0f493c36841583"
    d110_boot_sha256: str = "2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487"
    d110_boot_size: int = 52_944_896
    rollback_sha256: str = "1315e3a06ddff42e91f930f01b16a62ab30ab3d4f490e8e8e40d0af89c657279"
    rollback_size: int = 2_269_624_624
    baseline_raw_sha256: str = "33067d6954e28b88b78a79a6ba0f994c1b6aff5e77a664b726e5dbb6e90084d8"
    userdata_capacity: int = 114_898_743_296


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
    profile: dict[str, Any]
    profile_sha256: str
    policy: dict[str, Any]
    mapping: dict[str, Any]
    completed: dict[str, Any]
    runtime: dict[str, Any]
    held: dict[str, HeldFile]
    argv_prefix: tuple[str, ...]
    contract: Contract = PRODUCTION

    @property
    def candidate(self) -> HeldFile:
        return self.held["candidate"]

    def close(self) -> None:
        for item in reversed(tuple(self.held.values())):
            item.close()


@dataclass(frozen=True)
class CommandResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    started: bool = True
    timed_out: bool = False
    output_limited: bool = False


@dataclass(frozen=True)
class DeviceEvidence:
    serial: str
    identity_binding: str
    public: dict[str, Any]


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


def _canonical(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _exact(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise DeployError(f"{label} fields mismatch")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise DeployError(f"{label} is not a lowercase SHA-256")
    return value


def _positive(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise DeployError(f"{label} must be a positive integer")
    return value


def _identity(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_nlink,
        info.st_uid,
        info.st_gid,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _relative(value: Any, label: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise DeployError(f"{label} is not a canonical repository-relative path")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in result.parts):
        raise DeployError(f"{label} is not a canonical repository-relative path")
    if result.as_posix() != value:
        raise DeployError(f"{label} is not canonical")
    return result


def _repo_relative(path: Path, root: Path, label: str) -> str:
    try:
        value = path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError:
        raise DeployError(f"{label} escapes the repository") from None
    _relative(value, label)
    return value


def _check_ancestors(path: Path, root: Path | None, label: str) -> None:
    path = path.absolute()
    if root is not None:
        relative = PurePosixPath(_repo_relative(path, root, label))
        current = root.absolute()
        components = relative.parts[:-1]
    else:
        if not path.is_absolute():
            raise DeployError(f"{label} path is not absolute")
        current = Path("/")
        components = path.parts[1:-1]
    for component in components:
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise DeployError(f"cannot inspect {label} ancestor") from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise DeployError(f"{label} has a symlink or non-directory ancestor")
        if info.st_mode & 0o022:
            raise DeployError(f"{label} has a group/world-writable ancestor")


def _hash_descriptor(descriptor: int, size: int, label: str) -> str:
    os.lseek(descriptor, 0, os.SEEK_SET)
    digest = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = os.read(descriptor, min(4 * 1024 * 1024, remaining))
        if not chunk:
            raise DeployError(f"{label} was truncated while hashing")
        digest.update(chunk)
        remaining -= len(chunk)
    if os.read(descriptor, 1):
        raise DeployError(f"{label} grew while hashing")
    os.lseek(descriptor, 0, os.SEEK_SET)
    return digest.hexdigest()


def _open_regular(path: Path, root: Path | None, label: str, *, maximum: int | None = None) -> HeldFile:
    path = path.absolute()
    _check_ancestors(path, root, label)
    try:
        before = path.lstat()
    except OSError as error:
        raise DeployError(f"cannot inspect {label}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_mode & 0o022
        or before.st_size <= 0
        or (maximum is not None and before.st_size > maximum)
    ):
        raise DeployError(f"{label} is not a safe single-link regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise DeployError(f"cannot safely open {label}") from error
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise DeployError(f"{label} changed while opening")
        digest = _hash_descriptor(descriptor, opened.st_size, label)
        if _identity(os.fstat(descriptor)) != _identity(opened):
            raise DeployError(f"{label} changed while hashing")
        return HeldFile(path, descriptor, _identity(opened), opened.st_size, digest)
    except BaseException:
        os.close(descriptor)
        raise


def _held_bytes(item: HeldFile, maximum: int, label: str) -> bytes:
    if item.size > maximum:
        raise DeployError(f"{label} is too large")
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) < item.size:
        chunk = os.read(item.descriptor, item.size - len(result))
        if not chunk:
            raise DeployError(f"{label} became unreadable")
        result.extend(chunk)
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    return bytes(result)


def _open_spec(
    spec: Any,
    root: Path,
    label: str,
    held: dict[str, HeldFile],
    key: str,
    *,
    maximum: int | None = None,
    sparse: bool = False,
) -> HeldFile:
    value = _artifact(spec, label, sparse=sparse)
    path = root / _relative(value["path"], f"{label}.path")
    expected_sha = _sha(value["sha256"], f"{label}.sha256")
    expected_size = _positive(value["size"], f"{label}.size")
    item = _open_regular(path, root, label, maximum=maximum)
    if item.size != expected_size or item.sha256 != expected_sha:
        item.close()
        raise DeployError(f"{label} identity mismatch")
    held[key] = item
    return item


def _read_exact(stream: BinaryIO, length: int, label: str) -> bytes:
    result = stream.read(length)
    if len(result) != length:
        raise DeployError(f"short {label}")
    return result


def _hash_fill(digest: Any, pattern: bytes, length: int) -> None:
    block = pattern * (1024 * 1024 // len(pattern))
    while length:
        amount = min(length, len(block))
        digest.update(block[:amount])
        length -= amount


def inspect_sparse(item: HeldFile, logical_size: int, roundtrip_sha256: str) -> None:
    stream = os.fdopen(os.dup(item.descriptor), "rb", closefd=True)
    try:
        header = _read_exact(stream, SPARSE_HEADER.size, "sparse header")
        magic, major, minor, file_hdr_sz, chunk_hdr_sz, block_size, blocks, chunks, _checksum = SPARSE_HEADER.unpack(header)
        if (
            magic != SPARSE_MAGIC
            or (major, minor) != (1, 0)
            or file_hdr_sz < SPARSE_HEADER.size
            or chunk_hdr_sz < CHUNK_HEADER.size
            or block_size <= 0
            or blocks * block_size != logical_size
        ):
            raise DeployError("candidate sparse header mismatch")
        _read_exact(stream, file_hdr_sz - SPARSE_HEADER.size, "extended sparse header")
        digest = hashlib.sha256()
        produced = 0
        for _index in range(chunks):
            raw = _read_exact(stream, chunk_hdr_sz, "sparse chunk header")
            kind, _reserved, chunk_blocks, total_size = CHUNK_HEADER.unpack(raw[: CHUNK_HEADER.size])
            output_size = chunk_blocks * block_size
            payload_size = total_size - chunk_hdr_sz
            if total_size < chunk_hdr_sz:
                raise DeployError("negative sparse chunk payload")
            if kind == CHUNK_RAW:
                if payload_size != output_size:
                    raise DeployError("raw sparse chunk size mismatch")
                remaining = payload_size
                while remaining:
                    data = _read_exact(stream, min(4 * 1024 * 1024, remaining), "raw sparse chunk")
                    digest.update(data)
                    remaining -= len(data)
                produced += output_size
            elif kind == CHUNK_FILL:
                if payload_size != 4:
                    raise DeployError("fill sparse chunk size mismatch")
                _hash_fill(digest, _read_exact(stream, 4, "fill pattern"), output_size)
                produced += output_size
            elif kind == CHUNK_DONT_CARE:
                if payload_size != 0:
                    raise DeployError("don't-care sparse chunk has payload")
                _hash_fill(digest, b"\0\0\0\0", output_size)
                produced += output_size
            elif kind == CHUNK_CRC32:
                if payload_size != 4 or output_size != 0:
                    raise DeployError("CRC sparse chunk mismatch")
                _read_exact(stream, 4, "sparse CRC")
            else:
                raise DeployError("unknown sparse chunk type")
        if produced != logical_size or stream.read(1):
            raise DeployError("candidate sparse logical size or trailing data mismatch")
        if digest.hexdigest() != roundtrip_sha256:
            raise DeployError("candidate sparse roundtrip raw hash mismatch")
    finally:
        stream.close()
        os.lseek(item.descriptor, 0, os.SEEK_SET)


def _artifact(value: Any, label: str, *, sparse: bool = False) -> dict[str, Any]:
    keys = {"path", "sha256", "size"}
    if sparse:
        keys |= {"logical_size", "representation", "roundtrip_raw_sha256"}
    result = _exact(value, keys, label)
    _relative(result["path"], f"{label}.path")
    _sha(result["sha256"], f"{label}.sha256")
    _positive(result["size"], f"{label}.size")
    if sparse:
        _positive(result["logical_size"], f"{label}.logical_size")
        _sha(result["roundtrip_raw_sha256"], f"{label}.roundtrip_raw_sha256")
        if result["representation"] != "android-sparse":
            raise DeployError(f"{label} representation mismatch")
    return result


def _expected_policy_artifacts(contract: Contract) -> dict[str, Any]:
    return {
        "assembly_attestation": {"sha256": contract.assembly_sha256, "size": contract.assembly_size},
        "candidate_raw": {"sha256": contract.raw_sha256, "size": contract.raw_size},
        "candidate_sparse": {
            "logical_size": contract.raw_size,
            "roundtrip_raw_sha256": contract.raw_sha256,
            "sha256": contract.sparse_sha256,
            "size": contract.sparse_size,
        },
        "injection_attestation": {"sha256": contract.injection_sha256, "size": contract.injection_size},
        "p2_rootfs": {"sha256": contract.rootfs_sha256, "size": contract.rootfs_size},
        "rollback_sparse": {
            "logical_size": contract.raw_size,
            "roundtrip_raw_sha256": contract.baseline_raw_sha256,
            "sha256": contract.rollback_sha256,
            "size": contract.rollback_size,
        },
    }


def _validate_policy(value: dict[str, Any], contract: Contract) -> None:
    _exact(
        value,
        {
            "approval", "artifact_contract", "bindings", "device_gate", "execution",
            "fixed_read_only_queries", "hardware_test_only", "historical_actions",
            "privacy", "runtime", "schema",
        },
        "WSL deploy policy",
    )
    if value["schema"] != POLICY_SCHEMA or value["hardware_test_only"] is not True:
        raise DeployError("WSL deploy policy schema/scope mismatch")
    if value["approval"] != {
        "fresh_preflight_required": True,
        "preflight_max_age_seconds": PREFLIGHT_MAX_AGE_SECONDS,
        "same_claim_retry": False,
        "ttl_seconds": APPROVAL_TTL_SECONDS,
    }:
        raise DeployError("approval policy mismatch")
    if value["artifact_contract"] != _expected_policy_artifacts(contract):
        raise DeployError("artifact policy contract mismatch")
    expected_bindings = {
        "completed_actions_lock": {
            "path": "config/lmi-p2-d114/completed-userdata-actions-lock.json",
            "sha256": contract.completed_sha256,
            "size": contract.completed_size,
        },
        "fastboot_runtime_lock": {
            "path": "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json",
            "sha256": contract.runtime_sha256,
            "size": contract.runtime_size,
        },
        "physical_userdata_mapping": {
            "path": "config/lmi-p2-d114/physical-userdata-mapping.json",
            "sha256": contract.mapping_sha256,
            "size": contract.mapping_size,
        },
        "profile_template": {
            "path": "config/lmi-p2-d114/userdata-deploy-profile-wsl.template.json",
            "sha256": contract.template_sha256,
            "size": contract.template_size,
        },
    }
    if value["bindings"] != expected_bindings:
        raise DeployError("policy binding set mismatch")
    if value["device_gate"] != {
        "allowed_is_logical_userdata": ["no", "unsupported-exact-variable-not-found-with-mapping-override"],
        "battery_soc_ok": "yes",
        "expected_product": "lmi",
        "expected_userdata_capacity": contract.userdata_capacity,
        "fastboot_mode": "bootloader",
        "minimum_battery_mv": 3_800,
        "minimum_max_download_size": contract.d110_boot_size,
        "partition_type": "f2fs",
        "require_exactly_one_device": True,
        "require_nonce_scoped_identity": True,
        "unlocked": "yes",
        "userspace": "no",
    }:
        raise DeployError("device gate policy mismatch")
    if value["execution"] != {
        "allowed_argv_suffix": ["-s", "<identity-matched-serial>", "flash", "userdata", "/proc/self/fd/<held-candidate-fd>"],
        "automatic_retry": False,
        "candidate_transport": "held-read-only-fd-pass_fds",
        "durable_claim_consumption_before_attempt": True,
        "durable_intent_before_attempt": True,
        "environment": SAFE_ENV,
        "max_attempts": 1,
        "operation": "flash",
        "partition": "userdata",
        "process_group_kill_and_reap": True,
        "shell": False,
        "slot_layout_claim": "not-proven",
        "super_fastbootd_or_slotted_fallback": False,
        "write_timeout_seconds": WRITE_TIMEOUT_SECONDS,
    }:
        raise DeployError("one-write execution policy mismatch")
    if value["fixed_read_only_queries"] != list(QUERY_NAMES):
        raise DeployError("fixed query policy mismatch")
    if value["historical_actions"] != {
        "completed_sparse_sha256": contract.old_sparse_sha256,
        "d110_boot_authorization": False,
        "new_sparse_precompleted": False,
        "reauthorization": False,
    }:
        raise DeployError("historical action policy mismatch")
    if value["privacy"] != {
        "absolute_user_paths_in_reports": False,
        "raw_serial_in_reports": False,
        "stable_public_device_fingerprint": False,
        "usb_identifier_in_reports": False,
    }:
        raise DeployError("privacy policy mismatch")
    if value["runtime"] != {
        "absolute_argv": True,
        "ancestor_policy": "no-group-or-world-writable-ancestors",
        "ancestor_symlink_policy": "reject-except-exact-locked-interpreter-usrmerge-chain",
        "clear_loader_environment": True,
        "elf_closure": "exact-interpreter-and-complete-dt-needed-resolution",
        "shell": False,
    }:
        raise DeployError("runtime policy mismatch")


def _validate_mapping(value: dict[str, Any], contract: Contract) -> None:
    if value.get("schema") != MAPPING_SCHEMA:
        raise DeployError("physical userdata mapping schema mismatch")
    if value.get("override") != {
        "allowed_getvar_result": "unsupported",
        "fastboot_mode": "bootloader",
        "partition": "userdata",
        "partition_type": "f2fs",
        "super_or_fastbootd_fallback_allowed": False,
    }:
        raise DeployError("physical userdata override mismatch")
    identity = value.get("identity_binding")
    if identity != {
        "current_device_must_match_nonce_scoped_private_policy": True,
        "public_stable_fingerprint_forbidden": True,
    }:
        raise DeployError("mapping identity policy mismatch")
    userdata = value.get("userdata")
    if not isinstance(userdata, dict) or (
        userdata.get("capacity_bytes") != contract.userdata_capacity
        or userdata.get("partlabel") != "userdata"
        or userdata.get("gpt_logical_sector_size") != 4096
    ):
        raise DeployError("physical userdata geometry mismatch")


def _validate_completed(value: dict[str, Any], contract: Contract, candidate_sha256: str) -> None:
    _exact(value, {"compatibility_only", "completed_userdata_actions", "policy", "schema"}, "completed action lock")
    if value["schema"] != COMPLETED_SCHEMA or value["policy"] != {
        "boot_claims_forbidden": True,
        "completed_candidate_reauthorization": False,
        "new_candidate_precompleted": False,
        "same_claim_retry": False,
    }:
        raise DeployError("completed action policy mismatch")
    compatibility = value["compatibility_only"]
    if not isinstance(compatibility, list) or len(compatibility) != 1:
        raise DeployError("D110 compatibility-only lock mismatch")
    d110 = compatibility[0]
    if (
        not isinstance(d110, dict)
        or d110.get("artifact_sha256") != contract.d110_boot_sha256
        or d110.get("artifact_size") != contract.d110_boot_size
        or d110.get("authorization") is not False
        or d110.get("claim_kind") != "boot"
    ):
        raise DeployError("D110 boot authorization must remain false")
    actions = value["completed_userdata_actions"]
    if not isinstance(actions, list) or len(actions) != 1:
        raise DeployError("completed userdata action set mismatch")
    old = actions[0]
    if (
        not isinstance(old, dict)
        or old.get("candidate_sha256") != contract.old_sparse_sha256
        or old.get("authorization") is not False
        or old.get("operation") != "flash"
        or old.get("partition") != "userdata"
        or old.get("transport_completed") is not True
    ):
        raise DeployError("historical completed userdata lock mismatch")
    if candidate_sha256 == contract.old_sparse_sha256:
        raise DeployError("historically completed userdata candidate cannot be approved or executed")
    if any(isinstance(item, dict) and item.get("candidate_sha256") == candidate_sha256 for item in actions):
        raise DeployError("candidate is already present in completed action lock")


def _validate_profile(value: dict[str, Any], contract: Contract) -> None:
    _exact(value, {"artifacts", "compatibility", "device", "execution", "identity", "ledgers", "profile_id", "schema"}, "WSL profile")
    if value["schema"] != PROFILE_SCHEMA or not isinstance(value["profile_id"], str) or ID_RE.fullmatch(value["profile_id"]) is None:
        raise DeployError("WSL profile schema or id mismatch")
    artifacts = _exact(
        value["artifacts"],
        {
            "assembly_attestation", "candidate", "candidate_raw", "completed_actions_lock",
            "deploy_policy_lock", "fastboot_runtime_lock", "p2_injection_attestation",
            "p2_rootfs", "physical_mapping_evidence", "rollback",
        },
        "profile artifacts",
    )
    for name in (
        "assembly_attestation", "candidate_raw", "completed_actions_lock", "deploy_policy_lock",
        "fastboot_runtime_lock", "p2_injection_attestation", "p2_rootfs", "physical_mapping_evidence",
    ):
        _artifact(artifacts[name], name)
    candidate = _artifact(artifacts["candidate"], "candidate", sparse=True)
    rollback = _artifact(artifacts["rollback"], "rollback", sparse=True)
    if candidate != {
        "logical_size": contract.raw_size,
        "path": candidate["path"],
        "representation": "android-sparse",
        "roundtrip_raw_sha256": contract.raw_sha256,
        "sha256": contract.sparse_sha256,
        "size": contract.sparse_size,
    }:
        raise DeployError("candidate profile identity mismatch")
    if artifacts["candidate_raw"]["sha256"] != contract.raw_sha256 or artifacts["candidate_raw"]["size"] != contract.raw_size:
        raise DeployError("candidate raw profile identity mismatch")
    expected_small = {
        "assembly_attestation": (contract.assembly_sha256, contract.assembly_size),
        "p2_injection_attestation": (contract.injection_sha256, contract.injection_size),
        "p2_rootfs": (contract.rootfs_sha256, contract.rootfs_size),
        "physical_mapping_evidence": (contract.mapping_sha256, contract.mapping_size),
        "fastboot_runtime_lock": (contract.runtime_sha256, contract.runtime_size),
        "completed_actions_lock": (contract.completed_sha256, contract.completed_size),
    }
    for name, expected in expected_small.items():
        if (artifacts[name]["sha256"], artifacts[name]["size"]) != expected:
            raise DeployError(f"{name} profile identity mismatch")
    if rollback["sha256"] != contract.rollback_sha256 or rollback["size"] != contract.rollback_size or rollback["logical_size"] != contract.raw_size or rollback["roundtrip_raw_sha256"] != contract.baseline_raw_sha256:
        raise DeployError("rollback profile identity mismatch")
    if value["compatibility"] != {
        "d110_boot": {"authorization": False, "sha256": contract.d110_boot_sha256, "size": contract.d110_boot_size}
    }:
        raise DeployError("D110 compatibility profile must not authorize boot")
    if value["device"] != {
        "expected_product": "lmi",
        "expected_userdata_capacity": contract.userdata_capacity,
        "minimum_battery_mv": 3_800,
        "minimum_max_download_size": contract.d110_boot_size,
        "partition_type": "f2fs",
    }:
        raise DeployError("profile device gate mismatch")
    if value["execution"] != {
        "automatic_retry": False,
        "claim_kind": "flash-userdata",
        "max_attempts": 1,
        "operation": "flash",
        "partition": "userdata",
        "slot_layout_claim": "not-proven",
        "write_timeout_seconds": WRITE_TIMEOUT_SECONDS,
    }:
        raise DeployError("profile is not the one fixed physical userdata operation")
    ledgers = _exact(
        value["ledgers"],
        {"candidate_attempts", "claim_consumption"},
        "profile ledgers",
    )
    candidate_ledger = _relative(ledgers["candidate_attempts"], "candidate attempt ledger")
    claim_ledger = _relative(ledgers["claim_consumption"], "claim consumption ledger")
    if (
        not candidate_ledger.as_posix().startswith("private/")
        or not claim_ledger.as_posix().startswith("private/")
        or candidate_ledger == claim_ledger
    ):
        raise DeployError("profile ledgers must be distinct canonical private directories")
    identity = _exact(value["identity"], {"expected_nonce_scoped_serial_sha256", "expected_serial", "privacy_nonce"}, "profile identity")
    expected_serial = identity["expected_serial"]
    if not isinstance(expected_serial, str) or SERIAL_RE.fullmatch(expected_serial) is None:
        raise DeployError("private expected serial syntax mismatch")
    nonce = _sha(identity["privacy_nonce"], "privacy nonce")
    expected_binding = hashlib.sha256(f"{nonce}:{expected_serial}".encode("ascii")).hexdigest()
    if _sha(identity["expected_nonce_scoped_serial_sha256"], "identity binding") != expected_binding:
        raise DeployError("private nonce-scoped serial binding mismatch")


def _verify_runtime_object(spec: dict[str, Any], label: str) -> HeldFile:
    required = {"lookup_path", "link_target", "mode", "resolved_path", "sha256", "size"}
    if "soname" in spec:
        required |= {"soname", "dt_needed"}
    _exact(spec, required, label)
    lookup = Path(spec["lookup_path"])
    resolved = Path(spec["resolved_path"])
    if not lookup.is_absolute() or not resolved.is_absolute():
        raise DeployError(f"{label} paths must be absolute")
    _check_ancestors(lookup, None, label)
    try:
        lookup_info = lookup.lstat()
    except OSError as error:
        raise DeployError(f"cannot inspect {label} lookup path") from error
    target = spec["link_target"]
    if target is None:
        if stat.S_ISLNK(lookup_info.st_mode) or lookup != resolved:
            raise DeployError(f"{label} unexpected lookup symlink")
    else:
        if not stat.S_ISLNK(lookup_info.st_mode) or os.readlink(lookup) != target:
            raise DeployError(f"{label} lookup symlink mismatch")
    item = _open_regular(resolved, None, label)
    if (
        item.sha256 != _sha(spec["sha256"], f"{label}.sha256")
        or item.size != _positive(spec["size"], f"{label}.size")
        or stat.S_IMODE(os.fstat(item.descriptor).st_mode) != int(spec["mode"], 8)
    ):
        item.close()
        raise DeployError(f"{label} resolved identity mismatch")
    return item


def _verify_usrmerge_interpreter(spec: dict[str, Any], label: str) -> HeldFile:
    """Verify the one locked WSL usr-merge interpreter chain, fail closed."""

    _exact(
        spec,
        {"lookup_path", "mode", "resolved_path", "sha256", "size", "usrmerge_chain"},
        label,
    )
    expected_chain = [
        {
            "lstat_size": 9,
            "path": "/lib64",
            "target": "usr/lib64",
            "type": "symbolic-link",
        },
        {
            "lstat_size": 44,
            "path": "/usr/lib64/ld-linux-x86-64.so.2",
            "target": "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "type": "symbolic-link",
        },
    ]
    if (
        spec["lookup_path"] != "/lib64/ld-linux-x86-64.so.2"
        or spec["resolved_path"] != "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"
        or spec["usrmerge_chain"] != expected_chain
    ):
        raise DeployError(f"{label} usr-merge lock mismatch")

    before: list[os.stat_result] = []
    for index, entry in enumerate(expected_chain):
        path = Path(entry["path"])
        _check_ancestors(path, None, f"{label} usr-merge link {index}")
        try:
            info = path.lstat()
            target = os.readlink(path)
        except OSError as error:
            raise DeployError(f"cannot inspect {label} usr-merge link {index}") from error
        if (
            not stat.S_ISLNK(info.st_mode)
            or info.st_size != entry["lstat_size"]
            or target != entry["target"]
        ):
            raise DeployError(f"{label} usr-merge link {index} runtime mismatch")
        before.append(info)

    item = _open_regular(Path(spec["resolved_path"]), None, label)
    try:
        if (
            item.sha256 != _sha(spec["sha256"], f"{label}.sha256")
            or item.size != _positive(spec["size"], f"{label}.size")
            or stat.S_IMODE(os.fstat(item.descriptor).st_mode) != int(spec["mode"], 8)
        ):
            raise DeployError(f"{label} resolved identity mismatch")
        for index, (entry, original) in enumerate(zip(expected_chain, before, strict=True)):
            path = Path(entry["path"])
            try:
                current = path.lstat()
                target = os.readlink(path)
            except OSError as error:
                raise DeployError(f"cannot recheck {label} usr-merge link {index}") from error
            if _identity(current) != _identity(original) or target != entry["target"]:
                raise DeployError(f"{label} usr-merge link {index} changed while opening")
        return item
    except BaseException:
        item.close()
        raise


ProcessRunner = Callable[[Sequence[str], int, tuple[int, ...], Mapping[str, str]], CommandResult]
Clock = Callable[[], int]


def run_bounded(
    argv: Sequence[str],
    timeout_seconds: int,
    pass_fds: tuple[int, ...],
    environment: Mapping[str, str],
) -> CommandResult:
    """Run one absolute argv with bounded output and kill/reap its process group."""

    if (
        not argv
        or any(not isinstance(arg, str) or not arg or "\0" in arg for arg in argv)
        or not Path(argv[0]).is_absolute()
        or set(environment) & LOADER_ENV_NAMES
        or dict(environment) != SAFE_ENV
    ):
        raise DeployError("unsafe process invocation contract")
    try:
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            pass_fds=pass_fds,
            close_fds=True,
            env=dict(environment),
            shell=False,
            start_new_session=True,
        )
    except OSError:
        return CommandResult(None, b"", b"", started=False)
    assert process.stdout is not None and process.stderr is not None
    stdout_fd = process.stdout.fileno()
    stderr_fd = process.stderr.fileno()
    selector = selectors.DefaultSelector()
    output = {process.stdout.fileno(): bytearray(), process.stderr.fileno(): bytearray()}
    streams = {process.stdout.fileno(): process.stdout, process.stderr.fileno(): process.stderr}
    for stream in streams.values():
        os.set_blocking(stream.fileno(), False)
        selector.register(stream, selectors.EVENT_READ)
    deadline = time.monotonic() + timeout_seconds
    timed_out = False
    output_limited = False
    killed = False
    try:
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0 and not killed:
                timed_out = True
                killed = True
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            events = selector.select(max(0.0, min(0.1, remaining)) if not killed else 0.05)
            for key, _mask in events:
                fd = key.fd
                try:
                    chunk = os.read(fd, 16 * 1024)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(fd)
                    continue
                current_total = sum(len(value) for value in output.values())
                allowance = max(0, MAX_OUTPUT_BYTES - current_total)
                output[fd].extend(chunk[:allowance])
                if len(chunk) > allowance and not killed:
                    output_limited = True
                    killed = True
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            if killed and process.poll() is not None and not selector.get_map():
                break
        returncode = process.wait()
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()
    return CommandResult(
        returncode,
        bytes(output[stdout_fd]),
        bytes(output[stderr_fd]),
        started=True,
        timed_out=timed_out,
        output_limited=output_limited,
    )


def _validate_runtime(
    value: dict[str, Any],
    process_runner: ProcessRunner,
) -> tuple[tuple[str, ...], list[HeldFile]]:
    _exact(value, {"execution", "executable", "interpreter", "libraries", "package", "schema", "symlink", "version_output"}, "WSL runtime lock")
    if value["schema"] != RUNTIME_SCHEMA:
        raise DeployError("WSL runtime lock schema mismatch")
    symlink = value["symlink"]
    if symlink != {
        "lstat_size": 42,
        "path": "/usr/bin/fastboot",
        "target": "../lib/android-sdk/platform-tools/fastboot",
        "type": "symbolic-link",
    }:
        raise DeployError("fastboot WSL symlink lock mismatch")
    link_path = Path(symlink["path"])
    _check_ancestors(link_path, None, "fastboot symlink")
    info = link_path.lstat()
    if not stat.S_ISLNK(info.st_mode) or info.st_size != symlink["lstat_size"] or os.readlink(link_path) != symlink["target"]:
        raise DeployError("fastboot WSL symlink runtime mismatch")
    executable = _exact(value["executable"], {"dt_needed", "interpreter", "mode", "path", "runpath", "sha256", "size"}, "fastboot ELF")
    if executable != {
        "dt_needed": [
            "libbase.so.0", "libcrypto.so.0", "libcutils.so.0", "liblog.so.0",
            "libprotobuf.so.32", "libsparse.so.0", "libusb-1.0.so.0",
            "libziparchive.so.0", "libstdc++.so.6", "libm.so.6", "libgcc_s.so.1", "libc.so.6",
        ],
        "interpreter": "/lib64/ld-linux-x86-64.so.2",
        "mode": "0755",
        "path": "/usr/lib/android-sdk/platform-tools/fastboot",
        "runpath": ["/usr/lib/x86_64-linux-gnu/android"],
        "sha256": "4d90c8ff8569476a76ea1f6a2c86e54e833e0e1c0e82af13a10277c7b617c506",
        "size": 506_488,
    }:
        raise DeployError("fastboot ELF identity/DT_NEEDED lock mismatch")
    held: list[HeldFile] = []
    try:
        executable_item = _open_regular(Path(executable["path"]), None, "fastboot ELF")
        held.append(executable_item)
        if executable_item.sha256 != executable["sha256"] or executable_item.size != executable["size"] or stat.S_IMODE(os.fstat(executable_item.descriptor).st_mode) != 0o755:
            raise DeployError("fastboot ELF runtime identity mismatch")
        interpreter_spec = value["interpreter"]
        if executable["interpreter"] != interpreter_spec.get("lookup_path"):
            raise DeployError("fastboot PT_INTERP/runtime lookup binding mismatch")
        interpreter = _verify_usrmerge_interpreter(interpreter_spec, "ELF interpreter")
        held.append(interpreter)
        libraries = value["libraries"]
        if not isinstance(libraries, list) or not libraries:
            raise DeployError("runtime library closure is empty")
        by_soname: dict[str, dict[str, Any]] = {}
        for index, spec in enumerate(libraries):
            if not isinstance(spec, dict):
                raise DeployError("runtime library entry is not an object")
            soname = spec.get("soname")
            if not isinstance(soname, str) or soname in by_soname:
                raise DeployError("runtime library soname is invalid or duplicated")
            by_soname[soname] = spec
            held.append(_verify_runtime_object(spec, f"runtime library {index}"))
        allowed = set(by_soname) | {"ld-linux-x86-64.so.2"}
        if set(executable["dt_needed"]) - allowed:
            raise DeployError("fastboot direct DT_NEEDED closure is incomplete")
        for soname, spec in by_soname.items():
            needed = spec["dt_needed"]
            if not isinstance(needed, list) or any(not isinstance(item, str) for item in needed) or set(needed) - allowed:
                raise DeployError(f"transitive DT_NEEDED closure incomplete for {soname}")
        execution = value["execution"]
        expected_prefix = [
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "--inhibit-cache",
            "--library-path",
            "/usr/lib/x86_64-linux-gnu/android:/usr/lib/x86_64-linux-gnu",
            "/usr/lib/android-sdk/platform-tools/fastboot",
        ]
        if expected_prefix[0] != interpreter_spec["resolved_path"]:
            raise DeployError("runtime argv does not use the resolved ELF interpreter")
        if execution != {
            "argv_prefix": expected_prefix,
            "cleared_loader_environment": sorted(LOADER_ENV_NAMES),
            "shell": False,
        }:
            raise DeployError("runtime absolute loader argv policy mismatch")
        if value["package"] != {"architecture": "amd64", "name": "fastboot", "version": "1:34.0.5-12build1"}:
            raise DeployError("fastboot dpkg identity lock mismatch")
        expected_version_lines = [
            "fastboot version 34.0.5-debian",
            "Installed as /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        ]
        if value["version_output"] != expected_version_lines:
            raise DeployError("fastboot locked version output mismatch")
        version = process_runner(tuple(expected_prefix + ["--version"]), QUERY_TIMEOUT_SECONDS, (), SAFE_ENV)
        expected_version = ("\n".join(expected_version_lines) + "\n").encode("ascii")
        if version != CommandResult(0, expected_version, b""):
            raise DeployError("fastboot exact version output mismatch")
        dpkg_argv = (
            "/usr/bin/dpkg-query", "-W",
            "-f=${Package}\\t${Version}\\t${Architecture}\\n", "fastboot",
        )
        dpkg = process_runner(dpkg_argv, QUERY_TIMEOUT_SECONDS, (), SAFE_ENV)
        if dpkg != CommandResult(0, b"fastboot\t1:34.0.5-12build1\tamd64\n", b""):
            raise DeployError("fastboot dpkg runtime identity mismatch")
        return tuple(expected_prefix), held
    except BaseException:
        for item in reversed(held):
            item.close()
        raise


def _recheck(audit: Audit) -> bool:
    for item in audit.held.values():
        try:
            current = item.path.lstat()
            opened = os.fstat(item.descriptor)
        except OSError:
            return False
        if _identity(current) != item.identity or _identity(opened) != item.identity:
            return False
    return True


def local_audit(
    profile_path: Path,
    *,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
    process_runner: ProcessRunner = run_bounded,
) -> Audit:
    repo_root = repo_root.absolute()
    held: dict[str, HeldFile] = {}
    runtime_held: list[HeldFile] = []
    try:
        profile_item = _open_regular(profile_path, repo_root, "private WSL profile", maximum=64 * 1024)
        if stat.S_IMODE(os.fstat(profile_item.descriptor).st_mode) != 0o600:
            profile_item.close()
            raise DeployError("private WSL profile must have mode 0600")
        held["profile"] = profile_item
        profile = _json_bytes(_held_bytes(profile_item, 64 * 1024, "profile"), "profile")
        _validate_profile(profile, contract)
        artifacts = profile["artifacts"]
        assembly_item = _open_spec(artifacts["assembly_attestation"], repo_root, "assembly attestation", held, "assembly", maximum=64 * 1024)
        injection_item = _open_spec(artifacts["p2_injection_attestation"], repo_root, "injection attestation", held, "injection", maximum=64 * 1024)
        policy_item = _open_spec(artifacts["deploy_policy_lock"], repo_root, "WSL deploy policy", held, "policy", maximum=64 * 1024)
        runtime_item = _open_spec(artifacts["fastboot_runtime_lock"], repo_root, "WSL runtime lock", held, "runtime", maximum=64 * 1024)
        completed_item = _open_spec(artifacts["completed_actions_lock"], repo_root, "completed action lock", held, "completed", maximum=64 * 1024)
        mapping_item = _open_spec(artifacts["physical_mapping_evidence"], repo_root, "physical mapping", held, "mapping", maximum=64 * 1024)
        policy = _json_bytes(_held_bytes(policy_item, 64 * 1024, "policy"), "policy")
        runtime = _json_bytes(_held_bytes(runtime_item, 64 * 1024, "runtime"), "runtime")
        completed = _json_bytes(_held_bytes(completed_item, 64 * 1024, "completed"), "completed")
        mapping = _json_bytes(_held_bytes(mapping_item, 64 * 1024, "mapping"), "mapping")
        _validate_policy(policy, contract)
        if policy["bindings"]["fastboot_runtime_lock"] != {key: artifacts["fastboot_runtime_lock"][key] for key in ("path", "sha256", "size")}:
            raise DeployError("profile/policy runtime binding mismatch")
        if policy["bindings"]["completed_actions_lock"] != {key: artifacts["completed_actions_lock"][key] for key in ("path", "sha256", "size")}:
            raise DeployError("profile/policy completed-action binding mismatch")
        if policy["bindings"]["physical_userdata_mapping"] != {key: artifacts["physical_mapping_evidence"][key] for key in ("path", "sha256", "size")}:
            raise DeployError("profile/policy mapping binding mismatch")
        _validate_mapping(mapping, contract)
        _validate_completed(completed, contract, artifacts["candidate"]["sha256"])
        assembly = _json_bytes(_held_bytes(assembly_item, 64 * 1024, "assembly"), "assembly attestation")
        injection = _json_bytes(_held_bytes(injection_item, 64 * 1024, "injection"), "injection attestation")
        if (
            assembly.get("schema") != "lmi-p2-d114-userdata-assembly-attestation/v1"
            or assembly.get("output", {}).get("raw") != {
                "filename": "userdata.raw", "path": "userdata.raw", "sha256": contract.raw_sha256, "size": contract.raw_size,
            }
            or assembly.get("output", {}).get("sparse") != {
                "filename": "userdata.android-sparse.img", "logical_size": contract.raw_size,
                "path": "userdata.android-sparse.img", "sha256": contract.sparse_sha256, "size": contract.sparse_size,
            }
            or assembly.get("input", {}).get("p2", {}).get("sha256") != contract.rootfs_sha256
            or assembly.get("input", {}).get("p2", {}).get("size") != contract.rootfs_size
            or assembly.get("bindings", {}).get("p2_injection_attestation_sha256") != contract.injection_sha256
        ):
            raise DeployError("assembly attestation cross-binding mismatch")
        if (
            injection.get("schema") != "lmi-p2-d114-rootfs-injection-attestation/v3"
            or injection.get("output", {}).get("sha256") != contract.rootfs_sha256
            or injection.get("output", {}).get("size") != contract.rootfs_size
            or injection.get("claims") != {"hardware_test_only": True, "production": False, "release_eligible": False}
        ):
            raise DeployError("injection attestation cross-binding mismatch")
        argv_prefix, runtime_held = _validate_runtime(runtime, process_runner)
        # System runtime objects stay open until the full operation completes.
        for index, item in enumerate(runtime_held):
            held[f"system-runtime:{index}"] = item
        runtime_held = []
        # Open and hash multi-gigabyte inputs only after the small runtime gate.
        candidate = _open_spec(artifacts["candidate"], repo_root, "candidate", held, "candidate", sparse=True)
        raw = _open_spec(artifacts["candidate_raw"], repo_root, "candidate raw", held, "candidate_raw")
        rootfs = _open_spec(artifacts["p2_rootfs"], repo_root, "P2 rootfs", held, "rootfs")
        rollback = _open_spec(artifacts["rollback"], repo_root, "rollback", held, "rollback", sparse=True)
        if rootfs.sha256 != contract.rootfs_sha256 or raw.sha256 != contract.raw_sha256 or candidate.sha256 != contract.sparse_sha256 or rollback.sha256 != contract.rollback_sha256:
            raise DeployError("large artifact identity mismatch")
        inspect_sparse(candidate, contract.raw_size, contract.raw_sha256)
        inspect_sparse(rollback, contract.raw_size, contract.baseline_raw_sha256)
        if not _recheck(Audit(repo_root, profile, profile_item.sha256, policy, mapping, completed, runtime, held, argv_prefix)):
            raise DeployError("locked repository inputs drifted during local audit")
        return Audit(repo_root, profile, profile_item.sha256, policy, mapping, completed, runtime, held, argv_prefix, contract)
    except BaseException:
        for item in reversed(runtime_held):
            item.close()
        for item in reversed(tuple(held.values())):
            item.close()
        raise


def _strict_devices(result: CommandResult) -> str:
    if result != CommandResult(0, result.stdout, b"") or result.timed_out or result.output_limited or not result.started:
        raise DeployError("fastboot devices did not complete cleanly")
    try:
        text = result.stdout.decode("ascii")
    except UnicodeDecodeError:
        raise DeployError("fastboot devices output is not ASCII") from None
    match = re.fullmatch(
        r"([A-Za-z0-9._:-]{1,128})(?:\tfastboot(?:\n|\r\n)|\t fastboot(?:\n\n|\r\n\r\n))",
        text,
    )
    if match is None:
        raise DeployError("exactly one bootloader-mode fastboot device is required")
    return match.group(1)


def _finished_pattern() -> str:
    return r"Finished\. Total time: [0-9]+(?:\.[0-9]+)?s\r?\n?"


def _strict_getvar(name: str, result: CommandResult, *, allow_unsupported: bool = False) -> tuple[str | None, bool]:
    if not result.started or result.timed_out or result.output_limited or result.stdout != b"":
        raise DeployError(f"getvar:{name} did not complete through the strict stderr channel")
    try:
        text = result.stderr.decode("ascii")
    except UnicodeDecodeError:
        raise DeployError(f"getvar:{name} stderr is not ASCII") from None
    success = re.fullmatch(
        rf"(?:\(bootloader\) )?{re.escape(name)}: ([^\r\n]+)\r?\n{_finished_pattern()}",
        text,
    )
    if result.returncode == 0 and success is not None:
        return success.group(1), False
    if allow_unsupported:
        unsupported = re.fullmatch(
            rf"getvar:{re.escape(name)}[ \t]+FAILED \(remote: 'GetVar Variable Not found'\)\r?\n{_finished_pattern()}",
            text,
        )
        if result.returncode == 0 and unsupported is not None:
            return None, True
    raise DeployError(f"getvar:{name} output shape or exit status mismatch")


def _parse_integer(value: str, label: str, *, allow_one_leading_space: bool = False) -> int:
    pattern = r" ?(?:0[xX][0-9A-Fa-f]+|[0-9]+)" if allow_one_leading_space else r"0[xX][0-9A-Fa-f]+|[0-9]+"
    if re.fullmatch(pattern, value) is None:
        raise DeployError(f"{label} is not a strict integer")
    return int(value[1:] if value.startswith(" ") else value, 0)


def query_device(audit: Audit, process_runner: ProcessRunner = run_bounded) -> DeviceEvidence:
    prefix = list(audit.argv_prefix)
    devices = process_runner(tuple(prefix + ["devices"]), QUERY_TIMEOUT_SECONDS, (), SAFE_ENV)
    serial = _strict_devices(devices)
    expected_identity = audit.profile["identity"]
    nonce = expected_identity["privacy_nonce"]
    identity_binding = hashlib.sha256(f"{nonce}:{serial}".encode("ascii")).hexdigest()
    if serial != expected_identity["expected_serial"] or identity_binding != expected_identity["expected_nonce_scoped_serial_sha256"]:
        raise DeployError("enumerated device does not match the private nonce-scoped identity")
    values: dict[str, str | None] = {}
    unsupported = False
    for name in (
        "serialno", "product", "unlocked", "is-userspace", "is-logical:userdata",
        "partition-type:userdata", "partition-size:userdata", "battery-voltage",
        "battery-soc-ok", "max-download-size",
    ):
        result = process_runner(tuple(prefix + ["-s", serial, "getvar", name]), QUERY_TIMEOUT_SECONDS, (), SAFE_ENV)
        value, was_unsupported = _strict_getvar(name, result, allow_unsupported=(name == "is-logical:userdata"))
        values[name] = value
        unsupported = unsupported or was_unsupported
    if values["serialno"] != serial:
        raise DeployError("serialno getvar does not match enumeration")
    if values["product"] != "lmi" or values["unlocked"] != "yes" or values["is-userspace"] != "no":
        raise DeployError("product, unlock, or bootloader-mode gate failed")
    logical = "unsupported" if unsupported else values["is-logical:userdata"]
    if logical not in {"no", "unsupported"}:
        raise DeployError("userdata is not proven physical")
    if logical == "unsupported" and audit.mapping["override"] != {
        "allowed_getvar_result": "unsupported", "fastboot_mode": "bootloader",
        "partition": "userdata", "partition_type": "f2fs",
        "super_or_fastbootd_fallback_allowed": False,
    }:
        raise DeployError("unsupported physical mapping override is not exact")
    device = audit.profile["device"]
    partition_size = _parse_integer(
        str(values["partition-size:userdata"]),
        "partition size",
        allow_one_leading_space=True,
    )
    battery_mv = _parse_integer(str(values["battery-voltage"]), "battery voltage")
    max_download = _parse_integer(str(values["max-download-size"]), "max download size")
    if (
        values["partition-type:userdata"] != "f2fs"
        or partition_size != device["expected_userdata_capacity"]
        or battery_mv < device["minimum_battery_mv"]
        or values["battery-soc-ok"] != "yes"
        or max_download < device["minimum_max_download_size"]
    ):
        raise DeployError("userdata type/size, battery, or download-size gate failed")
    public = {
        "battery_mv": battery_mv,
        "identity_match": True,
        "is_logical_userdata": logical,
        "max_download_size": max_download,
        "partition_size": partition_size,
        "partition_type": "f2fs",
        "physical_mapping_evidence_override": logical == "unsupported",
        "product": "lmi",
        "slot_layout_claim": "not-proven",
        "soc_ok": "yes",
        "unlocked": "yes",
        "userspace": "no",
    }
    return DeviceEvidence(serial, identity_binding, public)


def _artifact_binding(audit: Audit) -> dict[str, Any]:
    artifacts = audit.profile["artifacts"]
    candidate = artifacts["candidate"]
    return {
        "assembly_attestation": artifacts["assembly_attestation"]["sha256"],
        "candidate": {
            "logical_size": candidate["logical_size"],
            "roundtrip_raw_sha256": candidate["roundtrip_raw_sha256"],
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        },
        "candidate_raw": artifacts["candidate_raw"]["sha256"],
        "completed_actions_lock": artifacts["completed_actions_lock"]["sha256"],
        "deploy_policy_lock": artifacts["deploy_policy_lock"]["sha256"],
        "fastboot_runtime_lock": artifacts["fastboot_runtime_lock"]["sha256"],
        "mapping": artifacts["physical_mapping_evidence"]["sha256"],
        "p2_injection_attestation": artifacts["p2_injection_attestation"]["sha256"],
        "p2_rootfs": artifacts["p2_rootfs"]["sha256"],
        "profile": audit.profile_sha256,
    }


def _preflight_binding(audit: Audit, device: DeviceEvidence) -> dict[str, Any]:
    return {
        "artifacts": _artifact_binding(audit),
        "device_evidence_sha256": hashlib.sha256(_canonical(device.public)).hexdigest(),
        "identity_binding": device.identity_binding,
        "profile_id": audit.profile["profile_id"],
        "write_argv_semantics": [
            *audit.argv_prefix,
            "-s", "<identity-matched-device>", "flash", "userdata",
            "/proc/self/fd/<held-candidate-fd>",
        ],
    }


def _validate_private_output(path: Path, root: Path, label: str) -> Path:
    relative = _repo_relative(path, root, label)
    if not relative.startswith("private/"):
        raise DeployError(f"{label} must be under private/")
    _check_ancestors(path.absolute(), root, label)
    parent = path.absolute().parent
    info = parent.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700:
        raise DeployError(f"{label} parent must be canonical mode 0700")
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise DeployError(f"{label} overwrite is forbidden")
    return parent


def _require_distinct_paths(paths: Sequence[tuple[Path, str]]) -> None:
    """Reject textual, symlink-parent, and existing inode aliases."""

    canonical: dict[tuple[str, str], str] = {}
    inodes: dict[tuple[int, int], str] = {}
    for path, label in paths:
        absolute = path.absolute()
        try:
            resolved_parent = absolute.parent.resolve(strict=True)
        except OSError as error:
            raise DeployError(f"cannot resolve {label} parent") from error
        if resolved_parent != absolute.parent:
            raise DeployError(f"{label} has a symlink or aliased parent")
        key = (str(resolved_parent), absolute.name)
        prior = canonical.get(key)
        if prior is not None:
            raise DeployError(f"{label} aliases {prior}")
        canonical[key] = label
        try:
            info = absolute.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise DeployError(f"cannot inspect {label}") from error
        if stat.S_ISLNK(info.st_mode):
            raise DeployError(f"{label} must not be a symlink")
        inode = (info.st_dev, info.st_ino)
        prior = inodes.get(inode)
        if prior is not None:
            raise DeployError(f"{label} is an inode alias of {prior}")
        inodes[inode] = label


def _ledger_directory(audit: Audit, name: str) -> Path:
    relative = audit.profile["ledgers"][name]
    path = audit.repo_root / _relative(relative, f"{name} ledger")
    _check_ancestors(path, audit.repo_root, f"{name} ledger")
    try:
        info = path.lstat()
    except OSError as error:
        raise DeployError(f"cannot inspect {name} ledger") from error
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise DeployError(f"{name} ledger must be a canonical mode-0700 directory")
    return path


def _claim_consumed_path(audit: Audit, approval_sha256: str) -> Path:
    _sha(approval_sha256, "approval hash for claim ledger")
    return _ledger_directory(audit, "claim_consumption") / f"{approval_sha256}.consumed.json"


def _candidate_attempt_path(audit: Audit) -> Path:
    candidate_sha256 = audit.profile["artifacts"]["candidate"]["sha256"]
    _sha(candidate_sha256, "candidate hash for attempt ledger")
    return _ledger_directory(audit, "candidate_attempts") / f"{candidate_sha256}.attempt.json"


def _require_outputs_outside_ledgers(audit: Audit, outputs: Sequence[tuple[Path, str]]) -> None:
    ledgers = (
        _ledger_directory(audit, "claim_consumption").absolute(),
        _ledger_directory(audit, "candidate_attempts").absolute(),
    )
    for path, label in outputs:
        absolute = path.absolute()
        if any(absolute == ledger or ledger in absolute.parents for ledger in ledgers):
            raise DeployError(f"{label} must not be placed inside a deterministic ledger")


def _assert_private_payload(value: Any, expected_serial: str) -> None:
    payload = _canonical(value) if isinstance(value, dict) else bytes(value)
    forbidden = (
        expected_serial.encode("ascii"), b"/home/", b"/mnt/c/Users/",
        b"usb:", b"usb_path", b"usb_id",
    )
    if any(token in payload for token in forbidden):
        raise DeployError("persistent evidence would disclose serial, user path, or USB identity")


def _publish(path: Path, value: dict[str, Any], audit: Audit, label: str) -> str:
    parent = _validate_private_output(path, audit.repo_root, label)
    _assert_private_payload(value, audit.profile["identity"]["expected_serial"])
    payload = _canonical(value)
    digest = hashlib.sha256(payload).hexdigest()
    descriptor, name = tempfile.mkstemp(prefix=".lmi-d114-wsl-", dir=parent)
    temporary: Path | None = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        cursor = 0
        while cursor < len(payload):
            written = os.write(descriptor, payload[cursor:])
            if written <= 0:
                raise DeployError(f"short {label} write")
            cursor += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path)
        except FileExistsError:
            raise DeployError(f"{label} was concurrently created; overwrite is forbidden") from None
        os.unlink(temporary)
        temporary = None
        directory = os.open(parent, os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        raise DeployError(f"published {label} metadata mismatch")
    return digest


def _load_small(path: Path, expected_sha256: str, audit: Audit, label: str) -> tuple[dict[str, Any], HeldFile]:
    _sha(expected_sha256, f"{label} expected hash")
    item = _open_regular(path, audit.repo_root, label, maximum=128 * 1024)
    if item.sha256 != expected_sha256:
        item.close()
        raise DeployError(f"{label} hash mismatch")
    return _json_bytes(_held_bytes(item, 128 * 1024, label), label), item


def _validate_preflight(value: dict[str, Any], audit: Audit, now_unix: int) -> dict[str, Any]:
    _exact(value, {"binding", "created_at_unix", "device", "mode", "route_status", "safety", "schema"}, "preflight report")
    if value["schema"] != PREFLIGHT_SCHEMA or value["mode"] != "preflight" or value["route_status"] != PREFLIGHT_ROUTE:
        raise DeployError("prior report is not a passed WSL preflight")
    created = value["created_at_unix"]
    if type(created) is not int or created > now_unix or now_unix - created > PREFLIGHT_MAX_AGE_SECONDS:
        raise DeployError("preflight is not fresh")
    binding = value["binding"]
    if not isinstance(binding, dict) or binding.get("artifacts") != _artifact_binding(audit):
        raise DeployError("preflight artifact binding mismatch")
    if binding.get("identity_binding") != audit.profile["identity"]["expected_nonce_scoped_serial_sha256"]:
        raise DeployError("preflight identity binding mismatch")
    device = value["device"]
    if not isinstance(device, dict) or hashlib.sha256(_canonical(device)).hexdigest() != binding.get("device_evidence_sha256"):
        raise DeployError("preflight device evidence binding mismatch")
    if binding.get("write_argv_semantics") != [
        *audit.argv_prefix, "-s", "<identity-matched-device>", "flash", "userdata",
        "/proc/self/fd/<held-candidate-fd>",
    ]:
        raise DeployError("preflight exact argv semantics mismatch")
    expected_safety = {
        "device_state_change_attempted": False,
        "raw_serial_disclosed": False,
        "slot_layout_claim": "not-proven",
        "super_fastbootd_or_slotted_fallback": False,
    }
    if value["safety"] != expected_safety:
        raise DeployError("preflight safety evidence mismatch")
    return binding


def _device_matches_approved_preflight(
    approved: dict[str, Any],
    current: dict[str, Any],
) -> bool:
    dynamic = {"battery_mv", "max_download_size"}
    return (
        isinstance(approved, dict)
        and isinstance(current, dict)
        and {key: value for key, value in approved.items() if key not in dynamic}
        == {key: value for key, value in current.items() if key not in dynamic}
    )


def _transport_completed(result: CommandResult) -> bool:
    if (
        not result.started
        or result.timed_out
        or result.output_limited
        or result.returncode != 0
        or result.stdout != b""
    ):
        return False
    try:
        lines = result.stderr.decode("ascii").splitlines()
    except UnicodeDecodeError:
        return False
    if not lines or re.fullmatch(r"Finished\. Total time: [0-9]+(?:\.[0-9]+)?s", lines[-1]) is None:
        return False
    sending = re.compile(
        r"Sending sparse 'userdata'(?: (?P<index>[0-9]+)/(?P<total>[0-9]+))? \([0-9]+ KB\)[ .]*OKAY \[[ ]*[0-9]+(?:\.[0-9]+)?s\]"
    )
    writing = re.compile(
        r"Writing 'userdata'[ .]*OKAY \[[ ]*[0-9]+(?:\.[0-9]+)?s\]"
    )
    body = lines[:-1]
    if len(body) < 2 or len(body) % 2:
        return False
    matches: list[re.Match[str]] = []
    for index in range(0, len(body), 2):
        match = sending.fullmatch(body[index])
        if match is None or writing.fullmatch(body[index + 1]) is None:
            return False
        matches.append(match)
    fractions = [(match.group("index"), match.group("total")) for match in matches]
    if all(index is None and total is None for index, total in fractions):
        return len(matches) == 1
    if any(index is None or total is None for index, total in fractions):
        return False
    totals = {int(total) for _index, total in fractions if total is not None}
    if len(totals) != 1:
        return False
    total = totals.pop()
    return total == len(matches) and [int(index) for index, _total in fractions if index is not None] == list(range(1, total + 1))


def _validate_approval(
    value: dict[str, Any],
    audit: Audit,
    preflight_sha256: str,
    preflight_binding: dict[str, Any],
    now_unix: int,
) -> None:
    _exact(value, {"authorization", "binding", "created_at_unix", "expires_at_unix", "ledger", "preflight_sha256", "schema"}, "approval claim")
    if value["schema"] != APPROVAL_SCHEMA or value["authorization"] != {
        "approved": True,
        "automatic_retry": False,
        "claim_kind": "flash-userdata",
        "max_attempts": 1,
        "operation": "flash",
        "partition": "userdata",
    }:
        raise DeployError("approval is not an exact physical userdata claim")
    created = value["created_at_unix"]
    expires = value["expires_at_unix"]
    if type(created) is not int or type(expires) is not int or expires - created != APPROVAL_TTL_SECONDS or now_unix < created or now_unix > expires:
        raise DeployError("approval claim is expired or malformed")
    if value["preflight_sha256"] != preflight_sha256 or value["binding"] != preflight_binding:
        raise DeployError("approval/preflight binding mismatch")
    if value["ledger"] != {
        "claim_consumption_directory": audit.profile["ledgers"]["claim_consumption"],
        "consumed_filename_semantics": "<approval-sha256>.consumed.json",
        "noreplace": True,
    }:
        raise DeployError("approval claim-consumption ledger binding mismatch")
    if preflight_binding.get("artifacts") != _artifact_binding(audit):
        raise DeployError("approval artifact binding mismatch")


def local_audit_report(audit: Audit, report_path: Path, *, now_unix: int) -> tuple[str, str]:
    report = {
        "artifacts": _artifact_binding(audit),
        "created_at_unix": now_unix,
        "mode": "local-audit",
        "profile": {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256},
        "route_status": "LOCAL_AUDIT_PASSED_NO_DEVICE_ACCESS",
        "safety": {
            "candidate_fd_held": True,
            "device_command_attempted": False,
            "raw_serial_disclosed": False,
            "sparse_roundtrip_verified": True,
        },
        "schema": REPORT_SCHEMA,
    }
    return report["route_status"], _publish(report_path, report, audit, "local audit report")


def preflight(audit: Audit, report_path: Path, *, process_runner: ProcessRunner, now_unix: int) -> tuple[str, str]:
    _validate_private_output(report_path, audit.repo_root, "preflight report")
    device = query_device(audit, process_runner)
    if not _recheck(audit):
        raise DeployError("locked inputs drifted during preflight")
    report = {
        "binding": _preflight_binding(audit, device),
        "created_at_unix": now_unix,
        "device": device.public,
        "mode": "preflight",
        "route_status": PREFLIGHT_ROUTE,
        "safety": {
            "device_state_change_attempted": False,
            "raw_serial_disclosed": False,
            "slot_layout_claim": "not-proven",
            "super_fastbootd_or_slotted_fallback": False,
        },
        "schema": PREFLIGHT_SCHEMA,
    }
    return PREFLIGHT_ROUTE, _publish(report_path, report, audit, "preflight report")


def approve(
    audit: Audit,
    preflight_path: Path,
    preflight_sha256: str,
    approval_path: Path,
    *,
    now_unix: int,
) -> tuple[str, str]:
    _validate_private_output(approval_path, audit.repo_root, "approval claim")
    preflight_value, preflight_item = _load_small(preflight_path, preflight_sha256, audit, "preflight report")
    audit.held["preflight"] = preflight_item
    binding = _validate_preflight(preflight_value, audit, now_unix)
    _validate_completed(audit.completed, audit.contract, audit.profile["artifacts"]["candidate"]["sha256"])
    if not _recheck(audit):
        raise DeployError("locked inputs drifted before approval")
    claim = {
        "authorization": {
            "approved": True,
            "automatic_retry": False,
            "claim_kind": "flash-userdata",
            "max_attempts": 1,
            "operation": "flash",
            "partition": "userdata",
        },
        "binding": binding,
        "created_at_unix": now_unix,
        "expires_at_unix": now_unix + APPROVAL_TTL_SECONDS,
        "ledger": {
            "claim_consumption_directory": audit.profile["ledgers"]["claim_consumption"],
            "consumed_filename_semantics": "<approval-sha256>.consumed.json",
            "noreplace": True,
        },
        "preflight_sha256": preflight_sha256,
        "schema": APPROVAL_SCHEMA,
    }
    return "APPROVAL_CREATED_NO_DEVICE_ACCESS", _publish(approval_path, claim, audit, "approval claim")


def _consume_claim(audit: Audit, approval_sha256: str, consumed_path: Path, now_unix: int) -> str:
    expected_path = _claim_consumed_path(audit, approval_sha256)
    if consumed_path.absolute() != expected_path.absolute():
        raise DeployError("consumed claim path is not the deterministic approval ledger path")
    value = {
        "approval_sha256": approval_sha256,
        "consumed_at_unix": now_unix,
        "ledger_directory": audit.profile["ledgers"]["claim_consumption"],
        "retry_authorization": False,
        "schema": CONSUMED_SCHEMA,
    }
    return _publish(consumed_path, value, audit, "consumed claim")


def _publish_candidate_attempt(
    audit: Audit,
    approval_sha256: str,
    identity_binding: str,
    now_unix: int,
) -> tuple[Path, str]:
    path = _candidate_attempt_path(audit)
    value = {
        "approval_sha256": approval_sha256,
        "attempted_at_unix": now_unix,
        "candidate_sha256": audit.profile["artifacts"]["candidate"]["sha256"],
        "identity_binding": identity_binding,
        "ledger_directory": audit.profile["ledgers"]["candidate_attempts"],
        "retry_authorization": False,
        "schema": "lmi-p2-d114-userdata-wsl-candidate-attempt/v1",
    }
    return path, _publish(path, value, audit, "candidate attempt ledger entry")


def execute(
    audit: Audit,
    preflight_path: Path,
    preflight_sha256: str,
    approval_path: Path,
    approval_sha256: str,
    consumed_path: Path,
    intent_path: Path,
    report_path: Path,
    *,
    process_runner: ProcessRunner,
    clock: Clock,
) -> tuple[str, str]:
    # Refuse all conflicting outputs before irreversibly consuming the claim.
    expected_consumed_path = _claim_consumed_path(audit, approval_sha256)
    if consumed_path.absolute() != expected_consumed_path.absolute():
        raise DeployError("consumed claim path is not the deterministic approval ledger path")
    attempt_path = _candidate_attempt_path(audit)
    _require_outputs_outside_ledgers(
        audit,
        (
            (preflight_path, "preflight report"),
            (approval_path, "approval claim"),
            (intent_path, "intent"),
            (report_path, "execute report"),
        ),
    )
    for path, label in ((consumed_path, "consumed claim"), (intent_path, "intent"), (report_path, "execute report")):
        _validate_private_output(path, audit.repo_root, label)
    _validate_private_output(attempt_path, audit.repo_root, "candidate attempt ledger entry")
    _require_distinct_paths(
        (
            (preflight_path, "preflight report"),
            (approval_path, "approval claim"),
            (consumed_path, "consumed claim"),
            (intent_path, "intent"),
            (report_path, "execute report"),
            (attempt_path, "candidate attempt ledger entry"),
        )
    )
    preflight_value, preflight_item = _load_small(preflight_path, preflight_sha256, audit, "preflight report")
    approval_value, approval_item = _load_small(approval_path, approval_sha256, audit, "approval claim")
    audit.held["preflight"] = preflight_item
    audit.held["approval"] = approval_item
    initial_now = clock()
    binding = _validate_preflight(preflight_value, audit, initial_now)
    _validate_approval(approval_value, audit, preflight_sha256, binding, initial_now)
    _validate_completed(audit.completed, audit.contract, audit.profile["artifacts"]["candidate"]["sha256"])
    consumed_sha256 = _consume_claim(audit, approval_sha256, consumed_path, initial_now)
    device = query_device(audit, process_runner)
    if (
        device.identity_binding != binding["identity_binding"]
        or not _device_matches_approved_preflight(preflight_value["device"], device.public)
    ):
        raise DeployError("fresh execute identity/static device gate differs from approved preflight")
    if not _recheck(audit):
        raise DeployError("locked inputs drifted after final device query; claim remains consumed")
    final_now = clock()
    _validate_preflight(preflight_value, audit, final_now)
    _validate_approval(approval_value, audit, preflight_sha256, binding, final_now)
    _attempt_path, attempt_sha256 = _publish_candidate_attempt(
        audit,
        approval_sha256,
        device.identity_binding,
        final_now,
    )
    candidate_fd = audit.candidate.descriptor
    candidate_arg = f"/proc/self/fd/{candidate_fd}"
    argv = (*audit.argv_prefix, "-s", device.serial, "flash", "userdata", candidate_arg)
    argv_semantics = [
        *audit.argv_prefix, "-s", "<identity-matched-device>", "flash", "userdata",
        "/proc/self/fd/<held-candidate-fd>",
    ]
    nonce = audit.profile["identity"]["privacy_nonce"]
    argv_binding = hashlib.sha256(nonce.encode("ascii") + b":" + _canonical({"argv": list(argv)})).hexdigest()
    intent = {
        "approval_sha256": approval_sha256,
        "argv_nonce_scoped_sha256": argv_binding,
        "argv_semantics": argv_semantics,
        "artifacts": _artifact_binding(audit),
        "candidate_attempt_sha256": attempt_sha256,
        "consumed_claim_sha256": consumed_sha256,
        "created_at_unix": final_now,
        "identity_binding": device.identity_binding,
        "max_attempts": 1,
        "retry_authorization": False,
        "schema": INTENT_SCHEMA,
    }
    intent_sha256 = _publish(intent_path, intent, audit, "intent")
    runner_exception = False
    try:
        result = process_runner(argv, WRITE_TIMEOUT_SECONDS, (candidate_fd,), SAFE_ENV)
    except Exception:
        runner_exception = True
        result = CommandResult(None, b"", b"", started=True)
    if not isinstance(result, CommandResult):
        runner_exception = True
        result = CommandResult(None, b"", b"", started=True)
    attempts = 1
    completed = _transport_completed(result) and not runner_exception
    route = COMPLETED_ROUTE if completed else UNKNOWN_ROUTE
    output = result.stdout + b"\0" + result.stderr
    reason = None if completed else (
        "WRITE_RUNNER_EXCEPTION" if runner_exception else
        "WRITE_TIMEOUT" if result.timed_out else
        "WRITE_OUTPUT_LIMIT" if result.output_limited else
        "WRITE_START_FAILED" if not result.started else
        "WRITE_NONZERO_OR_PARTIAL_RESULT"
    )
    if reason is not None and SAFE_REASON_RE.fullmatch(reason) is None:
        raise DeployError("internal unsafe reason code")
    report = {
        "artifacts": _artifact_binding(audit),
        "created_at_unix": clock(),
        "mode": "execute",
        "profile": {"id": audit.profile["profile_id"], "sha256": audit.profile_sha256},
        "result": {
            "approval_sha256": approval_sha256,
            "attempts": attempts,
            "argv_nonce_scoped_sha256": argv_binding,
            "candidate_attempt_sha256": attempt_sha256,
            "consumed_claim_sha256": consumed_sha256,
            "device": device.public,
            "exit_code": result.returncode,
            "intent_sha256": intent_sha256,
            "output_limited": result.output_limited,
            "output_sha256": hashlib.sha256(output).hexdigest(),
            "output_size": len(output),
            "reason": reason,
            "started": result.started,
            "timed_out": result.timed_out,
            "transport_completed": completed,
        },
        "route_status": route,
        "safety": {
            "automatic_retry": False,
            "candidate_attempt_ledger": "profile-bound-candidate-sha256-noreplace",
            "candidate_fd_passed": candidate_arg.startswith("/proc/self/fd/"),
            "claim_consumption_ledger": "profile-bound-approval-sha256-noreplace",
            "command_attempt_limit": 1,
            "partition": "userdata",
            "raw_serial_disclosed": False,
            "retry_scope": "no-automatic-or-same-claim-retry",
            "slot_layout_claim": "not-proven",
            "super_fastbootd_or_slotted_fallback": False,
        },
        "schema": REPORT_SCHEMA,
    }
    return route, _publish(report_path, report, audit, "execute report")


def deploy_once(
    audit: Audit,
    preflight_path: Path,
    approval_path: Path,
    intent_path: Path,
    report_path: Path,
    *,
    approved_operation: str,
    approved_sparse_sha256: str,
    process_runner: ProcessRunner,
    clock: Clock,
) -> tuple[str, str]:
    """Run the authorization-to-write chain with one large-artifact audit.

    The two explicit CLI authorization values are checked before any device
    query.  Only the small, newly-created preflight and approval files are
    reopened; the candidate/raw/rootfs/rollback and all governance inputs stay
    on the original held descriptors for the entire chain.
    """

    candidate_sha256 = audit.profile["artifacts"]["candidate"]["sha256"]
    if approved_operation != "flash-userdata":
        raise DeployError("combined deployment requires --approved-operation flash-userdata")
    if approved_sparse_sha256 != candidate_sha256 or _sha(approved_sparse_sha256, "approved sparse hash") != candidate_sha256:
        raise DeployError("combined deployment approval does not bind the exact sparse candidate")
    _validate_completed(audit.completed, audit.contract, candidate_sha256)
    caller_outputs = (
        (preflight_path, "preflight report"),
        (approval_path, "approval claim"),
        (intent_path, "intent"),
        (report_path, "execute report"),
    )
    _require_distinct_paths(caller_outputs)
    _require_outputs_outside_ledgers(audit, caller_outputs)
    for path, label in caller_outputs:
        _validate_private_output(path, audit.repo_root, label)
    preflight_now = clock()
    _route, preflight_sha256 = preflight(
        audit, preflight_path, process_runner=process_runner, now_unix=preflight_now
    )
    approval_now = clock()
    _route, approval_sha256 = approve(
        audit, preflight_path, preflight_sha256, approval_path, now_unix=approval_now
    )
    # approve() holds the small preflight.  execute() deliberately reopens it
    # by exact digest alongside the new approval, so close this duplicate now.
    audit.held.pop("preflight").close()
    consumed_path = _claim_consumed_path(audit, approval_sha256)
    return execute(
        audit,
        preflight_path,
        preflight_sha256,
        approval_path,
        approval_sha256,
        consumed_path,
        intent_path,
        report_path,
        process_runner=process_runner,
        clock=clock,
    )


AuditFactory = Callable[..., Audit]


def operate(
    mode: str,
    profile_path: Path,
    report_path: Path,
    *,
    preflight_path: Path | None = None,
    preflight_sha256: str | None = None,
    approval_path: Path | None = None,
    approval_sha256: str | None = None,
    consumed_path: Path | None = None,
    intent_path: Path | None = None,
    approved_operation: str | None = None,
    approved_sparse_sha256: str | None = None,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
    process_runner: ProcessRunner = run_bounded,
    audit_factory: AuditFactory = local_audit,
    now_unix: int | None = None,
    clock: Clock | None = None,
) -> tuple[str, str]:
    if clock is not None and now_unix is not None:
        raise DeployError("use either an injected clock or now_unix, not both")
    if clock is None:
        clock = (lambda: int(time.time())) if now_unix is None else (lambda: now_unix)
    path_set: list[tuple[Path, str]] = [(profile_path, "profile")]
    if mode == "approve" and preflight_path is not None:
        path_set.append((preflight_path, "preflight report"))
    elif mode == "execute":
        for path, label in (
            (preflight_path, "preflight report"),
            (approval_path, "approval claim"),
            (consumed_path, "consumed claim"),
            (intent_path, "intent"),
        ):
            if path is not None:
                path_set.append((path, label))
    elif mode == "deploy-once":
        if consumed_path is not None:
            raise DeployError("deploy-once derives claim consumption internally; --consumed-claim is forbidden")
        for path, label in (
            (preflight_path, "preflight report"),
            (approval_path, "approval claim"),
            (intent_path, "intent"),
        ):
            if path is not None:
                path_set.append((path, label))
    path_set.append((report_path, "output report"))
    _require_distinct_paths(path_set)
    audit = audit_factory(profile_path, repo_root=repo_root, contract=contract, process_runner=process_runner)
    try:
        if mode == "local-audit":
            return local_audit_report(audit, report_path, now_unix=clock())
        if mode == "preflight":
            return preflight(audit, report_path, process_runner=process_runner, now_unix=clock())
        if mode == "approve":
            if preflight_path is None or preflight_sha256 is None:
                raise DeployError("approve requires exact preflight path and SHA-256")
            return approve(audit, preflight_path, preflight_sha256, report_path, now_unix=clock())
        if mode == "execute":
            if None in (preflight_path, preflight_sha256, approval_path, approval_sha256, consumed_path, intent_path):
                raise DeployError("execute requires exact preflight, approval, consumed-claim, and intent inputs")
            return execute(
                audit, preflight_path, preflight_sha256, approval_path, approval_sha256,
                consumed_path, intent_path, report_path, process_runner=process_runner, clock=clock,
            )
        if mode == "deploy-once":
            if None in (
                preflight_path, approval_path, intent_path,
                approved_operation, approved_sparse_sha256,
            ):
                raise DeployError("deploy-once requires four caller evidence paths and exact operation/hash authorization")
            return deploy_once(
                audit,
                preflight_path,
                approval_path,
                intent_path,
                report_path,
                approved_operation=approved_operation,
                approved_sparse_sha256=approved_sparse_sha256,
                process_runner=process_runner,
                clock=clock,
            )
        raise DeployError("unsupported mode")
    finally:
        audit.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("local-audit", "preflight", "approve", "execute", "deploy-once"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--preflight", type=Path)
    parser.add_argument("--preflight-sha256")
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--approval-sha256")
    parser.add_argument("--consumed-claim", type=Path)
    parser.add_argument("--intent", type=Path)
    parser.add_argument("--approved-operation", choices=("flash-userdata",))
    parser.add_argument("--approved-sparse-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        route, digest = operate(
            args.mode,
            args.profile,
            args.report,
            preflight_path=args.preflight,
            preflight_sha256=args.preflight_sha256,
            approval_path=args.approval,
            approval_sha256=args.approval_sha256,
            consumed_path=args.consumed_claim,
            intent_path=args.intent,
            approved_operation=args.approved_operation,
            approved_sparse_sha256=args.approved_sparse_sha256,
        )
    except DeployError as error:
        print(f"refused: {error}", file=os.sys.stderr)
        return 2
    print(f"route_status={route}")
    print(f"report_sha256={digest}")
    return 0 if route not in {UNKNOWN_ROUTE} else 3


if __name__ == "__main__":
    raise SystemExit(main())
