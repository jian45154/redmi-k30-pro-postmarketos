#!/usr/bin/env python3
"""Lightweight, strictly read-only revalidation of the completed D114 write.

The completed write report and its exact profile are immutable inputs.  This
tool intentionally does not open, hash, decode, copy, or inspect any candidate,
raw, rollback, attestation, archive, or prepared-stage artifact.  It holds only
the small identity/mapping/provenance governance set while a Windows helper
performs a fixed set of fastboot ``devices``/``getvar`` queries.
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
import subprocess
import tempfile
import time
from typing import Any, Callable, Mapping


REPO = Path(__file__).resolve().parents[2]
HELPER = Path(__file__).with_name("postwrite_revalidate_helper.ps1")

PROFILE_SCHEMA = "lmi-p2-d114-userdata-deploy-profile/v2"
PRIOR_REPORT_SCHEMA = "lmi-p2-d114-userdata-deploy-report/v6"
HELPER_INPUT_SCHEMA = "lmi-p2-d114-postwrite-helper-input/v1"
HELPER_RESULT_SCHEMA = "lmi-p2-d114-postwrite-powershell-result/v1"
REPORT_SCHEMA = "lmi-p2-d114-postwrite-revalidation-report/v1"
PRIOR_ROUTE = "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING"
HELPER_PASS_ROUTE = "POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE"
PASS_ROUTE = "POSTWRITE_REVALIDATED_PRIOR_COMPLETED_NO_STATE_CHANGE"
FAIL_ROUTE = "POSTWRITE_REVALIDATION_FAILED_PRIOR_COMPLETED_NO_STATE_CHANGE"
RESULT_PREFIX = b"LMI_P2_D114_POSTWRITE_RESULT_JSON_BASE64="

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
POSTWRITE_QUERY_NAMES = (
    "devices",
    "serialno",
    "product",
    "unlocked",
    "is-userspace",
    "is-logical:userdata",
    "partition-type:userdata",
    "partition-size:userdata",
    "battery-voltage",
    "battery-soc-ok",
    "max-download-size",
)
FASTBOOT_MEMBERS = (
    ("fastboot.exe", 2_199_704, "dd55fef77ab2753b6423f37f39d91cb00ce53ab4539a2431577f07c4abcaa32a"),
    ("AdbWinApi.dll", 108_184, "120bef587119c6cb926b86b9be90fdfbce38937588eae28cd91a94ce63c7b965"),
    ("AdbWinUsbApi.dll", 73_368, "6ca69a2ca0e31309c087d288f058977d421ad03500e4c3e1dbd981241a069c60"),
)
FASTBOOT_SIGNER_LEAF_SHA256 = "2029505d14baf18af60a0d1a7d8b56447db643b32faa849d4c08d2ab1ff3a4fd"


class RevalidationError(RuntimeError):
    """An input, read-only device gate, or private publication failed."""


HELPER_FAILURE_REASONS = frozenset({
    "HELPER_NONZERO_EXIT",
    "HELPER_OUTER_TIMEOUT",
    "HELPER_RESULT_CHANNEL_INVALID",
    "HELPER_RESULT_ENCODING_INVALID",
    "HELPER_RESULT_JSON_INVALID",
    "HELPER_RESULT_VALIDATION_FAILED",
})


class HelperRunFailed(RevalidationError):
    """PowerShell started, was reaped, but did not return a trusted result."""

    def __init__(self, reason: str) -> None:
        if reason not in HELPER_FAILURE_REASONS:
            raise ValueError("helper failure reason is not whitelisted")
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class Contract:
    profile_path: str = (
        "private/lmi-p1/recovery/d110-d114/p2-d114-build-20260720/"
        "lmi-d114-userdata-p2-deploy-profile-20260721.json"
    )
    profile_sha256: str = "aa7d1bb42164a8049e662480ca0e2e49e01331760663a403782fa0f70c8f32d1"
    prior_report_path: str = (
        "private/lmi-p1/recovery/d110-d114/p2-d114-build-20260720/deploy-reports/"
        "flash-userdata-39d45c6d-20260721.json"
    )
    prior_report_sha256: str = "ba0da95faa2197f498a58b0e3d3a58534c9ab3badbec47d20e1771ebac1265b9"
    mapping_path: str = "config/lmi-p2-d114/physical-userdata-mapping.json"
    mapping_sha256: str = "59f27854ac595a9b615bddeb91aa72e6bf1e0dacd9341cda2783a19bb050014f"
    mapping_size: int = 3_879
    identity_path: str = "private/lmi-p1/recovery/d110-d114/d110-recovery-policy.json"
    identity_sha256: str = "18d3efc57152f297784e0b97af221789e4d508a73d5485e3fac3c5ba94c232cd"
    identity_size: int = 3_431
    provenance_path: str = "config/lmi-p2-d114/fastboot-windows-provenance-lock.json"
    provenance_sha256: str = "26b1882c1c2e7e9baeea86676a83eb39f1e3b77d81f6970a3ea2c96ba5a13afb"
    provenance_size: int = 3_921
    deploy_policy_path: str = "config/lmi-p2-d114/userdata-deploy-policy-lock.json"
    deploy_policy_sha256: str = "c810c807e13778a562cf6ac41be1de9ae170d1be1e4e9cff018c26b257c77fb8"
    deploy_policy_size: int = 6_089
    legacy_helper_path: str = "scripts/lmi_p2_d114/deploy_userdata_helper.ps1"
    legacy_helper_sha256: str = "759aa7e6f336cb9c3fcf9aff45a224886654b5f77d5fa6a139640e9a19969339"
    legacy_helper_size: int = 94_276
    legacy_gate_path: str = "scripts/lmi_p2_d114/deploy_userdata.py"
    legacy_gate_sha256: str = "2fcb1c540b950e20ed7a1d715270f09ce708fdf7a0018c9852bb97a90e6fd526"
    legacy_gate_size: int = 136794
    helper_sha256: str = "bb059d2a3b2ec24cd864a02c66521ce58cf92cbb751329c04485899823d737a6"
    helper_size: int = 33_078


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
    prior: dict[str, Any]
    mapping: dict[str, Any]
    identity_policy: dict[str, Any]
    profile_relative: str
    prior_relative: str
    held: dict[str, HeldFile]

    def close(self) -> None:
        for item in reversed(tuple(self.held.values())):
            item.close()


def _duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise RevalidationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _json_bytes(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload.decode("utf-8"), object_pairs_hook=_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RevalidationError(f"invalid {label} JSON: {error}") from None
    if not isinstance(value, dict):
        raise RevalidationError(f"{label} must be a JSON object")
    return value


def _canonical_json(value: Mapping[str, Any]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _exact_keys(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise RevalidationError(f"{label} fields mismatch")
    return value


def _sha(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise RevalidationError(f"{label} is not a lowercase SHA-256")
    return value


def _positive_int(value: Any, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise RevalidationError(f"{label} must be a positive integer")
    return value


def _identity(st: os.stat_result) -> tuple[int, ...]:
    return (
        st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
        st.st_size, st.st_mtime_ns, st.st_ctime_ns,
    )


def _relative(value: str, label: str) -> PurePosixPath:
    if not isinstance(value, str) or "\\" in value or "\0" in value:
        raise RevalidationError(f"{label} is not a repository-relative path")
    result = PurePosixPath(value)
    if result.is_absolute() or any(part in {"", ".", ".."} for part in result.parts) or result.as_posix() != value:
        raise RevalidationError(f"{label} is not a canonical repository-relative path")
    return result


def _repo_relative(path: Path, root: Path, label: str) -> str:
    try:
        value = path.absolute().relative_to(root.absolute()).as_posix()
    except ValueError:
        raise RevalidationError(f"{label} escapes the repository") from None
    _relative(value, label)
    return value


def _check_ancestors(path: Path, root: Path, label: str) -> None:
    relative = _repo_relative(path, root, label)
    current = root.absolute()
    for component in PurePosixPath(relative).parts[:-1]:
        current /= component
        try:
            info = current.lstat()
        except OSError as error:
            raise RevalidationError(f"cannot inspect {label} ancestor") from error
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RevalidationError(f"{label} has a symlink or non-directory ancestor")


def _open_small(path: Path, root: Path, label: str, maximum: int) -> HeldFile:
    path = path.absolute()
    _check_ancestors(path, root, label)
    try:
        before = path.lstat()
    except OSError as error:
        raise RevalidationError(f"cannot inspect {label}") from error
    if (
        not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1 or before.st_uid != os.geteuid()
        or before.st_mode & 0o022 or before.st_size <= 0 or before.st_size > maximum
    ):
        raise RevalidationError(f"{label} is not a safe small, single-link file")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RevalidationError(f"cannot safely open {label}") from error
    try:
        opened = os.fstat(descriptor)
        if _identity(opened) != _identity(before):
            raise RevalidationError(f"{label} changed while opening")
        digest = hashlib.sha256()
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                raise RevalidationError(f"{label} was truncated while hashing")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1) or _identity(os.fstat(descriptor)) != _identity(opened):
            raise RevalidationError(f"{label} changed while hashing")
        os.lseek(descriptor, 0, os.SEEK_SET)
        return HeldFile(path, descriptor, _identity(opened), opened.st_size, digest.hexdigest())
    except BaseException:
        os.close(descriptor)
        raise


def _held_bytes(item: HeldFile, label: str) -> bytes:
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    result = bytearray()
    while len(result) < item.size:
        chunk = os.read(item.descriptor, item.size - len(result))
        if not chunk:
            raise RevalidationError(f"{label} became unreadable")
        result.extend(chunk)
    os.lseek(item.descriptor, 0, os.SEEK_SET)
    return bytes(result)


def _artifact_identity(value: Any, label: str, *, logical: bool = False) -> dict[str, Any]:
    keys = {"path", "sha256", "size"}
    if logical:
        keys |= {"logical_size", "representation", "roundtrip_raw_sha256"}
    result = _exact_keys(value, keys, label)
    if not isinstance(result["path"], str) or not result["path"]:
        raise RevalidationError(f"{label}.path is invalid")
    _sha(result["sha256"], f"{label}.sha256")
    _positive_int(result["size"], f"{label}.size")
    if logical:
        _positive_int(result["logical_size"], f"{label}.logical_size")
        _sha(result["roundtrip_raw_sha256"], f"{label}.roundtrip_raw_sha256")
        if result["representation"] != "android-sparse":
            raise RevalidationError(f"{label} representation mismatch")
    return result


def _validate_profile(profile: dict[str, Any], contract: Contract) -> None:
    _exact_keys(profile, {"artifacts", "compatibility", "device", "execution", "fastboot", "profile_id", "schema"}, "profile")
    if profile["schema"] != PROFILE_SCHEMA or not isinstance(profile["profile_id"], str) or ID_RE.fullmatch(profile["profile_id"]) is None:
        raise RevalidationError("profile schema or id mismatch")
    artifacts = _exact_keys(profile["artifacts"], {
        "assembly_attestation", "candidate", "candidate_raw", "deploy_policy_lock",
        "p2_injection_attestation", "physical_mapping_evidence", "rollback", "source_lock",
    }, "profile artifacts")
    candidate = _artifact_identity(artifacts["candidate"], "candidate", logical=True)
    _artifact_identity(artifacts["candidate_raw"], "candidate_raw")
    rollback = _artifact_identity(artifacts["rollback"], "rollback", logical=True)
    mapping = _artifact_identity(artifacts["physical_mapping_evidence"], "mapping")
    if mapping != {"path": contract.mapping_path, "sha256": contract.mapping_sha256, "size": contract.mapping_size}:
        raise RevalidationError("profile mapping binding mismatch")
    deploy_policy = _artifact_identity(artifacts["deploy_policy_lock"], "deploy policy")
    if deploy_policy != {
        "path": contract.deploy_policy_path,
        "sha256": contract.deploy_policy_sha256,
        "size": contract.deploy_policy_size,
    }:
        raise RevalidationError("profile deploy policy binding mismatch")
    if candidate["logical_size"] != 3_339_714_560 or rollback["logical_size"] != 3_339_714_560:
        raise RevalidationError("profile logical artifact sizes mismatch")
    expected_device = {
        "expected_product": "lmi", "expected_userdata_capacity": 114_898_743_296,
        "minimum_battery_mv": 3_800, "minimum_max_download_size": 52_944_896,
        "partition_type": "f2fs", "require_soc_ok": True,
    }
    if profile["device"] != expected_device:
        raise RevalidationError("profile device gates mismatch")
    if profile["fastboot"] != {
        "path": "localappdata/lmi-p2-d114/fastboot-r37.0.0/fastboot.exe",
        "sha256": FASTBOOT_MEMBERS[0][2], "size": FASTBOOT_MEMBERS[0][1],
    }:
        raise RevalidationError("profile fastboot identity mismatch")


def _validate_prior(prior: dict[str, Any], profile: dict[str, Any], profile_sha256: str) -> None:
    _exact_keys(prior, {"artifacts", "created_at_unix", "mode", "profile", "result", "route_status", "safety", "schema"}, "prior report")
    if (
        prior["schema"] != PRIOR_REPORT_SCHEMA or prior["mode"] != "execute"
        or prior["route_status"] != PRIOR_ROUTE
        or prior["profile"] != {"id": profile["profile_id"], "sha256": profile_sha256}
    ):
        raise RevalidationError("prior report is not the exact pending completed write")
    prior_candidate = prior.get("artifacts", {}).get("candidate")
    candidate = profile["artifacts"]["candidate"]
    if prior_candidate != {"path": candidate["path"], "sha256": candidate["sha256"], "size": candidate["size"]}:
        raise RevalidationError("prior report candidate binding mismatch")
    result = prior["result"]
    flash = result.get("flash") if isinstance(result, dict) else None
    if (
        not isinstance(flash, dict) or flash.get("attempts") != 1
        or flash.get("exit_code") != 0 or flash.get("transport_completed") is not True
        or result.get("locked_inputs_intact") is not True
        or result.get("post_helper_input_recheck") is not True
    ):
        raise RevalidationError("prior report lacks completed transport and intact input evidence")
    artifact_hashes = result.get("artifact_hashes")
    if (
        not isinstance(artifact_hashes, dict)
        or artifact_hashes.get("profile") != profile_sha256
        or artifact_hashes.get("deploy_policy_lock")
        != profile["artifacts"]["deploy_policy_lock"]["sha256"]
    ):
        raise RevalidationError("prior report lacks its exact profile and deploy policy hashes")


def _validate_mapping(mapping: dict[str, Any], profile: dict[str, Any], contract: Contract) -> dict[str, Any]:
    if mapping.get("schema") != "lmi-d114-physical-userdata-mapping/v2":
        raise RevalidationError("mapping schema mismatch")
    identity_spec = mapping.get("evidence", {}).get("private_identity_policy")
    if identity_spec != {"path": contract.identity_path, "sha256": contract.identity_sha256, "size": contract.identity_size}:
        raise RevalidationError("mapping private identity binding mismatch")
    if mapping.get("identity_binding") != {
        "current_device_must_match_nonce_scoped_private_policy": True,
        "public_stable_fingerprint_forbidden": True,
    }:
        raise RevalidationError("mapping identity privacy policy mismatch")
    if mapping.get("override") != {
        "allowed_getvar_result": "unsupported", "fastboot_mode": "bootloader",
        "partition": "userdata", "partition_type": "f2fs",
        "super_or_fastbootd_fallback_allowed": False,
    }:
        raise RevalidationError("mapping physical override mismatch")
    userdata = mapping.get("userdata")
    if not isinstance(userdata, dict) or (
        userdata.get("block_device") != "/dev/sda34"
        or userdata.get("capacity_bytes") != profile["device"]["expected_userdata_capacity"]
        or userdata.get("gpt_logical_sector_size") != 4096
        or userdata.get("partlabel") != "userdata"
    ):
        raise RevalidationError("mapping userdata identity mismatch")
    return identity_spec


def _validate_identity_policy(value: dict[str, Any]) -> None:
    historical = value.get("historical_identity")
    if (
        value.get("schema") != "lmi-d110-recovery-policy/v2"
        or value.get("device", {}).get("product") != "lmi"
        or not isinstance(historical, dict)
        or SHA256_RE.fullmatch(str(historical.get("privacy_nonce", ""))) is None
        or SHA256_RE.fullmatch(str(historical.get("expected_nonce_scoped_serial_sha256", ""))) is None
    ):
        raise RevalidationError("private nonce-scoped identity policy mismatch")


def _validate_provenance(value: dict[str, Any]) -> None:
    if value.get("schema") != "lmi-p2-d114-fastboot-windows-provenance/v2":
        raise RevalidationError("fastboot provenance schema mismatch")
    expected = [
        {"path": f"platform-tools/{name}", "size": size, "sha256": digest}
        for name, size, digest in FASTBOOT_MEMBERS
    ]
    if value.get("members") != expected:
        raise RevalidationError("fastboot provenance member closure mismatch")
    auth = value.get("authenticode")
    if not isinstance(auth, dict) or (
        auth.get("signer_leaf_certificate_sha256") != FASTBOOT_SIGNER_LEAF_SHA256
        or auth.get("signer_subject_cn") != "Google LLC"
        or auth.get("runtime_gate") != "require-windows-status-valid-before-any-device-query"
    ):
        raise RevalidationError("fastboot provenance Authenticode policy mismatch")


def _validate_prior_deploy_policy(value: dict[str, Any], contract: Contract) -> None:
    """Bind the prior runtime provenance policy without rerunning it now."""

    if value.get("schema") != "lmi-p2-d114-userdata-deploy-policy-lock/v4":
        raise RevalidationError("prior deploy policy schema mismatch")
    if value.get("helper") != {
        "path": contract.legacy_helper_path,
        "sha256": contract.legacy_helper_sha256,
        "size": contract.legacy_helper_size,
    }:
        raise RevalidationError("prior deploy policy helper binding mismatch")
    bindings = value.get("repo_bindings")
    if not isinstance(bindings, dict) or bindings.get("fastboot_windows_provenance_lock") != {
        "path": contract.provenance_path,
        "sha256": contract.provenance_sha256,
        "size": contract.provenance_size,
    }:
        raise RevalidationError("prior deploy policy provenance binding mismatch")
    fastboot = value.get("fastboot")
    auth = fastboot.get("authenticode") if isinstance(fastboot, dict) else None
    if not isinstance(auth, dict) or (
        auth.get("runtime_gate") != "require-windows-status-valid-before-any-device-query"
        or auth.get("revocation_policy") != "online-entire-chain-no-ignore-flags-for-signer-and-timestamp"
        or auth.get("signer_leaf_certificate_sha256") != FASTBOOT_SIGNER_LEAF_SHA256
        or auth.get("signer_subject_cn") != "Google LLC"
    ):
        raise RevalidationError("prior deploy policy runtime provenance mismatch")
    if fastboot.get("executable") != {
        "path": "localappdata/lmi-p2-d114/fastboot-r37.0.0/fastboot.exe",
        "sha256": FASTBOOT_MEMBERS[0][2],
        "size": FASTBOOT_MEMBERS[0][1],
    }:
        raise RevalidationError("prior deploy policy fastboot executable mismatch")


def local_audit(
    profile_path: Path,
    profile_sha256: str,
    prior_report_path: Path,
    prior_report_sha256: str,
    *,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
) -> Audit:
    _sha(profile_sha256, "profile SHA-256")
    _sha(prior_report_sha256, "prior report SHA-256")
    repo_root = repo_root.absolute()
    profile_relative = _repo_relative(profile_path, repo_root, "profile")
    prior_relative = _repo_relative(prior_report_path, repo_root, "prior report")
    if (
        profile_relative != contract.profile_path or profile_sha256 != contract.profile_sha256
        or prior_relative != contract.prior_report_path or prior_report_sha256 != contract.prior_report_sha256
    ):
        raise RevalidationError("paths and hashes do not name the reviewed completed write")
    held: dict[str, HeldFile] = {}
    try:
        specs = (
            ("profile", profile_path, 256 * 1024, profile_sha256, None),
            ("prior_report", prior_report_path, 256 * 1024, prior_report_sha256, None),
            ("mapping", repo_root / contract.mapping_path, 64 * 1024, contract.mapping_sha256, contract.mapping_size),
            ("identity_policy", repo_root / contract.identity_path, 64 * 1024, contract.identity_sha256, contract.identity_size),
            ("provenance", repo_root / contract.provenance_path, 64 * 1024, contract.provenance_sha256, contract.provenance_size),
            ("deploy_policy", repo_root / contract.deploy_policy_path, 64 * 1024, contract.deploy_policy_sha256, contract.deploy_policy_size),
            ("legacy_helper", repo_root / contract.legacy_helper_path, 128 * 1024, contract.legacy_helper_sha256, contract.legacy_helper_size),
            ("legacy_gate", repo_root / contract.legacy_gate_path, 192 * 1024, contract.legacy_gate_sha256, contract.legacy_gate_size),
            ("helper", HELPER if repo_root == REPO else repo_root / "scripts/lmi_p2_d114/postwrite_revalidate_helper.ps1", 256 * 1024, contract.helper_sha256, contract.helper_size),
        )
        for name, path, maximum, digest, size in specs:
            item = _open_small(path, repo_root, name.replace("_", " "), maximum)
            if item.sha256 != digest or (size is not None and item.size != size):
                item.close()
                raise RevalidationError(f"{name.replace('_', ' ')} identity mismatch")
            held[name] = item
        profile = _json_bytes(_held_bytes(held["profile"], "profile"), "profile")
        prior = _json_bytes(_held_bytes(held["prior_report"], "prior report"), "prior report")
        mapping = _json_bytes(_held_bytes(held["mapping"], "mapping"), "mapping")
        identity_policy = _json_bytes(_held_bytes(held["identity_policy"], "identity policy"), "identity policy")
        provenance = _json_bytes(_held_bytes(held["provenance"], "provenance"), "provenance")
        deploy_policy = _json_bytes(_held_bytes(held["deploy_policy"], "deploy policy"), "deploy policy")
        _validate_profile(profile, contract)
        _validate_prior(prior, profile, profile_sha256)
        _validate_mapping(mapping, profile, contract)
        _validate_identity_policy(identity_policy)
        _validate_provenance(provenance)
        _validate_prior_deploy_policy(deploy_policy, contract)
        return Audit(repo_root, profile, prior, mapping, identity_policy, profile_relative, prior_relative, held)
    except BaseException:
        for item in reversed(tuple(held.values())):
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
        os.lseek(item.descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        remaining = item.size
        while remaining:
            chunk = os.read(item.descriptor, min(64 * 1024, remaining))
            if not chunk:
                return False
            digest.update(chunk)
            remaining -= len(chunk)
        os.lseek(item.descriptor, 0, os.SEEK_SET)
        if digest.hexdigest() != item.sha256:
            return False
    return True


def _helper_input(audit: Audit) -> dict[str, Any]:
    profile = audit.profile
    candidate = profile["artifacts"]["candidate"]
    historical = audit.identity_policy["historical_identity"]
    return {
        "candidate": {"logical_size": candidate["logical_size"], "sha256": candidate["sha256"], "size": candidate["size"]},
        "device": dict(profile["device"]),
        "fastboot": {
            "members": [{"name": name, "sha256": digest, "size": size} for name, size, digest in FASTBOOT_MEMBERS],
            "signer_leaf_certificate_sha256": FASTBOOT_SIGNER_LEAF_SHA256,
            "signer_subject_cn": "Google LLC",
        },
        "identity": {
            "expected_nonce_scoped_serial_sha256": historical["expected_nonce_scoped_serial_sha256"],
            "privacy_nonce": historical["privacy_nonce"],
        },
        "mapping": {
            "allowed_getvar_result": audit.mapping["override"]["allowed_getvar_result"],
            "block_device": audit.mapping["userdata"]["block_device"],
            "capacity_bytes": audit.mapping["userdata"]["capacity_bytes"],
            "fastboot_mode": audit.mapping["override"]["fastboot_mode"],
            "partition": audit.mapping["override"]["partition"],
            "partition_type": audit.mapping["override"]["partition_type"],
            "super_or_fastbootd_fallback_allowed": audit.mapping["override"]["super_or_fastbootd_fallback_allowed"],
        },
        "physical_replug_confirmed": True,
        "prior_write": {"route_status": PRIOR_ROUTE, "sha256": audit.held["prior_report"].sha256},
        "profile": {"id": profile["profile_id"], "sha256": audit.held["profile"].sha256},
        "schema": HELPER_INPUT_SCHEMA,
    }


PowerShellRunner = Callable[[Audit], dict[str, Any]]

POWERSHELL_BOOTSTRAP = r"""
$ErrorActionPreference='Stop';$p=$args[0];$expected=$args[1];$encoded=[Console]::In.ReadToEnd().Trim();$s=[IO.File]::Open($p,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read);try{$h=[Security.Cryptography.SHA256]::Create();try{$actual=([BitConverter]::ToString($h.ComputeHash($s))).Replace('-','').ToLowerInvariant()}finally{$h.Dispose()};if($actual-cne $expected){throw 'HELPER_HASH_MISMATCH'};$s.Position=0;$b=New-Object byte[] $s.Length;$n=0;while($n-lt $b.Length){$r=$s.Read($b,$n,$b.Length-$n);if($r-le 0){throw 'HELPER_SHORT_READ'};$n+=$r};$s.Position=0;$t=[Text.UTF8Encoding]::new($false,$true).GetString($b);$sb=[ScriptBlock]::Create($t);& $sb -ContractJsonBase64 $encoded}finally{$s.Dispose()}
""".strip()


def _windows_path(path: Path) -> str:
    result = subprocess.run(["wslpath", "-w", str(path)], check=False, capture_output=True, text=True, timeout=5)
    if result.returncode or not result.stdout.strip() or "\n" in result.stdout.strip():
        raise RevalidationError("could not convert the staged helper path")
    return result.stdout.strip()


def run_powershell(audit: Audit) -> dict[str, Any]:
    """Run the hash-locked read-only helper without placing identity data in argv."""

    with tempfile.TemporaryDirectory(prefix="lmi-d114-postwrite-") as temporary:
        root = Path(temporary)
        os.chmod(root, 0o700)
        helper_path = root / "helper.ps1"
        bootstrap_path = root / "bootstrap.ps1"
        for path, payload in (
            (helper_path, _held_bytes(audit.held["helper"], "helper")),
            (bootstrap_path, (POWERSHELL_BOOTSTRAP + "\n").encode("ascii")),
        ):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
            try:
                cursor = 0
                while cursor < len(payload):
                    written = os.write(descriptor, payload[cursor:])
                    if written <= 0:
                        raise RevalidationError("short staged helper write")
                    cursor += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        encoded = base64.b64encode(_canonical_json(_helper_input(audit))) + b"\n"
        command = [
            "/mnt/c/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe",
            "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
            "-File", _windows_path(bootstrap_path), _windows_path(helper_path), audit.held["helper"].sha256,
        ]
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except OSError as error:
            raise RevalidationError("could not start read-only PowerShell helper") from error
        try:
            stdout, _stderr = process.communicate(input=encoded, timeout=180)
        except subprocess.TimeoutExpired:
            # Terminating and then communicating explicitly waits for the
            # PowerShell host.  Closing its handles triggers the nested native
            # runner's JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE containment.
            process.kill()
            process.communicate()
            raise HelperRunFailed("HELPER_OUTER_TIMEOUT") from None
        if process.returncode != 0:
            raise HelperRunFailed("HELPER_NONZERO_EXIT")
        lines = [line for line in stdout.splitlines() if line]
        if len(lines) != 1 or not lines[0].startswith(RESULT_PREFIX):
            raise HelperRunFailed("HELPER_RESULT_CHANNEL_INVALID")
        try:
            payload = base64.b64decode(lines[0][len(RESULT_PREFIX):], validate=True)
        except (ValueError, base64.binascii.Error):
            raise HelperRunFailed("HELPER_RESULT_ENCODING_INVALID") from None
        try:
            return _json_bytes(payload, "PowerShell result")
        except RevalidationError:
            raise HelperRunFailed("HELPER_RESULT_JSON_INVALID") from None


def _validate_helper(value: dict[str, Any], audit: Audit) -> dict[str, Any]:
    expected_keys = {
        "candidate", "device", "fastboot_members", "fastboot_queries_attempted",
        "fastboot_queries_completed", "flash", "input_binding",
        "locked_inputs_intact", "mode", "reason", "route_status", "schema",
        "serial_disclosed",
    }
    _exact_keys(value, expected_keys, "PowerShell result")
    if value["schema"] != HELPER_RESULT_SCHEMA or value["mode"] != "PostwriteRevalidate":
        raise RevalidationError("PowerShell result schema mismatch")
    attempted = value["fastboot_queries_attempted"]
    completed = value["fastboot_queries_completed"]
    if (
        not isinstance(attempted, list)
        or attempted != list(POSTWRITE_QUERY_NAMES[:len(attempted)])
        or not isinstance(completed, list)
        or completed != list(POSTWRITE_QUERY_NAMES[:len(completed)])
        or completed != attempted[:len(completed)]
        or len(attempted) - len(completed) not in {0, 1}
    ):
        raise RevalidationError("PowerShell attempted/completed query evidence mismatch")
    if value["flash"] != {"attempts": 0} or value["serial_disclosed"] is not False:
        raise RevalidationError("PowerShell helper did not prove a zero-attempt private run")
    candidate = audit.profile["artifacts"]["candidate"]
    expected_candidate = {"logical_size": candidate["logical_size"], "sha256": candidate["sha256"], "size": candidate["size"]}
    if value["candidate"] != expected_candidate:
        raise RevalidationError("PowerShell candidate binding mismatch")
    if value["fastboot_members"] != [
        {"name": name, "sha256": digest, "size": size} for name, size, digest in FASTBOOT_MEMBERS
    ]:
        raise RevalidationError("PowerShell fastboot closure mismatch")
    if value["input_binding"] != {
        "physical_replug_confirmed": True,
        "prior_write_report_sha256": audit.held["prior_report"].sha256,
        "profile_sha256": audit.held["profile"].sha256,
    }:
        raise RevalidationError("PowerShell input binding mismatch")
    if type(value["locked_inputs_intact"]) is not bool:
        raise RevalidationError("PowerShell lock evidence type mismatch")
    if value["route_status"] not in {HELPER_PASS_ROUTE, "REFUSED_NO_STATE_CHANGE"}:
        raise RevalidationError("PowerShell route mismatch")
    reason = value["reason"]
    if reason is not None and (not isinstance(reason, str) or re.fullmatch(r"[A-Z0-9_]{1,96}", reason) is None):
        raise RevalidationError("PowerShell refusal reason is not a safe code")
    if value["route_status"] == HELPER_PASS_ROUTE and reason is not None:
        raise RevalidationError("PowerShell passed route unexpectedly has a reason")
    if value["route_status"] == HELPER_PASS_ROUTE:
        if (
            attempted != list(POSTWRITE_QUERY_NAMES)
            or completed != list(POSTWRITE_QUERY_NAMES)
            or value["locked_inputs_intact"] is not True
        ):
            raise RevalidationError("PowerShell passed route lacks complete queries and intact locks")
        expected = audit.profile["device"]
        device = value["device"]
        logical = device.get("is_logical_userdata") if isinstance(device, dict) else None
        if not (
            device.get("identity_match") is True and device.get("product") == "lmi"
            and device.get("unlocked") == "yes" and device.get("userspace") == "no"
            and logical in {"no", "unsupported"}
            and device.get("physical_mapping_evidence_override") is (logical == "unsupported")
            and device.get("partition_type") == "f2fs"
            and device.get("partition_size") == expected["expected_userdata_capacity"]
            and type(device.get("battery_mv")) is int and device["battery_mv"] >= expected["minimum_battery_mv"]
            and device.get("soc_ok") == "yes"
            and type(device.get("max_download_size")) is int and device["max_download_size"] >= expected["minimum_max_download_size"]
        ):
            raise RevalidationError("PowerShell passed route lacks the complete device gates")
    return value


def _private_parent(path: Path, repo_root: Path) -> Path:
    path = path.absolute()
    _check_ancestors(path, repo_root, "report")
    try:
        info = path.parent.lstat()
    except OSError as error:
        raise RevalidationError("cannot inspect report directory") from error
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise RevalidationError("report directory must be user-owned canonical mode-0700")
    return path.parent


def _publish(path: Path, value: dict[str, Any], repo_root: Path) -> str:
    parent = _private_parent(path, repo_root)
    try:
        path.lstat()
    except FileNotFoundError:
        pass
    else:
        raise RevalidationError("report overwrite is forbidden")
    payload = _canonical_json(value)
    digest = hashlib.sha256(payload).hexdigest()
    descriptor, name = tempfile.mkstemp(prefix=".lmi-d114-postwrite-", dir=parent)
    temporary: Path | None = Path(name)
    try:
        os.fchmod(descriptor, 0o600)
        cursor = 0
        while cursor < len(payload):
            written = os.write(descriptor, payload[cursor:])
            if written <= 0:
                raise RevalidationError("short report write")
            cursor += written
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.link(temporary, path)
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
        if temporary is not None and temporary.exists():
            temporary.unlink()
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600 or hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise RevalidationError("published report identity mismatch")
    return digest


def revalidate(
    profile_path: Path,
    profile_sha256: str,
    prior_report_path: Path,
    prior_report_sha256: str,
    report_path: Path,
    *,
    physical_replug_confirmed: bool,
    repo_root: Path = REPO,
    contract: Contract = PRODUCTION,
    powershell_runner: PowerShellRunner = run_powershell,
    now_unix: int | None = None,
) -> tuple[str, str]:
    if physical_replug_confirmed is not True:
        raise RevalidationError("explicit physical replug confirmation is required")
    if report_path.absolute() in {profile_path.absolute(), prior_report_path.absolute()}:
        raise RevalidationError("report must not replace a locked input")
    _private_parent(report_path, repo_root.absolute())
    audit = local_audit(
        profile_path, profile_sha256, prior_report_path, prior_report_sha256,
        repo_root=repo_root, contract=contract,
    )
    try:
        helper: dict[str, Any] | None = None
        helper_result_received = False
        helper_failure_reason: str | None = None
        try:
            raw_helper = powershell_runner(audit)
        except HelperRunFailed as error:
            helper_failure_reason = error.reason
        else:
            try:
                helper = _validate_helper(raw_helper, audit)
                helper_result_received = True
            except RevalidationError:
                helper_failure_reason = "HELPER_RESULT_VALIDATION_FAILED"
        recheck = _recheck(audit)
        passed = (
            helper is not None
            and helper["route_status"] == HELPER_PASS_ROUTE
            and recheck
        )
        route = PASS_ROUTE if passed else FAIL_ROUTE
        if not recheck:
            reason = "POST_HELPER_SMALL_INPUT_RECHECK_FAILED"
        elif helper is None:
            reason = helper_failure_reason
        else:
            reason = helper["reason"]
        if reason is None and not passed:
            reason = "HELPER_RESULT_VALIDATION_FAILED"
        candidate = audit.profile["artifacts"]["candidate"]
        current_fastboot_identity_verified = bool(
            helper_result_received
            and helper is not None
            and helper["locked_inputs_intact"] is True
        )
        report = {
            "created_at_unix": int(time.time()) if now_unix is None else now_unix,
            "mode": "postwrite-revalidate",
            "profile": {"id": audit.profile["profile_id"], "path": audit.profile_relative, "sha256": profile_sha256},
            "prior_write": {
                "candidate": {"logical_size": candidate["logical_size"], "sha256": candidate["sha256"], "size": candidate["size"]},
                "path": audit.prior_relative, "physical_replug_confirmed": True,
                "route_status": PRIOR_ROUTE, "sha256": prior_report_sha256,
            },
            "result": {
                "current_fastboot_identity_verified": current_fastboot_identity_verified,
                "device": helper["device"] if helper is not None else None,
                "expected_fastboot_members": [
                    {"name": name, "sha256": digest, "size": size}
                    for name, size, digest in FASTBOOT_MEMBERS
                ],
                "fastboot_members": (
                    helper["fastboot_members"]
                    if current_fastboot_identity_verified and helper is not None
                    else None
                ),
                "fastboot_query_contract": list(POSTWRITE_QUERY_NAMES),
                "fastboot_queries_attempted": (
                    helper["fastboot_queries_attempted"]
                    if helper_result_received and helper is not None else None
                ),
                "fastboot_queries_completed": (
                    helper["fastboot_queries_completed"]
                    if helper_result_received and helper is not None else None
                ),
                "flash": {"attempts": 0},
                "helper_result_received": helper_result_received,
                "locked_inputs_intact": helper["locked_inputs_intact"] if helper is not None else False,
                "post_helper_input_recheck": recheck, "reason": reason,
            },
            "route_status": route,
            "safety": {
                "candidate_or_rollback_opened": False, "device_state_change_attempted": False,
                "current_online_authenticode_repeated": False,
                "current_validation": (
                    "exact-three-member-sha256-size-acl-closure"
                    if current_fastboot_identity_verified
                    else "current-three-member-validation-not-confirmed"
                ),
                "physical_replug_confirmed": True, "serial_disclosed": False,
                "prior_runtime_gate_policy": "online-entire-chain-no-ignore-flags-for-signer-and-timestamp",
                "prior_runtime_provenance_reused": True,
                "prior_write_provenance_reused": True,
                "windows_absolute_path_disclosed": False,
            },
            "schema": REPORT_SCHEMA,
        }
        return route, _publish(report_path, report, audit.repo_root)
    finally:
        audit.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--write-report", required=True, type=Path)
    parser.add_argument("--write-report-sha256", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--physical-replug-confirmed", required=True, action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        route, digest = revalidate(
            args.profile, args.profile_sha256, args.write_report, args.write_report_sha256,
            args.report, physical_replug_confirmed=args.physical_replug_confirmed,
        )
    except RevalidationError as error:
        print(f"refused: {error}", file=os.sys.stderr)
        return 2
    print(f"route_status={route}")
    print(f"report_sha256={digest}")
    return 0 if route == PASS_ROUTE else 2


if __name__ == "__main__":
    raise SystemExit(main())
