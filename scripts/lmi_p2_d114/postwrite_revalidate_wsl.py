#!/usr/bin/env python3
"""Independent, read-only WSL postwrite revalidation for D114 userdata.

This gate records a host-observed zero-device-to-one-device fastboot sequence
instead of accepting a boolean "I replugged" assertion:

* ``arm-replug`` requires the fixed read-only ``fastboot devices`` query to
  report zero devices, then publishes a short-lived random nonce token.
* after the operator disconnects and reconnects the device, ``revalidate``
  durably consumes that exact token and requires one nonce-bound lmi device to
  pass the complete fixed read-only getvar gate.

The exact completed WSL execute report and its small profile/governance/runtime
closure are held throughout.  Its deterministic consumed-claim and
candidate-attempt ledger entries plus exact preattempt intent are also opened
and cross-validated.  Candidate, raw, rootfs, rollback, assembly, and injection
files are deliberately never opened.  This module has no boot, reboot, flash,
erase, format, or retry path.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat
import sys
import time
from typing import Any, Callable, Mapping, Sequence

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from scripts.lmi_p2_d114 import deploy_userdata_wsl as deploy


REPO = Path(__file__).resolve().parents[2]
ARM_SCHEMA = "lmi-p2-d114-userdata-wsl-postwrite-replug-arm/v1"
CONSUMED_SCHEMA = "lmi-p2-d114-userdata-wsl-postwrite-replug-consumed/v1"
REPORT_SCHEMA = "lmi-p2-d114-userdata-wsl-postwrite-revalidation/v1"
CANDIDATE_ATTEMPT_SCHEMA = "lmi-p2-d114-userdata-wsl-candidate-attempt/v1"
REPLUG_TTL_SECONDS = 300
ARM_ROUTE = "POSTWRITE_REPLUG_ARMED_ABSENCE_OBSERVED_NO_STATE_CHANGE"
PASS_ROUTE = "POSTWRITE_REVALIDATED_PRIOR_COMPLETED_NO_STATE_CHANGE"
FAIL_ROUTE = "POSTWRITE_REVALIDATION_FAILED_TOKEN_CONSUMED_NO_RETRY"
ABSENCE_QUERY = ("devices",)
FULL_QUERY_CONTRACT = deploy.QUERY_NAMES

EXPECTED_SPARSE_SHA256 = "c9bf765a9359603b2b7fb5d0c447e6c0bb83b14c7536366666c71d96790dfc8b"
EXPECTED_SPARSE_SIZE = 2_236_688_828
EXPECTED_LOGICAL_SIZE = 3_436_183_552
EXPECTED_RAW_SHA256 = "382f3ae32d5a3866a5ce0b5559e5289b784925c5377ce3906b1867e0c060acdf"


class RevalidationError(RuntimeError):
    """A small input, transition token, device query, or publication failed."""


@dataclass
class Audit:
    base: deploy.Audit
    write_report: dict[str, Any]
    write_report_path: Path
    write_report_sha256: str
    write_report_size: int
    lineage: dict[str, dict[str, Any]]

    def close(self) -> None:
        self.base.close()


ProcessRunner = Callable[
    [Sequence[str], int, tuple[int, ...], Mapping[str, str]],
    deploy.CommandResult,
]
NonceFactory = Callable[[], bytes]
Clock = Callable[[], int]


@dataclass(frozen=True)
class LineageSpec:
    path: Path
    sha256: str
    size: int


def _phase_time(now_unix: int | None, clock: Clock, label: str) -> int:
    value = clock() if now_unix is None else now_unix
    if type(value) is not int or value <= 0:
        raise RevalidationError(f"{label} time must be a positive integer")
    return value


def _raise_deploy(error: deploy.DeployError) -> RevalidationError:
    return RevalidationError(str(error))


def _artifact_binding(profile: dict[str, Any], profile_sha256: str) -> dict[str, Any]:
    artifacts = profile["artifacts"]
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
        "profile": profile_sha256,
    }


def _validate_execute_report(
    value: dict[str, Any],
    profile: dict[str, Any],
    profile_sha256: str,
) -> dict[str, Any]:
    try:
        deploy._exact(
            value,
            {"artifacts", "created_at_unix", "mode", "profile", "result", "route_status", "safety", "schema"},
            "WSL execute report",
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    if (
        value["schema"] != deploy.REPORT_SCHEMA
        or value["mode"] != "execute"
        or value["route_status"] != deploy.COMPLETED_ROUTE
        or value["profile"] != {"id": profile["profile_id"], "sha256": profile_sha256}
        or value["artifacts"] != _artifact_binding(profile, profile_sha256)
    ):
        raise RevalidationError("write report is not the exact completed WSL execute report")
    created = value["created_at_unix"]
    if type(created) is not int or created <= 0:
        raise RevalidationError("write report creation time is invalid")
    candidate = value["artifacts"].get("candidate")
    if candidate != {
        "logical_size": EXPECTED_LOGICAL_SIZE,
        "roundtrip_raw_sha256": EXPECTED_RAW_SHA256,
        "sha256": EXPECTED_SPARSE_SHA256,
        "size": EXPECTED_SPARSE_SIZE,
    }:
        raise RevalidationError("write report candidate is not the exact new sparse image")
    result = value["result"]
    try:
        deploy._exact(
            result,
            {
                "approval_sha256", "attempts", "argv_nonce_scoped_sha256",
                "candidate_attempt_sha256", "consumed_claim_sha256", "device",
                "exit_code", "intent_sha256",
                "output_limited", "output_sha256", "output_size", "reason",
                "started", "timed_out", "transport_completed",
            },
            "WSL execute result",
        )
        for name in (
            "approval_sha256", "argv_nonce_scoped_sha256", "candidate_attempt_sha256",
            "consumed_claim_sha256", "intent_sha256", "output_sha256",
        ):
            deploy._sha(result[name], f"WSL execute result {name}")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    device = result.get("device")
    if (
        result["attempts"] != 1
        or result["started"] is not True
        or result["timed_out"] is not False
        or result["output_limited"] is not False
        or result["exit_code"] != 0
        or result["reason"] is not None
        or result["transport_completed"] is not True
        or type(result["output_size"]) is not int
        or result["output_size"] <= 0
        or result["output_size"] > deploy.MAX_OUTPUT_BYTES + 1
        or not isinstance(device, dict)
    ):
        raise RevalidationError("write report lacks exact successful transport evidence")
    _validate_public_device(device, profile, "WSL execute result device")
    if value["safety"] != {
        "automatic_retry": False,
        "candidate_attempt_ledger": "profile-bound-candidate-sha256-noreplace",
        "candidate_fd_passed": True,
        "claim_consumption_ledger": "profile-bound-approval-sha256-noreplace",
        "command_attempt_limit": 1,
        "partition": "userdata",
        "raw_serial_disclosed": False,
        "retry_scope": "no-automatic-or-same-claim-retry",
        "slot_layout_claim": "not-proven",
        "super_fastbootd_or_slotted_fallback": False,
    }:
        raise RevalidationError("write report safety contract mismatch")
    return result


def _validate_public_device(
    value: dict[str, Any],
    profile: dict[str, Any],
    label: str,
) -> None:
    try:
        deploy._exact(
            value,
            {
                "battery_mv", "identity_match", "is_logical_userdata",
                "max_download_size", "partition_size", "partition_type",
                "physical_mapping_evidence_override", "product",
                "slot_layout_claim", "soc_ok", "unlocked", "userspace",
            },
            label,
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    expected = profile["device"]
    logical = value["is_logical_userdata"]
    if (
        type(value["battery_mv"]) is not int
        or value["battery_mv"] < expected["minimum_battery_mv"]
        or value["identity_match"] is not True
        or logical not in {"no", "unsupported"}
        or type(value["max_download_size"]) is not int
        or value["max_download_size"] < expected["minimum_max_download_size"]
        or value["partition_size"] != expected["expected_userdata_capacity"]
        or value["partition_type"] != "f2fs"
        or value["physical_mapping_evidence_override"] is not (logical == "unsupported")
        or value["product"] != "lmi"
        or value["slot_layout_claim"] != "not-proven"
        or value["soc_ok"] != "yes"
        or value["unlocked"] != "yes"
        or value["userspace"] != "no"
    ):
        raise RevalidationError(f"{label} is not exact passed public device evidence")


def _lineage_spec_binding(
    spec: LineageSpec,
    repo_root: Path,
    label: str,
) -> dict[str, Any]:
    try:
        relative = deploy._repo_relative(spec.path, repo_root, label)
        deploy._sha(spec.sha256, f"{label} hash")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    if not relative.startswith("private/"):
        raise RevalidationError(f"{label} must remain under private/")
    if type(spec.size) is not int or spec.size <= 0 or spec.size > 64 * 1024:
        raise RevalidationError(f"{label} size is not an exact safe small size")
    return {"path": relative, "sha256": spec.sha256, "size": spec.size}


def _open_lineage_file(
    spec: LineageSpec,
    audit: deploy.Audit,
    label: str,
    held_key: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    binding = _lineage_spec_binding(spec, audit.repo_root, label)
    parent = spec.path.absolute().parent
    try:
        deploy._check_ancestors(spec.path, audit.repo_root, label)
        parent_info = parent.lstat()
    except (deploy.DeployError, OSError) as error:
        raise RevalidationError(f"cannot inspect canonical private {label} parent") from error
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or stat.S_IMODE(parent_info.st_mode) != 0o700
    ):
        raise RevalidationError(f"{label} parent must be a canonical mode-0700 directory")
    try:
        item = deploy._open_regular(
            spec.path,
            audit.repo_root,
            label,
            maximum=64 * 1024,
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    if (
        item.sha256 != spec.sha256
        or item.size != spec.size
        or stat.S_IMODE(os.fstat(item.descriptor).st_mode) != 0o600
    ):
        item.close()
        raise RevalidationError(f"{label} exact path, hash, size, or mode mismatch")
    audit.held[held_key] = item
    try:
        value = deploy._json_bytes(
            deploy._held_bytes(item, 64 * 1024, label),
            label,
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    return value, binding


def _audit_lineage(
    audit: deploy.Audit,
    write_report: dict[str, Any],
    consumed_claim: LineageSpec,
    candidate_attempt: LineageSpec,
    intent: LineageSpec,
) -> dict[str, dict[str, Any]]:
    result = write_report["result"]
    approval_sha256 = result["approval_sha256"]
    candidate_sha256 = audit.profile["artifacts"]["candidate"]["sha256"]
    identity_binding = audit.profile["identity"]["expected_nonce_scoped_serial_sha256"]
    try:
        expected_consumed = deploy._claim_consumed_path(audit, approval_sha256)
        expected_attempt = deploy._candidate_attempt_path(audit)
        deploy._require_distinct_paths(
            (
                (consumed_claim.path, "consumed claim"),
                (candidate_attempt.path, "candidate attempt"),
                (intent.path, "preattempt intent"),
                (audit.held["profile"].path, "private WSL profile"),
                (audit.held["write_report"].path, "completed WSL execute report"),
            )
        )
        deploy._require_outputs_outside_ledgers(
            audit,
            (
                (intent.path, "preattempt intent"),
                (audit.held["write_report"].path, "completed WSL execute report"),
            ),
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    if consumed_claim.path.absolute() != expected_consumed.absolute():
        raise RevalidationError("consumed claim is not at its deterministic approval ledger path")
    if candidate_attempt.path.absolute() != expected_attempt.absolute():
        raise RevalidationError("candidate attempt is not at its deterministic candidate ledger path")

    consumed, consumed_binding = _open_lineage_file(
        consumed_claim, audit, "consumed claim", "lineage:consumed_claim"
    )
    attempt, attempt_binding = _open_lineage_file(
        candidate_attempt, audit, "candidate attempt", "lineage:candidate_attempt"
    )
    intent_value, intent_binding = _open_lineage_file(
        intent, audit, "preattempt intent", "lineage:intent"
    )
    try:
        deploy._exact(
            consumed,
            {
                "approval_sha256", "consumed_at_unix", "ledger_directory",
                "retry_authorization", "schema",
            },
            "consumed claim",
        )
        deploy._exact(
            attempt,
            {
                "approval_sha256", "attempted_at_unix", "candidate_sha256",
                "identity_binding", "ledger_directory", "retry_authorization",
                "schema",
            },
            "candidate attempt",
        )
        deploy._exact(
            intent_value,
            {
                "approval_sha256", "argv_nonce_scoped_sha256", "argv_semantics",
                "artifacts", "candidate_attempt_sha256", "consumed_claim_sha256",
                "created_at_unix", "identity_binding", "max_attempts",
                "retry_authorization", "schema",
            },
            "preattempt intent",
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None

    consumed_at = consumed["consumed_at_unix"]
    attempted_at = attempt["attempted_at_unix"]
    intent_at = intent_value["created_at_unix"]
    expected_argv_semantics = [
        *audit.argv_prefix,
        "-s", "<identity-matched-device>", "flash", "userdata",
        "/proc/self/fd/<held-candidate-fd>",
    ]
    if consumed != {
        "approval_sha256": approval_sha256,
        "consumed_at_unix": consumed_at,
        "ledger_directory": audit.profile["ledgers"]["claim_consumption"],
        "retry_authorization": False,
        "schema": deploy.CONSUMED_SCHEMA,
    }:
        raise RevalidationError("consumed claim schema or approval/ledger chain mismatch")
    if attempt != {
        "approval_sha256": approval_sha256,
        "attempted_at_unix": attempted_at,
        "candidate_sha256": candidate_sha256,
        "identity_binding": identity_binding,
        "ledger_directory": audit.profile["ledgers"]["candidate_attempts"],
        "retry_authorization": False,
        "schema": CANDIDATE_ATTEMPT_SCHEMA,
    }:
        raise RevalidationError("candidate attempt schema or candidate/device chain mismatch")
    if intent_value != {
        "approval_sha256": approval_sha256,
        "argv_nonce_scoped_sha256": result["argv_nonce_scoped_sha256"],
        "argv_semantics": expected_argv_semantics,
        "artifacts": _artifact_binding(audit.profile, audit.profile_sha256),
        "candidate_attempt_sha256": candidate_attempt.sha256,
        "consumed_claim_sha256": consumed_claim.sha256,
        "created_at_unix": intent_at,
        "identity_binding": identity_binding,
        "max_attempts": 1,
        "retry_authorization": False,
        "schema": deploy.INTENT_SCHEMA,
    }:
        raise RevalidationError("preattempt intent schema or profile/runtime/mapping chain mismatch")
    if (
        result["consumed_claim_sha256"] != consumed_claim.sha256
        or result["candidate_attempt_sha256"] != candidate_attempt.sha256
        or result["intent_sha256"] != intent.sha256
    ):
        raise RevalidationError("completed report lineage hashes do not name the opened records")
    if (
        type(consumed_at) is not int
        or type(attempted_at) is not int
        or type(intent_at) is not int
        or consumed_at <= 0
        or consumed_at > attempted_at
        or attempted_at != intent_at
        or intent_at > write_report["created_at_unix"]
    ):
        raise RevalidationError("consumed/attempt/intent/completed route chronology mismatch")
    return {
        "candidate_attempt": attempt_binding,
        "consumed_claim": consumed_binding,
        "intent": intent_binding,
    }


def _static_runtime_runner(
    argv: Sequence[str],
    timeout: int,
    pass_fds: tuple[int, ...],
    environment: Mapping[str, str],
) -> deploy.CommandResult:
    """Satisfy core metadata checks without executing any extra command.

    ``deploy._validate_runtime`` still opens and hashes the exact executable,
    interpreter, and complete DT_NEEDED closure.  The postwrite device-command
    contract permits only devices/getvars, so its version/dpkg subprocess hooks
    are replaced with exact locked metadata responses here.
    """

    if (
        timeout != deploy.QUERY_TIMEOUT_SECONDS
        or pass_fds
        or dict(environment) != deploy.SAFE_ENV
    ):
        raise RevalidationError("unexpected runtime metadata invocation")
    version_argv = (
        "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "--inhibit-cache",
        "--library-path",
        "/usr/lib/x86_64-linux-gnu/android:/usr/lib/x86_64-linux-gnu",
        "/usr/lib/android-sdk/platform-tools/fastboot",
        "--version",
    )
    if tuple(argv) == version_argv:
        # Direct loader invocation makes glibc expose argv[0] as Installed-as.
        # Derive it from the exact allowed argv instead of naming the ELF again.
        version_output = (
            "fastboot version 34.0.5-debian\n"
            f"Installed as {version_argv[0]}\n"
        ).encode("ascii")
        return deploy.CommandResult(
            0,
            version_output,
            b"",
        )
    if tuple(argv) == (
        "/usr/bin/dpkg-query", "-W",
        "-f=${Package}\\t${Version}\\t${Architecture}\\n", "fastboot",
    ):
        return deploy.CommandResult(0, b"fastboot\t1:34.0.5-12build1\tamd64\n", b"")
    raise RevalidationError("postwrite runtime metadata requested an unapproved command")


def _open_profile(
    profile_path: Path,
    profile_sha256: str,
    repo_root: Path,
    contract: deploy.Contract,
    held: dict[str, deploy.HeldFile],
) -> dict[str, Any]:
    try:
        deploy._sha(profile_sha256, "profile hash")
        if not deploy._repo_relative(profile_path, repo_root, "profile").startswith("private/"):
            raise RevalidationError("profile must remain under private/")
        item = deploy._open_regular(profile_path, repo_root, "private WSL profile", maximum=64 * 1024)
        if item.sha256 != profile_sha256 or stat.S_IMODE(os.fstat(item.descriptor).st_mode) != 0o600:
            item.close()
            raise RevalidationError("private WSL profile hash, size, or mode mismatch")
        held["profile"] = item
        profile = deploy._json_bytes(deploy._held_bytes(item, 64 * 1024, "profile"), "profile")
        deploy._validate_profile(profile, contract)
        return profile
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None


def local_audit(
    profile_path: Path,
    profile_sha256: str,
    write_report_path: Path,
    write_report_sha256: str,
    write_report_size: int,
    consumed_claim_path: Path,
    consumed_claim_sha256: str,
    consumed_claim_size: int,
    candidate_attempt_path: Path,
    candidate_attempt_sha256: str,
    candidate_attempt_size: int,
    intent_path: Path,
    intent_sha256: str,
    intent_size: int,
    *,
    repo_root: Path = REPO,
    contract: deploy.Contract = deploy.PRODUCTION,
) -> Audit:
    """Open only the small postwrite contract and exact WSL write report."""

    repo_root = repo_root.absolute()
    held: dict[str, deploy.HeldFile] = {}
    runtime_held: list[deploy.HeldFile] = []
    try:
        profile = _open_profile(profile_path, profile_sha256, repo_root, contract, held)
        artifacts = profile["artifacts"]
        policy_item = deploy._open_spec(
            artifacts["deploy_policy_lock"], repo_root, "WSL deploy policy", held, "policy", maximum=64 * 1024
        )
        runtime_item = deploy._open_spec(
            artifacts["fastboot_runtime_lock"], repo_root, "WSL runtime lock", held, "runtime", maximum=64 * 1024
        )
        mapping_item = deploy._open_spec(
            artifacts["physical_mapping_evidence"], repo_root, "physical mapping", held, "mapping", maximum=64 * 1024
        )
        completed_item = deploy._open_spec(
            artifacts["completed_actions_lock"], repo_root, "completed action lock", held, "completed", maximum=64 * 1024
        )
        policy = deploy._json_bytes(deploy._held_bytes(policy_item, 64 * 1024, "policy"), "policy")
        runtime = deploy._json_bytes(deploy._held_bytes(runtime_item, 64 * 1024, "runtime"), "runtime")
        mapping = deploy._json_bytes(deploy._held_bytes(mapping_item, 64 * 1024, "mapping"), "mapping")
        completed = deploy._json_bytes(deploy._held_bytes(completed_item, 64 * 1024, "completed"), "completed")
        deploy._validate_policy(policy, contract)
        deploy._validate_mapping(mapping, contract)
        deploy._validate_completed(completed, contract, profile["artifacts"]["candidate"]["sha256"])
        if policy["bindings"]["fastboot_runtime_lock"] != {
            key: artifacts["fastboot_runtime_lock"][key] for key in ("path", "sha256", "size")
        }:
            raise RevalidationError("profile/policy runtime binding mismatch")
        if policy["bindings"]["physical_userdata_mapping"] != {
            key: artifacts["physical_mapping_evidence"][key] for key in ("path", "sha256", "size")
        }:
            raise RevalidationError("profile/policy mapping binding mismatch")
        argv_prefix, runtime_held = deploy._validate_runtime(runtime, _static_runtime_runner)
        for index, item in enumerate(runtime_held):
            held[f"system-runtime:{index}"] = item
        runtime_held = []
        try:
            deploy._sha(write_report_sha256, "write report hash")
        except deploy.DeployError as error:
            raise _raise_deploy(error) from None
        if type(write_report_size) is not int or write_report_size <= 0 or write_report_size > 128 * 1024:
            raise RevalidationError("write report size is not an exact safe small size")
        if not deploy._repo_relative(write_report_path, repo_root, "write report").startswith("private/"):
            raise RevalidationError("write report must remain under private/")
        try:
            write_parent = write_report_path.absolute().parent.lstat()
        except OSError as error:
            raise RevalidationError("cannot inspect canonical write report parent") from error
        if (
            not stat.S_ISDIR(write_parent.st_mode)
            or stat.S_ISLNK(write_parent.st_mode)
            or stat.S_IMODE(write_parent.st_mode) != 0o700
        ):
            raise RevalidationError("write report parent must be a canonical mode-0700 directory")
        write_item = deploy._open_regular(write_report_path, repo_root, "exact WSL write report", maximum=128 * 1024)
        if (
            write_item.sha256 != write_report_sha256
            or write_item.size != write_report_size
            or stat.S_IMODE(os.fstat(write_item.descriptor).st_mode) != 0o600
        ):
            write_item.close()
            raise RevalidationError("write report exact hash, size, or mode mismatch")
        held["write_report"] = write_item
        write_report = deploy._json_bytes(
            deploy._held_bytes(write_item, 128 * 1024, "write report"), "write report"
        )
        _validate_execute_report(write_report, profile, profile_sha256)
        base = deploy.Audit(
            repo_root,
            profile,
            profile_sha256,
            policy,
            mapping,
            completed,
            runtime,
            held,
            argv_prefix,
            contract,
        )
        lineage = _audit_lineage(
            base,
            write_report,
            LineageSpec(
                consumed_claim_path,
                consumed_claim_sha256,
                consumed_claim_size,
            ),
            LineageSpec(
                candidate_attempt_path,
                candidate_attempt_sha256,
                candidate_attempt_size,
            ),
            LineageSpec(intent_path, intent_sha256, intent_size),
        )
        if not deploy._recheck(base):
            raise RevalidationError("small postwrite and lineage inputs drifted during audit")
        return Audit(
            base,
            write_report,
            write_report_path.absolute(),
            write_report_sha256,
            write_report_size,
            lineage,
        )
    except BaseException:
        for item in reversed(runtime_held):
            item.close()
        for item in reversed(tuple(held.values())):
            item.close()
        raise


def _bindings(audit: Audit) -> dict[str, Any]:
    profile = audit.base.profile
    candidate = profile["artifacts"]["candidate"]
    return {
        "candidate": {
            "logical_size": candidate["logical_size"],
            "roundtrip_raw_sha256": candidate["roundtrip_raw_sha256"],
            "sha256": candidate["sha256"],
            "size": candidate["size"],
        },
        "deploy_policy_lock_sha256": profile["artifacts"]["deploy_policy_lock"]["sha256"],
        "fastboot_runtime_lock_sha256": profile["artifacts"]["fastboot_runtime_lock"]["sha256"],
        "identity_binding": profile["identity"]["expected_nonce_scoped_serial_sha256"],
        "lineage": audit.lineage,
        "mapping_sha256": profile["artifacts"]["physical_mapping_evidence"]["sha256"],
        "ledgers": dict(profile["ledgers"]),
        "profile": {"id": profile["profile_id"], "sha256": audit.base.profile_sha256},
        "write_report": {
            "path": deploy._repo_relative(
                audit.write_report_path,
                audit.base.repo_root,
                "write report binding",
            ),
            "sha256": audit.write_report_sha256,
            "size": audit.write_report_size,
        },
    }


def _strict_absence(result: deploy.CommandResult) -> None:
    if result != deploy.CommandResult(0, b"", b""):
        raise RevalidationError("arm-replug requires an exact zero-device fastboot devices result")


def _token_relative(path: Path, root: Path) -> str:
    try:
        value = deploy._repo_relative(path, root, "replug token")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    if not value.startswith("private/"):
        raise RevalidationError("replug token must remain under private/")
    return value


def arm_replug(
    audit: Audit,
    token_path: Path,
    *,
    process_runner: ProcessRunner,
    nonce_factory: NonceFactory = lambda: os.urandom(32),
    now_unix: int | None = None,
    clock: Clock = lambda: int(time.time()),
) -> tuple[str, str]:
    try:
        deploy._validate_private_output(token_path, audit.base.repo_root, "replug token")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    result = process_runner(
        (*audit.base.argv_prefix, "devices"),
        deploy.QUERY_TIMEOUT_SECONDS,
        (),
        deploy.SAFE_ENV,
    )
    _strict_absence(result)
    if not deploy._recheck(audit.base):
        raise RevalidationError("small postwrite inputs drifted during absence observation")
    now = _phase_time(now_unix, clock, "arm-replug")
    nonce_bytes = nonce_factory()
    if not isinstance(nonce_bytes, bytes) or len(nonce_bytes) != 32:
        raise RevalidationError("replug nonce source did not return exactly 32 bytes")
    token = {
        "armed_at_unix": now,
        "bindings": _bindings(audit),
        "expires_at_unix": now + REPLUG_TTL_SECONDS,
        "mode": "arm-replug",
        "host_observation_transition": {
            "absence_observed": True,
            "absence_query": "exact-zero-fastboot-devices",
            "required_next_observation": "exactly-one-full-nonce-bound-device-gate",
        },
        "replug_nonce": nonce_bytes.hex(),
        "route_status": ARM_ROUTE,
        "safety": {
            "device_state_change_attempted": False,
            "fixed_read_only_queries": list(ABSENCE_QUERY),
            "raw_serial_disclosed": False,
            "retry_authorization": False,
            "transport_identity_disclosed": False,
        },
        "schema": ARM_SCHEMA,
        "token_path": _token_relative(token_path, audit.base.repo_root),
    }
    try:
        digest = deploy._publish(token_path, token, audit.base, "replug token")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    return ARM_ROUTE, digest


def _validate_token(
    value: dict[str, Any],
    token_path: Path,
    audit: Audit,
    now_unix: int,
) -> tuple[str, int]:
    try:
        deploy._exact(
            value,
            {
                "armed_at_unix", "bindings", "expires_at_unix", "mode",
                "host_observation_transition", "replug_nonce", "route_status", "safety",
                "schema", "token_path",
            },
            "replug token",
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    if (
        value["schema"] != ARM_SCHEMA
        or value["mode"] != "arm-replug"
        or value["route_status"] != ARM_ROUTE
        or value["bindings"] != _bindings(audit)
        or value["token_path"] != _token_relative(token_path, audit.base.repo_root)
        or value["host_observation_transition"] != {
            "absence_observed": True,
            "absence_query": "exact-zero-fastboot-devices",
            "required_next_observation": "exactly-one-full-nonce-bound-device-gate",
        }
        or value["safety"] != {
            "device_state_change_attempted": False,
            "fixed_read_only_queries": list(ABSENCE_QUERY),
            "raw_serial_disclosed": False,
            "retry_authorization": False,
            "transport_identity_disclosed": False,
        }
    ):
        raise RevalidationError("replug token contract or exact input binding mismatch")
    armed = value["armed_at_unix"]
    expires = value["expires_at_unix"]
    if (
        type(armed) is not int
        or type(expires) is not int
        or expires - armed != REPLUG_TTL_SECONDS
        or armed < audit.write_report["created_at_unix"]
        or now_unix < armed
        or now_unix > expires
    ):
        raise RevalidationError("replug token is stale, pre-write, or malformed")
    nonce = value["replug_nonce"]
    if not isinstance(nonce, str) or re.fullmatch(r"[0-9a-f]{64}", nonce) is None:
        raise RevalidationError("replug token nonce is invalid")
    return nonce, expires


def _load_token(
    token_path: Path,
    token_sha256: str,
    audit: Audit,
    now_unix: int,
) -> tuple[str, int, deploy.HeldFile]:
    try:
        deploy._sha(token_sha256, "replug token hash")
        item = deploy._open_regular(token_path, audit.base.repo_root, "replug token", maximum=64 * 1024)
        if item.sha256 != token_sha256 or stat.S_IMODE(os.fstat(item.descriptor).st_mode) != 0o600:
            item.close()
            raise RevalidationError("replug token exact hash or mode mismatch")
        value = deploy._json_bytes(deploy._held_bytes(item, 64 * 1024, "replug token"), "replug token")
        nonce, expires = _validate_token(value, token_path, audit, now_unix)
        return nonce, expires, item
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None


def _consumed_path(token_path: Path) -> Path:
    return token_path.with_name(token_path.name + ".consumed.json")


def _consume_token(
    audit: Audit,
    token_path: Path,
    token_sha256: str,
    nonce: str,
    now_unix: int,
) -> tuple[Path, str]:
    path = _consumed_path(token_path)
    value = {
        "consumed_at_unix": now_unix,
        "replug_nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
        "retry_authorization": False,
        "schema": CONSUMED_SCHEMA,
        "token_sha256": token_sha256,
    }
    try:
        return path, deploy._publish(path, value, audit.base, "consumed replug token")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None


def revalidate(
    audit: Audit,
    token_path: Path,
    token_sha256: str,
    report_path: Path,
    *,
    process_runner: ProcessRunner,
    now_unix: int | None = None,
    clock: Clock = lambda: int(time.time()),
) -> tuple[str, str]:
    consumed_path = _consumed_path(token_path)
    try:
        deploy._require_distinct_paths(
            (
                (token_path, "replug token"),
                (consumed_path, "consumed replug token"),
                (report_path, "postwrite report"),
            )
        )
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    try:
        deploy._validate_private_output(report_path, audit.base.repo_root, "postwrite report")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    initial_now = _phase_time(now_unix, clock, "initial revalidation")
    nonce, expires, token_item = _load_token(
        token_path, token_sha256, audit, initial_now
    )
    audit.base.held["replug_token"] = token_item
    if not deploy._recheck(audit.base):
        raise RevalidationError("small postwrite inputs drifted before token consumption")
    consumed_path, consumed_sha256 = _consume_token(
        audit, token_path, token_sha256, nonce, initial_now
    )
    device_public: dict[str, Any] | None = None
    passed = False
    reason: str | None = None
    try:
        device = deploy.query_device(audit.base, process_runner)
        if device.identity_binding != audit.base.profile["identity"]["expected_nonce_scoped_serial_sha256"]:
            raise deploy.DeployError("nonce-scoped replug identity mismatch")
        device_public = device.public
        passed = True
    except Exception:
        reason = "DEVICE_REVALIDATION_FAILED"
    if not deploy._recheck(audit.base):
        passed = False
        reason = "SMALL_INPUT_RECHECK_FAILED"
    final_now = _phase_time(now_unix, clock, "final revalidation")
    if final_now < initial_now:
        passed = False
        reason = "CLOCK_REGRESSED_DURING_REVALIDATION"
    elif final_now > expires:
        passed = False
        reason = "REPLUG_TOKEN_EXPIRED_DURING_REVALIDATION"
    route = PASS_ROUTE if passed else FAIL_ROUTE
    report = {
        "bindings": {
            **_bindings(audit),
            "consumed_token_sha256": consumed_sha256,
            "replug_nonce_sha256": hashlib.sha256(nonce.encode("ascii")).hexdigest(),
            "token_sha256": token_sha256,
        },
        "created_at_unix": final_now,
        "device": device_public,
        "mode": "revalidate",
        "result": {
            "host_observed_zero_then_one_fastboot_device": passed,
            "reason": reason,
            "token_consumed": True,
        },
        "route_status": route,
        "safety": {
            "candidate_or_other_large_artifact_opened": False,
            "consumed_token_path_semantics": "exact-token-path-plus-.consumed.json",
            "device_state_change_attempted": False,
            "fixed_read_only_queries": list(FULL_QUERY_CONTRACT),
            "raw_serial_disclosed": False,
            "retry_authorization": False,
            "transport_identity_disclosed": False,
        },
        "schema": REPORT_SCHEMA,
    }
    try:
        digest = deploy._publish(report_path, report, audit.base, "postwrite report")
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    # The consumed path is deliberately not serialized into the report; only
    # its exact digest and deterministic sibling semantics are retained.
    del consumed_path
    return route, digest


AuditFactory = Callable[..., Audit]


def operate(
    mode: str,
    profile_path: Path,
    profile_sha256: str,
    write_report_path: Path,
    write_report_sha256: str,
    write_report_size: int,
    consumed_claim_path: Path,
    consumed_claim_sha256: str,
    consumed_claim_size: int,
    candidate_attempt_path: Path,
    candidate_attempt_sha256: str,
    candidate_attempt_size: int,
    intent_path: Path,
    intent_sha256: str,
    intent_size: int,
    output_path: Path,
    *,
    token_path: Path | None = None,
    token_sha256: str | None = None,
    repo_root: Path = REPO,
    contract: deploy.Contract = deploy.PRODUCTION,
    process_runner: ProcessRunner = deploy.run_bounded,
    audit_factory: AuditFactory = local_audit,
    nonce_factory: NonceFactory = lambda: os.urandom(32),
    now_unix: int | None = None,
    clock: Clock = lambda: int(time.time()),
) -> tuple[str, str]:
    paths: list[tuple[Path, str]] = [
        (profile_path, "private WSL profile"),
        (write_report_path, "exact WSL write report"),
        (consumed_claim_path, "consumed claim"),
        (candidate_attempt_path, "candidate attempt"),
        (intent_path, "preattempt intent"),
        (output_path, "postwrite output"),
    ]
    if token_path is not None:
        paths.extend(
            (
                (token_path, "replug token"),
                (_consumed_path(token_path), "consumed replug token"),
            )
        )
    try:
        deploy._require_distinct_paths(paths)
    except deploy.DeployError as error:
        raise _raise_deploy(error) from None
    audit = audit_factory(
        profile_path,
        profile_sha256,
        write_report_path,
        write_report_sha256,
        write_report_size,
        consumed_claim_path,
        consumed_claim_sha256,
        consumed_claim_size,
        candidate_attempt_path,
        candidate_attempt_sha256,
        candidate_attempt_size,
        intent_path,
        intent_sha256,
        intent_size,
        repo_root=repo_root,
        contract=contract,
    )
    try:
        if mode == "arm-replug":
            if token_path is not None or token_sha256 is not None:
                raise RevalidationError("arm-replug does not accept an existing token")
            return arm_replug(
                audit,
                output_path,
                process_runner=process_runner,
                nonce_factory=nonce_factory,
                now_unix=now_unix,
                clock=clock,
            )
        if mode == "revalidate":
            if token_path is None or token_sha256 is None:
                raise RevalidationError("revalidate requires the exact armed token path and hash")
            return revalidate(
                audit,
                token_path,
                token_sha256,
                output_path,
                process_runner=process_runner,
                now_unix=now_unix,
                clock=clock,
            )
        raise RevalidationError("unsupported postwrite mode")
    finally:
        audit.close()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("arm-replug", "revalidate"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--write-report", required=True, type=Path)
    parser.add_argument("--write-report-sha256", required=True)
    parser.add_argument("--write-report-size", required=True, type=int)
    parser.add_argument("--consumed-claim", required=True, type=Path)
    parser.add_argument("--consumed-claim-sha256", required=True)
    parser.add_argument("--consumed-claim-size", required=True, type=int)
    parser.add_argument("--candidate-attempt", required=True, type=Path)
    parser.add_argument("--candidate-attempt-sha256", required=True)
    parser.add_argument("--candidate-attempt-size", required=True, type=int)
    parser.add_argument("--intent", required=True, type=Path)
    parser.add_argument("--intent-sha256", required=True)
    parser.add_argument("--intent-size", required=True, type=int)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--token", type=Path)
    parser.add_argument("--token-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        route, digest = operate(
            args.mode,
            args.profile,
            args.profile_sha256,
            args.write_report,
            args.write_report_sha256,
            args.write_report_size,
            args.consumed_claim,
            args.consumed_claim_sha256,
            args.consumed_claim_size,
            args.candidate_attempt,
            args.candidate_attempt_sha256,
            args.candidate_attempt_size,
            args.intent,
            args.intent_sha256,
            args.intent_size,
            args.output,
            token_path=args.token,
            token_sha256=args.token_sha256,
        )
    except RevalidationError as error:
        print(f"refused: {error}", file=os.sys.stderr)
        return 2
    print(f"route_status={route}")
    print(f"output_sha256={digest}")
    return 0 if route in {ARM_ROUTE, PASS_ROUTE} else 2


if __name__ == "__main__":
    raise SystemExit(main())
