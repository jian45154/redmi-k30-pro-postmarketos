#!/usr/bin/env python3
"""Bringup governance engine (schema v4, lmi adaptation).

Layer contract (L3):
- owns: record schema, artifact hashing, policy scope resolution, receipt
  issue-and-claim, the append-only claims ledger, and archival;
- never touches the device. Device identity, battery, and fastboot argument
  gates belong to the executor that runs the returned exact_command.

Tier model (adapted for lmi, where the rootfs lives inside userdata):
- read_only:  observation only; no receipt, no ledger entry.
- volatile:   bare `fastboot reboot`; worst case is a power cycle.
- ram_rw:     `fastboot boot` / runtime handoff. The command itself writes no
  partition, but the booted OS mounts userdata read-write, so a claim requires
  a persistent-media acknowledgment naming how userdata can be rebuilt.
- persistent: partition writes. Requires a hash-bound authorized_profiles
  entry in policy.json (per-profile owner authorization; never standing),
  a distinct-hash rollback artifact, and a repeat guard on re-writes.

Every structural check lives in exactly one function here; claim re-verifies
artifact bytes once, inside the ledger lock.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

SCHEMA_VERSION = 4

# The only permitted duplicate of config/governance/constants.json
# forbidden_command_words. load_constants() asserts equality so editing the
# data file can never widen what the engine accepts.
FORBIDDEN_COMMAND_WORDS = frozenset(
    {
        "erase",
        "format",
        "repartition",
        "set_active",
        "--force",
        "--disable-verity",
        "--disable-verification",
        "oem lock",
        "flashing lock",
    }
)

TIERS = ("read_only", "volatile", "ram_rw", "persistent")
OUTCOMES = ("success", "failure", "timeout", "unknown")
EXPERIMENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
ROUTE_STATUS_RE = re.compile(r"^route_status=\S+", re.MULTILINE)

# operation -> (tier, fixed target or None meaning constants.partition_targets,
#               artifact required?)
OPERATIONS = {
    "device_reboot": ("volatile", "device", False),
    "ram_boot": ("ram_rw", "ram", True),
    "runtime_handoff": ("ram_rw", "initramfs", False),
    "partition_write": ("persistent", None, True),
}

RECORD_FIELDS_READ_ONLY = frozenset(
    {
        "schema_version",
        "status",
        "experiment_id",
        "tier",
        "hypothesis",
        "discriminator",
        "next_if_positive",
        "next_if_negative",
        "timebox_seconds",
        "lanes",
        "observations",
        "result",
    }
)
RECORD_FIELDS_ACTION = frozenset(
    RECORD_FIELDS_READ_ONLY | {"action", "gates", "repeat_guard", "receipt"}
)
ACTION_FIELDS = frozenset(
    {
        "operation",
        "target",
        "profile",
        "profile_sha256",
        "artifact",
        "artifact_sha256",
        "artifact_size",
        "exact_command",
    }
)
GATES_FIELDS = frozenset({"identity", "persistent_media", "rollback"})
POLICY_FIELDS = frozenset(
    {
        "schema_version",
        "enabled",
        "revision",
        "authorized_by",
        "authorization_note",
        "standing_scopes",
        "authorized_profiles",
        "manual_only",
    }
)
SCOPE_FIELDS = frozenset({"tier", "operation", "target"})
AUTHORIZED_PROFILE_FIELDS = frozenset(
    {"profile_path", "profile_sha256", "targets", "authorized_by", "note"}
)
REPEAT_GUARD_FIELDS = frozenset(
    {
        "prior_experiment_id",
        "changed_discriminator",
        "evidence_report",
        "evidence_report_sha256",
    }
)
ROLLBACK_FIELDS = frozenset({"target", "path", "sha256", "size"})


class Refusal(Exception):
    """Fail-closed governance refusal; message explains the single reason."""


class Paths:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.constants = root / "config/governance/constants.json"
        self.policy = root / "config/governance/policy.json"
        self.active = root / "notes/bringup-active.json"
        self.claims_dir = root / "notes/bringup-claims"
        self.ledger = self.claims_dir / "claims.log"
        self.lock = self.claims_dir / ".lock"
        self.completed_dir = root / "notes/bringup-completed"
        self.logs_dir = root / "logs"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular_file(path: Path, label: str) -> bytes:
    if path.is_symlink():
        raise Refusal(f"{label} is a symlink: {path}")
    if not path.is_file():
        raise Refusal(f"{label} is not a regular file: {path}")
    return path.read_bytes()


def load_json(path: Path, label: str) -> dict:
    data = read_regular_file(path, label)
    try:
        loaded = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"{label} is not valid JSON: {path}: {exc}") from exc
    if not isinstance(loaded, dict):
        raise Refusal(f"{label} must be a JSON object: {path}")
    return loaded


def atomic_write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=False, ensure_ascii=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _require_fields(obj: dict, fields: frozenset, label: str) -> None:
    actual = frozenset(obj)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        raise Refusal(f"{label} fields mismatch: missing={missing} unexpected={extra}")


def load_constants(paths: Paths) -> dict:
    constants = load_json(paths.constants, "constants")
    _require_fields(
        constants,
        frozenset(
            {
                "schema_version",
                "expected_product",
                "battery_floor_mv",
                "receipt_ttl_seconds",
                "partition_targets",
                "volatile_operations",
                "ram_rw_operations",
                "persistent_operations",
                "forbidden_command_words",
            }
        ),
        "constants",
    )
    if constants["schema_version"] != SCHEMA_VERSION:
        raise Refusal("constants schema_version mismatch")
    declared = constants["forbidden_command_words"]
    if not isinstance(declared, list) or frozenset(declared) != FORBIDDEN_COMMAND_WORDS:
        raise Refusal(
            "constants forbidden_command_words diverge from the engine's hardcoded "
            "copy; the data file cannot change the forbidden set"
        )
    if not isinstance(constants["partition_targets"], list) or not all(
        isinstance(t, str) and t for t in constants["partition_targets"]
    ):
        raise Refusal("constants partition_targets must be a list of names")
    if not isinstance(constants["battery_floor_mv"], int) or constants["battery_floor_mv"] <= 0:
        raise Refusal("constants battery_floor_mv must be a positive integer")
    if (
        not isinstance(constants["receipt_ttl_seconds"], int)
        or constants["receipt_ttl_seconds"] <= 0
    ):
        raise Refusal("constants receipt_ttl_seconds must be a positive integer")
    for key, expected in (
        ("volatile_operations", {op for op, (tier, _, _) in OPERATIONS.items() if tier == "volatile"}),
        ("ram_rw_operations", {op for op, (tier, _, _) in OPERATIONS.items() if tier == "ram_rw"}),
        ("persistent_operations", {op for op, (tier, _, _) in OPERATIONS.items() if tier == "persistent"}),
    ):
        if not isinstance(constants[key], list) or frozenset(constants[key]) != frozenset(expected):
            raise Refusal(f"constants {key} diverge from the engine's operation table")
    return constants


def load_policy(paths: Paths, constants: dict) -> tuple[dict, str]:
    raw = read_regular_file(paths.policy, "policy")
    policy_sha256 = sha256_bytes(raw)
    try:
        policy = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Refusal(f"policy is not valid JSON: {exc}") from exc
    if not isinstance(policy, dict):
        raise Refusal("policy must be a JSON object")
    _require_fields(policy, POLICY_FIELDS, "policy")
    if policy["schema_version"] != SCHEMA_VERSION:
        raise Refusal("policy schema_version mismatch")
    if not isinstance(policy["enabled"], bool):
        raise Refusal("policy enabled must be a boolean")
    for key in ("revision", "authorized_by", "authorization_note"):
        if not isinstance(policy[key], str) or not policy[key].strip():
            raise Refusal(f"policy {key} must be a non-empty string")
    if not isinstance(policy["standing_scopes"], list):
        raise Refusal("policy standing_scopes must be a list")
    for scope in policy["standing_scopes"]:
        if not isinstance(scope, dict):
            raise Refusal("policy scope entries must be objects")
        _require_fields(scope, SCOPE_FIELDS, "policy scope")
        operation = scope["operation"]
        if operation not in OPERATIONS:
            raise Refusal(f"policy scope names unknown operation: {operation}")
        tier, fixed_target, _ = OPERATIONS[operation]
        if tier == "persistent":
            raise Refusal(
                "policy standing_scopes may not contain persistent operations; "
                "partition writes require authorized_profiles entries"
            )
        if scope["tier"] != tier:
            raise Refusal(f"policy scope tier mismatch for {operation}")
        if scope["target"] != fixed_target:
            raise Refusal(f"policy scope target mismatch for {operation}")
    if not isinstance(policy["authorized_profiles"], list):
        raise Refusal("policy authorized_profiles must be a list")
    for entry in policy["authorized_profiles"]:
        if not isinstance(entry, dict):
            raise Refusal("policy authorized_profiles entries must be objects")
        _require_fields(entry, AUTHORIZED_PROFILE_FIELDS, "policy authorized profile")
        if not isinstance(entry["profile_path"], str) or not entry["profile_path"]:
            raise Refusal("authorized profile profile_path must be a non-empty string")
        if not _is_sha256(entry["profile_sha256"]):
            raise Refusal("authorized profile profile_sha256 must be a SHA-256 hex digest")
        targets = entry["targets"]
        if (
            not isinstance(targets, list)
            or not targets
            or not frozenset(targets) <= frozenset(constants["partition_targets"])
        ):
            raise Refusal("authorized profile targets must be a subset of partition_targets")
        for key in ("authorized_by", "note"):
            if not isinstance(entry[key], str) or not entry[key].strip():
                raise Refusal(f"authorized profile {key} must be a non-empty string")
    if policy["manual_only"] != ["bootloader-relock"]:
        raise Refusal("policy manual_only must remain [\"bootloader-relock\"]")
    return policy, policy_sha256


def _is_sha256(value) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def build_exact_command(operation: str, target, artifact) -> list:
    if operation == "device_reboot":
        return ["fastboot", "reboot"]
    if operation == "ram_boot":
        return ["fastboot", "boot", str(artifact)]
    if operation == "runtime_handoff":
        return ["telnet", "172.16.42.1", "23"]
    if operation == "partition_write":
        return ["fastboot", "flash", str(target), str(artifact)]
    raise Refusal(f"unknown operation: {operation}")


def _check_forbidden(exact_command: list) -> None:
    joined = " ".join(exact_command)
    for word in sorted(FORBIDDEN_COMMAND_WORDS):
        if word in joined:
            raise Refusal(f"exact_command contains forbidden word: {word}")


def validate_record(record: dict, constants: dict) -> None:
    """The single structural validator; every subcommand routes through it."""
    if not isinstance(record, dict):
        raise Refusal("record must be a JSON object")
    tier = record.get("tier")
    if tier not in TIERS:
        raise Refusal(f"record tier must be one of {list(TIERS)}")
    expected_fields = (
        RECORD_FIELDS_READ_ONLY if tier == "read_only" else RECORD_FIELDS_ACTION
    )
    _require_fields(record, expected_fields, "record")
    if record["schema_version"] != SCHEMA_VERSION:
        raise Refusal("record schema_version mismatch")
    if record["status"] not in ("ready", "claimed", "completed"):
        raise Refusal("record status must be ready, claimed, or completed")
    if not isinstance(record["experiment_id"], str) or not EXPERIMENT_ID_RE.fullmatch(
        record["experiment_id"]
    ):
        raise Refusal("record experiment_id must match ^[a-z0-9][a-z0-9-]{2,63}$")
    for key in ("hypothesis", "discriminator", "next_if_positive", "next_if_negative"):
        if not isinstance(record[key], str) or not record[key].strip():
            raise Refusal(f"record {key} must be a non-empty string")
    if record["next_if_positive"].strip() == record["next_if_negative"].strip():
        raise Refusal("next_if_positive and next_if_negative must differ")
    if not isinstance(record["timebox_seconds"], int) or record["timebox_seconds"] <= 0:
        raise Refusal("record timebox_seconds must be a positive integer")
    if not isinstance(record["lanes"], list) or not isinstance(record["observations"], list):
        raise Refusal("record lanes and observations must be lists")
    if tier == "read_only":
        return

    action = record["action"]
    if not isinstance(action, dict):
        raise Refusal("record action must be an object")
    _require_fields(action, ACTION_FIELDS, "record action")
    operation = action["operation"]
    if operation not in OPERATIONS:
        raise Refusal(f"record action operation unknown: {operation}")
    op_tier, fixed_target, needs_artifact = OPERATIONS[operation]
    if op_tier != tier:
        raise Refusal(f"record tier {tier} does not match operation tier {op_tier}")
    target = action["target"]
    if fixed_target is None:
        if target not in constants["partition_targets"]:
            raise Refusal(f"record action target must be one of {constants['partition_targets']}")
    elif target != fixed_target:
        raise Refusal(f"record action target must be {fixed_target}")
    if needs_artifact:
        if not isinstance(action["artifact"], str) or not action["artifact"]:
            raise Refusal("record action artifact path required for this operation")
        if not _is_sha256(action["artifact_sha256"]):
            raise Refusal("record action artifact_sha256 must be a SHA-256 hex digest")
        if not isinstance(action["artifact_size"], int) or action["artifact_size"] <= 0:
            raise Refusal("record action artifact_size must be a positive integer")
    else:
        if action["artifact"] is not None or action["artifact_sha256"] is not None:
            raise Refusal("record action artifact must be null for this operation")
        if action["artifact_size"] is not None:
            raise Refusal("record action artifact_size must be null for this operation")
    if operation == "partition_write":
        if not isinstance(action["profile"], str) or not action["profile"]:
            raise Refusal("partition_write requires a profile path")
        if not _is_sha256(action["profile_sha256"]):
            raise Refusal("partition_write requires profile_sha256")
    expected_command = build_exact_command(operation, target, action["artifact"])
    if action["exact_command"] != expected_command:
        raise Refusal(
            f"record exact_command must equal the engine builder output {expected_command}"
        )
    _check_forbidden(action["exact_command"])

    gates = record["gates"]
    if not isinstance(gates, dict):
        raise Refusal("record gates must be an object")
    _require_fields(gates, GATES_FIELDS, "record gates")
    identity = gates["identity"]
    if not isinstance(identity, dict) or identity.get("expected_product") != constants[
        "expected_product"
    ]:
        raise Refusal(
            f"record gates.identity.expected_product must be {constants['expected_product']}"
        )
    if tier == "ram_rw":
        media = gates["persistent_media"]
        if not isinstance(media, dict):
            raise Refusal(
                "ram_rw records must acknowledge persistent media exposure "
                "(the booted OS mounts userdata read-write)"
            )
        _require_fields(
            media, frozenset({"acknowledged", "rebuild_reference"}), "persistent_media"
        )
        if media["acknowledged"] is not True:
            raise Refusal("ram_rw persistent_media.acknowledged must be true")
        if not isinstance(media["rebuild_reference"], str) or not media[
            "rebuild_reference"
        ].strip():
            raise Refusal("ram_rw persistent_media.rebuild_reference must name how userdata is rebuilt")
    else:
        if gates["persistent_media"] is not None:
            raise Refusal("persistent_media gate only applies to ram_rw records")
    if tier == "persistent":
        rollback = gates["rollback"]
        if not isinstance(rollback, dict):
            raise Refusal("persistent records require a rollback gate")
        _require_fields(rollback, ROLLBACK_FIELDS, "rollback gate")
        if rollback["target"] != target:
            raise Refusal("rollback target must match the action target")
        if not isinstance(rollback["path"], str) or not rollback["path"]:
            raise Refusal("rollback path must be a non-empty string")
        if not _is_sha256(rollback["sha256"]):
            raise Refusal("rollback sha256 must be a SHA-256 hex digest")
        if rollback["sha256"] == action["artifact_sha256"]:
            raise Refusal("rollback artifact hash must differ from the deploy artifact hash")
        if not isinstance(rollback["size"], int) or rollback["size"] <= 0:
            raise Refusal("rollback size must be a positive integer")
    else:
        if gates["rollback"] is not None:
            raise Refusal("rollback gate only applies to persistent records")

    repeat_guard = record["repeat_guard"]
    if repeat_guard is not None:
        if tier != "persistent":
            raise Refusal("repeat_guard only applies to persistent records")
        _require_fields(repeat_guard, REPEAT_GUARD_FIELDS, "repeat_guard")
        if not EXPERIMENT_ID_RE.fullmatch(str(repeat_guard["prior_experiment_id"])):
            raise Refusal("repeat_guard prior_experiment_id must be a valid experiment id")
        if (
            not isinstance(repeat_guard["changed_discriminator"], str)
            or not repeat_guard["changed_discriminator"].strip()
        ):
            raise Refusal("repeat_guard changed_discriminator must be a non-empty string")
        if not isinstance(repeat_guard["evidence_report"], str) or not repeat_guard[
            "evidence_report"
        ]:
            raise Refusal("repeat_guard evidence_report must be a path")
        if not _is_sha256(repeat_guard["evidence_report_sha256"]):
            raise Refusal("repeat_guard evidence_report_sha256 must be a SHA-256 hex digest")

    receipt = record["receipt"]
    if record["status"] == "ready" and receipt is not None:
        raise Refusal("ready records must not carry a receipt")
    if record["status"] in ("claimed", "completed") and not isinstance(receipt, dict):
        raise Refusal("claimed records must carry the consumed receipt")


def action_digest(record: dict) -> str:
    action = record["action"]
    gates = record["gates"]
    return sha256_bytes(
        canonical(
            {
                "tier": record["tier"],
                "operation": action["operation"],
                "target": action["target"],
                "artifact_sha256": action["artifact_sha256"],
                "exact_command": action["exact_command"],
                "identity": gates["identity"],
                "rollback": gates["rollback"],
            }
        ).encode("ascii")
    )


def load_active(paths: Paths, constants: dict) -> dict:
    if not paths.active.exists():
        raise Refusal(f"no active experiment record: {paths.active}")
    record = load_json(paths.active, "active record")
    validate_record(record, constants)
    return record


def _verify_pinned_file(root: Path, rel_path: str, expected_sha256: str, expected_size, label: str) -> None:
    path = (root / rel_path).resolve()
    data = read_regular_file(path, label)
    if expected_size is not None and len(data) != expected_size:
        raise Refusal(f"{label} size mismatch: {rel_path}")
    if sha256_bytes(data) != expected_sha256:
        raise Refusal(f"{label} hash mismatch: {rel_path}")


def _ledger_lines(paths: Paths) -> list:
    if not paths.ledger.exists():
        return []
    lines = []
    for line in paths.ledger.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        entry = {}
        for token in line.split():
            if "=" in token:
                key, _, value = token.partition("=")
                entry[key] = value
        lines.append(entry)
    return lines


def _check_repeat_guard(paths: Paths, record: dict) -> None:
    action = record["action"]
    prior = [
        entry
        for entry in _ledger_lines(paths)
        if entry.get("operation") == action["operation"]
        and entry.get("target") == action["target"]
        and entry.get("artifact_sha256") == action["artifact_sha256"]
    ]
    if not prior:
        return
    guard = record["repeat_guard"]
    if guard is None:
        raise Refusal(
            "this physical action was already claimed; a repeat requires a "
            "repeat_guard with a prior experiment, a changed discriminator, "
            "and new evidence"
        )
    archived = paths.completed_dir / f"{guard['prior_experiment_id']}.json"
    if not archived.is_file():
        raise Refusal(
            f"repeat_guard prior experiment is not archived: {archived}"
        )
    _verify_pinned_file(
        paths.root,
        guard["evidence_report"],
        guard["evidence_report_sha256"],
        None,
        "repeat_guard evidence report",
    )


def _resolve_scope(policy: dict, record: dict, paths: Paths) -> None:
    tier = record["tier"]
    action = record["action"]
    if not policy["enabled"]:
        raise Refusal("policy is disabled; no standing authorization exists")
    if tier in ("volatile", "ram_rw"):
        for scope in policy["standing_scopes"]:
            if (
                scope["tier"] == tier
                and scope["operation"] == action["operation"]
                and scope["target"] == action["target"]
            ):
                return
        raise Refusal(
            f"no standing scope covers {tier}/{action['operation']}/{action['target']}"
        )
    if tier == "persistent":
        for entry in policy["authorized_profiles"]:
            if entry["profile_path"] != action["profile"]:
                continue
            if entry["profile_sha256"] != action["profile_sha256"]:
                raise Refusal(
                    "authorized profile hash does not match the record's profile pin"
                )
            if action["target"] not in entry["targets"]:
                raise Refusal(
                    f"authorized profile does not cover target {action['target']}"
                )
            _verify_pinned_file(
                paths.root, action["profile"], entry["profile_sha256"], None, "profile"
            )
            return
        raise Refusal(
            "persistent actions require a matching authorized_profiles entry in "
            "policy.json (per-profile owner authorization); none matches this profile"
        )
    raise Refusal(f"tier {tier} does not take claims")


def _claim_checks(paths: Paths, constants: dict, policy: dict, record: dict) -> None:
    if record["tier"] == "read_only":
        raise Refusal("read_only records are not claimed; record results directly")
    if record["status"] != "ready":
        raise Refusal(
            f"record status is {record['status']}; a second execution requires a "
            "new experiment and a new receipt"
        )
    _resolve_scope(policy, record, paths)
    action = record["action"]
    if action["artifact"] is not None:
        _verify_pinned_file(
            paths.root,
            action["artifact"],
            action["artifact_sha256"],
            action["artifact_size"],
            "artifact",
        )
    if record["tier"] == "persistent":
        rollback = record["gates"]["rollback"]
        _verify_pinned_file(
            paths.root, rollback["path"], rollback["sha256"], rollback["size"], "rollback artifact"
        )
        _check_repeat_guard(paths, record)


def cmd_claim(paths: Paths, dry_run: bool) -> int:
    constants = load_constants(paths)
    policy, policy_sha256 = load_policy(paths, constants)
    paths.claims_dir.mkdir(parents=True, exist_ok=True)
    with open(paths.lock, "a+", encoding="utf-8") as lock_handle:
        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
        record = load_active(paths, constants)
        _claim_checks(paths, constants, policy, record)
        digest = action_digest(record)
        if dry_run:
            print("approve: ok (dry-run; no receipt issued, no state changed)")
            print(f"action_digest={digest}")
            return 0
        now = _now()
        receipt = {
            "issued_at": _iso(now),
            "expires_at": _iso(now + timedelta(seconds=constants["receipt_ttl_seconds"])),
            "consumed_at": _iso(now),
            "authority": "standing-policy",
            "policy_revision": policy["revision"],
            "policy_sha256": policy_sha256,
            "action_digest": digest,
        }
        action = record["action"]
        ledger_line = " ".join(
            [
                f"ts={receipt['consumed_at']}",
                f"experiment_id={record['experiment_id']}",
                f"tier={record['tier']}",
                f"operation={action['operation']}",
                f"target={action['target']}",
                f"artifact_sha256={action['artifact_sha256']}",
                f"action_digest={digest}",
                f"authority={receipt['authority']}",
                f"policy_revision={receipt['policy_revision']}",
                f"policy_sha256={receipt['policy_sha256']}",
            ]
        )
        with open(paths.ledger, "a", encoding="utf-8") as ledger_handle:
            ledger_handle.write(ledger_line + "\n")
            ledger_handle.flush()
            os.fsync(ledger_handle.fileno())
        record["status"] = "claimed"
        record["receipt"] = receipt
        atomic_write_json(paths.active, record)
    print("claim: consumed (issue-and-claim atomic)")
    print(f"action_digest={digest}")
    print("exact_command=" + " ".join(action["exact_command"]))
    return 0


def cmd_new(paths: Paths, args: argparse.Namespace) -> int:
    constants = load_constants(paths)
    load_policy(paths, constants)
    if paths.active.exists():
        raise Refusal(
            f"an active experiment already exists: {paths.active}; "
            "complete and archive it first (at most one active experiment)"
        )
    base = {
        "schema_version": SCHEMA_VERSION,
        "status": "ready",
        "experiment_id": args.experiment_id,
        "tier": None,
        "hypothesis": args.hypothesis,
        "discriminator": args.discriminator,
        "next_if_positive": args.next_if_positive,
        "next_if_negative": args.next_if_negative,
        "timebox_seconds": args.timebox_seconds,
        "lanes": [],
        "observations": [],
        "result": None,
    }
    if args.operation is None:
        base["tier"] = "read_only"
        record = base
    else:
        tier, fixed_target, needs_artifact = OPERATIONS[args.operation]
        base["tier"] = tier
        target = fixed_target if fixed_target is not None else args.target
        if target is None:
            raise Refusal("partition_write requires --target")
        artifact_rel = None
        artifact_sha = None
        artifact_size = None
        profile_rel = None
        profile_sha = None
        rollback = None
        if args.operation == "partition_write":
            if args.profile is None:
                raise Refusal("partition_write requires --profile")
            profile_rel = args.profile
            profile_bytes = read_regular_file((paths.root / profile_rel).resolve(), "profile")
            profile_sha = sha256_bytes(profile_bytes)
            profile = json.loads(profile_bytes.decode("utf-8"))
            entry = profile.get(target)
            if not isinstance(entry, dict):
                raise Refusal(f"profile has no entry for target {target}")
            artifact_rel = entry["path"]
            artifact_sha = entry["sha256"]
            artifact_size = entry["size"]
            profile_rollback = profile.get("rollback")
            if not isinstance(profile_rollback, dict):
                raise Refusal("profile has no rollback entry")
            rollback = {
                "target": profile_rollback["target"],
                "path": profile_rollback["path"],
                "sha256": profile_rollback["sha256"],
                "size": profile_rollback["size"],
            }
        elif needs_artifact:
            if args.artifact is None:
                raise Refusal(f"{args.operation} requires --artifact")
            artifact_rel = args.artifact
            artifact_bytes = read_regular_file((paths.root / artifact_rel).resolve(), "artifact")
            artifact_sha = sha256_bytes(artifact_bytes)
            artifact_size = len(artifact_bytes)
        persistent_media = None
        if tier == "ram_rw":
            if not args.acknowledge_persistent_media or not args.rebuild_reference:
                raise Refusal(
                    "ram_rw operations require --acknowledge-persistent-media and "
                    "--rebuild-reference: the booted OS mounts userdata read-write"
                )
            persistent_media = {
                "acknowledged": True,
                "rebuild_reference": args.rebuild_reference,
            }
        record = dict(base)
        record["action"] = {
            "operation": args.operation,
            "target": target,
            "profile": profile_rel,
            "profile_sha256": profile_sha,
            "artifact": artifact_rel,
            "artifact_sha256": artifact_sha,
            "artifact_size": artifact_size,
            "exact_command": build_exact_command(args.operation, target, artifact_rel),
        }
        record["gates"] = {
            "identity": {"expected_product": constants["expected_product"]},
            "persistent_media": persistent_media,
            "rollback": rollback,
        }
        record["repeat_guard"] = None
        if args.repeat_prior_experiment:
            record["repeat_guard"] = {
                "prior_experiment_id": args.repeat_prior_experiment,
                "changed_discriminator": args.repeat_changed_discriminator or "",
                "evidence_report": args.repeat_evidence_report or "",
                "evidence_report_sha256": sha256_bytes(
                    read_regular_file(
                        (paths.root / (args.repeat_evidence_report or "")).resolve(),
                        "repeat evidence report",
                    )
                )
                if args.repeat_evidence_report
                else "",
            }
        record["receipt"] = None
    validate_record(record, constants)
    atomic_write_json(paths.active, record)
    print(f"new: {paths.active}")
    print(f"experiment_id={record['experiment_id']} tier={record['tier']}")
    return 0


def cmd_validate(paths: Paths) -> int:
    constants = load_constants(paths)
    load_policy(paths, constants)
    if paths.active.exists():
        record = load_active(paths, constants)
        print(
            f"validate: ok (active experiment {record['experiment_id']}, "
            f"tier {record['tier']}, status {record['status']})"
        )
    else:
        print("validate: ok (no active experiment; safe idle state)")
    return 0


def cmd_result(paths: Paths, args: argparse.Namespace) -> int:
    constants = load_constants(paths)
    record = load_active(paths, constants)
    if record["tier"] == "read_only":
        if record["status"] != "ready":
            raise Refusal("read_only record already carries a result")
    elif record["status"] != "claimed":
        raise Refusal("result requires a claimed record (or a ready read_only record)")
    evidence = Path(args.evidence)
    if evidence.is_absolute():
        raise Refusal("evidence path must be repo-relative")
    unresolved = paths.root / evidence
    if unresolved.is_symlink():
        raise Refusal(f"evidence is a symlink: {evidence}")
    resolved = unresolved.resolve()
    if resolved.parent != paths.logs_dir.resolve() or resolved.suffix != ".txt":
        raise Refusal("evidence must be a top-level .txt file under logs/")
    data = read_regular_file(resolved, "evidence")
    if not ROUTE_STATUS_RE.search(data.decode("utf-8", errors="replace")):
        raise Refusal("evidence must contain a route_status=<value> line")
    record["result"] = {
        "outcome": args.outcome,
        "evidence": str(evidence),
        "evidence_sha256": sha256_bytes(data),
        "recorded_at": _iso(_now()),
        "note": args.note,
    }
    record["status"] = "completed"
    atomic_write_json(paths.active, record)
    print(f"result: {args.outcome} recorded; no automatic retry is permitted")
    return 0


def cmd_observe(paths: Paths, note: str) -> int:
    constants = load_constants(paths)
    record = load_active(paths, constants)
    record["observations"].append({"at": _iso(_now()), "note": note})
    atomic_write_json(paths.active, record)
    print(f"observe: recorded ({len(record['observations'])} total)")
    return 0


def cmd_archive(paths: Paths) -> int:
    constants = load_constants(paths)
    record = load_active(paths, constants)
    if record["status"] != "completed":
        raise Refusal("archive requires a completed record")
    destination = paths.completed_dir / f"{record['experiment_id']}.json"
    if destination.exists():
        raise Refusal(f"archive destination already exists: {destination}")
    atomic_write_json(destination, record)
    paths.active.unlink()
    print(f"archive: {destination}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bringup_loop.py", description="Bringup governance engine (schema v4)"
    )
    parser.add_argument(
        "--root",
        default=None,
        help="repository root (default: parent of scripts/)",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("validate", help="validate governance files and the active record")

    new = sub.add_parser("new", help="scaffold the active experiment record")
    new.add_argument("--experiment-id", required=True)
    new.add_argument(
        "--operation",
        choices=sorted(OPERATIONS),
        default=None,
        help="omit for a read_only observation record",
    )
    new.add_argument("--target", default=None, help="partition target for partition_write")
    new.add_argument("--profile", default=None, help="repo-relative profile JSON")
    new.add_argument("--artifact", default=None, help="repo-relative artifact for ram_boot")
    new.add_argument("--hypothesis", required=True)
    new.add_argument("--discriminator", required=True)
    new.add_argument("--next-if-positive", required=True)
    new.add_argument("--next-if-negative", required=True)
    new.add_argument("--timebox-seconds", type=int, default=300)
    new.add_argument("--acknowledge-persistent-media", action="store_true")
    new.add_argument("--rebuild-reference", default=None)
    new.add_argument("--repeat-prior-experiment", default=None)
    new.add_argument("--repeat-changed-discriminator", default=None)
    new.add_argument("--repeat-evidence-report", default=None)

    sub.add_parser("approve", help="dry-run claim: verify every gate, change nothing")
    sub.add_parser("claim", help="atomic issue-and-claim under the ledger lock")

    result = sub.add_parser("result", help="bind the outcome and evidence")
    result.add_argument("outcome", choices=OUTCOMES)
    result.add_argument("--evidence", required=True)
    result.add_argument("--note", default=None)

    observe = sub.add_parser("observe", help="append an observation sidecar entry")
    observe.add_argument("--note", required=True)

    sub.add_parser("archive", help="freeze the completed record into bringup-completed/")
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parents[1]
    paths = Paths(root)
    try:
        if args.command == "validate":
            return cmd_validate(paths)
        if args.command == "new":
            return cmd_new(paths, args)
        if args.command == "approve":
            return cmd_claim(paths, dry_run=True)
        if args.command == "claim":
            return cmd_claim(paths, dry_run=False)
        if args.command == "result":
            return cmd_result(paths, args)
        if args.command == "observe":
            return cmd_observe(paths, args.note)
        if args.command == "archive":
            return cmd_archive(paths)
        raise Refusal(f"unknown command: {args.command}")
    except Refusal as refusal:
        print(f"refused: {refusal}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
