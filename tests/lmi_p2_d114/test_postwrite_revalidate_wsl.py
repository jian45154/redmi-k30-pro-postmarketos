from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest

from tests.lmi_p2_d114 import host_bound
from unittest import mock

from scripts.lmi_p2_d114 import deploy_userdata_wsl as deploy
from scripts.lmi_p2_d114 import postwrite_revalidate_wsl as postwrite


SERIAL = "SYNTHETIC-LMI-0001"
OTHER_SERIAL = "SYNTHETIC-LMI-0002"
NONCE = "a" * 64
IDENTITY = hashlib.sha256(f"{NONCE}:{SERIAL}".encode("ascii")).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def public_device(*, battery_mv: int = 4373) -> dict[str, object]:
    return {
        "battery_mv": battery_mv,
        "identity_match": True,
        "is_logical_userdata": "unsupported",
        "max_download_size": 805_306_368,
        "partition_size": deploy.PRODUCTION.userdata_capacity,
        "partition_type": "f2fs",
        "physical_mapping_evidence_override": True,
        "product": "lmi",
        "slot_layout_claim": "not-proven",
        "soc_ok": "yes",
        "unlocked": "yes",
        "userspace": "no",
    }


class FastbootRunner:
    def __init__(
        self,
        *,
        serial: str = SERIAL,
        devices_stdout: bytes | None = None,
        noisy_getvar: str | None = None,
    ) -> None:
        self.serial = serial
        self.devices_stdout = devices_stdout
        self.noisy_getvar = noisy_getvar
        self.calls: list[tuple[tuple[str, ...], int, tuple[int, ...], dict[str, str]]] = []

    def __call__(
        self,
        argv: tuple[str, ...] | list[str],
        timeout: int,
        pass_fds: tuple[int, ...],
        environment: dict[str, str],
    ) -> deploy.CommandResult:
        call = (tuple(argv), timeout, pass_fds, dict(environment))
        self.calls.append(call)
        if argv[-1] == "devices":
            output = self.devices_stdout
            if output is None:
                output = f"{self.serial}\tfastboot\n".encode("ascii")
            return deploy.CommandResult(0, output, b"")
        name = argv[-1]
        values = {
            "serialno": self.serial,
            "product": "lmi",
            "unlocked": "yes",
            "is-userspace": "no",
            "partition-type:userdata": "f2fs",
            "partition-size:userdata": "0x1AC07FB000",
            "battery-voltage": "4373",
            "battery-soc-ok": "yes",
            "max-download-size": "805306368",
        }
        finished = b"Finished. Total time: 0.007s\n"
        if name == "is-logical:userdata":
            stderr = (
                b"getvar:is-logical:userdata   FAILED "
                b"(remote: 'GetVar Variable Not found')\n" + finished
            )
        else:
            stderr = f"{name}: {values[name]}\n".encode("ascii") + finished
        if name == self.noisy_getvar:
            stderr += b"UNEXPECTED NOISE\n"
        return deploy.CommandResult(0, b"", stderr)


def absent_runner(
    argv: tuple[str, ...] | list[str],
    timeout: int,
    pass_fds: tuple[int, ...],
    environment: dict[str, str],
) -> deploy.CommandResult:
    if (
        argv[-1] != "devices"
        or timeout != deploy.QUERY_TIMEOUT_SECONDS
        or pass_fds
        or environment != deploy.SAFE_ENV
    ):
        raise AssertionError("arm-replug invoked something other than the fixed absence query")
    return deploy.CommandResult(0, b"", b"")


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.private = root / "private"
        self.reports = self.private / "reports"
        self.reports.mkdir(parents=True)
        os.chmod(self.private, 0o700)
        os.chmod(self.reports, 0o700)
        for name in ("attempt-ledger", "claim-ledger"):
            directory = self.reports / name
            directory.mkdir()
            os.chmod(directory, 0o700)
        self.argv_prefix = (
            "/runtime/ld-linux.so", "--inhibit-cache", "--library-path",
            "/runtime/lib", "/runtime/fastboot",
        )
        self.profile = self.make_profile()
        self.profile_sha256 = hashlib.sha256(canonical(self.profile)).hexdigest()
        self.lineage = self.make_lineage(self.profile, self.profile_sha256)
        self.write_report = self.make_write_report(
            self.profile, self.profile_sha256, self.lineage
        )
        self.write_report_bytes = canonical(self.write_report)
        self.write_report_sha256 = hashlib.sha256(self.write_report_bytes).hexdigest()
        self.profile_path = self.private / "profile.json"
        self.profile_path.write_bytes(canonical(self.profile))
        os.chmod(self.profile_path, 0o600)
        self.write_report_path = self.path("synthetic-execute-report.json")
        self.write_report_path.write_bytes(self.write_report_bytes)
        os.chmod(self.write_report_path, 0o600)

    def make_profile(self) -> dict[str, object]:
        contract = deploy.PRODUCTION
        return {
            "artifacts": {
                "assembly_attestation": {"path": "private/assembly.json", "sha256": contract.assembly_sha256, "size": contract.assembly_size},
                "candidate": {"logical_size": contract.raw_size, "path": "private/userdata.sparse", "representation": "android-sparse", "roundtrip_raw_sha256": contract.raw_sha256, "sha256": contract.sparse_sha256, "size": contract.sparse_size},
                "candidate_raw": {"path": "private/userdata.raw", "sha256": contract.raw_sha256, "size": contract.raw_size},
                "completed_actions_lock": {"path": "config/lmi-p2-d114/completed-userdata-actions-lock.json", "sha256": contract.completed_sha256, "size": contract.completed_size},
                "deploy_policy_lock": {"path": "config/lmi-p2-d114/userdata-deploy-policy-lock-wsl-r2.json", "sha256": "1" * 64, "size": 1},
                "fastboot_runtime_lock": {"path": "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json", "sha256": contract.runtime_sha256, "size": contract.runtime_size},
                "p2_injection_attestation": {"path": "private/injection.json", "sha256": contract.injection_sha256, "size": contract.injection_size},
                "p2_rootfs": {"path": "private/rootfs.ext4", "sha256": contract.rootfs_sha256, "size": contract.rootfs_size},
                "physical_mapping_evidence": {"path": "config/lmi-p2-d114/physical-userdata-mapping.json", "sha256": contract.mapping_sha256, "size": contract.mapping_size},
                "rollback": {"logical_size": contract.raw_size, "path": "private/rollback.sparse", "representation": "android-sparse", "roundtrip_raw_sha256": contract.baseline_raw_sha256, "sha256": contract.rollback_sha256, "size": contract.rollback_size},
            },
            "compatibility": {"d110_boot": {"authorization": False, "sha256": contract.d110_boot_sha256, "size": contract.d110_boot_size}},
            "device": {"expected_product": "lmi", "expected_userdata_capacity": contract.userdata_capacity, "minimum_battery_mv": 3800, "minimum_max_download_size": contract.d110_boot_size, "partition_type": "f2fs"},
            "execution": {"automatic_retry": False, "claim_kind": "flash-userdata", "max_attempts": 1, "operation": "flash", "partition": "userdata", "slot_layout_claim": "not-proven", "write_timeout_seconds": deploy.WRITE_TIMEOUT_SECONDS},
            "identity": {"expected_nonce_scoped_serial_sha256": IDENTITY, "expected_serial": SERIAL, "privacy_nonce": NONCE},
            "ledgers": {"candidate_attempts": "private/reports/attempt-ledger", "claim_consumption": "private/reports/claim-ledger"},
            "profile_id": "synthetic-postwrite-r1",
            "schema": deploy.PROFILE_SCHEMA,
        }

    def make_lineage(
        self,
        profile: dict[str, object],
        profile_sha256: str,
    ) -> dict[str, dict[str, object]]:
        approval_sha256 = "2" * 64
        consumed = {
            "approval_sha256": approval_sha256,
            "consumed_at_unix": 800,
            "ledger_directory": profile["ledgers"]["claim_consumption"],
            "retry_authorization": False,
            "schema": deploy.CONSUMED_SCHEMA,
        }
        attempt = {
            "approval_sha256": approval_sha256,
            "attempted_at_unix": 850,
            "candidate_sha256": profile["artifacts"]["candidate"]["sha256"],
            "identity_binding": profile["identity"]["expected_nonce_scoped_serial_sha256"],
            "ledger_directory": profile["ledgers"]["candidate_attempts"],
            "retry_authorization": False,
            "schema": postwrite.CANDIDATE_ATTEMPT_SCHEMA,
        }
        consumed_bytes = canonical(consumed)
        attempt_bytes = canonical(attempt)
        consumed_sha = hashlib.sha256(consumed_bytes).hexdigest()
        attempt_sha = hashlib.sha256(attempt_bytes).hexdigest()
        intent = {
            "approval_sha256": approval_sha256,
            "argv_nonce_scoped_sha256": "3" * 64,
            "argv_semantics": [
                *self.argv_prefix,
                "-s", "<identity-matched-device>", "flash", "userdata",
                "/proc/self/fd/<held-candidate-fd>",
            ],
            "artifacts": postwrite._artifact_binding(profile, profile_sha256),
            "candidate_attempt_sha256": attempt_sha,
            "consumed_claim_sha256": consumed_sha,
            "created_at_unix": 850,
            "identity_binding": profile["identity"]["expected_nonce_scoped_serial_sha256"],
            "max_attempts": 1,
            "retry_authorization": False,
            "schema": deploy.INTENT_SCHEMA,
        }
        intent_bytes = canonical(intent)
        values = {
            "consumed_claim": {
                "bytes": consumed_bytes,
                "path": self.root / profile["ledgers"]["claim_consumption"] / f"{approval_sha256}.consumed.json",
                "sha256": consumed_sha,
                "size": len(consumed_bytes),
                "value": consumed,
            },
            "candidate_attempt": {
                "bytes": attempt_bytes,
                "path": self.root / profile["ledgers"]["candidate_attempts"] / f"{profile['artifacts']['candidate']['sha256']}.attempt.json",
                "sha256": attempt_sha,
                "size": len(attempt_bytes),
                "value": attempt,
            },
            "intent": {
                "bytes": intent_bytes,
                "path": self.path("preattempt-intent.json"),
                "sha256": hashlib.sha256(intent_bytes).hexdigest(),
                "size": len(intent_bytes),
                "value": intent,
            },
        }
        for item in values.values():
            item["path"].write_bytes(item["bytes"])
            os.chmod(item["path"], 0o600)
        return values

    @staticmethod
    def make_write_report(
        profile: dict[str, object],
        profile_sha256: str,
        lineage: dict[str, dict[str, object]],
    ) -> dict[str, object]:
        return {
            "artifacts": postwrite._artifact_binding(profile, profile_sha256),
            "created_at_unix": 900,
            "mode": "execute",
            "profile": {"id": profile["profile_id"], "sha256": profile_sha256},
            "result": {
                "approval_sha256": "2" * 64,
                "attempts": 1,
                "argv_nonce_scoped_sha256": "3" * 64,
                "candidate_attempt_sha256": lineage["candidate_attempt"]["sha256"],
                "consumed_claim_sha256": lineage["consumed_claim"]["sha256"],
                "device": public_device(),
                "exit_code": 0,
                "intent_sha256": lineage["intent"]["sha256"],
                "output_limited": False,
                "output_sha256": "7" * 64,
                "output_size": 123,
                "reason": None,
                "started": True,
                "timed_out": False,
                "transport_completed": True,
            },
            "route_status": deploy.COMPLETED_ROUTE,
            "safety": {
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
            },
            "schema": deploy.REPORT_SCHEMA,
        }

    def lineage_bindings(self) -> dict[str, dict[str, object]]:
        return {
            name: {
                "path": item["path"].relative_to(self.root).as_posix(),
                "sha256": item["sha256"],
                "size": item["size"],
            }
            for name, item in self.lineage.items()
        }

    def audit(self, *, hold_lineage_anchors: bool = False) -> postwrite.Audit:
        held: dict[str, deploy.HeldFile] = {}
        if hold_lineage_anchors:
            held["profile"] = deploy._open_regular(
                self.profile_path, self.root, "private WSL profile"
            )
            held["write_report"] = deploy._open_regular(
                self.write_report_path, self.root, "completed WSL execute report"
            )
        base = deploy.Audit(
            self.root,
            self.profile,
            self.profile_sha256,
            {},
            {
                "override": {
                    "allowed_getvar_result": "unsupported",
                    "fastboot_mode": "bootloader",
                    "partition": "userdata",
                    "partition_type": "f2fs",
                    "super_or_fastbootd_fallback_allowed": False,
                }
            },
            {},
            {},
            held,
            self.argv_prefix,
        )
        return postwrite.Audit(
            base,
            self.write_report,
            self.write_report_path,
            self.write_report_sha256,
            len(self.write_report_bytes),
            self.lineage_bindings(),
        )

    def lineage_specs(self) -> tuple[postwrite.LineageSpec, ...]:
        return tuple(
            postwrite.LineageSpec(item["path"], item["sha256"], item["size"])
            for item in (
                self.lineage["consumed_claim"],
                self.lineage["candidate_attempt"],
                self.lineage["intent"],
            )
        )

    def path(self, name: str) -> Path:
        return self.reports / name

    def arm(self, name: str = "replug-token.json", now: int = 1000) -> tuple[Path, str]:
        path = self.path(name)
        audit = self.audit()
        try:
            route, digest = postwrite.arm_replug(
                audit,
                path,
                process_runner=absent_runner,
                nonce_factory=lambda: b"n" * 32,
                now_unix=now,
            )
        finally:
            audit.close()
        if route != postwrite.ARM_ROUTE:
            raise AssertionError("arm-replug did not return its exact route")
        return path, digest


class PostwriteRevalidateWslTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def _revalidate(
        self,
        token_path: Path,
        token_sha256: str,
        runner: FastbootRunner,
        *,
        report_name: str = "postwrite.json",
        now: int = 1001,
    ) -> tuple[str, str, Path]:
        report_path = self.fixture.path(report_name)
        audit = self.fixture.audit()
        try:
            route, digest = postwrite.revalidate(
                audit,
                token_path,
                token_sha256,
                report_path,
                process_runner=runner,
                now_unix=now,
            )
        finally:
            audit.close()
        return route, digest, report_path

    def _audit_lineage(
        self,
        *,
        report: dict[str, object] | None = None,
        specs: tuple[postwrite.LineageSpec, ...] | None = None,
    ) -> dict[str, dict[str, object]]:
        audit = self.fixture.audit(hold_lineage_anchors=True)
        try:
            return postwrite._audit_lineage(
                audit.base,
                report or self.fixture.write_report,
                *(specs or self.fixture.lineage_specs()),
            )
        finally:
            audit.close()

    def test_absence_then_exact_presence_passes_and_persists_only_redacted_evidence(self) -> None:
        token_path, token_sha = self.fixture.arm()
        runner = FastbootRunner()
        route, digest, report_path = self._revalidate(token_path, token_sha, runner)
        self.assertEqual(route, postwrite.PASS_ROUTE)
        self.assertEqual(hashlib.sha256(report_path.read_bytes()).hexdigest(), digest)
        self.assertEqual(len(runner.calls), len(deploy.QUERY_NAMES))
        self.assertEqual(
            [call[0][-1] if call[0][-1] == "devices" else f"getvar:{call[0][-1]}" for call in runner.calls],
            list(deploy.QUERY_NAMES),
        )
        consumed_path = postwrite._consumed_path(token_path)
        self.assertTrue(consumed_path.is_file())
        report = json.loads(report_path.read_text())
        self.assertTrue(report["result"]["host_observed_zero_then_one_fastboot_device"])
        for path in (token_path, consumed_path, report_path):
            payload = path.read_bytes()
            self.assertNotIn(SERIAL.encode("ascii"), payload)
            self.assertNotIn(str(self.fixture.root).encode("ascii"), payload)
            self.assertNotIn(b"usb:", payload.lower())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_arm_rejects_continuous_presence_and_never_publishes_token(self) -> None:
        token_path = self.fixture.path("continuous.json")
        audit = self.fixture.audit()
        runner = FastbootRunner()
        try:
            with self.assertRaises(postwrite.RevalidationError):
                postwrite.arm_replug(
                    audit,
                    token_path,
                    process_runner=runner,
                    nonce_factory=lambda: b"n" * 32,
                    now_unix=1000,
                )
        finally:
            audit.close()
        self.assertFalse(token_path.exists())
        self.assertEqual(len(runner.calls), 1)

    def test_revalidate_zero_or_two_devices_consumes_token_and_fails_without_retry(self) -> None:
        for index, devices in enumerate((b"", f"{SERIAL}\tfastboot\n{OTHER_SERIAL}\tfastboot\n".encode("ascii"))):
            with self.subTest(devices=devices):
                token_path, token_sha = self.fixture.arm(f"device-count-{index}.json")
                runner = FastbootRunner(devices_stdout=devices)
                route, _digest, report_path = self._revalidate(
                    token_path,
                    token_sha,
                    runner,
                    report_name=f"device-count-{index}-report.json",
                )
                self.assertEqual(route, postwrite.FAIL_ROUTE)
                self.assertTrue(postwrite._consumed_path(token_path).exists())
                self.assertEqual(len(runner.calls), 1)
                report = json.loads(report_path.read_text())
                self.assertEqual(report["result"]["reason"], "DEVICE_REVALIDATION_FAILED")
                self.assertIsNone(report["device"])

    def test_identity_mismatch_consumes_token_and_persists_no_raw_serial(self) -> None:
        token_path, token_sha = self.fixture.arm("identity.json")
        runner = FastbootRunner(serial=OTHER_SERIAL)
        route, _digest, report_path = self._revalidate(
            token_path, token_sha, runner, report_name="identity-report.json"
        )
        self.assertEqual(route, postwrite.FAIL_ROUTE)
        payload = report_path.read_bytes()
        self.assertNotIn(OTHER_SERIAL.encode("ascii"), payload)
        self.assertNotIn(SERIAL.encode("ascii"), payload)
        self.assertEqual(len(runner.calls), 1)

    def test_old_windows_or_unknown_execute_reports_are_rejected(self) -> None:
        for mutation in (
            {"schema": "lmi-p2-d114-userdata-deploy-report/windows-v1"},
            {"route_status": "USERDATA_TRANSPORT_UNKNOWN_NO_RETRY"},
        ):
            with self.subTest(mutation=mutation):
                report = json.loads(json.dumps(self.fixture.write_report))
                report.update(mutation)
                with self.assertRaises(postwrite.RevalidationError):
                    postwrite._validate_execute_report(
                        report, self.fixture.profile, self.fixture.profile_sha256
                    )
        report = json.loads(json.dumps(self.fixture.write_report))
        report["result"]["transport_completed"] = False
        report["result"]["timed_out"] = True
        with self.assertRaises(postwrite.RevalidationError):
            postwrite._validate_execute_report(
                report, self.fixture.profile, self.fixture.profile_sha256
            )

    def test_completed_report_requires_exact_opened_lineage_chain(self) -> None:
        bindings = self._audit_lineage()
        self.assertEqual(bindings, self.fixture.lineage_bindings())

        forged = json.loads(json.dumps(self.fixture.write_report))
        forged["result"]["consumed_claim_sha256"] = "f" * 64
        postwrite._validate_execute_report(
            forged, self.fixture.profile, self.fixture.profile_sha256
        )
        with self.assertRaises(postwrite.RevalidationError):
            self._audit_lineage(report=forged)

    def test_lineage_missing_replaced_or_wrong_path_hash_size_is_rejected(self) -> None:
        consumed, attempt, intent = self.fixture.lineage_specs()
        missing_intent = postwrite.LineageSpec(
            self.fixture.path("missing-intent.json"), intent.sha256, intent.size
        )
        wrong_consumed_path = self.fixture.path("copied-consumed.json")
        wrong_consumed_path.write_bytes(consumed.path.read_bytes())
        os.chmod(wrong_consumed_path, 0o600)
        cases = (
            (consumed, attempt, missing_intent),
            (
                postwrite.LineageSpec(
                    wrong_consumed_path, consumed.sha256, consumed.size
                ),
                attempt,
                intent,
            ),
            (
                postwrite.LineageSpec(
                    consumed.path, "e" * 64, consumed.size
                ),
                attempt,
                intent,
            ),
            (
                consumed,
                postwrite.LineageSpec(
                    attempt.path, attempt.sha256, attempt.size + 1
                ),
                intent,
            ),
        )
        for specs in cases:
            with self.subTest(specs=specs):
                with self.assertRaises(postwrite.RevalidationError):
                    self._audit_lineage(specs=specs)

        replacement = json.loads(intent.path.read_text())
        replacement["identity_binding"] = "d" * 64
        replacement_bytes = canonical(replacement)
        intent.path.write_bytes(replacement_bytes)
        os.chmod(intent.path, 0o600)
        replacement_spec = postwrite.LineageSpec(
            intent.path,
            hashlib.sha256(replacement_bytes).hexdigest(),
            len(replacement_bytes),
        )
        forged_report = json.loads(json.dumps(self.fixture.write_report))
        forged_report["result"]["intent_sha256"] = replacement_spec.sha256
        postwrite._validate_execute_report(
            forged_report, self.fixture.profile, self.fixture.profile_sha256
        )
        with self.assertRaises(postwrite.RevalidationError):
            self._audit_lineage(
                report=forged_report,
                specs=(consumed, attempt, replacement_spec),
            )

    def test_lineage_requires_both_existing_mode_0700_ledgers(self) -> None:
        claim_ledger = self.fixture.root / self.fixture.profile["ledgers"]["claim_consumption"]
        moved_claim_ledger = claim_ledger.with_name("claim-ledger-not-present")
        claim_ledger.rename(moved_claim_ledger)
        try:
            with self.assertRaises(postwrite.RevalidationError):
                self._audit_lineage()
        finally:
            moved_claim_ledger.rename(claim_ledger)

        attempt_ledger = self.fixture.root / self.fixture.profile["ledgers"]["candidate_attempts"]
        os.chmod(attempt_ledger, 0o755)
        try:
            with self.assertRaises(postwrite.RevalidationError):
                self._audit_lineage()
        finally:
            os.chmod(attempt_ledger, 0o700)

    def test_token_is_path_bound_one_use_and_has_a_hard_ttl(self) -> None:
        token_path, token_sha = self.fixture.arm("one-use.json")
        first_runner = FastbootRunner()
        route, _digest, _report = self._revalidate(
            token_path, token_sha, first_runner, report_name="first.json"
        )
        self.assertEqual(route, postwrite.PASS_ROUTE)
        second_runner = FastbootRunner()
        audit = self.fixture.audit()
        try:
            with self.assertRaises(postwrite.RevalidationError):
                postwrite.revalidate(
                    audit,
                    token_path,
                    token_sha,
                    self.fixture.path("second.json"),
                    process_runner=second_runner,
                    now_unix=1002,
                )
        finally:
            audit.close()
        self.assertEqual(second_runner.calls, [])

        copied_path = self.fixture.path("copied-token.json")
        copied_path.write_bytes(token_path.read_bytes())
        os.chmod(copied_path, 0o600)
        audit = self.fixture.audit()
        try:
            with self.assertRaises(postwrite.RevalidationError):
                postwrite.revalidate(
                    audit,
                    copied_path,
                    token_sha,
                    self.fixture.path("copied-report.json"),
                    process_runner=second_runner,
                    now_unix=1002,
                )
        finally:
            audit.close()
        self.assertEqual(second_runner.calls, [])

        expired_path, expired_sha = self.fixture.arm("expired.json", now=2000)
        audit = self.fixture.audit()
        try:
            with self.assertRaises(postwrite.RevalidationError):
                postwrite.revalidate(
                    audit,
                    expired_path,
                    expired_sha,
                    self.fixture.path("expired-report.json"),
                    process_runner=second_runner,
                    now_unix=2000 + postwrite.REPLUG_TTL_SECONDS + 1,
                )
        finally:
            audit.close()
        self.assertFalse(postwrite._consumed_path(expired_path).exists())
        self.assertEqual(second_runner.calls, [])

    def test_token_binds_exact_execute_report_path_hash_and_size(self) -> None:
        token_path, token_sha = self.fixture.arm("write-binding.json")
        runner = FastbootRunner()
        for field, value in (
            ("write_report_path", self.fixture.path("copied-execute-report.json")),
            ("write_report_sha256", "8" * 64),
            ("write_report_size", len(self.fixture.write_report_bytes) + 1),
        ):
            with self.subTest(field=field):
                audit = self.fixture.audit()
                setattr(audit, field, value)
                try:
                    with self.assertRaises(postwrite.RevalidationError):
                        postwrite.revalidate(
                            audit,
                            token_path,
                            token_sha,
                            self.fixture.path(f"write-binding-{field}.json"),
                            process_runner=runner,
                            now_unix=1001,
                        )
                finally:
                    audit.close()
        self.assertFalse(postwrite._consumed_path(token_path).exists())
        self.assertEqual(runner.calls, [])

    def test_token_expiring_during_full_gate_is_consumed_and_cannot_pass(self) -> None:
        token_path, token_sha = self.fixture.arm("expires-during-query.json")
        runner = FastbootRunner()
        times = iter((1001, 1000 + postwrite.REPLUG_TTL_SECONDS + 1))
        report_path = self.fixture.path("expires-during-query-report.json")
        audit = self.fixture.audit()
        try:
            route, _digest = postwrite.revalidate(
                audit,
                token_path,
                token_sha,
                report_path,
                process_runner=runner,
                clock=lambda: next(times),
            )
        finally:
            audit.close()
        self.assertEqual(route, postwrite.FAIL_ROUTE)
        self.assertEqual(len(runner.calls), len(deploy.QUERY_NAMES))
        self.assertTrue(postwrite._consumed_path(token_path).exists())
        report = json.loads(report_path.read_text())
        self.assertEqual(
            report["result"]["reason"],
            "REPLUG_TOKEN_EXPIRED_DURING_REVALIDATION",
        )
        self.assertFalse(report["result"]["host_observed_zero_then_one_fastboot_device"])

    def test_noisy_getvar_consumes_token_and_emits_fail_report(self) -> None:
        token_path, token_sha = self.fixture.arm("noise.json")
        runner = FastbootRunner(noisy_getvar="product")
        route, _digest, report_path = self._revalidate(
            token_path, token_sha, runner, report_name="noise-report.json"
        )
        self.assertEqual(route, postwrite.FAIL_ROUTE)
        self.assertTrue(postwrite._consumed_path(token_path).exists())
        report = json.loads(report_path.read_text())
        self.assertEqual(report["result"]["reason"], "DEVICE_REVALIDATION_FAILED")
        self.assertEqual(len(runner.calls), 3)

    def test_report_cannot_alias_the_deterministic_consumption_marker(self) -> None:
        token_path, token_sha = self.fixture.arm("alias.json")
        runner = FastbootRunner()
        audit = self.fixture.audit()
        try:
            with self.assertRaises(postwrite.RevalidationError):
                postwrite.revalidate(
                    audit,
                    token_path,
                    token_sha,
                    postwrite._consumed_path(token_path),
                    process_runner=runner,
                    now_unix=1001,
                )
        finally:
            audit.close()
        self.assertFalse(postwrite._consumed_path(token_path).exists())
        self.assertEqual(runner.calls, [])

    def test_local_audit_opens_only_small_contract_files_and_execute_report(self) -> None:
        host_bound.require_path(host_bound.REPO / "private")
        root = self.fixture.root
        config = root / "config" / "lmi-p2-d114"
        config.mkdir(parents=True)
        source_config = deploy.REPO / "config" / "lmi-p2-d114"
        names = (
            "userdata-deploy-policy-lock-wsl-r2.json",
            "fastboot-wsl-runtime-lock.json",
            "physical-userdata-mapping.json",
            "completed-userdata-actions-lock.json",
        )
        specs: dict[str, tuple[str, int]] = {}
        for name in names:
            payload = (source_config / name).read_bytes()
            target = config / name
            target.write_bytes(payload)
            os.chmod(target, 0o644)
            specs[name] = (hashlib.sha256(payload).hexdigest(), len(payload))
            if name == "fastboot-wsl-runtime-lock.json":
                runtime_value = json.loads(payload)
                self.fixture.argv_prefix = tuple(runtime_value["execution"]["argv_prefix"])

        profile = self.fixture.make_profile()
        artifacts = profile["artifacts"]
        artifact_names = {
            "deploy_policy_lock": "userdata-deploy-policy-lock-wsl-r2.json",
            "fastboot_runtime_lock": "fastboot-wsl-runtime-lock.json",
            "physical_mapping_evidence": "physical-userdata-mapping.json",
            "completed_actions_lock": "completed-userdata-actions-lock.json",
        }
        for artifact_name, filename in artifact_names.items():
            digest, size = specs[filename]
            artifacts[artifact_name] = {
                "path": f"config/lmi-p2-d114/{filename}",
                "sha256": digest,
                "size": size,
            }
        profile_bytes = canonical(profile)
        profile_sha = hashlib.sha256(profile_bytes).hexdigest()
        profile_path = self.fixture.private / "profile.json"
        profile_path.write_bytes(profile_bytes)
        os.chmod(profile_path, 0o600)

        lineage = self.fixture.make_lineage(profile, profile_sha)
        write_report = self.fixture.make_write_report(profile, profile_sha, lineage)
        write_bytes = canonical(write_report)
        write_sha = hashlib.sha256(write_bytes).hexdigest()
        write_path = self.fixture.path("exact-write-report.json")
        write_path.write_bytes(write_bytes)
        os.chmod(write_path, 0o600)

        with (
            mock.patch.object(
                postwrite,
                "_static_runtime_runner",
                wraps=postwrite._static_runtime_runner,
            ) as runtime_runner,
            mock.patch.object(
                postwrite.deploy,
                "_open_regular",
                wraps=deploy._open_regular,
            ) as opened,
        ):
            audit = postwrite.local_audit(
                profile_path,
                profile_sha,
                write_path,
                write_sha,
                len(write_bytes),
                lineage["consumed_claim"]["path"],
                lineage["consumed_claim"]["sha256"],
                lineage["consumed_claim"]["size"],
                lineage["candidate_attempt"]["path"],
                lineage["candidate_attempt"]["sha256"],
                lineage["candidate_attempt"]["size"],
                lineage["intent"]["path"],
                lineage["intent"]["sha256"],
                lineage["intent"]["size"],
                repo_root=root,
            )
            audit.close()
        self.assertEqual(len(runtime_runner.call_args_list), 2)
        for call in runtime_runner.call_args_list:
            command = tuple(call.args[0])
            self.assertNotIn("devices", command)
            self.assertFalse(any(value.startswith("getvar:") for value in command))
            self.assertNotIn("flash", command)
        labels = {
            call.args[2]
            for call in opened.call_args_list
            if call.args[0].is_relative_to(root)
        }
        self.assertEqual(
            labels,
            {
                "private WSL profile",
                "WSL deploy policy",
                "WSL runtime lock",
                "physical mapping",
                "completed action lock",
                "exact WSL write report",
                "consumed claim",
                "candidate attempt",
                "preattempt intent",
            },
        )
        for artifact_name in (
            "assembly_attestation", "candidate", "candidate_raw",
            "p2_injection_attestation", "p2_rootfs", "rollback",
        ):
            self.assertFalse((root / artifacts[artifact_name]["path"]).exists())

    def test_actual_runtime_v2_combines_with_static_postwrite_runner(self) -> None:
        host_bound.require_path(host_bound.REPO / "private")
        runtime = json.loads(
            (deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text()
        )
        with mock.patch.object(
            postwrite,
            "_static_runtime_runner",
            wraps=postwrite._static_runtime_runner,
        ) as runner:
            prefix, held = deploy._validate_runtime(runtime, runner)
        try:
            self.assertEqual(prefix, tuple(runtime["execution"]["argv_prefix"]))
            self.assertEqual(len(runner.call_args_list), 2)
            for call in runner.call_args_list:
                command = tuple(call.args[0])
                self.assertNotIn("devices", command)
                self.assertFalse(any(value.startswith("getvar:") for value in command))
                self.assertNotIn("flash", command)
        finally:
            for item in reversed(held):
                item.close()

    def test_source_has_only_read_only_device_query_contract(self) -> None:
        source = Path(postwrite.__file__).read_text()
        tree = ast.parse(source)
        imported = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        }
        self.assertNotIn("subprocess", imported)
        self.assertEqual(postwrite.ABSENCE_QUERY, ("devices",))
        self.assertEqual(postwrite.FULL_QUERY_CONTRACT, deploy.QUERY_NAMES)
        forbidden = ("flash", "boot", "reboot", "erase", "format")
        for query in (postwrite.ABSENCE_QUERY, postwrite.FULL_QUERY_CONTRACT):
            self.assertFalse(any(item in forbidden for item in query))
        direct_runner_calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "process_runner"
        ]
        self.assertEqual(len(direct_runner_calls), 1)


if __name__ == "__main__":
    unittest.main()
