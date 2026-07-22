from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import unittest

from tests.lmi_p2_d114 import host_bound
from unittest import mock

from scripts.lmi_p2_d114 import postwrite_revalidate as postwrite


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.nonce = "11" * 32
        self.identity = "22" * 32
        self.profile_path = "private/final/profile.json"
        self.prior_path = "private/final/reports/write.json"
        self.mapping_path = "config/lmi-p2-d114/physical-userdata-mapping.json"
        self.identity_path = "private/identity.json"
        self.provenance_path = "config/lmi-p2-d114/fastboot-windows-provenance-lock.json"
        self.deploy_policy_path = "config/lmi-p2-d114/userdata-deploy-policy-lock.json"
        self.legacy_helper_path = "scripts/lmi_p2_d114/deploy_userdata_helper.ps1"
        self.legacy_gate_path = "scripts/lmi_p2_d114/deploy_userdata.py"
        self.helper_path = "scripts/lmi_p2_d114/postwrite_revalidate_helper.ps1"
        self.report_path = self.root / "private/final/reports/postwrite.json"
        self.large_paths = {
            "candidate": "private/final/bundle/userdata.android-sparse.img",
            "candidate_raw": "private/final/bundle/userdata.raw",
            "rollback": "private/final/rollback.android-sparse.img",
            "assembly_attestation": "private/final/bundle/assembly-attestation.json",
            "p2_injection_attestation": "private/final/bundle/injection-attestation.json",
            "source_lock": "config/lmi-p2-d114/source-lock.json",
        }
        for directory in (
            "private/final/reports", "private/final/bundle", "config/lmi-p2-d114",
            "private", "scripts/lmi_p2_d114",
        ):
            path = root / directory
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        helper_payload = postwrite.HELPER.read_bytes()
        self.write(self.helper_path, helper_payload)
        identity_payload = canonical({
            "device": {"product": "lmi"},
            "historical_identity": {
                "expected_nonce_scoped_serial_sha256": self.identity,
                "privacy_nonce": self.nonce,
            },
            "schema": "lmi-d110-recovery-policy/v2",
        })
        self.write(self.identity_path, identity_payload)
        mapping_payload = canonical({
            "evidence": {"private_identity_policy": {
                "path": self.identity_path, "sha256": sha(identity_payload), "size": len(identity_payload),
            }},
            "identity_binding": {
                "current_device_must_match_nonce_scoped_private_policy": True,
                "public_stable_fingerprint_forbidden": True,
            },
            "override": {
                "allowed_getvar_result": "unsupported", "fastboot_mode": "bootloader",
                "partition": "userdata", "partition_type": "f2fs",
                "super_or_fastbootd_fallback_allowed": False,
            },
            "schema": "lmi-d114-physical-userdata-mapping/v2",
            "userdata": {
                "block_device": "/dev/sda34", "capacity_bytes": 114_898_743_296,
                "gpt_logical_sector_size": 4096, "partlabel": "userdata",
            },
        })
        self.write(self.mapping_path, mapping_payload)
        provenance_payload = canonical({
            "authenticode": {
                "runtime_gate": "require-windows-status-valid-before-any-device-query",
                "signer_leaf_certificate_sha256": postwrite.FASTBOOT_SIGNER_LEAF_SHA256,
                "signer_subject_cn": "Google LLC",
            },
            "members": [
                {"path": f"platform-tools/{name}", "sha256": digest, "size": size}
                for name, size, digest in postwrite.FASTBOOT_MEMBERS
            ],
            "schema": "lmi-p2-d114-fastboot-windows-provenance/v2",
        })
        self.write(self.provenance_path, provenance_payload)
        legacy_helper_payload = b"synthetic locked legacy helper\n"
        legacy_gate_payload = b"synthetic locked legacy gate\n"
        self.write(self.legacy_helper_path, legacy_helper_payload)
        self.write(self.legacy_gate_path, legacy_gate_payload)
        deploy_policy_payload = canonical({
            "fastboot": {
                "authenticode": {
                    "revocation_policy": "online-entire-chain-no-ignore-flags-for-signer-and-timestamp",
                    "runtime_gate": "require-windows-status-valid-before-any-device-query",
                    "signer_leaf_certificate_sha256": postwrite.FASTBOOT_SIGNER_LEAF_SHA256,
                    "signer_subject_cn": "Google LLC",
                },
                "executable": {
                    "path": "localappdata/lmi-p2-d114/fastboot-r37.0.0/fastboot.exe",
                    "sha256": postwrite.FASTBOOT_MEMBERS[0][2],
                    "size": postwrite.FASTBOOT_MEMBERS[0][1],
                },
            },
            "helper": {
                "path": self.legacy_helper_path,
                "sha256": sha(legacy_helper_payload),
                "size": len(legacy_helper_payload),
            },
            "repo_bindings": {"fastboot_windows_provenance_lock": {
                "path": self.provenance_path,
                "sha256": sha(provenance_payload),
                "size": len(provenance_payload),
            }},
            "schema": "lmi-p2-d114-userdata-deploy-policy-lock/v4",
        })
        self.write(self.deploy_policy_path, deploy_policy_payload)
        artifacts = {
            "assembly_attestation": {"path": self.large_paths["assembly_attestation"], "sha256": "31" * 32, "size": 111},
            "candidate": {
                "logical_size": 3_339_714_560, "path": self.large_paths["candidate"],
                "representation": "android-sparse", "roundtrip_raw_sha256": "32" * 32,
                "sha256": "33" * 32, "size": 2_111_708_940,
            },
            "candidate_raw": {"path": self.large_paths["candidate_raw"], "sha256": "32" * 32, "size": 3_339_714_560},
            "deploy_policy_lock": {"path": self.deploy_policy_path, "sha256": sha(deploy_policy_payload), "size": len(deploy_policy_payload)},
            "p2_injection_attestation": {"path": self.large_paths["p2_injection_attestation"], "sha256": "35" * 32, "size": 333},
            "physical_mapping_evidence": {"path": self.mapping_path, "sha256": sha(mapping_payload), "size": len(mapping_payload)},
            "rollback": {
                "logical_size": 3_339_714_560, "path": self.large_paths["rollback"],
                "representation": "android-sparse", "roundtrip_raw_sha256": "36" * 32,
                "sha256": "37" * 32, "size": 2_192_400_084,
            },
            "source_lock": {"path": self.large_paths["source_lock"], "sha256": "38" * 32, "size": 444},
        }
        self.profile = {
            "artifacts": artifacts,
            "compatibility": {},
            "device": {
                "expected_product": "lmi", "expected_userdata_capacity": 114_898_743_296,
                "minimum_battery_mv": 3_800, "minimum_max_download_size": 52_944_896,
                "partition_type": "f2fs", "require_soc_ok": True,
            },
            "execution": {},
            "fastboot": {
                "path": "localappdata/lmi-p2-d114/fastboot-r37.0.0/fastboot.exe",
                "sha256": postwrite.FASTBOOT_MEMBERS[0][2], "size": postwrite.FASTBOOT_MEMBERS[0][1],
            },
            "profile_id": "synthetic-postwrite",
            "schema": postwrite.PROFILE_SCHEMA,
        }
        profile_payload = canonical(self.profile)
        self.write(self.profile_path, profile_payload)
        self.prior = {
            "artifacts": {"candidate": {
                "path": artifacts["candidate"]["path"], "sha256": artifacts["candidate"]["sha256"],
                "size": artifacts["candidate"]["size"],
            }},
            "created_at_unix": 100,
            "mode": "execute",
            "profile": {"id": "synthetic-postwrite", "sha256": sha(profile_payload)},
            "result": {
                "artifact_hashes": {
                    "deploy_policy_lock": sha(deploy_policy_payload),
                    "profile": sha(profile_payload),
                },
                "flash": {"attempts": 1, "exit_code": 0, "transport_completed": True},
                "locked_inputs_intact": True, "post_helper_input_recheck": True,
            },
            "route_status": postwrite.PRIOR_ROUTE,
            "safety": {},
            "schema": postwrite.PRIOR_REPORT_SCHEMA,
        }
        prior_payload = canonical(self.prior)
        self.write(self.prior_path, prior_payload)
        helper_size = len(helper_payload)
        self.contract = postwrite.Contract(
            profile_path=self.profile_path, profile_sha256=sha(profile_payload),
            prior_report_path=self.prior_path, prior_report_sha256=sha(prior_payload),
            mapping_path=self.mapping_path, mapping_sha256=sha(mapping_payload), mapping_size=len(mapping_payload),
            identity_path=self.identity_path, identity_sha256=sha(identity_payload), identity_size=len(identity_payload),
            provenance_path=self.provenance_path, provenance_sha256=sha(provenance_payload), provenance_size=len(provenance_payload),
            deploy_policy_path=self.deploy_policy_path, deploy_policy_sha256=sha(deploy_policy_payload), deploy_policy_size=len(deploy_policy_payload),
            legacy_helper_path=self.legacy_helper_path, legacy_helper_sha256=sha(legacy_helper_payload), legacy_helper_size=len(legacy_helper_payload),
            legacy_gate_path=self.legacy_gate_path, legacy_gate_sha256=sha(legacy_gate_payload), legacy_gate_size=len(legacy_gate_payload),
            helper_sha256=sha(helper_payload), helper_size=helper_size,
        )

    def write(self, relative: str, payload: bytes) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, 0o700)
        path.write_bytes(payload)
        os.chmod(path, 0o600)

    def helper_result(self) -> dict[str, object]:
        candidate = self.profile["artifacts"]["candidate"]
        return {
            "candidate": {"logical_size": candidate["logical_size"], "sha256": candidate["sha256"], "size": candidate["size"]},
            "device": {
                "battery_mv": 4_300, "identity_match": True, "is_logical_userdata": "unsupported",
                "max_download_size": 805_306_368, "partition_size": 114_898_743_296,
                "partition_type": "f2fs", "physical_mapping_evidence_override": True,
                "product": "lmi", "soc_ok": "yes", "unlocked": "yes", "userspace": "no",
            },
            "fastboot_members": [
                {"name": name, "sha256": digest, "size": size}
                for name, size, digest in postwrite.FASTBOOT_MEMBERS
            ],
            "fastboot_queries_attempted": list(postwrite.POSTWRITE_QUERY_NAMES),
            "fastboot_queries_completed": list(postwrite.POSTWRITE_QUERY_NAMES),
            "flash": {"attempts": 0},
            "input_binding": {
                "physical_replug_confirmed": True,
                "prior_write_report_sha256": self.contract.prior_report_sha256,
                "profile_sha256": self.contract.profile_sha256,
            },
            "locked_inputs_intact": True,
            "mode": "PostwriteRevalidate", "reason": None,
            "route_status": postwrite.HELPER_PASS_ROUTE,
            "schema": postwrite.HELPER_RESULT_SCHEMA, "serial_disclosed": False,
        }

    def run(self, runner=None) -> tuple[str, str]:
        return postwrite.revalidate(
            self.root / self.profile_path, self.contract.profile_sha256,
            self.root / self.prior_path, self.contract.prior_report_sha256,
            self.report_path, physical_replug_confirmed=True, repo_root=self.root,
            contract=self.contract, powershell_runner=runner or (lambda _audit: self.helper_result()),
            now_unix=200,
        )


class PostwriteRevalidationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        os.chmod(self.root, 0o700)
        self.fixture = Fixture(self.root)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_fake_runner_success_is_zero_attempt_private_report(self) -> None:
        observed: list[str] = []

        def runner(_audit: postwrite.Audit) -> dict[str, object]:
            observed.extend(postwrite.POSTWRITE_QUERY_NAMES)
            return self.fixture.helper_result()

        route, digest = self.fixture.run(runner)
        self.assertEqual(route, postwrite.PASS_ROUTE)
        report = json.loads(self.fixture.report_path.read_text(encoding="ascii"))
        self.assertEqual(digest, sha(canonical(report)))
        self.assertEqual(report["result"]["flash"], {"attempts": 0})
        self.assertTrue(report["result"]["helper_result_received"])
        self.assertEqual(report["result"]["fastboot_queries_attempted"], list(postwrite.POSTWRITE_QUERY_NAMES))
        self.assertEqual(report["result"]["fastboot_queries_completed"], list(postwrite.POSTWRITE_QUERY_NAMES))
        self.assertFalse(report["safety"]["device_state_change_attempted"])
        self.assertFalse(report["safety"]["current_online_authenticode_repeated"])
        self.assertTrue(report["safety"]["prior_runtime_provenance_reused"])
        self.assertEqual(observed, list(postwrite.POSTWRITE_QUERY_NAMES))
        self.assertTrue({"flash", "boot", "reboot", "erase", "format"}.isdisjoint(observed))
        self.assertEqual(self.fixture.report_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.fixture.report_path.stat().st_nlink, 1)
        rendered = self.fixture.report_path.read_text(encoding="ascii")
        self.assertNotIn(self.fixture.nonce, rendered)
        self.assertNotIn(self.fixture.identity, rendered)

    def test_postlaunch_outer_failure_is_a_private_zero_attempt_report(self) -> None:
        def runner(_audit: postwrite.Audit) -> dict[str, object]:
            raise postwrite.HelperRunFailed("HELPER_OUTER_TIMEOUT")

        route, _digest = self.fixture.run(runner)
        self.assertEqual(route, postwrite.FAIL_ROUTE)
        report = json.loads(self.fixture.report_path.read_text(encoding="ascii"))
        self.assertFalse(report["result"]["helper_result_received"])
        self.assertIsNone(report["result"]["fastboot_queries_attempted"])
        self.assertIsNone(report["result"]["fastboot_queries_completed"])
        self.assertEqual(report["result"]["fastboot_query_contract"], list(postwrite.POSTWRITE_QUERY_NAMES))
        self.assertEqual(report["result"]["flash"], {"attempts": 0})
        self.assertEqual(report["result"]["reason"], "HELPER_OUTER_TIMEOUT")
        self.assertFalse(report["safety"]["device_state_change_attempted"])
        self.assertFalse(report["safety"]["current_online_authenticode_repeated"])
        self.assertEqual(self.fixture.report_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.fixture.report_path.stat().st_nlink, 1)

    def test_outer_timeout_kills_and_waits_for_powershell(self) -> None:
        audit = postwrite.local_audit(
            self.root / self.fixture.profile_path, self.fixture.contract.profile_sha256,
            self.root / self.fixture.prior_path, self.fixture.contract.prior_report_sha256,
            repo_root=self.root, contract=self.fixture.contract,
        )
        events: list[str] = []

        class TimedOutProcess:
            returncode = None

            def communicate(self, input=None, timeout=None):
                events.append("communicate" if timeout is not None else "wait")
                if timeout is not None:
                    raise postwrite.subprocess.TimeoutExpired("powershell", timeout)
                self.returncode = -9
                return b"", b""

            def kill(self):
                events.append("kill")

        try:
            with (
                mock.patch.object(postwrite, "_windows_path", return_value=r"C:\locked.ps1"),
                mock.patch.object(postwrite.subprocess, "Popen", return_value=TimedOutProcess()),
            ):
                with self.assertRaisesRegex(postwrite.HelperRunFailed, "HELPER_OUTER_TIMEOUT"):
                    postwrite.run_powershell(audit)
        finally:
            audit.close()
        self.assertEqual(events, ["communicate", "kill", "wait"])

    def test_internal_refusal_keeps_unfinished_query_out_of_completed(self) -> None:
        audit = postwrite.local_audit(
            self.root / self.fixture.profile_path, self.fixture.contract.profile_sha256,
            self.root / self.fixture.prior_path, self.fixture.contract.prior_report_sha256,
            repo_root=self.root, contract=self.fixture.contract,
        )
        try:
            value = self.fixture.helper_result()
            value["fastboot_queries_attempted"] = list(postwrite.POSTWRITE_QUERY_NAMES[:3])
            value["fastboot_queries_completed"] = list(postwrite.POSTWRITE_QUERY_NAMES[:2])
            value["reason"] = "FASTBOOT_QUERY_CONTAINMENT_FAILED"
            value["route_status"] = "REFUSED_NO_STATE_CHANGE"
            validated = postwrite._validate_helper(value, audit)
            self.assertEqual(validated["fastboot_queries_attempted"][-1], "product")
            self.assertEqual(validated["fastboot_queries_completed"][-1], "serialno")

            value["fastboot_queries_completed"] = list(postwrite.POSTWRITE_QUERY_NAMES[:3])
            value["fastboot_queries_attempted"] = list(postwrite.POSTWRITE_QUERY_NAMES[:2])
            with self.assertRaisesRegex(postwrite.RevalidationError, "attempted/completed"):
                postwrite._validate_helper(value, audit)
        finally:
            audit.close()

    def test_large_artifact_paths_are_never_opened(self) -> None:
        real_open = postwrite.os.open
        forbidden = {str((self.root / path).absolute()) for path in self.fixture.large_paths.values()}

        def guarded_open(path, *args, **kwargs):
            if str(Path(path).absolute()) in forbidden:
                raise AssertionError(f"large artifact opened: {path}")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(postwrite.os, "open", side_effect=guarded_open):
            route, _digest = self.fixture.run()
        self.assertEqual(route, postwrite.PASS_ROUTE)

    def test_replug_and_exact_completed_prior_are_mandatory(self) -> None:
        with self.assertRaisesRegex(postwrite.RevalidationError, "physical replug"):
            postwrite.revalidate(
                self.root / self.fixture.profile_path, self.fixture.contract.profile_sha256,
                self.root / self.fixture.prior_path, self.fixture.contract.prior_report_sha256,
                self.fixture.report_path, physical_replug_confirmed=False, repo_root=self.root,
                contract=self.fixture.contract, powershell_runner=lambda _audit: self.fixture.helper_result(),
            )
        value = dict(self.fixture.prior)
        value["route_status"] = "WRITE_ATTEMPTED_RESULT_UNKNOWN"
        payload = canonical(value)
        self.fixture.write(self.fixture.prior_path, payload)
        bad = postwrite.Contract(**{
            **self.fixture.contract.__dict__, "prior_report_sha256": sha(payload),
        })
        with self.assertRaisesRegex(postwrite.RevalidationError, "pending completed write"):
            postwrite.local_audit(
                self.root / self.fixture.profile_path, bad.profile_sha256,
                self.root / self.fixture.prior_path, bad.prior_report_sha256,
                repo_root=self.root, contract=bad,
            )

    def test_static_fastboot_dispatch_contains_only_fixed_read_queries(self) -> None:
        helper = postwrite.HELPER.read_text(encoding="utf-8")
        switch = re.search(r"\$tokens = switch \(\$Query\) \{(?P<body>.*?)\n\s*default", helper, re.DOTALL)
        self.assertIsNotNone(switch)
        cases = re.findall(r"'([^']+)'\s*\{\s*@\(([^)]*)\)\s*\}", switch.group("body"))
        self.assertEqual([name for name, _tokens in cases], list(postwrite.POSTWRITE_QUERY_NAMES))
        forbidden = {"flash", "boot", "reboot", "erase", "format", "update", "oem", "flashing"}
        for name, raw_tokens in cases:
            tokens = re.findall(r"'([^']+)'", raw_tokens)
            self.assertTrue(forbidden.isdisjoint(tokens), (name, tokens))
            if name == "devices":
                self.assertEqual(tokens, ["devices"])
            else:
                self.assertEqual(tokens, ["-s", "getvar", name])
        calls = re.findall(r"Invoke-Fastboot\s+-Query\s+([^\s]+)", helper)
        self.assertEqual(calls, ["$Name", "'devices'"])
        self.assertNotRegex(helper, r"Invoke-Fastboot\s+@\(")
        self.assertIn("JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE", helper)
        self.assertIn("AssignProcessToJobObject", helper)
        self.assertIn("WaitForQuiescence", helper)
        self.assertIn("TerminateJobObject", helper)
        self.assertNotIn("Get-AuthenticodeSignature", helper)
        self.assertNotIn("X509Chain", helper)
        self.assertLess(helper.index("TreeQuiescent"), helper.index("$DeviceLockStream.Dispose()"))
        dispatch = helper.index("$commandLine =")
        attempted = helper.index("$QueriesAttempted.Add($Query)")
        native = helper.index("[LmiPostwriteNativeRunner]::Run")
        containment = helper.index("FASTBOOT_QUERY_CONTAINMENT_FAILED")
        completed = helper.index("$QueriesCompleted.Add($Query)")
        self.assertLess(dispatch, attempted)
        self.assertLess(attempted, native)
        self.assertLess(native, containment)
        self.assertLess(containment, completed)

    def test_current_completed_write_accepts_fake_readonly_device_result(self) -> None:
        host_bound.require_path(host_bound.REPO / "private")
        audit = postwrite.local_audit(
            postwrite.REPO / postwrite.PRODUCTION.profile_path,
            postwrite.PRODUCTION.profile_sha256,
            postwrite.REPO / postwrite.PRODUCTION.prior_report_path,
            postwrite.PRODUCTION.prior_report_sha256,
        )
        try:
            self.assertEqual(
                set(audit.held),
                {
                    "profile", "prior_report", "mapping", "identity_policy", "provenance",
                    "deploy_policy", "legacy_helper", "legacy_gate", "helper",
                },
            )
            candidate = audit.profile["artifacts"]["candidate"]
            result = self.fixture.helper_result()
            result["candidate"] = {
                "logical_size": candidate["logical_size"],
                "sha256": candidate["sha256"],
                "size": candidate["size"],
            }
            result["input_binding"] = {
                "physical_replug_confirmed": True,
                "prior_write_report_sha256": postwrite.PRODUCTION.prior_report_sha256,
                "profile_sha256": postwrite.PRODUCTION.profile_sha256,
            }
            validated = postwrite._validate_helper(result, audit)
            self.assertEqual(validated["flash"], {"attempts": 0})
        finally:
            audit.close()


if __name__ == "__main__":
    unittest.main()
