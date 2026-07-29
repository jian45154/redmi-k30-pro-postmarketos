from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest

from scripts import bringup_loop


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.constants = {
            "schema_version": 4,
            "expected_product": "lmi",
            "battery_floor_mv": 3800,
            "receipt_ttl_seconds": 900,
            "partition_targets": ["boot", "userdata", "dtbo", "vbmeta"],
            "volatile_operations": ["device_reboot"],
            "ram_rw_operations": ["ram_boot", "runtime_handoff"],
            "persistent_operations": ["partition_write"],
            "forbidden_command_words": sorted(bringup_loop.FORBIDDEN_COMMAND_WORDS),
        }
        self.policy = {
            "schema_version": 4,
            "enabled": True,
            "revision": "2026-07-22.1",
            "authorized_by": "ian",
            "authorization_note": "test fixture",
            "standing_scopes": [
                {"tier": "volatile", "operation": "device_reboot", "target": "device"},
                {"tier": "ram_rw", "operation": "ram_boot", "target": "ram"},
                {"tier": "ram_rw", "operation": "runtime_handoff", "target": "initramfs"},
            ],
            "authorized_profiles": [],
            "manual_only": ["bootloader-relock"],
        }
        (root / "logs").mkdir(parents=True, exist_ok=True)
        (root / "notes").mkdir(parents=True, exist_ok=True)
        self.flush()

    def flush(self) -> None:
        _write_json(self.root / "config/governance/constants.json", self.constants)
        _write_json(self.root / "config/governance/policy.json", self.policy)

    def write_artifact(self, rel: str, data: bytes) -> str:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return bringup_loop.sha256_bytes(data)

    def write_profile(self, rel: str, boot_rel: str, rollback_rel: str) -> str:
        boot_sha = self.write_artifact(boot_rel, b"boot-image-bytes")
        rollback_sha = self.write_artifact(rollback_rel, b"rollback-image-bytes")
        profile = {
            "schema_version": 1,
            "release": "D-v115",
            "boot": {"path": boot_rel, "sha256": boot_sha, "size": len(b"boot-image-bytes")},
            "rollback": {
                "target": "boot",
                "path": rollback_rel,
                "sha256": rollback_sha,
                "size": len(b"rollback-image-bytes"),
            },
        }
        _write_json(self.root / rel, profile)
        return bringup_loop.sha256_bytes((self.root / rel).read_bytes())

    def authorize_profile(self, rel: str, sha256: str, targets: list) -> None:
        self.policy["authorized_profiles"] = [
            {
                "profile_path": rel,
                "profile_sha256": sha256,
                "targets": targets,
                "authorized_by": "ian",
                "note": "test authorization",
            }
        ]
        self.flush()

    def write_evidence(self, name: str = "evidence.txt", route: str = "OK") -> str:
        path = self.root / "logs" / name
        path.write_text(f"probe output\nroute_status={route}\n", encoding="utf-8")
        return f"logs/{name}"

    def run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = bringup_loop.main(["--root", str(self.root), *argv])
        return code, out.getvalue(), err.getvalue()

    def new_reboot(self, experiment_id: str = "reboot-check-1") -> tuple[int, str, str]:
        return self.run(
            "new",
            "--experiment-id",
            experiment_id,
            "--operation",
            "device_reboot",
            "--hypothesis",
            "device returns to fastboot after reboot",
            "--discriminator",
            "fastboot devices lists the unit within 120s",
            "--next-if-positive",
            "proceed to ram boot",
            "--next-if-negative",
            "inspect usb enumeration",
        )

    def active(self) -> dict:
        return json.loads((self.root / "notes/bringup-active.json").read_text())

    def patch_active(self, mutate) -> None:
        record = self.active()
        mutate(record)
        _write_json(self.root / "notes/bringup-active.json", record)

    def ledger_text(self) -> str:
        path = self.root / "notes/bringup-claims/claims.log"
        return path.read_text(encoding="utf-8") if path.exists() else ""


class BringupLoopTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fx = Fixture(Path(self._tmp.name))

    def test_validate_safe_idle(self) -> None:
        code, out, err = self.fx.run("validate")
        self.assertEqual(code, 0, err)
        self.assertIn("safe idle state", out)

    def test_forbidden_words_data_file_cannot_diverge(self) -> None:
        self.fx.constants["forbidden_command_words"] = ["erase"]
        self.fx.flush()
        code, _, err = self.fx.run("validate")
        self.assertEqual(code, 2)
        self.assertIn("forbidden_command_words diverge", err)

    def test_new_volatile_record_shape(self) -> None:
        code, _, err = self.fx.new_reboot()
        self.assertEqual(code, 0, err)
        record = self.fx.active()
        self.assertEqual(record["tier"], "volatile")
        self.assertEqual(record["action"]["exact_command"], ["fastboot", "reboot"])
        self.assertIsNone(record["gates"]["rollback"])
        self.assertIsNone(record["gates"]["persistent_media"])
        self.assertLessEqual(len(record), 16)

    def test_single_active_record(self) -> None:
        self.assertEqual(self.fx.new_reboot()[0], 0)
        code, _, err = self.fx.new_reboot("reboot-check-2")
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)

    def test_claim_volatile_standing_issue_and_claim(self) -> None:
        self.fx.new_reboot()
        code, out, err = self.fx.run("claim")
        self.assertEqual(code, 0, err)
        self.assertIn("exact_command=fastboot reboot", out)
        record = self.fx.active()
        self.assertEqual(record["status"], "claimed")
        self.assertEqual(record["receipt"]["authority"], "standing-policy")
        self.assertEqual(record["receipt"]["issued_at"], record["receipt"]["consumed_at"])
        ledger = self.fx.ledger_text()
        self.assertIn("operation=device_reboot", ledger)
        self.assertIn(record["receipt"]["action_digest"], ledger)

    def test_second_claim_refused(self) -> None:
        self.fx.new_reboot()
        self.assertEqual(self.fx.run("claim")[0], 0)
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("new experiment and a new receipt", err)

    def test_claim_refused_when_policy_disabled(self) -> None:
        self.fx.policy["enabled"] = False
        self.fx.flush()
        self.fx.new_reboot()
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("policy is disabled", err)

    def test_claim_refused_without_standing_scope(self) -> None:
        self.fx.policy["standing_scopes"] = [
            {"tier": "ram_rw", "operation": "ram_boot", "target": "ram"}
        ]
        self.fx.flush()
        self.fx.new_reboot()
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("no standing scope covers", err)

    def test_approve_is_dry_run(self) -> None:
        self.fx.new_reboot()
        code, out, err = self.fx.run("approve")
        self.assertEqual(code, 0, err)
        self.assertIn("dry-run", out)
        self.assertEqual(self.fx.active()["status"], "ready")
        self.assertEqual(self.fx.ledger_text(), "")

    def test_ram_boot_requires_persistent_media_ack(self) -> None:
        self.fx.write_artifact("artifacts/boot.img", b"ram-boot-bytes")
        code, _, err = self.fx.run(
            "new",
            "--experiment-id",
            "ramboot-1",
            "--operation",
            "ram_boot",
            "--artifact",
            "artifacts/boot.img",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "p",
            "--next-if-negative",
            "n",
        )
        self.assertEqual(code, 2)
        self.assertIn("userdata read-write", err)

    def test_ram_boot_with_ack_claims_and_verifies_artifact(self) -> None:
        self.fx.write_artifact("artifacts/boot.img", b"ram-boot-bytes")
        code, _, err = self.fx.run(
            "new",
            "--experiment-id",
            "ramboot-2",
            "--operation",
            "ram_boot",
            "--artifact",
            "artifacts/boot.img",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "p",
            "--next-if-negative",
            "n",
            "--acknowledge-persistent-media",
            "--rebuild-reference",
            "config/lmi-p2-d114/completed-userdata-actions-lock.json",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fx.run("claim")[0], 0)
        self.assertIn("operation=ram_boot", self.fx.ledger_text())

    def test_ram_boot_tampered_artifact_refused_at_claim(self) -> None:
        self.fx.write_artifact("artifacts/boot.img", b"ram-boot-bytes")
        self.fx.run(
            "new",
            "--experiment-id",
            "ramboot-3",
            "--operation",
            "ram_boot",
            "--artifact",
            "artifacts/boot.img",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "p",
            "--next-if-negative",
            "n",
            "--acknowledge-persistent-media",
            "--rebuild-reference",
            "rebuild via assemble_userdata_image.py",
        )
        self.fx.write_artifact("artifacts/boot.img", b"tampered-bytes!")
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("artifact", err)

    def _new_partition_write(self, experiment_id: str = "write-1") -> tuple[int, str, str]:
        return self.fx.run(
            "new",
            "--experiment-id",
            experiment_id,
            "--operation",
            "partition_write",
            "--target",
            "boot",
            "--profile",
            "profiles/d115.json",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "p",
            "--next-if-negative",
            "n",
        )

    def test_partition_write_requires_authorized_profile(self) -> None:
        profile_sha = self.fx.write_profile(
            "profiles/d115.json", "artifacts/d115-boot.img", "artifacts/d114-rollback.img"
        )
        code, _, err = self._new_partition_write()
        self.assertEqual(code, 0, err)
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("authorized_profiles", err)
        self.fx.authorize_profile("profiles/d115.json", profile_sha, ["boot"])
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 0, err)
        self.assertIn("operation=partition_write", self.fx.ledger_text())

    def test_partition_write_wrong_profile_hash_refused(self) -> None:
        profile_sha = self.fx.write_profile(
            "profiles/d115.json", "artifacts/d115-boot.img", "artifacts/d114-rollback.img"
        )
        self._new_partition_write()
        self.fx.authorize_profile("profiles/d115.json", "0" * 64, ["boot"])
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("hash does not match", err)
        del profile_sha

    def test_partition_write_target_outside_authorization_refused(self) -> None:
        profile_sha = self.fx.write_profile(
            "profiles/d115.json", "artifacts/d115-boot.img", "artifacts/d114-rollback.img"
        )
        self._new_partition_write()
        self.fx.authorize_profile("profiles/d115.json", profile_sha, ["userdata"])
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("does not cover target", err)

    def test_rollback_hash_must_differ(self) -> None:
        boot_sha = self.fx.write_artifact("artifacts/d115-boot.img", b"same-bytes")
        self.fx.write_artifact("artifacts/d114-rollback.img", b"same-bytes")
        profile = {
            "schema_version": 1,
            "release": "D-v115",
            "boot": {"path": "artifacts/d115-boot.img", "sha256": boot_sha, "size": 10},
            "rollback": {
                "target": "boot",
                "path": "artifacts/d114-rollback.img",
                "sha256": boot_sha,
                "size": 10,
            },
        }
        _write_json(self.fx.root / "profiles/d115.json", profile)
        code, _, err = self._new_partition_write()
        self.assertEqual(code, 2)
        self.assertIn("must differ", err)

    def test_repeat_guard_required_on_second_write(self) -> None:
        profile_sha = self.fx.write_profile(
            "profiles/d115.json", "artifacts/d115-boot.img", "artifacts/d114-rollback.img"
        )
        self.fx.authorize_profile("profiles/d115.json", profile_sha, ["boot"])
        self.assertEqual(self._new_partition_write("write-first")[0], 0)
        self.assertEqual(self.fx.run("claim")[0], 0)
        evidence = self.fx.write_evidence("write-first.txt", "BOOT_OK")
        self.assertEqual(self.fx.run("result", "success", "--evidence", evidence)[0], 0)
        self.assertEqual(self.fx.run("archive")[0], 0)

        self.assertEqual(self._new_partition_write("write-second")[0], 0)
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("repeat", err)

        report = self.fx.write_evidence("write-second-reason.txt", "NEW_EVIDENCE")
        (self.fx.root / "notes/bringup-active.json").unlink()
        code, _, err = self.fx.run(
            "new",
            "--experiment-id",
            "write-second-guarded",
            "--operation",
            "partition_write",
            "--target",
            "boot",
            "--profile",
            "profiles/d115.json",
            "--hypothesis",
            "h2",
            "--discriminator",
            "d2",
            "--next-if-positive",
            "p2",
            "--next-if-negative",
            "n2",
            "--repeat-prior-experiment",
            "write-first",
            "--repeat-changed-discriminator",
            "new discriminator after evidence review",
            "--repeat-evidence-report",
            report,
        )
        self.assertEqual(code, 0, err)
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 0, err)

    def test_result_requires_route_status_evidence(self) -> None:
        self.fx.new_reboot()
        self.fx.run("claim")
        bad = self.fx.root / "logs" / "bad.txt"
        bad.write_text("no route marker here\n", encoding="utf-8")
        code, _, err = self.fx.run("result", "success", "--evidence", "logs/bad.txt")
        self.assertEqual(code, 2)
        self.assertIn("route_status", err)

    def test_result_rejects_evidence_outside_logs(self) -> None:
        self.fx.new_reboot()
        self.fx.run("claim")
        stray = self.fx.root / "notes" / "evidence.txt"
        stray.write_text("route_status=OK\n", encoding="utf-8")
        code, _, err = self.fx.run("result", "success", "--evidence", "notes/evidence.txt")
        self.assertEqual(code, 2)
        self.assertIn("logs/", err)

    def test_result_rejects_symlink_evidence(self) -> None:
        self.fx.new_reboot()
        self.fx.run("claim")
        real = self.fx.root / "notes" / "real.txt"
        real.write_text("route_status=OK\n", encoding="utf-8")
        os.symlink(real, self.fx.root / "logs" / "link.txt")
        code, _, err = self.fx.run("result", "success", "--evidence", "logs/link.txt")
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)

    def test_result_before_claim_refused(self) -> None:
        self.fx.new_reboot()
        evidence = self.fx.write_evidence()
        code, _, err = self.fx.run("result", "success", "--evidence", evidence)
        self.assertEqual(code, 2)
        self.assertIn("claimed", err)

    def test_archive_and_duplicate_refused(self) -> None:
        self.fx.new_reboot()
        self.fx.run("claim")
        evidence = self.fx.write_evidence()
        self.fx.run("result", "unknown", "--evidence", evidence)
        code, out, err = self.fx.run("archive")
        self.assertEqual(code, 0, err)
        archived = self.fx.root / "notes/bringup-completed/reboot-check-1.json"
        self.assertTrue(archived.is_file())
        self.assertFalse((self.fx.root / "notes/bringup-active.json").exists())
        self.fx.new_reboot()
        self.fx.run("claim")
        self.fx.run("result", "unknown", "--evidence", evidence)
        code, _, err = self.fx.run("archive")
        self.assertEqual(code, 2)
        self.assertIn("already exists", err)
        del out

    def test_read_only_record_cannot_claim(self) -> None:
        code, _, err = self.fx.run(
            "new",
            "--experiment-id",
            "observe-1",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "p",
            "--next-if-negative",
            "n",
        )
        self.assertEqual(code, 0, err)
        record = self.fx.active()
        self.assertEqual(record["tier"], "read_only")
        self.assertNotIn("action", record)
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("read_only", err)
        evidence = self.fx.write_evidence("observe.txt")
        self.assertEqual(self.fx.run("result", "success", "--evidence", evidence)[0], 0)
        self.assertEqual(self.fx.run("archive")[0], 0)

    def test_tampered_exact_command_refused(self) -> None:
        self.fx.new_reboot()
        self.fx.patch_active(
            lambda record: record["action"].__setitem__(
                "exact_command", ["fastboot", "reboot", "--force"]
            )
        )
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("exact_command", err)

    def test_policy_rejects_persistent_standing_scope(self) -> None:
        self.fx.policy["standing_scopes"].append(
            {"tier": "persistent", "operation": "partition_write", "target": "boot"}
        )
        self.fx.flush()
        code, _, err = self.fx.run("validate")
        self.assertEqual(code, 2)
        self.assertIn("authorized_profiles", err)

    def test_next_hypotheses_must_differ(self) -> None:
        code, _, err = self.fx.run(
            "new",
            "--experiment-id",
            "same-next-1",
            "--operation",
            "device_reboot",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "same",
            "--next-if-negative",
            "same",
        )
        self.assertEqual(code, 2)
        self.assertIn("must differ", err)

    def test_observe_appends_sidecar(self) -> None:
        self.fx.new_reboot()
        code, _, err = self.fx.run("observe", "--note", "panel stayed dark")
        self.assertEqual(code, 0, err)
        self.assertEqual(self.fx.active()["observations"][0]["note"], "panel stayed dark")


if __name__ == "__main__":
    unittest.main()
