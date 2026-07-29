from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import tempfile
import unittest
from unittest import mock

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
        engine = root / bringup_loop.ENGINE_REL
        engine.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Path(bringup_loop.__file__), engine)
        self.git("init", "-q")
        self.git("config", "user.name", "Governance Test")
        self.git("config", "user.email", "governance-test@example.invalid")
        self.git(
            "add",
            "--",
            bringup_loop.ENGINE_REL,
            "config/governance/constants.json",
            "config/governance/policy.json",
        )
        self.git("commit", "-q", "-m", "initial governance TCB")

    def flush(self) -> None:
        _write_json(self.root / "config/governance/constants.json", self.constants)
        _write_json(self.root / "config/governance/policy.json", self.policy)

    def git(self, *arguments: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", "-C", str(self.root), *arguments],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def commit_paths(self, *paths: str, message: str = "update test fixture") -> None:
        self.git("add", "--", *paths)
        self.git("commit", "-q", "-m", message)

    def write_artifact(self, rel: str, data: bytes) -> str:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return bringup_loop.sha256_bytes(data)

    def write_profile(
        self, rel: str, boot_rel: str, rollback_rel: str, *, commit: bool = True
    ) -> str:
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
        if commit:
            self.commit_paths(rel, message=f"add {rel}")
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

    def authorize_profile_via_cli(
        self,
        rel: str,
        target: str,
        note: str = "owner reviewed candidate and rollback pins",
    ) -> tuple[int, str, str]:
        with mock.patch.object(bringup_loop, "_confirm_authorization") as confirmation:
            result = self.run(
                "authorize-profile",
                "--profile",
                rel,
                "--target",
                target,
                "--note",
                note,
            )
        confirmation.assert_called_once()
        self.assert_confirmation_shape(confirmation.call_args.args[0])
        return result

    @staticmethod
    def assert_confirmation_shape(value: str) -> None:
        prefix = "AUTHORIZE-PERSISTENT "
        if not value.startswith(prefix) or len(value.removeprefix(prefix)) != 64:
            raise AssertionError(f"unexpected authorization confirmation: {value}")

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

    def new_ram(
        self, artifact: str, experiment_id: str = "ramboot-security"
    ) -> tuple[int, str, str]:
        return self.run(
            "new",
            "--experiment-id",
            experiment_id,
            "--operation",
            "ram_boot",
            "--artifact",
            artifact,
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
            "rebuild fixture userdata",
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

    def test_claim_loads_constants_after_entering_lock(self) -> None:
        self.assertEqual(self.fx.new_reboot()[0], 0)

        class MutateOnEnter:
            def __enter__(inner_self):
                self.fx.constants["expected_product"] = "different-product"
                self.fx.flush()

            def __exit__(inner_self, exc_type, exc, traceback):
                return False

        with mock.patch.object(
            bringup_loop, "governance_lock", return_value=MutateOnEnter()
        ):
            code, _, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertIn("expected_product", err)

    def test_preflight_is_dry_run(self) -> None:
        self.fx.new_reboot()
        code, out, err = self.fx.run("preflight")
        self.assertEqual(code, 0, err)
        self.assertIn("dry-run", out)
        self.assertEqual(self.fx.active()["status"], "ready")
        self.assertEqual(self.fx.ledger_text(), "")

    def test_authorize_profile_is_host_only_and_claim_can_follow(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        code, out, err = self.fx.authorize_profile_via_cli(
            "profiles/d115.json", "boot"
        )
        self.assertEqual(code, 0, err)
        self.assertIn("authorization recorded", out)
        self.assertIn("no claim or device action executed", out)
        self.assertIn("git_head=", out)
        self.assertIn("engine_sha256=", out)
        self.assertIn("constants_sha256=", out)
        self.assertNotIn("exact_command", out)
        self.assertFalse((self.fx.root / "notes/bringup-active.json").exists())
        self.assertEqual(self.fx.ledger_text(), "")

        policy = json.loads(
            (self.fx.root / "config/governance/policy.json").read_text()
        )
        self.assertRegex(policy["revision"], r"^\d{4}-\d{2}-\d{2}\.[1-9]\d*$")
        self.assertNotEqual(policy["revision"], "2026-07-22.1")
        self.assertEqual(len(policy["authorized_profiles"]), 1)
        entry = policy["authorized_profiles"][0]
        self.assertEqual(entry["profile_path"], "profiles/d115.json")
        self.assertEqual(entry["targets"], ["boot"])
        self.assertEqual(entry["authorized_by"], "ian")
        self.assertIn("authorization_digest=", entry["note"])

        code, _, err = self._new_partition_write()
        self.assertEqual(code, 0, err)
        code, _, err = self.fx.run("claim")
        self.assertEqual(code, 0, err)

    def test_authorize_profile_refuses_non_tty_without_mutating_policy(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        before = policy_path.read_bytes()
        with mock.patch("sys.stdin", io.StringIO("")):
            code, _, err = self.fx.run(
                "authorize-profile",
                "--profile",
                "profiles/d115.json",
                "--target",
                "boot",
                "--note",
                "owner review",
            )
        self.assertEqual(code, 2)
        self.assertIn("interactive TTY", err)
        self.assertEqual(policy_path.read_bytes(), before)

    def test_authorize_profile_refuses_wrong_confirmation(self) -> None:
        class WrongTTY(io.StringIO):
            def isatty(self) -> bool:
                return True

        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        before = policy_path.read_bytes()
        with mock.patch("sys.stdin", WrongTTY("AUTHORIZE-PERSISTENT wrong\n")):
            code, _, err = self.fx.run(
                "authorize-profile",
                "--profile",
                "profiles/d115.json",
                "--target",
                "boot",
                "--note",
                "owner review",
            )
        self.assertEqual(code, 2)
        self.assertIn("did not match exactly", err)
        self.assertEqual(policy_path.read_bytes(), before)

    def test_authorize_profile_requires_safe_idle(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        self.assertEqual(self.fx.new_reboot()[0], 0)
        policy_path = self.fx.root / "config/governance/policy.json"
        before = policy_path.read_bytes()
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("requires safe idle", err)
        self.assertEqual(policy_path.read_bytes(), before)

    def test_authorize_profile_rechecks_after_confirmation(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        before = policy_path.read_bytes()

        def tamper_after_preview(_expected: str) -> None:
            (self.fx.root / "artifacts/d115-boot.img").write_bytes(b"changed")

        with mock.patch.object(
            bringup_loop,
            "_confirm_authorization",
            side_effect=tamper_after_preview,
        ):
            code, _, err = self.fx.run(
                "authorize-profile",
                "--profile",
                "profiles/d115.json",
                "--target",
                "boot",
                "--note",
                "owner review",
            )
        self.assertEqual(code, 2)
        self.assertIn("artifact", err)
        self.assertEqual(policy_path.read_bytes(), before)

    def test_authorize_profile_rejects_repo_escape_and_symlink(self) -> None:
        outside = Path(self._tmp.name).parent / "outside-governance-profile.json"
        outside.write_text("{}\n", encoding="utf-8")
        self.addCleanup(lambda: outside.unlink(missing_ok=True))
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "../outside-governance-profile.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("inside the repository", err)

        self.fx.write_profile(
            "profiles/real.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        os.symlink("real.json", self.fx.root / "profiles/link.json")
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/link.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)

    def test_authorize_profile_is_idempotent_and_conflicts_fail_closed(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        self.assertEqual(
            self.fx.authorize_profile_via_cli("profiles/d115.json", "boot")[0],
            0,
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        authorized = policy_path.read_bytes()
        self.fx.commit_paths(
            "config/governance/policy.json",
            message="record reviewed test authorization",
        )
        code, out, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "different note does not rewrite an existing authorization",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("already authorized", out)
        self.assertEqual(policy_path.read_bytes(), authorized)

        profile_path = self.fx.root / "profiles/d115.json"
        profile = json.loads(profile_path.read_text())
        profile["release"] = "D-v116"
        _write_json(profile_path, profile)
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "attempted dirty replacement",
        )
        self.assertEqual(code, 2)
        self.assertIn("dirty", err)
        self.fx.commit_paths(
            "profiles/d115.json", message="stage reviewed conflicting profile"
        )
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "attempted replacement",
        )
        self.assertEqual(code, 2)
        self.assertIn("different authorization", err)
        self.assertEqual(policy_path.read_bytes(), authorized)

    def test_authorize_profile_rejects_disabled_policy_and_duplicate_json(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        self.fx.policy["enabled"] = False
        self.fx.flush()
        self.fx.commit_paths(
            "config/governance/policy.json", message="disable test policy"
        )
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("policy is disabled", err)

        self.fx.policy["enabled"] = True
        self.fx.flush()
        self.fx.commit_paths(
            "config/governance/policy.json", message="enable test policy"
        )
        duplicate = self.fx.root / "profiles/duplicate.json"
        duplicate.write_text(
            '{"boot":{"path":"a","path":"b","sha256":"'
            + ("0" * 64)
            + '","size":1},"rollback":{}}\n',
            encoding="utf-8",
        )
        self.fx.commit_paths(
            "profiles/duplicate.json", message="add malformed test profile"
        )
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/duplicate.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("duplicate key", err)

    def test_authorize_profile_requires_clean_tracked_profile_states(self) -> None:
        self.fx.write_profile(
            "profiles/untracked.json",
            "artifacts/untracked.img",
            "artifacts/untracked-rollback.img",
            commit=False,
        )
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/untracked.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("tracked at Git HEAD", err)

    def test_authorize_profile_requires_profiles_directory(self) -> None:
        self.fx.write_profile(
            "reviewed/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "reviewed/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("under profiles/", err)

    def test_authorize_profile_rejects_dirty_and_staged_profile(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        profile_path = self.fx.root / "profiles/d115.json"
        profile_path.write_text(profile_path.read_text() + " \n", encoding="utf-8")
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("dirty", err)

        profile = json.loads(profile_path.read_text())
        profile["release"] = "D-v116"
        _write_json(profile_path, profile)
        self.fx.git("add", "--", "profiles/d115.json")
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("staged", err)

    def test_authorize_profile_rejects_dirty_staged_and_untracked_tcb(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        engine = self.fx.root / bringup_loop.ENGINE_REL
        engine.write_text(engine.read_text() + "\n# dirty test\n", encoding="utf-8")
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("dirty", err)

        self.fx.git("restore", "--", bringup_loop.ENGINE_REL)
        self.fx.constants["battery_floor_mv"] += 1
        self.fx.flush()
        self.fx.git("add", "--", "config/governance/constants.json")
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("staged", err)

        self.fx.git("restore", "--staged", "config/governance/constants.json")
        self.fx.git("restore", "--", "config/governance/constants.json")
        self.fx.git("rm", "--cached", "config/governance/policy.json")
        self.fx.git("commit", "-q", "-m", "remove policy from HEAD for test")
        code, _, err = self.fx.run(
            "authorize-profile",
            "--profile",
            "profiles/d115.json",
            "--target",
            "boot",
            "--note",
            "owner review",
        )
        self.assertEqual(code, 2)
        self.assertIn("tracked at Git HEAD", err)

    def test_authorize_profile_binds_tcb_and_git_head_after_confirmation(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        before = policy_path.read_bytes()

        def dirty_engine(_expected: str) -> None:
            engine = self.fx.root / bringup_loop.ENGINE_REL
            engine.write_text(engine.read_text() + "\n# post-confirm drift\n")

        with mock.patch.object(
            bringup_loop, "_confirm_authorization", side_effect=dirty_engine
        ):
            code, _, err = self.fx.run(
                "authorize-profile",
                "--profile",
                "profiles/d115.json",
                "--target",
                "boot",
                "--note",
                "owner review",
            )
        self.assertEqual(code, 2)
        self.assertIn("dirty", err)
        self.assertEqual(policy_path.read_bytes(), before)

        self.fx.git("restore", "--", bringup_loop.ENGINE_REL)

        def advance_head(_expected: str) -> None:
            marker = self.fx.root / "head-drift.txt"
            marker.write_text("new commit\n", encoding="utf-8")
            self.fx.commit_paths("head-drift.txt", message="advance HEAD during test")

        with mock.patch.object(
            bringup_loop, "_confirm_authorization", side_effect=advance_head
        ):
            code, _, err = self.fx.run(
                "authorize-profile",
                "--profile",
                "profiles/d115.json",
                "--target",
                "boot",
                "--note",
                "owner review",
            )
        self.assertEqual(code, 2)
        self.assertIn("Git HEAD", err)
        self.assertEqual(policy_path.read_bytes(), before)

    def test_authorize_profile_rechecks_safe_idle_after_confirmation(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )

        def create_active(_expected: str) -> None:
            self.assertEqual(self.fx.new_reboot()[0], 0)

        with mock.patch.object(
            bringup_loop, "_confirm_authorization", side_effect=create_active
        ):
            code, _, err = self.fx.run(
                "authorize-profile",
                "--profile",
                "profiles/d115.json",
                "--target",
                "boot",
                "--note",
                "owner review",
            )
        self.assertEqual(code, 2)
        self.assertIn("active experiment appeared", err)

    def test_authorize_profile_rejects_unsafe_note_text(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        before = policy_path.read_bytes()
        for note, expected in (
            (" owner review", "leading or trailing"),
            ("owner\treview", "control or formatting"),
            ("owner\u202ereview", "control or formatting"),
        ):
            with self.subTest(note=repr(note)):
                code, _, err = self.fx.run(
                    "authorize-profile",
                    "--profile",
                    "profiles/d115.json",
                    "--target",
                    "boot",
                    "--note",
                    note,
                )
                self.assertEqual(code, 2)
                self.assertIn(expected, err)
                self.assertEqual(policy_path.read_bytes(), before)

    def test_authorize_profile_ignores_hostile_git_environment(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        hostile = {
            "GIT_DIR": str(self.fx.root / "does-not-exist"),
            "GIT_INDEX_FILE": str(self.fx.root / "fake-index"),
            "GIT_OBJECT_DIRECTORY": str(self.fx.root / "fake-objects"),
            "GIT_CONFIG_GLOBAL": str(self.fx.root / "fake-gitconfig"),
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            code, _, err = self.fx.authorize_profile_via_cli(
                "profiles/d115.json", "boot"
            )
        self.assertEqual(code, 0, err)

    def test_policy_atomic_write_preserves_mode_and_cleans_failed_temp(self) -> None:
        self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        policy_path = self.fx.root / "config/governance/policy.json"
        policy_path.chmod(0o640)
        code, _, err = self.fx.authorize_profile_via_cli(
            "profiles/d115.json", "boot"
        )
        self.assertEqual(code, 0, err)
        self.assertEqual(policy_path.stat().st_mode & 0o777, 0o640)

        self.fx.commit_paths(
            "config/governance/policy.json",
            message="commit first authorization for failure test",
        )
        profile = json.loads((self.fx.root / "profiles/d115.json").read_text())
        profile["release"] = "D-v116"
        _write_json(self.fx.root / "profiles/d116.json", profile)
        self.fx.commit_paths("profiles/d116.json", message="add second test profile")
        before = policy_path.read_bytes()
        with mock.patch.object(
            bringup_loop.os, "rename", side_effect=OSError("simulated rename failure")
        ):
            with mock.patch.object(bringup_loop, "_confirm_authorization"):
                code, _, err = self.fx.run(
                    "authorize-profile",
                    "--profile",
                    "profiles/d116.json",
                    "--target",
                    "boot",
                    "--note",
                    "owner review",
                )
        self.assertEqual(code, 2)
        self.assertIn("filesystem operation failed", err)
        self.assertEqual(policy_path.read_bytes(), before)
        self.assertFalse(
            any(
                path.name.startswith(".tmp-")
                for path in policy_path.parent.iterdir()
            )
        )

    def test_repo_paths_reject_control_noncanonical_and_unsafe_file_types(self) -> None:
        for unsafe, expected in (
            ("artifacts/boot\n.img", "control or formatting character"),
            ("profiles/candidate\u202egnp.json", "control or formatting character"),
            ("artifacts//boot.img", "canonical"),
        ):
            with self.subTest(path=unsafe):
                code, _, err = self.fx.new_ram(unsafe)
                self.assertEqual(code, 2)
                self.assertIn(expected, err)

        real_dir = self.fx.root / "real-artifacts"
        real_dir.mkdir()
        (real_dir / "boot.img").write_bytes(b"boot")
        os.symlink("real-artifacts", self.fx.root / "artifact-link")
        code, _, err = self.fx.new_ram("artifact-link/boot.img")
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)

        artifacts = self.fx.root / "artifacts"
        artifacts.mkdir(exist_ok=True)
        os.symlink("../real-artifacts/boot.img", artifacts / "leaf-link.img")
        code, _, err = self.fx.new_ram("artifacts/leaf-link.img")
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)

        source = artifacts / "hardlink-source.img"
        source.write_bytes(b"hardlink")
        os.link(source, artifacts / "hardlink.img")
        code, _, err = self.fx.new_ram("artifacts/hardlink.img")
        self.assertEqual(code, 2)
        self.assertIn("hard-linked", err)

        os.mkfifo(artifacts / "fifo.img")
        code, _, err = self.fx.new_ram("artifacts/fifo.img")
        self.assertEqual(code, 2)
        self.assertIn("not a regular file", err)

    def test_repo_paths_reject_untrusted_writable_metadata(self) -> None:
        artifact = self.fx.root / "artifacts/writable.img"
        artifact.parent.mkdir(exist_ok=True)
        artifact.write_bytes(b"writable")
        artifact.chmod(0o666)
        code, _, err = self.fx.new_ram("artifacts/writable.img")
        self.assertEqual(code, 2)
        self.assertIn("group/world writable", err)

        artifact.chmod(0o600)
        artifact.parent.chmod(0o777)
        code, _, err = self.fx.new_ram("artifacts/writable.img")
        self.assertEqual(code, 2)
        self.assertIn("directory ancestry is group/world writable", err)

        artifact.parent.chmod(0o755)
        policy_path = self.fx.root / "config/governance/policy.json"
        policy_path.chmod(0o666)
        code, _, err = self.fx.run("validate")
        self.assertEqual(code, 2)
        self.assertIn("policy is group/world writable", err)

    def test_safe_metadata_rejects_untrusted_owner(self) -> None:
        unsafe_stat = mock.Mock(
            st_uid=max(os.geteuid(), 0) + 1,
            st_mode=0o100600,
        )
        with self.assertRaisesRegex(
            bringup_loop.Refusal,
            "untrusted owner",
        ):
            bringup_loop._validate_safe_owner_mode(
                unsafe_stat,
                "profiles/reviewed.json",
                "profile",
            )

    def test_governance_lock_rejects_symlink_and_hardlink(self) -> None:
        claims = self.fx.root / "notes/bringup-claims"
        claims.mkdir()
        target = self.fx.root / "notes/lock-target"
        target.write_text("", encoding="utf-8")
        os.symlink("../lock-target", claims / ".lock")
        code, _, err = self.fx.new_reboot()
        self.assertEqual(code, 2)
        self.assertIn("symlink", err)

        (claims / ".lock").unlink()
        os.link(target, claims / ".lock")
        code, _, err = self.fx.new_reboot()
        self.assertEqual(code, 2)
        self.assertIn("hard-linked", err)

    def test_large_partition_artifacts_are_hashed_in_bounded_chunks(self) -> None:
        chunk = bringup_loop.HASH_CHUNK_SIZE
        boot = b"B" * (chunk * 2 + 17)
        rollback = b"R" * (chunk * 2 + 31)
        boot_sha = self.fx.write_artifact("artifacts/d115-boot.img", boot)
        rollback_sha = self.fx.write_artifact(
            "artifacts/d114-rollback.img", rollback
        )
        _write_json(
            self.fx.root / "profiles/d115.json",
            {
                "schema_version": 1,
                "release": "D-v115",
                "boot": {
                    "path": "artifacts/d115-boot.img",
                    "sha256": boot_sha,
                    "size": len(boot),
                },
                "rollback": {
                    "target": "boot",
                    "path": "artifacts/d114-rollback.img",
                    "sha256": rollback_sha,
                    "size": len(rollback),
                },
            },
        )
        real_read = os.read
        requests = []

        def bounded_read(file_fd: int, count: int) -> bytes:
            requests.append(count)
            return real_read(file_fd, count)

        with mock.patch.object(bringup_loop.os, "read", side_effect=bounded_read):
            code, _, err = self._new_partition_write()
        self.assertEqual(code, 0, err)
        self.assertLessEqual(max(requests), chunk)
        self.assertGreaterEqual(requests.count(chunk), 4)
        self.assertEqual(self.fx.active()["action"]["artifact_size"], len(boot))

    def test_partial_claim_commit_retains_guard_and_never_reissues(self) -> None:
        self.assertEqual(self.fx.new_reboot()[0], 0)
        original_atomic_write = bringup_loop.atomic_write_repo_json

        def fail_active_write(paths, rel_path, value, **kwargs):
            if rel_path == paths.active_rel:
                raise OSError("simulated active write failure")
            return original_atomic_write(paths, rel_path, value, **kwargs)

        with mock.patch.object(
            bringup_loop,
            "atomic_write_repo_json",
            side_effect=fail_active_write,
        ):
            code, out, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertNotIn("exact_command=", out)
        self.assertIn("replay guard", err)
        self.assertEqual(self.fx.active()["status"], "ready")
        self.assertTrue(
            (
                self.fx.root
                / "notes/bringup-claims/reboot-check-1.claim-guard.json"
            ).is_file()
        )

        code, out, err = self.fx.run("claim")
        self.assertEqual(code, 2)
        self.assertNotIn("exact_command=", out)
        self.assertIn("will not be reissued", err)
        self.assertEqual(self.fx.active()["status"], "ready")

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
        self.fx.run(
            "new",
            "--experiment-id",
            "reboot-check-1",
            "--hypothesis",
            "h",
            "--discriminator",
            "d",
            "--next-if-positive",
            "p",
            "--next-if-negative",
            "n",
        )
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

    def test_policy_profile_owner_must_match_top_level_owner(self) -> None:
        profile_sha = self.fx.write_profile(
            "profiles/d115.json",
            "artifacts/d115-boot.img",
            "artifacts/d114-rollback.img",
        )
        self.fx.authorize_profile("profiles/d115.json", profile_sha, ["boot"])
        self.fx.policy["authorized_profiles"][0]["authorized_by"] = "someone-else"
        self.fx.flush()
        code, _, err = self.fx.run("validate")
        self.assertEqual(code, 2)
        self.assertIn("must equal policy authorized_by", err)

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
