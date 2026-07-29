"""Focused unit tests for scripts/lmi_d110_session.py.

The module holds the Python bodies lifted out of the D110 RAM-boot helper's
heredocs. The end-to-end contract is still covered by
test_hardware_helper_safety.py through the shell script; these tests exercise
the lifted functions in isolation — the policy validator and the
grant/receipt state machine were previously untestable without driving the
whole script.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

try:
    from tests.lmi_p1.test_hardware_helper_safety import D110GateFixture
except ImportError:  # unittest discover -s tests/lmi_p1 imports top-level names
    from test_hardware_helper_safety import D110GateFixture


REPO = Path(__file__).resolve().parents[2]
STAGE_SCRIPT = REPO / "scripts/72_stage_downstream_ssh_wifi_test.sh"
MODULE_PATH = REPO / "scripts/lmi_d110_session.py"
POLICY_FAILURE = "private D110 policy or pinned local evidence validation failed"

_spec = importlib.util.spec_from_file_location("lmi_d110_session", MODULE_PATH)
assert _spec is not None and _spec.loader is not None
session = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(session)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class SessionModulePinTests(unittest.TestCase):
    def test_stage_script_pin_matches_the_real_module_hash(self) -> None:
        module_hash = digest(MODULE_PATH)
        script = STAGE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            f"readonly TRUSTED_SESSION_MODULE_SHA256='{module_hash}'", script
        )

    def test_stage_script_keeps_isolated_interpreter_and_fd3_serial_protocol(self) -> None:
        script = STAGE_SCRIPT.read_text(encoding="utf-8")
        self.assertIn(
            '/usr/bin/python3 -I -S -B "$session_module_exec" device-identity '
            '"$privacy_nonce" "$expected_identity" "$historical_fingerprint" '
            '3<<< "$device_serial"',
            script,
        )
        for line in script.splitlines():
            if "$session_module_exec" in line and "python3" in line:
                self.assertIn("/usr/bin/python3 -I -S -B", line)
                # The raw serial must never be an argv item; it is only ever
                # attached via the fd-3 herestring redirection.
                self.assertNotIn("$device_serial", line.split("3<<<")[0])
        self.assertNotIn(
            '/usr/bin/python3 -I -S -B "$session_module" ',
            script,
        )
        self.assertIn('exec 9<"$session_module"', script)
        self.assertIn(
            "readonly session_module_exec=/proc/self/fd/$session_module_fd",
            script,
        )
        # The module pin is captured in the main flow before the first module
        # invocation (capture_helper_identity).
        self.assertLess(
            script.index("\ncapture_session_module\n"),
            script.index("\ncapture_helper_identity\n"),
        )

    def test_module_contains_no_fastboot_invocation(self) -> None:
        text = MODULE_PATH.read_text(encoding="utf-8")
        self.assertNotIn("subprocess", text)
        self.assertNotIn("os.exec", text)
        self.assertNotIn("os.system", text)


class ParseUintTests(unittest.TestCase):
    def test_accepts_decimal_and_hex_within_63_bits(self) -> None:
        self.assertEqual(session.parse_uint("0"), 0)
        self.assertEqual(session.parse_uint("4200"), 4200)
        self.assertEqual(session.parse_uint("0x10000000"), 268435456)
        self.assertEqual(session.parse_uint("0XFF"), 255)
        self.assertEqual(session.parse_uint("9223372036854775807"), 2**63 - 1)

    def test_rejects_malformed_negative_and_oversized_values(self) -> None:
        for value in (
            "",
            "-1",
            "1e3",
            "0x",
            "0x1234567890abcdef0",  # 17 hex digits
            "12345678901234567890",  # 20 decimal digits
            "9223372036854775808",  # 2**63
            "10 ",
            "0b101",
        ):
            with self.subTest(value=value):
                with self.assertRaises(SystemExit):
                    session.parse_uint(value)


class DeviceIdentityTests(unittest.TestCase):
    serial = "SYNTHETIC-LMI-01"
    nonce = "1" * 64

    def scoped(self, serial: str) -> str:
        return hashlib.sha256(
            self.nonce.encode("ascii") + b"\0" + serial.encode("ascii")
        ).hexdigest()

    def legacy(self, serial: str) -> str:
        return hashlib.sha256(serial.encode("ascii")).hexdigest()[:16]

    def test_matching_serial_passes_with_and_without_trailing_newline(self) -> None:
        for raw in (self.serial, self.serial + "\n"):
            session.verify_private_device_identity(
                self.nonce, self.scoped(self.serial), self.legacy(self.serial), raw
            )

    def test_wrong_serial_wrong_history_and_bad_charset_fail(self) -> None:
        good_scoped = self.scoped(self.serial)
        good_legacy = self.legacy(self.serial)
        cases = (
            (self.nonce, good_scoped, good_legacy, "OTHER-HANDSET"),
            (self.nonce, good_scoped, self.legacy("OTHER"), self.serial),
            (self.nonce, self.scoped("OTHER"), good_legacy, self.serial),
            (self.nonce, good_scoped, good_legacy, "bad serial with spaces"),
            (self.nonce, good_scoped, good_legacy, ""),
            (self.nonce, good_scoped, good_legacy, "evil\nSYNTHETIC-LMI-01"),
        )
        for case in cases:
            with self.subTest(case=case):
                with self.assertRaises(SystemExit):
                    session.verify_private_device_identity(*case)


class SessionScopeTests(unittest.TestCase):
    def test_valid_thread_id_yields_two_hex_bindings_and_is_deterministic(self) -> None:
        first = session.capture_session_scope({"CODEX_THREAD_ID": "thread-a"})
        second = session.capture_session_scope({"CODEX_THREAD_ID": "thread-a"})
        other = session.capture_session_scope({"CODEX_THREAD_ID": "thread-b"})
        self.assertEqual(first, second)
        thread_binding, boot_binding = first.split("\t")
        self.assertRegex(thread_binding, r"^[0-9a-f]{64}$")
        self.assertRegex(boot_binding, r"^[0-9a-f]{64}$")
        self.assertNotEqual(first.split("\t")[0], other.split("\t")[0])
        self.assertEqual(first.split("\t")[1], other.split("\t")[1])

    def test_missing_oversized_and_control_character_thread_ids_fail(self) -> None:
        for environ in (
            {},
            {"CODEX_THREAD_ID": ""},
            {"CODEX_THREAD_ID": "x" * 513},
            {"CODEX_THREAD_ID": "bad\x1fthread"},
            {"CODEX_THREAD_ID": "bad\x7fthread"},
        ):
            with self.subTest(environ=environ):
                with self.assertRaises(SystemExit):
                    session.capture_session_scope(environ)

    def test_malformed_host_boot_id_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            boot_id = Path(temporary) / "boot_id"
            boot_id.write_text("not-a-uuid\n", encoding="ascii")
            with self.assertRaises(SystemExit):
                session.capture_session_scope(
                    {"CODEX_THREAD_ID": "thread-a"}, boot_id_path=str(boot_id)
                )
            missing = Path(temporary) / "absent"
            with self.assertRaises(SystemExit):
                session.capture_session_scope(
                    {"CODEX_THREAD_ID": "thread-a"}, boot_id_path=str(missing)
                )


class GrantStorageAndStateMachineTests(unittest.TestCase):
    thread_binding = hashlib.sha256(b"unit-thread").hexdigest()
    host_boot = hashlib.sha256(b"unit-boot").hexdigest()
    policy_sha = "a" * 64
    action_digest = "b" * 64
    boot_sha = "c" * 64
    device_identity = "d" * 64
    fastboot_sha = "e" * 64
    fastboot_identity = "1:2:81a4:1:100:x:y"
    stage = "ramboot"
    helper_sha = "f" * 64
    session_max = "43200"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.parent = Path(self.temp_dir.name) / "private-parent"
        self.parent.mkdir(mode=0o700)
        self.parent.chmod(0o700)
        self.grant_dir = self.parent / "grants"

    def grant_args(self, **overrides: str) -> list[str]:
        values = {
            "grant_dir": str(self.grant_dir),
            "thread_binding": self.thread_binding,
            "host_boot": self.host_boot,
            "policy_sha": self.policy_sha,
            "action_digest": self.action_digest,
            "boot_sha": self.boot_sha,
            "device_identity": self.device_identity,
            "fastboot_sha": self.fastboot_sha,
            "fastboot_identity": self.fastboot_identity,
            "stage": self.stage,
            "helper_sha": self.helper_sha,
            "session_max": self.session_max,
        }
        values.update(overrides)
        return list(values.values())

    def verify_args(self, grant_path: str, **overrides: str) -> list[str]:
        return [grant_path] + self.grant_args(**overrides)[1:]

    def test_storage_validate_fails_before_create_and_succeeds_after(self) -> None:
        with self.assertRaises(SystemExit):
            session.prepare_session_storage(str(self.grant_dir), "validate")
        session.prepare_session_storage(str(self.grant_dir), "create")
        session.prepare_session_storage(str(self.grant_dir), "validate")
        self.assertEqual(self.grant_dir.stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.grant_dir / "active").stat().st_mode & 0o777, 0o700)
        self.assertEqual((self.grant_dir / "revoked").stat().st_mode & 0o777, 0o700)
        lock = self.grant_dir / "execute.lock"
        self.assertTrue(lock.is_file())
        self.assertEqual(lock.stat().st_mode & 0o777, 0o600)

    def test_storage_with_unsafe_parent_mode_fails(self) -> None:
        self.parent.chmod(0o755)
        with self.assertRaises(SystemExit):
            session.prepare_session_storage(str(self.grant_dir), "create")

    def test_grant_create_verify_revoke_lifecycle(self) -> None:
        session.prepare_session_storage(str(self.grant_dir), "create")
        grant_path = session.create_session_grant(*self.grant_args())
        expected_path = (
            self.grant_dir / "active" / f"grant-{self.thread_binding}.json"
        )
        self.assertEqual(grant_path, str(expected_path))
        record = json.loads(expected_path.read_text(encoding="ascii"))
        self.assertEqual(record["schema"], "lmi-d110-codex-session-grant/v1")
        self.assertEqual(record["operation"], "fastboot boot")
        self.assertEqual(
            record["expires_at_epoch"] - record["issued_at_epoch"],
            int(self.session_max),
        )
        self.assertEqual(expected_path.stat().st_mode & 0o777, 0o600)

        session.verify_session_grant(*self.verify_args(grant_path))

        session.revoke_session_grant(str(self.grant_dir), self.thread_binding)
        self.assertFalse(expected_path.exists())
        revoked = self.grant_dir / "revoked" / expected_path.name
        self.assertTrue(revoked.is_file())
        with self.assertRaises(SystemExit):
            session.verify_session_grant(*self.verify_args(grant_path))
        with self.assertRaises(SystemExit):
            session.revoke_session_grant(str(self.grant_dir), self.thread_binding)

    def test_grant_verify_rejects_any_changed_binding_field(self) -> None:
        session.prepare_session_storage(str(self.grant_dir), "create")
        grant_path = session.create_session_grant(*self.grant_args())
        for field, value in (
            ("thread_binding", "9" * 64),
            ("host_boot", "9" * 64),
            ("policy_sha", "9" * 64),
            ("action_digest", "9" * 64),
            ("boot_sha", "9" * 64),
            ("device_identity", "9" * 64),
            ("fastboot_sha", "9" * 64),
            ("fastboot_identity", "9:9:9"),
            ("stage", "rootfs"),
            ("helper_sha", "9" * 64),
            ("session_max", "43201"),
        ):
            with self.subTest(field=field):
                with self.assertRaises(SystemExit):
                    session.verify_session_grant(
                        *self.verify_args(grant_path, **{field: value})
                    )
        session.verify_session_grant(*self.verify_args(grant_path))

    def test_grant_verify_rejects_expired_tampered_and_hardlinked_records(self) -> None:
        session.prepare_session_storage(str(self.grant_dir), "create")
        grant_path = Path(session.create_session_grant(*self.grant_args()))

        record = json.loads(grant_path.read_text(encoding="ascii"))
        issued = int(time.time()) - int(self.session_max) - 1
        record["issued_at_epoch"] = issued
        record["expires_at_epoch"] = issued + int(self.session_max)
        payload = json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n"
        grant_path.write_text(payload, encoding="ascii")
        grant_path.chmod(0o600)
        os.utime(grant_path, (issued, issued))
        with self.assertRaises(SystemExit):
            session.verify_session_grant(*self.verify_args(str(grant_path)))

        session.revoke_session_grant(str(self.grant_dir), self.thread_binding)
        grant_path = Path(session.create_session_grant(*self.grant_args()))
        os.link(grant_path, self.parent / "grant-hardlink.json")
        with self.assertRaises(SystemExit):
            session.verify_session_grant(*self.verify_args(str(grant_path)))

    def test_grant_recreate_is_atomic_over_the_existing_record(self) -> None:
        session.prepare_session_storage(str(self.grant_dir), "create")
        first = Path(session.create_session_grant(*self.grant_args()))
        before = first.read_bytes()
        second = Path(session.create_session_grant(*self.grant_args()))
        self.assertEqual(first, second)
        record_before = json.loads(before.decode("ascii"))
        record_after = json.loads(second.read_bytes().decode("ascii"))
        self.assertEqual(
            {k: v for k, v in record_before.items() if not k.endswith("_epoch")},
            {k: v for k, v in record_after.items() if not k.endswith("_epoch")},
        )
        leftovers = [
            path
            for path in (self.grant_dir / "active").iterdir()
            if path.name.endswith(".tmp")
        ]
        self.assertEqual(leftovers, [])


class AttemptReceiptTests(unittest.TestCase):
    policy_sha = "a" * 64
    action_digest = "b" * 64
    boot_sha = "c" * 64
    device_identity = "d" * 64
    thread_binding = "e" * 64
    host_boot = "f" * 64
    helper_sha = "0" * 64
    fastboot_identity = "1:2:81a4:1:100:x:y"
    stage = "ramboot"

    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.parent = Path(self.temp_dir.name) / "private-parent"
        self.parent.mkdir(mode=0o700)
        self.parent.chmod(0o700)
        self.receipt_dir = self.parent / "receipts"

    def create_args(self, ttl: str = "30") -> list[str]:
        return [
            str(self.receipt_dir),
            self.policy_sha,
            self.action_digest,
            self.boot_sha,
            self.device_identity,
            self.thread_binding,
            self.host_boot,
            self.helper_sha,
            self.fastboot_identity,
            self.stage,
            "4200",
            "268435456",
            ttl,
        ]

    def consume_args(self, pending: str, ttl: str = "30") -> list[str]:
        return [
            str(self.receipt_dir),
            pending,
            self.policy_sha,
            self.action_digest,
            self.boot_sha,
            self.device_identity,
            self.thread_binding,
            self.host_boot,
            self.helper_sha,
            self.fastboot_identity,
            self.stage,
            ttl,
        ]

    def test_receipt_is_single_use_and_moves_to_consumed(self) -> None:
        pending = session.create_attempt_receipt(*self.create_args())
        pending_path = Path(pending)
        self.assertTrue(pending_path.is_file())
        self.assertEqual(pending_path.parent.name, "pending")
        record = json.loads(pending_path.read_text(encoding="ascii"))
        self.assertEqual(record["schema"], "lmi-d110-internal-attempt-receipt/v1")
        self.assertEqual(record["expires_at_epoch"] - record["issued_at_epoch"], 30)
        receipt_id = hashlib.sha256(
            (self.policy_sha + "\0" + record["challenge_nonce"]).encode("ascii")
        ).hexdigest()
        self.assertEqual(pending_path.name, f"receipt-{receipt_id}.json")

        expires = session.consume_attempt_receipt(*self.consume_args(pending))
        self.assertEqual(expires, str(record["expires_at_epoch"]))
        self.assertFalse(pending_path.exists())
        consumed = self.receipt_dir / "consumed" / (
            pending_path.name[:-5] + ".consumed.json"
        )
        self.assertTrue(consumed.is_file())
        with self.assertRaises(SystemExit):
            session.consume_attempt_receipt(*self.consume_args(pending))

    def test_renamed_receipt_and_wrong_binding_or_ttl_are_rejected(self) -> None:
        pending = Path(session.create_attempt_receipt(*self.create_args()))
        renamed = pending.with_name("receipt-" + "9" * 64 + ".json")
        os.rename(pending, renamed)
        with self.assertRaises(SystemExit):
            session.consume_attempt_receipt(*self.consume_args(str(renamed)))
        os.rename(renamed, pending)

        with self.assertRaises(SystemExit):
            session.consume_attempt_receipt(*self.consume_args(str(pending), ttl="31"))

        outside = self.parent / pending.name
        with self.assertRaises(SystemExit):
            session.consume_attempt_receipt(*self.consume_args(str(outside)))

        args = self.consume_args(str(pending))
        args[3] = "9" * 64  # action_digest
        with self.assertRaises(SystemExit):
            session.consume_attempt_receipt(*args)

        session.consume_attempt_receipt(*self.consume_args(str(pending)))

    def test_expired_receipt_is_rejected(self) -> None:
        pending = Path(session.create_attempt_receipt(*self.create_args()))
        record = json.loads(pending.read_text(encoding="ascii"))
        issued = int(time.time()) - 31
        record["issued_at_epoch"] = issued
        record["expires_at_epoch"] = issued + 30
        pending.write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        pending.chmod(0o600)
        os.utime(pending, (issued, issued))
        with self.assertRaises(SystemExit):
            session.consume_attempt_receipt(*self.consume_args(str(pending)))


class PolicyValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fixture = D110GateFixture(Path(self.temp_dir.name))

    def validate(self, trusted: str | None = None) -> list[str]:
        trusted = trusted if trusted is not None else digest(self.fixture.policy)
        line = session.capture_local_policy(
            str(self.fixture.repo), str(self.fixture.policy), trusted
        )
        return line.split("\t")

    def test_valid_fixture_policy_yields_the_pinned_field_record(self) -> None:
        fields = self.validate()
        self.assertEqual(len(fields), 32)
        self.assertEqual(fields[-1], "END")
        self.assertEqual(fields[4], digest(self.fixture.boot))
        self.assertEqual(fields[5], str(self.fixture.boot.stat().st_size))
        self.assertEqual(fields[10], self.fixture.boot_uuid)
        self.assertEqual(fields[11], self.fixture.root_uuid)
        self.assertEqual(fields[19], "lmi")
        self.assertRegex(fields[30], r"^[0-9a-f]{64}$")  # action digest
        serial_material = self.fixture.serial
        self.assertNotIn(serial_material, "\t".join(fields))

    def test_wrong_trusted_pin_fails_with_the_exact_error_string(self) -> None:
        with self.assertRaises(SystemExit) as caught:
            self.validate(trusted="0" * 64)
        self.assertEqual(str(caught.exception), POLICY_FAILURE)

    def test_boot_image_bit_flip_fails_closed(self) -> None:
        data = bytearray(self.fixture.boot.read_bytes())
        data[4096] ^= 0x01  # first kernel byte
        self.fixture.boot.write_bytes(bytes(data))
        self.fixture.boot.chmod(0o600)
        with self.assertRaises(SystemExit) as caught:
            self.validate()
        self.assertEqual(str(caught.exception), POLICY_FAILURE)

    def test_duplicate_json_keys_in_policy_fail_closed(self) -> None:
        text = self.fixture.policy.read_text(encoding="utf-8")
        marker = '"schema": "lmi-d110-recovery-policy/v2"'
        self.assertIn(marker, text)
        text = text.replace(marker, marker + ",\n  " + marker, 1)
        self.fixture.private_write(self.fixture.policy, text)
        with self.assertRaises(SystemExit) as caught:
            self.validate()
        self.assertEqual(str(caught.exception), POLICY_FAILURE)

    def test_manifest_and_history_cross_checks_fail_closed(self) -> None:
        for mutate in (
            lambda p: p["artifact"].__setitem__("kernel_sha256", "0" * 64),
            lambda p: p["artifact"].__setitem__(
                "boot_uuid", "99999999-2222-4333-8444-555555555555"
            ),
            lambda p: p["historical_identity"].__setitem__(
                "legacy_fingerprint", "0" * 16
            ),
            lambda p: p["execution"].__setitem__("max_action_attempts", 2),
            lambda p: p["execution"].__setitem__("automatic_retry", True),
            lambda p: p["approval"].__setitem__("session_max_seconds", 86401),
        ):
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = D110GateFixture(Path(temporary))
                    fixture.write_policy(host_kind="linux", mutate=mutate)
                    with self.assertRaises(SystemExit) as caught:
                        session.capture_local_policy(
                            str(fixture.repo),
                            str(fixture.policy),
                            digest(fixture.policy),
                        )
                    self.assertEqual(str(caught.exception), POLICY_FAILURE)

    def test_world_readable_policy_file_fails_closed(self) -> None:
        self.fixture.policy.chmod(0o644)
        with self.assertRaises(SystemExit) as caught:
            self.validate()
        self.assertEqual(str(caught.exception), POLICY_FAILURE)


if __name__ == "__main__":
    unittest.main()
