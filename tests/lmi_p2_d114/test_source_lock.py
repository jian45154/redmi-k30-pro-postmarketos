from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.lmi_p2_d114.source_lock import LockError, load_source_lock


REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "config/lmi-p2-d114/source-lock.json"


class SourceLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(LOCK.read_text(encoding="utf-8"))

    def write(self, value: object) -> Path:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / "source-lock.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_reviewed_lock_is_valid_but_not_release_ready(self) -> None:
        source_lock = load_source_lock(LOCK)
        self.assertFalse(source_lock.release_eligible)
        self.assertRegex(source_lock.sha256, r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(LockError, "physical-input evidence"):
            source_lock.require_release_ready()

    def test_session_script_child_sha256_match_runtime_components(self) -> None:
        # Cross-check that the runtime keyboard/terminal SHA-256 the session
        # script hardcodes (to validate its live children) equals the value
        # pinned in source-lock runtime.component_sha256. Skipping this is how
        # the r2 six-row keyboard black screen shipped: source-lock was bumped
        # but the session copy went stale, with no test catching the drift.
        session = (REPO / "files/lmi-p2-d114/lmi-p2-d114-session").read_text(
            encoding="utf-8"
        )
        components = self.value["runtime"]["component_sha256"]
        for path in (
            "/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow",
            "/usr/libexec/lmi-p2-d114/weston-terminal-sixrow",
        ):
            expected = components[path]
            self.assertIn(
                expected,
                session,
                f"session script does not reference the source-lock SHA for {path}",
            )
        # And it must not still reference a now-superseded child SHA.
        stale = "88d06d99f7c2d3eb1da64e7f89a0f5e37b87bc4c93f8b6778b1ca6491bf1dba6"
        if stale not in components.values():
            self.assertNotIn(
                stale, session, "session script pins a keyboard SHA not in source-lock"
            )

    def test_rejects_unknown_duplicate_and_wrong_schema_fields(self) -> None:
        unknown = deepcopy(self.value)
        unknown["fastboot"] = "flash userdata"
        with self.assertRaisesRegex(LockError, "top-level fields"):
            load_source_lock(self.write(unknown))

        path = self.write(self.value)
        payload = path.read_text(encoding="utf-8")
        path.write_text(
            payload.replace('"schema":', '"schema":"shadow", "schema":', 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(LockError, "duplicate JSON field: schema"):
            load_source_lock(path)

        wrong = deepcopy(self.value)
        wrong["schema"] = "lmi-p2-source-profile/v1"
        with self.assertRaisesRegex(LockError, "unsupported"):
            load_source_lock(self.write(wrong))

    def test_rejects_every_baseline_identity_drift(self) -> None:
        mutations = {
            "D80 device": ("device_package", "device-xiaomi-lmi=1-r139"),
            "old kernel": ("installed_kernel_package", "linux-xiaomi-lmi=4.19.325-r8"),
            "wrong boot": ("boot_sha256", "0" * 64),
            "wrong root": ("root_uuid", "00000000-0000-0000-0000-000000000000"),
            "512-byte GPT": ("gpt_logical_sector_size", 512),
            "authority drift": ("authority", "windows-governance"),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(label=label):
                value = deepcopy(self.value)
                value["baseline"][field] = replacement
                with self.assertRaisesRegex(LockError, "baseline"):
                    load_source_lock(self.write(value))

    def test_rejects_dependency_or_package_weakening(self) -> None:
        for dependency in (
            "device-xiaomi-lmi=1-r144",
            "linux-xiaomi-lmi=4.19.325-r15",
            "lmi-weston-sixrow-clients=14.0.2-r2",
            "weston=14.0.2-r5",
            "greetd=0.10.3-r11",
        ):
            with self.subTest(dependency=dependency):
                value = deepcopy(self.value)
                value["dependencies"].remove(dependency)
                with self.assertRaisesRegex(LockError, "dependencies"):
                    load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["package"]["arch"] = "aarch64"
        with self.assertRaisesRegex(LockError, "package"):
            load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["package"]["release_eligible"] = True
        with self.assertRaisesRegex(LockError, "package"):
            load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["package"]["source_date_epoch"] += 1
        with self.assertRaisesRegex(LockError, "package"):
            load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["package"]["packager"] = "Unknown"
        with self.assertRaisesRegex(LockError, "package"):
            load_source_lock(self.write(value))

    def test_rejects_runtime_fallback_or_service_drift(self) -> None:
        mutations = {
            "renderer fallback": ("renderer", "gl"),
            "wrong seat service": ("seat_service", "seatd"),
            "weak socket mode": ("seatd_socket_mode", 777),
            "runlevel mutation": ("runlevel_links_modified", True),
            "generic socket": ("socket", "wayland-0"),
            "Phrog config": ("greetd_config", "/etc/phrog/greetd-config.toml"),
            "profile injection": ("greetd_source_profile", True),
            "wrong runfile": ("greetd_runfile", "/run/greetd.run"),
            "missing seat ordering": ("greetd_rc_need", "seatd"),
            "no terminal supervision": ("terminal_child_required", False),
            "no keyboard supervision": ("keyboard_child_required", False),
            "wrong takeover lock": ("system_takeover_lock", "/tmp/takeover"),
            "stock keyboard": ("keyboard_path", "/usr/libexec/weston-keyboard"),
            "stock terminal": ("terminal_path", "/usr/bin/weston-terminal"),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(label=label):
                value = deepcopy(self.value)
                value["runtime"][field] = replacement
                with self.assertRaisesRegex(LockError, "runtime"):
                    load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["runtime"]["component_sha256"]["/usr/bin/weston"] = "0" * 64
        with self.assertRaisesRegex(LockError, "runtime"):
            load_source_lock(self.write(value))

        value = deepcopy(self.value)
        del value["runtime"]["component_sha256"][
            "/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"
        ]
        with self.assertRaisesRegex(LockError, "runtime"):
            load_source_lock(self.write(value))

    def test_rejects_source_set_and_digest_drift(self) -> None:
        value = deepcopy(self.value)
        value["source_files"]["custom-osk.bin"] = "0" * 64
        with self.assertRaisesRegex(LockError, "exact D114 P2 source set"):
            load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["source_files"]["lmi-p2-d114-session"] = "UNVERIFIED"
        with self.assertRaisesRegex(LockError, "invalid sha256"):
            load_source_lock(self.write(value))


if __name__ == "__main__":
    unittest.main()
