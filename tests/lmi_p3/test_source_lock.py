from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest

from scripts.lmi_p3.source_lock import LockError, load_source_lock


REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "config/lmi-p3/source-lock.json"


class SourceLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(LOCK.read_text(encoding="utf-8"))

    def write(self, value: object) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "source-lock.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_reviewed_lock_is_valid_but_never_release_ready(self) -> None:
        source_lock = load_source_lock(LOCK)
        self.assertFalse(source_lock.release_eligible)
        self.assertRegex(source_lock.sha256, r"^[0-9a-f]{64}$")
        with self.assertRaisesRegex(LockError, "hardware evidence and approvals"):
            source_lock.require_release_ready()

    def test_rejects_unknown_and_duplicate_fields(self) -> None:
        unknown = deepcopy(self.value)
        unknown["command"] = "sh -c id"
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

    def test_rejects_every_kernel_or_baseline_drift(self) -> None:
        mutations = {
            "mainline stack": ("audio_implementation", "mainline-qcom-asoc"),
            "kernel edits": ("kernel_change_policy", "enable-more-config"),
            "D80 kernel": ("kernel_dependency", "linux-xiaomi-lmi=4.19.325-r9"),
            "D80 device": ("device_dependency", "device-xiaomi-lmi=1-r139"),
            "kernel APK drift": ("kernel_apk_sha256", "0" * 64),
            "kernel release drift": (
                "running_kernel_release",
                "4.19.325-cip128-st12-perf-dirty",
            ),
            "rootctl drift": ("rootctl_sha256", "0" * 64),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(label=label):
                value = deepcopy(self.value)
                value["baseline"][field] = replacement
                with self.assertRaisesRegex(LockError, "baseline"):
                    load_source_lock(self.write(value))

    def test_rejects_runtime_guard_weakening(self) -> None:
        mutations = {
            "runlevel": ("runlevel_enablement", True),
            "wrong write": ("boot_control", "/sys/kernel/boot_adsp/state"),
            "weak boot metadata": (
                "boot_control_metadata",
                "0:1000:220:regular file",
            ),
            "weak confirmation": ("confirmation", "yes"),
            "missing target subsystem": (
                "allowed_subsystem_names",
                [
                    "a650_zap",
                    "adsp",
                    "cdsp",
                    "cvpss",
                    "esoc0",
                    "ipa_fws",
                    "ipa_uc",
                    "npu",
                    "slpi",
                    "spss",
                    "venus",
                ],
            ),
            "unreviewed source root": ("firmware_source_root", "/lib/firmware"),
            "missing service": (
                "required_started_services",
                ["lmi-firmware-mount", "lmi-qrtr-ns", "rmtfs", "tqftpserv"],
            ),
            "weak ordering": ("ordering_directive", "after"),
            "weak pre-state": ("prewrite_state", "offline"),
            "weak post-state": ("postcheck_state", "running"),
            "unbounded postcheck": ("postcheck_attempts", 0),
            "active default": ("probe_default", "boot"),
            "raw probe stdout": ("probe_stdout", "raw"),
            "public raw archive": (
                "probe_private_archive_directory",
                "/tmp",
            ),
            "weak raw archive mode": ("probe_private_file_mode", "0644"),
            "ambiguous share output": ("probe_shareable_suffix", ".log"),
            "public runtime boundary": ("runtime_directory", "/run/lock"),
            "external transition lock": (
                "transition_lock",
                "/run/lock/lmi-adsp-control.lock",
            ),
            "external attempt latch": (
                "attempt_latch",
                "/run/lock/lmi-adsp-attempted",
            ),
        }
        for label, (field, replacement) in mutations.items():
            with self.subTest(label=label):
                value = deepcopy(self.value)
                value["runtime"][field] = replacement
                with self.assertRaisesRegex(LockError, "runtime"):
                    load_source_lock(self.write(value))

        integer_false = deepcopy(self.value)
        integer_false["runtime"]["runlevel_enablement"] = 0
        with self.assertRaisesRegex(LockError, "runtime"):
            load_source_lock(self.write(integer_false))

        boolean_pkgrel = deepcopy(self.value)
        boolean_pkgrel["package"]["pkgrel"] = False
        with self.assertRaisesRegex(LockError, "package"):
            load_source_lock(self.write(boolean_pkgrel))

    def test_rejects_proprietary_or_guessed_ucm_payload_policy(self) -> None:
        for field in ("proprietary_firmware_included", "ucm_profile_included"):
            with self.subTest(field=field):
                value = deepcopy(self.value)
                value["distribution"][field] = True
                with self.assertRaisesRegex(LockError, "distribution"):
                    load_source_lock(self.write(value))

    def test_rejects_dependency_pin_or_legacy_conflict_removal(self) -> None:
        for dependency in (
            "!adsp-audio",
            "!adsp-audio-openrc",
            "device-xiaomi-lmi=1-r107",
            "linux-xiaomi-lmi=4.19.325-r8",
        ):
            with self.subTest(dependency=dependency):
                value = deepcopy(self.value)
                value["dependencies"].remove(dependency)
                with self.assertRaisesRegex(LockError, "dependencies"):
                    load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["dependencies"][value["dependencies"].index("linux-xiaomi-lmi=4.19.325-r8")] = (
            "linux-xiaomi-lmi"
        )
        with self.assertRaisesRegex(LockError, "dependencies"):
            load_source_lock(self.write(value))

    def test_rejects_source_set_or_digest_drift(self) -> None:
        value = deepcopy(self.value)
        value["source_files"]["firmware.bin"] = "0" * 64
        with self.assertRaisesRegex(LockError, "exact P3 source set"):
            load_source_lock(self.write(value))

        value = deepcopy(self.value)
        value["source_files"]["lmi-audio-probe"] = "UNVERIFIED"
        with self.assertRaisesRegex(LockError, "invalid sha256"):
            load_source_lock(self.write(value))


if __name__ == "__main__":
    unittest.main()
