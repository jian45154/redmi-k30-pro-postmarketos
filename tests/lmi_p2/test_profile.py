from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.lmi_p2.profile import ProfileError, load_profile


REPO = Path(__file__).resolve().parents[2]
PROFILE = REPO / "config/lmi-p2/source-profile.json"


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.value = json.loads(PROFILE.read_text(encoding="utf-8"))

    def write(self, value: dict) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "profile.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def test_reviewed_profile_is_valid_and_not_releasable(self) -> None:
        profile = load_profile(PROFILE)
        self.assertFalse(profile.release_eligible)
        self.assertEqual(profile.sha256, hashlib.sha256(profile.raw).hexdigest())
        self.assertEqual(
            profile.package_pins["linux-xiaomi-lmi"]["version"],
            "4.19.325-r8",
        )
        self.assertEqual(
            profile.value["release"]["blockers"],
            [
                "alpine-edge-libseat-runtime-requires-libelogind",
                "hardware-display-and-touch-validation-not-run",
                "linux-xiaomi-lmi-r8-vt-delta-unverified",
                "native-osk-not-built-in-pinned-aarch64-chroot",
                "repository-index-and-apk-digests-unverified",
                "stock-weston-terminal-native-focus-integration-unavailable",
            ],
        )
        with self.assertRaisesRegex(ProfileError, "not release eligible"):
            profile.require_release_ready()

    def test_rejects_unknown_fields_and_shell_injection(self) -> None:
        for mutation in (
            lambda value: value.update({"command": "sh -c 'id'"}),
            lambda value: value["package_pins"][0].update(
                {"name": "device-xiaomi-lmi;touch /tmp/owned"}
            ),
            lambda value: value["keyboard"]["layers"][0]["rows"][0][0].update(
                {"value": "q\ncommand"}
            ),
        ):
            with self.subTest(mutation=mutation):
                value = deepcopy(self.value)
                mutation(value)
                with self.assertRaises(ProfileError):
                    load_profile(self.write(value))

    def test_rejects_duplicate_json_fields(self) -> None:
        path = self.write(self.value)
        payload = path.read_text(encoding="utf-8")
        path.write_text(
            payload.replace('"schema":', '"schema":"shadow", "schema":', 1),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ProfileError, "duplicate JSON field: schema"):
            load_profile(path)

    def test_rejects_a_symlinked_profile_path(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "profile.json"
        path.symlink_to(PROFILE)
        with self.assertRaisesRegex(ProfileError, "could not read P2 profile"):
            load_profile(path)

    def test_rejects_missing_or_mismatched_libweston_abi(self) -> None:
        missing = deepcopy(self.value)
        missing["package_pins"] = [
            item for item in missing["package_pins"] if item["name"] != "libweston"
        ]
        with self.assertRaisesRegex(ProfileError, "package set"):
            load_profile(self.write(missing))

        mismatch = deepcopy(self.value)
        mismatch["weston"]["abi"] = 13
        with self.assertRaisesRegex(ProfileError, "libweston-14"):
            load_profile(self.write(mismatch))

        split_mismatch = deepcopy(self.value)
        next(
            item for item in split_mismatch["package_pins"] if item["name"] == "weston-terminal"
        )["version"] = "14.0.2-r4"
        with self.assertRaisesRegex(ProfileError, "source fact changed"):
            load_profile(self.write(split_mismatch))

    def test_rejects_elogind_mixing(self) -> None:
        value = deepcopy(self.value)
        value["package_pins"][1]["name"] = "elogind-openrc"
        with self.assertRaisesRegex(ProfileError, "forbidden"):
            load_profile(self.write(value))

    def test_rejects_incomplete_keyboard(self) -> None:
        cases = []
        no_backslash = deepcopy(self.value)
        for layer in no_backslash["keyboard"]["layers"]:
            for row in layer["rows"]:
                row[:] = [key for key in row if key["value"] != "\\"]
        cases.append((no_backslash, "shell-symbol"))

        no_delete = deepcopy(self.value)
        for layer in no_delete["keyboard"]["layers"]:
            for row in layer["rows"]:
                row[:] = [key for key in row if key["value"] != "Delete"]
        cases.append((no_delete, "keysym"))

        no_alt = deepcopy(self.value)
        for layer in no_alt["keyboard"]["layers"]:
            for row in layer["rows"]:
                row[:] = [key for key in row if key["value"] != "alt"]
        cases.append((no_alt, "modifier"))

        for value, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ProfileError, message):
                    load_profile(self.write(value))

    def test_rejects_unreachable_layer_and_clipped_keys(self) -> None:
        unreachable = deepcopy(self.value)
        for layer in unreachable["keyboard"]["layers"]:
            if layer["name"] != "symbols":
                for row in layer["rows"]:
                    row[:] = [
                        key
                        for key in row
                        if not (key["action"] == "layer" and key["value"] == "symbols")
                    ]
        with self.assertRaisesRegex(ProfileError, "reachable"):
            load_profile(self.write(unreachable))

        clipped = deepcopy(self.value)
        clipped["keyboard"]["layers"][0]["rows"][0][0]["weight"] = 5
        clipped["keyboard"]["layers"][0]["rows"][0][1]["weight"] = 50
        with self.assertRaisesRegex(ProfileError, "clipped touch target"):
            load_profile(self.write(clipped))

    def test_exact_screen_and_p1_contracts_are_immutable(self) -> None:
        value = deepcopy(self.value)
        value["display"]["scale"] = 1
        with self.assertRaisesRegex(ProfileError, "1080x2400"):
            load_profile(self.write(value))

        value = deepcopy(self.value)
        value["baseline"]["device_dependency"] = "device-xiaomi-lmi=1-r139"
        with self.assertRaisesRegex(ProfileError, "locked P1"):
            load_profile(self.write(value))


if __name__ == "__main__":
    unittest.main()
