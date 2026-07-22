from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from scripts.lmi_p2.generate import (
    PACKAGE_RELATIVE,
    generate_overlay,
    generate_overlay_from_profile,
)
from scripts.lmi_p2.profile import ProfileError, load_profile


REPO = Path(__file__).resolve().parents[2]
PROFILE = REPO / "config/lmi-p2/source-profile.json"


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        digest.update(path.relative_to(root).as_posix().encode())
        digest.update(b"\0")
        digest.update(f"{stat.S_IMODE(path.stat().st_mode):04o}".encode())
        digest.update(b"\0")
        if path.is_file():
            digest.update(path.read_bytes())
    return digest.hexdigest()


class GeneratorTests(unittest.TestCase):
    def test_generation_is_deterministic_and_contained(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            package = generate_overlay(PROFILE, first)
            generate_overlay(PROFILE, second)
            self.assertEqual(package, first / PACKAGE_RELATIVE)
            self.assertEqual(tree_digest(first), tree_digest(second))
            self.assertEqual(
                {path.relative_to(package).as_posix() for path in package.iterdir()},
                {
                    "APKBUILD",
                    "device-xiaomi-lmi-gui.post-install",
                    "device-xiaomi-lmi-gui.post-upgrade",
                    "device-xiaomi-lmi-gui.pre-deinstall",
                    "lmi-account-lifecycle",
                    "lmi-child-supervisor.c",
                    "lmi-child-supervisor.h",
                    "lmi-input-state.c",
                    "lmi-input-state.h",
                    "lmi-layer-state.c",
                    "lmi-layer-state.h",
                    "lmi-display-handoff.c",
                    "lmi-display.initd",
                    "lmi-editor",
                    "lmi-osk-layout.h",
                    "lmi-session-launcher.c",
                    "lmi-terminal",
                    "lmi-terminal-bridge.c",
                    "lmi-weston-osk.c",
                    "lmi-weston-user-session",
                    "weston.ini",
                },
            )

    def test_apkbuild_has_exact_p1_and_weston_split_dependencies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = generate_overlay(PROFILE, Path(directory) / "overlay")
            apkbuild = (package / "APKBUILD").read_text(encoding="utf-8")
            for dependency in (
                "device-xiaomi-lmi=1-r107",
                "libweston=14.0.2-r5",
                "linux-xiaomi-lmi=4.19.325-r8",
                "weston=14.0.2-r5",
                "weston-backend-drm=14.0.2-r5",
                "weston-clients=14.0.2-r5",
                "weston-shell-desktop=14.0.2-r5",
                "weston-terminal=14.0.2-r5",
                "seatd=0.9.3-r0",
                "seatd-openrc=0.9.3-r0",
                "libdrm-tests=2.4.134-r0",
                "kbd=2.8.0-r0",
                "font-dejavu=2.37-r6",
            ):
                self.assertIn(f"\t{dependency}\n", apkbuild)
            self.assertNotIn("elogind", apkbuild.lower())
            self.assertNotIn("su-exec", apkbuild)
            self.assertNotIn("device-xiaomi-lmi=1-r139", apkbuild)
            source_block = apkbuild.split('source="', 1)[1].split('"', 1)[0]
            self.assertNotIn(".post-install", source_block)
            self.assertNotIn(".post-upgrade", source_block)
            self.assertNotIn(".pre-deinstall", source_block)
            self.assertIn(
                'install="$pkgname.post-install $pkgname.post-upgrade $pkgname.pre-deinstall"',
                apkbuild,
            )
            self.assertIn('"$srcdir"/lmi-child-supervisor.c', apkbuild)
            self.assertIn('"$srcdir"/lmi-account-lifecycle', apkbuild)
            self.assertNotIn("text-input-unstable-v1", apkbuild)
            self.assertIn("\tlinux-headers\n", apkbuild)

    def test_generation_retains_the_one_validated_profile_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile_path = root / "profile.json"
            shutil.copy2(PROFILE, profile_path)
            profile = load_profile(profile_path)
            expected_digest = hashlib.sha256(profile.raw).hexdigest()
            profile_path.write_text("{}\n", encoding="utf-8")
            package = generate_overlay_from_profile(
                profile, root / "overlay", source_root=REPO
            )
            manifest = json.loads(
                (package.parents[2] / ".lmi-p2-overlay.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(profile.sha256, expected_digest)
            self.assertEqual(manifest["profile_sha256"], expected_digest)

    def test_generated_modes_ignore_restrictive_umask(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            previous = os.umask(0o077)
            try:
                output = Path(directory) / "overlay"
                package = generate_overlay(PROFILE, output)
            finally:
                os.umask(previous)
            for path in [output, output / "device", output / "device/downstream", package]:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o755)
            for path in (item for item in output.rglob("*") if item.is_file()):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    def test_refuses_output_or_p1_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            marker = output / "P1-MARKER"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(ProfileError, "refusing to overwrite"):
                generate_overlay(PROFILE, output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_rejects_source_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            (source_root / "files").mkdir(parents=True)
            shutil.copytree(REPO / "files/lmi-p2", source_root / "files/lmi-p2")
            target = source_root / "files/lmi-p2/lmi-terminal"
            target.write_text(target.read_text(encoding="utf-8") + "# changed\n")
            with self.assertRaisesRegex(ProfileError, "digest mismatch"):
                generate_overlay(PROFILE, root / "output", source_root=source_root)


if __name__ == "__main__":
    unittest.main()
