from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from scripts.lmi_p3.generate import PACKAGE_RELATIVE, generate_overlay
from scripts.lmi_p3.source_lock import LockError


REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "config/lmi-p3/source-lock.json"


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


class GeneratorTests(unittest.TestCase):
    def test_generation_is_deterministic_contained_and_manifested(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            package = generate_overlay(LOCK, first)
            generate_overlay(LOCK, second)
            self.assertEqual(package, first / PACKAGE_RELATIVE)
            self.assertEqual(tree_digest(first), tree_digest(second))
            self.assertEqual(
                {path.name for path in package.iterdir()},
                {
                    "APKBUILD",
                    "device-xiaomi-lmi-audio.post-install",
                    "lmi-adsp-boot.confd",
                    "lmi-adsp-boot.initd",
                    "lmi-adsp-control",
                    "lmi-audio-probe",
                    "lmi-p3-route-guard",
                },
            )
            manifest = json.loads((first / ".lmi-p3-overlay.json").read_text())
            self.assertEqual(manifest["schema"], "lmi-p3-generated-overlay/v1")
            self.assertFalse(manifest["release_eligible"])
            self.assertEqual(manifest["status"], "host-source-only-candidate")
            self.assertEqual(
                manifest["distribution"],
                {
                    "proprietary_firmware_included": False,
                    "ucm_profile_included": False,
                },
            )
            for generated in (first, first / "device", first / "device/downstream", package):
                self.assertEqual(stat.S_IMODE(generated.stat().st_mode), 0o755)
            self.assertEqual(
                stat.S_IMODE((first / ".lmi-p3-overlay.json").stat().st_mode), 0o644
            )
            for generated_file in package.iterdir():
                self.assertEqual(stat.S_IMODE(generated_file.stat().st_mode), 0o644)

    def test_apkbuild_is_composable_exactly_pinned_and_installs_no_runlevel_or_blobs(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = generate_overlay(LOCK, Path(directory) / "overlay")
            apkbuild = (package / "APKBUILD").read_text(encoding="utf-8")
            self.assertIn("pkgname=device-xiaomi-lmi-audio\n", apkbuild)
            for dependency in (
                "!adsp-audio",
                "!adsp-audio-openrc",
                "alsa-utils",
                "device-xiaomi-lmi=1-r107",
                "linux-xiaomi-lmi=4.19.325-r8",
                "openrc",
                "pd-mapper",
                "rmtfs",
                "tqftpserv",
            ):
                self.assertIn(f"\t{dependency}\n", apkbuild)
            self.assertIn('install="$pkgname.post-install"', apkbuild)
            self.assertIn(
                'install -Dm600 "$srcdir"/lmi-adsp-boot.confd', apkbuild
            )
            self.assertIn(
                'install -Dm755 "$srcdir"/lmi-p3-route-guard', apkbuild
            )
            self.assertIn('install -dm700 "$pkgdir"/etc/lmi-p3', apkbuild)
            self.assertNotIn("/etc/runlevels", apkbuild)
            self.assertNotIn('"$pkgdir"/lib/firmware', apkbuild)
            self.assertNotIn('"$pkgdir"/usr/share/alsa/ucm', apkbuild)
            self.assertNotIn("linux-postmarketos", apkbuild)
            self.assertNotIn("device-xiaomi-lmi=1-r139", apkbuild)
            self.assertNotIn("linux-xiaomi-lmi=4.19.325-r9", apkbuild)

    def test_refuses_existing_output_without_touching_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            marker = output / "P1-P2-MARKER"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(LockError, "refusing to overwrite"):
                generate_overlay(LOCK, output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_rejects_digest_mismatch_binary_and_unexpected_source(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            (source_root / "files").mkdir(parents=True)
            shutil.copytree(REPO / "files/lmi-p3", source_root / "files/lmi-p3")
            target = source_root / "files/lmi-p3/lmi-audio-probe"
            target.write_text(target.read_text() + "# changed\n", encoding="utf-8")
            with self.assertRaisesRegex(LockError, "digest mismatch"):
                generate_overlay(LOCK, root / "digest-output", source_root=source_root)

            shutil.rmtree(source_root / "files/lmi-p3")
            shutil.copytree(REPO / "files/lmi-p3", source_root / "files/lmi-p3")
            target = source_root / "files/lmi-p3/lmi-audio-probe"
            target.write_bytes(b"\0proprietary")
            with self.assertRaisesRegex(LockError, "binary payloads are forbidden"):
                generate_overlay(LOCK, root / "binary-output", source_root=source_root)

            shutil.rmtree(source_root / "files/lmi-p3")
            shutil.copytree(REPO / "files/lmi-p3", source_root / "files/lmi-p3")
            (source_root / "files/lmi-p3/adsp.mdt").write_bytes(b"blob")
            with self.assertRaisesRegex(LockError, "exactly the locked source set"):
                generate_overlay(LOCK, root / "extra-output", source_root=source_root)

    def test_rejects_noncanonical_source_file_or_directory_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            (source_root / "files").mkdir(parents=True)
            shutil.copytree(REPO / "files/lmi-p3", source_root / "files/lmi-p3")
            target = source_root / "files/lmi-p3/lmi-audio-probe"
            target.chmod(0o755)
            with self.assertRaisesRegex(LockError, "non-mode-644"):
                generate_overlay(LOCK, root / "file-mode-output", source_root=source_root)

            target.chmod(0o644)
            (source_root / "files/lmi-p3").chmod(0o700)
            with self.assertRaisesRegex(LockError, "mode-755"):
                generate_overlay(LOCK, root / "directory-mode-output", source_root=source_root)


if __name__ == "__main__":
    unittest.main()
