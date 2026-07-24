from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest

from scripts.lmi_p2_d114.generate import PACKAGE_RELATIVE, generate_overlay
from scripts.lmi_p2_d114.source_lock import LockError


REPO = Path(__file__).resolve().parents[2]
LOCK = REPO / "config/lmi-p2-d114/source-lock.json"
TRACKED_MANIFEST = REPO / "config/lmi-p2-d114/generated-overlay.json"
HOOK_NAMES = (
    "device-xiaomi-lmi-terminal.post-install",
    "device-xiaomi-lmi-terminal.post-upgrade",
    "device-xiaomi-lmi-terminal.pre-deinstall",
)


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
                    "device-xiaomi-lmi-terminal.post-install",
                    "device-xiaomi-lmi-terminal.post-upgrade",
                    "device-xiaomi-lmi-terminal.pre-deinstall",
                    "lmi-p2-d114-config-lifecycle",
                    "lmi-p2-d114-greetd.confd",
                    "lmi-p2-d114-greetd.toml",
                    "lmi-p2-d114-session",
                    "lmi-p2-d114-weston.ini",
                },
            )
            manifest = json.loads(
                (first / ".lmi-p2-d114-overlay.json").read_text(encoding="ascii")
            )
            self.assertEqual(
                (first / ".lmi-p2-d114-overlay.json").read_bytes(),
                TRACKED_MANIFEST.read_bytes(),
            )
            self.assertEqual(
                manifest["schema"], "lmi-p2-d114-generated-overlay/v1"
            )
            self.assertFalse(manifest["release_eligible"])
            self.assertEqual(
                manifest["status"], "private-d114-hardware-test-candidate"
            )
            for generated in (
                first,
                first / "device",
                first / "device/downstream",
                package,
            ):
                self.assertEqual(stat.S_IMODE(generated.stat().st_mode), 0o755)
            for generated_file in package.iterdir():
                self.assertEqual(stat.S_IMODE(generated_file.stat().st_mode), 0o644)

    def test_apkbuild_is_noarch_pinned_and_changes_no_runlevel(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = generate_overlay(LOCK, Path(directory) / "overlay")
            apkbuild = (package / "APKBUILD").read_text(encoding="utf-8")
            self.assertIn("pkgname=device-xiaomi-lmi-terminal\n", apkbuild)
            self.assertIn("pkgrel=2\n", apkbuild)
            self.assertIn('arch="noarch"\n', apkbuild)
            self.assertIn(
                'maintainer="lmi P2 maintainers <noreply@example.invalid>"\n',
                apkbuild,
            )
            self.assertIn(
                'export PACKAGER="lmi P2 private builder <noreply@example.invalid>"\n',
                apkbuild,
            )
            self.assertIn(
                'export ABUILD_LAST_COMMIT="uncommitted-p2-d114-source-lock-v4"\n',
                apkbuild,
            )
            self.assertIn("export SOURCE_DATE_EPOCH=1784522705\n", apkbuild)
            for dependency in (
                "device-xiaomi-lmi=1-r144",
                "linux-xiaomi-lmi=4.19.325-r15",
                "lmi-weston-sixrow-clients=14.0.2-r2",
                "greetd=0.10.3-r11",
                "weston=14.0.2-r5",
                "weston-terminal=14.0.2-r5",
            ):
                self.assertIn(f"\t{dependency}\n", apkbuild)
            self.assertIn(
                'install="$pkgname.post-install $pkgname.post-upgrade $pkgname.pre-deinstall"',
                apkbuild,
            )
            self.assertIn(
                '"$pkgdir"/etc/lmi-p2-d114/greetd.toml', apkbuild
            )
            self.assertIn(
                '"$pkgdir"/usr/share/lmi-p2-d114/greetd.confd', apkbuild
            )
            self.assertNotIn("/etc/runlevels", apkbuild)
            self.assertNotIn("lmi-p2-gui", apkbuild)
            self.assertNotIn("gcc", apkbuild)
            self.assertNotIn("wayland-scanner", apkbuild)
            self.assertNotIn("lmi-weston-sixrow-clients>=", apkbuild)
            source_block = apkbuild.split('source="\n', 1)[1].split('\n"', 1)[0]
            checksum_block = apkbuild.split('sha512sums="\n', 1)[1].split(
                '\n"', 1
            )[0]
            for hook_name in HOOK_NAMES:
                self.assertIn(f"\t{hook_name}\n", f"{source_block}\n")
                hook_payload = (REPO / "files/lmi-p2-d114" / hook_name).read_bytes()
                self.assertIn(
                    f"{hashlib.sha512(hook_payload).hexdigest()}  {hook_name}\n",
                    f"{checksum_block}\n",
                )

    def test_refuses_existing_output_without_touching_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "existing"
            output.mkdir()
            marker = output / "KEEP"
            marker.write_text("preserve\n", encoding="utf-8")
            with self.assertRaisesRegex(LockError, "refusing to overwrite"):
                generate_overlay(LOCK, output)
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve\n")

    def test_rejects_digest_binary_extra_source_and_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source_root = root / "source"
            (source_root / "files").mkdir(parents=True)

            def reset() -> Path:
                target = source_root / "files/lmi-p2-d114"
                shutil.rmtree(target, ignore_errors=True)
                shutil.copytree(REPO / "files/lmi-p2-d114", target)
                return target

            sources = reset()
            session = sources / "lmi-p2-d114-session"
            session.write_text(session.read_text() + "# drift\n", encoding="utf-8")
            with self.assertRaisesRegex(LockError, "digest mismatch"):
                generate_overlay(
                    LOCK, root / "digest-output", source_root=source_root
                )

            sources = reset()
            (sources / "lmi-p2-d114-session").write_bytes(b"\0binary")
            with self.assertRaisesRegex(LockError, "binary payloads"):
                generate_overlay(
                    LOCK, root / "binary-output", source_root=source_root
                )

            sources = reset()
            (sources / "old-d80-wrapper").write_text("root\n", encoding="utf-8")
            with self.assertRaisesRegex(LockError, "exactly the locked source set"):
                generate_overlay(LOCK, root / "extra-output", source_root=source_root)

            sources = reset()
            (sources / "lmi-p2-d114-session").chmod(0o755)
            with self.assertRaisesRegex(LockError, "non-mode-644"):
                generate_overlay(LOCK, root / "mode-output", source_root=source_root)


if __name__ == "__main__":
    unittest.main()
