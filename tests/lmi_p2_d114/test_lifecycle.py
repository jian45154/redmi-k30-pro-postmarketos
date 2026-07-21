from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-p2-d114"
LIFECYCLE = FILES / "lmi-p2-d114-config-lifecycle"

BASELINE_CONFD = """# Configuration for greetd

# Path to config file to use.
cfgfile="/etc/phrog/greetd-config.toml"

# Uncomment to use process supervisor when using openrc.
# supervisor=supervise-daemon
"""


@unittest.skipIf(os.getuid() == 0, "test-root redirection is intentionally non-root-only")
class LifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        (self.root / "etc/conf.d").mkdir(parents=True, mode=0o755)
        (self.root / "usr/share/lmi-p2-d114").mkdir(parents=True, mode=0o755)
        (self.root / "var/lib").mkdir(parents=True, mode=0o755)
        self.target = self.root / "etc/conf.d/greetd"
        self.target.write_text(BASELINE_CONFD, encoding="utf-8")
        self.target.chmod(0o644)
        self.packaged = self.root / "usr/share/lmi-p2-d114/greetd.confd"
        shutil.copyfile(FILES / "lmi-p2-d114-greetd.confd", self.packaged)
        self.packaged.chmod(0o644)

    def run_lifecycle(self, operation: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["LMI_P2_D114_TEST_ROOT"] = str(self.root)
        return subprocess.run(
            ["/bin/sh", str(LIFECYCLE), operation],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_install_upgrade_remove_round_trip(self) -> None:
        install = self.run_lifecycle("install")
        self.assertEqual(install.returncode, 0, install.stderr)
        self.assertEqual(self.target.read_bytes(), self.packaged.read_bytes())
        state = self.root / "var/lib/lmi-p2-d114"
        self.assertEqual((state / "config-v1").read_text(), "lmi-p2-d114-greetd-confd/v1\n")
        self.assertEqual((state / "greetd-confd.original").read_text(), BASELINE_CONFD)
        self.assertFalse((state / "config-v1.pending").exists())

        reinstall = self.run_lifecycle("install")
        self.assertEqual(reinstall.returncode, 0, reinstall.stderr)
        upgrade = self.run_lifecycle("upgrade")
        self.assertEqual(upgrade.returncode, 0, upgrade.stderr)

        remove = self.run_lifecycle("remove")
        self.assertEqual(remove.returncode, 0, remove.stderr)
        self.assertEqual(self.target.read_text(), BASELINE_CONFD)
        self.assertFalse(state.exists())

    def test_remove_refuses_to_overwrite_external_change(self) -> None:
        self.assertEqual(self.run_lifecycle("install").returncode, 0)
        self.target.write_text("external=true\n", encoding="utf-8")
        result = self.run_lifecycle("remove")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("changed externally", result.stderr)
        self.assertEqual(self.target.read_text(), "external=true\n")
        self.assertTrue((self.root / "var/lib/lmi-p2-d114").exists())

    def test_recovers_pending_install_from_untouched_baseline(self) -> None:
        state = self.root / "var/lib/lmi-p2-d114"
        state.mkdir(mode=0o700)
        pending = state / "config-v1.pending"
        pending.write_text("lmi-p2-d114-greetd-confd/v1\n", encoding="utf-8")
        pending.chmod(0o600)
        result = self.run_lifecycle("install")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_bytes(), self.packaged.read_bytes())
        self.assertFalse(pending.exists())
        self.assertTrue((state / "config-v1").exists())
        self.assertEqual(self.run_lifecycle("remove").returncode, 0)

    def test_recovers_removal_after_target_was_already_restored(self) -> None:
        self.assertEqual(self.run_lifecycle("install").returncode, 0)
        state = self.root / "var/lib/lmi-p2-d114"
        removing = state / "config-v1.removing"
        removing.write_text("lmi-p2-d114-greetd-confd/v1\n", encoding="utf-8")
        removing.chmod(0o600)
        self.target.write_text(BASELINE_CONFD, encoding="utf-8")
        self.target.chmod(0o644)

        result = self.run_lifecycle("remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_text(), BASELINE_CONFD)
        self.assertFalse(state.exists())

    def test_recovers_removal_with_completed_restore_staging_file(self) -> None:
        self.assertEqual(self.run_lifecycle("install").returncode, 0)
        state = self.root / "var/lib/lmi-p2-d114"
        removing = state / "config-v1.removing"
        removing.write_text("lmi-p2-d114-greetd-confd/v1\n", encoding="utf-8")
        removing.chmod(0o600)
        replacement = self.root / "etc/conf.d/.greetd.lmi-p2-d114-new"
        replacement.write_text(BASELINE_CONFD, encoding="utf-8")
        replacement.chmod(0o644)

        result = self.run_lifecycle("remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.target.read_text(), BASELINE_CONFD)
        self.assertFalse(state.exists())

    def test_rejects_symlink_target_and_preserves_destination(self) -> None:
        destination = self.root / "external-greetd"
        destination.write_text(BASELINE_CONFD, encoding="utf-8")
        self.target.unlink()
        self.target.symlink_to(destination)
        result = self.run_lifecycle("install")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("baseline metadata changed", result.stderr)
        self.assertEqual(destination.read_text(), BASELINE_CONFD)
        self.assertTrue(self.target.is_symlink())


if __name__ == "__main__":
    unittest.main()
