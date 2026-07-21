from __future__ import annotations

import hashlib
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


VERSION = "0.1.0-alpha.1"
PACKAGE = f"lmi-installer-v{VERSION}"
ARCHIVE = f"{PACKAGE}-source.tar.gz"
SOURCE_DATE_EPOCH = 1784505600


class SourceReleaseTests(unittest.TestCase):
    def test_release_builder_is_reproducible_and_allowlisted(self) -> None:
        repo_root = Path(__file__).resolve().parents[2]
        builder = repo_root / "scripts/73_build_lmi_installer_source_release.sh"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second"
            for output in (first, second):
                result = subprocess.run(
                    [str(builder), str(output)],
                    cwd=repo_root,
                    text=True,
                    capture_output=True,
                    timeout=30,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

            first_archive = first / ARCHIVE
            second_archive = second / ARCHIVE
            payload = first_archive.read_bytes()
            self.assertEqual(payload, second_archive.read_bytes())

            sidecar = first_archive.with_name(f"{ARCHIVE}.sha256").read_text(
                encoding="ascii"
            )
            self.assertEqual(
                sidecar,
                f"{hashlib.sha256(payload).hexdigest()}  {ARCHIVE}\n",
            )

            expected = {
                PACKAGE,
                f"{PACKAGE}/LICENSE",
                f"{PACKAGE}/NOTICE",
                f"{PACKAGE}/SHA256SUMS",
                f"{PACKAGE}/USER_GUIDE.md",
                f"{PACKAGE}/lmi-installer",
                f"{PACKAGE}/lmi_cli_installer.py",
            }
            with tarfile.open(first_archive, "r:gz") as archive:
                members = archive.getmembers()
                self.assertEqual({member.name for member in members}, expected)
                for member in members:
                    self.assertFalse(member.issym() or member.islnk())
                    self.assertEqual(member.uid, 0)
                    self.assertEqual(member.gid, 0)
                    self.assertEqual(member.mtime, SOURCE_DATE_EPOCH)
                modes = {
                    member.name: member.mode
                    for member in members
                    if member.isfile()
                }
                self.assertEqual(modes[f"{PACKAGE}/lmi-installer"], 0o755)
                for name, mode in modes.items():
                    if name != f"{PACKAGE}/lmi-installer":
                        self.assertEqual(mode, 0o644)


if __name__ == "__main__":
    unittest.main()
