"""Host-side tests for the owner-mode opt-in staging generator.

Owner-mode (notes/ssh-owner-mode-addendum-2026-07-29.md) is a distinct,
explicitly labeled configuration variant layered on top of the hardened
r145 SSH contract. These tests pin the generated owner-mode artifacts and,
in the same suite, re-pin the hardened default-profile bytes under
files/lmi-p1/, so recognizing owner-mode can never weaken the shipped
default. The generator is exercised through its public seam only: running
scripts/75_generate_lmi_owner_mode_config.sh as a subprocess. Nothing here
contacts a device.
"""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "scripts/75_generate_lmi_owner_mode_config.sh"
BASE_SSHD = REPO_ROOT / "files/lmi-p1/sshd_config"
DEFAULT_SUDOERS = REPO_ROOT / "files/lmi-p1/sudoers"
DEFAULT_SUDOERS_DROPIN = REPO_ROOT / "files/lmi-p1/90-lmi-rootctl"
ADDENDUM = REPO_ROOT / "notes/ssh-owner-mode-addendum-2026-07-29.md"

EXPECTED_DEFAULT_SUDOERS = b"root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n"
EXPECTED_DEFAULT_DROPIN = b"lmi ALL=(root) NOPASSWD: /usr/sbin/lmi-rootctl\n"
OWNER_MODE_SUDOERS_DROPIN = (
    b"# lmi owner-mode opt-in sudoers variant (91-lmi-owner-mode).\n"
    b"# Explicitly labeled owner-mode: never shipped in the public image "
    b"default,\n"
    b'# which allows exactly "lmi ALL=(root) NOPASSWD: '
    b'/usr/sbin/lmi-rootctl".\n'
    b"lmi ALL=(ALL) NOPASSWD: ALL\n"
)
RETAINED_PROHIBITIONS = (
    "PasswordAuthentication no",
    "KbdInteractiveAuthentication no",
    "AuthenticationMethods publickey",
    "GatewayPorts no",
    "X11Forwarding no",
    "PermitTunnel no",
    "PermitUserEnvironment no",
)
VALID_ED25519_LINE = (
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPlaceholderPlaceholderPlaceholder"
    "Placeh owner@host"
)


def run_generator(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(GENERATOR), *args],
        cwd=REPO_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def visudo_path() -> str | None:
    found = shutil.which("visudo")
    if found:
        return found
    fallback = Path("/usr/sbin/visudo")
    return str(fallback) if fallback.exists() else None


class DefaultProfileUnchangedTests(unittest.TestCase):
    """The hardened default profile must not absorb owner-mode."""

    def test_default_sudoers_bytes_are_exactly_the_hardened_policy(self) -> None:
        self.assertEqual(DEFAULT_SUDOERS.read_bytes(), EXPECTED_DEFAULT_SUDOERS)
        self.assertEqual(
            DEFAULT_SUDOERS_DROPIN.read_bytes(), EXPECTED_DEFAULT_DROPIN
        )

    def test_default_sshd_config_keeps_hardened_directives(self) -> None:
        lines = BASE_SSHD.read_text(encoding="ascii").splitlines()
        self.assertIn("PermitRootLogin no", lines)
        self.assertIn("AllowUsers lmi", lines)
        for retained in RETAINED_PROHIBITIONS:
            self.assertIn(retained, lines)
        self.assertNotIn("PermitRootLogin prohibit-password", lines)
        self.assertNotIn("AllowUsers lmi root", lines)

    def test_owner_mode_rule_never_appears_in_shipped_profile_files(self) -> None:
        for shipped in sorted((REPO_ROOT / "files").rglob("*")):
            if not shipped.is_file():
                continue
            data = shipped.read_bytes()
            self.assertNotIn(
                b"NOPASSWD: ALL",
                data,
                f"owner-mode sudo rule leaked into shipped file: {shipped}",
            )
            self.assertNotIn(
                b"prohibit-password",
                data,
                f"owner-mode sshd rule leaked into shipped file: {shipped}",
            )


class OwnerModeGeneratorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)

    def generate(self, *extra: str) -> Path:
        output = self.root / "stage"
        result = run_generator("--output", str(output), *extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("nothing was applied", result.stdout)
        return output

    def test_generates_labeled_variant_without_weakening_prohibitions(self) -> None:
        before = {
            path: path.read_bytes()
            for path in (BASE_SSHD, DEFAULT_SUDOERS, DEFAULT_SUDOERS_DROPIN)
        }
        output = self.generate()

        sudoers = output / "etc/sudoers.d/91-lmi-owner-mode"
        self.assertEqual(sudoers.read_bytes(), OWNER_MODE_SUDOERS_DROPIN)
        self.assertIn(b"owner-mode", sudoers.read_bytes())

        dropin = (output / "etc/ssh/sshd_config.d/40-lmi-owner-mode.conf").read_text(
            encoding="ascii"
        )
        self.assertIn("owner-mode", dropin)
        self.assertIn("PermitRootLogin prohibit-password", dropin)
        self.assertIn("AllowUsers lmi root", dropin)
        self.assertIn("first obtained value", dropin)
        self.assertNotIn("PasswordAuthentication yes", dropin)

        variant_lines = (
            (output / "etc/ssh/sshd_config.owner-mode")
            .read_text(encoding="ascii")
            .splitlines()
        )
        base_lines = BASE_SSHD.read_text(encoding="ascii").splitlines()
        self.assertEqual(len(variant_lines), len(base_lines))
        changed = [
            (old, new)
            for old, new in zip(base_lines, variant_lines)
            if old != new
        ]
        self.assertEqual(
            changed,
            [
                ("PermitRootLogin no", "PermitRootLogin prohibit-password"),
                ("AllowUsers lmi", "AllowUsers lmi root"),
            ],
        )
        for retained in RETAINED_PROHIBITIONS:
            self.assertIn(retained, variant_lines)

        placeholder = (output / "root-authorized-keys/authorized_keys").read_text(
            encoding="ascii"
        )
        self.assertTrue(
            all(line.startswith("#") for line in placeholder.splitlines())
        )
        self.assertIn("replace", placeholder)

        instructions = (output / "OWNER-MODE-APPLY.md").read_text(encoding="utf-8")
        self.assertIn("nothing here has been applied", instructions)
        self.assertIn("ssh-owner-mode-addendum-2026-07-29", instructions)
        self.assertIn("FIRST line", instructions)
        self.assertIn("Still forbidden in owner-mode", instructions)

        # Generation must never touch the shipped default profile.
        for path, payload in before.items():
            self.assertEqual(path.read_bytes(), payload)

    def test_owner_pubkey_is_embedded_only_when_valid(self) -> None:
        key_file = self.root / "owner.pub"
        key_file.write_text(VALID_ED25519_LINE + "\n", encoding="ascii")
        output = self.generate("--owner-pubkey", str(key_file))
        self.assertEqual(
            (output / "root-authorized-keys/authorized_keys").read_text(
                encoding="ascii"
            ),
            VALID_ED25519_LINE + "\n",
        )

        for invalid in (
            "ssh-rsa AAAAB3NzaC1yc2E owner@host\n",
            VALID_ED25519_LINE + "\n" + VALID_ED25519_LINE + "\n",
        ):
            bad = self.root / "bad.pub"
            bad.write_text(invalid, encoding="ascii")
            result = run_generator(
                "--output", str(self.root / "rejected"), "--owner-pubkey", str(bad)
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((self.root / "rejected").exists())

    def test_refuses_system_roots_and_nonempty_output(self) -> None:
        for system_path in ("/etc/ssh", "/usr/local/lmi", "/var/lib/lmi", "/"):
            with self.subTest(system_path=system_path):
                result = run_generator("--output", system_path)
                self.assertEqual(result.returncode, 2)
                self.assertIn("refusing system path", result.stderr)

        occupied = self.root / "occupied"
        occupied.mkdir()
        (occupied / "existing").write_text("x\n", encoding="ascii")
        result = run_generator("--output", str(occupied))
        self.assertEqual(result.returncode, 2)
        self.assertIn("not empty", result.stderr)
        self.assertEqual(
            sorted(path.name for path in occupied.iterdir()), ["existing"]
        )

    def test_help_states_host_only_boundary_and_takes_no_device_action(self) -> None:
        result = run_generator("--help")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("never talks to the phone", result.stdout)
        self.assertIn("refuses to run as root", result.stdout)
        script = GENERATOR.read_text(encoding="utf-8")
        for remote_tool in ("ssh ", "scp ", "adb "):
            self.assertNotIn(remote_tool, script)

    @unittest.skipUnless(visudo_path(), "visudo is not installed on this host")
    def test_generated_sudoers_dropin_passes_visudo(self) -> None:
        output = self.generate()
        result = subprocess.run(
            [
                str(visudo_path()),
                "-c",
                "-f",
                str(output / "etc/sudoers.d/91-lmi-owner-mode"),
            ],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


class AddendumContractTests(unittest.TestCase):
    def test_addendum_states_boundary_and_default(self) -> None:
        text = ADDENDUM.read_text(encoding="utf-8")
        self.assertIn("Status:", text)
        self.assertIn("No phone", text)
        self.assertIn("never the\nshipped default", text.replace("**", ""))
        self.assertIn("lmi ALL=(ALL) NOPASSWD: ALL", text)
        self.assertIn("prohibit-password", text)
        self.assertIn("PasswordAuthentication no", text)
        self.assertIn("KbdInteractiveAuthentication no", text)
        self.assertIn("GatewayPorts no", text)
        self.assertIn("ssh-full-function-contract-2026-07-24", text)


if __name__ == "__main__":
    unittest.main()
