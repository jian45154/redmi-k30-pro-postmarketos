from __future__ import annotations

import hashlib
import importlib.util
import os
from pathlib import Path
import py_compile
import stat
import subprocess
import sys
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
BUNDLE = (
    REPO
    / "private/lmi-p1/recovery/d110-d114/p2-d114-build-20260720"
)
HELPER = BUNDLE / "live-install-root.sh"
STAGER = BUNDLE / "secure-stage.py"
APK = BUNDLE / "run2-device-xiaomi-lmi-terminal-0.1.0-r0.apk"
KEY = BUNDLE / "pmos@local-6a5d38f2.rsa.pub"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load_stager():
    spec = importlib.util.spec_from_file_location("lmi_secure_stage", STAGER)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not create secure-stage module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class LiveInstallerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.shell = HELPER.read_text(encoding="utf-8")
        cls.stage_source = STAGER.read_text(encoding="utf-8")
        cls.stage = load_stager()

    def run_record_verifier(
        self, record: str, policy: str
    ) -> subprocess.CompletedProcess[str]:
        prefix = self.shell[: self.shell.index("trap cleanup_on_exit EXIT")]
        prefix = prefix.replace(
            "\t' /lib/apk/db/installed\n}",
            "\t' \"$LMI_TEST_INSTALLED\"\n}",
            1,
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            installed = root / "installed"
            harness = root / "verify-record.sh"
            installed.write_text(record, encoding="utf-8")
            harness.write_text(
                prefix + '\nverify_package_record "$1"\n', encoding="utf-8"
            )
            return subprocess.run(
                ["sh", str(harness), policy],
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
                env=dict(os.environ, LMI_TEST_INSTALLED=str(installed)),
            )

    def test_helper_and_stager_are_syntactically_valid(self) -> None:
        result = subprocess.run(
            ["sh", "-n", str(HELPER)],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with tempfile.TemporaryDirectory() as temporary:
            py_compile.compile(
                str(STAGER),
                cfile=str(Path(temporary) / "secure-stage.pyc"),
                doraise=True,
            )

    def test_stager_pins_the_exact_helper_apk_and_key(self) -> None:
        self.assertEqual(self.stage.HELPER_SIZE, HELPER.stat().st_size)
        self.assertEqual(self.stage.HELPER_SHA256, sha256(HELPER))
        self.assertEqual(self.stage.APK_SIZE, APK.stat().st_size)
        self.assertEqual(self.stage.APK_SHA256, sha256(APK))
        self.assertEqual(self.stage.KEY_SIZE, KEY.stat().st_size)
        self.assertEqual(self.stage.KEY_SHA256, sha256(KEY))
        self.assertEqual(
            self.stage.EXPECTED_UPLOAD_ENTRIES,
            {
                "secure-stage.py",
                "live-install-root.sh",
                "device-xiaomi-lmi-terminal-0.1.0-r0.apk",
                "pmos@local-6a5d38f2.rsa.pub",
            },
        )

    def test_unprivileged_sources_and_root_stage_metadata_are_exact(self) -> None:
        for literal in (
            "SOURCE_UID = 10000",
            "SOURCE_GID = 10000",
            "SOURCE_MODE = 0o600",
            "SOURCE_DIRECTORY_MODE = 0o700",
            "ROOT_DIRECTORY_MODE = 0o700",
            "ROOT_FILE_MODE = 0o600",
            "before.st_nlink",
            "os.O_NOFOLLOW",
            "os.O_CREAT",
            "os.O_EXCL",
            "os.fchown(descriptor, 0, 0)",
            "os.fsync(descriptor)",
            "hashlib.sha256(verified).hexdigest()",
        ):
            self.assertIn(literal, self.stage_source)
        self.assertLess(
            self.stage_source.index("content = _read_all_sources()"),
            self.stage_source.index("_stage_sources(content)"),
        )
        self.assertIn(
            '("/bin/sh", RUN_HELPER, "--secure-stage")', self.stage_source
        )

    def test_exact_reader_accepts_bytes_and_rejects_symlink_hardlink_and_drift(self) -> None:
        stage = self.stage
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            content = b"immutable-source-fixture\n"
            source = root / "source"
            source.write_bytes(content)
            source.chmod(0o600)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                result = stage._read_exact_at(
                    directory_fd,
                    source.name,
                    expected_size=len(content),
                    expected_sha256=hashlib.sha256(content).hexdigest(),
                    expected_uid=os.getuid(),
                    expected_gid=os.getgid(),
                )
                self.assertIsInstance(result, bytes)
                self.assertEqual(result, content)

                link = root / "link"
                link.symlink_to(source.name)
                with self.assertRaises(stage.StageError):
                    stage._read_exact_at(
                        directory_fd,
                        link.name,
                        expected_size=len(content),
                        expected_sha256=hashlib.sha256(content).hexdigest(),
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )

                hardlink = root / "hardlink"
                os.link(source, hardlink)
                with self.assertRaises(stage.StageError):
                    stage._read_exact_at(
                        directory_fd,
                        source.name,
                        expected_size=len(content),
                        expected_sha256=hashlib.sha256(content).hexdigest(),
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
                hardlink.unlink()

                source.chmod(0o644)
                with self.assertRaises(stage.StageError):
                    stage._read_exact_at(
                        directory_fd,
                        source.name,
                        expected_size=len(content),
                        expected_sha256=hashlib.sha256(content).hexdigest(),
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
                source.chmod(0o600)
                with self.assertRaises(stage.StageError):
                    stage._read_exact_at(
                        directory_fd,
                        source.name,
                        expected_size=len(content),
                        expected_sha256="0" * 64,
                        expected_uid=os.getuid(),
                        expected_gid=os.getgid(),
                    )
            finally:
                os.close(directory_fd)

    def test_created_inode_is_new_root_style_0600_fsynced_and_hashed(self) -> None:
        stage = self.stage
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            content = b"staged fixture\n"
            try:
                if os.geteuid() != 0:
                    with self.assertRaises(OSError):
                        stage._create_exact_file(
                            descriptor,
                            "new-file",
                            content,
                            hashlib.sha256(content).hexdigest(),
                        )
                    self.assertFalse((root / "new-file").exists())
                    return
                stage._create_exact_file(
                    descriptor,
                    "new-file",
                    content,
                    hashlib.sha256(content).hexdigest(),
                )
                target = root / "new-file"
                metadata = target.stat()
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_nlink, 1)
                self.assertEqual((metadata.st_uid, metadata.st_gid), (0, 0))
                self.assertEqual(target.read_bytes(), content)
                with self.assertRaises(FileExistsError):
                    stage._create_exact_file(
                        descriptor,
                        "new-file",
                        content,
                        hashlib.sha256(content).hexdigest(),
                    )
            finally:
                os.close(descriptor)

    def test_inline_loader_is_tiny_passwordless_and_executes_hashed_bytes(self) -> None:
        for literal in (
            "ssh -T -o BatchMode=yes -o PasswordAuthentication=no",
            "/usr/bin/sudo -n -- /usr/bin/python3 -I -S -B -",
            "os.open(p,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW)",
            "os.fstat(f)",
            "(10000,10000,1,n)",
            "hashlib.sha256(b).hexdigest()==h",
            "exec(compile(b,p,'exec')",
            "lmi-rootctl-only sudo policy does not authorize arbitrary Python",
        ):
            self.assertIn(literal, self.shell)

    def test_apk_commands_are_exact_offline_isolated_key_operations(self) -> None:
        common = (
            "apk --force-non-repository --interactive=no --no-network --no-cache"
        )
        self.assertEqual(self.shell.count(common), 3)
        self.assertEqual(self.shell.count("--repositories-file /dev/null"), 3)
        self.assertEqual(self.shell.count('--keys-dir "$run_keys"'), 3)
        self.assertNotIn("allow-untrusted", self.shell)
        self.assertNotIn("--network=false", self.shell)
        self.assertNotIn("--cache=false", self.shell)
        for action in (
            'verify "$run_apk"',
            'add "$run_apk"',
            "del device-xiaomi-lmi-terminal",
        ):
            self.assertIn(action, self.shell)

    def test_exact_baseline_postadd_world_record_and_inventory_are_pinned(self) -> None:
        for literal in (
            "b61419fa3c96feaf5d2e1b1f4e0aaab27e252d2ae2e6d47d33a56e3538ba7da4",
            "00a770856b6f2a1d15063c9e5085a3fea7e0e2d5ee5f421138ee90a06217a465",
            "fc9af3810c6baf8f1dbd389a6b13bc354d11dd34e0819e95717f1fc3f7c45039",
            "ee66cbf049c70c6c992f27da83d45166a02c9b16c1efcf4b2206791a0adcacf7",
            "6523d36fa3490b4f518184bb0d5a1dd025f14e93ead2b0f9a80f82d685a953f0",
            "38bdd6fd1ecd51bbd3b8d06b6e50952a483aa2584de5d4ecb679b46c4d6d0c36",
            "a0e872f6d79f718789964910475abd999f0fe35bd29384fa65a244c3b75dd197",
            "e4c4e56e54317d11dcf3792529f091790e55a917833a4cc1d7db90820088ef5b",
            "device-xiaomi-lmi-terminal><Q1FNANyYbzQO5vT8J9epgsMCV1nNg=",
            'expected_value["P"]="device-xiaomi-lmi-terminal"',
            'expected_value["V"]="0.1.0-r0"',
            'expected_value["A"]="noarch"',
            'expected_value["S"]="7929"',
            'expected_value["I"]="19693"',
            'expected_value["o"]="device-xiaomi-lmi-terminal"',
            'expected_value["c"]="uncommitted-p2-d114-source-lock-v1"',
            'if (count["C"] != 1 || value["C"] != package_checksum)',
            'if (count["D"] != 1 || value["D"] != expected_D)',
            'count["R"] != 5',
            'broken_policy == "clean" && f_count != 0',
        ):
            self.assertIn(literal, self.shell)
        for path in (
            "/etc/lmi-p2-d114",
            "/usr/libexec/lmi-p2-d114",
            "/usr/share/lmi-p2-d114",
            "/var/lib/lmi-p2-d114",
            "/etc/conf.d/.greetd.lmi-p2-d114-new",
        ):
            self.assertIn(path, self.shell)

    def test_package_record_verifier_accepts_only_the_exact_clean_or_broken_shape(self) -> None:
        dependencies = " ".join(
            (
                "device-xiaomi-lmi=1-r142",
                "greetd=0.10.3-r11",
                "greetd-openrc=0.10.3-r11",
                "greetd-phrog=0.53.0-r0",
                "libseat=0.9.3-r0",
                "libweston=14.0.2-r10",
                "linux-xiaomi-lmi=4.19.325-r9",
                "openrc=0.63.2-r0",
                "seatd=0.9.3-r0",
                "seatd-openrc=0.9.3-r0",
                "weston=14.0.2-r10",
                "weston-backend-drm=14.0.2-r10",
                "weston-shell-desktop=14.0.2-r10",
                "weston-terminal=14.0.2-r10",
                "/bin/sh",
            )
        )
        clean = (
            "C:Q1FNANyYbzQO5vT8J9epgsMCV1nNg=\n"
            "P:device-xiaomi-lmi-terminal\n"
            "V:0.1.0-r0\nA:noarch\nS:7929\nI:19693\n"
            "T:Pinned non-root Weston terminal session for Xiaomi lmi D114\n"
            "U:https://postmarketos.org\nL:MIT\n"
            "o:device-xiaomi-lmi-terminal\n"
            "m:lmi P2 maintainers <noreply@example.invalid>\n"
            "t:1784522705\nc:uncommitted-p2-d114-source-lock-v1\n"
            f"D:{dependencies}\n"
            "F:etc\nF:etc/lmi-p2-d114\n"
            "R:greetd.toml\nZ:Q17aD3D/27DhKiygFdfBjjWQ46v/4=\n"
            "R:weston.ini\nZ:Q1LAAnmdOVCpbwvFJEu23JxDl9w4U=\n"
            "F:usr\nF:usr/libexec\nF:usr/libexec/lmi-p2-d114\n"
            "R:config-lifecycle\na:0:0:755\nZ:Q1fz2JibH7B8jAdosh8vogpdSyQZM=\n"
            "R:session\na:0:0:755\nZ:Q1lfFk1wgoedOPUHfcdzHO2YBct/k=\n"
            "F:usr/share\nF:usr/share/lmi-p2-d114\n"
            "R:greetd.confd\nZ:Q11ujOtYABrGQSohB67SphVfwH5C8=\n\n"
        )
        accepted = self.run_record_verifier(clean, "clean")
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertNotEqual(self.run_record_verifier(clean, "broken").returncode, 0)

        broken = clean.replace(f"D:{dependencies}\n", f"D:{dependencies}\nf:\n")
        self.assertEqual(self.run_record_verifier(broken, "broken").returncode, 0)
        self.assertNotEqual(self.run_record_verifier(broken, "clean").returncode, 0)
        for drifted in (
            clean.replace("S:7929", "S:7930"),
            clean.replace("C:Q1FN", "C:Q1XX"),
            clean.replace(
                "D:device-xiaomi-lmi=1-r142 greetd=0.10.3-r11",
                "D:greetd=0.10.3-r11 device-xiaomi-lmi=1-r142",
            ),
            clean.replace("R:greetd.confd", "R:extra\nR:greetd.confd"),
            clean.replace("\n\n", "\np:unexpected=1\n\n"),
        ):
            self.assertNotEqual(
                self.run_record_verifier(drifted, "clean").returncode,
                0,
            )

    def test_state_classification_and_cleanup_are_fail_closed(self) -> None:
        for literal in (
            "if success_exact; then",
            "if baseline_exact && keys_inventory_unchanged; then",
            "if broken_pending_recoverable; then",
            "installed_other_records_exact",
            "lifecycle_pending_recoverable",
            "verified apk del did not restore the exact baseline",
            "post-add state is unknown; no rollback attempted and evidence retained",
            "staging cleanup failed; inspect",
        ):
            self.assertIn(literal, self.shell)
        success_block = self.shell.index("if success_exact; then")
        cleanup_call = self.shell.index("finish_clean 0 'live_p2_install=verified'", success_block)
        self.assertGreater(cleanup_call, success_block)
        finish_definition = self.shell.index("finish_clean()")
        finish_print = self.shell.index("printf '%s\\n' \"$message\"", finish_definition)
        finish_cleanup = self.shell.index("cleanup_staging", finish_definition)
        self.assertLess(finish_cleanup, finish_print)
        self.assertIn("canonical_keys_inventory >\"$evidence/keys.before\"", self.shell)
        self.assertIn("keys_inventory_unchanged", self.shell)
        self.assertIn("pmos@local-6a5d38f2.rsa.pub", self.shell)

    def test_installer_has_no_service_boot_reboot_flash_or_partition_action(self) -> None:
        executable = "\n".join(
            line for line in self.shell.splitlines() if not line.lstrip().startswith("#")
        )
        for forbidden in (
            "rc-service",
            "rc-update",
            "systemctl",
            " fastboot ",
            " reboot ",
            " flash ",
            "service start",
        ):
            self.assertNotIn(forbidden, executable)


if __name__ == "__main__":
    unittest.main()
