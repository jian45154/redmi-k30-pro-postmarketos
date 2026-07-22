from __future__ import annotations

import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import tarfile
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.build as build_module
from scripts.lmi_p1.common import GateError, sha256_file
import scripts.lmi_p1.known_good_kernel as package_module


REPOSITORY = Path(__file__).resolve().parents[2]


class KnownGoodKernelArtifactTests(unittest.TestCase):
    def test_production_artifacts_are_exactly_source_locked(self):
        source_lock = json.loads(
            (REPOSITORY / "config/lmi-p1/source-lock.json").read_text(
                encoding="utf-8"
            )
        )
        pin = source_lock["known_good_kernel_package"]
        self.assertEqual(pin, build_module._EXPECTED_KNOWN_GOOD_KERNEL_PIN)
        for field in ("artifact", "pmbootstrap_status_index", "signer_public_key"):
            artifact = REPOSITORY / pin[field]["path"]
            metadata = artifact.lstat()
            self.assertFalse(artifact.is_symlink())
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(metadata.st_size, pin[field]["size"])
            self.assertEqual(sha256_file(artifact), pin[field]["sha256"])

        self.assertEqual(
            pin["payload"]["boot/vmlinuz"]["sha256"],
            "38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e",
        )
        self.assertEqual(
            pin["artifact"]["world_checksum"],
            "Q17Cf8DcVUIUw2n/xDNf7Pr9WKqpU=",
        )
        self.assertEqual(
            pin["source_apk"],
            {
                "acquisition_provenance": "unavailable",
                "format": "apk-v2",
                "sha256": package_module.SOURCE_APK_SHA256,
                "signature_verification": {
                    "apk_tools_sha256": package_module.APK_STATIC_SHA256,
                    "result": "untrusted-signature",
                    "signer_provenance": "unavailable",
                },
                "size": package_module.SOURCE_APK_SIZE,
            },
        )
        self.assertNotIn(
            "4583ada334aec2e4602519f7559f8a86026681f2a41497438a649d38090e5428",
            json.dumps(source_lock, sort_keys=True),
        )
        package = REPOSITORY / pin["artifact"]["path"]
        self.assertNotIn(b"BEGIN PRIVATE KEY", package.read_bytes())
        self.assertNotIn(b"BEGIN RSA PRIVATE KEY", package.read_bytes())

    def test_sealed_staging_uses_status_only_then_direct_signed_apkv3(self):
        pin = build_module._EXPECTED_KNOWN_GOOD_KERNEL_PIN
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            shutil.copytree(
                REPOSITORY / "artifacts/lmi-p1/known-good-kernel",
                project / "artifacts/lmi-p1/known-good-kernel",
            )
            work = root / "work"
            work.mkdir()

            status = build_module._stage_known_good_kernel_status(
                project, work, pin
            )
            self.assertEqual(
                sha256_file(status),
                "62578fea929f40c9b8ee8a66d96eefb2daaf6b77fb86be52a240d2979d76fe3b",
            )
            self.assertFalse(
                (status.parent / package_module.OUTPUT_APK_NAME).exists()
            )
            with self.assertRaisesRegex(GateError, "still advertises a kernel"):
                build_module._stage_known_good_kernel_install(project, work, pin)

            index_text = (
                "P:postmarketos-initramfs\nV:2-r0\nA:aarch64\n\n"
                "P:device-xiaomi-lmi\nV:1-r107\nA:aarch64\n\n"
            ).encode("ascii")
            info = tarfile.TarInfo("APKINDEX")
            info.size = len(index_text)
            with tarfile.open(status, mode="w:gz") as archive:
                archive.addfile(info, io.BytesIO(index_text))
            package = build_module._stage_known_good_kernel_install(
                project, work, pin
            )
            self.assertEqual(package.name, package_module.OUTPUT_APK_NAME)
            self.assertEqual(
                sha256_file(package),
                "01b199611407c100c621599bd3060084c19e1fd90f8e9df64cc10966f6949eb0",
            )
            self.assertEqual(
                sha256_file(
                    work
                    / "config_apk_keys/lmi-p1-known-good-kernel.rsa.pub"
                ),
                "c42ba833751ab9ca164c506cd72c2c3b9a6079db09ebe2cf52838ae79e936736",
            )
            self.assertEqual(
                build_module._known_good_install_add(package),
                "unudhcpd-openrc,linux-xiaomi-lmi=4.19.325-r8," + str(package),
            )
            self.assertTrue(package.is_absolute())
            self.assertEqual(
                package,
                work
                / "packages/edge/aarch64"
                / package_module.OUTPUT_APK_NAME,
            )
            self.assertNotIn("/mnt/pmbootstrap/", str(package))

    def test_installed_database_checksum_encoding_is_apkv3_sha256_prefix(self):
        expected = {
            path: "Q1"
            + base64.b64encode(bytes.fromhex(values[0])[:20]).decode("ascii")
            for path, values in package_module.PAYLOAD.items()
        }
        self.assertEqual(
            expected["boot/vmlinuz"],
            "Q1OMODkMqaR0tNKdJPslrZE5u1jio=",
        )
        for path, checksum in expected.items():
            self.assertEqual(
                build_module._known_good_installed_checksum(
                    package_module.PAYLOAD[path][0]
                ),
                checksum,
            )

    def test_only_the_locked_apkv3_world_checksum_can_be_rewritten(self):
        checksum_spec = (
            "linux-xiaomi-lmi><" + package_module.PACKAGE_WORLD_CHECKSUM
        )
        with tempfile.TemporaryDirectory() as temporary:
            world = Path(temporary) / "world"
            world.write_text(checksum_spec + "\npostmarketos-ui-shelli\n")
            build_module._pin_exact_world_package(
                world,
                package_module.PACKAGE_NAME,
                package_module.PACKAGE_VERSION,
                allowed_current=(checksum_spec,),
            )
            self.assertEqual(
                world.read_text(),
                "linux-xiaomi-lmi=4.19.325-r8\npostmarketos-ui-shelli\n",
            )
            world.write_text("linux-xiaomi-lmi><Q1attacker=\n")
            with self.assertRaisesRegex(GateError, "conflicting world constraint"):
                build_module._pin_exact_world_package(
                    world,
                    package_module.PACKAGE_NAME,
                    package_module.PACKAGE_VERSION,
                    allowed_current=(checksum_spec,),
                )

    def test_installed_payload_verification_does_not_normalize_bad_modes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            payload = root / "boot/vmlinuz"
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b"known-good-test\n")
            payload.parent.chmod(0o755)
            payload.chmod(0o600)
            sha256 = hashlib.sha256(payload.read_bytes()).hexdigest()
            q1 = "Q1" + base64.b64encode(
                hashlib.sha1(payload.read_bytes(), usedforsecurity=False).digest()
            ).decode("ascii")
            fixture = {"boot/vmlinuz": (sha256, q1, 0o644)}
            with mock.patch.object(package_module, "PAYLOAD", fixture):
                with self.assertRaisesRegex(package_module.PackageError, "mode"):
                    package_module._payload_inventory(root)
                self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o600)
                package_module._payload_inventory(root, normalize=True)
                self.assertEqual(stat.S_IMODE(payload.stat().st_mode), 0o644)

    def test_external_commands_do_not_inherit_hostile_environment(self):
        completed = mock.Mock(returncode=0, stdout="ok\n", stderr="")
        hostile = {
            "APK_CONFIG": "/attacker/apk-config",
            "LD_PRELOAD": "/attacker/preload.so",
            "PATH": "/attacker/bin",
            "PYTHONPATH": "/attacker/python",
        }
        with mock.patch.dict(os.environ, hostile, clear=False):
            with mock.patch.object(
                package_module.subprocess, "run", return_value=completed
            ) as run:
                self.assertEqual(
                    package_module._run(["/trusted/tool", "--version"]),
                    "ok\n",
                )
        self.assertEqual(run.call_args.args[0], ["/trusted/tool", "--version"])
        environment = run.call_args.kwargs["env"]
        self.assertEqual(environment, dict(package_module.COMMAND_ENVIRONMENT))
        for name in hostile:
            if name != "PATH":
                self.assertNotIn(name, environment)
        self.assertEqual(environment["PATH"], "/usr/bin:/bin")

    def test_mkpkg_uses_absolute_unshare_and_env_helpers(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            workspace = root / "workspace"
            workspace.mkdir()
            with (
                mock.patch.object(package_module, "_stage_payload"),
                mock.patch.object(package_module, "_run", return_value="") as run,
                mock.patch.object(package_module, "_verify_package"),
            ):
                package_module._mkpkg(
                    root / "apk.static",
                    root / "signing-key",
                    root / "signer-public-key",
                    root / "source.apk",
                    root / "vmlinuz",
                    root / "output.apk",
                    workspace,
                )
        command = run.call_args.args[0]
        self.assertEqual(command[0], "/usr/bin/unshare")
        self.assertEqual(command[4], "/usr/bin/env")
        self.assertTrue(Path(command[0]).is_absolute())
        self.assertTrue(Path(command[4]).is_absolute())


if __name__ == "__main__":
    unittest.main()
