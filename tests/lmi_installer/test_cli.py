from __future__ import annotations

import argparse
import ast
from contextlib import redirect_stderr, redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import lmi_cli_installer as installer


class InstallerFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.boot = root / "boot.img"
        self.rootfs = root / "userdata.img"
        self.manifest = root / "build.manifest"
        self.recovery = root / "RECOVERY.md"
        self.fastboot = root / "fastboot"
        self.log = root / "fastboot.log"
        self.write_boot()
        self.write_sparse()
        self.manifest.write_text("build=fixture\n", encoding="ascii")
        self.recovery.write_text("Fixture recovery guide.\n", encoding="ascii")
        self.log.write_text("", encoding="ascii")
        self.write_fastboot()

    def write_boot(self) -> None:
        header = bytearray(4096)
        header[:8] = b"ANDROID!"
        struct.pack_into("<I", header, 8, 1)
        struct.pack_into("<I", header, 16, 1)
        struct.pack_into("<I", header, 36, 4096)
        self.boot.write_bytes(bytes(header) + b"K" + b"\0" * 4095 + b"R")

    def write_sparse(self) -> None:
        header = installer.SPARSE_HEADER.pack(
            installer.SPARSE_MAGIC,
            1,
            0,
            installer.SPARSE_HEADER.size,
            installer.SPARSE_CHUNK.size,
            4096,
            1,
            1,
            0,
        )
        chunk = installer.SPARSE_CHUNK.pack(
            0xCAC1, 0, 1, installer.SPARSE_CHUNK.size + 4096
        )
        self.rootfs.write_bytes(header + chunk + b"R" * 4096)

    def write_fastboot(self) -> None:
        self.fastboot.write_text(
            """#!/usr/bin/env sh
set -eu
printf '%s\\n' "$*" >> "$FAKE_FASTBOOT_LOG"
if [ "$1" = "--version" ]; then
    printf 'fastboot version fixture\\n'
    exit 0
fi
if [ "$1" = "devices" ]; then
    printf '%s\\tfastboot\\n' "${FAKE_SERIAL:-FIXTURE-LMI}"
    if [ "${FAKE_EXTRA_DEVICE:-0}" = 1 ]; then
        printf 'SECOND-LMI\\tfastboot\\n'
    fi
    exit 0
fi
[ "$1" = "-s" ] || exit 40
[ "$2" = "${FAKE_SERIAL:-FIXTURE-LMI}" ] || exit 41
if [ "$3" = "getvar" ]; then
    if [ "${FAKE_FAIL_GETVAR:-0}" = 1 ]; then
        printf 'stdout contains raw serial %s\\n' "$2"
        printf 'stderr contains raw serial %s\\n' "$2" >&2
        exit 47
    fi
    key=$4
    case "$key" in
        product) value=${FAKE_PRODUCT:-lmi} ;;
        unlocked) value=yes ;;
        is-userspace) value=${FAKE_USERSPACE:-yes} ;;
        battery-voltage) value=4200 ;;
        partition-size:boot) value=0x08000000 ;;
        partition-size:userdata) value=0x100000000 ;;
        *) exit 42 ;;
    esac
    printf '%s: %s\\n' "$key" "$value" >&2
    exit 0
fi
exit 46
""",
            encoding="ascii",
        )
        self.fastboot.chmod(0o755)

    def build_args(self, output: Path) -> argparse.Namespace:
        return argparse.Namespace(
            boot=self.boot,
            rootfs=self.rootfs,
            build_manifest=self.manifest,
            recovery_guide=self.recovery,
            release_id="fixture-lmi-1",
            source_commit="a" * 40,
            channel="experimental",
            minimum_battery_mv=3800,
            sparse_limit="256M",
            output=output,
        )


class InstallerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = InstallerFixture(self.root)
        self.old_log = os.environ.get("FAKE_FASTBOOT_LOG")
        os.environ["FAKE_FASTBOOT_LOG"] = str(self.fixture.log)

    def tearDown(self) -> None:
        if self.old_log is None:
            os.environ.pop("FAKE_FASTBOOT_LOG", None)
        else:
            os.environ["FAKE_FASTBOOT_LOG"] = self.old_log
        self.temporary.cleanup()

    def make_bundle(self, name: str = "audit-only") -> installer.Profile:
        output = self.root / name
        installer.build_bundle(self.fixture.build_args(output))
        return installer.load_profile(output / "installer-profile.json")

    def test_cli_reports_the_release_version(self) -> None:
        result = subprocess.run(
            [str(Path(installer.__file__).with_name("lmi-installer")), "--version"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "lmi-installer 0.1.0-alpha.1\n")
        self.assertEqual(result.stderr, "")

    def test_builder_creates_self_contained_verification_only_bundle(self) -> None:
        profile = self.make_bundle()
        self.assertFalse(profile.release_eligible)
        installer.verify_bundle(profile)
        self.assertTrue((profile.root / "lmi-installer").is_file())
        self.assertTrue((profile.root / "lmi_cli_installer.py").is_file())
        self.assertTrue((profile.root / "SHA256SUMS").is_file())
        self.assertEqual(profile.artifacts["rootfs"].logical_size, 4096)
        result = subprocess.run(
            [str(profile.root / "lmi-installer"), "verify"],
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("bundle_verify=OK", result.stdout)

    def test_builder_never_trusts_injected_legacy_execution_flags(self) -> None:
        output = self.root / "injected-legacy-flags"
        arguments = self.fixture.build_args(output)
        arguments.enable_execution = True
        arguments.i_verified_this_exact_build_on_lmi = True
        installer.build_bundle(arguments)
        profile = installer.load_profile(output / "installer-profile.json")
        self.assertFalse(profile.release_eligible)

    def test_corrupted_artifact_fails_before_device_access(self) -> None:
        profile = self.make_bundle()
        profile.artifacts["rootfs"].path.write_bytes(b"corrupt")
        with self.assertRaisesRegex(installer.InstallerError, "size mismatch"):
            installer.verify_bundle(profile)
        self.assertEqual(self.fixture.log.read_text(encoding="ascii"), "")

    def test_sparse_parser_rejects_truncated_payload(self) -> None:
        truncated = self.root / "truncated.img"
        truncated.write_bytes(self.fixture.rootfs.read_bytes()[:-1])
        with self.assertRaisesRegex(installer.InstallerError, "truncated"):
            installer._verify_sparse(truncated, 4096)

    def test_install_is_dry_run_without_device_access(self) -> None:
        profile = self.make_bundle()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            installer,
            "Fastboot",
            side_effect=AssertionError("install must not construct Fastboot"),
        ), mock.patch.object(
            installer,
            "_host_kind",
            side_effect=AssertionError("install must not probe the device path"),
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            status = installer.main(["install", "--profile", str(profile.path)])
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn("dry_run=OK", stdout.getvalue())
        self.assertIn("no device was accessed", stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        self.assertEqual(self.fixture.log.read_text(encoding="ascii"), "")

    def test_preflight_selects_one_lmi_and_redacts_serial(self) -> None:
        profile = self.make_bundle()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            status = installer.main(
                [
                    "preflight",
                    "--profile",
                    str(profile.path),
                    "--fastboot",
                    str(self.fixture.fastboot),
                ]
            )
        output = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(status, 0, stderr.getvalue())
        self.assertIn(
            f"device_fingerprint={hashlib.sha256(b'FIXTURE-LMI').hexdigest()[:12]}",
            output,
        )
        self.assertNotIn("FIXTURE-LMI", output)

    def test_multiple_devices_fail_without_state_change(self) -> None:
        profile = self.make_bundle()
        fastboot = installer.Fastboot(str(self.fixture.fastboot))
        os.environ["FAKE_EXTRA_DEVICE"] = "1"
        try:
            with self.assertRaisesRegex(installer.InstallerError, "exactly one"):
                installer.inspect_device(fastboot, profile)
        finally:
            os.environ.pop("FAKE_EXTRA_DEVICE", None)
        self.assertNotIn(
            " flash ", f" {self.fixture.log.read_text(encoding='ascii')} "
        )

    def test_wrong_product_fails_closed(self) -> None:
        profile = self.make_bundle()
        fastboot = installer.Fastboot(str(self.fixture.fastboot))
        old = os.environ.get("FAKE_PRODUCT")
        os.environ["FAKE_PRODUCT"] = "raphael"
        try:
            with self.assertRaisesRegex(installer.InstallerError, "product must be lmi"):
                installer.inspect_device(fastboot, profile)
        finally:
            if old is None:
                os.environ.pop("FAKE_PRODUCT", None)
            else:
                os.environ["FAKE_PRODUCT"] = old

    def test_fastboot_failure_does_not_echo_output_or_raw_serial(self) -> None:
        profile = self.make_bundle()
        raw_serial = "PRIVATE-LMI-SERIAL-123"
        os.environ["FAKE_SERIAL"] = raw_serial
        os.environ["FAKE_FAIL_GETVAR"] = "1"
        stdout = io.StringIO()
        stderr = io.StringIO()
        try:
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = installer.main(
                    [
                        "preflight",
                        "--profile",
                        str(profile.path),
                        "--fastboot",
                        str(self.fixture.fastboot),
                    ]
                )
        finally:
            os.environ.pop("FAKE_SERIAL", None)
            os.environ.pop("FAKE_FAIL_GETVAR", None)
        output = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(status, 2)
        self.assertNotIn(raw_serial, output)
        self.assertNotIn("stdout contains", output)
        self.assertNotIn("stderr contains", output)
        self.assertIn("fastboot query failed with status 47", output)

    def test_fastboot_wrapper_rejects_state_change_before_subprocess(self) -> None:
        fastboot = installer.Fastboot(str(self.fixture.fastboot))
        with self.assertRaisesRegex(installer.InstallerError, "read-only"):
            fastboot.run(["reboot"])
        self.assertEqual(self.fixture.log.read_text(encoding="ascii"), "")

    def test_parser_rejects_legacy_execution_interfaces(self) -> None:
        rejected = [
            ["enter-fastbootd"],
            ["flash-rootfs"],
            ["flash-boot"],
            ["reboot"],
            ["install", "--execute"],
        ]
        build = [
            "build-bundle",
            "--boot",
            "boot.img",
            "--rootfs",
            "userdata.img",
            "--build-manifest",
            "build.manifest",
            "--recovery-guide",
            "RECOVERY.md",
            "--release-id",
            "fixture-lmi-1",
            "--source-commit",
            "a" * 40,
            "--output",
            "bundle",
        ]
        rejected.extend(
            [
                [*build, "--enable-execution"],
                [*build, "--i-verified-this-exact-build-on-lmi"],
            ]
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments), redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    installer.parser().parse_args(arguments)
                self.assertEqual(raised.exception.code, 2)

    def test_source_contains_no_fastboot_state_change_argv(self) -> None:
        source = Path(installer.__file__).read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)
        self.assertNotIn("def _write", source)
        tree = ast.parse(source)
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if not isinstance(call.func, ast.Attribute) or call.func.attr != "run":
                continue
            if not call.args or not isinstance(call.args[0], (ast.List, ast.Tuple)):
                continue
            argv = {
                item.value
                for item in call.args[0].elts
                if isinstance(item, ast.Constant) and isinstance(item.value, str)
            }
            self.assertTrue(argv.isdisjoint({"flash", "reboot"}), argv)
        for forbidden in (
            '"super"',
            '"dtbo"',
            '"vbmeta"',
            '"persist"',
            '"modem"',
            '"erase"',
            '"format"',
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
