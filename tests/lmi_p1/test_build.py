from __future__ import annotations

import base64
from contextlib import redirect_stdout
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import stat
import struct
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.build as build_module
from scripts.lmi_p1.build import BuildContext, BuildResult, build_candidate
from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.pmaports import prepare_pmaports
import scripts.lmi_p1_cli as cli_module
from tests.lmi_p1.test_pmaports import (
    APKBUILD as PMAPORTS_APKBUILD,
    INIT_2ND as PMAPORTS_INIT_2ND,
    INIT_FUNCTIONS as PMAPORTS_INIT_FUNCTIONS,
    PATCH as PMAPORTS_PATCH,
)


REPO = Path(__file__).resolve().parents[2]
PAYLOAD = REPO / "files/lmi-p1"


def _source_lock_v3_fixture(value: dict[str, object]) -> dict[str, object]:
    result = json.loads(json.dumps(value))
    result["schema"] = "lmi-source-lock/v3"
    result["offline_cache"] = {
        "aggregate_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "schema": "lmi-p1-offline-cache/v2",
    }
    return result


class RootfsPolicyTests(unittest.TestCase):
    def test_sshd_policy_is_exact(self):
        expected = """\
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers lmi
UsePAM yes
DisableForwarding no
PermitTTY yes
AllowAgentForwarding yes
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
PermitOpen any
PermitListen any
GatewayPorts no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
LogLevel VERBOSE
Subsystem sftp internal-sftp
"""
        self.assertEqual((PAYLOAD / "sshd_config").read_text(), expected)

    def test_sudoers_grants_only_the_allowlisted_helper(self):
        self.assertEqual(
            (PAYLOAD / "90-lmi-rootctl").read_text(),
            "lmi ALL=(root) NOPASSWD: /usr/sbin/lmi-rootctl\n",
        )
        sudoers = PAYLOAD / "sudoers"
        self.assertTrue(sudoers.is_file())
        self.assertEqual(
            sudoers.read_text(),
            "root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n",
        )

    def test_packaged_and_finalizer_rootctl_are_byte_identical_and_checksummed(self):
        packaged = (
            REPO / "artifacts/wsl-pmaports/device-xiaomi-lmi/lmi-rootctl"
        )
        finalizer = PAYLOAD / "lmi-rootctl"
        self.assertEqual(packaged.read_bytes(), finalizer.read_bytes())
        expected = hashlib.sha512(packaged.read_bytes()).hexdigest()
        apkbuild = (
            REPO / "artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD"
        ).read_text()
        matches = re.findall(
            rf"^([0-9a-f]{{128}})  {re.escape(packaged.name)}$",
            apkbuild,
            flags=re.MULTILINE,
        )
        self.assertEqual(matches, [expected])

    def test_headless_package_policy_rejects_any_pmbootstrap_ui_package(self):
        packages = [
            "device-xiaomi-lmi-1-r145",
            "linux-xiaomi-lmi-4.19.325-r8",
            "postmarketos-ui-shelli-3-r8",
        ]
        with self.assertRaisesRegex(GateError, "forbidden UI packages.*shelli"):
            build_module._verify_package_policy(packages)

    def test_headless_package_has_no_display_manager_session_path(self):
        package = REPO / "artifacts/wsl-pmaports/device-xiaomi-lmi"
        apkbuild = (package / "APKBUILD").read_text()
        post_install = (package / "device-xiaomi-lmi.post-install").read_text()
        power_panel_init = (package / "lmi-power-panel.initd").read_text()
        splash_release_init = (package / "lmi-splash-release.initd").read_text()
        for prohibited in (
            "greetd",
            "lmi-greetd",
            "lmi-phosh-session",
            "phosh-session",
            "\ttinydm\n",
        ):
            with self.subTest(prohibited=prohibited):
                self.assertNotIn(prohibited, apkbuild)
                self.assertNotIn(prohibited, post_install)
        self.assertNotIn("greetd", power_panel_init)
        self.assertNotIn("greetd", splash_release_init)
        self.assertNotIn(
            '"$pkgdir"/etc/runlevels/default/lmi-power-panel',
            apkbuild,
        )
        self.assertNotIn(
            '"$pkgdir"/etc/runlevels/default/lmi-splash-release',
            apkbuild,
        )
        self.assertIn(
            'exec /usr/sbin/lmi-display-takeover',
            (package / "lmi-rootctl").read_text(),
        )
        for removed in (
            "lmi-greetd-config.toml",
            "lmi-greetd-log",
            "lmi-phosh-session-log",
        ):
            with self.subTest(removed=removed):
                self.assertFalse((package / removed).exists())

    def test_headless_package_policy_rejects_display_session_packages(self):
        for forbidden in (
            "greetd-0.10.3-r11",
            "greetd-openrc-0.10.3-r11",
            "phoc-0.46.0-r0",
            "phosh-0.46.0-r0",
            "phosh-mobile-settings-0.46.0-r0",
            "postmarketos-base-ui-tinydm-55-r0",
            "tinydm-1.3.1-r1",
            "tinydm-openrc-1.3.1-r1",
        ):
            with self.subTest(forbidden=forbidden):
                packages = [
                    "device-xiaomi-lmi-1-r145",
                    "linux-xiaomi-lmi-4.19.325-r8",
                    forbidden,
                ]
                with self.assertRaisesRegex(
                    GateError,
                    "forbidden headless session packages.*"
                    + re.escape(forbidden),
                ):
                    build_module._verify_package_policy(packages)

    def test_usb0_networkmanager_profile_is_exact(self):
        expected = """\
[connection]
id=lmi-usb0
type=ethernet
interface-name=usb0
autoconnect=true
autoconnect-priority=100

[ethernet]

[ipv4]
method=manual
address1=172.16.42.1/24
never-default=true

[ipv6]
method=disabled
"""
        profile = PAYLOAD / "lmi-usb0.nmconnection"
        self.assertTrue(profile.is_file())
        self.assertEqual(profile.read_text(), expected)
        self.assertNotIn("shared", expected)

    def test_usb0_dhcp_runtime_and_openrc_policy_are_exact(self):
        wrapper = (PAYLOAD / "lmi-usb0-dhcp").read_text()
        service = (PAYLOAD / "lmi-usb0-dhcp.initd").read_text()
        config = (PAYLOAD / "unudhcpd.usb0.confd").read_text()
        self.assertEqual(wrapper.count('rc-service "$dhcp_service" start'), 1)
        self.assertIn("profile=lmi-usb0", wrapper)
        self.assertIn("interface=usb0", wrapper)
        self.assertIn("dhcp_service=unudhcpd.usb0", wrapper)
        self.assertNotIn("method=shared", wrapper)
        self.assertIn("need net", service)
        self.assertIn("after networkmanager", service)
        self.assertEqual(
            config.splitlines()[-1],
            'command_args="-i usb0 -s 172.16.42.1 -c 172.16.42.2"',
        )

    def test_usb0_networkmanager_takeover_policy_is_exact(self):
        expected = """\
[device-lmi-usb0]
match-device=interface-name:usb0
managed=1
keep-configuration=no
"""
        policy = PAYLOAD / "90-lmi-usb0-takeover.conf"
        self.assertTrue(policy.is_file())
        self.assertEqual(policy.read_text(), expected)

    def test_finalizer_closes_privilege_world_and_usb_policy(self):
        finalizer = build_module._finalizer_script()
        for marker in (
            '/bin/cp "$stage/sudoers" /etc/sudoers',
            "/usr/bin/visudo -cf /etc/sudoers",
            "/usr/bin/sudo -n -l -U lmi",
            "/usr/sbin/delgroup lmi wheel",
            "/usr/bin/id -nG lmi",
            "/bin/rm -f /etc/doas.conf /etc/doas.d/* /etc/doas.d/.[!.]* /etc/doas.d/..?*",
            "/bin/rm -f /etc/sudoers.d/* /etc/sudoers.d/.[!.]* /etc/sudoers.d/..?*",
            '/bin/cp "$stage/world" /etc/apk/world',
            '/bin/cp "$stage/lmi-usb0.nmconnection"',
            "/etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
            '/bin/cp "$stage/90-lmi-usb0-takeover.conf"',
            "/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
            "/bin/chmod 0600 /etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
            "/bin/chmod 0644 /etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
            "/bin/chown root:root /etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
            '/usr/bin/cmp -s "$stage/90-lmi-usb0-takeover.conf"',
            '/bin/cp "$stage/lmi-usb0-dhcp" /usr/sbin/lmi-usb0-dhcp',
            '/bin/cp "$stage/lmi-usb0-dhcp.initd" /etc/init.d/lmi-usb0-dhcp',
            '/bin/cp "$stage/unudhcpd.usb0.confd" /etc/conf.d/unudhcpd.usb0',
            "/bin/ln -s unudhcpd /etc/init.d/unudhcpd.usb0",
            "/sbin/rc-update add lmi-usb0-dhcp default",
            "/bin/rm -f /etc/runlevels/default/unudhcpd",
            "/bin/chown root:root /etc/ssh/sshd_config",
            "/bin/chown root:root /usr/sbin/lmi-rootctl",
            "/bin/chown root:root /etc/lmi-release-identity",
            "/bin/rm -f /etc/machine-id",
            "/bin/cp /etc/shadow /etc/shadow-",
            "/usr/bin/cmp -s /etc/shadow /etc/shadow-",
            "lmi:x:10000:10000::/home/lmi:/bin/ash",
            "lmi:!::0:99999:7:::",
            '[ "$(/usr/bin/readlink /usr/bin/ash)" = /usr/bin/busybox ]',
            "for nologin_path in /etc/nologin /run/nologin /var/run/nologin",
            "/bin/rm -f /etc/conf.d/networkmanager",
            "/etc/pam.d/base-session-noninteractive",
            "(root) NOPASSWD: /usr/sbin/lmi-rootctl",
        ):
            self.assertIn(marker, finalizer)

    def test_rootctl_bootloader_dispatch_uses_exact_fake_command(self):
        source = (PAYLOAD / "lmi-rootctl").read_text()
        self.assertIn('exec /sbin/reboot bootloader', source)
        self.assertNotIn("sh -c", source)
        self.assertNotIn("eval", source)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"
            fake_reboot = root / "reboot"
            fake_logger = root / "logger"
            fake_reboot.write_text(
                "#!/bin/sh\nprintf 'reboot' >> \"$LMI_TEST_CALLS\"\n"
                "for argument do printf ' <%s>' \"$argument\" >> \"$LMI_TEST_CALLS\"; done\n"
                "printf '\\n' >> \"$LMI_TEST_CALLS\"\n"
            )
            fake_logger.write_text(
                "#!/bin/sh\nprintf 'logger' >> \"$LMI_TEST_CALLS\"\n"
                "printf ' <%s>' \"$@\" >> \"$LMI_TEST_CALLS\"\nprintf '\\n' >> \"$LMI_TEST_CALLS\"\n"
                "[ \"${LMI_LOGGER_FAIL:-0}\" -eq 0 ] || exit 9\n"
            )
            fake_reboot.chmod(0o755)
            fake_logger.chmod(0o755)
            harness = root / "lmi-rootctl"
            harness.write_text(
                source.replace("/sbin/reboot", str(fake_reboot)).replace(
                    "/usr/bin/logger", str(fake_logger)
                )
            )
            harness.chmod(0o755)
            env = dict(os.environ, LMI_TEST_CALLS=str(calls), SUDO_USER="lmi")
            completed = subprocess.run(
                [
                    str(harness),
                    "reboot-bootloader",
                    "--confirm",
                    "reboot-bootloader-lmi-p1",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(calls.read_text().splitlines()[-1], "reboot <bootloader>")

            calls.write_text("")
            completed = subprocess.run(
                [str(harness), "reboot"],
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertEqual(calls.read_text(), "")

            completed = subprocess.run(
                [str(harness), "reboot", "--confirm", "reboot-lmi-p1"],
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(calls.read_text().splitlines()[-1], "reboot")

            calls.write_text("")
            env["LMI_LOGGER_FAIL"] = "1"
            completed = subprocess.run(
                [
                    str(harness),
                    "reboot-bootloader",
                    "--confirm",
                    "reboot-bootloader-lmi-p1",
                ],
                text=True,
                capture_output=True,
                check=False,
                env=env,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertFalse(
                any(line.startswith("reboot") for line in calls.read_text().splitlines())
            )

    def test_rootctl_preserves_r144_allowlist_and_optional_wifi_arguments(self):
        source = (PAYLOAD / "lmi-rootctl").read_text()
        self.assertIn("PATH=/usr/sbin:/usr/bin:/sbin:/bin", source)
        self.assertNotIn("sh -c", source)
        self.assertNotIn("eval", source)
        self.assertNotIn('exec "$@"', source)
        for service in (
            "lmi-firmware-mount",
            "lmi-qrtr-ns",
            "lmi-cnss-daemon",
            "lmi-cnss-fs-ready",
            "lmi-wlan-on",
            "pd-mapper",
            "lmi-seatd",
            "rmtfs",
            "tqftpserv",
            "wpa_supplicant",
            "networkmanager",
            "bluetooth",
            "sshd",
        ):
            self.assertIn(service, source)
        for command in (
            "bluetooth-rfkill",
            "adsp-boot",
            "wifi-start",
            "display-probe",
            "display-takeover",
            "poweroff",
            "rc-status",
        ):
            self.assertIn(command, source)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            calls = root / "calls"

            def make_fake(name: str, body: str) -> Path:
                path = root / name
                path.write_text("#!/bin/sh\n" + body)
                path.chmod(0o755)
                return path

            fake_logger = make_fake(
                "logger",
                "printf 'logger' >> \"$LMI_TEST_CALLS\"\n"
                "for argument do printf ' <%s>' \"$argument\" >> \"$LMI_TEST_CALLS\"; done\n"
                "printf '\\n' >> \"$LMI_TEST_CALLS\"\n",
            )
            fake_rc_service = make_fake(
                "rc-service",
                "printf 'rc-service' >> \"$LMI_TEST_CALLS\"\n"
                "for argument do printf ' <%s>' \"$argument\" >> \"$LMI_TEST_CALLS\"; done\n"
                "printf '\\n' >> \"$LMI_TEST_CALLS\"\n",
            )
            fake_wifi = make_fake(
                "lmi-wifi-start",
                "printf 'wifi board=<%s> pre=<%s> post=<%s>' "
                "\"${LMI_WLAN_BOARDDATA:-}\" \"${LMI_WLAN_PRE_ON_DELAY:-}\" "
                "\"${LMI_WLAN_POST_ON_DELAY:-}\" >> \"$LMI_TEST_CALLS\"\n"
                "for argument do printf ' <%s>' \"$argument\" >> \"$LMI_TEST_CALLS\"; done\n"
                "printf '\\n' >> \"$LMI_TEST_CALLS\"\n",
            )
            fake_display_probe = make_fake(
                "lmi-display-probe",
                "printf 'display-probe' >> \"$LMI_TEST_CALLS\"\n"
                "for argument do printf ' <%s>' \"$argument\" >> \"$LMI_TEST_CALLS\"; done\n"
                "printf '\\n' >> \"$LMI_TEST_CALLS\"\n",
            )
            fake_display_takeover = make_fake(
                "lmi-display-takeover",
                "printf 'display-takeover\\n' >> \"$LMI_TEST_CALLS\"\n",
            )
            harness_source = source
            for original, replacement in (
                ("/usr/sbin/rc-service", str(fake_rc_service)),
                ("/sbin/rc-service", str(fake_rc_service)),
                ("/usr/bin/logger", str(fake_logger)),
                ("/usr/sbin/lmi-wifi-start", str(fake_wifi)),
                ("/usr/sbin/lmi-display-probe", str(fake_display_probe)),
                ("/usr/sbin/lmi-display-takeover", str(fake_display_takeover)),
            ):
                harness_source = harness_source.replace(original, replacement)
            harness = root / "lmi-rootctl"
            harness.write_text(harness_source)
            harness.chmod(0o755)
            environment = dict(
                os.environ,
                LMI_TEST_CALLS=str(calls),
                SUDO_USER="lmi",
            )

            def run(*arguments: str) -> tuple[subprocess.CompletedProcess[str], list[str]]:
                calls.write_text("")
                completed = subprocess.run(
                    [str(harness), *arguments],
                    text=True,
                    capture_output=True,
                    check=False,
                    env=environment,
                )
                return completed, calls.read_text().splitlines()

            completed, lines = run("service", "pd-mapper", "status")
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("rc-service <pd-mapper> <status>", lines)

            completed, lines = run(
                "service",
                "pd-mapper",
                "restart",
                "--confirm",
                "service-state-change-xiaomi-lmi",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("rc-service <pd-mapper> <restart>", lines)

            completed, lines = run(
                "service",
                "sshd",
                "restart",
                "--confirm",
                "restart-sshd-lmi-p1",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("rc-service <sshd> <restart>", lines)

            completed, lines = run("service", "unlisted", "status")
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(any(line.startswith("rc-service") for line in lines))

            completed, lines = run(
                "wifi-start",
                "--confirm",
                "wifi-start-xiaomi-lmi",
                "--fs-ready-only",
                "--boarddata",
                "bdwlan.bin",
                "--pre-on-delay",
                "2",
                "--post-on-delay",
                "3",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn(
                "wifi board=<bdwlan.bin> pre=<2> post=<3> <--fs-ready-only>",
                lines,
            )
            for delay in ("0", "45", "120"):
                with self.subTest(accepted_wifi_delay=delay):
                    completed, lines = run(
                        "wifi-start",
                        "--confirm",
                        "wifi-start-xiaomi-lmi",
                        "--pre-on-delay",
                        delay,
                        "--post-on-delay",
                        delay,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)
                    self.assertIn(
                        f"wifi board=<> pre=<{delay}> post=<{delay}>",
                        lines,
                    )
            for option in ("--pre-on-delay", "--post-on-delay"):
                for delay in (
                    "121",
                    "999999999999999999999999999999999999",
                    "-1",
                    "abc",
                ):
                    with self.subTest(rejected_wifi_delay=(option, delay)):
                        completed, lines = run(
                            "wifi-start",
                            "--confirm",
                            "wifi-start-xiaomi-lmi",
                            option,
                            delay,
                        )
                        self.assertEqual(completed.returncode, 2)
                        self.assertFalse(
                            any(line.startswith("wifi") for line in lines)
                        )

            completed, lines = run(
                "wifi-start",
                "--confirm",
                "wifi-start-xiaomi-lmi",
                "--boarddata",
                "../unsafe",
            )
            self.assertEqual(completed.returncode, 2)
            self.assertFalse(any(line.startswith("wifi") for line in lines))

            completed, lines = run(
                "display-probe",
                "--active-all",
                "--confirm",
                "display-takeover-d62-openvt-cleanup-xiaomi-lmi",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("display-probe <--active-all>", lines)

            completed, lines = run(
                "display-takeover",
                "--confirm",
                "display-takeover-d67-clear129-plane58-then-weston-dsi-only-xiaomi-lmi",
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("display-takeover", lines)

    def test_new_p1_production_files_reject_forbidden_literals(self):
        forbidden = (
            "147" + "147",
            "StrictHostKeyChecking" + "=no",
            "--" + "clobber",
            "fastboot " + "erase",
            "fastboot " + "format",
        )
        roots = [
            PAYLOAD,
            REPO / "scripts/lmi_p1",
            REPO / "scripts/lmi_p1_cli.py",
            REPO / "scripts/70_build_downstream_ssh_wifi.sh",
        ]
        forbidden_partitions = (
            "super",
            "vbmeta",
            "dtbo",
            "vendor_boot",
            "init_boot",
            "modem",
            "persist",
        )
        findings: list[str] = []
        for root in roots:
            paths = [root] if root.is_file() else sorted(root.rglob("*"))
            for path in paths:
                if not path.is_file() or "__pycache__" in path.parts:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
                for literal in forbidden:
                    if literal in text:
                        findings.append(f"{path.relative_to(REPO)}: {literal}")
                compact = " ".join(text.split())
                for partition in forbidden_partitions:
                    write = "fastboot " + "flash " + partition
                    if write in compact:
                        findings.append(f"{path.relative_to(REPO)}: {write}")
        self.assertEqual(findings, [])


class PublicInterfaceTests(unittest.TestCase):
    def test_build_result_contract_is_frozen_and_path_typed(self):
        self.assertEqual(
            tuple(BuildContext.__dataclass_fields__),
            (
                "repo",
                "tag",
                "privilege_model",
                "policy_id",
                "source_commit",
                "work",
                "pmaports",
                "pmbootstrap",
                "public_key",
                "public_key_fingerprint",
            ),
        )
        self.assertEqual(
            tuple(BuildResult.__dataclass_fields__),
            (
                "boot_img",
                "userdata_img",
                "vmlinuz",
                "initramfs",
                "dtb_dir",
                "packages",
                "world",
                "sshd_pam",
                "semantics",
                "build_log",
                "identity",
                "manifest",
                "manifest_sha256",
                "artifact_set_id",
            ),
        )
        self.assertTrue(callable(build_candidate))

    def test_cli_build_subcommand_constructs_the_frozen_context(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            expected = BuildResult(
                boot_img=(root / "boot.img").absolute(),
                userdata_img=(root / "xiaomi-lmi.img").absolute(),
                vmlinuz=(root / "vmlinuz").absolute(),
                initramfs=(root / "initramfs").absolute(),
                dtb_dir=(root / "dtbs").absolute(),
                packages=(root / "packages.txt").absolute(),
                world=(root / "world").absolute(),
                sshd_pam=(root / "sshd-pam.json").absolute(),
                semantics=(root / "artifact-semantics.json").absolute(),
                build_log=(root / "build.log").absolute(),
                identity=(root / "identity").absolute(),
                manifest=(root / "artifact-manifest.json").absolute(),
                manifest_sha256="a" * 64,
                artifact_set_id="b" * 64,
            )
            argv = [
                "build",
                "--repo",
                str(REPO),
                "--tag",
                "lmi-p1-ssh-20260719-1",
                "--source-commit",
                "a" * 40,
                "--work",
                str(root / "work"),
                "--pmaports",
                str(root / "pmaports"),
                "--pmbootstrap",
                str(root / "pmbootstrap"),
                "--public-key",
                str(root / "id_ed25519.pub"),
                "--public-key-fingerprint",
                "SHA256:test",
            ]
            output = io.StringIO()
            with mock.patch.object(
                cli_module, "build_candidate", return_value=expected
            ) as called, redirect_stdout(output):
                self.assertEqual(cli_module.main(argv), 0)
            context = called.call_args.args[0]
            self.assertEqual(context.tag, "lmi-p1-ssh-20260719-1")
            self.assertEqual(context.privilege_model, "unsealed-development")
            self.assertEqual(context.policy_id, "none")
            self.assertEqual(context.source_commit, "a" * 40)
            self.assertEqual(context.repo, REPO)
            encoded = json.loads(output.getvalue())
            self.assertEqual(encoded["boot_img"], str(expected.boot_img))

    def test_wrapper_emits_only_a_canonical_request_to_the_fixed_launcher(self):
        wrapper = (REPO / "scripts/70_build_downstream_ssh_wifi.sh").read_text()
        self.assertIn(
            "/usr/bin/sudo -n -- /usr/bin/python3 -I -S -B",
            wrapper,
        )
        self.assertIn(
            "/usr/local/sbin/lmi-p1-root-launcher <\"$request_file\"",
            wrapper,
        )
        self.assertNotIn("| /usr/bin/sudo", wrapper)
        for forbidden in ("lmi_p1_cli.py", '"$@"', "--repo", "--work"):
            self.assertNotIn(forbidden, wrapper)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            request = root / "request"
            arguments = root / "arguments"
            input_kind = root / "input-kind"
            input_path = root / "input-path"
            fake_sudo = root / "sudo"
            fake_sudo.write_text(
                "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$LMI_TEST_ARGUMENTS\"\n"
                "if [ ! -f /proc/self/fd/0 ]; then exit 90; fi\n"
                "printf 'regular\\n' > \"$LMI_TEST_INPUT_KIND\"\n"
                "readlink /proc/self/fd/0 > \"$LMI_TEST_INPUT_PATH\"\n"
                "cat /proc/self/fd/0 > \"$LMI_TEST_REQUEST\"\n"
                "[ \"$(head -c 4 \"$LMI_TEST_REQUEST\")\" = LMIR ] || exit 91\n"
            )
            fake_sudo.chmod(0o755)
            harness = root / "build.sh"
            harness.write_text(wrapper.replace("/usr/bin/sudo", str(fake_sudo)))
            harness.chmod(0o755)
            policy_id = "a" * 64
            completed = subprocess.run(
                [str(harness), policy_id, "lmi-p1-sealed-1"],
                text=True,
                capture_output=True,
                check=False,
                env=dict(
                    os.environ,
                    LMI_TEST_ARGUMENTS=str(arguments),
                    LMI_TEST_REQUEST=str(request),
                    LMI_TEST_INPUT_KIND=str(input_kind),
                    LMI_TEST_INPUT_PATH=str(input_path),
                ),
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertEqual(
                arguments.read_text(),
                "-n -- /usr/bin/python3 -I -S -B /usr/local/sbin/lmi-p1-root-launcher\n",
            )
            self.assertEqual(input_kind.read_text(), "regular\n")
            self.assertFalse(Path(input_path.read_text().strip()).exists())
            framed = request.read_bytes()
            self.assertEqual(framed[:4], b"LMIR")
            self.assertEqual(int.from_bytes(framed[4:8], "big"), len(framed) - 8)
            self.assertEqual(
                framed[8:],
                cli_module._canonical_request_bytes(
                    {
                        "policy_id": policy_id,
                        "schema": "lmi-p1-build-request/v1",
                        "tag": "lmi-p1-sealed-1",
                    }
                ),
            )
            hostile_environment = dict(
                os.environ,
                LMI_TEST_ARGUMENTS=str(arguments),
                LMI_TEST_REQUEST=str(request),
                LMI_TEST_INPUT_KIND=str(input_kind),
                LMI_TEST_INPUT_PATH=str(input_path),
            )
            piped = subprocess.run(
                [str(fake_sudo), "-n", "--", "launcher"],
                input=b"LMIR\x00\x00\x00\x00",
                capture_output=True,
                check=False,
                env=hostile_environment,
            )
            self.assertEqual(piped.returncode, 90)
            plain = root / "plain-request"
            plain.write_bytes(b'{"schema":"lmi-p1-build-request/v1"}\n')
            with plain.open("rb") as stream:
                plain_result = subprocess.run(
                    [str(fake_sudo), "-n", "--", "launcher"],
                    stdin=stream,
                    capture_output=True,
                    check=False,
                    env=hostile_environment,
                )
            self.assertEqual(plain_result.returncode, 91)


class SourceLockAndKernelPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.production_lock = json.loads(
            (REPO / "config/lmi-p1/source-lock.json").read_text()
        )
        self.lock_value = _source_lock_v3_fixture(self.production_lock)

    def _read_lock(self, value: dict[str, object]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "source-lock.json"
            path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
            return build_module._read_source_lock(path)

    def test_public_base_policy_is_exact(self):
        self.assertEqual(self.production_lock["schema"], "lmi-source-lock/v3")
        self.assertEqual(
            self._read_lock(self.production_lock), self.production_lock
        )
        self.assertEqual(self._read_lock(self.lock_value), self.lock_value)
        mutations = (
            ("public_credential_policy", "boot_state", "booted"),
            ("public_credential_policy", "credential_state", "owner-key-provisioned"),
            ("public_credential_policy", "owner_test_artifact", "publish"),
            ("public_credential_policy", "personalization_required", False),
            ("public_credential_policy", "personalization_required", 1),
            ("public_credential_policy", "ssh_ready", True),
            ("release", "source_repo", "attacker/project"),
            ("release", "public_allowed", False),
            ("release", "public_allowed", 1),
            ("release", "visibility", "private"),
        )
        for section, field, replacement in mutations:
            with self.subTest(section=section, field=field):
                value = json.loads(json.dumps(self.lock_value))
                value[section][field] = replacement
                with self.assertRaisesRegex(GateError, "policy mismatch"):
                    self._read_lock(value)

    def test_kernel_source_lock_is_exact(self):
        for field, replacement in (
            ("commit", "0" * 40),
            ("remote", "https://example.invalid/kernel.git"),
            ("sha512", "0" * 128),
            ("version", "4.19.325-r9"),
        ):
            with self.subTest(field=field):
                value = json.loads(json.dumps(self.lock_value))
                value["kernel"][field] = replacement
                with self.assertRaisesRegex(GateError, "kernel pin does not match P1"):
                    self._read_lock(value)

    def test_known_good_kernel_source_lock_is_exact(self):
        mutations = (
            ("artifact", "sha256", "0" * 64),
            ("artifact", "format", "apk-v2"),
            ("artifact", "world_checksum", "Q1attacker="),
            ("identity", "origin", "linux-xiaomi-lmi"),
            ("identity", "version", "4.19.325-r9"),
            ("selection", "sealed_build", "repository-index"),
            ("pmbootstrap_status_index", "install_trust", True),
            ("signer_public_key", "size", True),
            ("source_apk", "acquisition_provenance", "verified"),
            ("source_apk", "size", 1),
        )
        for section, field, replacement in mutations:
            with self.subTest(section=section, field=field):
                value = json.loads(json.dumps(self.lock_value))
                value["known_good_kernel_package"][section][field] = replacement
                with self.assertRaisesRegex(
                    GateError, "known-good kernel pin does not match P1"
                ):
                    self._read_lock(value)

        value = json.loads(json.dumps(self.lock_value))
        value["known_good_kernel_package"]["source_apk"][
            "signature_verification"
        ]["result"] = "verified"
        with self.assertRaisesRegex(
            GateError, "known-good kernel pin does not match P1"
        ):
            self._read_lock(value)

    def test_kernel_apkbuild_is_statically_bound_without_shell_evaluation(self):
        source = REPO / "artifacts/wsl-pmaports/linux-xiaomi-lmi"
        kernel = self.lock_value["kernel"]
        build_module._validate_kernel_apkbuild(source, kernel)
        mutations = (
            ("pkgrel", lambda text: text.replace("pkgrel=8", "pkgrel=9")),
            (
                "commit",
                lambda text: text.replace(
                    "_commit=\"a5b3099017ae581aae8bf597b2f9c8c765026af1\"",
                    "_commit=\"" + "0" * 40 + "\"",
                ),
            ),
            (
                "remote",
                lambda text: text.replace(
                    "url=\"https://github.com/LineageOS/android_kernel_xiaomi_sm8250\"",
                    "url=\"https://example.invalid/kernel\"",
                ),
            ),
            (
                "source-member",
                lambda text: text.replace(
                    "\t$_config\n", "\t$_config\n\tattacker.patch\n"
                ),
            ),
            (
                "skip-checksum",
                lambda text: text.replace(
                    build_module._EXPECTED_KERNEL_TARBALL_SHA512, "SKIP", 1
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (label, mutate) in enumerate(mutations):
                with self.subTest(label=label):
                    package = root / str(index)
                    shutil.copytree(source, package)
                    apkbuild = package / "APKBUILD"
                    apkbuild.write_text(mutate(apkbuild.read_text()))
                    with self.assertRaises(GateError):
                        build_module._validate_kernel_apkbuild(package, kernel)

            package = root / "local-content"
            shutil.copytree(source, package)
            with (package / "config-xiaomi-lmi.aarch64").open("a") as stream:
                stream.write("# mutation\n")
            with self.assertRaisesRegex(GateError, "local source checksum mismatch"):
                build_module._validate_kernel_apkbuild(package, kernel)

    def test_production_kernel_output_digest_is_pinned(self):
        self.assertEqual(
            hashlib.sha256(
                (REPO / "artifacts/wsl-pmaports/linux-xiaomi-lmi/APKBUILD").read_bytes()
            ).hexdigest(),
            build_module._EXPECTED_KERNEL_APKBUILD_SHA256,
        )
        self.assertEqual(
            build_module._EXPECTED_VMLINUZ_SHA256,
            "38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e",
        )


class BuilderTests(unittest.TestCase):
    package_lines = (
        "device-xiaomi-lmi-1-r145",
        "linux-xiaomi-lmi-4.19.325-r8",
    )
    required_versions = {
        "device-xiaomi-lmi": "1-r145",
        "linux-xiaomi-lmi": "4.19.325-r8",
    }
    ephemeral = "runtime-generated-test-password"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "pmbootstrap-argv.jsonl"
        self.pmbootstrap_environment_log = self.root / "pmbootstrap-environment.json"
        self.pmbootstrap_entrypoint_log = self.root / "pmbootstrap-entrypoint.txt"
        self.export_inventory_log = self.root / "pmbootstrap-export-inventory.json"
        self.finalizer_copy = self.root / "finalize-copy"
        self.fake_repo = self.root / "fake-pmbootstrap"
        self.fake_repo.mkdir()
        self.pmbootstrap = self.fake_repo / "pmbootstrap.py"
        self.pmbootstrap.write_text(self._fake_pmbootstrap_source())
        self.pmbootstrap.chmod(0o755)
        self._git("init", "-q", cwd=self.fake_repo)
        self._git("config", "user.name", "LMI test", cwd=self.fake_repo)
        self._git("config", "user.email", "lmi-test@example.invalid", cwd=self.fake_repo)
        self._git("add", "pmbootstrap.py", cwd=self.fake_repo)
        self._git("commit", "-q", "-m", "fake pmbootstrap", cwd=self.fake_repo)
        self.fake_commit = self._git("rev-parse", "HEAD", cwd=self.fake_repo).strip()

        self.pmaports_source = self.root / "pmaports-source"
        self.pmaports_source.mkdir()
        (self.pmaports_source / "pmaports.cfg").write_text(
            "[pmaports]\nchannel = edge\nversion = 7\n"
        )
        (self.pmaports_source / ".gitignore").write_text("*.ignored\n")
        (self.pmaports_source / "device/downstream").mkdir(parents=True)
        (self.pmaports_source / "device/downstream/README.md").write_text(
            "fixture downstream directory\n"
        )
        initramfs_package = (
            self.pmaports_source / "main/postmarketos-initramfs"
        )
        initramfs_package.mkdir(parents=True)
        (initramfs_package / "APKBUILD").write_text(PMAPORTS_APKBUILD)
        (initramfs_package / "init_functions.sh").write_text(
            PMAPORTS_INIT_FUNCTIONS
        )
        (initramfs_package / "init_2nd.sh").write_text(PMAPORTS_INIT_2ND)
        self._git("init", "-q", cwd=self.pmaports_source)
        self._git("config", "user.name", "LMI test", cwd=self.pmaports_source)
        self._git(
            "config",
            "user.email",
            "lmi-pmaports-test@example.invalid",
            cwd=self.pmaports_source,
        )
        self._git("add", ".", cwd=self.pmaports_source)
        self._git(
            "commit",
            "-q",
            "-m",
            "pinned pmaports base",
            cwd=self.pmaports_source,
        )
        self.pmaports_commit = self._git(
            "rev-parse", "HEAD", cwd=self.pmaports_source
        ).strip()
        self.pmaports = self.root / "staged-pmaports"

        key_type = b"ssh-ed25519"
        blob = (
            struct.pack(">I", len(key_type))
            + key_type
            + struct.pack(">I", 32)
            + bytes(range(32))
        )
        encoded = base64.b64encode(blob).decode()
        self.public_key = self.root / "id_ed25519.pub"
        self.public_key.write_text(f"ssh-ed25519 {encoded} lmi-test\n")
        digest = base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")
        self.fingerprint = f"SHA256:{digest}"
        self.source_repo = self.root / "source-repo"
        (self.source_repo / "files").mkdir(parents=True)
        shutil.copytree(PAYLOAD, self.source_repo / "files/lmi-p1")
        overlay = self.source_repo / "artifacts/wsl-pmaports"
        device_overlay = overlay / "device-xiaomi-lmi"
        kernel_overlay = overlay / "linux-xiaomi-lmi"
        device_overlay.mkdir(parents=True)
        (device_overlay / "APKBUILD").write_text("device overlay\n")
        (device_overlay / "deviceinfo").write_text(
            'deviceinfo_codename="xiaomi-lmi"\n'
            'deviceinfo_arch="aarch64"\n'
            'deviceinfo_dtb="qcom/kona-v2.1-lmi"\n'
            'deviceinfo_rootfs_image_sector_size="4096"\n'
        )
        shutil.copytree(
            REPO / "artifacts/wsl-pmaports/linux-xiaomi-lmi",
            kernel_overlay,
        )
        source_lock_directory = self.source_repo / "config/lmi-p1"
        source_lock_directory.mkdir(parents=True)
        shutil.copyfile(
            REPO / "config/lmi-p1/initramfs-manifest.json",
            source_lock_directory / "initramfs-manifest.json",
        )
        self.initramfs_manifest = build_module.load_initramfs_manifest(
            source_lock_directory / "initramfs-manifest.json"
        )
        source_lock_value = json.loads(
            (REPO / "config/lmi-p1/source-lock.json").read_text()
        )
        source_lock_value = _source_lock_v3_fixture(source_lock_value)
        source_lock_value["pmbootstrap"].update(
            {
                "commit": self.fake_commit,
                "entrypoint_sha256": hashlib.sha256(
                    self.pmbootstrap.read_bytes()
                ).hexdigest(),
                "remote": "https://example.invalid/pmbootstrap.git",
                "tree": self._git(
                    "rev-parse", "HEAD^{tree}", cwd=self.fake_repo
                ).strip(),
            }
        )
        source_lock_value["pmaports"].update(
            {
                "commit": self.pmaports_commit,
                "remote": "https://example.invalid/pmaports.git",
                "tree": self._git(
                    "rev-parse", "HEAD^{tree}", cwd=self.pmaports_source
                ).strip(),
            }
        )
        (source_lock_directory / "source-lock.json").write_text(
            json.dumps(source_lock_value, indent=2, sort_keys=True) + "\n"
        )
        source_patch = (
            self.source_repo
            / "patches/postmarketos-initramfs/0001-lmi-handle-4096-sector-loop-partitions.patch"
        )
        source_patch.parent.mkdir(parents=True)
        shutil.copyfile(PMAPORTS_PATCH, source_patch)
        self._git("init", "-q", cwd=self.source_repo)
        self._git("config", "user.name", "LMI test", cwd=self.source_repo)
        self._git(
            "config", "user.email", "lmi-source-test@example.invalid", cwd=self.source_repo
        )
        self._git("add", ".", cwd=self.source_repo)
        self._git("commit", "-q", "-m", "source payload", cwd=self.source_repo)
        self.work = self.root / "candidate"
        self.source_commit = self._git("rev-parse", "HEAD", cwd=self.source_repo).strip()
        prepare_pmaports(
            source=self.pmaports_source,
            destination=self.pmaports,
            commit=self.pmaports_commit,
            overlay=overlay,
            patch=source_patch,
        )
        self._git("config", "user.name", "LMI test", cwd=self.pmaports)
        self._git(
            "config",
            "user.email",
            "lmi-pmaports-test@example.invalid",
            cwd=self.pmaports,
        )
        self.ctx = BuildContext(
            repo=self.source_repo,
            tag="lmi-p1-ssh-20260719-1",
            privilege_model="unsealed-development",
            policy_id="none",
            source_commit=self.source_commit,
            work=self.work,
            pmaports=self.pmaports,
            pmbootstrap=self.pmbootstrap,
            public_key=self.public_key,
            public_key_fingerprint=self.fingerprint,
        )
        self.environment = mock.patch.dict(
            os.environ,
            {
                "LMI_FAKE_PMBOOTSTRAP_LOG": str(self.log),
                "LMI_FAKE_PMBOOTSTRAP_ENV_LOG": str(self.pmbootstrap_environment_log),
                "LMI_FAKE_PMBOOTSTRAP_ENTRYPOINT_LOG": str(self.pmbootstrap_entrypoint_log),
                "LMI_FAKE_EXPORT_INVENTORY_LOG": str(self.export_inventory_log),
                "LMI_FAKE_FINALIZER_COPY": str(self.finalizer_copy),
            },
            clear=False,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        production_environment = build_module._pmbootstrap_environment

        def fake_pmbootstrap_environment():
            environment = production_environment()
            environment.update(
                {
                    key: value
                    for key, value in os.environ.items()
                    if key.startswith("LMI_FAKE_")
                }
            )
            return environment

        self.fake_environment = mock.patch.object(
            build_module,
            "_pmbootstrap_environment",
            side_effect=fake_pmbootstrap_environment,
        )
        self.fake_environment.start()
        self.addCleanup(self.fake_environment.stop)
        self.constants = mock.patch.multiple(
            build_module,
            _EXPECTED_PMBOOTSTRAP_COMMIT=self.fake_commit,
            _EXPECTED_PMAPORTS_COMMIT=self.pmaports_commit,
            _EXPECTED_VMLINUZ_SHA256=hashlib.sha256(b"kernel").hexdigest(),
        )
        self.constants.start()
        self.addCleanup(self.constants.stop)
        self.semantic_inputs = {
            label: {}
            for label in (
                "boot_img",
                "userdata_img",
                "vmlinuz",
                "initramfs",
                "dtb",
                "deviceinfo",
                "staged_deviceinfo",
                "staged_init_functions",
                "staged_init_2nd",
                "fstab",
                "rootfs_apk_installed",
                "rootfs_busybox",
                "rootfs_rootctl",
                "rootfs_sudoers",
                "rootfs_sudoers_dropin",
                "rootfs_nmcli",
                "rootfs_networkmanager_daemon",
                "rootfs_networkmanager_service",
                "rootfs_networkmanager_wifi_plugin",
                "rootfs_networkmanager_vendor_interfaces",
                "rootfs_networkmanager_vendor_dhcp",
                "rootfs_sshd_config",
                "rootfs_sshd_service",
                "rootfs_sshd_pam",
                "rootfs_sshd_pam_config",
                "rootfs_sshd_confd",
                "rootfs_sshd_auth",
                "rootfs_sshd_session",
                "rootfs_ssh_keygen",
                "rootfs_pam_base_auth",
                "rootfs_pam_base_account",
                "rootfs_pam_base_password",
                "rootfs_pam_base_session",
                "rootfs_pam_base_session_noninteractive",
                "rootfs_pam_unix",
                "rootfs_pam_nologin",
                "rootfs_pam_env",
                "rootfs_pam_limits",
                "rootfs_libpam",
                "rootfs_ssh",
                "rootfs_scp",
                "rootfs_sftp",
                "rootfs_ssh_add",
                "rootfs_ssh_agent",
                "rootfs_ssh_keyscan",
                "rootfs_authorized_keys",
                "rootfs_release_identity",
                "rootfs_networkmanager_profile",
                "rootfs_networkmanager_takeover",
                "rootfs_unudhcpd",
                "rootfs_unudhcpd_service",
                "rootfs_unudhcpd_config",
                "rootfs_usb_dhcp_wrapper",
                "rootfs_usb_dhcp_service",
            )
        }
        self.semantics_report = {
            "schema": "lmi-artifact-semantics-v3",
            "boot": {
                "sha256": hashlib.sha256(b"android-boot").hexdigest(),
                "kernel": {"sha256": hashlib.sha256(b"kernel").hexdigest()},
                "initramfs": {
                    "compressed_sha256": hashlib.sha256(b"initramfs").hexdigest()
                },
                "dtb": {"sha256": hashlib.sha256(b"dtb").hexdigest()},
            },
            "userdata": {
                "sha256": hashlib.sha256(b"combined-image").hexdigest()
            },
            "inputs": self.semantic_inputs,
            "release": {"eligible": True},
        }
        self.semantic_validator = mock.patch.object(
            build_module,
            "validate_artifact_pair",
            return_value=self.semantics_report,
        )
        self.validate_artifact_pair = self.semantic_validator.start()
        self.addCleanup(self.semantic_validator.stop)
        production_verify_sshd_pam = build_module._verify_sshd_pam
        production_verify_ssh_client = build_module._verify_ssh_client
        production_lstat = Path.lstat
        production_fstat = os.fstat

        def logical_root_metadata(
            metadata: os.stat_result, *, uid: int = 0, gid: int = 0
        ) -> os.stat_result:
            fields = list(metadata)
            fields[4] = uid
            fields[5] = gid
            return os.stat_result(fields)

        def verify_sshd_pam_as_image_root(
            rootfs: Path, installed_db: Path, expected_version: str
        ) -> dict[str, object]:
            server_files = {
                "usr/sbin/sshd.pam",
                "usr/bin/ssh-keygen",
                "etc/pam.d/sshd",
                "etc/conf.d/sshd",
                "etc/init.d/sshd",
                "usr/lib/ssh/sshd-auth.pam",
                "usr/lib/ssh/sshd-session.pam",
                "usr/lib/pam.d/base-auth",
                "usr/lib/pam.d/base-account",
                "usr/lib/pam.d/base-password",
                "usr/lib/pam.d/base-session",
                "usr/lib/pam.d/base-session-noninteractive",
                "usr/lib/security/pam_unix.so",
                "usr/lib/security/pam_nologin.so",
                "usr/lib/security/pam_env.so",
                "usr/lib/security/pam_limits.so",
                "usr/lib/libpam.so.0",
                "usr/lib/libpam.so.0.85.1",
            }
            server_ancestry = {
                "usr",
                "usr/sbin",
                "usr/bin",
                "etc",
                "etc/pam.d",
                "etc/conf.d",
                "etc/init.d",
                "usr/lib",
                "usr/lib/ssh",
                "usr/lib/pam.d",
                "usr/lib/security",
            }

            def logical_lstat(path: Path) -> os.stat_result:
                metadata = production_lstat(path)
                try:
                    relative = Path(path).relative_to(rootfs).as_posix()
                except ValueError:
                    return metadata
                if relative in server_files | server_ancestry:
                    return logical_root_metadata(metadata)
                return metadata

            def logical_fstat(descriptor: int) -> os.stat_result:
                metadata = production_fstat(descriptor)
                try:
                    opened_path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                    relative = opened_path.relative_to(rootfs).as_posix()
                except (OSError, ValueError):
                    return metadata
                if relative in server_files:
                    return logical_root_metadata(metadata)
                return metadata

            with mock.patch.object(Path, "lstat", new=logical_lstat), mock.patch.object(
                os, "fstat", new=logical_fstat
            ):
                return production_verify_sshd_pam(
                    rootfs, installed_db, expected_version
                )

        self.ssh_server_verifier = mock.patch.object(
            build_module,
            "_verify_sshd_pam",
            side_effect=verify_sshd_pam_as_image_root,
        )
        self.ssh_server_verifier.start()
        self.addCleanup(self.ssh_server_verifier.stop)

        def verify_ssh_client_as_image_root(
            rootfs: Path,
            installed_db: Path,
            expected_versions: dict[str, str],
            *,
            expected_openssh_version: str,
        ) -> None:
            client_files = {
                f"usr/bin/{name}"
                for name in ("scp", "sftp", "ssh", "ssh-add", "ssh-agent", "ssh-keyscan")
            }
            client_ancestry = {"usr", "usr/bin"}
            nonroot_uid = os.geteuid() or 1000
            nonroot_gid = os.getegid() or 1000

            def logical_owner(
                metadata: os.stat_result, relative: str
            ) -> os.stat_result:
                user_owned = os.environ.get(
                    "LMI_FAKE_OPENSSH_CLIENT_USER_OWNED"
                )
                nonroot_parent = os.environ.get(
                    "LMI_FAKE_OPENSSH_CLIENT_NONROOT_PARENT"
                )
                if (
                    relative == f"usr/bin/{user_owned}"
                    or relative == nonroot_parent
                ):
                    return logical_root_metadata(
                        metadata, uid=nonroot_uid, gid=nonroot_gid
                    )
                return logical_root_metadata(metadata)

            def logical_lstat(path: Path) -> os.stat_result:
                metadata = production_lstat(path)
                try:
                    relative = Path(path).relative_to(rootfs).as_posix()
                except ValueError:
                    return metadata
                if relative in client_files | client_ancestry:
                    return logical_owner(metadata, relative)
                return metadata

            def logical_fstat(descriptor: int) -> os.stat_result:
                metadata = production_fstat(descriptor)
                try:
                    opened_path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                    relative = opened_path.relative_to(rootfs).as_posix()
                except (OSError, ValueError):
                    return metadata
                if relative in client_files:
                    return logical_owner(metadata, relative)
                return metadata

            # The unprivileged fake pmbootstrap cannot create uid/gid 0 files.
            # Present its intended image ownership only while exercising the
            # production verifier; explicit attack variables retain non-root ids.
            with mock.patch.object(Path, "lstat", new=logical_lstat), mock.patch.object(
                os, "fstat", new=logical_fstat
            ):
                production_verify_ssh_client(
                    rootfs,
                    installed_db,
                    expected_versions,
                    expected_openssh_version=expected_openssh_version,
                )

        self.ssh_client_verifier = mock.patch.object(
            build_module,
            "_verify_ssh_client",
            side_effect=verify_ssh_client_as_image_root,
        )
        self.ssh_client_verifier.start()
        self.addCleanup(self.ssh_client_verifier.stop)
        production_verify_networkmanager_files = (
            build_module._verify_networkmanager_files
        )

        def verify_networkmanager_files_as_image_root(
            rootfs: Path,
            installed_db: Path,
            expected_versions: dict[str, str],
        ) -> None:
            networkmanager_files = {
                "etc/init.d/networkmanager",
                "usr/bin/nmcli",
                "usr/sbin/NetworkManager",
                "usr/lib/NetworkManager/1.52.2/libnm-device-plugin-wifi.so",
                "usr/lib/NetworkManager/conf.d/00-interfaces.conf",
                "usr/lib/NetworkManager/conf.d/20-dhcp-internal.conf",
            }
            networkmanager_ancestry = {
                "etc",
                "etc/init.d",
                "usr",
                "usr/bin",
                "usr/sbin",
                "usr/lib",
                "usr/lib/NetworkManager",
                "usr/lib/NetworkManager/1.52.2",
                "usr/lib/NetworkManager/conf.d",
            }

            def logical_lstat(path: Path) -> os.stat_result:
                metadata = production_lstat(path)
                try:
                    relative = Path(path).relative_to(rootfs).as_posix()
                except ValueError:
                    return metadata
                if relative in networkmanager_files | networkmanager_ancestry:
                    return logical_root_metadata(metadata)
                return metadata

            def logical_fstat(descriptor: int) -> os.stat_result:
                metadata = production_fstat(descriptor)
                try:
                    opened_path = Path(os.readlink(f"/proc/self/fd/{descriptor}"))
                    relative = opened_path.relative_to(rootfs).as_posix()
                except (OSError, ValueError):
                    return metadata
                if relative in networkmanager_files:
                    return logical_root_metadata(metadata)
                return metadata

            with mock.patch.object(Path, "lstat", new=logical_lstat), mock.patch.object(
                os, "fstat", new=logical_fstat
            ):
                production_verify_networkmanager_files(
                    rootfs, installed_db, expected_versions
                )

        self.networkmanager_verifier = mock.patch.object(
            build_module,
            "_verify_networkmanager_files",
            side_effect=verify_networkmanager_files_as_image_root,
        )
        self.networkmanager_verifier.start()
        self.addCleanup(self.networkmanager_verifier.stop)
        self.identity_rechecker = mock.patch.object(
            build_module,
            "recheck_input_identities",
        )
        self.recheck_input_identities = self.identity_rechecker.start()
        self.addCleanup(self.identity_rechecker.stop)

    @staticmethod
    def _git(*args: str, cwd: Path) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, check=True
        )
        return completed.stdout

    def _repin_pmbootstrap_in_project_lock(self, commit: str) -> None:
        lock_path = self.source_repo / "config/lmi-p1/source-lock.json"
        value = json.loads(lock_path.read_text())
        value["pmbootstrap"].update(
            {
                "commit": commit,
                "entrypoint_sha256": hashlib.sha256(
                    self.pmbootstrap.read_bytes()
                ).hexdigest(),
                "tree": self._git(
                    "rev-parse", f"{commit}^{{tree}}", cwd=self.fake_repo
                ).strip(),
            }
        )
        lock_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
        self._git("add", "config/lmi-p1/source-lock.json", cwd=self.source_repo)
        self._git(
            "commit", "-q", "-m", "repin fixture pmbootstrap", cwd=self.source_repo
        )
        self.source_commit = self._git(
            "rev-parse", "HEAD", cwd=self.source_repo
        ).strip()
        self.ctx = dataclasses.replace(
            self.ctx,
            source_commit=self.source_commit,
        )

    @staticmethod
    def _fake_pmbootstrap_source() -> str:
        return r'''#!/usr/bin/env python3
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
log = Path(os.environ["LMI_FAKE_PMBOOTSTRAP_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")

if "--as-root" in args:
    print("unsafe global --as-root was supplied", file=sys.stderr)
    raise SystemExit(96)
for flag in ("-c", "-w", "-p"):
    if flag not in args or args.index(flag) + 1 >= len(args):
        print(f"missing global {flag}", file=sys.stderr)
        raise SystemExit(97)
work = Path(args[args.index("-w") + 1])
tail = args[args.index("-p") + 2:]
if tail == ["--version"]:
    Path(os.environ["LMI_FAKE_PMBOOTSTRAP_ENV_LOG"]).write_text(
        json.dumps(
            {
                key: value
                for key, value in os.environ.items()
                if key.upper()
                in {
                    "HOME",
                    "USER",
                    "LOGNAME",
                    "SHELL",
                    "LANG",
                    "LC_ALL",
                    "TZ",
                    "TMPDIR",
                    "TERM",
                    "GIT_CONFIG_NOSYSTEM",
                    "GIT_CONFIG_GLOBAL",
                    "GIT_TERMINAL_PROMPT",
                    "GIT_NO_REPLACE_OBJECTS",
                    "GIT_NO_LAZY_FETCH",
                    "GIT_ALLOW_PROTOCOL",
                    "BASH_ENV",
                    "ENV",
                    "CDPATH",
                    "SHELLOPTS",
                    "BASHOPTS",
                    "IFS",
                    "PATH",
                    "PYTHONPATH",
                    "PYTHONBREAKPOINT",
                    "PYTHONATTACKVECTOR",
                    "LD_LIBRARY_PATH",
                    "LD_AUDIT",
                    "PMBOOTSTRAP_CMD",
                    "PMB_ATTACK",
                    "APK_CONFIG",
                    "CCACHE_DIR",
                    "XDG_CACHE_HOME",
                    "XDG_CONFIG_HOME",
                    "XDG_DATA_HOME",
                    "GIT_DIR",
                    "GIT_OPTIONAL_LOCKS",
                    "GH_TOKEN",
                    "AWS_SECRET_ACCESS_KEY",
                    "SSH_AUTH_SOCK",
                    "HTTPS_PROXY",
                    "SSL_CERT_FILE",
                    "HOST_BUILD_SECRET",
                }
            }
        )
    )
    Path(os.environ["LMI_FAKE_PMBOOTSTRAP_ENTRYPOINT_LOG"]).write_text(
        str(Path(__file__).resolve()) + "\n"
    )
    print("3.11.1")
    raise SystemExit(0)
action = tail[0]
rest = tail[1:]
rootfs = work / "chroot_rootfs_xiaomi-lmi"
db = rootfs / "lib/apk/db/installed"
package_list = rootfs / "packages.txt"
world = rootfs / "etc/apk/world"

def sshd_blob():
    payload = b"fixture-openssh-server-pam\n"
    two_segments = os.environ.get("LMI_FAKE_OPENSSH_NONEXEC_ENTRY") == "1"
    blob = bytearray(64 + (112 if two_segments else 56))
    blob[:4] = b"\x7fELF"
    blob[4] = 2
    blob[5] = 1
    blob[6] = 1
    blob[16:18] = (2).to_bytes(2, "little")
    blob[18:20] = (183).to_bytes(2, "little")
    blob[20:24] = (1).to_bytes(4, "little")
    blob[24:32] = (0x400000).to_bytes(8, "little")
    blob[32:40] = (64).to_bytes(8, "little")
    blob[52:54] = (64).to_bytes(2, "little")
    blob[54:56] = (56).to_bytes(2, "little")
    blob[56:58] = (2 if two_segments else 1).to_bytes(2, "little")
    blob[64:68] = (1).to_bytes(4, "little")
    blob[68:72] = (5).to_bytes(4, "little")
    blob[72:80] = (0).to_bytes(8, "little")
    blob[80:88] = (0x400000).to_bytes(8, "little")
    blob[88:96] = (0x400000).to_bytes(8, "little")
    blob[96:104] = (len(blob) + len(payload)).to_bytes(8, "little")
    blob[104:112] = (len(blob) + len(payload)).to_bytes(8, "little")
    blob[112:120] = (0x1000).to_bytes(8, "little")
    if os.environ.get("LMI_FAKE_OPENSSH_ZERO_ENTRY") == "1":
        blob[24:32] = (0).to_bytes(8, "little")
    if os.environ.get("LMI_FAKE_OPENSSH_OUT_OF_RANGE_ENTRY") == "1":
        blob[24:32] = (0x500000).to_bytes(8, "little")
    if os.environ.get("LMI_FAKE_OPENSSH_OVERFLOW_ENTRY") == "1":
        blob[24:32] = ((1 << 64) - 4).to_bytes(8, "little")
        blob[80:88] = ((1 << 64) - 8).to_bytes(8, "little")
        blob[88:96] = ((1 << 64) - 8).to_bytes(8, "little")
        blob[96:104] = (0).to_bytes(8, "little")
        blob[104:112] = (32).to_bytes(8, "little")
        blob[112:120] = (1).to_bytes(8, "little")
    if two_segments:
        blob[68:72] = (4).to_bytes(4, "little")
        blob[96:104] = (0).to_bytes(8, "little")
        blob[104:112] = (0x1000).to_bytes(8, "little")
        blob[112:120] = (1).to_bytes(8, "little")
        second = 120
        blob[second:second + 4] = (1).to_bytes(4, "little")
        blob[second + 4:second + 8] = (5).to_bytes(4, "little")
        blob[second + 16:second + 24] = (0x500000).to_bytes(8, "little")
        blob[second + 24:second + 32] = (0x500000).to_bytes(8, "little")
        blob[second + 40:second + 48] = (0x1000).to_bytes(8, "little")
        blob[second + 48:second + 56] = (1).to_bytes(8, "little")
    return bytes(blob) + payload

def sshd_service_blob():
    return b"#!/sbin/openrc-run\ncommand=/usr/sbin/sshd.pam\n"

def sshd_pam_config_blob():
    return b"auth required pam_unix.so\naccount required pam_unix.so\n"

def sshd_confd_blob():
    return b"# OpenSSH daemon options are intentionally unset.\n"

def openssh_record(version="9.9_p2-r0", *, owner="openssh-server-pam"):
    if os.environ.get("LMI_FAKE_OPENSSH_MISSING_PACKAGE") == "1":
        return ""
    elf_digest = base64.b64encode(hashlib.sha1(sshd_blob()).digest()).decode().rstrip("=")
    service_digest = base64.b64encode(
        hashlib.sha1(sshd_service_blob()).digest()
    ).decode().rstrip("=")
    pam_digest = base64.b64encode(
        hashlib.sha1(sshd_pam_config_blob()).digest()
    ).decode().rstrip("=")
    confd_digest = base64.b64encode(
        hashlib.sha1(sshd_confd_blob()).digest()
    ).decode().rstrip("=")
    if os.environ.get("LMI_FAKE_OPENSSH_BAD_DB_CHECKSUM") == "1":
        elf_digest = base64.b64encode(b"x" * 20).decode().rstrip("=")
    file_name = (
        "other-sshd" if os.environ.get("LMI_FAKE_OPENSSH_UNOWNED") == "1" else "sshd.pam"
    )
    missing = os.environ.get("LMI_FAKE_OPENSSH_SERVER_MISSING_PACKAGE")
    records = {
        "openssh-keygen": (
            f"P:openssh-keygen\nV:{version}\nA:aarch64\n"
            f"F:usr/bin\nR:ssh-keygen\nZ:Q1{elf_digest}\n\n"
        ),
        "openssh-server-common": (
            f"P:openssh-server-common\nV:{version}\nA:aarch64\n"
            "F:etc/ssh\nR:sshd_config\nZ:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA\n\n"
        ),
        "openssh-server-common-openrc": (
            f"P:openssh-server-common-openrc\nV:{version}\nA:aarch64\n"
            f"F:etc/conf.d\nR:sshd\nZ:Q1{confd_digest}\n"
            f"F:etc/init.d\nR:sshd\nZ:Q1{service_digest}\n\n"
        ),
        "openssh-server-pam": (
            f"P:{owner}\nV:{version}\nA:aarch64\n"
            f"F:etc/pam.d\nR:sshd\nZ:Q1{pam_digest}\n"
            f"F:usr/lib/ssh\nR:sshd-auth.pam\nZ:Q1{elf_digest}\n"
            f"R:sshd-session.pam\nZ:Q1{elf_digest}\n"
            f"F:usr/sbin\nR:{file_name}\nZ:Q1{elf_digest}\n\n"
        ),
    }
    if os.environ.get("LMI_FAKE_OPENSSH_SERVER_VERSION_MISMATCH") == "1":
        records["openssh-keygen"] = records["openssh-keygen"].replace(
            f"V:{version}", "V:9.9_p3-r0"
        )
    return (
        "".join(record for name, record in records.items() if name != missing)
    )

def linux_pam_records():
    digest = base64.b64encode(hashlib.sha1(sshd_blob()).digest()).decode().rstrip("=")
    policies = {
        "base-auth": b"auth required pam_unix.so\nauth required pam_nologin.so\nauth required pam_env.so\n",
        "base-account": b"account required pam_unix.so\naccount required pam_nologin.so\n",
        "base-password": b"password required pam_unix.so\n",
        "base-session": b"session include base-session-noninteractive\n",
        "base-session-noninteractive": b"session required pam_env.so\nsession required pam_limits.so\nsession required pam_unix.so\n",
    }
    records = "P:linux-pam\nV:1.7.1-r2\nA:aarch64\nF:usr/lib\n"
    records += "R:libpam.so.0\nZ:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA\n"
    records += f"R:libpam.so.0.85.1\nZ:Q1{digest}\nF:usr/lib/pam.d\n"
    for name, value in policies.items():
        policy_digest = base64.b64encode(hashlib.sha1(value).digest()).decode().rstrip("=")
        records += f"R:{name}\nZ:Q1{policy_digest}\n"
    records += "F:usr/lib/security\n"
    for name in ("pam_unix.so", "pam_nologin.so", "pam_env.so", "pam_limits.so"):
        records += f"R:{name}\nZ:Q1{digest}\n"
    return records + "\n"

def ssh_client_records(version="9.9_p2-r0"):
    if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_MISSING") == "1":
        return ""
    digest = base64.b64encode(hashlib.sha1(sshd_blob()).digest()).decode().rstrip("=")
    if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_BAD_DB_CHECKSUM") == "1":
        digest = base64.b64encode(b"y" * 20).decode().rstrip("=")
    architecture = (
        "x86_64"
        if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_WRONG_ARCH") == "1"
        else "aarch64"
    )
    ssh_name = (
        "other-ssh"
        if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_UNOWNED") == "1"
        else "ssh"
    )
    return (
        f"P:openssh-client-default\nV:{version}\nA:{architecture}\n"
        f"F:usr/bin\nR:{ssh_name}\nZ:Q1{digest}\n\n"
        f"P:openssh-client-common\nV:{version}\nA:{architecture}\n"
        f"F:usr/bin\nR:scp\nZ:Q1{digest}\n"
        f"R:sftp\nZ:Q1{digest}\n"
        f"R:ssh-add\nZ:Q1{digest}\n"
        f"R:ssh-agent\nZ:Q1{digest}\n"
        f"R:ssh-keyscan\nZ:Q1{digest}\n\n"
    )

def unudhcpd_service_blob():
    return b"#!/sbin/openrc-run\ncommand=/usr/bin/unudhcpd\n"

def dhcp_records(version="0.1.4-r0"):
    digest = base64.b64encode(hashlib.sha1(sshd_blob()).digest()).decode().rstrip("=")
    service_digest = base64.b64encode(
        hashlib.sha1(unudhcpd_service_blob()).digest()
    ).decode().rstrip("=")
    architecture = (
        "x86_64" if os.environ.get("LMI_FAKE_UNUDHCPD_WRONG_ARCH") == "1" else "aarch64"
    )
    binary = (
        f"P:unudhcpd\nV:{version}\nA:{architecture}\n"
        f"F:usr/bin\nR:unudhcpd\nZ:Q1{digest}\n\n"
    )
    openrc = ""
    if os.environ.get("LMI_FAKE_UNUDHCPD_OPENRC_MISSING") != "1":
        openrc = (
            f"P:unudhcpd-openrc\nV:{version}\nA:aarch64\n"
            f"F:etc/init.d\nR:unudhcpd\nZ:Q1{service_digest}\n\n"
        )
    extra = ""
    if os.environ.get("LMI_FAKE_SECOND_DHCP_OWNER") == "1":
        extra = "P:dnsmasq\nV:2.91-r0\nA:aarch64\n\n"
    return binary + openrc + extra

def networkmanager_records(version="1.52.2-r0"):
    if os.environ.get("LMI_FAKE_NETWORKMANAGER_VERSION") == "1":
        version = "1.52.3-r0"
    digest = base64.b64encode(hashlib.sha1(sshd_blob()).digest()).decode().rstrip("=")
    service_digest = base64.b64encode(
        hashlib.sha1(networkmanager_service_blob()).digest()
    ).decode().rstrip("=")
    nmcli = (
        "other-nmcli"
        if os.environ.get("LMI_FAKE_NETWORKMANAGER_NMCLI_OWNER") == "1"
        else "nmcli"
    )
    daemon = (
        "other-NetworkManager"
        if os.environ.get("LMI_FAKE_NETWORKMANAGER_DAEMON_OWNER") == "1"
        else "NetworkManager"
    )
    daemon_digest = digest
    interfaces_blob = b"[main]\nplugins=keyfile\n\n[ifupdown]\nmanaged=true\n"
    dhcp_blob = b"[main]\ndhcp=internal\n"
    interfaces_digest = base64.b64encode(
        hashlib.sha1(interfaces_blob).digest()
    ).decode().rstrip("=")
    dhcp_digest = base64.b64encode(
        hashlib.sha1(dhcp_blob).digest()
    ).decode().rstrip("=")
    if os.environ.get("LMI_FAKE_NETWORKMANAGER_VENDOR_BAD_DB_CHECKSUM") == "1":
        interfaces_digest = base64.b64encode(b"v" * 20).decode().rstrip("=")
    if os.environ.get("LMI_FAKE_NETWORKMANAGER_DAEMON_BAD_DB_CHECKSUM") == "1":
        daemon_digest = base64.b64encode(b"n" * 20).decode().rstrip("=")
    return (
        f"P:networkmanager\nV:{version}\nA:aarch64\n"
        f"F:usr/sbin\nR:{daemon}\nZ:Q1{daemon_digest}\n"
        f"F:usr/lib/NetworkManager/conf.d\n"
        f"R:00-interfaces.conf\nZ:Q1{interfaces_digest}\n"
        f"R:20-dhcp-internal.conf\nZ:Q1{dhcp_digest}\n\n"
        f"P:networkmanager-openrc\nV:{version}\nA:aarch64\n"
        f"F:etc/init.d\nR:networkmanager\nZ:Q1{service_digest}\n\n"
        f"P:networkmanager-cli\nV:{version}\nA:aarch64\n"
        f"F:usr/bin\nR:{nmcli}\nZ:Q1{digest}\n\n"
        f"P:networkmanager-wifi\nV:{version}\nA:aarch64\n"
        f"F:usr/lib/NetworkManager/1.52.2\n"
        f"R:libnm-device-plugin-wifi.so\nZ:Q1{digest}\n\n"
    )

def networkmanager_service_blob():
    return b"#!/sbin/openrc-run\ncommand=/usr/sbin/NetworkManager\n"

def install_networkmanager_files():
    files = {
        "etc/init.d/networkmanager": (networkmanager_service_blob(), 0o755),
        "usr/bin/nmcli": (sshd_blob(), 0o755),
        "usr/sbin/NetworkManager": (sshd_blob(), 0o755),
        "usr/lib/NetworkManager/1.52.2/libnm-device-plugin-wifi.so": (
            sshd_blob(),
            0o755,
        ),
        "usr/lib/NetworkManager/conf.d/00-interfaces.conf": (
            b"[main]\nplugins=keyfile\n\n[ifupdown]\nmanaged=true\n",
            0o644,
        ),
        "usr/lib/NetworkManager/conf.d/20-dhcp-internal.conf": (
            b"[main]\ndhcp=internal\n",
            0o644,
        ),
    }
    for relative, (blob, mode) in files.items():
        target = rootfs / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if (
            os.environ.get("LMI_FAKE_NETWORKMANAGER_MISSING_PAYLOAD")
            == relative
        ):
            target.unlink(missing_ok=True)
            continue
        target.write_bytes(blob)
        if (
            os.environ.get("LMI_FAKE_NETWORKMANAGER_VENDOR_BAD_MODE") == "1"
            and relative.endswith("20-dhcp-internal.conf")
        ):
            mode = 0o666
        target.chmod(mode)

def install_sshd_file():
    target = rootfs / "usr/sbin/sshd.pam"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.unlink(missing_ok=True)
    missing_sshd = os.environ.get("LMI_FAKE_OPENSSH_MISSING_FILE") == "1"
    symlink_sshd = os.environ.get("LMI_FAKE_OPENSSH_SYMLINK") == "1"
    if symlink_sshd:
        target.symlink_to(rootfs / "missing-sshd-target")
    elif not missing_sshd:
        blob = sshd_blob()
        if os.environ.get("LMI_FAKE_OPENSSH_WRONG_ARCH") == "1":
            blob = blob[:18] + (62).to_bytes(2, "little") + blob[20:]
        if os.environ.get("LMI_FAKE_OPENSSH_TRUNCATED_ELF") == "1":
            blob = blob[:24]
        if os.environ.get("LMI_FAKE_OPENSSH_BAD_ELF_TYPE") == "1":
            blob = blob[:16] + (0).to_bytes(2, "little") + blob[18:]
        if os.environ.get("LMI_FAKE_OPENSSH_BAD_ELF_HEADER_SIZE") == "1":
            blob = blob[:52] + (24).to_bytes(2, "little") + blob[54:]
        if os.environ.get("LMI_FAKE_OPENSSH_BAD_PROGRAM_TABLE") == "1":
            blob = blob[:32] + (len(blob) + 1).to_bytes(8, "little") + blob[40:]
        target.write_bytes(blob)
        target.chmod(0o755)
    support_files = {
        "usr/bin/ssh-keygen": (sshd_blob(), 0o755),
        "etc/init.d/sshd": (sshd_service_blob(), 0o755),
        "etc/conf.d/sshd": (sshd_confd_blob(), 0o644),
        "etc/pam.d/sshd": (sshd_pam_config_blob(), 0o644),
        "usr/lib/ssh/sshd-auth.pam": (sshd_blob(), 0o755),
        "usr/lib/ssh/sshd-session.pam": (sshd_blob(), 0o755),
        "usr/lib/pam.d/base-auth": (
            b"auth required pam_unix.so\nauth required pam_nologin.so\nauth required pam_env.so\n",
            0o644,
        ),
        "usr/lib/pam.d/base-account": (
            b"account required pam_unix.so\naccount required pam_nologin.so\n",
            0o644,
        ),
        "usr/lib/pam.d/base-password": (b"password required pam_unix.so\n", 0o644),
        "usr/lib/pam.d/base-session": (
            b"session include base-session-noninteractive\n",
            0o644,
        ),
        "usr/lib/pam.d/base-session-noninteractive": (
            b"session required pam_env.so\nsession required pam_limits.so\nsession required pam_unix.so\n",
            0o644,
        ),
        "usr/lib/security/pam_unix.so": (sshd_blob(), 0o755),
        "usr/lib/security/pam_nologin.so": (sshd_blob(), 0o755),
        "usr/lib/security/pam_env.so": (sshd_blob(), 0o755),
        "usr/lib/security/pam_limits.so": (sshd_blob(), 0o755),
        "usr/lib/libpam.so.0.85.1": (sshd_blob(), 0o755),
    }
    missing_support = os.environ.get("LMI_FAKE_OPENSSH_SERVER_MISSING_PAYLOAD")
    for relative, (value, mode) in support_files.items():
        support = rootfs / relative
        support.parent.mkdir(parents=True, exist_ok=True)
        support.unlink(missing_ok=True)
        if relative == missing_support:
            continue
        support.write_bytes(value)
        support.chmod(mode)
    libpam_link = rootfs / "usr/lib/libpam.so.0"
    libpam_link.unlink(missing_ok=True)
    libpam_link.symlink_to("libpam.so.0.85.1")

def install_ssh_client_files():
    client_directory = rootfs / "usr/bin"
    if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_PARENT_SYMLINK") == "1":
        redirected = rootfs / "ssh-client-bin"
        redirected.mkdir(parents=True, exist_ok=True)
        if not client_directory.is_symlink():
            if client_directory.exists():
                shutil.rmtree(client_directory)
            client_directory.symlink_to(redirected)
    for name in ("scp", "sftp", "ssh", "ssh-add", "ssh-agent", "ssh-keyscan"):
        target = client_directory / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.unlink(missing_ok=True)
        if (
            os.environ.get("LMI_FAKE_OPENSSH_CLIENT_MISSING_FILE") == name
        ):
            continue
        if (
            os.environ.get("LMI_FAKE_OPENSSH_CLIENT_SYMLINK") == name
        ):
            target.symlink_to(rootfs / "missing-ssh-client-target")
            continue
        blob = sshd_blob()
        if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_WRONG_ELF") == name:
            blob = blob[:18] + (62).to_bytes(2, "little") + blob[20:]
        target.write_bytes(blob)
        target.chmod(0o755)
    writable_parent = os.environ.get("LMI_FAKE_OPENSSH_CLIENT_WRITABLE_PARENT")
    if writable_parent in {"usr", "usr/bin"}:
        rootfs.joinpath(*Path(writable_parent).parts).chmod(0o775)

def install_dhcp_files():
    binary = rootfs / "usr/bin/unudhcpd"
    binary.parent.mkdir(parents=True, exist_ok=True)
    blob = sshd_blob()
    if os.environ.get("LMI_FAKE_UNUDHCPD_BINARY_WRONG_ARCH") == "1":
        blob = blob[:18] + (62).to_bytes(2, "little") + blob[20:]
    binary.write_bytes(blob)
    binary.chmod(0o755)
    service = rootfs / "etc/init.d/unudhcpd"
    service.parent.mkdir(parents=True, exist_ok=True)
    service.write_bytes(unudhcpd_service_blob())
    service.chmod(0o755)

def write_bootstrap_rootfs():
    device_version = (
        "1-r139" if os.environ.get("LMI_FAKE_DEVICE_R139") == "1" else "1-r145"
    )
    kernel_version = (
        "4.19.325-r9"
        if os.environ.get("LMI_FAKE_KERNEL_R9") == "1"
        else "4.19.325-r8"
    )
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_text(
        f"P:device-xiaomi-lmi\nV:{device_version}\n\n"
        f"P:linux-xiaomi-lmi\nV:{kernel_version}\n\n"
        "P:weston\nV:14.0.2-r8\n\n"
        + openssh_record()
        + linux_pam_records()
        + ssh_client_records()
        + networkmanager_records()
        + dhcp_records()
    )
    package_list.write_text(
        f"device-xiaomi-lmi-{device_version}\n"
        f"linux-xiaomi-lmi-{kernel_version}\n"
        "weston-14.0.2-r8\n"
        "openssh-keygen-9.9_p2-r0\n"
        "openssh-server-common-9.9_p2-r0\n"
        "openssh-server-common-openrc-9.9_p2-r0\n"
        "openssh-server-pam-9.9_p2-r0\n"
        "linux-pam-1.7.1-r2\n"
        "openssh-client-common-9.9_p2-r0\n"
        "openssh-client-default-9.9_p2-r0\n"
        "networkmanager-1.52.2-r0\n"
        "networkmanager-openrc-1.52.2-r0\n"
        "networkmanager-cli-1.52.2-r0\n"
        "networkmanager-wifi-1.52.2-r0\n"
        "unudhcpd-0.1.4-r0\n"
        "unudhcpd-openrc-0.1.4-r0\n"
    )
    world.parent.mkdir(parents=True, exist_ok=True)
    world.write_text(
        "device-xiaomi-lmi\n"
        "networkmanager\n"
        "networkmanager-cli\n"
        "networkmanager-openrc\n"
        "networkmanager-wifi\n"
        "openssh-client-default\n"
        "unudhcpd-openrc\n"
    )
    if os.environ.get("LMI_FAKE_CONFLICTING_WORLD") == "1":
        world.write_text(
            world.read_text().replace(
                "device-xiaomi-lmi\n", "device-xiaomi-lmi=1-r139\n"
            )
        )
    if os.environ.get("LMI_FAKE_TAGGED_WORLD") == "1":
        world.write_text(
            world.read_text().replace(
                "device-xiaomi-lmi\n", "device-xiaomi-lmi@edge=1-r145\n"
            )
        )
    if os.environ.get("LMI_FAKE_OPENSSH_WORLD_CONFLICT") == "1":
        world.write_text(world.read_text() + "openssh-server-pam>=99\n")
    for key_root in (work / "config_apk_keys", rootfs / "etc/apk/keys"):
        key_root.mkdir(parents=True, exist_ok=True)
        (key_root / "pmos-current.rsa.pub").write_text("current-key\n")
    install_networkmanager_files()

if action == "checksum" or action == "build":
    raise SystemExit(0)
if action == "install":
    if "--no-image" in rest:
        write_bootstrap_rootfs()
        raise SystemExit(0)
    if os.environ.get("LMI_FAKE_FAIL_FINAL_INSTALL") == "1":
        print("forced final install failure", file=sys.stderr)
        raise SystemExit(46)
    if os.environ.get("LMI_FAKE_FINAL_DEVICE_R139") == "1":
        db.write_text(db.read_text().replace("V:1-r145", "V:1-r139", 1))
        package_list.write_text(
            package_list.read_text().replace(
                "device-xiaomi-lmi-1-r145", "device-xiaomi-lmi-1-r139"
            )
        )
    if os.environ.get("LMI_FAKE_FINAL_KERNEL_R9") == "1":
        db.write_text(db.read_text().replace("V:4.19.325-r8", "V:4.19.325-r9", 1))
        package_list.write_text(
            package_list.read_text().replace(
                "linux-xiaomi-lmi-4.19.325-r8", "linux-xiaomi-lmi-4.19.325-r9"
            )
        )
    if os.environ.get("LMI_FAKE_OPENSSH_VERSION_CHANGE") == "1":
        db.write_text(
            db.read_text().replace(
                openssh_record(), openssh_record(version="9.9_p3-r0")
            )
        )
        package_list.write_text(
            package_list.read_text().replace(
                "openssh-server-pam-9.9_p2-r0", "openssh-server-pam-9.9_p3-r0"
            )
        )
    if os.environ.get("LMI_FAKE_OPENSSH_CLIENT_VERSION_CHANGE") == "1":
        db.write_text(
            db.read_text().replace(
                ssh_client_records(), ssh_client_records(version="9.9_p3-r0")
            )
        )
        package_list.write_text(
            package_list.read_text()
            .replace(
                "openssh-client-common-9.9_p2-r0",
                "openssh-client-common-9.9_p3-r0",
            )
            .replace(
                "openssh-client-default-9.9_p2-r0",
                "openssh-client-default-9.9_p3-r0",
            )
        )
    if os.environ.get("LMI_FAKE_UNUDHCPD_VERSION_CHANGE") == "1":
        db.write_text(db.read_text().replace(dhcp_records(), dhcp_records(version="0.1.5-r0")))
        package_list.write_text(
            package_list.read_text()
            .replace("unudhcpd-0.1.4-r0", "unudhcpd-0.1.5-r0")
            .replace("unudhcpd-openrc-0.1.4-r0", "unudhcpd-openrc-0.1.5-r0")
        )
    install_sshd_file()
    install_ssh_client_files()
    install_dhcp_files()
    native_rootfs = work / "chroot_native/home/pmos/rootfs"
    native_rootfs.mkdir(parents=True, exist_ok=True)
    (native_rootfs / "xiaomi-lmi.img").write_bytes(b"combined-image")
    boot = rootfs / "boot"
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "boot.img").write_bytes(b"android-boot")
    (boot / "vmlinuz").write_bytes(b"kernel")
    (boot / "initramfs").write_bytes(b"initramfs")
    if os.environ.get("LMI_FAKE_EXPORT_INITRAMFS_EXTRA") == "1":
        (boot / "initramfs-extra").write_bytes(b"initramfs-extra")
    if os.environ.get("LMI_FAKE_EXPORT_UNKNOWN_DYNAMIC") == "1":
        (boot / "initramfs-extra-attacker").write_bytes(b"unknown-dynamic")
    if os.environ.get("LMI_FAKE_EXPORT_OPTIONAL_REAL") == "1":
        (boot / "vendor_boot.img").write_bytes(b"vendor-boot")
    selected_dtb = boot / "dtbs/qcom/kona-v2.1-lmi.dtb"
    selected_dtb.parent.mkdir(parents=True, exist_ok=True)
    if os.environ.get("LMI_FAKE_DTB_MISSING") != "1":
        if os.environ.get("LMI_FAKE_DTB_DANGLING") == "1":
            selected_dtb.symlink_to((work / "missing-selected-dtb").resolve())
        elif os.environ.get("LMI_FAKE_DTB_ESCAPE") == "1":
            selected_dtb.symlink_to(Path("/etc/passwd"))
        else:
            selected_dtb.write_bytes(b"dtb")
    (rootfs / "etc/fstab").write_text(
        "UUID=11111111-2222-3333-4444-555555555555 / ext4 defaults 0 0\n"
        "UUID=AAAA-BBBB /boot vfat nodev,nosuid,noexec 0 0\n"
    )
    if os.environ.get("LMI_FAKE_FINAL_INSTALL_BARE_WORLD") == "1":
        world.write_text(
            world.read_text().replace(
                "device-xiaomi-lmi=1-r145\n", "device-xiaomi-lmi\n"
            )
        )
    raise SystemExit(0)
if action == "chroot":
    inner = rest[rest.index("--") + 1:]
    if inner == ["apk", "info", "-v"]:
        sys.stdout.write(package_list.read_text())
        raise SystemExit(0)
    if inner[:2] == ["/bin/sh", "/mnt/pmbootstrap/packages/lmi-p1-finalize/finalize.sh"]:
        staged = work / "packages/lmi-p1-finalize"
        copied = Path(os.environ["LMI_FAKE_FINALIZER_COPY"])
        copied.mkdir(parents=True, exist_ok=True)
        for name in (
            "finalize.sh",
            "lmi-release-identity",
            "lmi-rootctl",
            "world",
            "sudoers",
            "90-lmi-rootctl",
            "sshd_config",
            "lmi-usb0.nmconnection",
            "90-lmi-usb0-takeover.conf",
            "lmi-usb0-dhcp",
            "lmi-usb0-dhcp.initd",
            "unudhcpd.usb0.confd",
            "authorized_keys",
        ):
            shutil.copy2(staged / name, copied / name)
        print("lmi-p1-finalize=ok")
        raise SystemExit(0)
    print("unsupported fake chroot command: " + repr(inner), file=sys.stderr)
    raise SystemExit(88)
if action == "shutdown":
    raise SystemExit(0)
if action == "export":
    export = Path(rest[0])
    if export.exists() and next(export.iterdir(), None) is not None:
        print("export was not empty", file=sys.stderr)
        raise SystemExit(90)
    export.mkdir(parents=True, exist_ok=True)
    export_targets = {
        "boot.img": rootfs / "boot/boot.img",
        "vendor_boot.img": rootfs / "boot/vendor_boot.img",
        "uInitrd": rootfs / "boot/uInitrd",
        "uImage": rootfs / "boot/uImage",
        "dtbo.img": rootfs / "boot/dtbo.img",
        "xiaomi-lmi.img": work / "chroot_native/home/pmos/rootfs/xiaomi-lmi.img",
        "xiaomi-lmi-boot.img": work / "chroot_native/home/pmos/rootfs/xiaomi-lmi-boot.img",
        "xiaomi-lmi-root.img": work / "chroot_native/home/pmos/rootfs/xiaomi-lmi-root.img",
        "pmos-xiaomi-lmi.zip": work / "chroot_buildroot_aarch64/var/lib/postmarketos-android-recovery-installer/pmos-xiaomi-lmi.zip",
        "lk2nd.img": rootfs / "boot/lk2nd.img",
        "vmlinuz": rootfs / "boot/vmlinuz",
        "initramfs": rootfs / "boot/initramfs",
    }
    if os.environ.get("LMI_FAKE_EXPORT_INITRAMFS_EXTRA") == "1":
        export_targets["initramfs-extra"] = rootfs / "boot/initramfs-extra"
    if os.environ.get("LMI_FAKE_EXPORT_UNKNOWN_DYNAMIC") == "1":
        export_targets["initramfs-extra-attacker"] = (
            rootfs / "boot/initramfs-extra-attacker"
        )
    for name, target in export_targets.items():
        (export / name).symlink_to(target.resolve())
    Path(os.environ["LMI_FAKE_EXPORT_INVENTORY_LOG"]).write_text(
        json.dumps(
            {
                name: os.readlink(export / name)
                for name in sorted(export_targets)
            },
            sort_keys=True,
        )
    )
    if os.environ.get("LMI_FAKE_EXPORT_EXTRA") == "1":
        (export / "unexpected.bin").symlink_to((rootfs / "boot/vmlinuz").resolve())
    if os.environ.get("LMI_FAKE_EXPORT_UNKNOWN_DANGLING") == "1":
        (export / "unknown-optional.img").symlink_to(
            (work / "missing-unknown-optional.img").resolve()
        )
    if os.environ.get("LMI_FAKE_EXPORT_ESCAPE") == "1":
        (export / "boot.img").unlink()
        (export / "boot.img").symlink_to(Path("/etc/passwd"))
    if os.environ.get("LMI_FAKE_EXPORT_DANGLING") == "1":
        (export / "boot.img").unlink()
        (export / "boot.img").symlink_to((work / "missing-boot.img").resolve())
    if os.environ.get("LMI_FAKE_EXPORT_OPTIONAL_ESCAPE") == "1":
        (export / "vendor_boot.img").unlink()
        (export / "vendor_boot.img").symlink_to(Path("/etc/passwd"))
    raise SystemExit(0)
print("unsupported fake action: " + action, file=sys.stderr)
raise SystemExit(89)
'''

    def _records(self) -> list[list[str]]:
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    @staticmethod
    def _tail(record: list[str]) -> list[str]:
        return record[record.index("-p") + 2 :]

    def _build(self) -> BuildResult:
        with mock.patch.object(
            build_module.secrets, "token_urlsafe", return_value=self.ephemeral
        ) as token:
            result = build_candidate(self.ctx)
        token.assert_called_once_with(32)
        return result

    def _sealed_artifact_result(
        self, name: str
    ) -> tuple[BuildResult, str, Path]:
        export = self.root / name
        export.mkdir(mode=0o700)
        dtb_dir = export / "dtbs/qcom"
        dtb_dir.mkdir(parents=True)
        paths = {
            "boot_img": export / "boot.img",
            "userdata_img": export / "xiaomi-lmi.img",
            "vmlinuz": export / "vmlinuz",
            "initramfs": export / "initramfs",
            "dtb": dtb_dir / "kona-v2.1-lmi.dtb",
            "packages": export / "packages.txt",
            "world": export / "world",
            "sshd_pam": export / "sshd-pam.json",
            "semantics": export / "artifact-semantics.json",
            "build_log": export / "build.log",
            "identity": export / "lmi-release-identity",
        }
        payloads = {
            "boot_img": b"android-boot",
            "userdata_img": b"combined-image",
            "vmlinuz": b"kernel",
            "initramfs": b"initramfs",
            "dtb": b"dtb",
            "packages": b"linux-xiaomi-lmi-4.19.325-r8\n",
            "world": b"linux-xiaomi-lmi=4.19.325-r8\n",
            "sshd_pam": b"{}\n",
            "semantics": b"{}\n",
            "build_log": b"private redacted log\n",
        }
        for field, payload in payloads.items():
            paths[field].write_bytes(payload)
        build_id = "c" * 64
        policy_id = "d" * 64
        paths["identity"].write_text(
            "\n".join(
                (
                    f"candidate_id={build_id}",
                    f"policy_id={policy_id}",
                    "privilege_model=root-owned-sealed-production",
                    "artifact_classification=owner-test-private",
                    "release_eligible=false",
                    "publication=never-publish",
                    "credential_state=owner-key-provisioned",
                )
            )
            + "\n"
        )
        semantics = {
            "boot": {
                "sha256": hashlib.sha256(payloads["boot_img"]).hexdigest(),
                "kernel": {
                    "sha256": hashlib.sha256(payloads["vmlinuz"]).hexdigest()
                },
                "initramfs": {
                    "compressed_sha256": hashlib.sha256(
                        payloads["initramfs"]
                    ).hexdigest()
                },
                "dtb": {"sha256": hashlib.sha256(payloads["dtb"]).hexdigest()},
            },
            "userdata": {
                "sha256": hashlib.sha256(payloads["userdata_img"]).hexdigest()
            },
        }
        manifest, manifest_sha256, artifact_set_id = (
            build_module._freeze_and_recheck_outputs(
                export,
                tuple(paths.values()),
                semantics,
                boot_img=paths["boot_img"],
                userdata_img=paths["userdata_img"],
                vmlinuz=paths["vmlinuz"],
                initramfs=paths["initramfs"],
                dtb=paths["dtb"],
                build_id=build_id,
                privilege_model="root-owned-sealed-production",
                policy_id=policy_id,
            )
        )
        active = self.root / f"{name}-active"
        active.write_text(policy_id + "\n", encoding="ascii")
        active.chmod(0o600)
        result = BuildResult(
            boot_img=paths["boot_img"],
            userdata_img=paths["userdata_img"],
            vmlinuz=paths["vmlinuz"],
            initramfs=paths["initramfs"],
            dtb_dir=export / "dtbs",
            packages=paths["packages"],
            world=paths["world"],
            sshd_pam=paths["sshd_pam"],
            semantics=paths["semantics"],
            build_log=paths["build_log"],
            identity=paths["identity"],
            manifest=manifest,
            manifest_sha256=manifest_sha256,
            artifact_set_id=artifact_set_id,
        )
        return result, policy_id, active

    def test_final_sealed_result_helper_rechecks_policy_and_all_outputs(self):
        result, policy_id, active = self._sealed_artifact_result("final-result")
        self.assertIs(
            build_module.revalidate_sealed_build_result(
                result,
                expected_policy_id=policy_id,
                active_path=active,
                trusted_root=self.root,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            ),
            result,
        )
        with mock.patch.object(
            build_module,
            "read_active_policy",
            side_effect=(policy_id, "e" * 64),
        ), self.assertRaisesRegex(GateError, "changed before result return"):
            build_module.revalidate_sealed_build_result(
                result,
                expected_policy_id=policy_id,
                active_path=active,
                trusted_root=self.root,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )

    def test_final_sealed_result_helper_rejects_output_or_manifest_mutation(self):
        result, policy_id, active = self._sealed_artifact_result("mutated-output")
        result.boot_img.chmod(0o644)
        result.boot_img.write_bytes(b"attacker")
        result.boot_img.chmod(0o444)
        with self.assertRaisesRegex(GateError, "digest changed"):
            build_module.revalidate_sealed_build_result(
                result,
                expected_policy_id=policy_id,
                active_path=active,
                trusted_root=self.root,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )

        other, other_policy, other_active = self._sealed_artifact_result(
            "mutated-manifest"
        )
        other.manifest.chmod(0o644)
        other.manifest.write_bytes(other.manifest.read_bytes() + b" ")
        other.manifest.chmod(0o444)
        with self.assertRaisesRegex(GateError, "manifest"):
            build_module.revalidate_sealed_build_result(
                other,
                expected_policy_id=other_policy,
                active_path=other_active,
                trusted_root=self.root,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
            )

    def test_exported_vmlinuz_must_match_the_pinned_production_digest(self):
        with mock.patch.object(
            build_module, "_EXPECTED_VMLINUZ_SHA256", "f" * 64
        ), self.assertRaisesRegex(GateError, "pinned P1 kernel"):
            self._sealed_artifact_result("wrong-kernel")

    def test_exact_two_pass_p1_sequence_security_identity_and_exports(self):
        result = self._build()
        self.assertEqual(self.work.stat().st_mode & 0o777, 0o700)
        self.assertEqual(self.work.stat().st_uid, os.geteuid())
        records = self._records()
        for record in records:
            self.assertNotIn("--as-root", record)
            for flag in ("-c", "-w", "-p"):
                self.assertIn(flag, record)
                self.assertTrue(Path(record[record.index(flag) + 1]).is_absolute())
            self.assertNotIn("--zap", record)

        tails = [self._tail(record) for record in records]
        self.assertEqual(tails[0], ["--version"])
        self.assertEqual(
            tails[1],
            [
                "checksum",
                "--verify",
                "postmarketos-initramfs",
                "linux-xiaomi-lmi",
                "device-xiaomi-lmi",
            ],
        )
        self.assertEqual(
            tails[2],
            [
                "build",
                "postmarketos-initramfs",
                "linux-xiaomi-lmi",
                "device-xiaomi-lmi",
            ],
        )
        self.assertIn(
            [
                "install",
                "--no-image",
                "--no-fde",
                "--add",
                "networkmanager=1.52.2-r0,networkmanager-openrc=1.52.2-r0,"
                "networkmanager-cli=1.52.2-r0,networkmanager-wifi=1.52.2-r0,"
                "unudhcpd-openrc,openssh-client-default",
                "--password",
                self.ephemeral,
            ],
            tails,
        )
        self.assertFalse(
            [tail for tail in tails if tail and tail[0] == "chroot" and "apk" in tail]
        )
        install_records = [record for record in records if self._tail(record)[:1] == ["install"]]
        self.assertEqual(len(install_records), 2)
        for record in install_records:
            self.assertEqual(record.count("--add"), 1)
            self.assertEqual(
                record[record.index("--add") + 1],
                "networkmanager=1.52.2-r0,networkmanager-openrc=1.52.2-r0,"
                "networkmanager-cli=1.52.2-r0,networkmanager-wifi=1.52.2-r0,"
                "unudhcpd-openrc,openssh-client-default",
            )
            self.assertFalse(any("dnsmasq" in argument for argument in record))
        for record in records:
            self.assertNotIn("--allow-untrusted", record)
            self.assertFalse(any("replay" in argument.lower() for argument in record))
        final_install = [
            tail for tail in tails if tail and tail[0] == "install" and "--no-image" not in tail
        ]
        self.assertEqual(
            final_install,
            [[
                "install",
                "--no-fde",
                "--sector-size",
                "4096",
                "--no-sparse",
                "--add",
                "networkmanager=1.52.2-r0,networkmanager-openrc=1.52.2-r0,"
                "networkmanager-cli=1.52.2-r0,networkmanager-wifi=1.52.2-r0,"
                "unudhcpd-openrc,openssh-client-default",
                "--password",
                self.ephemeral,
            ]],
        )
        image_commands = [tail for tail in tails if tail[:2] == ["chroot", "-r"] and "--image" in tail]
        self.assertEqual(len(image_commands), 1)
        export = [tail for tail in tails if tail and tail[0] == "export"]
        self.assertEqual(len(export), 1)
        self.assertEqual(export[0][-1], "--no-install")
        self.assertEqual(tails[-1], export[0])

        self.assertFalse((self.work / "work/packages/bootstrap-quarantine").exists())
        self.assertFalse((self.work / "work/packages/replay").exists())
        config = (self.work / "config/pmbootstrap.cfg").read_text()
        private_public_key = self.work / "config/authorized_key.pub"
        for expected in (
            "device = xiaomi-lmi",
            "ui = none",
            "user = lmi",
            "ssh_keys = True",
            f"ssh_key_glob = {private_public_key}",
            "service_manager = openrc",
            "extra_packages = none",
        ):
            self.assertIn(expected, config)
        self.assertNotIn("ui = shelli", config)
        self.assertEqual(private_public_key.read_text(), self.public_key.read_text())
        self.assertEqual(private_public_key.stat().st_mode & 0o777, 0o600)

        for path in (
            value for value in result.__dict__.values() if isinstance(value, Path)
        ):
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.exists(), path)
        self.assertTrue(result.dtb_dir.is_dir())
        self.assertEqual((self.work / "export").stat().st_mode & 0o777, 0o555)
        self.assertEqual(result.dtb_dir.stat().st_mode & 0o777, 0o555)
        for path in (
            value for value in result.__dict__.values() if isinstance(value, Path)
        ):
            if path.is_file():
                self.assertEqual(path.stat().st_mode & 0o777, 0o444, path)
        artifact_manifest = json.loads(result.manifest.read_text())
        self.assertEqual(
            hashlib.sha256(result.manifest.read_bytes()).hexdigest(),
            result.manifest_sha256,
        )
        self.assertEqual(artifact_manifest["artifact_set_id"], result.artifact_set_id)
        self.assertEqual(artifact_manifest["schema"], "lmi-p1-artifact-manifest/v1")
        self.assertEqual(
            artifact_manifest["artifact_classification"], "owner-test-private"
        )
        self.assertIs(artifact_manifest["release_eligible"], False)
        self.assertEqual(artifact_manifest["publication"], "never-publish")
        self.assertEqual(
            artifact_manifest["credential_state"], "owner-key-provisioned"
        )
        listed_paths = {entry["path"] for entry in artifact_manifest["files"]}
        self.assertNotIn("artifact-manifest.json", listed_paths)
        self.assertEqual(
            listed_paths,
            {
                path.relative_to(self.work / "export").as_posix()
                for path in (self.work / "export").rglob("*")
                if path.is_file() and path != result.manifest
            },
        )
        self.assertEqual(json.loads(result.semantics.read_text()), self.semantics_report)
        rootfs = self.work / "work/chroot_rootfs_xiaomi-lmi"
        self.validate_artifact_pair.assert_called_once_with(
            result.boot_img,
            result.userdata_img,
            result.vmlinuz,
            result.initramfs,
            result.dtb_dir / "qcom/kona-v2.1-lmi.dtb",
            rootfs / "usr/share/deviceinfo/device-xiaomi-lmi",
            self.work
            / "pmaports/device/downstream/device-xiaomi-lmi/deviceinfo",
            self.work / "pmaports/main/postmarketos-initramfs/init_functions.sh",
            self.work / "pmaports/main/postmarketos-initramfs/init_2nd.sh",
            rootfs / "etc/fstab",
            rootfs_bindings=build_module.RootfsBindings(
                apk_installed=rootfs / "lib/apk/db/installed",
                busybox=rootfs / "usr/bin/busybox",
                rootctl=self.work / "source/files/lmi-p1/lmi-rootctl",
                sudoers=self.work / "source/files/lmi-p1/sudoers",
                sudoers_dropin=self.work
                / "source"
                / "files/lmi-p1/90-lmi-rootctl",
                nmcli=rootfs / "usr/bin/nmcli",
                networkmanager_daemon=rootfs / "usr/sbin/NetworkManager",
                networkmanager_service=rootfs / "etc/init.d/networkmanager",
                networkmanager_wifi_plugin=rootfs
                / "usr/lib/NetworkManager/1.52.2/libnm-device-plugin-wifi.so",
                networkmanager_vendor_interfaces=rootfs
                / "usr/lib/NetworkManager/conf.d/00-interfaces.conf",
                networkmanager_vendor_dhcp=rootfs
                / "usr/lib/NetworkManager/conf.d/20-dhcp-internal.conf",
                sshd_config=rootfs / "etc/ssh/sshd_config",
                sshd_service=rootfs / "etc/init.d/sshd",
                sshd_pam=rootfs / "usr/sbin/sshd.pam",
                sshd_pam_config=rootfs / "etc/pam.d/sshd",
                sshd_confd=rootfs / "etc/conf.d/sshd",
                sshd_auth=rootfs / "usr/lib/ssh/sshd-auth.pam",
                sshd_session=rootfs / "usr/lib/ssh/sshd-session.pam",
                ssh_keygen=rootfs / "usr/bin/ssh-keygen",
                pam_base_auth=rootfs / "usr/lib/pam.d/base-auth",
                pam_base_account=rootfs / "usr/lib/pam.d/base-account",
                pam_base_password=rootfs / "usr/lib/pam.d/base-password",
                pam_base_session=rootfs / "usr/lib/pam.d/base-session",
                pam_base_session_noninteractive=rootfs
                / "usr/lib/pam.d/base-session-noninteractive",
                pam_unix=rootfs / "usr/lib/security/pam_unix.so",
                pam_nologin=rootfs / "usr/lib/security/pam_nologin.so",
                pam_env=rootfs / "usr/lib/security/pam_env.so",
                pam_limits=rootfs / "usr/lib/security/pam_limits.so",
                libpam=rootfs / "usr/lib/libpam.so.0.85.1",
                ssh=rootfs / "usr/bin/ssh",
                scp=rootfs / "usr/bin/scp",
                sftp=rootfs / "usr/bin/sftp",
                ssh_add=rootfs / "usr/bin/ssh-add",
                ssh_agent=rootfs / "usr/bin/ssh-agent",
                ssh_keyscan=rootfs / "usr/bin/ssh-keyscan",
                authorized_keys=rootfs / "home/lmi/.ssh/authorized_keys",
                release_identity=rootfs / "etc/lmi-release-identity",
                networkmanager_profile=rootfs
                / "etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
                networkmanager_takeover=rootfs
                / "etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
                unudhcpd=rootfs / "usr/bin/unudhcpd",
                unudhcpd_service=rootfs / "etc/init.d/unudhcpd",
                unudhcpd_config=rootfs / "etc/conf.d/unudhcpd.usb0",
                usb_dhcp_wrapper=rootfs / "usr/sbin/lmi-usb0-dhcp",
                usb_dhcp_service=rootfs / "etc/init.d/lmi-usb0-dhcp",
            ),
            limits=build_module.PartitionLimits(),
            expectations=build_module.ArtifactExpectations(
                initramfs_manifest=self.initramfs_manifest
            ),
            calibration=False,
        )
        self.recheck_input_identities.assert_called_once_with(
            self.semantic_inputs,
            {
                "boot_img": result.boot_img,
                "userdata_img": result.userdata_img,
                "vmlinuz": result.vmlinuz,
                "initramfs": result.initramfs,
                "dtb": result.dtb_dir / "qcom/kona-v2.1-lmi.dtb",
                "deviceinfo": rootfs
                / "usr/share/deviceinfo/device-xiaomi-lmi",
                "staged_deviceinfo": self.work
                / "pmaports/device/downstream/device-xiaomi-lmi/deviceinfo",
                "staged_init_functions": self.work
                / "pmaports/main/postmarketos-initramfs/init_functions.sh",
                "staged_init_2nd": self.work
                / "pmaports/main/postmarketos-initramfs/init_2nd.sh",
                "fstab": rootfs / "etc/fstab",
                "rootfs_apk_installed": rootfs / "lib/apk/db/installed",
                "rootfs_busybox": rootfs / "usr/bin/busybox",
                "rootfs_rootctl": self.work
                / "source/files/lmi-p1/lmi-rootctl",
                "rootfs_sudoers": self.work
                / "source/files/lmi-p1/sudoers",
                "rootfs_sudoers_dropin": self.work
                / "source"
                / "files/lmi-p1/90-lmi-rootctl",
                "rootfs_nmcli": rootfs / "usr/bin/nmcli",
                "rootfs_networkmanager_daemon": rootfs
                / "usr/sbin/NetworkManager",
                "rootfs_networkmanager_service": rootfs
                / "etc/init.d/networkmanager",
                "rootfs_networkmanager_wifi_plugin": rootfs
                / "usr/lib/NetworkManager/1.52.2/libnm-device-plugin-wifi.so",
                "rootfs_networkmanager_vendor_interfaces": rootfs
                / "usr/lib/NetworkManager/conf.d/00-interfaces.conf",
                "rootfs_networkmanager_vendor_dhcp": rootfs
                / "usr/lib/NetworkManager/conf.d/20-dhcp-internal.conf",
                "rootfs_sshd_config": rootfs / "etc/ssh/sshd_config",
                "rootfs_sshd_service": rootfs / "etc/init.d/sshd",
                "rootfs_sshd_pam": rootfs / "usr/sbin/sshd.pam",
                "rootfs_sshd_pam_config": rootfs / "etc/pam.d/sshd",
                "rootfs_sshd_confd": rootfs / "etc/conf.d/sshd",
                "rootfs_sshd_auth": rootfs / "usr/lib/ssh/sshd-auth.pam",
                "rootfs_sshd_session": rootfs
                / "usr/lib/ssh/sshd-session.pam",
                "rootfs_ssh_keygen": rootfs / "usr/bin/ssh-keygen",
                "rootfs_pam_base_auth": rootfs / "usr/lib/pam.d/base-auth",
                "rootfs_pam_base_account": rootfs
                / "usr/lib/pam.d/base-account",
                "rootfs_pam_base_password": rootfs
                / "usr/lib/pam.d/base-password",
                "rootfs_pam_base_session": rootfs
                / "usr/lib/pam.d/base-session",
                "rootfs_pam_base_session_noninteractive": rootfs
                / "usr/lib/pam.d/base-session-noninteractive",
                "rootfs_pam_unix": rootfs / "usr/lib/security/pam_unix.so",
                "rootfs_pam_nologin": rootfs
                / "usr/lib/security/pam_nologin.so",
                "rootfs_pam_env": rootfs / "usr/lib/security/pam_env.so",
                "rootfs_pam_limits": rootfs
                / "usr/lib/security/pam_limits.so",
                "rootfs_libpam": rootfs / "usr/lib/libpam.so.0.85.1",
                "rootfs_ssh": rootfs / "usr/bin/ssh",
                "rootfs_scp": rootfs / "usr/bin/scp",
                "rootfs_sftp": rootfs / "usr/bin/sftp",
                "rootfs_ssh_add": rootfs / "usr/bin/ssh-add",
                "rootfs_ssh_agent": rootfs / "usr/bin/ssh-agent",
                "rootfs_ssh_keyscan": rootfs / "usr/bin/ssh-keyscan",
                "rootfs_authorized_keys": rootfs
                / "home/lmi/.ssh/authorized_keys",
                "rootfs_release_identity": rootfs
                / "etc/lmi-release-identity",
                "rootfs_networkmanager_profile": rootfs
                / "etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
                "rootfs_networkmanager_takeover": rootfs
                / "etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
                "rootfs_unudhcpd": rootfs / "usr/bin/unudhcpd",
                "rootfs_unudhcpd_service": rootfs / "etc/init.d/unudhcpd",
                "rootfs_unudhcpd_config": rootfs / "etc/conf.d/unudhcpd.usb0",
                "rootfs_usb_dhcp_wrapper": rootfs / "usr/sbin/lmi-usb0-dhcp",
                "rootfs_usb_dhcp_service": rootfs / "etc/init.d/lmi-usb0-dhcp",
            },
        )
        fake_export = json.loads(self.export_inventory_log.read_text())
        self.assertEqual(
            set(fake_export),
            {
                "boot.img",
                "vendor_boot.img",
                "uInitrd",
                "uImage",
                "dtbo.img",
                "xiaomi-lmi.img",
                "xiaomi-lmi-boot.img",
                "xiaomi-lmi-root.img",
                "pmos-xiaomi-lmi.zip",
                "lk2nd.img",
                "vmlinuz",
                "initramfs",
            },
        )
        self.assertTrue(all(Path(target).is_absolute() for target in fake_export.values()))
        materialized = (
            result.boot_img,
            result.userdata_img,
            result.vmlinuz,
            result.initramfs,
            *sorted(path for path in result.dtb_dir.rglob("*") if path.is_file()),
        )
        for output in materialized:
            self.assertTrue(output.is_file(), output)
            self.assertFalse(output.is_symlink(), output)
            self.assertEqual(output.stat().st_nlink, 1, output)
        self.assertEqual(
            {
                path.relative_to(result.dtb_dir).as_posix()
                for path in result.dtb_dir.rglob("*")
                if path.is_file()
            },
            {"qcom/kona-v2.1-lmi.dtb"},
        )
        for optional in (
            "vendor_boot.img",
            "uInitrd",
            "uImage",
            "dtbo.img",
            "xiaomi-lmi-boot.img",
            "xiaomi-lmi-root.img",
            "pmos-xiaomi-lmi.zip",
            "lk2nd.img",
        ):
            self.assertFalse((self.work / "export" / optional).exists())
            self.assertFalse((self.work / "export" / optional).is_symlink())
        packages = result.packages.read_text().splitlines()
        for required in self.package_lines:
            self.assertIn(required, packages)
        self.assertIn("openssh-server-pam-9.9_p2-r0", packages)
        self.assertIn("openssh-client-common-9.9_p2-r0", packages)
        self.assertIn("openssh-client-default-9.9_p2-r0", packages)
        for package in (
            "networkmanager-1.52.2-r0",
            "networkmanager-openrc-1.52.2-r0",
            "networkmanager-cli-1.52.2-r0",
            "networkmanager-wifi-1.52.2-r0",
        ):
            self.assertIn(package, packages)
        self.assertFalse(
            any(
                package == "networkmanager-dnsmasq"
                or package.startswith("networkmanager-dnsmasq-")
                for package in packages
            )
        )
        self.assertIn("unudhcpd-0.1.4-r0", packages)
        self.assertIn("unudhcpd-openrc-0.1.4-r0", packages)
        sshd_pam = json.loads(result.sshd_pam.read_text())
        self.assertEqual(
            sshd_pam,
            {
                "apk_database_checksum": sshd_pam["apk_database_checksum"],
                "architecture": "aarch64",
                "package": "openssh-server-pam",
                "package_id": "openssh-server-pam-9.9_p2-r0",
                "path": "/usr/sbin/sshd.pam",
                "schema": "lmi-sshd-pam-attestation/v1",
                "sha256": sshd_pam["sha256"],
                "size": 147,
                "version": "9.9_p2-r0",
            },
        )
        self.assertRegex(sshd_pam["apk_database_checksum"], r"^Q1[A-Za-z0-9+/]+$")
        self.assertRegex(sshd_pam["sha256"], r"^[0-9a-f]{64}$")
        identity = dict(
            line.split("=", 1) for line in result.identity.read_text().splitlines()
        )
        manifest_sha = hashlib.sha256(result.packages.read_bytes()).hexdigest()
        expected_id = hashlib.sha256(
            b"\0".join(
                value.encode()
                for value in (
                    "lmi-p1-release-identity/v2",
                    self.ctx.tag,
                    self.ctx.policy_id,
                    self.ctx.source_commit,
                    self.fake_commit,
                    self.pmaports_commit,
                    "AAAA-BBBB",
                    "11111111-2222-3333-4444-555555555555",
                    manifest_sha,
                )
            )
        ).hexdigest()
        self.assertEqual(identity["candidate_id"], expected_id)
        self.assertEqual(artifact_manifest["build_id"], expected_id)
        self.assertNotEqual(artifact_manifest["artifact_set_id"], expected_id)
        self.assertEqual(
            artifact_manifest["files"],
            sorted(artifact_manifest["files"], key=lambda entry: entry["path"]),
        )
        self.assertEqual(identity["boot_uuid"], "AAAA-BBBB")
        self.assertEqual(identity["root_uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(identity["package_manifest_sha256"], manifest_sha)
        self.assertEqual(identity["scope"], "lmi-p1-ssh")
        self.assertEqual(identity["privilege_model"], "unsealed-development")
        self.assertEqual(identity["policy_id"], "none")
        self.assertEqual(identity["source_commit"], self.source_commit)
        self.assertEqual(identity["pmbootstrap_commit"], self.fake_commit)
        self.assertEqual(identity["pmaports_commit"], self.pmaports_commit)
        self.assertEqual(identity["artifact_classification"], "owner-test-private")
        self.assertEqual(identity["release_eligible"], "false")
        self.assertEqual(identity["publication"], "never-publish")
        self.assertEqual(identity["credential_state"], "owner-key-provisioned")
        self.assertEqual(identity["device_xiaomi_lmi"], "1-r145")
        self.assertEqual(identity["linux_xiaomi_lmi"], "4.19.325-r8")
        self.assertFalse(any(key.startswith("weston") for key in identity))
        self.assertNotIn("boot_sha256", identity)
        self.assertNotIn("rootfs_sha256", identity)
        self.assertEqual((self.finalizer_copy / "lmi-release-identity").read_bytes(), result.identity.read_bytes())
        world = result.world.read_text().splitlines()
        pinned_world = {
            f"{name}={version}" for name, version in self.required_versions.items()
        }
        self.assertTrue(pinned_world.issubset(world))
        self.assertIn("openssh-server-pam=9.9_p2-r0", world)
        self.assertIn("openssh-client-default=9.9_p2-r0", world)
        for name in (
            "networkmanager",
            "networkmanager-openrc",
            "networkmanager-cli",
            "networkmanager-wifi",
        ):
            self.assertIn(f"{name}=1.52.2-r0", world)
        self.assertIn("unudhcpd-openrc=0.1.4-r0", world)
        self.assertTrue(set(self.required_versions).isdisjoint(world))
        self.assertEqual(
            (self.finalizer_copy / "world").read_bytes(), result.world.read_bytes()
        )
        self.assertEqual(
            (self.finalizer_copy / "sudoers").read_bytes(),
            (PAYLOAD / "sudoers").read_bytes(),
        )
        self.assertEqual(
            (self.finalizer_copy / "90-lmi-rootctl").read_bytes(),
            (PAYLOAD / "90-lmi-rootctl").read_bytes(),
        )
        self.assertEqual(
            (self.finalizer_copy / "lmi-rootctl").read_bytes(),
            (
                REPO
                / "artifacts/wsl-pmaports/device-xiaomi-lmi/lmi-rootctl"
            ).read_bytes(),
        )
        self.assertEqual(
            (self.finalizer_copy / "lmi-usb0.nmconnection").read_bytes(),
            (PAYLOAD / "lmi-usb0.nmconnection").read_bytes(),
        )
        self.assertEqual(
            (self.finalizer_copy / "90-lmi-usb0-takeover.conf").read_bytes(),
            (PAYLOAD / "90-lmi-usb0-takeover.conf").read_bytes(),
        )
        for name in (
            "lmi-usb0-dhcp",
            "lmi-usb0-dhcp.initd",
            "unudhcpd.usb0.confd",
        ):
            self.assertEqual(
                (self.finalizer_copy / name).read_bytes(),
                (PAYLOAD / name).read_bytes(),
            )
        self.assertEqual(
            self.finalizer_copy.joinpath("90-lmi-usb0-takeover.conf").stat().st_mode
            & 0o777,
            0o644,
        )
        finalizer = (self.finalizer_copy / "finalize.sh").read_text()
        for marker in (
            "/etc/ssh/ssh_host_*",
            "/etc/ssh/sshd_config",
            "/usr/sbin/lmi-rootctl",
            "/etc/sudoers.d/90-lmi-rootctl",
            "/etc/runlevels/default/sshd",
            "/etc/runlevels/default/networkmanager",
            "/etc/runlevels/default/lmi-usb0-dhcp",
            "/etc/init.d/unudhcpd.usb0",
            "/etc/conf.d/unudhcpd.usb0",
            "lmi-p1-finalize=ok",
        ):
            self.assertIn(marker, finalizer)
        candidate_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in self.work.rglob("*")
            if path.is_file()
        )
        self.assertNotIn(self.ephemeral, candidate_text)
        build_log = result.build_log.read_text()
        self.assertIn("[REDACTED_EPHEMERAL_PASSWORD]", build_log)
        self.assertNotIn(str(self.root), build_log)
        self.assertNotIn(str(self.source_repo), build_log)
        self.assertNotIn(str(self.pmaports), build_log)
        self.assertNotIn(str(self.pmbootstrap), build_log)
        for label in (
            "[CANDIDATE]",
            "[PROJECT_INPUT]",
            "[PMBOOTSTRAP_INPUT]",
            "[PMAPORTS_INPUT]",
        ):
            self.assertIn(label, build_log)

    def test_release_identity_rejects_non_p1_scope_and_package_revisions(self):
        source = (PAYLOAD / "lmi-release-identity").read_text()
        for current, replacement in (
            ("scope=lmi-p1-ssh", "scope=lmi-p1-other"),
            (
                "artifact_classification={artifact_classification}",
                "artifact_classification=public-release",
            ),
            ("release_eligible={release_eligible}", "release_eligible=true"),
            ("publication={publication}", "publication=public"),
            (
                "credential_state={credential_state}",
                "credential_state=unprovisioned",
            ),
            ("device_xiaomi_lmi=1-r145", "device_xiaomi_lmi=1-r139"),
            ("linux_xiaomi_lmi=4.19.325-r8", "linux_xiaomi_lmi=4.19.325-r9"),
        ):
            with self.subTest(replacement=replacement):
                template = self.root / "identity-template"
                template.write_text(source.replace(current, replacement))
                with self.assertRaisesRegex(
                    GateError, "release identity template P1 policy mismatch"
                ):
                    build_module._render_identity(
                        template,
                        tag=self.ctx.tag,
                        privilege_model=self.ctx.privilege_model,
                        policy_id=self.ctx.policy_id,
                        source_commit=self.ctx.source_commit,
                        boot_uuid="AAAA-BBBB",
                        root_uuid="11111111-2222-3333-4444-555555555555",
                        package_manifest_sha256="a" * 64,
                    )

    def test_initial_install_rejects_r139_and_r9_package_revisions(self):
        for variable, forbidden in (
            ("LMI_FAKE_DEVICE_R139", "device-xiaomi-lmi-1-r139"),
            ("LMI_FAKE_KERNEL_R9", "linux-xiaomi-lmi-4.19.325-r9"),
        ):
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(
                            GateError,
                            rf"P1 package policy mismatch.*{re.escape(forbidden)}",
                        ):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_final_install_rejects_r139_and_r9_package_revisions(self):
        for variable, forbidden in (
            ("LMI_FAKE_FINAL_DEVICE_R139", "device-xiaomi-lmi-1-r139"),
            ("LMI_FAKE_FINAL_KERNEL_R9", "linux-xiaomi-lmi-4.19.325-r9"),
        ):
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(
                            GateError,
                            rf"P1 package policy mismatch.*{re.escape(forbidden)}",
                        ):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_missing_openssh_server_pam_package_is_rejected_before_final_install(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_OPENSSH_MISSING_PACKAGE": "1"}):
            with self.assertRaisesRegex(
                GateError, "missing installed SSH server package"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_ssh_client_packages_and_command_owners_are_required(self):
        cases = (
            (
                {"LMI_FAKE_OPENSSH_CLIENT_MISSING": "1"},
                "missing installed SSH client package",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_WRONG_ARCH": "1"},
                "openssh-client-.* architecture is not exactly aarch64",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_UNOWNED": "1"},
                "/usr/bin/ssh does not have its canonical SSH client owner",
            ),
        )
        for environment, message in cases:
            with self.subTest(environment=environment):
                try:
                    with mock.patch.dict(os.environ, environment):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_ssh_client_versions_and_binaries_are_frozen(self):
        cases = (
            (
                {"LMI_FAKE_OPENSSH_CLIENT_VERSION_CHANGE": "1"},
                "version does not match openssh-server-pam|versions changed",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_MISSING_FILE": "ssh"},
                "ssh must be a regular non-symlink",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_WRONG_ELF": "ssh-add"},
                "ssh-add is not a valid little-endian 64-bit AArch64 ELF",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_BAD_DB_CHECKSUM": "1"},
                "does not match its APK database checksum",
            ),
        )
        for environment, message in cases:
            with self.subTest(environment=environment):
                try:
                    with mock.patch.dict(os.environ, environment):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_ssh_client_files_and_ancestry_require_root_owned_safe_metadata(self):
        cases = (
            (
                {"LMI_FAKE_OPENSSH_CLIENT_USER_OWNED": "ssh"},
                "ssh metadata is not canonical",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_PARENT_SYMLINK": "1"},
                "OpenSSH server ancestry is not canonical: /usr/bin",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_WRITABLE_PARENT": "usr/bin"},
                "OpenSSH server ancestry is not canonical: /usr/bin",
            ),
            (
                {"LMI_FAKE_OPENSSH_CLIENT_NONROOT_PARENT": "usr"},
                "SSH client ancestry is not a safe real directory: /usr",
            ),
        )
        for environment, message in cases:
            with self.subTest(environment=environment):
                try:
                    with mock.patch.dict(os.environ, environment):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_dhcp_packages_are_exact_and_have_one_owner(self):
        cases = (
            (
                "LMI_FAKE_UNUDHCPD_OPENRC_MISSING",
                "missing installed DHCP package.*unudhcpd-openrc",
            ),
            (
                "LMI_FAKE_UNUDHCPD_WRONG_ARCH",
                "unudhcpd architecture is not exactly aarch64",
            ),
            (
                "LMI_FAKE_SECOND_DHCP_OWNER",
                "second full-userland DHCP owner.*dnsmasq",
            ),
        )
        for variable, message in cases:
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_headless_networkmanager_closure_is_exact_and_owns_nmcli(self):
        cases = (
            (
                "LMI_FAKE_NETWORKMANAGER_VERSION",
                "networkmanager version differs from the pinned offline package",
            ),
            (
                "LMI_FAKE_NETWORKMANAGER_NMCLI_OWNER",
                "networkmanager-cli does not uniquely own /usr/bin/nmcli",
            ),
            (
                "LMI_FAKE_NETWORKMANAGER_DAEMON_OWNER",
                "networkmanager does not uniquely own /usr/sbin/NetworkManager",
            ),
            (
                "LMI_FAKE_NETWORKMANAGER_DAEMON_BAD_DB_CHECKSUM",
                "NetworkManager does not match its APK database checksum",
            ),
            (
                "LMI_FAKE_NETWORKMANAGER_VENDOR_BAD_DB_CHECKSUM",
                "00-interfaces.conf does not match its APK database checksum",
            ),
            (
                "LMI_FAKE_NETWORKMANAGER_VENDOR_BAD_MODE",
                "20-dhcp-internal.conf",
            ),
        )
        for variable, message in cases:
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_unudhcpd_version_and_binary_architecture_are_frozen(self):
        cases = (
            (
                "LMI_FAKE_UNUDHCPD_VERSION_CHANGE",
                "P1 package policy mismatch|versions changed",
            ),
            (
                "LMI_FAKE_UNUDHCPD_BINARY_WRONG_ARCH",
                "unudhcpd is not a valid little-endian 64-bit AArch64 ELF",
            ),
        )
        for variable, message in cases:
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_openssh_server_pam_version_cannot_change_during_final_install(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_OPENSSH_VERSION_CHANGE": "1"}):
            with self.assertRaisesRegex(
                GateError, "openssh-server-pam version changed during final install"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_conflicting_openssh_server_pam_world_constraint_is_rejected(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_OPENSSH_WORLD_CONFLICT": "1"}):
            with self.assertRaisesRegex(
                GateError, "conflicting world constraint for openssh-server-pam"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_sshd_pam_must_be_owned_by_openssh_server_pam(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_OPENSSH_UNOWNED": "1"}):
            with self.assertRaisesRegex(
                GateError, "openssh-server-pam does not uniquely own /usr/sbin/sshd.pam"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_openssh_server_closure_packages_and_payloads_are_required(self):
        cases = (
            (
                {"LMI_FAKE_OPENSSH_SERVER_MISSING_PACKAGE": "openssh-keygen"},
                "missing installed SSH server package",
            ),
            (
                {"LMI_FAKE_OPENSSH_SERVER_VERSION_MISMATCH": "1"},
                "installed OpenSSH server package versions differ",
            ),
            (
                {
                    "LMI_FAKE_OPENSSH_SERVER_MISSING_PAYLOAD":
                    "usr/lib/ssh/sshd-session.pam"
                },
                "required OpenSSH server payload is missing",
            ),
        )
        for environment, message in cases:
            with self.subTest(environment=environment):
                try:
                    with mock.patch.dict(os.environ, environment):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)

    def test_sshd_pam_must_be_a_real_aarch64_elf(self):
        elf_error = "sshd.pam is not a valid little-endian 64-bit AArch64 ELF"
        for variable, message in (
            ("LMI_FAKE_OPENSSH_MISSING_FILE", "sshd.pam must be a regular non-symlink"),
            ("LMI_FAKE_OPENSSH_SYMLINK", "sshd.pam must be a regular non-symlink"),
            ("LMI_FAKE_OPENSSH_WRONG_ARCH", elf_error),
            ("LMI_FAKE_OPENSSH_TRUNCATED_ELF", elf_error),
            ("LMI_FAKE_OPENSSH_BAD_ELF_TYPE", elf_error),
            ("LMI_FAKE_OPENSSH_BAD_ELF_HEADER_SIZE", elf_error),
            ("LMI_FAKE_OPENSSH_BAD_PROGRAM_TABLE", elf_error),
        ):
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(GateError, message):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)
                    self.finalizer_copy = self.root / f"finalize-copy-{variable}"
                    os.environ["LMI_FAKE_FINALIZER_COPY"] = str(self.finalizer_copy)

    def test_sshd_pam_entry_must_be_in_nonempty_executable_load_segment(self):
        elf_error = "sshd.pam is not a valid little-endian 64-bit AArch64 ELF"
        variables = (
            "LMI_FAKE_OPENSSH_ZERO_ENTRY",
            "LMI_FAKE_OPENSSH_OUT_OF_RANGE_ENTRY",
            "LMI_FAKE_OPENSSH_OVERFLOW_ENTRY",
            "LMI_FAKE_OPENSSH_NONEXEC_ENTRY",
        )
        for variable in variables:
            with self.subTest(variable=variable):
                try:
                    with mock.patch.dict(os.environ, {variable: "1"}):
                        with self.assertRaisesRegex(GateError, elf_error):
                            build_candidate(self.ctx)
                    self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
                finally:
                    if self.work.exists():
                        shutil.rmtree(self.work)
                    self.log.unlink(missing_ok=True)
                    self.finalizer_copy = self.root / f"finalize-copy-{variable}"
                    os.environ["LMI_FAKE_FINALIZER_COPY"] = str(self.finalizer_copy)

    def test_sshd_pam_must_match_its_apk_database_checksum(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_OPENSSH_BAD_DB_CHECKSUM": "1"}):
            with self.assertRaisesRegex(
                GateError, "sshd.pam does not match its APK database checksum"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_conflicting_p1_world_constraint_is_rejected(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_CONFLICTING_WORLD": "1"}):
            with self.assertRaisesRegex(
                GateError, "conflicting world constraint for device-xiaomi-lmi"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_tagged_p1_world_constraint_is_rejected(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_TAGGED_WORLD": "1"}):
            with self.assertRaisesRegex(
                GateError, "conflicting world constraint for device-xiaomi-lmi"
            ):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_final_install_cannot_relax_pinned_world(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_FINAL_INSTALL_BARE_WORLD": "1"}):
            with self.assertRaisesRegex(GateError, "P1 world constraint mismatch"):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_exception_runs_shutdown_and_does_not_copy_password_to_logs(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_FAIL_FINAL_INSTALL": "1"}):
            with mock.patch.object(
                build_module.secrets, "token_urlsafe", return_value=self.ephemeral
            ):
                with self.assertRaises(GateError) as raised:
                    build_candidate(self.ctx)
        self.assertNotIn(self.ephemeral, str(raised.exception))
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])
        for path in self.work.rglob("*"):
            if path.is_file():
                self.assertNotIn(
                    self.ephemeral,
                    path.read_text(encoding="utf-8", errors="replace"),
                    path,
                )
        self.assertFalse((self.work / "work/packages/lmi-p1-finalize").exists())

    def test_export_rejects_extra_entry(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_EXTRA": "1"}):
            with self.assertRaisesRegex(GateError, "unexpected export inventory"):
                build_candidate(self.ctx)

    def test_export_rejects_target_outside_candidate(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_ESCAPE": "1"}):
            with self.assertRaisesRegex(GateError, "export target escapes candidate"):
                build_candidate(self.ctx)

    def test_export_rejects_dangling_target(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_DANGLING": "1"}):
            with self.assertRaisesRegex(GateError, "dangling export target"):
                build_candidate(self.ctx)

    def test_export_rejects_unknown_dangling_entry(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_UNKNOWN_DANGLING": "1"}):
            with self.assertRaisesRegex(GateError, "unexpected export inventory"):
                build_candidate(self.ctx)

    def test_export_rejects_known_optional_target_escape(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_OPTIONAL_ESCAPE": "1"}):
            with self.assertRaisesRegex(GateError, "export target escapes candidate"):
                build_candidate(self.ctx)

    def test_export_materializes_known_optional_when_real(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_OPTIONAL_REAL": "1"}):
            self._build()
        optional = self.work / "export/vendor_boot.img"
        self.assertTrue(optional.is_file())
        self.assertFalse(optional.is_symlink())
        self.assertEqual(optional.stat().st_nlink, 1)
        self.assertEqual(optional.read_bytes(), b"vendor-boot")

    def test_export_materializes_exact_initramfs_extra_when_real(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_INITRAMFS_EXTRA": "1"}):
            self._build()
        extra = self.work / "export/initramfs-extra"
        self.assertTrue(extra.is_file())
        self.assertFalse(extra.is_symlink())
        self.assertEqual(extra.stat().st_nlink, 1)
        self.assertEqual(extra.read_bytes(), b"initramfs-extra")

    def test_export_rejects_unknown_dynamic_variant(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_EXPORT_UNKNOWN_DYNAMIC": "1"}):
            with self.assertRaisesRegex(GateError, "unexpected export inventory"):
                build_candidate(self.ctx)

    def test_export_rejects_missing_selected_nested_dtb(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_DTB_MISSING": "1"}):
            with self.assertRaisesRegex(GateError, "selected DTB is missing"):
                build_candidate(self.ctx)

    def test_export_rejects_dangling_selected_nested_dtb(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_DTB_DANGLING": "1"}):
            with self.assertRaisesRegex(GateError, "selected DTB must be a real file"):
                build_candidate(self.ctx)

    def test_export_rejects_escaping_selected_nested_dtb(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_DTB_ESCAPE": "1"}):
            with self.assertRaisesRegex(GateError, "selected DTB must be a real file"):
                build_candidate(self.ctx)

    def test_export_target_swap_after_validation_fails_closed(self):
        original = build_module._validate_export_links

        def validate_then_swap(*arguments):
            result = original(*arguments)
            target = self.work / "work/chroot_rootfs_xiaomi-lmi/boot/boot.img"
            target.unlink()
            target.symlink_to("/etc/passwd")
            return result

        with mock.patch.object(
            build_module, "_validate_export_links", side_effect=validate_then_swap
        ):
            with self.assertRaisesRegex(GateError, "changed|identity"):
                build_candidate(self.ctx)

    def test_export_parent_swap_after_validation_fails_closed(self):
        original = build_module._validate_export_links

        def validate_then_swap(*arguments):
            result = original(*arguments)
            self.work.joinpath("export").rename(self.work / "export-attacker-hidden")
            (self.work / "export").mkdir()
            return result

        with mock.patch.object(
            build_module, "_validate_export_links", side_effect=validate_then_swap
        ):
            with self.assertRaisesRegex(GateError, "changed|identity"):
                build_candidate(self.ctx)

    def test_export_target_parent_swap_after_validation_fails_closed(self):
        original = build_module._validate_export_links

        def validate_then_swap(*arguments):
            result = original(*arguments)
            boot = self.work / "work/chroot_rootfs_xiaomi-lmi/boot"
            boot.rename(boot.parent / "boot-attacker-hidden")
            boot.mkdir()
            (boot / "boot.img").write_bytes(b"attacker replacement")
            return result

        with mock.patch.object(
            build_module, "_validate_export_links", side_effect=validate_then_swap
        ):
            with self.assertRaisesRegex(GateError, "changed|identity"):
                build_candidate(self.ctx)

    def test_existing_work_root_is_rejected_before_pmbootstrap(self):
        self.work.mkdir(mode=0o700)

        with self.assertRaisesRegex(GateError, "must not already exist"):
            build_candidate(self.ctx)

        self.assertFalse(self.log.exists())

    def test_root_euid_is_rejected_before_pmbootstrap(self):
        with mock.patch.object(os, "geteuid", return_value=0):
            with self.assertRaisesRegex(GateError, "unprivileged user"):
                build_candidate(self.ctx)

        self.assertFalse(self.log.exists())

    def test_forged_root_context_strings_do_not_grant_sealed_authorization(self):
        forged = dataclasses.replace(
            self.ctx,
            privilege_model="root-owned-sealed-production",
            policy_id="a" * 64,
        )
        with mock.patch.object(os, "geteuid", return_value=0):
            with self.assertRaisesRegex(GateError, "verified internal authorization"):
                build_candidate(forged)
            with self.assertRaisesRegex(GateError, "authorization is invalid"):
                build_candidate(forged, _sealed_authorization=object())

        self.assertFalse(self.log.exists())

    def test_pmbootstrap_as_root_is_inserted_only_for_authorized_sealed_mode(self):
        arguments = ("--version",)
        development = build_module._pmbootstrap_argv(
            self.pmbootstrap,
            self.root / "config",
            self.root / "work",
            self.pmaports,
            arguments,
            sealed=False,
        )
        sealed = build_module._pmbootstrap_argv(
            self.pmbootstrap,
            self.root / "config",
            self.root / "work",
            self.pmaports,
            arguments,
            sealed=True,
        )
        self.assertNotIn("--as-root", development)
        self.assertNotIn("--offline", development)
        self.assertEqual(sealed[sealed.index(str(self.pmbootstrap)) + 1], "--as-root")
        self.assertEqual(sealed.count("--as-root"), 1)
        self.assertEqual(sealed.count("--offline"), 1)
        self.assertLess(sealed.index("--offline"), sealed.index("-c"))

    def test_attacker_owned_work_ancestry_is_rejected_before_pmbootstrap(self):
        attacker_parent = self.root / "attacker-owned"
        attacker_parent.mkdir(mode=0o700)
        attacker_work = attacker_parent / "candidate"
        with mock.patch.object(os, "geteuid", return_value=os.geteuid() + 1):
            with self.assertRaisesRegex(GateError, "unsafe candidate work ancestry"):
                build_candidate(dataclasses.replace(self.ctx, work=attacker_work))

        self.assertFalse(self.log.exists())

    def test_world_writable_work_ancestry_is_rejected_before_pmbootstrap(self):
        attacker_parent = self.root / "replaceable-parent"
        attacker_parent.mkdir(mode=0o777)
        attacker_parent.chmod(0o777)

        with self.assertRaisesRegex(GateError, "unsafe candidate work ancestry"):
            build_candidate(
                dataclasses.replace(self.ctx, work=attacker_parent / "candidate")
            )

        self.assertFalse(self.log.exists())

    def test_dirty_source_worktree_is_not_used_as_a_build_input(self):
        (self.source_repo / "untracked-build-input").write_text("dirty\n")
        self._build()
        self.assertTrue(self.log.exists())
        self.assertFalse((self.work / "source/untracked-build-input").exists())

    def test_dirty_pmbootstrap_repository_is_rejected_before_version_probe(self):
        (self.fake_repo / "untracked-tool-input").write_text("dirty\n")
        with self.assertRaisesRegex(GateError, "pmbootstrap repository is dirty"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_rejects_unlisted_tracked_member(self):
        with (self.pmaports / ".gitignore").open("a") as stream:
            stream.write("extra-unmanifested-pattern\n")
        with self.assertRaisesRegex(GateError, "pmaports stage inventory mismatch"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_rejects_unlisted_ignored_member(self):
        (self.pmaports / "unlisted.ignored").write_text("ignored but unmanifested\n")
        with self.assertRaisesRegex(GateError, "pmaports stage inventory mismatch"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_rejects_assume_unchanged_tracked_bytes(self):
        config = self.pmaports / "pmaports.cfg"
        config.write_text(config.read_text() + "# hidden attacker bytes\n")
        self._git(
            "update-index", "--assume-unchanged", "pmaports.cfg", cwd=self.pmaports
        )
        with self.assertRaisesRegex(GateError, "special index flags"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_rejects_skip_worktree_tracked_bytes(self):
        self._git("update-index", "--skip-worktree", "pmaports.cfg", cwd=self.pmaports)
        config = self.pmaports / "pmaports.cfg"
        config.write_text(config.read_text() + "# hidden attacker bytes\n")
        with self.assertRaisesRegex(GateError, "special index flags"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_rejects_replacement_tree(self):
        original = self.pmaports_commit
        self._git("config", "user.name", "LMI test", cwd=self.pmaports)
        self._git(
            "config",
            "user.email",
            "lmi-pmaports-test@example.invalid",
            cwd=self.pmaports,
        )
        config = self.pmaports / "pmaports.cfg"
        attacker = config.read_text() + "# replacement-tree bytes\n"
        config.write_text(attacker)
        self._git("add", "pmaports.cfg", cwd=self.pmaports)
        self._git("commit", "-q", "-m", "replacement tree", cwd=self.pmaports)
        replacement = self._git("rev-parse", "HEAD", cwd=self.pmaports).strip()
        self._git("checkout", "-q", "--detach", original, cwd=self.pmaports)
        config.write_text(attacker)
        self._git("replace", original, replacement, cwd=self.pmaports)

        with self.assertRaisesRegex(GateError, "replace refs"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_head_must_match_manifest_commit(self):
        self._git("commit", "--allow-empty", "-q", "-m", "unexpected head", cwd=self.pmaports)
        with self.assertRaisesRegex(GateError, "pmaports base source HEAD mismatch"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_staged_pmaports_manifest_must_be_a_real_file(self):
        manifest = self.pmaports / ".lmi-p1-stage.json"
        external = self.root / "external-stage-manifest.json"
        manifest.replace(external)
        manifest.symlink_to(external)
        with self.assertRaisesRegex(GateError, "manifest must be a real file"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_copied_pmaports_is_fully_revalidated_before_pmbootstrap(self):
        original_prepare = build_module.prepare_pmaports

        def prepare_then_tamper(*args, **kwargs):
            manifest = original_prepare(*args, **kwargs)
            destination = Path(kwargs["destination"])
            (destination / "copied-extra").write_text("unlisted after copy\n")
            return manifest

        with mock.patch.object(
            build_module, "prepare_pmaports", side_effect=prepare_then_tamper
        ):
            with self.assertRaisesRegex(GateError, "pmaports stage inventory mismatch"):
                build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_ignored_fake_pmbootstrap_entrypoint_is_rejected(self):
        ignored = self.fake_repo / "ignored-pmbootstrap.py"
        ignored.write_text(self._fake_pmbootstrap_source())
        ignored.chmod(0o755)
        (self.fake_repo / ".git/info/exclude").write_text("ignored-pmbootstrap.py\n")
        with self.assertRaisesRegex(GateError, "tracked pmbootstrap.py"):
            build_candidate(dataclasses.replace(self.ctx, pmbootstrap=ignored))
        self.assertFalse(self.log.exists())

    def test_source_assume_unchanged_payload_uses_commit_blob(self):
        relative = Path("files/lmi-p1/sshd_config")
        payload = self.source_repo / relative
        committed = subprocess.run(
            ["git", "-C", str(self.source_repo), "show", f"{self.source_commit}:{relative.as_posix()}"],
            capture_output=True,
            check=True,
        ).stdout
        payload.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")
        self._git(
            "update-index", "--assume-unchanged", relative.as_posix(), cwd=self.source_repo
        )

        self._build()

        self.assertEqual((self.finalizer_copy / "sshd_config").read_bytes(), committed)
        self.assertNotIn(b"PermitRootLogin yes", committed)

    def test_source_repository_rejects_replace_refs(self):
        original = self.source_commit
        payload = self.source_repo / "files/lmi-p1/sshd_config"
        payload.write_text("PermitRootLogin yes\n")
        self._git("add", "files/lmi-p1/sshd_config", cwd=self.source_repo)
        self._git("commit", "-q", "-m", "replacement payload", cwd=self.source_repo)
        replacement = self._git("rev-parse", "HEAD", cwd=self.source_repo).strip()
        self._git("checkout", "-q", "--detach", original, cwd=self.source_repo)
        self._git("replace", original, replacement, cwd=self.source_repo)

        with self.assertRaisesRegex(GateError, "replace refs"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_pmbootstrap_runs_only_isolated_clone_with_python_env_sanitized(self):
        injected = {
            "PYTHONPATH": "/tmp/attacker-pythonpath",
            "PYTHONBREAKPOINT": "attacker.breakpoint",
            "PYTHONATTACKVECTOR": "must-not-reach-pmbootstrap",
            "LD_LIBRARY_PATH": "/tmp/attacker-native-library-path",
            "LD_AUDIT": "/tmp/attacker-audit-library",
            "BASH_ENV": "/tmp/attacker-bash-env",
            "ENV": "/tmp/attacker-shell-env",
            "CDPATH": "/tmp/attacker-cdpath",
            "SHELLOPTS": "xtrace",
            "BASHOPTS": "extdebug",
            "IFS": "attacker-ifs",
            "BASH_FUNC_attacker%%": "() { /usr/bin/false; }",
            "PMBOOTSTRAP_CMD": "attacker-pmbootstrap-command",
            "PMB_ATTACK": "attacker-pmb-control",
            "APK_CONFIG": "/tmp/attacker-apk-config",
            "CCACHE_DIR": "/tmp/attacker-ccache",
            "XDG_CONFIG_HOME": "/tmp/attacker-xdg-config",
            "PATH": "/tmp/attacker-path",
            "GIT_DIR": "/tmp/attacker-git-dir",
            "GIT_CONFIG_GLOBAL": "/tmp/attacker-global-gitconfig",
            "GIT_OPTIONAL_LOCKS": "0",
            "GH_TOKEN": "synthetic-gh-secret",
            "AWS_SECRET_ACCESS_KEY": "synthetic-aws-secret",
            "SSH_AUTH_SOCK": "/tmp/synthetic-agent.sock",
            "HTTPS_PROXY": "http://synthetic-proxy.invalid",
            "SSL_CERT_FILE": "/tmp/synthetic-ca.pem",
            "HOST_BUILD_SECRET": "synthetic-host-secret",
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            self._build()
        self.assertEqual(
            json.loads(self.pmbootstrap_environment_log.read_text()),
            {
                "HOME": str(self.work / ".runtime/home"),
                "USER": "root",
                "LOGNAME": "root",
                "SHELL": "/bin/sh",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
                "TMPDIR": str(self.work / ".runtime/tmp"),
                "XDG_CACHE_HOME": str(self.work / ".runtime/cache"),
                "XDG_CONFIG_HOME": str(self.work / ".runtime/config"),
                "XDG_DATA_HOME": str(self.work / ".runtime/data"),
                "TERM": "dumb",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_NO_LAZY_FETCH": "1",
                "GIT_ALLOW_PROTOCOL": "",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        for name in (".runtime", ".runtime/home", ".runtime/tmp", ".runtime/cache", ".runtime/config", ".runtime/data"):
            directory = self.work / name
            self.assertTrue(directory.is_dir())
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        entrypoint = Path(self.pmbootstrap_entrypoint_log.read_text().strip())
        self.assertNotEqual(entrypoint, self.pmbootstrap.resolve())
        self.assertEqual(entrypoint, (self.work / "pmbootstrap/pmbootstrap.py").resolve())

    def test_git_dir_environment_cannot_redirect_repository_validation(self):
        with mock.patch.dict(
            os.environ, {"GIT_DIR": str(self.fake_repo / ".git")}, clear=False
        ):
            self._build()

    def test_global_post_checkout_hook_cannot_execute(self):
        sentinel = self.root / "malicious-hook-ran"
        hooks = self.root / "global-hooks"
        hooks.mkdir()
        hook = hooks / "post-checkout"
        hook.write_text(f"#!/bin/sh\n/usr/bin/touch {sentinel}\n")
        hook.chmod(0o755)
        global_config = self.root / "malicious-global-gitconfig"
        global_config.write_text(f"[core]\n\thooksPath = {hooks}\n")
        with mock.patch.dict(
            os.environ, {"GIT_CONFIG_GLOBAL": str(global_config)}, clear=False
        ):
            self._build()
        self.assertFalse(sentinel.exists())

    def test_git_commands_are_sanitized_and_bind_exact_safe_directories(self):
        with mock.patch.dict(
            os.environ, {"GIT_OPTIONAL_LOCKS": "0"}, clear=False
        ), mock.patch.object(build_module, "run", wraps=build_module.run) as runner:
            self._build()

        allowed_repositories = {
            self.pmaports.resolve(),
            self.source_repo.resolve(),
            self.fake_repo.resolve(),
            (self.work / "pmaports").resolve(),
            (self.work / "pmbootstrap").resolve(),
        }
        git_calls = [
            call
            for call in runner.call_args_list
            if Path(call.args[0][0]).name == "git"
        ]
        self.assertTrue(git_calls)
        for call in git_calls:
            argv = list(call.args[0])
            environment = call.kwargs.get("env")
            self.assertIsNotNone(environment, argv)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
            self.assertEqual(environment["GIT_NO_LAZY_FETCH"], "1")
            self.assertIn(environment["GIT_ALLOW_PROTOCOL"], {"", "file"})
            self.assertEqual(environment["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")
            self.assertNotIn("GIT_OPTIONAL_LOCKS", environment)
            for key in environment:
                self.assertFalse(key.upper().startswith("LD_"), key)
                self.assertFalse(key.upper().startswith("PYTHON"), key)
                self.assertFalse(
                    key.upper().startswith(
                        (
                            "BASH_FUNC_",
                            "PMBOOTSTRAP",
                            "PMB",
                            "APK_",
                            "CCACHE",
                        )
                    ),
                    key,
                )
                self.assertNotIn(
                    key.upper(),
                    {"BASH_ENV", "ENV", "CDPATH", "SHELLOPTS", "BASHOPTS", "IFS"},
                )
            private_runtime = self.work / ".runtime"
            self.assertEqual(Path(environment["HOME"]), private_runtime / "home")
            self.assertEqual(Path(environment["TMPDIR"]), private_runtime / "tmp")
            self.assertEqual(
                Path(environment["XDG_CACHE_HOME"]), private_runtime / "cache"
            )
            self.assertEqual(
                Path(environment["XDG_CONFIG_HOME"]), private_runtime / "config"
            )
            self.assertEqual(
                Path(environment["XDG_DATA_HOME"]), private_runtime / "data"
            )
            configs = [
                argv[index + 1]
                for index, value in enumerate(argv[:-1])
                if value == "-c"
            ]
            safe = [value for value in configs if value.startswith("safe.directory=")]
            self.assertEqual(len(safe), 1, argv)
            self.assertIn(Path(safe[0].split("=", 1)[1]), allowed_repositories)
            self.assertIn("core.hooksPath=/dev/null", configs)

    def test_missing_promised_pmbootstrap_attributes_never_runs_remote_helper(self):
        attributes = self.fake_repo / ".gitattributes"
        attributes.write_text("*.py text\n")
        self._git("add", ".gitattributes", cwd=self.fake_repo)
        self._git("commit", "-q", "-m", "promised attributes", cwd=self.fake_repo)
        promised_commit = self._git("rev-parse", "HEAD", cwd=self.fake_repo).strip()
        self._repin_pmbootstrap_in_project_lock(promised_commit)
        blob = self._git(
            "rev-parse", "HEAD:.gitattributes", cwd=self.fake_repo
        ).strip()
        sentinel = self.root / "remote-helper-ran"
        helper = self.root / "sentinel-helper"
        helper.write_text(f"#!/bin/sh\n/usr/bin/touch {sentinel}\nexit 1\n")
        helper.chmod(0o755)
        self._git("config", "core.repositoryFormatVersion", "1", cwd=self.fake_repo)
        self._git("config", "extensions.partialClone", "origin", cwd=self.fake_repo)
        self._git("config", "remote.origin.promisor", "true", cwd=self.fake_repo)
        self._git(
            "config", "remote.origin.partialCloneFilter", "blob:none", cwd=self.fake_repo
        )
        self._git("config", "remote.origin.url", f"ext::{helper}", cwd=self.fake_repo)
        self._git("config", "protocol.ext.allow", "always", cwd=self.fake_repo)
        (self.fake_repo / ".git/objects" / blob[:2] / blob[2:]).unlink()

        with mock.patch.object(build_module, "_EXPECTED_PMBOOTSTRAP_COMMIT", promised_commit):
            with self.assertRaisesRegex(GateError, "promisor|partial clone"):
                build_candidate(
                    dataclasses.replace(self.ctx, source_commit=self.source_commit)
                )

        self.assertFalse(sentinel.exists())
        self.assertFalse(self.log.exists())

    def test_pmbootstrap_source_object_alternates_are_rejected(self):
        alternates = self.fake_repo / ".git/objects/info/alternates"
        alternates.parent.mkdir(parents=True, exist_ok=True)
        alternates.write_text(str(self.root / "attacker-objects") + "\n")

        with self.assertRaisesRegex(GateError, "object alternates"):
            build_candidate(self.ctx)

        self.assertFalse(self.log.exists())

    def test_newline_public_key_path_is_copied_to_fixed_private_config_path(self):
        injected = self.root / "key\nmalicious_setting = yes.pub"
        self.public_key.rename(injected)
        self.ctx = dataclasses.replace(self.ctx, public_key=injected)

        self._build()

        config = (self.work / "config/pmbootstrap.cfg").read_text()
        self.assertNotIn("malicious_setting", config)
        self.assertIn(
            f"ssh_key_glob = {self.work / 'config/authorized_key.pub'}", config
        )

    def test_public_key_source_replacement_after_secure_read_is_ignored(self):
        original_key = self.public_key.read_text()
        replacement = original_key.replace("lmi-test", "attacker-replacement")
        original_checkout = build_module._secure_checkout
        replaced = False

        def replace_after_read(*arguments, **keywords):
            nonlocal replaced
            if not replaced:
                replaced = True
                self.public_key.write_text(replacement)
            return original_checkout(*arguments, **keywords)

        with mock.patch.object(
            build_module, "_secure_checkout", side_effect=replace_after_read
        ):
            self._build()

        self.assertEqual(
            (self.finalizer_copy / "authorized_keys").read_text(), original_key
        )

    def test_pmbootstrap_tree_with_checkout_filter_is_rejected(self):
        (self.fake_repo / ".gitattributes").write_text("*.py filter=evil\n")
        self._git("add", ".gitattributes", cwd=self.fake_repo)
        self._git("commit", "-q", "-m", "add checkout filter", cwd=self.fake_repo)
        filtered_commit = self._git(
            "rev-parse", "HEAD", cwd=self.fake_repo
        ).strip()
        self._repin_pmbootstrap_in_project_lock(filtered_commit)
        with mock.patch.object(
            build_module, "_EXPECTED_PMBOOTSTRAP_COMMIT", filtered_commit
        ):
            with self.assertRaisesRegex(GateError, "checkout filter attributes"):
                build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_tampered_staged_pmaports_manifest_member_is_rejected(self):
        deviceinfo = self.pmaports / "device/downstream/device-xiaomi-lmi/deviceinfo"
        with deviceinfo.open("a") as stream:
            stream.write("# tampered after staging\n")
        with self.assertRaisesRegex(GateError, "pmaports stage hash mismatch"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

    def test_artifact_semantic_failure_rejects_the_candidate(self):
        with mock.patch.object(
            build_module,
            "validate_artifact_pair",
            side_effect=GateError("synthetic semantic rejection"),
        ) as validator:
            with self.assertRaisesRegex(GateError, "synthetic semantic rejection"):
                self._build()

        validator.assert_called_once()
        self.recheck_input_identities.assert_not_called()
        self.assertFalse((self.work / "export/artifact-semantics.json").exists())

    def test_release_ineligible_semantic_report_rejects_before_identity_recheck(self):
        report = dict(self.semantics_report)
        report["release"] = {"eligible": False}
        with mock.patch.object(
            build_module,
            "validate_artifact_pair",
            return_value=report,
        ), self.assertRaisesRegex(GateError, "not release eligible"):
            self._build()

        self.recheck_input_identities.assert_not_called()
        self.assertFalse((self.work / "export/artifact-semantics.json").exists())

    def test_identity_recheck_race_rejects_before_publication(self):
        self.recheck_input_identities.side_effect = GateError(
            "synthetic artifact input race"
        )

        with self.assertRaisesRegex(GateError, "synthetic artifact input race"):
            self._build()

        self.validate_artifact_pair.assert_called_once()
        self.recheck_input_identities.assert_called_once()
        self.assertFalse((self.work / "export/artifact-semantics.json").exists())

    def test_semantic_validation_precedes_identity_recheck(self):
        ordering: list[str] = []

        def validate(*_arguments, **_keywords):
            ordering.append("validate")
            return self.semantics_report

        def recheck(*_arguments, **_keywords):
            ordering.append("recheck")

        with mock.patch.object(
            build_module,
            "validate_artifact_pair",
            side_effect=validate,
        ), mock.patch.object(
            build_module,
            "recheck_input_identities",
            side_effect=recheck,
        ):
            self._build()

        self.assertEqual(ordering, ["validate", "recheck"])

    def test_post_validation_artifact_mutation_is_rejected_before_publication(self):
        def mutate_after_validation(*arguments, **_keywords):
            Path(arguments[0]).write_bytes(b"mutated-after-semantic-validation")
            return self.semantics_report

        with mock.patch.object(
            build_module,
            "validate_artifact_pair",
            side_effect=mutate_after_validation,
        ):
            with self.assertRaisesRegex(
                GateError, "no longer matches semantic evidence"
            ):
                self._build()


if __name__ == "__main__":
    unittest.main()
