from __future__ import annotations

import base64
from contextlib import redirect_stdout
import dataclasses
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import struct
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.build as build_module
from scripts.lmi_p1.build import BuildContext, BuildResult, build_candidate
from scripts.lmi_p1.common import GateError
import scripts.lmi_p1_cli as cli_module


REPO = Path(__file__).resolve().parents[2]
PAYLOAD = REPO / "files/lmi-p1"


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
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
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
method=shared
address1=172.16.42.1/24
never-default=true
shared-dhcp-range=172.16.42.2,172.16.42.2

[ipv6]
method=disabled
"""
        profile = PAYLOAD / "lmi-usb0.nmconnection"
        self.assertTrue(profile.is_file())
        self.assertEqual(profile.read_text(), expected)

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
            "/bin/chown root:root /etc/ssh/sshd_config",
            "/bin/chown root:root /usr/sbin/lmi-rootctl",
            "/bin/chown root:root /etc/lmi-release-identity",
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
                "printf ' <%s>' \"$@\" >> \"$LMI_TEST_CALLS\"\nprintf '\\n' >> \"$LMI_TEST_CALLS\"\n"
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
                "source_commit",
                "work",
                "pmaports",
                "d80",
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
                "build_log",
                "identity",
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
                build_log=(root / "build.log").absolute(),
                identity=(root / "identity").absolute(),
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
                "--d80",
                str(root / "d80"),
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
            self.assertEqual(context.source_commit, "a" * 40)
            self.assertEqual(context.repo, REPO)
            encoded = json.loads(output.getvalue())
            self.assertEqual(encoded["boot_img"], str(expected.boot_img))

    def test_legacy_builder_is_only_a_deprecation_wrapper(self):
        wrapper = (REPO / "scripts/70_build_downstream_ssh_wifi.sh").read_text()
        self.assertIn("deprecated:", wrapper)
        self.assertIn("exec python3 scripts/lmi_p1_cli.py build", wrapper)
        self.assertNotIn("21_build_pmos", wrapper)
        self.assertNotIn("PMOS_INSTALL_PASSWORD", wrapper)


class BuilderTests(unittest.TestCase):
    apk_names = (
        "device-xiaomi-lmi-1-r139.apk",
        "linux-xiaomi-lmi-4.19.325-r9.apk",
        "weston-14.0.2-r10.apk",
        "weston-backend-drm-14.0.2-r10.apk",
        "weston-clients-14.0.2-r10.apk",
        "weston-shell-desktop-14.0.2-r10.apk",
        "weston-terminal-14.0.2-r10.apk",
    )
    package_lines = (
        "device-xiaomi-lmi-1-r139",
        "linux-xiaomi-lmi-4.19.325-r9",
        "weston-14.0.2-r10",
        "weston-backend-drm-14.0.2-r10",
        "weston-clients-14.0.2-r10",
        "weston-shell-desktop-14.0.2-r10",
        "weston-terminal-14.0.2-r10",
    )
    required_versions = {
        "device-xiaomi-lmi": "1-r139",
        "linux-xiaomi-lmi": "4.19.325-r9",
        "weston": "14.0.2-r10",
        "weston-backend-drm": "14.0.2-r10",
        "weston-clients": "14.0.2-r10",
        "weston-shell-desktop": "14.0.2-r10",
        "weston-terminal": "14.0.2-r10",
    }
    fixed_add = (
        "evtest,pd-mapper,pd-mapper-openrc,seatd,seatd-openrc,"
        "weston-backend-drm,weston-clients,weston-shell-desktop,weston-terminal"
    )
    ephemeral = "runtime-generated-test-password"

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "pmbootstrap-argv.jsonl"
        self.pmbootstrap_environment_log = self.root / "pmbootstrap-environment.json"
        self.pmbootstrap_entrypoint_log = self.root / "pmbootstrap-entrypoint.txt"
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

        self.pmaports = self.root / "staged-pmaports"
        self.pmaports.mkdir()
        (self.pmaports / "pmaports.cfg").write_text(
            "[pmaports]\nchannel = edge\nversion = 7\n"
        )
        (self.pmaports / ".gitignore").write_text("*.ignored\n")
        device_package = self.pmaports / "device/downstream/device-xiaomi-lmi"
        device_package.mkdir(parents=True)
        (device_package / "deviceinfo").write_text(
            'deviceinfo_codename="xiaomi-lmi"\n'
            'deviceinfo_arch="aarch64"\n'
            'deviceinfo_rootfs_image_sector_size="512"\n'
        )
        self._git("init", "-q", cwd=self.pmaports)
        self._git("config", "user.name", "LMI test", cwd=self.pmaports)
        self._git(
            "config", "user.email", "lmi-pmaports-test@example.invalid", cwd=self.pmaports
        )
        self._git("add", ".", cwd=self.pmaports)
        self._git("commit", "-q", "-m", "pinned pmaports base", cwd=self.pmaports)
        self.pmaports_commit = self._git("rev-parse", "HEAD", cwd=self.pmaports).strip()
        (device_package / "deviceinfo").write_text(
            'deviceinfo_codename="xiaomi-lmi"\n'
            'deviceinfo_arch="aarch64"\n'
            'deviceinfo_rootfs_image_sector_size="4096"\n'
        )
        (self.pmaports / ".lmi-p1-stage.json").write_text(
            json.dumps(
                {
                    "commit": self.pmaports_commit,
                    "device/downstream/device-xiaomi-lmi/deviceinfo": hashlib.sha256(
                        (device_package / "deviceinfo").read_bytes()
                    ).hexdigest(),
                }
            )
            + "\n"
        )

        self.d80 = self.root / "d80"
        self.d80.mkdir()
        self.replay_hashes: dict[str, str] = {}
        for index, name in enumerate(self.apk_names):
            path = self.d80 / name
            path.write_bytes(f"fixture-apk-{index}\n".encode())
            self.replay_hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest()

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
        self._git("init", "-q", cwd=self.source_repo)
        self._git("config", "user.name", "LMI test", cwd=self.source_repo)
        self._git(
            "config", "user.email", "lmi-source-test@example.invalid", cwd=self.source_repo
        )
        self._git("add", "files/lmi-p1", cwd=self.source_repo)
        self._git("commit", "-q", "-m", "source payload", cwd=self.source_repo)
        self.work = self.root / "candidate"
        self.source_commit = self._git("rev-parse", "HEAD", cwd=self.source_repo).strip()
        self.ctx = BuildContext(
            repo=self.source_repo,
            tag="lmi-p1-ssh-20260719-1",
            source_commit=self.source_commit,
            work=self.work,
            pmaports=self.pmaports,
            d80=self.d80,
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
                "LMI_FAKE_FINALIZER_COPY": str(self.finalizer_copy),
            },
            clear=False,
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.constants = mock.patch.multiple(
            build_module,
            _EXPECTED_PMBOOTSTRAP_COMMIT=self.fake_commit,
            _EXPECTED_PMAPORTS_COMMIT=self.pmaports_commit,
            _REPLAY_APK_HASHES=self.replay_hashes,
        )
        self.constants.start()
        self.addCleanup(self.constants.stop)

    @staticmethod
    def _git(*args: str, cwd: Path) -> str:
        completed = subprocess.run(
            ["git", *args], cwd=cwd, text=True, capture_output=True, check=True
        )
        return completed.stdout

    @staticmethod
    def _fake_pmbootstrap_source() -> str:
        return r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

args = sys.argv[1:]
log = Path(os.environ["LMI_FAKE_PMBOOTSTRAP_LOG"])
with log.open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(args) + "\n")

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
                if key.upper().startswith(("PYTHON", "GIT_"))
                or key.upper() in {"LD_LIBRARY_PATH", "LD_PRELOAD"}
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

def write_bootstrap_rootfs():
    db.parent.mkdir(parents=True, exist_ok=True)
    db.write_text(
        "P:device-xiaomi-lmi\nV:1-r107\n\n"
        "P:linux-xiaomi-lmi\nV:4.19.325-r8\n\n"
        "P:weston\nV:14.0.2-r8\n\n"
    )
    package_list.write_text(
        "device-xiaomi-lmi-1-r107\n"
        "linux-xiaomi-lmi-4.19.325-r8\n"
        "weston-14.0.2-r8\n"
    )
    world.parent.mkdir(parents=True, exist_ok=True)
    world.write_text("device-xiaomi-lmi\npostmarketos-ui-shelli\n")
    for key_root in (work / "config_apk_keys", rootfs / "etc/apk/keys"):
        key_root.mkdir(parents=True, exist_ok=True)
        (key_root / "pmos-current.rsa.pub").write_text("current-key\n")

def install_replay():
    lines = (
        "device-xiaomi-lmi-1-r139\n"
        "linux-xiaomi-lmi-4.19.325-r9\n"
        "weston-14.0.2-r10\n"
        "weston-backend-drm-14.0.2-r10\n"
        "weston-clients-14.0.2-r10\n"
        "weston-shell-desktop-14.0.2-r10\n"
        "weston-terminal-14.0.2-r10\n"
    )
    db.write_text(
        "P:device-xiaomi-lmi\nV:1-r139\n\n"
        "P:linux-xiaomi-lmi\nV:4.19.325-r9\n\n"
        "P:weston\nV:14.0.2-r10\n\n"
        "P:weston-backend-drm\nV:14.0.2-r10\n\n"
        "P:weston-clients\nV:14.0.2-r10\n\n"
        "P:weston-shell-desktop\nV:14.0.2-r10\n\n"
        "P:weston-terminal\nV:14.0.2-r10\n\n"
    )
    package_list.write_text(lines)
    world.write_text(
        "device-xiaomi-lmi\nlinux-xiaomi-lmi\npostmarketos-ui-shelli\n"
        "weston\nweston-backend-drm\nweston-clients\n"
        "weston-shell-desktop\nweston-terminal\n"
    )
    if os.environ.get("LMI_FAKE_CONFLICTING_WORLD") == "1":
        world.write_text(world.read_text().replace("weston\n", "weston=14.0.2-r8\n"))
    if os.environ.get("LMI_FAKE_TAGGED_WORLD") == "1":
        world.write_text(
            world.read_text().replace("weston\n", "weston@edge=14.0.2-r10\n")
        )

if action == "checksum" or action == "build" or action == "index":
    raise SystemExit(0)
if action == "install":
    if "--no-image" in rest:
        write_bootstrap_rootfs()
        repo = work / "packages/edge/aarch64"
        repo.mkdir(parents=True, exist_ok=True)
        (repo / "device-xiaomi-lmi-1-r107.apk").write_bytes(b"old-device")
        (repo / "linux-xiaomi-lmi-4.19.325-r8.apk").write_bytes(b"old-kernel")
        raise SystemExit(0)
    quarantine = work / "packages/bootstrap-quarantine"
    normal = work / "packages/edge/aarch64"
    expected = (
        quarantine / "device-xiaomi-lmi-1-r107.apk",
        quarantine / "linux-xiaomi-lmi-4.19.325-r8.apk",
    )
    if not all(path.is_file() for path in expected):
        print("old packages were not quarantined", file=sys.stderr)
        raise SystemExit(44)
    if any((normal / path.name).exists() for path in expected):
        print("old packages remain in normal repo", file=sys.stderr)
        raise SystemExit(45)
    if os.environ.get("LMI_FAKE_FAIL_FINAL_INSTALL") == "1":
        print("forced final install failure", file=sys.stderr)
        raise SystemExit(46)
    native_rootfs = work / "chroot_native/home/pmos/rootfs"
    native_rootfs.mkdir(parents=True, exist_ok=True)
    (native_rootfs / "xiaomi-lmi.img").write_bytes(b"combined-image")
    boot = rootfs / "boot"
    boot.mkdir(parents=True, exist_ok=True)
    (boot / "boot.img").write_bytes(b"android-boot")
    (boot / "vmlinuz").write_bytes(b"kernel")
    (boot / "initramfs").write_bytes(b"initramfs")
    (boot / "sm8250-xiaomi-lmi.dtb").write_bytes(b"dtb")
    (rootfs / "etc/fstab").write_text(
        "UUID=11111111-2222-3333-4444-555555555555 / ext4 defaults 0 0\n"
        "UUID=AAAA-BBBB /boot vfat nodev,nosuid,noexec 0 0\n"
    )
    if os.environ.get("LMI_FAKE_FINAL_INSTALL_BARE_WORLD") == "1":
        world.write_text(world.read_text().replace("weston=14.0.2-r10\n", "weston\n"))
    raise SystemExit(0)
if action == "chroot":
    inner = rest[rest.index("--") + 1:]
    if inner[:3] == ["apk", "--no-network", "add"]:
        if os.environ.get("LMI_FAKE_MUTATE_ON_PROBE") == "1":
            db.write_text("mutated-by-rejected-probe\n")
        print("ERROR: package has an UNTRUSTED signature", file=sys.stderr)
        raise SystemExit(2)
    if inner[:4] == ["apk", "--no-network", "--allow-untrusted", "add"]:
        install_replay()
        raise SystemExit(0)
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
            "world",
            "sudoers",
            "lmi-usb0.nmconnection",
            "90-lmi-usb0-takeover.conf",
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
        "xiaomi-lmi.img": work / "chroot_native/home/pmos/rootfs/xiaomi-lmi.img",
        "vmlinuz": rootfs / "boot/vmlinuz",
        "initramfs": rootfs / "boot/initramfs",
    }
    for name, target in export_targets.items():
        (export / name).symlink_to(target.resolve())
    dtbs = export / "dtbs"
    dtbs.mkdir()
    (dtbs / "sm8250-xiaomi-lmi.dtb").symlink_to(
        (rootfs / "boot/sm8250-xiaomi-lmi.dtb").resolve()
    )
    if os.environ.get("LMI_FAKE_EXPORT_EXTRA") == "1":
        (export / "unexpected.bin").symlink_to((rootfs / "boot/vmlinuz").resolve())
    if os.environ.get("LMI_FAKE_EXPORT_ESCAPE") == "1":
        (export / "boot.img").unlink()
        (export / "boot.img").symlink_to(Path("/etc/passwd"))
    if os.environ.get("LMI_FAKE_EXPORT_DANGLING") == "1":
        (export / "boot.img").unlink()
        (export / "boot.img").symlink_to((work / "missing-boot.img").resolve())
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

    def test_exact_two_pass_sequence_security_identity_and_exports(self):
        result = self._build()
        records = self._records()
        for record in records:
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
                self.fixed_add,
                "--password",
                self.ephemeral,
            ],
            tails,
        )
        raw_apk = [tail for tail in tails if tail and tail[0] == "chroot" and "apk" in tail]
        unsigned = [tail for tail in raw_apk if "--allow-untrusted" not in tail]
        trusted_exception = [tail for tail in raw_apk if "--allow-untrusted" in tail]
        self.assertEqual(len(unsigned), 1)
        self.assertEqual(len(trusted_exception), 1)
        for tail in unsigned + trusted_exception:
            self.assertIn("--no-network", tail)
            paths = [arg for arg in tail if arg.endswith(".apk")]
            self.assertEqual(len(paths), 7)
            self.assertEqual(
                {Path(path).name for path in paths}, set(self.apk_names)
            )
            self.assertTrue(all(path.startswith("/") for path in paths))
            self.assertTrue(
                all(path.startswith("/mnt/pmbootstrap/packages/replay/aarch64/") for path in paths)
            )
        allow_occurrences = sum(record.count("--allow-untrusted") for record in records)
        self.assertEqual(allow_occurrences, 1)
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

        quarantine = self.work / "work/packages/bootstrap-quarantine"
        self.assertEqual(
            {path.name for path in quarantine.iterdir()},
            {"device-xiaomi-lmi-1-r107.apk", "linux-xiaomi-lmi-4.19.325-r8.apk"},
        )
        config = (self.work / "config/pmbootstrap.cfg").read_text()
        for expected in (
            "device = xiaomi-lmi",
            "ui = shelli",
            "user = lmi",
            "ssh_keys = True",
            f"ssh_key_glob = {self.public_key.resolve()}",
            "service_manager = openrc",
            "extra_packages = none",
        ):
            self.assertIn(expected, config)

        for path in result.__dict__.values():
            self.assertTrue(path.is_absolute())
            self.assertTrue(path.exists(), path)
        self.assertTrue(result.dtb_dir.is_dir())
        materialized = (
            result.boot_img,
            result.userdata_img,
            result.vmlinuz,
            result.initramfs,
            *sorted(result.dtb_dir.iterdir()),
        )
        for output in materialized:
            self.assertTrue(output.is_file(), output)
            self.assertFalse(output.is_symlink(), output)
            self.assertEqual(output.stat().st_nlink, 1, output)
        packages = result.packages.read_text().splitlines()
        for required in self.package_lines:
            self.assertIn(required, packages)
        identity = dict(
            line.split("=", 1) for line in result.identity.read_text().splitlines()
        )
        manifest_sha = hashlib.sha256(result.packages.read_bytes()).hexdigest()
        expected_id = hashlib.sha256(
            b"\0".join(
                value.encode()
                for value in (
                    self.ctx.tag,
                    self.ctx.source_commit,
                    "AAAA-BBBB",
                    "11111111-2222-3333-4444-555555555555",
                    manifest_sha,
                )
            )
        ).hexdigest()
        self.assertEqual(identity["candidate_id"], expected_id)
        self.assertEqual(identity["boot_uuid"], "AAAA-BBBB")
        self.assertEqual(identity["root_uuid"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(identity["package_manifest_sha256"], manifest_sha)
        self.assertNotIn("boot_sha256", identity)
        self.assertNotIn("rootfs_sha256", identity)
        self.assertEqual((self.finalizer_copy / "lmi-release-identity").read_bytes(), result.identity.read_bytes())
        world = result.world.read_text().splitlines()
        pinned_world = {
            f"{name}={version}" for name, version in self.required_versions.items()
        }
        self.assertTrue(pinned_world.issubset(world))
        self.assertTrue(set(self.required_versions).isdisjoint(world))
        self.assertEqual(
            (self.finalizer_copy / "world").read_bytes(), result.world.read_bytes()
        )
        self.assertEqual(
            (self.finalizer_copy / "sudoers").read_bytes(),
            (PAYLOAD / "sudoers").read_bytes(),
        )
        self.assertEqual(
            (self.finalizer_copy / "lmi-usb0.nmconnection").read_bytes(),
            (PAYLOAD / "lmi-usb0.nmconnection").read_bytes(),
        )
        self.assertEqual(
            (self.finalizer_copy / "90-lmi-usb0-takeover.conf").read_bytes(),
            (PAYLOAD / "90-lmi-usb0-takeover.conf").read_bytes(),
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
            "lmi-p1-finalize=ok",
        ):
            self.assertIn(marker, finalizer)
        candidate_text = "\n".join(
            path.read_text(encoding="utf-8", errors="replace")
            for path in self.work.rglob("*")
            if path.is_file()
        )
        self.assertNotIn(self.ephemeral, candidate_text)
        self.assertIn("[REDACTED_EPHEMERAL_PASSWORD]", result.build_log.read_text())

    def test_rejected_unsigned_probe_must_not_change_installed_database(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_MUTATE_ON_PROBE": "1"}):
            with mock.patch.object(
                build_module.secrets, "token_urlsafe", return_value=self.ephemeral
            ):
                with self.assertRaisesRegex(GateError, "changed installed package database"):
                    build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_conflicting_replay_world_constraint_is_rejected(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_CONFLICTING_WORLD": "1"}):
            with self.assertRaisesRegex(GateError, "conflicting replay world constraint"):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_tagged_replay_world_constraint_is_rejected(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_TAGGED_WORLD": "1"}):
            with self.assertRaisesRegex(GateError, "conflicting replay world constraint"):
                build_candidate(self.ctx)
        self.assertEqual(self._tail(self._records()[-1]), ["shutdown"])

    def test_final_install_cannot_relax_pinned_world(self):
        with mock.patch.dict(os.environ, {"LMI_FAKE_FINAL_INSTALL_BARE_WORLD": "1"}):
            with self.assertRaisesRegex(GateError, "replay world constraint mismatch"):
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

    def test_dirty_source_repository_is_rejected_before_pmbootstrap(self):
        (self.source_repo / "untracked-build-input").write_text("dirty\n")
        with self.assertRaisesRegex(GateError, "repository is dirty"):
            build_candidate(self.ctx)
        self.assertFalse(self.log.exists())

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

    def test_staged_pmaports_head_must_match_manifest_commit(self):
        self._git("commit", "--allow-empty", "-q", "-m", "unexpected head", cwd=self.pmaports)
        with self.assertRaisesRegex(GateError, "pmaports stage HEAD mismatch"):
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
        original_copy = build_module._copy_pmaports

        def copy_then_tamper(source: Path, destination: Path) -> None:
            original_copy(source, destination)
            (destination / "copied-extra").write_text("unlisted after copy\n")

        with mock.patch.object(build_module, "_copy_pmaports", side_effect=copy_then_tamper):
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

    def test_pmbootstrap_runs_only_isolated_clone_with_python_env_sanitized(self):
        injected = {
            "PYTHONPATH": "/tmp/attacker-pythonpath",
            "PYTHONBREAKPOINT": "attacker.breakpoint",
            "PYTHONATTACKVECTOR": "must-not-reach-pmbootstrap",
            "LD_LIBRARY_PATH": "/tmp/attacker-native-library-path",
            "GIT_DIR": "/tmp/attacker-git-dir",
            "GIT_CONFIG_GLOBAL": "/tmp/attacker-global-gitconfig",
            "GIT_OPTIONAL_LOCKS": "0",
        }
        with mock.patch.dict(os.environ, injected, clear=False):
            self._build()
        self.assertEqual(
            json.loads(self.pmbootstrap_environment_log.read_text()),
            {
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0",
            },
        )
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
            call for call in runner.call_args_list if call.args[0][0] == "git"
        ]
        self.assertTrue(git_calls)
        for call in git_calls:
            argv = list(call.args[0])
            environment = call.kwargs.get("env")
            self.assertIsNotNone(environment, argv)
            self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")
            self.assertEqual(environment["GIT_CONFIG_GLOBAL"], os.devnull)
            self.assertEqual(environment["GIT_TERMINAL_PROMPT"], "0")
            self.assertNotIn("GIT_OPTIONAL_LOCKS", environment)
            configs = [
                argv[index + 1]
                for index, value in enumerate(argv[:-1])
                if value == "-c"
            ]
            safe = [value for value in configs if value.startswith("safe.directory=")]
            self.assertEqual(len(safe), 1, argv)
            self.assertIn(Path(safe[0].split("=", 1)[1]), allowed_repositories)
            self.assertIn("core.hooksPath=/dev/null", configs)

    def test_pmbootstrap_tree_with_checkout_filter_is_rejected(self):
        (self.fake_repo / ".gitattributes").write_text("*.py filter=evil\n")
        self._git("add", ".gitattributes", cwd=self.fake_repo)
        self._git("commit", "-q", "-m", "add checkout filter", cwd=self.fake_repo)
        filtered_commit = self._git(
            "rev-parse", "HEAD", cwd=self.fake_repo
        ).strip()
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


if __name__ == "__main__":
    unittest.main()
