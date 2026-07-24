from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import shlex
import subprocess
import struct
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[2]
HELPER = REPO / "scripts/74_verify_lmi_ssh_full.sh"

STRICT_OPTIONS = {
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "GlobalKnownHostsFile=/dev/null",
    "UpdateHostKeys=no",
    "VerifyHostKeyDNS=no",
    "KnownHostsCommand=none",
    "PubkeyAuthentication=yes",
    "PreferredAuthentications=publickey",
    "PasswordAuthentication=no",
    "KbdInteractiveAuthentication=no",
    "GSSAPIAuthentication=no",
    "HostbasedAuthentication=no",
    "IdentitiesOnly=yes",
    "IdentityAgent=none",
    "NumberOfPasswordPrompts=0",
    "ForwardAgent=no",
    "ForwardX11=no",
    "PermitLocalCommand=no",
    "ControlMaster=no",
    "ControlPath=none",
    "ControlPersist=no",
}


FAKE_OPENSSH = r"""#!/usr/bin/python3
import hashlib
import json
import os
from pathlib import Path
import signal
import sys


tool = Path(sys.argv[0]).name
argv = sys.argv[1:]
log_path = Path(os.environ["LMI_SSH_HELPER_LOG"])
payload_path = Path(os.environ["LMI_SSH_HELPER_PAYLOAD"])
failure = os.environ.get("LMI_SSH_HELPER_FAIL", "")


def record(**extra):
    value = {"tool": tool, "argv": argv}
    value.update(extra)
    with log_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, sort_keys=True) + "\n")


if tool == "ssh":
    if argv == ["-V"]:
        record(stage="version")
        print(
            os.environ.get(
                "LMI_SSH_HELPER_VERSION",
                "OpenSSH_10.2p1 fixture",
            ),
            file=sys.stderr,
        )
        raise SystemExit(0)

    command = argv[-1]
    if "-N" in argv:
        stage = "forward"
    elif "-tt" in argv:
        stage = "pty"
    elif "sha256sum /etc/os-release" in command:
        stage = "file"
    else:
        stage = "command"
    record(stage=stage)
    if failure == stage:
        raise SystemExit(81)

    if stage == "command":
        if command != "printf '%s\\n' lmi-ssh-command-ok":
            raise SystemExit(82)
        method = "password" if failure == "auth-wrong-method" else "publickey"
        authentication = (
            'Authenticated to 172.16.42.1 ([172.16.42.1]:2222) '
            f'using "{method}".\n'
        )
        Path(argv[argv.index("-E") + 1]).write_text(
            authentication,
            encoding="utf-8",
        )
        print("lmi-ssh-command-ok")
    elif stage == "pty":
        if command != "test -t 0 && printf '%s\\n' lmi-ssh-pty-ok":
            raise SystemExit(83)
        sys.stdout.write("lmi-ssh-pty-ok\r\n")
    elif stage == "file":
        expected = (
            "test -f /etc/os-release && test -r /etc/os-release "
            "&& test ! -w /etc/os-release && sha256sum /etc/os-release"
        )
        if command != expected:
            raise SystemExit(84)
        digest = hashlib.sha256(payload_path.read_bytes()).hexdigest()
        print(digest + "  /etc/os-release")
        if failure == "hash-multiline":
            print("unexpected trailing output")
        elif failure == "hash-trailing-blank":
            print()
    else:
        position = argv.index("-L")
        forward = argv[position + 1]
        fields = forward.split(":")
        if (
            len(fields) != 4
            or fields[0] != "127.0.0.1"
            or fields[2] != "127.0.0.1"
        ):
            raise SystemExit(85)

        def stop(_number, _frame):
            raise SystemExit(0)

        signal.signal(signal.SIGTERM, stop)
        signal.signal(signal.SIGINT, stop)
        while True:
            signal.pause()
elif tool == "sftp":
    batch_path = Path(argv[argv.index("-b") + 1])
    batch = batch_path.read_text(encoding="utf-8")
    record(stage="sftp", batch=batch)
    if failure == "sftp":
        raise SystemExit(86)
    if batch != "ls -l /etc/os-release\n":
        raise SystemExit(87)
    if failure != "sftp-empty":
        print("-rw-r--r-- 1 root root 55 Jan 1 00:00 /etc/os-release")
elif tool == "scp":
    record(stage="scp")
    if failure == "scp":
        raise SystemExit(88)
    if argv[-2] != "lmi@172.16.42.1:/etc/os-release":
        raise SystemExit(89)
    if failure == "scp-legacy-trace":
        trace = (
            "Executing: program /usr/bin/ssh host 172.16.42.1, "
            "user lmi, command scp -f /etc/os-release"
        )
    else:
        trace = (
            "Executing: program /usr/bin/ssh host 172.16.42.1, "
            "user lmi, command sftp"
        )
    print(trace, file=sys.stderr)
    payload = payload_path.read_bytes()
    if failure == "hash-mismatch":
        payload += b"unexpected"
    Path(argv[-1]).write_bytes(payload)
else:
    raise SystemExit(90)
"""

FAKE_PYTHON_PROBE = r"""#!/usr/bin/python3
import os
import json
from pathlib import Path
import sys
import time

source = sys.stdin.read()
if len(sys.argv) == 3:
    if 'listener.bind(("127.0.0.1", port))' not in source:
        raise SystemExit(91)
elif len(sys.argv) == 4:
    if 'banner.startswith(b"SSH-2.0-")' not in source:
        raise SystemExit(92)
    log_path = Path(os.environ["LMI_SSH_HELPER_LOG"])
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        if log_path.exists() and any(
            json.loads(line).get("stage") == "forward"
            for line in log_path.read_text(encoding="utf-8").splitlines()
        ):
            break
        time.sleep(0.01)
    else:
        raise SystemExit(95)
    if os.environ.get("LMI_SSH_HELPER_FAIL") == "forward":
        raise SystemExit(93)
else:
    raise SystemExit(94)
"""


class SshFullHelperTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.log = self.root / "openssh.jsonl"
        self.payload = self.root / "os-release"
        self.payload.write_bytes(
            b'NAME="postmarketOS"\nID=postmarketos\nVERSION_ID="edge"\n'
        )
        self.identity = self.root / "id_ed25519"
        self.identity.write_text("fixture private key\n", encoding="utf-8")
        self.identity.chmod(0o600)
        self.known_hosts = self.root / "known_hosts"
        algorithm = b"ssh-ed25519"
        key = bytes(range(32))
        blob = (
            struct.pack(">I", len(algorithm))
            + algorithm
            + struct.pack(">I", len(key))
            + key
        )
        self.host_key = base64.b64encode(blob).decode("ascii")
        self.pin_line = (
            f"[172.16.42.1]:2222 ssh-ed25519 {self.host_key}\n"
        )
        self.known_hosts.write_text(
            self.pin_line,
            encoding="utf-8",
        )
        self.known_hosts.chmod(0o600)

        self.tools = self.root / "tools"
        self.tools.mkdir()
        for name in ("ssh", "sftp", "scp"):
            path = self.tools / name
            path.write_text(FAKE_OPENSSH, encoding="utf-8")
            path.chmod(0o755)
        python_probe = self.tools / "python-probe"
        python_probe.write_text(FAKE_PYTHON_PROBE, encoding="utf-8")
        python_probe.chmod(0o755)

        source = HELPER.read_text(encoding="utf-8")
        replacements = {
            "readonly SSH=/usr/bin/ssh": (
                f"readonly SSH={shlex.quote(str(self.tools / 'ssh'))}"
            ),
            "readonly SFTP=/usr/bin/sftp": (
                f"readonly SFTP={shlex.quote(str(self.tools / 'sftp'))}"
            ),
            "readonly SCP=/usr/bin/scp": (
                f"readonly SCP={shlex.quote(str(self.tools / 'scp'))}"
            ),
            "readonly PYTHON=/usr/bin/python3": (
                f"readonly PYTHON={shlex.quote(str(python_probe))}"
            ),
            "readonly FORWARD_TIMEOUT_SECONDS=10": (
                "readonly FORWARD_TIMEOUT_SECONDS=1"
            ),
        }
        for old, new in replacements.items():
            self.assertEqual(source.count(old), 1)
            source = source.replace(old, new)
        self.helper = self.root / "74_verify_lmi_ssh_full.sh"
        self.helper.write_text(source, encoding="utf-8")
        self.helper.chmod(0o755)

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "LMI_SSH_HELPER_LOG": str(self.log),
                "LMI_SSH_HELPER_PAYLOAD": str(self.payload),
            }
        )

    def arguments(self) -> list[str]:
        return [
            "--host",
            "172.16.42.1",
            "--port",
            "2222",
            "--user",
            "lmi",
            "--identity-file",
            str(self.identity),
            "--known-hosts",
            str(self.known_hosts),
            "--local-forward-port",
            "40222",
        ]

    def run_helper(
        self,
        *extra: str,
        failure: str | None = None,
        version: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        environment = self.environment.copy()
        if failure is not None:
            environment["LMI_SSH_HELPER_FAIL"] = failure
        if version is not None:
            environment["LMI_SSH_HELPER_VERSION"] = version
        return subprocess.run(
            [str(self.helper), *self.arguments(), *extra],
            text=True,
            capture_output=True,
            env=environment,
            timeout=15,
            check=False,
        )

    def calls(self) -> list[dict[str, object]]:
        if not self.log.exists():
            return []
        return [
            json.loads(line)
            for line in self.log.read_text(encoding="utf-8").splitlines()
        ]

    def assert_strict_policy(self, argv: list[str]) -> None:
        self.assertIn("-F", argv)
        self.assertEqual(argv[argv.index("-F") + 1], "/dev/null")
        options = {
            argv[index + 1]
            for index, argument in enumerate(argv[:-1])
            if argument == "-o"
        }
        self.assertTrue(STRICT_OPTIONS <= options)
        self.assertIn(
            f"UserKnownHostsFile={self.known_hosts}",
            options,
        )
        self.assertIn("-i", argv)
        self.assertEqual(argv[argv.index("-i") + 1], str(self.identity))

    def test_source_is_syntax_valid_and_contains_no_state_changing_clients(self) -> None:
        syntax = subprocess.run(
            ["/usr/bin/bash", "-n", str(HELPER)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)
        source = HELPER.read_text(encoding="utf-8")
        for prohibited in (
            "/fastboot",
            "/sudo",
            "/systemctl",
            "/rc-service",
            "/reboot",
            "/shutdown",
            "/poweroff",
        ):
            self.assertNotIn(prohibited, source)
        self.assertIn("readonly REMOTE_FILE=/etc/os-release", source)

    def test_complete_suite_uses_only_pinned_noninteractive_public_key_auth(
        self,
    ) -> None:
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                "PASS remote-command",
                "PASS pty",
                "PASS sftp-metadata",
                "PASS scp-sftp-download",
                "PASS local-tcp-forward",
                (
                    "accepted: SSH protocol suite passed with no explicit "
                    "remote mutation"
                ),
            ],
        )

        calls = self.calls()
        self.assertEqual(
            [call["stage"] for call in calls],
            ["version", "command", "pty", "file", "sftp", "scp", "forward"],
        )
        for call in calls[1:]:
            self.assert_strict_policy(call["argv"])

        by_stage = {call["stage"]: call["argv"] for call in calls}
        self.assertIn("-v", by_stage["command"])
        self.assertIn("-T", by_stage["command"])
        self.assertIn("-tt", by_stage["pty"])
        self.assertEqual(calls[4]["batch"], "ls -l /etc/os-release\n")
        self.assertNotIn("-O", by_stage["scp"])
        self.assertIn("-v", by_stage["scp"])
        self.assertEqual(
            by_stage["scp"][-2],
            "lmi@172.16.42.1:/etc/os-release",
        )
        self.assertIn("-N", by_stage["forward"])
        self.assertIn("-T", by_stage["forward"])
        forward = by_stage["forward"][by_stage["forward"].index("-L") + 1]
        self.assertRegex(forward, r"^127\.0\.0\.1:[0-9]+:127\.0\.0\.1:2222$")

    def test_each_protocol_check_fails_closed(self) -> None:
        for stage in ("command", "pty", "file", "sftp", "scp", "forward"):
            with self.subTest(stage=stage):
                self.log.unlink(missing_ok=True)
                result = self.run_helper(failure=stage)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("accepted:", result.stdout)
                observed = [call["stage"] for call in self.calls()]
                self.assertIn(stage, observed)

    def test_hash_listing_and_download_evidence_fail_closed(self) -> None:
        expected_stage = {
            "auth-wrong-method": "command",
            "hash-multiline": "file",
            "hash-trailing-blank": "file",
            "sftp-empty": "sftp",
            "hash-mismatch": "scp",
            "scp-legacy-trace": "scp",
        }
        for failure, stage in expected_stage.items():
            with self.subTest(failure=failure):
                self.log.unlink(missing_ok=True)
                result = self.run_helper(failure=failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("accepted:", result.stdout)
                observed = [call["stage"] for call in self.calls()]
                self.assertIn(stage, observed)

    def test_insecure_or_implicit_inputs_are_rejected_before_connection(
        self,
    ) -> None:
        self.identity.chmod(0o644)
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "private key must not grant group or other permissions",
            result.stderr,
        )
        self.assertEqual(self.calls(), [])

        help_result = subprocess.run(
            [str(self.helper), "--help"],
            text=True,
            capture_output=True,
            env=self.environment,
            timeout=5,
            check=False,
        )
        self.assertEqual(help_result.returncode, 0)
        self.assertEqual(self.calls(), [])

        missing = subprocess.run(
            [str(self.helper)],
            text=True,
            capture_output=True,
            env=self.environment,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(missing.returncode, 0)
        self.assertEqual(self.calls(), [])

    def test_user_must_be_exactly_lmi_before_connection(self) -> None:
        arguments = self.arguments()
        arguments[arguments.index("--user") + 1] = "operator"
        result = subprocess.run(
            [str(self.helper), *arguments],
            text=True,
            capture_output=True,
            env=self.environment,
            timeout=5,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--user must be exactly lmi", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_known_hosts_requires_one_exact_plain_ed25519_host_port_pin(
        self,
    ) -> None:
        invalid = {
            "wildcard": f"*.16.42.1 ssh-ed25519 {self.host_key}\n",
            "certificate-authority": (
                "@cert-authority [172.16.42.1]:2222 "
                f"ssh-ed25519 {self.host_key}\n"
            ),
            "multiple": self.pin_line + self.pin_line,
            "comment": self.pin_line.rstrip("\n") + " comment\n",
            "wrong-port": (
                f"[172.16.42.1]:22 ssh-ed25519 {self.host_key}\n"
            ),
            "wrong-algorithm": (
                f"[172.16.42.1]:2222 ssh-rsa {self.host_key}\n"
            ),
            "malformed-key": (
                "[172.16.42.1]:2222 ssh-ed25519 AAAA\n"
            ),
        }
        for label, value in invalid.items():
            with self.subTest(label=label):
                self.log.unlink(missing_ok=True)
                self.known_hosts.write_text(value, encoding="utf-8")
                self.known_hosts.chmod(0o600)
                result = self.run_helper()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "exactly one plain ED25519 pin for HOST and PORT",
                    result.stderr,
                )
                self.assertEqual(self.calls(), [])

    def test_old_or_invalid_openssh_version_is_rejected_before_connection(
        self,
    ) -> None:
        for version in ("OpenSSH_8.9p1 fixture", "not-an-openssh-client"):
            with self.subTest(version=version):
                self.log.unlink(missing_ok=True)
                result = self.run_helper(version=version)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("accepted:", result.stdout)
                self.assertEqual(
                    [call["stage"] for call in self.calls()],
                    ["version"],
                )

    def test_unknown_skip_flag_is_rejected(self) -> None:
        result = self.run_helper("--skip-sftp")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown argument: --skip-sftp", result.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == "__main__":
    unittest.main()
