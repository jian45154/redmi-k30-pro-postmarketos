import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts.lmi_p1.common import GateError, run, sha256_file, write_json


class CommonTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def test_sha256_file_streams_exact_bytes(self):
        payload = (b"lmi-p1\x00" * 200_000) + b"tail"
        path = self.root / "payload.bin"
        path.write_bytes(payload)

        self.assertEqual(sha256_file(path), hashlib.sha256(payload).hexdigest())

    def test_write_json_sorts_keys_and_atomically_replaces_destination(self):
        path = self.root / "result.json"
        with mock.patch(
            "scripts.lmi_p1.common.os.replace", wraps=os.replace
        ) as replace:
            write_json(path, {"z": 1, "a": {"d": 4, "b": 2}})

        self.assertEqual(
            path.read_text(encoding="utf-8"),
            '{\n  "a": {\n    "b": 2,\n    "d": 4\n  },\n  "z": 1\n}\n',
        )
        replace.assert_called_once()
        temporary, destination = map(Path, replace.call_args.args)
        self.assertEqual(temporary.parent, path.parent)
        self.assertNotEqual(temporary, path)
        self.assertEqual(destination, path)
        self.assertFalse(temporary.exists())

    def test_run_passes_an_argv_list_and_never_requests_a_shell(self):
        completed = subprocess.CompletedProcess(
            ["example", "literal;argument"], 0, "stdout", "stderr"
        )
        cwd = self.root / "cwd"
        environment = {"EXAMPLE": "value"}
        with mock.patch(
            "scripts.lmi_p1.common.subprocess.run", return_value=completed
        ) as subprocess_run:
            result = run(
                ("example", "literal;argument"),
                timeout=17,
                cwd=cwd,
                env=environment,
            )

        self.assertIs(result, completed)
        subprocess_run.assert_called_once_with(
            ["example", "literal;argument"],
            text=True,
            capture_output=True,
            timeout=17,
            cwd=cwd,
            env=environment,
            check=False,
        )

    def test_run_converts_timeout_to_gate_error(self):
        with self.assertRaisesRegex(GateError, "timed out after 1 seconds"):
            run(
                [sys.executable, "-c", "import time; time.sleep(5)"],
                timeout=1,
            )

    def test_run_redacts_tokens_private_keys_and_device_serial(self):
        classic_token = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"
        fine_grained_token = (
            "github_pat_11ABCDEFGHIJKLMNOP_0123456789abcdefghijklmnopqrstuv"
        )
        private_key = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "private-key-material\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        serial = "8336ded7"
        stdout = f"classic={classic_token}\n{private_key}\nserial={serial}\n"
        stderr = f"fine={fine_grained_token}\nserial={serial}\n"
        code = (
            "import sys; "
            f"sys.stdout.write({stdout!r}); "
            f"sys.stderr.write({stderr!r}); "
            "raise SystemExit(7)"
        )

        with self.assertRaises(GateError) as raised:
            run([sys.executable, "-c", code], timeout=5)

        message = str(raised.exception)
        for secret in (
            classic_token,
            fine_grained_token,
            private_key,
            "private-key-material",
            serial,
        ):
            self.assertNotIn(secret, message)
        self.assertIn("[REDACTED_GITHUB_TOKEN]", message)
        self.assertIn("[REDACTED_PRIVATE_KEY]", message)
        self.assertIn("[REDACTED_DEVICE_SERIAL]", message)
        self.assertIn("exit status 7", message)

    def test_run_returns_nonzero_process_when_check_is_false(self):
        result = run(
            [sys.executable, "-c", "raise SystemExit(9)"],
            timeout=5,
            check=False,
        )

        self.assertEqual(result.returncode, 9)


if __name__ == "__main__":
    unittest.main()
