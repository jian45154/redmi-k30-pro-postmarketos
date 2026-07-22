from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
from dataclasses import dataclass
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import scripts.lmi_p1_cli as cli


REPO = Path(__file__).resolve().parents[2]

_ATTESTATION = REPO / "config/lmi-p1/offline-cache-promotion-attestation.json"
_ATTESTED_RUNTIME = json.loads(_ATTESTATION.read_bytes())["runtime_trust"][
    "python_major_minor"
]
_RUNTIME_MATCHES_ATTESTATION = (
    sys.implementation.name == "cpython"
    and f"{sys.version_info.major}.{sys.version_info.minor}" == _ATTESTED_RUNTIME
)
_FOREIGN_RUNTIME_REASON = (
    f"reviewed promotion attestation binds CPython {_ATTESTED_RUNTIME}; "
    "the promotion trust gate fails closed on other interpreters"
)


@dataclass(frozen=True)
class _VerifiedResult:
    root: Path
    manifest: dict[str, str]
    manifest_sha256: str
    aggregate_sha256: str


class OfflineCacheCliTests(unittest.TestCase):
    def test_cli_derives_one_reviewed_attestation_from_executing_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile = object()
            authorization = SimpleNamespace(profile=profile)
            verified = _VerifiedResult(
                root=root / "published",
                manifest={"schema": "lmi-p1-offline-cache/v2"},
                manifest_sha256="a" * 64,
                aggregate_sha256="b" * 64,
            )
            argv = [
                "promote-offline-cache",
                "--acquisition", str(root / "acquisition"),
                "--quarantine", str(root / "cache.quarantine"),
                "--published", str(root / "cache"),
                "--trusted-pmbootstrap", str(root / "pmbootstrap"),
            ]
            output = io.StringIO()
            with (
                mock.patch.object(
                    cli, "load_promotion_authorization", return_value=authorization
                ) as load,
                mock.patch.object(
                    cli, "promote_offline_cache", return_value=verified
                ) as promote,
                redirect_stdout(output),
            ):
                self.assertEqual(cli.main(argv), 0)

            load.assert_called_once_with()
            args = promote.call_args
            self.assertEqual(
                args.args,
                (
                    root / "acquisition",
                    root / "cache.quarantine",
                    root / "cache",
                    profile,
                ),
            )
            self.assertEqual(args.kwargs["trusted_key_root"], root / "pmbootstrap")
            self.assertIs(args.kwargs["authorization"], authorization)
            rendered = json.loads(output.getvalue())
            self.assertEqual(rendered["root"], str(root / "published"))
            self.assertEqual(rendered["manifest_sha256"], "a" * 64)

    def test_cli_rejects_caller_supplied_bootstrap_pins(self) -> None:
        argv = [
            "promote-offline-cache",
            "--attestation", "/tmp/attestation.json",
            "--acquisition", "/tmp/acquisition",
            "--quarantine", "/tmp/quarantine",
            "--published", "/tmp/published",
            "--trusted-pmbootstrap", "/tmp/pmbootstrap",
            "--openssl-path", "/usr/bin/openssl",
            "--openssl-size", "1132128",
            "--openssl-sha256", "c" * 64,
            "--openssl-version", "3.5.5",
            "--apk-static-size", "5462696",
            "--apk-static-sha256", "d" * 64,
            "--apk-static-version", "3.0.6-r0",
        ]
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            cli.main(argv)
        self.assertEqual(error.exception.code, 2)

    @unittest.skipUnless(_RUNTIME_MATCHES_ATTESTATION, _FOREIGN_RUNTIME_REASON)
    def test_clean_process_loads_exact_attested_lazy_promotion_tcb(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            result = subprocess.run(
                [
                    sys.executable,
                    str(REPO / "scripts/lmi_p1_cli.py"),
                    "promote-offline-cache",
                    "--acquisition",
                    str(root / "missing-acquisition"),
                    "--quarantine",
                    str(root / "quarantine"),
                    "--published",
                    str(root / "published"),
                    "--trusted-pmbootstrap",
                    str(root / "missing-pmbootstrap"),
                ],
                cwd=REPO,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 1)
        self.assertIn("could not inspect acquisition root", result.stderr)
        self.assertNotIn("producer code", result.stderr)


if __name__ == "__main__":
    unittest.main()
