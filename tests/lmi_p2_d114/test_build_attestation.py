from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


REPO = Path(__file__).resolve().parents[2]
ATTESTATION = REPO / "config/lmi-p2-d114/apk-build-attestation.json"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class BuildAttestationTests(unittest.TestCase):
    def test_attestation_binds_tracked_inputs_key_and_two_saved_runs(self) -> None:
        value = json.loads(ATTESTATION.read_text(encoding="utf-8"))
        self.assertEqual(value["schema"], "lmi-p2-d114-apk-build-attestation/v1")
        self.assertEqual(value["status"], "private-d114-hardware-test-candidate")
        self.assertFalse(value["security_boundaries"]["release_eligible"])
        self.assertFalse(value["security_boundaries"]["rootfs_injection_completed"])

        for path_field, digest_field in (
            ("source_lock_path", "source_lock_sha256"),
            ("generated_overlay_path", "generated_overlay_sha256"),
        ):
            path = REPO / value["inputs"][path_field]
            self.assertEqual(sha256(path), value["inputs"][digest_field])

        public_key = REPO / value["signature"]["public_key_path"]
        self.assertEqual(sha256(public_key), value["signature"]["public_key_sha256"])
        self.assertEqual(value["signature"]["verification"], "OK")

        runs = value["reproducibility"]["runs"]
        self.assertEqual(len(runs), 2)
        self.assertTrue(value["reproducibility"]["byte_identical"])
        self.assertEqual(runs[0]["sha256"], runs[1]["sha256"])
        self.assertEqual(runs[0]["size"], runs[1]["size"])
        self.assertEqual(runs[0]["sha256"], value["artifact"]["apk_sha256"])
        self.assertEqual(runs[0]["size"], value["artifact"]["apk_size"])
        for run in runs:
            self.assertTrue(run["signature_verified"])
            artifact = REPO / run["path"]
            if artifact.exists():
                self.assertEqual(artifact.stat().st_size, run["size"])
                self.assertEqual(sha256(artifact), run["sha256"])


if __name__ == "__main__":
    unittest.main()
