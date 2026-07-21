from __future__ import annotations

import json
import os
import unittest
from pathlib import Path

from scripts.lmi_weston_sixrow import verify


class SixRowStaticTests(unittest.TestCase):
    def test_locked_recipe_and_unique_install_paths(self) -> None:
        verify.verify_recipe()

    def test_build_attestation_and_apk_payload_when_present(self) -> None:
        attestation = json.loads(
            verify.BUILD_ATTESTATION_PATH.read_text(encoding="utf-8")
        )
        artifact = verify.REPO / attestation["artifact"]["path"]
        if not artifact.exists():
            self.skipTest("attested local APK is not present")
        self.assertTrue(verify.verify_build_attestation(require_artifact=True))

    def test_layout_and_ctrl_are_present_in_locked_patches(self) -> None:
        verify.verify_patch_contract()

    def test_official_tarball_patch_dry_run_and_source_contract(self) -> None:
        value = os.environ.get("LMI_WESTON_14_0_2_TARBALL")
        if not value:
            self.skipTest("set LMI_WESTON_14_0_2_TARBALL for exact patch dry-run")
        verify.verify_tarball(Path(value))


if __name__ == "__main__":
    unittest.main()
