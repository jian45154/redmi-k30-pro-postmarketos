"""Regression tests for the Claude Code PreToolUse flash gate."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import unittest


REPO = Path(__file__).resolve().parents[2]
HOOK = REPO / "scripts/hooks/claude_flash_gate.sh"


class ClaudeFlashGateTests(unittest.TestCase):
    def classify(self, command: str) -> dict[str, object] | None:
        payload = json.dumps({"tool_input": {"command": command}}).encode()
        env = {
            **os.environ,
            "CLAUDE_PROJECT_DIR": str(REPO),
            "LANG": "C",
            "LC_ALL": "C",
        }
        result = subprocess.run(
            [str(HOOK)],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(result.stderr, b"")
        if not result.stdout:
            return None
        return json.loads(result.stdout)

    def decision(self, command: str) -> str | None:
        result = self.classify(command)
        if result is None:
            return None
        return str(result["hookSpecificOutput"]["permissionDecision"])

    def test_only_canonical_governed_executor_commands_are_allowed(self) -> None:
        modes = (
            "--dry-run",
            "--preflight",
            "--authorize-session",
            "--execute",
            "--revoke-session",
        )
        for mode in modes:
            with self.subTest(mode=mode):
                self.assertEqual(
                    self.decision(
                        "scripts/72_stage_downstream_ssh_wifi_test.sh "
                        f"--stage ramboot {mode}"
                    ),
                    "allow",
                )
        self.assertEqual(
            self.decision(
                "/usr/bin/bash ./scripts/72_stage_downstream_ssh_wifi_test.sh "
                "--stage ramboot --preflight"
            ),
            "allow",
        )

    def test_executor_substrings_and_noncanonical_calls_are_not_elevated(self) -> None:
        commands = (
            "echo scripts/72_stage_downstream_ssh_wifi_test.sh",
            "scripts/72_stage_downstream_ssh_wifi_test.sh --dry-run",
            "VAR=x scripts/72_stage_downstream_ssh_wifi_test.sh "
            "--stage ramboot --execute",
            "scripts/72_stage_downstream_ssh_wifi_test.sh "
            "--stage ramboot --execute | tee result",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertIsNone(self.decision(command))

    def test_compound_executor_and_raw_fastboot_is_denied_before_allow(self) -> None:
        command = (
            "scripts/72_stage_downstream_ssh_wifi_test.sh "
            "--stage ramboot --execute; fastboot flash boot evil.img"
        )
        self.assertEqual(self.decision(command), "deny")

    def test_fastboot_options_before_state_change_verb_are_denied(self) -> None:
        commands = (
            "fastboot -s SERIAL flash userdata candidate.img",
            "/usr/bin/fastboot --slot all reboot",
            "fastboot.exe -s SERIAL boot candidate.img",
            "fastboot \\\n-s SERIAL flash userdata candidate.img",
            r"fastboot -s SERIAL fl\ash userdata candidate.img",
            "fa''stboot -s SERIAL flash userdata candidate.img",
            "fa$'st'boot -s SERIAL flash userdata candidate.img",
            r"fa$'\x73\x74'boot -s SERIAL flash userdata candidate.img",
            r"fa$'\c@'stboot -s SERIAL flash userdata candidate.img",
            r"fa$'\x00'stboot -s SERIAL flash userdata candidate.img",
            r"fa$'\400'stboot -s SERIAL flash userdata candidate.img",
            'fa$"st"boot -s SERIAL flash userdata candidate.img',
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), "deny")

    def test_dd_to_any_dev_path_is_denied(self) -> None:
        commands = (
            "dd if=image of=/dev/mapper/userdata",
            "/usr/bin/dd if=image of=/dev/disk/by-id/phone",
            "dd if=image of=/dev/mmcblk0",
            "dd \\\nif=image of=/dev/mmcblk0",
            r"d\d if=image of=/dev/mmcblk0",
            "d$'d' if=image of=/dev/mmcblk0",
            r"d$'\x64' if=image of=/dev/mmcblk0",
            r"d$'\c@'d if=image of=/dev/mmcblk0",
            r"d$'\400'd if=image of=/dev/mmcblk0",
        )
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.decision(command), "deny")

    def test_unrelated_commands_and_d114_entrypoints_keep_normal_flow(self) -> None:
        for command in (
            "git status --short",
            "python3 scripts/lmi_p2_d114/deploy_userdata.py preflight",
        ):
            with self.subTest(command=command):
                self.assertIsNone(self.decision(command))


if __name__ == "__main__":
    unittest.main()
