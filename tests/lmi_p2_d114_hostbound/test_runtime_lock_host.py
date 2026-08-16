"""Bind the tracked WSL runtime lock to the real maintainer host.

Public CI runs the portable accept-path tests in ``tests/lmi_p2_d114``
against a synthetic host derived from the lock.  This suite keeps the other
half of the guard: the captured lock must still describe *this* host before
the deploy toolchain is trusted.  See README.md in this directory.
"""

from __future__ import annotations

import json
import unittest

from tests.lmi_p2_d114 import host_bound
from unittest import mock

from scripts.lmi_p2_d114 import deploy_userdata_wsl as deploy
from scripts.lmi_p2_d114 import postwrite_revalidate_wsl as postwrite


class RuntimeLockHostBindingTests(unittest.TestCase):
    def _runtime(self) -> dict[str, object]:
        host_bound.require_path("/usr/bin/fastboot")
        return json.loads(
            (deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text()
        )

    def test_current_host_matches_lock_and_accepts_without_device_command(self) -> None:
        runtime = self._runtime()
        calls: list[tuple[str, ...]] = []

        def runtime_only_runner(
            argv: tuple[str, ...] | list[str],
            timeout: int,
            pass_fds: tuple[int, ...],
            environment: dict[str, str],
        ) -> deploy.CommandResult:
            command = tuple(argv)
            self.assertNotIn("devices", command)
            self.assertFalse(any(value.startswith("getvar:") for value in command))
            self.assertNotIn("flash", command)
            calls.append(command)
            return deploy.run_bounded(command, timeout, pass_fds, environment)

        prefix, held = deploy._validate_runtime(runtime, runtime_only_runner)
        try:
            self.assertEqual(prefix[0], "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
            self.assertEqual([command[-1] for command in calls], ["--version", "fastboot"])
        finally:
            for item in reversed(held):
                item.close()

    def test_current_host_combines_with_static_postwrite_runner(self) -> None:
        runtime = self._runtime()
        with mock.patch.object(
            postwrite,
            "_static_runtime_runner",
            wraps=postwrite._static_runtime_runner,
        ) as runner:
            prefix, held = deploy._validate_runtime(runtime, runner)
        try:
            self.assertEqual(prefix, tuple(runtime["execution"]["argv_prefix"]))
            self.assertEqual(len(runner.call_args_list), 2)
            for call in runner.call_args_list:
                command = tuple(call.args[0])
                self.assertNotIn("devices", command)
                self.assertFalse(any(value.startswith("getvar:") for value in command))
                self.assertNotIn("flash", command)
        finally:
            for item in reversed(held):
                item.close()


if __name__ == "__main__":
    unittest.main()
