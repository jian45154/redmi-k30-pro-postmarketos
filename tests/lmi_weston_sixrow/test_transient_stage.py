from __future__ import annotations

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.lmi_weston_sixrow import stage_transient as transient


class SixRowTransientStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.artifact = (
            transient.REPO
            / ".work/pmbootstrap-sixrow/packages/edge/aarch64/"
            "lmi-weston-sixrow-clients-14.0.2-r1.apk"
        )

    def _render_components(self) -> tuple[str, str, str, str]:
        config = transient.render_config()
        config_sha256 = transient.digest_bytes(config.encode("utf-8"))
        candidate = transient.replace_exact(
            transient.render_session("candidate"),
            "@CONFIG_SHA256@",
            config_sha256,
        )
        fallback = transient.render_session("fallback")
        supervisor = transient._render_supervisor(
            candidate_session_sha256=transient.digest_bytes(
                candidate.encode("utf-8")
            ),
            fallback_session_sha256=transient.digest_bytes(
                fallback.encode("utf-8")
            ),
            config_sha256=config_sha256,
        )
        return config, candidate, fallback, supervisor

    def assertShellSyntax(self, script: str) -> None:
        result = subprocess.run(
            ["sh", "-n"],
            input=script,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_rendered_sessions_are_tmp_scoped_and_identity_bound(self) -> None:
        _config, candidate, fallback, _supervisor = self._render_components()
        self.assertShellSyntax(candidate)
        self.assertShellSyntax(fallback)

        for script in (candidate, fallback):
            self.assertIn("export HISTFILE=/dev/null", script)
            self.assertIn("unset LD_PRELOAD LD_LIBRARY_PATH ENV BASH_ENV", script)
            self.assertIn('cd "$HOME"', script)
            self.assertIn("process_starttime()", script)
            self.assertIn("process_identity_full()", script)
            self.assertIn("publish_ready()", script)
            self.assertIn("release_ready()", script)
            self.assertIn("keyboard_starttime=$(process_starttime", script)
            self.assertIn("core_child_valid", script)
            self.assertIn('kill -TERM "$stop_pid"', script)
            self.assertIn('kill -KILL "$stop_pid"', script)
            self.assertIn('"$stop_starttime"', script)
            self.assertNotIn("state_dir=$HOME/.local", script)
            self.assertNotIn("> /home/", script)
            self.assertNotIn("mkdir -p /home/", script)
            weston_pid = script.index("weston_pid=$!")
            weston_start = script.index(
                'weston_starttime=$(process_starttime "$weston_pid")', weston_pid
            )
            socket_wait = script.index("socket_ready=0", weston_start)
            self.assertLess(weston_pid, weston_start)
            self.assertLess(weston_start, socket_wait)
            terminal_pid = script.index("terminal_pid=$!")
            terminal_start = script.index(
                'terminal_starttime=$(process_starttime "$terminal_pid")', terminal_pid
            )
            terminal_wait = script.index(
                'wait_for_core_child "$terminal_pid"', terminal_start
            )
            ready_publish = script.index("publish_ready ||", terminal_wait)
            self.assertLess(terminal_pid, terminal_start)
            self.assertLess(terminal_start, terminal_wait)
            self.assertLess(terminal_wait, ready_publish)

        self.assertIn("export HOME=$stage/home", candidate)
        self.assertIn("export XDG_STATE_HOME=$stage/state", candidate)
        self.assertIn("wayland-lmi-sixrow-r1", candidate)
        self.assertIn(
            f"{transient.REMOTE_ROOT}/weston-keyboard-sixrow", candidate
        )
        self.assertIn("export HOME=$stage/stock-home", fallback)
        self.assertIn("export XDG_STATE_HOME=$stage/stock-state", fallback)
        self.assertIn("wayland-lmi-p2-d114", fallback)
        self.assertIn("/usr/libexec/weston-keyboard", fallback)
        self.assertIn("/usr/bin/weston-terminal", fallback)

        self.assertEqual(
            transient.FROZEN_STOCK_SESSION,
            transient.FILES / "frozen-d114-r1-stock-session",
        )
        self.assertEqual(
            transient.FROZEN_STOCK_CONFIG,
            transient.FILES / "frozen-d114-r1-stock-weston.ini",
        )
        self.assertEqual(
            transient.digest(transient.FROZEN_STOCK_SESSION),
            transient.FROZEN_STOCK_SESSION_SHA256,
        )
        self.assertEqual(
            transient.digest(transient.FROZEN_STOCK_CONFIG),
            transient.FROZEN_STOCK_CONFIG_SHA256,
        )
        self.assertNotIn("files/lmi-p2-d114", str(transient.FROZEN_STOCK_SESSION))
        self.assertNotIn("files/lmi-p2-d114", str(transient.FROZEN_STOCK_CONFIG))

    def test_supervisor_has_bounded_atomic_handoff_and_positive_restore(self) -> None:
        _config, _candidate, _fallback, supervisor = self._render_components()
        self.assertShellSyntax(supervisor)
        disabled = subprocess.run(
            ["sh"],
            input=supervisor,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(disabled.returncode, 125)
        self.assertIn("NO-GO; execution disabled", disabled.stderr)
        required = (
            "trial_ticks=600",
            "stable_ticks=60",
            "restore_stable_ticks=60",
            "session_ready_ticks=350",
            "acquire_takeover_lock()",
            "validate_script_runner_identity()",
            "validate_script_runner_full()",
            "process_starttime()",
            "stock identity changed before signal",
            "candidate identity changed during trial",
            "stock-restored-and-stable",
            "manual-recovery-required-stock-restore-failed",
            "/usr/bin/setsid /bin/sh \"$fallback_session\" &",
            "set -C",
            'mv "$status_tmp" "$status_file"',
            "unset LD_PRELOAD LD_LIBRARY_PATH ENV BASH_ENV",
            "validate_root_regular /usr/bin/setsid 755",
            "validate_ready_file()",
            "$stage/candidate-ready",
            "$stage/stock-ready",
        )
        for token in required:
            self.assertIn(token, supervisor)

        acquire = supervisor.index("acquire_takeover_lock ||")
        revalidate = supervisor.index("stock identity changed before signal")
        stock_signal = supervisor.index('kill -TERM "$stock_pid"')
        self.assertLess(acquire, revalidate)
        self.assertLess(revalidate, stock_signal)
        restore_status = supervisor.index("stock-restored-and-stable")
        release = supervisor.index("release_takeover_lock ||", restore_status)
        self.assertLess(restore_status, release)

        for forbidden in (
            "rm -rf",
            "apk add",
            "apk fix",
            "fastboot",
            "pmbootstrap",
            "rc-service",
            "rc-update",
            "reboot",
            "flash ",
            "exec /bin/sh \"$fallback_session\"",
        ):
            self.assertNotIn(forbidden, supervisor)

    def test_status_update_replaces_symlink_without_touching_target(self) -> None:
        _config, _candidate, _fallback, supervisor = self._render_components()
        function_start = supervisor.index("sha256_of() {")
        function_end = supervisor.index("validate_script_runner_identity() {")
        functions = supervisor[function_start:function_end]
        with tempfile.TemporaryDirectory(prefix="lmi-sixrow-status-test-") as temp:
            root = Path(temp)
            stage = root / "stage"
            stage.mkdir(mode=0o700)
            victim = root / "victim"
            victim.write_text("unchanged\n", encoding="utf-8")
            status = stage / "status"
            status.symlink_to(victim)
            functions = functions.replace(
                '[ "$(stat -c %u "$directory")" = 10000 ]',
                f'[ "$(stat -c %u "$directory")" = {os.getuid()} ]',
            ).replace(
                '[ "$(stat -c %g "$directory")" = 10000 ]',
                f'[ "$(stat -c %g "$directory")" = {os.getgid()} ]',
            ).replace(
                '[ "$(stat -c %u "$status_file")" = 10000 ]',
                f'[ "$(stat -c %u "$status_file")" = {os.getuid()} ]',
            ).replace(
                '[ "$(stat -c %g "$status_file")" = 10000 ]',
                f'[ "$(stat -c %g "$status_file")" = {os.getgid()} ]',
            ).replace(
                '[ "$(stat -c %u "$status_tmp")" = 10000 ]',
                f'[ "$(stat -c %u "$status_tmp")" = {os.getuid()} ]',
            ).replace(
                '[ "$(stat -c %g "$status_tmp")" = 10000 ]',
                f'[ "$(stat -c %g "$status_tmp")" = {os.getgid()} ]',
            )
            harness = (
                "set -eu\n"
                f"stage={shlex.quote(str(stage))}\n"
                f"status_file={shlex.quote(str(status))}\n"
                + functions
                + '\nwrite_status "safe-update"\n'
            )
            result = subprocess.run(
                ["sh"],
                input=harness,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(victim.read_text(encoding="utf-8"), "unchanged\n")
            self.assertFalse(status.is_symlink())
            self.assertEqual(status.read_text(encoding="utf-8"), "safe-update\n")

    def test_takeover_lock_acquisition_is_atomic(self) -> None:
        _config, _candidate, _fallback, supervisor = self._render_components()
        function_start = supervisor.index("sha256_of() {")
        function_end = supervisor.index("release_takeover_lock() {")
        functions = supervisor[function_start:function_end]
        with tempfile.TemporaryDirectory(prefix="lmi-sixrow-lock-test-") as temp:
            lock = Path(temp) / "takeover.lock"
            harness = (
                "set -eu\n"
                f"takeover_lock={shlex.quote(str(lock))}\n"
                "takeover_lock_owned=0\n"
                "own_starttime=123\n"
                + functions
                + "\nacquire_takeover_lock\n"
                + "if acquire_takeover_lock; then exit 9; fi\n"
            )
            result = subprocess.run(
                ["sh"],
                input=harness,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            lock_pid = (lock / "pid").read_text(encoding="utf-8").strip()
            self.assertTrue(lock_pid.isdecimal())
            self.assertGreater(int(lock_pid), 1)
            self.assertEqual((lock / "starttime").read_text(encoding="utf-8"), "123\n")

    def test_exact_artifact_stage_and_atomic_failure_cleanup(self) -> None:
        if not self.artifact.exists():
            self.skipTest("attested local r1 APK is not present")
        with tempfile.TemporaryDirectory(prefix="lmi-sixrow-stage-test-") as temp:
            root = Path(temp)
            output = root / "stage"
            manifest = transient.stage(self.artifact, output)
            self.assertEqual(
                manifest["schema"], "lmi-weston-sixrow-transient-stage/v2"
            )
            self.assertEqual(manifest["status"], transient.TRANSIENT_LOCK_STATUS)
            self.assertIs(manifest["execution_enabled"], False)
            self.assertEqual(
                manifest["apk"]["path"],
                ".work/pmbootstrap-sixrow/packages/edge/aarch64/"
                "lmi-weston-sixrow-clients-14.0.2-r1.apk",
            )
            self.assertNotIn(str(transient.REPO), json.dumps(manifest))
            self.assertEqual(
                manifest["runtime_pins"]["/usr/bin/setsid"],
                transient.SETSID_SHA256,
            )
            self.assertEqual(len(manifest["known_residual_risks"]), 2)
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            for directory in transient.SESSION_DIRECTORIES:
                self.assertEqual((output / directory).stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "supervisor").stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / "status").stat().st_mode & 0o777, 0o600)
            self.assertEqual(
                (output / "status").read_text(encoding="utf-8"),
                "NO-GO: execution disabled after PID-signal-race review\n",
            )
            with self.assertRaises(transient.StageError):
                transient.stage(self.artifact, output)

            failed_output = root / "failed-stage"
            with mock.patch.object(
                transient.subprocess,
                "run",
                side_effect=subprocess.CalledProcessError(2, ["sh", "-n"]),
            ):
                with self.assertRaises(subprocess.CalledProcessError):
                    transient.stage(self.artifact, failed_output)
            self.assertFalse(failed_output.exists())
            self.assertEqual(list(root.glob(".failed-stage.partial-*")), [])

    def test_symlink_alias_and_corrupt_apk_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="lmi-sixrow-input-test-") as temp:
            root = Path(temp)
            corrupt = root / "corrupt.apk"
            corrupt.write_bytes(b"not-an-apk")
            with self.assertRaisesRegex(transient.StageError, "SHA-256"):
                transient.extract_payload(corrupt)
            if self.artifact.exists():
                alias = root / "alias.apk"
                alias.symlink_to(self.artifact)
                with self.assertRaisesRegex(transient.StageError, "non-symlink"):
                    transient.stage(alias, root / "output")

    def test_stock_source_drift_is_rejected(self) -> None:
        with mock.patch.object(transient, "digest", return_value="0" * 64):
            with self.assertRaisesRegex(transient.StageError, "stock session source"):
                transient.render_session("candidate")

    def test_transient_source_lock_binds_reviewed_inputs(self) -> None:
        lock = transient.verify_transient_source_lock()
        self.assertEqual(lock["remote_root"], transient.REMOTE_ROOT)
        self.assertEqual(
            lock["runtime_pins"]["candidate_apk_sha256"],
            transient.EXPECTED_APK_SHA256,
        )
        self.assertEqual(
            lock["runtime_pins"]["setsid_sha256"], transient.SETSID_SHA256
        )
        self.assertEqual(lock["status"], transient.TRANSIENT_LOCK_STATUS)
        self.assertIs(lock["execution_enabled"], False)
        self.assertEqual(lock["review_decision"]["outcome"], "NO-GO")
        self.assertEqual(
            lock["review_decision"]["reason_code"],
            transient.TRANSIENT_NO_GO_REASON_CODE,
        )
        self.assertIn(
            "execution remains disabled",
            lock["trial_contract"]["legacy_active_stock_shutdown_risk"].lower(),
        )


if __name__ == "__main__":
    unittest.main()
