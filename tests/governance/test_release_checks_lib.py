"""Behavior tests for the shared shell assertion library.

scripts/lib/release_checks.sh is the single assertion vocabulary shared by
scripts/59_release_static_ci.sh (exit-fast), and by
scripts/65_lmi_release_safety_lint.sh and scripts/69_audit_lmi_resources.sh
(count-and-continue). These tests exercise the library through its public
seam only: sourcing it in a bash process and calling its functions.
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RELEASE_CHECKS_LIB = REPO_ROOT / "scripts" / "lib" / "release_checks.sh"
LMI_ENV_LIB = REPO_ROOT / "scripts" / "lib" / "mainline_r6_env.sh"


def run_with_lib(snippet: str, lib: Path = RELEASE_CHECKS_LIB) -> subprocess.CompletedProcess:
    script = 'set -euo pipefail\nsource "{}"\n{}'.format(lib, snippet)
    return subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
    )


class ExitFastModeTests(unittest.TestCase):
    """Default mode reproduces 59_release_static_ci.sh semantics."""

    def test_require_file_missing_exits_1_with_59_message(self) -> None:
        result = run_with_lib(
            'require_file /nonexistent/path\necho unreachable'
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr,
            "missing release contract file: /nonexistent/path\n",
        )
        self.assertNotIn("unreachable", result.stdout)

    def test_require_file_present_is_silent_and_continues(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "present.txt"
            path.write_text("x\n")
            result = run_with_lib(f'require_file "{path}"\necho reached')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "reached\n")
        self.assertEqual(result.stderr, "")

    def test_require_literal_missing_exits_1_with_59_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doc.md"
            path.write_text("some content\n")
            result = run_with_lib(f'require_literal "{path}" needle\necho unreachable')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr,
            f"missing release contract in {path}: needle\n",
        )
        self.assertNotIn("unreachable", result.stdout)

    def test_require_literal_matches_fixed_string_not_regex(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doc.md"
            path.write_text("literal a.b here\n")
            # "a.b" must match only the exact characters (grep -F), and
            # a leading dash must not be parsed as a grep option.
            ok = run_with_lib(f'require_literal "{path}" "a.b"\necho reached')
            self.assertEqual(ok.returncode, 0, ok.stderr)
            miss = run_with_lib(f'require_literal "{path}" "axb"')
            self.assertEqual(miss.returncode, 1)
            dash = run_with_lib(f'require_literal "{path}" "--not-an-option"')
            self.assertEqual(dash.returncode, 1)

    def test_reject_literal_present_exits_1_with_59_message(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doc.md"
            path.write_text("retired thing\n")
            result = run_with_lib(f'reject_literal "{path}" "retired thing"')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(
            result.stderr,
            f"retired release contract remains in {path}: retired thing\n",
        )

    def test_reject_literal_absent_is_silent_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "doc.md"
            path.write_text("clean\n")
            result = run_with_lib(f'reject_literal "{path}" "retired thing"\necho reached')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "reached\n")

    def test_fail_exits_1_with_bare_message_on_stderr(self) -> None:
        result = run_with_lib('fail "boom happened"\necho unreachable')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stderr, "boom happened\n")
        self.assertNotIn("unreachable", result.stdout)


class CountModeTests(unittest.TestCase):
    """RELEASE_CHECKS_MODE=count reproduces 65/69 count-and-continue."""

    def test_fail_counts_and_continues_default_stderr(self) -> None:
        # 65-style: FAIL lines on stderr, script keeps going.
        result = run_with_lib(
            'RELEASE_CHECKS_MODE=count\n'
            'fail "first"\n'
            'fail "second"\n'
            'echo "failures=$release_checks_failures"'
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, "FAIL: first\nFAIL: second\n")
        self.assertEqual(result.stdout, "failures=2\n")

    def test_fail_to_log_goes_to_stdout_and_report(self) -> None:
        # 69-style: FAIL lines flow through log() into stdout and report.
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "report.txt"
            result = run_with_lib(
                'RELEASE_CHECKS_MODE=count\n'
                'RELEASE_CHECKS_FAIL_TO=log\n'
                f'RELEASE_CHECKS_REPORT="{report}"\n'
                ': > "$RELEASE_CHECKS_REPORT"\n'
                'fail "missing file: /x"\n'
                'echo "failures=$release_checks_failures"'
            )
            report_text = report.read_text()
        self.assertEqual(result.returncode, 0)
        self.assertIn("FAIL: missing file: /x\n", result.stdout)
        self.assertIn("failures=1\n", result.stdout)
        self.assertEqual(result.stderr, "")
        self.assertEqual(report_text, "FAIL: missing file: /x\n")

    def test_warn_counts_separately_and_logs(self) -> None:
        result = run_with_lib(
            'RELEASE_CHECKS_MODE=count\n'
            'warn "may be absent"\n'
            'echo "warnings=$release_checks_warnings"\n'
            'echo "failures=$release_checks_failures"'
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("WARN: may be absent\n", result.stdout)
        self.assertIn("warnings=1\n", result.stdout)
        self.assertIn("failures=0\n", result.stdout)

    def test_require_file_and_dir_log_ok_or_count_fail(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "present.txt"
            path.write_text("x\n")
            result = run_with_lib(
                'RELEASE_CHECKS_MODE=count\n'
                'RELEASE_CHECKS_FAIL_TO=log\n'
                f'require_file "{path}"\n'
                'require_file /nonexistent/one\n'
                f'require_dir "{tmp}"\n'
                'require_dir /nonexistent/two\n'
                'echo "failures=$release_checks_failures"'
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn(f"OK file: {path}\n", result.stdout)
        self.assertIn("FAIL: missing file: /nonexistent/one\n", result.stdout)
        self.assertIn(f"OK dir: {tmp}\n", result.stdout)
        self.assertIn("FAIL: missing directory: /nonexistent/two\n", result.stdout)
        self.assertIn("failures=2\n", result.stdout)

    def test_require_grep_matches_69_message_shapes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "deviceinfo"
            path.write_text('deviceinfo_dtb="qcom/example"\n')
            result = run_with_lib(
                'RELEASE_CHECKS_MODE=count\n'
                'RELEASE_CHECKS_FAIL_TO=log\n'
                f'require_grep "dtb name" \'deviceinfo_dtb="qcom/example"\' "{path}"\n'
                f'require_grep "absent key" absent_pattern "{path}"\n'
                'require_grep "gone file" anything /nonexistent/file\n'
                'echo "failures=$release_checks_failures"'
            )
        self.assertEqual(result.returncode, 0)
        self.assertIn("OK grep: dtb name\n", result.stdout)
        self.assertIn(
            f"FAIL: absent key: pattern not found in {path}: absent_pattern\n",
            result.stdout,
        )
        self.assertIn("FAIL: gone file: missing file /nonexistent/file\n", result.stdout)
        self.assertIn("failures=2\n", result.stdout)

    def test_log_writes_stdout_and_appends_report_when_set(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            report = Path(tmp) / "r.txt"
            result = run_with_lib(
                f'RELEASE_CHECKS_REPORT="{report}"\n'
                ': > "$RELEASE_CHECKS_REPORT"\n'
                'log "line one"\n'
                'log "line two"'
            )
            report_text = report.read_text()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "line one\nline two\n")
        self.assertEqual(report_text, "line one\nline two\n")

    def test_log_without_report_is_stdout_only(self) -> None:
        result = run_with_lib('log "plain line"')
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "plain line\n")


class LibrarySafetyTests(unittest.TestCase):
    """The shared libraries must hold generic helpers only: no device
    state-change vocabulary, so the safety lint's scans stay meaningful."""

    def _assert_no_forbidden_words(self, lib: Path) -> None:
        import sys

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        try:
            import bringup_loop
        finally:
            sys.path.pop(0)
        text = lib.read_text()
        for word in sorted(bringup_loop.FORBIDDEN_COMMAND_WORDS) + ["fastboot"]:
            self.assertNotIn(word, text, f"{lib.name} must not contain {word!r}")

    def test_release_checks_lib_has_no_device_command_vocabulary(self) -> None:
        self._assert_no_forbidden_words(RELEASE_CHECKS_LIB)

    def test_lmi_env_lib_has_no_device_command_vocabulary(self) -> None:
        self._assert_no_forbidden_words(LMI_ENV_LIB)


class MainlineR6EnvLibTests(unittest.TestCase):
    """M-r6 release env defaults and repo-root discovery."""

    def test_defaults_match_the_historical_values(self) -> None:
        script = (
            'set -euo pipefail\n'
            'unset OUT_DIR PMOS_EXPORT_DIR LMI_RELEASE_BUNDLE_DIR LMI_RELEASE_TAG\n'
            f'source "{LMI_ENV_LIB}"\n'
            'echo "$lmi_repo"\n'
            'echo "$lmi_default_out_dir"\n'
            'echo "$lmi_default_export_dir"\n'
            'echo "$lmi_default_bundle_dir"\n'
            'echo "$lmi_default_release_tag"'
        )
        result = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, cwd=REPO_ROOT
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout.splitlines(),
            [
                str(REPO_ROOT),
                "/tmp/lmi-copydown-r6-bootmem-20260624",
                "/tmp/postmarketOS-export",
                "/tmp/lmi-release-r6-bootmem-20260624",
                "r6-bootmem",
            ],
        )

    def test_environment_overrides_win(self) -> None:
        result = run_with_lib(
            'echo "$lmi_default_out_dir $lmi_default_export_dir"\n'
            'echo "$lmi_default_bundle_dir $lmi_default_release_tag"',
            lib=LMI_ENV_LIB,
        )
        # Baseline sanity established above; now override all four.
        script = (
            'set -euo pipefail\n'
            'export OUT_DIR=/o PMOS_EXPORT_DIR=/e LMI_RELEASE_BUNDLE_DIR=/b LMI_RELEASE_TAG=tag9\n'
            f'source "{LMI_ENV_LIB}"\n'
            'echo "$lmi_default_out_dir $lmi_default_export_dir '
            '$lmi_default_bundle_dir $lmi_default_release_tag"'
        )
        override = subprocess.run(
            ["bash", "-c", script], capture_output=True, text=True, cwd=REPO_ROOT
        )
        self.assertEqual(override.returncode, 0, override.stderr)
        self.assertEqual(override.stdout, "/o /e /b tag9\n")
        self.assertEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
