"""Behavioural tests for the release pin cross-check registry.

The registry declares every file location ("site") that hand-copies a
release pin (SHA-256 digest or byte size) and verifies that all sites
agree with their declared truth.  These tests drive the public seams:

- ``verify_registry(root, registry)`` -> findings
- ``main(argv)`` -> process exit code (CLI ``verify`` / ``list``)
- module-level ``REGISTRY`` against the real repository
"""

import contextlib
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))

import lmi_release_pins as pins  # noqa: E402

GOOD = "a" * 64
STALE = "b" * 64


def _write(root, relative, text):
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _fixture_repo(root, apk_sha=GOOD, lock_sha=GOOD, shell_sha=GOOD,
                  const_sha=GOOD, session_sha=GOOD, second_order_pin=None):
    """A miniature repo exercising one site of every extractor kind."""
    _write(root, "config/attestation.json", json.dumps(
        {"artifact": {"sha256": apk_sha}}
    ))
    _write(root, "config/stage-lock.json", json.dumps(
        {"runtime_pins": {"candidate_apk_sha256": lock_sha}}
    ))
    _write(root, "scripts/inject.sh", "\n".join([
        "#!/bin/sh",
        "readonly SIXROW_APK_SHA256=%s" % shell_sha,
        "",
    ]))
    _write(root, "scripts/stage.py", "\n".join([
        'EXPECTED_APK_SHA256 = "%s"' % const_sha,
        "PAYLOAD = {",
        '    "usr/libexec/tool": ("tool", "%s"),' % const_sha,
        "}",
        "",
    ]))
    _write(root, "files/session", "\n".join([
        "#!/bin/sh",
        "check_sha256 /usr/bin/tool \\",
        "\t%s" % session_sha,
        "",
    ]))
    lock_body = json.dumps({"schema": "test-lock/v1"})
    _write(root, "config/rebuild-lock.json", lock_body)
    if second_order_pin is None:
        second_order_pin = hashlib.sha256(
            lock_body.encode("utf-8")
        ).hexdigest()
    _write(root, "scripts/launcher.sh", "\n".join([
        "#!/bin/sh",
        "readonly REBUILD_LOCK_SHA256=%s" % second_order_pin,
        "",
    ]))


def _fixture_registry():
    site = pins.Site
    return (
        pins.Artifact(
            name="candidate-apk",
            truth=site(
                label="attestation.artifact.sha256",
                path="config/attestation.json",
                kind="json",
                pointer=("artifact", "sha256"),
            ),
            sites=(
                site(
                    label="stage-lock.candidate_apk_sha256",
                    path="config/stage-lock.json",
                    kind="json",
                    pointer=("runtime_pins", "candidate_apk_sha256"),
                ),
                site(
                    label="inject.SIXROW_APK_SHA256",
                    path="scripts/inject.sh",
                    kind="shell_var",
                    var="SIXROW_APK_SHA256",
                ),
                site(
                    label="stage.EXPECTED_APK_SHA256",
                    path="scripts/stage.py",
                    kind="python_const",
                    const="EXPECTED_APK_SHA256",
                ),
                site(
                    label="stage.PAYLOAD[usr/libexec/tool]",
                    path="scripts/stage.py",
                    kind="python_const",
                    const="PAYLOAD",
                    selector=("usr/libexec/tool", 1),
                ),
                site(
                    label="session.check_sha256[/usr/bin/tool]",
                    path="files/session",
                    kind="regex",
                    pattern=(
                        r"check_sha256 /usr/bin/tool \\\s*"
                        r"([0-9a-f]{64})"
                    ),
                    exact_count=1,
                ),
            ),
        ),
        pins.Artifact(
            name="rebuild-lock-file",
            truth=site(
                label="sha256(config/rebuild-lock.json)",
                path="config/rebuild-lock.json",
                kind="file_sha256",
            ),
            sites=(
                site(
                    label="launcher.REBUILD_LOCK_SHA256",
                    path="scripts/launcher.sh",
                    kind="shell_var",
                    var="REBUILD_LOCK_SHA256",
                ),
            ),
        ),
    )


class VerifyRegistryFixtureTest(unittest.TestCase):
    def _verify(self, **fixture_kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _fixture_repo(root, **fixture_kwargs)
            return pins.verify_registry(root, _fixture_registry())

    def _failed_labels(self, findings):
        return [
            finding.site_label
            for finding in findings
            if finding.status in ("MISMATCH", "UNREADABLE")
        ]

    def test_all_sites_agree_reports_no_failures(self):
        findings = self._verify()
        self.assertEqual(self._failed_labels(findings), [])
        self.assertTrue(
            all(finding.status == "OK" for finding in findings)
        )

    def test_every_site_is_reported_even_when_healthy(self):
        findings = self._verify()
        labels = [finding.site_label for finding in findings]
        self.assertIn("stage-lock.candidate_apk_sha256", labels)
        self.assertIn("session.check_sha256[/usr/bin/tool]", labels)
        self.assertIn("launcher.REBUILD_LOCK_SHA256", labels)

    def test_stale_json_site_is_a_mismatch(self):
        findings = self._verify(lock_sha=STALE)
        self.assertEqual(
            self._failed_labels(findings),
            ["stage-lock.candidate_apk_sha256"],
        )

    def test_stale_shell_variable_is_a_mismatch(self):
        findings = self._verify(shell_sha=STALE)
        self.assertEqual(
            self._failed_labels(findings),
            ["inject.SIXROW_APK_SHA256"],
        )

    def test_stale_python_constant_is_a_mismatch_at_both_sites(self):
        findings = self._verify(const_sha=STALE)
        self.assertEqual(
            self._failed_labels(findings),
            [
                "stage.EXPECTED_APK_SHA256",
                "stage.PAYLOAD[usr/libexec/tool]",
            ],
        )

    def test_stale_session_gate_line_is_a_mismatch(self):
        findings = self._verify(session_sha=STALE)
        self.assertEqual(
            self._failed_labels(findings),
            ["session.check_sha256[/usr/bin/tool]"],
        )

    def test_duplicate_session_gate_line_is_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _fixture_repo(root)
            session = root / "files/session"
            session.write_text(
                session.read_text(encoding="utf-8")
                + "check_sha256 /usr/bin/tool \\\n\t%s\n" % GOOD,
                encoding="utf-8",
            )
            findings = pins.verify_registry(root, _fixture_registry())
        by_label = {finding.site_label: finding for finding in findings}
        finding = by_label["session.check_sha256[/usr/bin/tool]"]
        self.assertEqual(finding.status, "UNREADABLE")
        self.assertIn("need exactly 1", finding.detail)

    def test_second_order_pin_is_checked_against_real_file_hash(self):
        findings = self._verify(second_order_pin=STALE)
        self.assertEqual(
            self._failed_labels(findings),
            ["launcher.REBUILD_LOCK_SHA256"],
        )

    def test_missing_site_file_is_unreadable_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _fixture_repo(root)
            (root / "scripts/inject.sh").unlink()
            findings = pins.verify_registry(root, _fixture_registry())
        by_label = {f.site_label: f for f in findings}
        self.assertEqual(
            by_label["inject.SIXROW_APK_SHA256"].status, "UNREADABLE"
        )


class BestEffortSiteTest(unittest.TestCase):
    def test_unreadable_best_effort_site_warns_instead_of_failing(self):
        registry = (
            pins.Artifact(
                name="candidate-apk",
                truth=pins.Site(
                    label="attestation.artifact.sha256",
                    path="config/attestation.json",
                    kind="json",
                    pointer=("artifact", "sha256"),
                ),
                sites=(
                    pins.Site(
                        label="doc prose digest (best effort)",
                        path="docs/missing.md",
                        kind="regex",
                        pattern=r"SHA-256 `([0-9a-f]{64})`",
                        best_effort=True,
                    ),
                ),
            ),
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _fixture_repo(root)
            findings = pins.verify_registry(root, registry)
        by_label = {f.site_label: f for f in findings}
        finding = by_label["doc prose digest (best effort)"]
        self.assertEqual(finding.status, "WARN")
        self.assertFalse(finding.fatal)


class TruncatedPrefixSiteTest(unittest.TestCase):
    def test_prefix_transform_checks_truncated_pin_copies(self):
        def registry(_root):
            return (
                pins.Artifact(
                    name="candidate-apk",
                    truth=pins.Site(
                        label="attestation.artifact.sha256",
                        path="config/attestation.json",
                        kind="json",
                        pointer=("artifact", "sha256"),
                    ),
                    sites=(
                        pins.Site(
                            label="remote-root prefix",
                            path="config/remote-root.json",
                            kind="json",
                            pointer=("remote_root",),
                            value_pattern=r"-r1-([0-9a-f]{12})$",
                            expected_transform="prefix:12",
                        ),
                    ),
                ),
            )

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            _fixture_repo(root)
            _write(root, "config/remote-root.json", json.dumps(
                {"remote_root": "/tmp/x-r1-" + GOOD[:12]}
            ))
            agree = pins.verify_registry(root, registry(root))
            _write(root, "config/remote-root.json", json.dumps(
                {"remote_root": "/tmp/x-r1-" + STALE[:12]}
            ))
            stale = pins.verify_registry(root, registry(root))
        self.assertEqual(
            [f.status for f in agree if f.site_label == "remote-root prefix"],
            ["OK"],
        )
        self.assertEqual(
            [f.status for f in stale if f.site_label == "remote-root prefix"],
            ["MISMATCH"],
        )


class CliTest(unittest.TestCase):
    def _run(self, *argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), \
                contextlib.redirect_stderr(stderr):
            code = pins.main(list(argv))
        return code, stdout.getvalue(), stderr.getvalue()

    def test_verify_exits_zero_on_the_real_repository(self):
        code, out, _ = self._run("verify", "--root", str(REPO_ROOT))
        self.assertEqual(
            code, 0, "real-repo pin verification failed:\n%s" % out
        )
        self.assertIn("0 mismatched, 0 unreadable", out)

    def test_verify_exits_nonzero_listing_the_stale_site(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            code, out, _ = self._run("verify", "--root", str(root))
        self.assertEqual(code, 1)
        self.assertIn("UNREADABLE", out)

    def test_list_prints_every_registered_site_label(self):
        code, out, _ = self._run("list", "--root", str(REPO_ROOT))
        self.assertEqual(code, 0)
        self.assertIn("inject_rootfs_candidate.SIXROW_APK_SHA256", out)
        self.assertIn("session-gate", out)
        self.assertIn("known-good-kernel-apk-size", out)

    def test_bad_root_is_a_usage_error(self):
        code, _, err = self._run("verify", "--root", "/nonexistent-root-xyz")
        self.assertEqual(code, 2)
        self.assertIn("not a directory", err)


class RealRegistryShapeTest(unittest.TestCase):
    """The registry must keep covering the known brick-path sites."""

    def _labels(self):
        labels = []
        for artifact in pins.REGISTRY:
            labels.append(artifact.truth.label)
            labels.extend(site.label for site in artifact.sites)
        return labels

    def test_site_labels_are_unique_within_the_registry(self):
        per_artifact = [
            [artifact.truth.label]
            + [site.label for site in artifact.sites]
            for artifact in pins.REGISTRY
        ]
        for labels in per_artifact:
            self.assertEqual(len(labels), len(set(labels)))

    def test_session_gate_brick_path_sites_are_registered(self):
        labels = "\n".join(self._labels())
        self.assertIn("weston-keyboard-sixrow", labels)
        self.assertIn("weston-terminal-sixrow", labels)
        self.assertIn("session-gate", labels)
        self.assertIn("/usr/bin/weston", labels)
        session_sites = [
            site
            for artifact in pins.REGISTRY
            for site in artifact.sites
            if site.label.startswith("session-gate")
        ]
        self.assertEqual(
            sorted(site.exact_count for site in session_sites),
            [1, 2, 3, 3],
        )

    def test_second_order_file_hash_truths_are_registered(self):
        hashed = [
            artifact.truth.path
            for artifact in pins.REGISTRY
            if artifact.truth.kind == "file_sha256"
        ]
        self.assertIn(
            "config/lmi-weston-sixrow/build-attestation-r4.json", hashed
        )
        self.assertIn("config/lmi-p2-d114/source-lock.json", hashed)
        self.assertIn(
            "scripts/lmi_p2_d114/inject_rootfs_candidate.sh", hashed
        )


if __name__ == "__main__":
    unittest.main()
