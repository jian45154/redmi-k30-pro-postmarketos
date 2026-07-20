from __future__ import annotations

from contextlib import ExitStack, redirect_stdout
import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.build as build_module
from scripts.lmi_p1.build import BuildResult
from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.seal import (
    GitProvenance,
    PmbootstrapProvenance,
    SealProvenance,
    SealSources,
    create_seal,
)
import scripts.lmi_p1_cli as cli_module
from tests.lmi_p1.offline_cache_fixtures import offline_binding, write_offline_cache


class SealedBuildCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()

        sources = self.root / "sources"
        sources.mkdir(mode=0o700)
        self.project = sources / "project"
        self.pmbootstrap = sources / "pmbootstrap"
        self.pmaports = sources / "pmaports"
        self.project.mkdir(mode=0o755)
        self.pmbootstrap.mkdir(mode=0o755)
        self.pmaports.mkdir(mode=0o755)

        (self.project / "scripts").mkdir(mode=0o755)
        (self.project / "scripts/lmi_p1_cli.py").write_text(
            "raise SystemExit('test seal must not execute this placeholder')\n"
        )
        (self.project / "project-input").write_text("project\n")
        shutil_source = (
            Path(__file__).resolve().parents[2]
            / "artifacts/wsl-pmaports/linux-xiaomi-lmi"
        )
        shutil.copytree(
            shutil_source,
            self.project / "artifacts/wsl-pmaports/linux-xiaomi-lmi",
        )
        self.pmbootstrap_entrypoint = self.pmbootstrap / "pmbootstrap.py"
        self.pmbootstrap_entrypoint.write_text("print('3.11.1')\n")
        self.pmbootstrap_entrypoint.chmod(0o755)
        (self.pmaports / "pmaports.cfg").write_text(
            "[pmaports]\nchannel = edge\nversion = 7\n"
        )
        # The sealed offline cache fixture installs the pinned APK trust roots
        # into the pmbootstrap checkout. Do that before committing its tree so
        # the production clean-checkout gate remains meaningful.
        self.offline_cache, self.offline_manifest = write_offline_cache(sources)

        self.project_remote = "https://example.invalid/lmi-project.git"
        self.pmbootstrap_remote = (
            "https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git"
        )
        self.pmaports_remote = (
            "https://gitlab.postmarketos.org/postmarketOS/pmaports.git"
        )
        self.project_commit, self.project_tree = self._init_git(
            self.project, self.project_remote
        )
        self.pmbootstrap_commit, self.pmbootstrap_tree = self._init_git(
            self.pmbootstrap, self.pmbootstrap_remote
        )
        self.pmaports_commit, self.pmaports_tree = self._init_git(
            self.pmaports, self.pmaports_remote
        )

        key_type = b"ssh-ed25519"
        # A known-valid public key fixture already used by the main builder tests.
        key_blob = (
            len(key_type).to_bytes(4, "big")
            + key_type
            + (32).to_bytes(4, "big")
            + bytes(range(32))
        )
        import base64

        self.authorized_key = sources / "authorized_key.pub"
        self.authorized_key.write_text(
            "ssh-ed25519 "
            + base64.b64encode(key_blob).decode("ascii")
            + " sealed-test\n"
        )
        self.authorized_key.chmod(0o600)
        self.source_lock = sources / "source-lock.json"

        self.seals = self.root / "seals"
        self.seals.mkdir(mode=0o700)
        policy = self.root / "policy"
        policy.mkdir(mode=0o700)
        self.active = policy / "active"
        self.runs = self.root / "runs"
        self.runs.mkdir(mode=0o700)
        self.paths = cli_module.SealedCliPaths(
            active=self.active,
            seals=self.seals,
            runs=self.runs,
            trusted_root=self.root,
        )

    @staticmethod
    def _git(path: Path, *arguments: str) -> str:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=path,
            text=True,
            capture_output=True,
            check=True,
        )
        return completed.stdout.strip()

    def _init_git(self, path: Path, remote: str) -> tuple[str, str]:
        self._git(path, "init", "-q")
        self._git(path, "config", "user.name", "LMI sealed test")
        self._git(path, "config", "user.email", "sealed@example.invalid")
        self._git(path, "remote", "add", "origin", remote)
        self._git(path, "add", ".")
        self._git(path, "commit", "-q", "-m", "sealed fixture")
        return (
            self._git(path, "rev-parse", "HEAD"),
            self._git(path, "rev-parse", "HEAD^{tree}"),
        )

    def _source_lock_value(
        self,
        *,
        pmbootstrap_commit: str | None = None,
        pmaports_commit: str | None = None,
    ) -> dict[str, object]:
        return {
            "schema": "lmi-source-lock/v3",
            "offline_cache": offline_binding(
                self.offline_cache, self.offline_manifest
            ),
            "pmbootstrap": {
                "entrypoint_sha256": hashlib.sha256(
                    self.pmbootstrap_entrypoint.read_bytes()
                ).hexdigest(),
                "remote": self.pmbootstrap_remote,
                "commit": pmbootstrap_commit or self.pmbootstrap_commit,
                "tree": self.pmbootstrap_tree,
                "version": "3.11.1",
            },
            "pmaports": {
                "remote": self.pmaports_remote,
                "commit": pmaports_commit or self.pmaports_commit,
                "tree": self.pmaports_tree,
            },
            "kernel": {
                "commit": "a5b3099017ae581aae8bf597b2f9c8c765026af1",
                "package": "linux-xiaomi-lmi",
                "remote": "https://github.com/LineageOS/android_kernel_xiaomi_sm8250",
                "sha512": (
                    "b9d00e0efcb88d613bd65b1f2cd6b75e2b5f0d79b23def0b9c14eb397265e582"
                    "a580e93cb365d81e7aa167b027920845ff8db798bbf781bbd9e7845e796bd923"
                ),
                "version": "4.19.325-r8",
            },
            "known_good_kernel_package": json.loads(
                json.dumps(build_module._EXPECTED_KNOWN_GOOD_KERNEL_PIN)
            ),
            "public_credential_policy": {
                "boot_state": "never_booted",
                "credential_state": "unprovisioned",
                "owner_test_artifact": "never-publish",
                "personalization_required": True,
                "ssh_ready": False,
            },
            "release": {
                "source_repo": "jian45154/redmi-k30-pro-postmarketos",
                "public_allowed": True,
                "visibility": "public",
            },
        }

    def _make_seal(
        self,
        *,
        lock_pmbootstrap_commit: str | None = None,
        manifest_project_commit: str | None = None,
        kernel_updates: dict[str, object] | None = None,
    ):
        source_lock_value = self._source_lock_value(
            pmbootstrap_commit=lock_pmbootstrap_commit,
        )
        if kernel_updates is not None:
            source_lock_value["kernel"].update(kernel_updates)
        self.source_lock.write_text(
            json.dumps(
                source_lock_value,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        self.source_lock.chmod(0o600)
        return create_seal(
            self.seals,
            SealSources(
                project=self.project,
                pmbootstrap=self.pmbootstrap,
                pmaports=self.pmaports,
                authorized_key=self.authorized_key,
                source_lock=self.source_lock,
                offline_cache=self.offline_cache,
            ),
            SealProvenance(
                generation=1,
                project=GitProvenance(
                    remote=self.project_remote,
                    commit=manifest_project_commit or self.project_commit,
                    tree=self.project_tree,
                ),
                pmbootstrap=PmbootstrapProvenance(
                    remote=self.pmbootstrap_remote,
                    commit=self.pmbootstrap_commit,
                    tree=self.pmbootstrap_tree,
                    version="3.11.1",
                    entrypoint_sha256=hashlib.sha256(
                        self.pmbootstrap_entrypoint.read_bytes()
                    ).hexdigest(),
                ),
                pmaports=GitProvenance(
                    remote=self.pmaports_remote,
                    commit=self.pmaports_commit,
                    tree=self.pmaports_tree,
                ),
            ),
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def _activate_and_request(
        self,
        seal,
        *,
        request_updates: dict[str, object] | None = None,
        canonical: bool = True,
    ) -> Path:
        self.active.write_text(seal.policy_id + "\n", encoding="ascii")
        self.active.chmod(0o600)
        run = self.runs / ("run-" + "3" * 32)
        run.mkdir(mode=0o700)
        request: dict[str, object] = {
            "policy_id": seal.policy_id,
            "schema": "lmi-p1-build-request/v1",
            "tag": "lmi-p1-sealed-test-1",
        }
        if request_updates:
            request.update(request_updates)
        request_path = run / "request.json"
        payload = (
            cli_module._canonical_request_bytes(request)
            if canonical
            else json.dumps(request, indent=2).encode("ascii")
        )
        request_path.write_bytes(payload)
        request_path.chmod(0o600)
        return request_path

    def _build_result(self) -> BuildResult:
        output = self.root / "mock-output"
        output.mkdir(exist_ok=True)
        values = [
            output / "boot.img",
            output / "root.img",
            output / "vmlinuz",
            output / "initramfs",
            output / "dtbs",
            output / "packages.txt",
            output / "world",
            output / "sshd.json",
            output / "semantics.json",
            output / "build.log",
            output / "identity",
            output / "artifact-manifest.json",
            "a" * 64,
            "b" * 64,
        ]
        return BuildResult(*values)

    def _constant_patch(self):
        stack = ExitStack()
        stack.enter_context(
            mock.patch.multiple(
                build_module,
                _EXPECTED_PMBOOTSTRAP_COMMIT=self.pmbootstrap_commit,
                _EXPECTED_PMAPORTS_COMMIT=self.pmaports_commit,
            )
        )
        return stack

    def test_build_sealed_derives_every_context_field_and_internal_capability(self):
        seal = self._make_seal()
        request = self._activate_and_request(seal)
        expected = self._build_result()
        hostile = {
            "LMI_REPO": "/attacker/project",
            "LMI_PMAPORTS": "/attacker/pmaports",
            "LMI_WORK": "/attacker/work",
            "PYTHONPATH": "/attacker/modules",
        }
        ordering: list[str] = []

        def build(*_arguments, **_keywords):
            ordering.append("build")
            return expected

        def revalidate(*_arguments, **_keywords):
            ordering.append("revalidate")
            return expected

        with self._constant_patch(), mock.patch.dict(
            os.environ, hostile, clear=False
        ), mock.patch.object(
            cli_module, "build_candidate", side_effect=build
        ) as called, mock.patch.object(
            cli_module,
            "revalidate_sealed_build_result",
            side_effect=revalidate,
        ) as final_recheck:
            actual = cli_module.build_sealed_from_request(
                request,
                executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
                geteuid=lambda: self.uid,
            )

        self.assertIs(actual, expected)
        self.assertEqual(ordering, ["build", "revalidate"])
        context = called.call_args.args[0]
        authorization = called.call_args.kwargs["_sealed_authorization"]
        self.assertEqual(context.repo, seal.project)
        self.assertEqual(context.pmaports, seal.pmaports)
        self.assertEqual(context.pmbootstrap, seal.pmbootstrap / "pmbootstrap.py")
        self.assertEqual(context.public_key, seal.authorized_key)
        self.assertEqual(context.source_commit, self.project_commit)
        self.assertEqual(context.policy_id, seal.policy_id)
        self.assertEqual(context.privilege_model, "root-owned-sealed-production")
        self.assertEqual(context.work, request.parent / "candidate")
        for name in (
            ".verification-runtime",
            ".verification-runtime/home",
            ".verification-runtime/tmp",
            ".verification-runtime/cache",
            ".verification-runtime/config",
            ".verification-runtime/data",
        ):
            directory = request.parent / name
            self.assertTrue(directory.is_dir())
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
        with mock.patch.object(os, "geteuid", return_value=0):
            self.assertTrue(build_module._sealed_build_mode(context, authorization))
        final_recheck.assert_called_once_with(
            expected,
            expected_policy_id=seal.policy_id,
            active_path=self.paths.active,
            trusted_root=self.paths.trusted_root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def test_build_sealed_propagates_final_result_revalidation_failure(self):
        seal = self._make_seal()
        request = self._activate_and_request(seal)
        expected = self._build_result()
        with self._constant_patch(), mock.patch.object(
            cli_module,
            "build_candidate",
            return_value=expected,
        ) as build, mock.patch.object(
            cli_module,
            "revalidate_sealed_build_result",
            side_effect=GateError("synthetic final result race"),
        ) as final_recheck, self.assertRaisesRegex(
            GateError, "synthetic final result race"
        ):
            cli_module.build_sealed_from_request(
                request,
                executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
                geteuid=lambda: self.uid,
            )

        build.assert_called_once()
        final_recheck.assert_called_once_with(
            expected,
            expected_policy_id=seal.policy_id,
            active_path=self.paths.active,
            trusted_root=self.paths.trusted_root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def test_build_sealed_main_accepts_only_launcher_request_argument(self):
        expected = self._build_result()
        output = io.StringIO()
        request = Path("/var/lib/lmi-p1/runs/run-" + "a" * 32) / "request.json"
        with mock.patch.object(
            cli_module, "build_sealed_from_request", return_value=expected
        ) as called, redirect_stdout(output):
            self.assertEqual(
                cli_module.main(["build-sealed", "--request", str(request)]), 0
            )
        called.assert_called_once_with(request)
        self.assertEqual(json.loads(output.getvalue())["boot_img"], str(expected.boot_img))

    def test_final_result_revalidation_exposes_the_cli_integration_contract(self):
        self.assertEqual(
            tuple(
                inspect.signature(
                    build_module.revalidate_sealed_build_result
                ).parameters
            ),
            (
                "result",
                "expected_policy_id",
                "active_path",
                "trusted_root",
                "expected_uid",
                "expected_gid",
            ),
        )
        result = self._build_result()
        with mock.patch.object(
            build_module, "read_active_policy", return_value="b" * 64
        ) as active, mock.patch.object(
            build_module, "_revalidate_artifact_manifest"
        ) as artifacts, self.assertRaisesRegex(
            GateError, "active production policy changed"
        ):
            build_module.revalidate_sealed_build_result(
                result,
                expected_policy_id="a" * 64,
                active_path=self.active,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        active.assert_called_once()
        artifacts.assert_not_called()

    def test_active_policy_mismatch_rejects_before_build(self):
        seal = self._make_seal()
        request = self._activate_and_request(seal)
        self.active.write_text("0" * 64 + "\n", encoding="ascii")
        with self._constant_patch(), mock.patch.object(
            cli_module, "build_candidate"
        ) as build:
            with self.assertRaisesRegex(GateError, "not the active policy"):
                cli_module.build_sealed_from_request(
                    request,
                    executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                    paths=self.paths,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                    geteuid=lambda: self.uid,
                )
        build.assert_not_called()


    def test_request_rejects_paths_env_extra_fields_and_noncanonical_bytes(self):
        seal = self._make_seal()
        policy_id = seal.policy_id
        for marker, (field, value) in zip(
            "4567",
            (
                ("repo", "/attacker/project"),
                ("work", "/attacker/work"),
                ("env", {"PYTHONPATH": "/attacker"}),
                ("argv", ["--as-root"]),
            ),
        ):
            request = self.runs / ("run-" + marker * 32) / "request.json"
            request.parent.mkdir(mode=0o700)
            request.write_bytes(
                cli_module._canonical_request_bytes(
                    {
                        "policy_id": policy_id,
                        "schema": "lmi-p1-build-request/v1",
                        "tag": "lmi-p1-test",
                        field: value,
                    }
                )
            )
            request.chmod(0o600)
            with self.assertRaisesRegex(GateError, "unexpected or missing"):
                cli_module._read_sealed_request(
                    request,
                    paths=self.paths,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )

        noncanonical = self.runs / ("run-" + "8" * 32) / "request.json"
        noncanonical.parent.mkdir(mode=0o700)
        noncanonical.write_text(
            json.dumps(
                {
                    "policy_id": policy_id,
                    "schema": "lmi-p1-build-request/v1",
                    "tag": "lmi-p1-test",
                },
                indent=2,
            )
            + "\n"
        )
        noncanonical.chmod(0o600)
        with self.assertRaisesRegex(GateError, "not canonical"):
            cli_module._read_sealed_request(
                noncanonical,
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_source_lock_and_manifest_pin_mismatches_fail_closed(self):
        seal = self._make_seal()
        request = self._activate_and_request(seal)
        with mock.patch.object(
            build_module, "_EXPECTED_PMBOOTSTRAP_COMMIT", "f" * 40
        ), mock.patch.object(
            build_module, "_EXPECTED_PMAPORTS_COMMIT", self.pmaports_commit
        ), self.assertRaisesRegex(
            GateError, "source lock pmbootstrap commit does not match builder"
        ):
            cli_module.build_sealed_from_request(
                request,
                executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
                geteuid=lambda: self.uid,
            )

    def test_manifest_project_commit_must_match_the_sealed_git_tree(self):
        seal = self._make_seal(manifest_project_commit="e" * 40)
        request = self._activate_and_request(seal)
        with self._constant_patch(), self.assertRaisesRegex(
            GateError, "project Git provenance mismatch"
        ):
            cli_module.build_sealed_from_request(
                request,
                executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
                geteuid=lambda: self.uid,
            )

    def test_verified_offline_cache_is_carried_into_build_authorization(self):
        seal = self._make_seal()
        request = self._activate_and_request(seal)
        expected = self._build_result()
        with self._constant_patch(), mock.patch.object(
            cli_module, "build_candidate", return_value=expected
        ) as build, mock.patch.object(
            cli_module, "revalidate_sealed_build_result", return_value=expected
        ):
            cli_module.build_sealed_from_request(
                request,
                executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
                geteuid=lambda: self.uid,
            )
        authorization = build.call_args.kwargs["_sealed_authorization"]
        self.assertEqual(authorization.offline_cache, seal.offline_cache)
        self.assertEqual(
            authorization.offline_cache_manifest["aggregate_sha256"],
            self.offline_manifest["aggregate_sha256"],
        )

    def test_dummy_kernel_lock_no_longer_passes_production_preparation(self):
        seal = self._make_seal(
            kernel_updates={
                "commit": "1" * 40,
                "remote": "https://example.invalid/kernel.git",
                "sha512": "2" * 128,
            }
        )
        request = self._activate_and_request(seal)
        with self._constant_patch(), mock.patch.object(
            cli_module, "build_candidate"
        ) as build, self.assertRaisesRegex(
            GateError, "kernel pin does not match P1"
        ):
            cli_module.build_sealed_from_request(
                request,
                executing_cli=seal.project / "scripts/lmi_p1_cli.py",
                paths=self.paths,
                expected_uid=self.uid,
                expected_gid=self.gid,
                geteuid=lambda: self.uid,
            )
        build.assert_not_called()


class OfflineCacheSeedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

    def cache(self, name: str):
        parent = self.root / name
        parent.mkdir(mode=0o700)
        return write_offline_cache(parent)

    def test_seed_is_byte_copy_isolated_from_the_immutable_seal(self):
        cache, manifest = self.cache("isolated")
        destination = self.root / "candidate-work"
        build_module._seed_verified_offline_cache(cache, destination, manifest)
        source = next((cache / "work/cache_apk_aarch64").glob("APKINDEX.*.tar.gz"))
        copied = destination / "cache_apk_aarch64" / source.name
        before = copied.read_bytes()
        self.assertNotEqual(
            (source.stat().st_dev, source.stat().st_ino),
            (copied.stat().st_dev, copied.stat().st_ino),
        )
        source.write_bytes(b"post-copy mutation\n")
        self.assertEqual(copied.read_bytes(), before)

    def test_seed_rejects_corrupt_missing_extra_and_wrong_version(self):
        mutations = {
            "corrupt": lambda cache: (
                next((cache / "work/cache_apk_aarch64").glob("APKINDEX.*.tar.gz"))
            ).write_bytes(b"corrupt\n"),
            "missing": lambda cache: (
                next((cache / "work/cache_apk_aarch64").glob("APKINDEX.*.tar.gz"))
            ).unlink(),
            "extra": lambda cache: (cache / "work/chroot_rootfs_xiaomi-lmi").mkdir(),
            "version": lambda cache: (cache / "work/version").write_bytes(b"7\n"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                cache, manifest = self.cache(label)
                mutate(cache)
                with self.assertRaises(GateError):
                    build_module._seed_verified_offline_cache(
                        cache, self.root / f"candidate-{label}", manifest
                    )

    def test_seed_rejects_symlinks_hardlinks_and_special_members(self):
        mutations = {
            "symlink": lambda cache: (
                cache / "work/cache_http/escape"
            ).symlink_to("/etc/passwd"),
            "hardlink": lambda cache: os.link(
                next((cache / "work/cache_apk_aarch64").glob("APKINDEX.*.tar.gz")),
                cache / "work/cache_http/shared",
            ),
            "fifo": lambda cache: os.mkfifo(cache / "work/cache_http/fifo", 0o600),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                cache, manifest = self.cache(label)
                mutate(cache)
                with self.assertRaises(GateError):
                    build_module._seed_verified_offline_cache(
                        cache, self.root / f"candidate-{label}", manifest
                    )


if __name__ == "__main__":
    unittest.main()
