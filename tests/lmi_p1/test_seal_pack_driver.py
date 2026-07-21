from __future__ import annotations

import contextlib
import dataclasses
import hashlib
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

import scripts.lmi_p1_root_launcher as launcher
import scripts.lmi_p1_seal_pack as driver
import scripts.lmi_p1.build as build_module
import scripts.lmi_p1.pmaports as pmaports_module
from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.seal import GitProvenance, SealSources, STREAM_MAGIC
from tests.lmi_p1.offline_cache_fixtures import offline_binding, write_offline_cache


class SealPackDriverTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.sources_root = self.root / "sources"
        self.sources_root.mkdir(mode=0o700)
        self.project = self.sources_root / "project"
        self.pmbootstrap = self.sources_root / "pmbootstrap"
        self.pmaports = self.sources_root / "pmaports"
        for repository in (self.project, self.pmbootstrap, self.pmaports):
            repository.mkdir(mode=0o755)

        (self.project / "scripts").mkdir()
        (self.project / "scripts/lmi_p1_cli.py").write_text(
            "raise SystemExit('fixture only')\n", encoding="utf-8"
        )
        (self.project / ".gitignore").write_text(
            "ignored.input\n", encoding="utf-8"
        )
        (self.pmbootstrap / "pmbootstrap.py").write_text(
            "#!/usr/bin/python3\nfrom pmb import main\nraise SystemExit(main())\n",
            encoding="utf-8",
        )
        (self.pmbootstrap / "pmbootstrap.py").chmod(0o755)
        (self.pmbootstrap / "pmb").mkdir()
        (self.pmbootstrap / "pmb/__init__.py").write_text(
            '# fixture\n__version__ = "3.11.1"\n', encoding="utf-8"
        )
        (self.pmbootstrap / ".gitignore").write_text(
            "ignored.input\n", encoding="utf-8"
        )
        (self.pmaports / "pmaports.cfg").write_text(
            "[pmaports]\n", encoding="utf-8"
        )
        (self.pmaports / ".gitignore").write_text(
            "ignored-stage.txt\n", encoding="utf-8"
        )
        initramfs = self.pmaports / "main/postmarketos-initramfs"
        initramfs.mkdir(parents=True)
        (initramfs / "APKBUILD").write_text(
            "pkgname=postmarketos-initramfs\npkgrel=0\n", encoding="utf-8"
        )
        (initramfs / "init_2nd.sh").write_text(
            "#!/bin/sh\nexec switch_root /sysroot /sbin/init\n", encoding="utf-8"
        )
        (initramfs / "init_2nd.sh").chmod(0o755)
        (initramfs / "init_functions.sh").write_text(
            "fixture_base() { :; }\n", encoding="utf-8"
        )
        self.offline_cache, offline_manifest = write_offline_cache(self.sources_root)

        self._init_repository(
            self.pmbootstrap,
            "https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git",
        )
        self._init_repository(
            self.pmaports,
            "https://gitlab.postmarketos.org/postmarketOS/pmaports.git",
        )
        self._write_valid_pmaports_stage()
        self._seal_git_admin(self.pmbootstrap, "pmbootstrap")
        self._seal_git_admin(self.pmaports, "pmaports")

        self.authorized_key = self.sources_root / "authorized_key.pub"
        self.key_bytes = b"ssh-ed25519 AAAA_DRIVER_PRIVATE_FIXTURE lmi-driver-test\n"
        self.authorized_key.write_bytes(self.key_bytes)
        self.source_lock = self.sources_root / "source-lock.json"
        self.lock = {
            "schema": "lmi-source-lock/v3",
            "offline_cache": offline_binding(self.offline_cache, offline_manifest),
            "pmbootstrap": {
                **self._git_provenance(self.pmbootstrap),
                "version": "3.11.1",
                "entrypoint_sha256": hashlib.sha256(
                    (self.pmbootstrap / "pmbootstrap.py").read_bytes()
                ).hexdigest(),
            },
            "pmaports": self._git_provenance(self.pmaports),
        }
        self._write_lock()
        project_lock = self.project / "config/lmi-p1/source-lock.json"
        project_lock.parent.mkdir(parents=True)
        project_lock.write_bytes(self.source_lock.read_bytes())
        self._init_repository(
            self.project,
            "https://github.com/jian45154/redmi-k30-pro-postmarketos.git",
        )
        self._seal_git_admin(self.project, "project")
        self.sources = SealSources(
            project=self.project,
            pmbootstrap=self.pmbootstrap,
            pmaports=self.pmaports,
            offline_cache=self.offline_cache,
            authorized_key=self.authorized_key,
            source_lock=self.source_lock,
        )
        self.outputs = self.root / "outputs"
        self.outputs.mkdir(mode=0o700)

    def _git(self, repository: Path, *arguments: str) -> str:
        return subprocess.run(
            ["/usr/bin/git", "-C", str(repository), *arguments],
            check=True,
            text=True,
            capture_output=True,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.root),
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
            },
        ).stdout.strip()

    def _init_repository(self, repository: Path, remote: str) -> None:
        self._git(repository, "init", "-q")
        self._git(repository, "config", "user.name", "LMI seal driver fixture")
        self._git(repository, "config", "user.email", "seal-driver@example.invalid")
        self._git(repository, "remote", "add", "origin", remote)
        self._git(repository, "add", "-A")
        self._git(repository, "commit", "-q", "-m", "fixture")

    def _seal_git_admin(self, repository: Path, label: str) -> None:
        commit = self._git(repository, "rev-parse", "HEAD")
        git_dir = repository / ".git"
        for child in tuple(git_dir.iterdir()):
            if child.name in driver._GIT_ADMIN_TOP:
                continue
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child)
            else:
                child.unlink()
        refs = git_dir / "refs"
        if refs.exists():
            shutil.rmtree(refs)
        (refs / "heads").mkdir(parents=True)
        (refs / "tags").mkdir()
        (git_dir / "HEAD").write_text(commit + "\n", encoding="ascii")
        (git_dir / "config").write_bytes(driver._canonical_git_config(label))
        for path in (git_dir, git_dir / "objects", refs, refs / "heads", refs / "tags"):
            path.chmod(0o755)
        for path in (git_dir / "HEAD", git_dir / "config", git_dir / "index"):
            path.chmod(0o644)

    def _write_valid_pmaports_stage(self) -> None:
        patched_root = self.pmaports / "main/postmarketos-initramfs"
        (patched_root / "APKBUILD").write_text(
            "pkgname=postmarketos-initramfs\npkgrel=1\n", encoding="utf-8"
        )
        (patched_root / "init_2nd.sh").write_text(
            "#!/bin/sh\nprintf transition-ready\n"
            "exec switch_root /sysroot /sbin/init\n",
            encoding="utf-8",
        )
        (patched_root / "init_functions.sh").write_text(
            "fixture_base() { :; }\nfixture_stage() { :; }\n", encoding="utf-8"
        )
        deviceinfo = (
            self.pmaports
            / "device/downstream/device-xiaomi-lmi/deviceinfo"
        )
        deviceinfo.parent.mkdir(parents=True)
        deviceinfo.write_text(
            'deviceinfo_rootfs_image_sector_size="4096"\n', encoding="utf-8"
        )
        device_apkbuild = deviceinfo.parent / "APKBUILD"
        device_apkbuild.write_text("pkgname=device-xiaomi-lmi\n", encoding="utf-8")
        kernel_apkbuild = (
            self.pmaports / "device/downstream/linux-xiaomi-lmi/APKBUILD"
        )
        kernel_apkbuild.parent.mkdir(parents=True)
        kernel_apkbuild.write_text("pkgname=linux-xiaomi-lmi\n", encoding="utf-8")
        stage = {
            "commit": self._git(self.pmaports, "rev-parse", "HEAD"),
            "device/downstream/device-xiaomi-lmi/APKBUILD": hashlib.sha256(
                device_apkbuild.read_bytes()
            ).hexdigest(),
            "device/downstream/device-xiaomi-lmi/deviceinfo": hashlib.sha256(
                deviceinfo.read_bytes()
            ).hexdigest(),
            "device/downstream/linux-xiaomi-lmi/APKBUILD": hashlib.sha256(
                kernel_apkbuild.read_bytes()
            ).hexdigest(),
            "main/postmarketos-initramfs/APKBUILD": hashlib.sha256(
                (patched_root / "APKBUILD").read_bytes()
            ).hexdigest(),
            "main/postmarketos-initramfs/init_2nd.sh": hashlib.sha256(
                (patched_root / "init_2nd.sh").read_bytes()
            ).hexdigest(),
            "main/postmarketos-initramfs/init_functions.sh": hashlib.sha256(
                (patched_root / "init_functions.sh").read_bytes()
            ).hexdigest(),
        }
        (self.pmaports / ".lmi-p1-stage.json").write_text(
            json.dumps(stage, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _git_provenance(self, repository: Path) -> dict[str, str]:
        return {
            "remote": self._git(repository, "remote", "get-url", "origin"),
            "commit": self._git(repository, "rev-parse", "HEAD"),
            "tree": self._git(repository, "rev-parse", "HEAD^{tree}"),
        }

    def _write_lock(self) -> None:
        self.source_lock.write_text(
            json.dumps(self.lock, sort_keys=True) + "\n", encoding="utf-8"
        )
        self.source_lock.chmod(0o644)

    def _assert_no_temporary(self) -> None:
        self.assertEqual(
            [path.name for path in self.outputs.iterdir() if ".tmp-" in path.name],
            [],
        )

    def _stage_manifest(self, repository: Path) -> dict[str, str]:
        return json.loads(
            (repository / ".lmi-p1-stage.json").read_text(encoding="utf-8")
        )

    def _write_stage_manifest(
        self, repository: Path, manifest: dict[str, str]
    ) -> None:
        (repository / ".lmi-p1-stage.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    def _copy_pmaports(self, name: str) -> Path:
        destination = self.root / name
        shutil.copytree(self.pmaports, destination, symlinks=True)
        return destination

    def _build_stage_accepts(self, repository: Path) -> bool:
        runtime = Path(tempfile.mkdtemp(prefix="build-runtime-", dir=self.root))
        runtime.chmod(0o700)
        token = build_module._PRIVATE_ENVIRONMENT_ROOT.set(runtime)
        try:
            with mock.patch.object(
                build_module,
                "_EXPECTED_PMAPORTS_COMMIT",
                self.lock["pmaports"]["commit"],
            ):
                build_module._validate_staged_pmaports_self(repository)
        except GateError:
            return False
        finally:
            build_module._PRIVATE_ENVIRONMENT_ROOT.reset(token)
        return True

    def _pack_stage_accepts(self, repository: Path, name: str) -> bool:
        output = self.outputs / f"{name}.stream"
        sources = dataclasses.replace(self.sources, pmaports=repository)
        try:
            driver.pack_seal(output, sources, 13)
        except GateError:
            self.assertFalse(os.path.lexists(output))
            self._assert_no_temporary()
            return False
        return True

    def test_pack_derives_provenance_and_publishes_exact_v3_stream(self):
        output = self.outputs / "seal.stream"
        policy_id = driver.pack_seal(output, self.sources, 9)

        self.assertRegex(policy_id, r"^[0-9a-f]{64}$")
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.stat().st_nlink, 1)
        with output.open("rb") as stream:
            self.assertEqual(stream.read(len(STREAM_MAGIC)), STREAM_MAGIC)
            manifest_length = int.from_bytes(stream.read(8), "big")
            manifest_payload = stream.read(manifest_length)
        manifest = json.loads(manifest_payload)
        self.assertEqual(hashlib.sha256(manifest_payload).hexdigest(), policy_id)
        self.assertEqual(manifest["schema"], 3)
        self.assertEqual(manifest["provenance"]["project"], self._git_provenance(self.project))
        self.assertEqual(manifest["provenance"]["pmbootstrap"], self.lock["pmbootstrap"])
        self.assertEqual(manifest["provenance"]["pmaports"], self.lock["pmaports"])
        self.assertEqual(manifest["provenance"]["generation"], 9)
        self._assert_no_temporary()

    def test_request_is_exact_launcher_canonical_frame(self):
        output = self.outputs / "request.frame"
        policy_id = "a" * 64
        driver.create_request(output, policy_id, "reviewed-01")

        expected = {
            "policy_id": policy_id,
            "schema": launcher.REQUEST_SCHEMA,
            "tag": "reviewed-01",
        }
        self.assertEqual(output.read_bytes(), launcher.encode_request(expected))
        self.assertEqual(launcher.parse_request(io.BytesIO(output.read_bytes())), expected)
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        self.assertEqual(output.stat().st_nlink, 1)

    def test_partial_pack_failure_leaves_no_output_or_temporary(self):
        output = self.outputs / "partial.stream"

        def fail(stream, *_arguments, **_keywords):
            stream.write(b"partial-sensitive-bytes")
            raise GateError("hostile fixture stopped packing")

        with mock.patch.object(driver.seal, "pack_seal_stream", side_effect=fail):
            with self.assertRaisesRegex(GateError, "hostile fixture"):
                driver.pack_seal(output, self.sources, 2)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_generic_pack_failure_leaves_no_output_or_temporary(self):
        output = self.outputs / "generic-failure.stream"

        def fail(stream, *_arguments, **_keywords):
            stream.write(b"private-partial")
            raise RuntimeError("generic fixture failure")

        with mock.patch.object(driver.seal, "pack_seal_stream", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "generic fixture"):
                driver.pack_seal(output, self.sources, 2)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_keyboard_interrupt_after_partial_private_write_cleans_every_name(self):
        output = self.outputs / "interrupt.stream"

        def interrupt(stream, *_arguments, **_keywords):
            stream.write(b"partial-private-interrupt-bytes")
            raise KeyboardInterrupt()

        with mock.patch.object(
            driver.seal, "pack_seal_stream", side_effect=interrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                driver.pack_seal(output, self.sources, 2)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_interrupt_immediately_after_rename_removes_owned_publication(self):
        output = self.outputs / "post-rename-interrupt.frame"
        original = driver._rename_noreplace

        def rename_then_interrupt(
            parent_fd: int, temporary: str, destination: str
        ) -> None:
            original(parent_fd, temporary, destination)
            raise KeyboardInterrupt()

        with mock.patch.object(
            driver, "_rename_noreplace", side_effect=rename_then_interrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                driver.create_request(output, "4" * 64, "reviewed")
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_sigterm_during_private_write_is_caught_inside_cleanup_boundary(self):
        output = self.outputs / "sigterm.frame"
        program = "\n".join(
            (
                "import os, signal",
                "from pathlib import Path",
                "from scripts.lmi_p1.common import GateError",
                "import scripts.lmi_p1_seal_pack as driver",
                f"output = Path({str(output)!r})",
                "def writer(stream):",
                "    stream.write(b'partial-private-sigterm-bytes')",
                "    os.kill(os.getpid(), signal.SIGTERM)",
                "    return None",
                "try:",
                "    driver._publish_new(output, writer)",
                "except GateError as error:",
                "    if 'termination signal' not in str(error):",
                "        raise",
                "else:",
                "    raise SystemExit('SIGTERM did not interrupt publication')",
            )
        )
        result = subprocess.run(
            ["/usr/bin/python3", "-B", "-c", program],
            cwd=Path(driver.__file__).resolve().parents[1],
            text=True,
            capture_output=True,
            check=False,
            env={
                "HOME": str(self.root),
                "PATH": "/usr/bin:/bin",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_missing_renameat2_fails_closed_and_cleans_temporary(self):
        output = self.outputs / "no-rename.frame"

        class NoRenameAt2:
            pass

        with mock.patch.object(driver.ctypes, "CDLL", return_value=NoRenameAt2()):
            with self.assertRaisesRegex(GateError, "no-replace publication is unavailable"):
                driver.create_request(output, "e" * 64, "reviewed")
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_parent_fsync_failure_removes_own_publication(self):
        output = self.outputs / "fsync-failure.frame"
        original = driver.os.fsync
        failed = False

        def fail_directory_fsync(descriptor: int) -> None:
            nonlocal failed
            if stat.S_ISDIR(os.fstat(descriptor).st_mode) and not failed:
                failed = True
                raise OSError(5, "fixture parent fsync failure")
            original(descriptor)

        with mock.patch.object(driver.os, "fsync", side_effect=fail_directory_fsync):
            with self.assertRaisesRegex(OSError, "fixture parent fsync failure"):
                driver.create_request(output, "f" * 64, "reviewed")
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_final_parent_revalidation_failure_removes_own_publication(self):
        output = self.outputs / "parent-revalidation.frame"
        original = driver._stable_parent
        calls = 0

        def fail_final(parent, descriptor, expected):
            nonlocal calls
            calls += 1
            original(parent, descriptor, expected)
            if calls == 3:
                raise GateError("fixture final parent revalidation failure")

        with mock.patch.object(driver, "_stable_parent", side_effect=fail_final):
            with self.assertRaisesRegex(GateError, "final parent revalidation"):
                driver.create_request(output, "1" * 64, "reviewed")
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_preexisting_and_concurrent_symlink_outputs_are_never_replaced(self):
        existing = self.outputs / "existing.frame"
        existing.write_bytes(b"keep-existing\n")
        with self.assertRaisesRegex(GateError, "already exists"):
            driver.create_request(existing, "b" * 64, "reviewed")
        self.assertEqual(existing.read_bytes(), b"keep-existing\n")

        raced = self.outputs / "raced.frame"
        original = driver._rename_noreplace

        def install_symlink(parent_fd: int, temporary: str, destination: str) -> None:
            os.symlink("attacker-target", destination, dir_fd=parent_fd)
            original(parent_fd, temporary, destination)

        with mock.patch.object(driver, "_rename_noreplace", side_effect=install_symlink):
            with self.assertRaisesRegex(GateError, "appeared concurrently"):
                driver.create_request(raced, "c" * 64, "reviewed")
        self.assertTrue(raced.is_symlink())
        self.assertEqual(os.readlink(raced), "attacker-target")
        self._assert_no_temporary()

    def test_parent_replacement_race_cleans_only_its_own_publication(self):
        parent = self.outputs
        moved = self.root / "moved-outputs"
        output = parent / "request.frame"
        original = driver._rename_noreplace

        def replace_parent(parent_fd: int, temporary: str, destination: str) -> None:
            parent.rename(moved)
            parent.mkdir(mode=0o700)
            original(parent_fd, temporary, destination)

        with mock.patch.object(driver, "_rename_noreplace", side_effect=replace_parent):
            with self.assertRaisesRegex(GateError, "parent was replaced"):
                driver.create_request(output, "d" * 64, "reviewed")
        self.assertFalse(os.path.lexists(output))
        self.assertFalse(os.path.lexists(moved / "request.frame"))
        self.assertEqual(list(moved.iterdir()), [])

    def test_dirty_untracked_and_ignored_project_or_pmbootstrap_fail_closed(self):
        cases = (
            (self.project, "scripts/lmi_p1_cli.py", "changed\n", "modified"),
            (self.project, "untracked.input", "untracked\n", "untracked"),
            (self.pmbootstrap, "ignored.input", "ignored\n", "ignored"),
        )
        for index, (repository, relative, payload, kind) in enumerate(cases):
            with self.subTest(kind=kind):
                path = repository / relative
                original = path.read_bytes() if path.exists() else None
                path.write_text(payload, encoding="utf-8")
                output = self.outputs / f"dirty-{index}.stream"
                try:
                    with self.assertRaisesRegex(
                        GateError, "physical (path inventory|bytes or mode)"
                    ):
                        driver.pack_seal(output, self.sources, 3)
                    self.assertFalse(os.path.lexists(output))
                    self._assert_no_temporary()
                finally:
                    if original is None:
                        path.unlink()
                    else:
                        path.write_bytes(original)

    def test_local_path_origin_and_source_lock_provenance_drift_are_rejected(self):
        output = self.outputs / "local.stream"
        original_remote = self._git(self.project, "remote", "get-url", "origin")
        self._git(self.project, "remote", "set-url", "origin", str(self.root / "local"))
        try:
            with self.assertRaisesRegex(GateError, "canonical safe profile"):
                driver.pack_seal(output, self.sources, 4)
        finally:
            self._git(self.project, "remote", "set-url", "origin", original_remote)
        self.assertFalse(os.path.lexists(output))

        self.lock["pmbootstrap"]["tree"] = "f" * 40
        self._write_lock()
        with self.assertRaisesRegex(GateError, "external source-lock bytes differ"):
            driver.pack_seal(output, self.sources, 4)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_provenance_change_after_packing_removes_private_temporary(self):
        output = self.outputs / "drift.stream"
        actual = driver.derive_seal_provenance(self.sources, 5)
        drifted = dataclasses.replace(
            actual,
            project=GitProvenance(
                remote=actual.project.remote,
                commit="e" * 40,
                tree=actual.project.tree,
            ),
        )
        with mock.patch.object(
            driver, "derive_seal_provenance", side_effect=[actual, drifted]
        ):
            with self.assertRaisesRegex(GateError, "changed while packing"):
                driver.pack_seal(output, self.sources, 5)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_hardlinked_input_fails_before_output_allocation(self):
        alias = self.sources_root / "authorized-key-hardlink"
        os.link(self.authorized_key, alias)
        self.addCleanup(alias.unlink)
        output = self.outputs / "hardlink.stream"
        with self.assertRaisesRegex(GateError, "unsafe type or link count"):
            driver.pack_seal(output, self.sources, 6)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_xattr_input_fails_before_output_allocation(self):
        try:
            os.setxattr(self.authorized_key, "user.lmi-hostile", b"present")
        except (AttributeError, OSError) as error:
            self.skipTest(f"fixture filesystem has no user xattr support: {error}")
        output = self.outputs / "xattr.stream"
        with self.assertRaisesRegex(GateError, "has xattrs"):
            driver.pack_seal(output, self.sources, 6)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_cli_error_does_not_echo_authorized_key_bytes(self):
        config = self.project / ".git/config"
        config.write_bytes(
            config.read_bytes().replace(
                driver._AUTHORITATIVE_REMOTES["project"].encode("ascii"),
                b"https://TOKEN_SECRET@github.com/jian45154/redmi-k30-pro-postmarketos.git",
            )
        )
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), mock.patch.object(
            driver, "_require_cli_runtime"
        ):
            result = driver.main(
                [
                    "pack",
                    "--project",
                    str(self.project),
                    "--pmbootstrap",
                    str(self.pmbootstrap),
                    "--pmaports",
                    str(self.pmaports),
                    "--offline-cache",
                    str(self.offline_cache),
                    "--authorized-key",
                    str(self.authorized_key),
                    "--source-lock",
                    str(self.source_lock),
                    "--generation",
                    "7",
                    "--output",
                    str(self.outputs / "private.stream"),
                ]
            )
        self.assertEqual(result, 1)
        self.assertNotIn(self.key_bytes.decode("ascii").strip(), stderr.getvalue())
        self.assertNotIn("TOKEN_SECRET", stderr.getvalue())
        self.assertFalse(os.path.lexists(self.outputs / "private.stream"))
        self._assert_no_temporary()

    def test_cli_requires_and_accepts_exact_isolated_python_flags(self):
        script = Path(driver.__file__).resolve(strict=True)
        rejected = self.outputs / "runtime-rejected.frame"
        result = subprocess.run(
            [
                "/usr/bin/python3",
                str(script),
                "request",
                "--policy-id",
                "2" * 64,
                "--tag",
                "reviewed",
                "--output",
                str(rejected),
            ],
            text=True,
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(self.root)},
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("requires /usr/bin/python3 -I -S -B", result.stderr)
        self.assertFalse(os.path.lexists(rejected))

        accepted = self.outputs / "runtime-accepted.frame"
        result = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-S",
                "-B",
                str(script),
                "request",
                "--policy-id",
                "3" * 64,
                "--tag",
                "reviewed",
                "--output",
                str(accepted),
            ],
            text=True,
            capture_output=True,
            check=False,
            env={"PATH": "/usr/bin:/bin", "PYTHONPATH": str(self.root)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "request-created\n")
        self.assertEqual(
            launcher.parse_request(io.BytesIO(accepted.read_bytes()))["policy_id"],
            "3" * 64,
        )

    def test_authoritative_remote_parser_rejects_every_noncanonical_form(self):
        for label, expected in driver._AUTHORITATIVE_REMOTES.items():
            self.assertEqual(driver._authoritative_remote(expected, label), expected)
            parsed = expected.removeprefix("https://")
            hostile = (
                expected + "?token=QUERY_SECRET",
                expected + "#FRAGMENT_SECRET",
                "https://user:AUTH_SECRET@" + parsed,
                expected.replace("https://", "ssh://"),
                expected.replace("https://", "https://LOCALHOST@"),
                expected.replace("https://", "https://", 1).replace(".git", "%2egit"),
                expected.removesuffix(".git") + ".GIT",
                expected.replace("https://", "HTTPS://"),
                expected.replace("/", "\\", 1),
                expected + "\nCONTROL_SECRET",
                "https://[malformed-ipv6/REMOTE_SECRET.git",
            )
            for value in hostile:
                with self.subTest(label=label, value=value):
                    with self.assertRaisesRegex(GateError, "canonical URL") as caught:
                        driver._authoritative_remote(value, label)
                    self.assertNotIn("SECRET", str(caught.exception))

    def test_hostile_clean_filter_cannot_hide_raw_tracked_bytes_or_execute_in_packer(self):
        marker = self.root / "filter-executed"
        helper = self.root / "clean-filter"
        helper.write_text(
            "#!/bin/sh\n"
            f"printf invoked > {marker}\n"
            f"exec /usr/bin/git -C {self.project} show HEAD:scripts/lmi_p1_cli.py\n",
            encoding="utf-8",
        )
        helper.chmod(0o700)
        info = self.project / ".git/info"
        info.mkdir()
        (info / "attributes").write_text(
            "scripts/lmi_p1_cli.py filter=mask\n", encoding="utf-8"
        )
        self._git(self.project, "config", "filter.mask.clean", str(helper))
        target = self.project / "scripts/lmi_p1_cli.py"
        target.write_bytes(target.read_bytes().replace(b"fixture", b"hostile"))

        self.assertEqual(self._git(self.project, "status", "--porcelain"), "")
        self.assertTrue(marker.exists())
        marker.unlink()
        output = self.outputs / "filter.stream"
        with self.assertRaisesRegex(GateError, "Git administration|Git config"):
            driver.pack_seal(output, self.sources, 14)
        self.assertFalse(marker.exists())
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_git_admin_profile_rejects_private_or_behavioral_state(self):
        cases = {
            "reflog": lambda git: (git / "logs").mkdir(),
            "hooks": lambda git: (git / "hooks").mkdir(),
            "attributes": lambda git: (git / "info").mkdir(),
            "shallow": lambda git: (git / "shallow").write_text(
                self.lock["pmaports"]["commit"] + "\n", encoding="ascii"
            ),
            "packed-refs": lambda git: (git / "packed-refs").write_text(
                "# pack-refs with: peeled fully-peeled sorted\n", encoding="ascii"
            ),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                repository = self._copy_pmaports(f"admin-{name}")
                mutate(repository / ".git")
                output = self.outputs / f"admin-{name}.stream"
                sources = dataclasses.replace(self.sources, pmaports=repository)
                with self.assertRaisesRegex(GateError, "privacy-minimal"):
                    driver.pack_seal(output, sources, 15)
                self.assertFalse(os.path.lexists(output))
                self._assert_no_temporary()

    def test_git_config_rejects_extra_remote_credentials_include_and_rewrites(self):
        additions = (
            '[remote "backup"]\n\turl = https://TOKEN@example.invalid/private.git\n',
            "[credential]\n\thelper = store\n",
            "[http]\n\textraHeader = Authorization: TOKEN_SECRET\n",
            '[url "https://TOKEN@example.invalid/"]\n\tinsteadOf = https://github.com/\n',
            "[include]\n\tpath = /tmp/TOKEN_SECRET\n",
            "[filter \"mask\"]\n\tclean = /tmp/TOKEN_SECRET\n",
            "[extensions]\n\tworktreeConfig = true\n",
        )
        for index, addition in enumerate(additions):
            with self.subTest(index=index):
                repository = self._copy_pmaports(f"config-{index}")
                config = repository / ".git/config"
                config.write_bytes(config.read_bytes() + addition.encode("ascii"))
                output = self.outputs / f"config-{index}.stream"
                sources = dataclasses.replace(self.sources, pmaports=repository)
                with self.assertRaisesRegex(GateError, "canonical safe profile") as caught:
                    driver.pack_seal(output, sources, 16)
                self.assertNotIn("TOKEN_SECRET", str(caught.exception))
                self.assertFalse(os.path.lexists(output))
                self._assert_no_temporary()

    def test_external_source_lock_must_equal_tracked_physical_and_head_bytes(self):
        self.source_lock.write_bytes(self.source_lock.read_bytes() + b"\n")
        output = self.outputs / "lock-drift.stream"
        with self.assertRaisesRegex(GateError, "external source-lock bytes differ"):
            driver.pack_seal(output, self.sources, 17)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_filemode_false_and_tracked_mode_change_are_rejected(self):
        target = self.project / "scripts/lmi_p1_cli.py"
        target.chmod(0o755)
        config = self.project / ".git/config"
        config.write_bytes(config.read_bytes().replace(b"filemode = true", b"filemode = false"))
        self.assertEqual(self._git(self.project, "status", "--porcelain"), "")
        output = self.outputs / "filemode.stream"
        with self.assertRaisesRegex(GateError, "canonical safe profile"):
            driver.pack_seal(output, self.sources, 18)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_raw_mode_change_is_rejected_even_with_canonical_git_config(self):
        (self.project / "scripts/lmi_p1_cli.py").chmod(0o755)
        output = self.outputs / "raw-mode.stream"
        with self.assertRaisesRegex(GateError, "physical bytes or mode"):
            driver.pack_seal(output, self.sources, 19)
        self.assertFalse(os.path.lexists(output))
        self._assert_no_temporary()

    def test_build_and_pack_share_stage_accept_reject_contract(self):
        valid = self._copy_pmaports("stage-valid")
        self.assertTrue(self._build_stage_accepts(valid))
        self.assertTrue(self._pack_stage_accepts(valid, "stage-valid"))

        def arbitrary_tracked(repository: Path) -> None:
            with (repository / "pmaports.cfg").open("ab") as stream:
                stream.write(b"arbitrary=true\n")

        def extra_ignored(repository: Path) -> None:
            (repository / "ignored-stage.txt").write_text(
                "ignored but physical\n", encoding="utf-8"
            )

        def index_change(repository: Path) -> None:
            arbitrary_tracked(repository)
            self._git(repository, "add", "pmaports.cfg")

        def manifest_tamper(repository: Path) -> None:
            manifest = self._stage_manifest(repository)
            manifest["main/postmarketos-initramfs/init_functions.sh"] = "f" * 64
            self._write_stage_manifest(repository, manifest)

        def symlink_member(repository: Path) -> None:
            target = repository / "device/downstream/device-xiaomi-lmi/deviceinfo"
            target.unlink()
            target.symlink_to("../../../pmaports.cfg")
            manifest = self._stage_manifest(repository)
            manifest["device/downstream/device-xiaomi-lmi/deviceinfo"] = hashlib.sha256(
                b"../../../pmaports.cfg"
            ).hexdigest()
            self._write_stage_manifest(repository, manifest)

        def hardlink_member(repository: Path) -> None:
            target = repository / "device/downstream/device-xiaomi-lmi/deviceinfo"
            target.unlink()
            os.link(repository / "pmaports.cfg", target)
            manifest = self._stage_manifest(repository)
            manifest["device/downstream/device-xiaomi-lmi/deviceinfo"] = hashlib.sha256(
                target.read_bytes()
            ).hexdigest()
            self._write_stage_manifest(repository, manifest)

        def mode_member(repository: Path) -> None:
            (repository / "device/downstream/device-xiaomi-lmi/deviceinfo").chmod(0o755)

        mutations = {
            "arbitrary-tracked": arbitrary_tracked,
            "extra-ignored": extra_ignored,
            "index-change": index_change,
            "manifest-tamper": manifest_tamper,
            "symlink-member": symlink_member,
            "hardlink-member": hardlink_member,
            "mode-member": mode_member,
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                repository = self._copy_pmaports(f"stage-{name}")
                mutate(repository)
                self.assertFalse(self._build_stage_accepts(repository))
                self.assertFalse(self._pack_stage_accepts(repository, f"stage-{name}"))

    def test_build_and_pack_both_reject_stage_xattrs(self):
        repository = self._copy_pmaports("stage-xattr")
        member = repository / "device/downstream/device-xiaomi-lmi/deviceinfo"
        try:
            os.setxattr(member, "user.lmi-hostile", b"present")
        except (AttributeError, OSError) as error:
            self.skipTest(f"fixture filesystem has no user xattr support: {error}")
        self.assertFalse(self._build_stage_accepts(repository))
        self.assertFalse(self._pack_stage_accepts(repository, "stage-xattr"))

    def test_build_and_pack_both_reject_post_inventory_stage_race(self):
        original = pmaports_module._physical_tree

        def reject_for(repository: Path, name: str, build: bool) -> bool:
            raced = False

            def mutate_after_inventory(root: Path, label: str):
                nonlocal raced
                result = original(root, label)
                if Path(root) == repository and not raced:
                    raced = True
                    member = root / "device/downstream/device-xiaomi-lmi/deviceinfo"
                    member.write_text(
                        'deviceinfo_rootfs_image_sector_size="512"\n',
                        encoding="utf-8",
                    )
                return result

            with mock.patch.object(
                pmaports_module, "_physical_tree", side_effect=mutate_after_inventory
            ):
                if build:
                    return self._build_stage_accepts(repository)
                return self._pack_stage_accepts(repository, name)

        build_repository = self._copy_pmaports("stage-race-build")
        pack_repository = self._copy_pmaports("stage-race-pack")
        self.assertFalse(reject_for(build_repository, "stage-race-build", True))
        self.assertFalse(reject_for(pack_repository, "stage-race-pack", False))


if __name__ == "__main__":
    unittest.main()
