from __future__ import annotations

import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts.lmi_p1.seal import (
    GitProvenance,
    PmbootstrapProvenance,
    SealProvenance,
    SealSources,
    activate_policy,
    create_seal,
    pack_seal_stream,
)
import scripts.lmi_p1_root_launcher as launcher
import scripts.lmi_p1_seal_installer as installer
from tests.lmi_p1.offline_cache_fixtures import offline_binding, write_offline_cache


class _ExecCalled(Exception):
    pass


class RootLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()
        sources_root = self.root / "sources"
        sources_root.mkdir(mode=0o700)
        project = sources_root / "project"
        pmbootstrap = sources_root / "pmbootstrap"
        pmaports = sources_root / "pmaports"
        for directory in (project, pmbootstrap, pmaports):
            directory.mkdir(mode=0o755)
        (project / "scripts").mkdir(mode=0o755)
        (project / "scripts/lmi_p1_cli.py").write_text(
            "raise SystemExit('test-only')\n", encoding="utf-8"
        )
        (project / "bound-input").write_text("project\n", encoding="utf-8")
        entrypoint = pmbootstrap / "pmbootstrap.py"
        entrypoint.write_text("print('pmb')\n", encoding="utf-8")
        (pmaports / "pmaports.cfg").write_text("[pmaports]\n", encoding="utf-8")
        (pmaports / "nested").mkdir(mode=0o755)
        (pmaports / "nested/target").write_text("target\n", encoding="utf-8")
        (pmaports / "nested/target.alias").symlink_to("./target")
        key = sources_root / "authorized_key.pub"
        key.write_text("ssh-ed25519 AAAATEST launcher-test\n", encoding="utf-8")
        offline_cache, offline_manifest = write_offline_cache(sources_root)
        self.provenance = SealProvenance(
            generation=7,
            project=GitProvenance(
                "https://example.invalid/project.git", "1" * 40, "2" * 40
            ),
            pmbootstrap=PmbootstrapProvenance(
                "https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git",
                "3" * 40,
                "4" * 40,
                "3.11.1",
                hashlib.sha256(entrypoint.read_bytes()).hexdigest(),
            ),
            pmaports=GitProvenance(
                "https://gitlab.postmarketos.org/postmarketOS/pmaports.git",
                "5" * 40,
                "6" * 40,
            ),
        )
        source_lock = sources_root / "source-lock.json"
        source_lock.write_text(
            json.dumps(
                {
                    "schema": "lmi-source-lock/v3",
                    "offline_cache": offline_binding(
                        offline_cache, offline_manifest
                    ),
                    "pmbootstrap": {
                        "remote": self.provenance.pmbootstrap.remote,
                        "commit": self.provenance.pmbootstrap.commit,
                        "tree": self.provenance.pmbootstrap.tree,
                        "version": self.provenance.pmbootstrap.version,
                        "entrypoint_sha256": self.provenance.pmbootstrap.entrypoint_sha256,
                    },
                    "pmaports": {
                        "remote": self.provenance.pmaports.remote,
                        "commit": self.provenance.pmaports.commit,
                        "tree": self.provenance.pmaports.tree,
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        for path in sources_root.rglob("*"):
            if path.is_file():
                path.chmod(0o644)

        self.seals = self.root / "seals"
        self.seals.mkdir(mode=0o700)
        self.sources = SealSources(
            project, pmbootstrap, pmaports, key, source_lock, offline_cache
        )
        self.seal = create_seal(
            self.seals,
            self.sources,
            self.provenance,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        policy = self.root / "policy"
        policy.mkdir(mode=0o700)
        self.active = policy / "active-policy"
        self.active.write_text(self.seal.policy_id + "\n", encoding="ascii")
        self.active.chmod(0o600)
        self.runs = self.root / "runs"
        self.runs.mkdir(mode=0o700)
        self.python = self.root / "python3"
        self.python.write_text("test interpreter placeholder\n", encoding="utf-8")
        self.python.chmod(0o755)
        pin_root = self.root / "configuration"
        pin_root.mkdir(mode=0o700)
        self.python_pin = pin_root / "python.pin.json"
        self.python_pin.write_bytes(
            launcher.canonical_json_bytes(
                {
                    "path": str(self.python),
                    "schema": "lmi-p1-python-pin/v1",
                    "sha256": hashlib.sha256(self.python.read_bytes()).hexdigest(),
                }
            )
        )
        self.python_pin.chmod(0o600)
        self.installed_launcher = self.root / "lmi-p1-root-launcher"
        self.installed_launcher.write_text("test installed launcher\n", encoding="utf-8")
        self.installed_launcher.chmod(0o755)
        self.paths = launcher.LauncherPaths(
            active=self.active,
            seals=self.seals,
            runs=self.runs,
            python=self.python,
            python_pin=self.python_pin,
            launcher=self.installed_launcher,
            trusted_root=self.root,
        )

    def request_value(self, **updates: object) -> dict[str, object]:
        value: dict[str, object] = {
            "schema": launcher.REQUEST_SCHEMA,
            "policy_id": self.seal.policy_id,
            "tag": "lmi-p1-test-1",
        }
        value.update(updates)
        return value

    def request(self, **updates: object) -> bytes:
        return launcher.encode_request(self.request_value(**updates))

    def launch_kwargs(self, payload: bytes | None = None) -> dict[str, object]:
        framed = self.request() if payload is None else payload
        return {
            "request_fd": 0,
            "paths": self.paths,
            "expected_uid": self.uid,
            "expected_gid": self.gid,
            "executing_path": self.installed_launcher,
            "executing_interpreter": self.python,
            "getresuid": lambda: (self.uid, self.uid, self.uid),
            "getresgid": lambda: (self.gid, self.gid, self.gid),
            "setgroups": lambda _groups: None,
            "getgroups": lambda: [],
            "set_umask": lambda _mode: 0o022,
            "read_request": lambda _fd: launcher.parse_request(io.BytesIO(framed)),
            "close_fds": lambda: None,
            "normalize_signals": lambda: None,
            "normalize_rlimits": lambda: None,
            "normalize_stdin": lambda: None,
            "change_directory": lambda _path: None,
        }

    def invoke(self):
        calls: list[tuple[str, list[str], dict[str, str]]] = []
        groups = [10, 20]
        umasks: list[int] = []
        normalized: list[str] = []
        kwargs = self.launch_kwargs()
        kwargs.update(
            {
                "setgroups": lambda value: groups.__setitem__(slice(None), value),
                "getgroups": lambda: list(groups),
                "set_umask": lambda value: umasks.append(value) or 0o022,
                "close_fds": lambda: normalized.append("fds"),
                "normalize_signals": lambda: normalized.append("signals"),
                "normalize_rlimits": lambda: normalized.append("rlimits"),
                "normalize_stdin": lambda: normalized.append("stdin"),
                "change_directory": lambda path: normalized.append(f"cwd:{path}"),
                "execve": lambda path, argv, env: (
                    calls.append((path, argv, dict(env))),
                    (_ for _ in ()).throw(_ExecCalled()),
                )[-1],
            }
        )
        with self.assertRaises(_ExecCalled):
            launcher.launch(**kwargs)
        return calls, groups, umasks, normalized

    def test_execve_uses_verified_target_private_environment_and_normalized_process(self):
        with mock.patch.dict(os.environ, {"PYTHONPATH": "/attacker", "HOME": "/bad"}):
            calls, groups, umasks, normalized = self.invoke()
        self.assertEqual(groups, [])
        self.assertEqual(umasks, [0o077])
        self.assertEqual(len(calls), 1)
        executable, argv, environment = calls[0]
        cwd = next(value for value in normalized if value.startswith("cwd:"))
        run_root = Path(cwd.removeprefix("cwd:"))
        request_copy = run_root / "request.json"
        self.assertEqual(executable, str(self.python))
        self.assertEqual(
            argv,
            [
                str(self.python),
                "-I",
                "-S",
                "-B",
                "-c",
                launcher._CLI_BOOTSTRAP,
                str(self.seal.project / "scripts"),
                str(self.seal.project / "scripts/lmi_p1_cli.py"),
                "build-sealed",
                "--request",
                str(request_copy),
            ],
        )
        self.assertEqual(json.loads(request_copy.read_bytes()), self.request_value())
        self.assertEqual(environment["HOME"], str(run_root / "home"))
        self.assertEqual(environment["TMPDIR"], str(run_root / "tmp"))
        self.assertNotIn("PYTHONPATH", environment)
        self.assertEqual(
            normalized,
            ["fds", f"cwd:{run_root}", "signals", "rlimits", "stdin"],
        )

    def test_disposable_pack_install_activate_launch_pipeline(self):
        bundle = io.BytesIO()
        policy_id = pack_seal_stream(
            bundle,
            self.sources,
            self.provenance,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        isolated_seals = self.root / "pipeline-seals"
        isolated_seals.mkdir(mode=0o700)
        installed = installer._install_stream(
            io.BytesIO(bundle.getvalue()),
            seals_root=str(isolated_seals),
            expected_uid=self.uid,
            expected_gid=self.gid,
            verify_ancestry=False,
        )
        self.assertEqual(installed, policy_id)

        policy_root = self.root / "pipeline-policy"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active-policy"
        activate_policy(
            active,
            policy_id,
            seals_root=isolated_seals,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        isolated_runs = self.root / "pipeline-runs"
        isolated_runs.mkdir(mode=0o700)
        paths = launcher.LauncherPaths(
            active=active,
            seals=isolated_seals,
            runs=isolated_runs,
            python=self.python,
            python_pin=self.python_pin,
            launcher=self.installed_launcher,
            trusted_root=self.root,
        )
        payload = launcher.encode_request(
            {
                "schema": launcher.REQUEST_SCHEMA,
                "policy_id": policy_id,
                "tag": "disposable-pipeline",
            }
        )
        calls: list[tuple[str, list[str], dict[str, str]]] = []
        kwargs = self.launch_kwargs(payload)
        kwargs["paths"] = paths
        kwargs["execve"] = lambda path, argv, env: (
            calls.append((path, argv, dict(env))),
            (_ for _ in ()).throw(_ExecCalled()),
        )[-1]
        with self.assertRaises(_ExecCalled):
            launcher.launch(**kwargs)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], str(self.python))
        self.assertEqual(
            calls[0][1][-3:],
            [
                "build-sealed",
                "--request",
                str(next(isolated_runs.glob("run-*/request.json"))),
            ],
        )

    def test_offline_cache_signer_must_match_pinned_pmbootstrap_key(self):
        manifest = self.seal.manifest
        members = copy.deepcopy(manifest["members"])
        trust_key = next(
            item
            for item in members
            if str(item["path"]).startswith("pmbootstrap/pmb/data/keys/")
        )
        trust_key["sha256"] = "0" * 64
        payload = (
            self.seal.offline_cache / "offline-cache.manifest.json"
        ).read_bytes()
        with self.assertRaisesRegex(
            launcher.LauncherError, "differs from the pinned pmbootstrap"
        ):
            launcher._validate_offline_contract(
                payload,
                members,
                manifest["provenance"],
            )

    def test_standalone_launcher_requires_producer_cardinality(self):
        manifest = self.seal.manifest
        original = json.loads(
            (self.seal.offline_cache / "offline-cache.manifest.json").read_bytes()
        )
        for collection, message in (
            ("http_artifacts", "exactly one apk-tools-static"),
            ("distfiles", "exactly one kernel distfile"),
        ):
            with self.subTest(collection=collection):
                inner = copy.deepcopy(original)
                removed = inner[collection].pop()
                inner["members"] = [
                    item for item in inner["members"]
                    if item["path"] != removed["path"]
                ]
                preimage = dict(inner)
                del preimage["aggregate_sha256"]
                inner["aggregate_sha256"] = hashlib.sha256(
                    launcher.canonical_json_bytes(preimage)
                ).hexdigest()
                payload = launcher.canonical_json_bytes(inner)
                members = [
                    item for item in manifest["members"]
                    if item["path"] != f'offline-cache/{removed["path"]}'
                ]
                provenance = copy.deepcopy(manifest["provenance"])
                provenance["offline_cache"] = {
                    "aggregate_sha256": inner["aggregate_sha256"],
                    "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                    "schema": launcher.OFFLINE_CACHE_SCHEMA,
                }
                with self.assertRaisesRegex(launcher.LauncherError, message):
                    launcher._validate_offline_contract(
                        payload, members, provenance
                    )

    def test_request_parser_rejects_extra_duplicate_truncated_trailing_and_oversized(self):
        with self.assertRaisesRegex(launcher.LauncherError, "unexpected"):
            launcher.parse_request(io.BytesIO(self.request(path="/attacker")))
        duplicate_json = (
            b'{"policy_id":"'
            + self.seal.policy_id.encode("ascii")
            + b'","schema":"lmi-p1-build-request/v1","tag":"one","tag":"two"}\n'
        )
        duplicate = (
            launcher.REQUEST_MAGIC
            + len(duplicate_json).to_bytes(launcher.REQUEST_LENGTH_BYTES, "big")
            + duplicate_json
        )
        invalid = (
            duplicate,
            self.request()[:-1],
            self.request() + b"x",
            launcher.REQUEST_MAGIC + (4097).to_bytes(4, "big") + b"x" * 4097,
        )
        for payload in invalid:
            with self.subTest(payload=payload[:64]):
                with self.assertRaises(launcher.LauncherError):
                    launcher.parse_request(io.BytesIO(payload))

    def test_request_fd_rejects_pipe_and_reads_regular_file_without_offset_dependency(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        with self.assertRaisesRegex(launcher.LauncherError, "regular file"):
            launcher.parse_request_fd(read_fd)
        request_file = self.root / "request.frame"
        request_file.write_bytes(self.request())
        fd = os.open(request_file, os.O_RDONLY)
        self.addCleanup(os.close, fd)
        os.lseek(fd, 2, os.SEEK_SET)
        self.assertEqual(launcher.parse_request_fd(fd), self.request_value())

    def test_standalone_manifest_and_source_lock_provenance_are_strict(self):
        broken = copy.deepcopy(dict(self.seal.manifest))
        broken["provenance"]["project"]["tree"] = "z" * 40
        with self.assertRaisesRegex(launcher.LauncherError, "provenance"):
            launcher._validated_manifest(launcher.canonical_json_bytes(broken))
        lock = json.loads(self.seal.source_lock.read_bytes())
        lock["pmbootstrap"]["commit"] = "0" * 40
        with self.assertRaisesRegex(launcher.LauncherError, "provenance mismatch"):
            launcher._validate_source_lock(
                json.dumps(lock).encode("utf-8"), self.seal.manifest["provenance"]
            )

    def test_wrong_active_and_bit_flip_stop_before_run(self):
        self.active.write_text("0" * 64 + "\n", encoding="ascii")
        with self.assertRaisesRegex(launcher.LauncherError, "not the active"):
            launcher.launch(**self.launch_kwargs())
        self.assertEqual(list(self.runs.iterdir()), [])
        self.active.write_text(self.seal.policy_id + "\n", encoding="ascii")
        (self.seal.project / "bound-input").write_text("changed\n", encoding="utf-8")
        with self.assertRaisesRegex(
            launcher.LauncherError, "inventory|not one regular file"
        ):
            launcher.launch(**self.launch_kwargs())
        self.assertEqual(list(self.runs.iterdir()), [])

    def test_launcher_verifies_declared_symlink_and_rejects_target_mutation(self):
        link = self.seal.pmaports / "nested/target.alias"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "./target")
        launcher.verify_seal_standalone(
            self.seal.root,
            self.seal.policy_id,
            seals_root=self.seals,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

        link.unlink()
        link.symlink_to("../pmaports.cfg")
        with self.assertRaisesRegex(launcher.LauncherError, "inventory"):
            launcher.verify_seal_standalone(
                self.seal.root,
                self.seal.policy_id,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_launcher_never_descends_through_symlink_member_ancestor(self):
        nested = self.seal.pmaports / "nested"
        saved = self.seal.pmaports / "saved-nested"
        nested.rename(saved)
        nested.symlink_to("saved-nested", target_is_directory=True)
        with self.assertRaisesRegex(
            launcher.LauncherError, "inventory|not one regular file"
        ):
            launcher.verify_seal_standalone(
                self.seal.root,
                self.seal.policy_id,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_launcher_manifest_validator_rejects_symlink_chain_and_ancestor(self):
        for target, message in (
            ("/etc/passwd", "unsafe"),
            ("../../../project/scripts/lmi_p1_cli.py", "escapes"),
            ("a" * (launcher._MAX_SYMLINK_TARGET_BYTES + 1), "limits"),
        ):
            with self.subTest(target=target[:40]):
                manifest = copy.deepcopy(dict(self.seal.manifest))
                record = next(
                    item
                    for item in manifest["members"]
                    if item["path"] == "pmaports/nested/target.alias"
                )
                encoded = target.encode("utf-8")
                record.update(
                    target=target,
                    size=len(encoded),
                    sha256=hashlib.sha256(encoded).hexdigest(),
                )
                with self.assertRaisesRegex(launcher.LauncherError, message):
                    launcher._validated_manifest(
                        launcher.canonical_json_bytes(manifest)
                    )

        manifest = copy.deepcopy(dict(self.seal.manifest))
        first = next(
            item
            for item in manifest["members"]
            if item["path"] == "pmaports/nested/target.alias"
        )
        second = copy.deepcopy(first)
        second["path"] = "pmaports/nested/second.alias"
        target = b"target"
        second.update(
            target="target",
            size=len(target),
            sha256=hashlib.sha256(target).hexdigest(),
        )
        chained = b"second.alias"
        first.update(
            target="second.alias",
            size=len(chained),
            sha256=hashlib.sha256(chained).hexdigest(),
        )
        manifest["members"].append(second)
        manifest["members"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(launcher.LauncherError, "not one regular file"):
            launcher._validated_manifest(launcher.canonical_json_bytes(manifest))

        manifest = copy.deepcopy(dict(self.seal.manifest))
        ancestor = next(
            item
            for item in manifest["members"]
            if item["path"] == "pmaports/nested/target.alias"
        )
        manifest["members"].append(
            {
                "mode": 0o644,
                "path": ancestor["path"] + "/child",
                "sha256": hashlib.sha256(b"child").hexdigest(),
                "size": len(b"child"),
                "type": "file",
            }
        )
        manifest["members"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(launcher.LauncherError, "parent.*not a directory"):
            launcher._validated_manifest(launcher.canonical_json_bytes(manifest))

    def test_identity_installed_path_and_interpreter_are_fail_closed(self):
        for uids in (
            (self.uid + 1, self.uid, self.uid),
            (self.uid, self.uid + 1, self.uid),
            (self.uid, self.uid, self.uid + 1),
        ):
            kwargs = self.launch_kwargs()
            kwargs["getresuid"] = lambda uids=uids: uids
            with self.assertRaisesRegex(launcher.LauncherError, "UIDs"):
                launcher.launch(**kwargs)
        kwargs = self.launch_kwargs()
        kwargs["executing_path"] = Path(__file__)
        with self.assertRaisesRegex(launcher.LauncherError, "fixed installed path"):
            launcher.launch(**kwargs)
        kwargs = self.launch_kwargs()
        kwargs["executing_interpreter"] = Path("/attacker/python")
        with self.assertRaisesRegex(launcher.LauncherError, "fixed /usr/bin/python3"):
            launcher.launch(**kwargs)

    def test_partial_run_is_cleaned_when_exec_fails(self):
        kwargs = self.launch_kwargs()
        kwargs["execve"] = mock.Mock(side_effect=OSError("exec failed"))
        with self.assertRaisesRegex(launcher.LauncherError, "execute"):
            launcher.launch(**kwargs)
        self.assertEqual(list(self.runs.iterdir()), [])

    def test_remove_run_deletes_frozen_completed_tree(self):
        run = self.runs / ("run-" + "0" * 32)
        run.mkdir(mode=0o700)
        export = run / "export"
        export.mkdir(mode=0o755)
        dtbs = export / "dtbs"
        dtbs.mkdir(mode=0o755)
        artifact = dtbs / "qcom-sm8250-xiaomi-lmi.dtb"
        artifact.write_bytes(b"dtb")
        artifact.chmod(0o444)
        (export / "latest.dtb").symlink_to(f"dtbs/{artifact.name}")
        dtbs.chmod(0o555)
        export.chmod(0o555)

        launcher._remove_run(run, expected_uid=self.uid, expected_gid=self.gid)

        self.assertFalse(run.exists())

    def test_remove_run_unlinks_symlink_escape_without_touching_target(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        outside_file = outside / "keep.txt"
        outside_file.write_text("keep\n", encoding="utf-8")

        run = self.runs / ("run-" + "1" * 32)
        run.mkdir(mode=0o700)
        (run / "outside-link").symlink_to(outside)

        launcher._remove_run(run, expected_uid=self.uid, expected_gid=self.gid)

        self.assertFalse(run.exists())
        self.assertEqual(outside_file.read_text(encoding="utf-8"), "keep\n")

    def test_remove_run_rejects_hardlink_without_partially_deleting_tree(self):
        outside = self.root / "outside-hardlink"
        outside.write_text("keep\n", encoding="utf-8")
        run = self.runs / ("run-" + "2" * 32)
        run.mkdir(mode=0o700)
        ordinary = run / "aaa-ordinary"
        ordinary.write_text("ordinary\n", encoding="utf-8")
        linked = run / "zzz-hardlink"
        os.link(outside, linked)

        with self.assertRaisesRegex(launcher.LauncherError, "hardlinked"):
            launcher._remove_run(run, expected_uid=self.uid, expected_gid=self.gid)

        self.assertTrue(ordinary.exists())
        self.assertEqual(outside.read_text(encoding="utf-8"), "keep\n")
        self.assertTrue(linked.exists())

    def test_remove_run_rejects_foreign_owned_member(self):
        run = self.runs / ("run-" + "3" * 32)
        run.mkdir(mode=0o700)
        foreign = run / "foreign"
        foreign.write_text("foreign\n", encoding="utf-8")
        foreign_identity = (foreign.stat().st_dev, foreign.stat().st_ino)
        real_fstat = os.fstat

        def simulated_foreign_owner(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            if (metadata.st_dev, metadata.st_ino) == foreign_identity:
                fields = list(metadata)
                fields[4] = self.uid + 1
                return os.stat_result(fields)
            return metadata

        with mock.patch.object(launcher.os, "fstat", simulated_foreign_owner):
            with self.assertRaisesRegex(launcher.LauncherError, "foreign-owned"):
                launcher._remove_run(run, expected_uid=self.uid, expected_gid=self.gid)

        self.assertEqual(foreign.read_text(encoding="utf-8"), "foreign\n")

    def test_remove_run_rejects_unsupported_special_member(self):
        run = self.runs / ("run-" + "4" * 32)
        run.mkdir(mode=0o700)
        fifo = run / "unsafe-fifo"
        os.mkfifo(fifo, 0o600)

        with self.assertRaisesRegex(launcher.LauncherError, "unsupported"):
            launcher._remove_run(run, expected_uid=self.uid, expected_gid=self.gid)

        self.assertTrue(fifo.exists())

    def test_remove_run_rejects_member_on_another_mount_identity(self):
        run = self.runs / ("run-" + "5" * 32)
        run.mkdir(mode=0o700)
        member = run / "mounted-member"
        member.write_text("keep\n", encoding="utf-8")
        member_inode = member.stat().st_ino
        real_mount_id = launcher._fd_mount_id

        def simulated_mount_id(descriptor: int) -> int:
            mount_id = real_mount_id(descriptor)
            if os.fstat(descriptor).st_ino == member_inode:
                return mount_id + 1
            return mount_id

        with mock.patch.object(launcher, "_fd_mount_id", simulated_mount_id):
            with self.assertRaisesRegex(launcher.LauncherError, "mount boundary"):
                launcher._remove_run(
                    run,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )

        self.assertEqual(member.read_text(encoding="utf-8"), "keep\n")

    def test_ninth_launch_prunes_one_run_and_retains_eight(self):
        observed: set[str] = set()
        for _index in range(9):
            self.invoke()
            current = {path.name for path in self.runs.iterdir()}
            observed.update(current)
            self.assertLessEqual(len(current), launcher._RETAIN_RUNS)

        retained = {path.name for path in self.runs.iterdir()}
        self.assertEqual(len(retained), launcher._RETAIN_RUNS)
        self.assertEqual(len(observed), launcher._RETAIN_RUNS + 1)
        self.assertEqual(len(observed - retained), 1)

    def test_busy_run_lock_stops_before_expensive_seal_verification(self):
        with mock.patch.object(
            launcher,
            "_acquire_run_lock",
            side_effect=launcher.LauncherError("another sealed build is already running"),
        ) as acquire, mock.patch.object(launcher, "verify_seal_standalone") as verify:
            with self.assertRaisesRegex(launcher.LauncherError, "already running"):
                launcher.launch(**self.launch_kwargs())

        acquire.assert_called_once_with(self.runs)
        verify.assert_not_called()

    def test_inherited_fd_closer_targets_every_descriptor_at_or_above_three(self):
        with mock.patch.object(launcher.os, "listdir", return_value=["0", "2", "3", "9"]), mock.patch.object(
            launcher.os, "close"
        ) as close:
            launcher._close_inherited_fds()
        self.assertEqual(close.call_args_list, [mock.call(3), mock.call(9)])

    @unittest.skipUnless(Path("/usr/bin/python3").exists(), "host Python unavailable")
    def test_real_host_python_symlink_chain_resolves_to_secure_regular_target(self):
        root_metadata = Path("/").stat()
        target = launcher._resolve_secure_python(
            Path("/usr/bin/python3"),
            trusted_root=Path("/"),
            expected_uid=root_metadata.st_uid,
            expected_gid=root_metadata.st_gid,
        )
        self.assertTrue(target.is_file())
        self.assertFalse(target.is_symlink())

    def test_launcher_is_standalone_and_uses_fixed_production_paths(self):
        source = Path(launcher.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import scripts.lmi_p1", source)
        self.assertNotIn("from lmi_p1", source)
        self.assertNotIn("from scripts", source)
        self.assertEqual(launcher.DEFAULT_PATHS.active, Path("/opt/lmi-p1/active-policy"))
        self.assertEqual(launcher.DEFAULT_PATHS.seals, Path("/opt/lmi-p1/seals"))
        self.assertEqual(launcher.DEFAULT_PATHS.runs, Path("/var/lib/lmi-p1/runs"))


if __name__ == "__main__":
    unittest.main()
