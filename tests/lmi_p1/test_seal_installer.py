from __future__ import annotations

import copy
import contextlib
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
    canonical_manifest_bytes,
    pack_seal_stream,
)
import scripts.lmi_p1_seal_installer as installer
from tests.lmi_p1.offline_cache_fixtures import offline_binding, write_offline_cache


class SealInstallerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()
        source_root = self.root / "sources"
        source_root.mkdir(mode=0o700)
        project = source_root / "project"
        pmbootstrap = source_root / "pmbootstrap"
        pmaports = source_root / "pmaports"
        for path in (project, pmbootstrap, pmaports):
            path.mkdir(mode=0o755)
        (project / "scripts").mkdir(mode=0o755)
        (project / "scripts/lmi_p1_cli.py").write_text("print('cli')\n")
        (project / "README").write_bytes(b"project\x00data\n")
        entrypoint = pmbootstrap / "pmbootstrap.py"
        entrypoint.write_text("print('pmb')\n")
        (pmaports / "pmaports.cfg").write_text("[pmaports]\n")
        (pmaports / "pmaports.alias").symlink_to("./pmaports.cfg")
        key = source_root / "authorized_key.pub"
        key.write_text("ssh-ed25519 AAAATEST installer-test\n")
        offline_cache, offline_manifest = write_offline_cache(source_root)
        self.provenance = SealProvenance(
            generation=11,
            project=GitProvenance("https://example.invalid/project.git", "1" * 40, "2" * 40),
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
        source_lock = source_root / "source-lock.json"
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
            + "\n"
        )
        for path in source_root.rglob("*"):
            if path.is_file():
                path.chmod(0o644)
        self.sources = SealSources(
            project, pmbootstrap, pmaports, key, source_lock, offline_cache
        )
        output = io.BytesIO()
        self.policy_id = pack_seal_stream(
            output,
            self.sources,
            self.provenance,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.bundle = output.getvalue()
        self.seals = self.root / "seals"
        self.seals.mkdir(mode=0o700)

    def install(self, payload: bytes | None = None, root: Path | None = None) -> str:
        return installer._install_stream(
            io.BytesIO(self.bundle if payload is None else payload),
            seals_root=str(self.seals if root is None else root),
            expected_uid=self.uid,
            expected_gid=self.gid,
            verify_ancestry=False,
        )

    def split_bundle(self, payload: bytes | None = None):
        value = self.bundle if payload is None else payload
        offset = len(installer.STREAM_MAGIC)
        length = int.from_bytes(value[offset : offset + installer.STREAM_LENGTH_BYTES], "big")
        offset += installer.STREAM_LENGTH_BYTES
        manifest_payload = value[offset : offset + length]
        offset += length
        manifest = json.loads(manifest_payload)
        data: dict[str, bytes] = {}
        for member in manifest["members"]:
            if member["type"] == "file":
                size = member["size"]
                data[member["path"]] = value[offset : offset + size]
                offset += size
        return manifest, data

    def bundle_for(self, manifest: dict[str, object], data: dict[str, bytes]) -> bytes:
        manifest_payload = canonical_manifest_bytes(manifest)
        body = b"".join(
            data[member["path"]]
            for member in manifest["members"]
            if member["type"] == "file"
        )
        return (
            installer.STREAM_MAGIC
            + len(manifest_payload).to_bytes(installer.STREAM_LENGTH_BYTES, "big")
            + manifest_payload
            + body
        )

    def test_installs_exact_inactive_generation_and_never_creates_activation(self):
        self.assertEqual(self.install(), self.policy_id)
        generation = self.seals / self.policy_id
        self.assertTrue((generation / installer.MANIFEST_NAME).is_file())
        self.assertEqual((generation / "project/README").read_bytes(), b"project\x00data\n")
        self.assertEqual(generation.stat().st_mode & 0o777, 0o700)
        self.assertFalse((self.root / "active-policy").exists())
        self.assertEqual(
            set(path.name for path in generation.iterdir()),
            {installer.MANIFEST_NAME, *installer.LAYOUT.values()},
        )
        link = generation / "pmaports/pmaports.alias"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "./pmaports.cfg")
        record = next(
            item
            for item in json.loads(
                (generation / installer.MANIFEST_NAME).read_bytes()
            )["members"]
            if item["path"] == "pmaports/pmaports.alias"
        )
        self.assertEqual(record["type"], "symlink")
        self.assertEqual(record["target"], "./pmaports.cfg")
        self.assertEqual(record["size"], len(b"./pmaports.cfg"))
        self.assertEqual(
            record["sha256"], hashlib.sha256(b"./pmaports.cfg").hexdigest()
        )

    def test_symlink_targets_are_manifest_framed_not_raw_stream_members(self):
        manifest, data = self.split_bundle()
        link = next(
            item
            for item in manifest["members"]
            if item["path"] == "pmaports/pmaports.alias"
        )
        self.assertNotIn(link["path"], data)
        self.assertEqual(self.bundle_for(manifest, data), self.bundle)

    def test_installer_stream_and_manifest_remain_v3_only(self):
        self.assertEqual(installer.STREAM_MAGIC, b"LMI-P1-SEAL\x00V3\n")
        self.assertEqual(installer.READ_MANIFEST_SCHEMAS, frozenset({3}))
        manifest, data = self.split_bundle()
        manifest["schema"] = 2
        manifest["members"] = [
            item for item in manifest["members"] if item["type"] != "symlink"
        ]
        with self.assertRaisesRegex(installer.InstallerError, "schema"):
            self.install(self.bundle_for(manifest, data))
        self.assertEqual(list(self.seals.iterdir()), [])

        legacy_magic = b"LMI-P1-SEAL\x00V2\n" + self.bundle[len(installer.STREAM_MAGIC) :]
        with self.assertRaisesRegex(installer.InstallerError, "magic/version"):
            self.install(legacy_magic)
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_hostile_symlink_targets_and_graphs_are_rejected_before_extraction(self):
        def bind_target(record: dict[str, object], target: str) -> None:
            encoded = target.encode("utf-8")
            record["target"] = target
            record["size"] = len(encoded)
            record["sha256"] = hashlib.sha256(encoded).hexdigest()

        for target, message in (
            ("/etc/passwd", "unsafe"),
            ("../pmbootstrap/pmbootstrap.py", "escapes"),
            ("", "unsafe"),
            ("x\0y", "unsafe"),
            ("a" * (installer.MAX_SYMLINK_TARGET_BYTES + 1), "limits"),
            ("./" * 33 + "pmaports.cfg", "limits"),
        ):
            with self.subTest(target=target[:40]):
                manifest, data = self.split_bundle()
                record = next(
                    item
                    for item in manifest["members"]
                    if item["path"] == "pmaports/pmaports.alias"
                )
                bind_target(record, target)
                with self.assertRaisesRegex(installer.InstallerError, message):
                    self.install(self.bundle_for(manifest, data))
                self.assertEqual(list(self.seals.iterdir()), [])

        manifest, data = self.split_bundle()
        first = next(
            item
            for item in manifest["members"]
            if item["path"] == "pmaports/pmaports.alias"
        )
        second = copy.deepcopy(first)
        second["path"] = "pmaports/second.alias"
        bind_target(second, "pmaports.cfg")
        bind_target(first, "second.alias")
        manifest["members"].append(second)
        manifest["members"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(installer.InstallerError, "not one regular file"):
            self.install(self.bundle_for(manifest, data))
        self.assertEqual(list(self.seals.iterdir()), [])

        manifest, data = self.split_bundle()
        ancestor = next(
            item
            for item in manifest["members"]
            if item["path"] == "pmaports/pmaports.alias"
        )
        child_payload = b"child"
        child_path = ancestor["path"] + "/child"
        manifest["members"].append(
            {
                "mode": 0o644,
                "path": child_path,
                "sha256": hashlib.sha256(child_payload).hexdigest(),
                "size": len(child_payload),
                "type": "file",
            }
        )
        manifest["members"].sort(key=lambda item: item["path"])
        data[child_path] = child_payload
        with self.assertRaisesRegex(
            installer.InstallerError, "parent.*(not a directory|unordered)"
        ):
            self.install(self.bundle_for(manifest, data))
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_installer_uses_dirfd_relative_symlink_and_rejects_target_race(self):
        real_symlink = installer.os.symlink
        observed: list[tuple[str, str, int | None]] = []

        def record_symlink(src, dst, target_is_directory=False, *, dir_fd=None):
            observed.append((src, dst, dir_fd))
            return real_symlink(
                src,
                dst,
                target_is_directory=target_is_directory,
                dir_fd=dir_fd,
            )

        with mock.patch.object(installer.os, "symlink", side_effect=record_symlink):
            self.install()
        self.assertEqual(len(observed), 1)
        self.assertEqual(observed[0][:2], ("./pmaports.cfg", "pmaports.alias"))
        self.assertIsInstance(observed[0][2], int)

        racing_root = self.root / "racing-seals"
        racing_root.mkdir(mode=0o700)
        real_readlink = installer.os.readlink
        calls = 0

        def mutate_link(name, *, dir_fd=None):
            nonlocal calls
            target = real_readlink(name, dir_fd=dir_fd)
            if name == "pmaports.alias" and calls == 0:
                calls += 1
                os.unlink(name, dir_fd=dir_fd)
                real_symlink("pmaports.cfg", name, dir_fd=dir_fd)
            return target

        with mock.patch.object(installer.os, "readlink", side_effect=mutate_link):
            with self.assertRaisesRegex(installer.InstallerError, "symlink"):
                self.install(root=racing_root)
        self.assertEqual(list(racing_root.iterdir()), [])

    def test_created_member_gate_rejects_hardlinks_xattrs_and_specials(self):
        regular = self.root / "created-contract-file"
        regular.write_bytes(b"contract")
        regular.chmod(0o644)
        hardlink = self.root / "created-contract-hardlink"
        os.link(regular, hardlink)
        descriptor = os.open(regular, os.O_RDONLY)
        try:
            with self.assertRaisesRegex(installer.InstallerError, "metadata"):
                installer._secure_fd(
                    descriptor,
                    directory=False,
                    mode=0o644,
                    uid=self.uid,
                    gid=self.gid,
                )
        finally:
            os.close(descriptor)
            hardlink.unlink()

        if hasattr(os, "setxattr"):
            try:
                os.setxattr(regular, "user.lmi-contract", b"unexpected")
            except OSError:
                pass
            else:
                descriptor = os.open(regular, os.O_RDONLY)
                try:
                    with self.assertRaisesRegex(installer.InstallerError, "xattrs"):
                        installer._secure_fd(
                            descriptor,
                            directory=False,
                            mode=0o644,
                            uid=self.uid,
                            gid=self.gid,
                        )
                finally:
                    os.close(descriptor)
                    os.removexattr(regular, "user.lmi-contract")

        fifo = self.root / "created-contract-fifo"
        os.mkfifo(fifo, 0o600)
        descriptor = os.open(fifo, os.O_RDWR | os.O_NONBLOCK)
        try:
            with self.assertRaisesRegex(installer.InstallerError, "metadata"):
                installer._secure_fd(
                    descriptor,
                    directory=False,
                    mode=0o600,
                    uid=self.uid,
                    gid=self.gid,
                )
        finally:
            os.close(descriptor)

    def test_truncated_extra_bad_magic_and_oversized_manifest_leave_no_partial(self):
        invalid = (
            self.bundle[:-1],
            self.bundle + b"trailing",
            b"X" + self.bundle[1:],
            installer.STREAM_MAGIC
            + (installer.MAX_MANIFEST_BYTES + 1).to_bytes(8, "big"),
        )
        for payload in invalid:
            with self.subTest(size=len(payload)):
                with self.assertRaises(installer.InstallerError):
                    self.install(payload)
                self.assertEqual(list(self.seals.iterdir()), [])

    def test_duplicate_traversal_and_oversized_member_are_rejected(self):
        manifest, data = self.split_bundle()
        cases = []
        duplicate = copy.deepcopy(manifest)
        duplicate["members"].append(dict(duplicate["members"][-1]))
        cases.append(canonical_manifest_bytes(duplicate))
        traversal = copy.deepcopy(manifest)
        traversal["members"][0]["path"] = "../escape"
        cases.append(canonical_manifest_bytes(traversal))
        oversized = copy.deepcopy(manifest)
        next(item for item in oversized["members"] if item["type"] == "file")[
            "size"
        ] = installer.MAX_FILE_BYTES + 1
        cases.append(canonical_manifest_bytes(oversized))
        for manifest_payload in cases:
            payload = (
                installer.STREAM_MAGIC
                + len(manifest_payload).to_bytes(8, "big")
                + manifest_payload
                + b"".join(data.values())
            )
            with self.assertRaises(installer.InstallerError):
                self.install(payload)
            self.assertEqual(list(self.seals.iterdir()), [])

    def test_oversized_source_lock_is_rejected_before_extraction(self):
        manifest, _data = self.split_bundle()
        source_lock = next(
            item for item in manifest["members"] if item["path"] == "source-lock.json"
        )
        source_lock["size"] = installer.MAX_SOURCE_LOCK_BYTES + 1
        manifest_payload = canonical_manifest_bytes(manifest)
        payload = (
            installer.STREAM_MAGIC
            + len(manifest_payload).to_bytes(installer.STREAM_LENGTH_BYTES, "big")
            + manifest_payload
        )
        with self.assertRaisesRegex(installer.InstallerError, "source lock exceeds"):
            self.install(payload)
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_offline_manifest_record_limit_is_exact_and_path_scoped(self):
        manifest, _data = self.split_bundle()
        offline_path = "offline-cache/offline-cache.manifest.json"

        boundary = copy.deepcopy(manifest)
        next(
            item for item in boundary["members"] if item["path"] == offline_path
        )["size"] = installer.MAX_OFFLINE_CACHE_MANIFEST_BYTES
        installer._validated_manifest(canonical_manifest_bytes(boundary))

        path_scoped = copy.deepcopy(manifest)
        next(
            item
            for item in path_scoped["members"]
            if item["type"] == "file" and item["path"] != offline_path
        )["size"] = installer.MAX_OFFLINE_CACHE_MANIFEST_BYTES + 1
        installer._validated_manifest(canonical_manifest_bytes(path_scoped))

        oversized = copy.deepcopy(manifest)
        next(
            item for item in oversized["members"] if item["path"] == offline_path
        )["size"] = installer.MAX_OFFLINE_CACHE_MANIFEST_BYTES + 1
        with self.assertRaisesRegex(
            installer.InstallerError, "offline-cache manifest exceeds"
        ):
            installer._validated_manifest(canonical_manifest_bytes(oversized))

    def test_fragmented_oversized_offline_manifest_header_rejects_before_body_or_cas(
        self,
    ):
        manifest, _data = self.split_bundle()
        offline_path = "offline-cache/offline-cache.manifest.json"
        next(
            item for item in manifest["members"] if item["path"] == offline_path
        )["size"] = installer.MAX_OFFLINE_CACHE_MANIFEST_BYTES + 1
        manifest_payload = canonical_manifest_bytes(manifest)
        header = (
            installer.STREAM_MAGIC
            + len(manifest_payload).to_bytes(installer.STREAM_LENGTH_BYTES, "big")
            + manifest_payload
        )
        unread_body = b"offline-manifest-body-must-remain-unread"

        class FragmentedStream(io.BytesIO):
            def read(inner_self, size=-1):
                if size < 0:
                    size = 5
                return super().read(min(size, 5))

        stream = FragmentedStream(header + unread_body)
        with mock.patch.object(
            installer.secrets,
            "token_hex",
            side_effect=AssertionError("incoming generation allocated too early"),
        ):
            with self.assertRaisesRegex(
                installer.InstallerError, "offline-cache manifest exceeds"
            ):
                installer._install_stream(
                    stream,
                    seals_root=str(self.seals),
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                    verify_ancestry=False,
                )
        self.assertEqual(stream.tell(), len(header))
        self.assertEqual(stream.read(), unread_body[:5])
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_source_lock_provenance_mismatch_is_rejected_after_member_hashes_match(self):
        manifest, data = self.split_bundle()
        source_lock = json.loads(data["source-lock.json"])
        source_lock["pmbootstrap"]["commit"] = "0" * 40
        changed = (json.dumps(source_lock, sort_keys=True) + "\n").encode()
        data["source-lock.json"] = changed
        record = next(
            item for item in manifest["members"] if item["path"] == "source-lock.json"
        )
        record["size"] = len(changed)
        record["sha256"] = hashlib.sha256(changed).hexdigest()
        manifest["inputs"]["source_lock_sha256"] = record["sha256"]
        with self.assertRaisesRegex(installer.InstallerError, "provenance mismatch"):
            self.install(self.bundle_for(manifest, data))
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_offline_cache_aggregate_and_work_version_are_rejected(self):
        manifest, data = self.split_bundle()
        inner_path = "offline-cache/offline-cache.manifest.json"
        inner = json.loads(data[inner_path])
        inner["aggregate_sha256"] = "0" * 64
        changed = canonical_manifest_bytes(inner)
        data[inner_path] = changed
        record = next(
            item for item in manifest["members"] if item["path"] == inner_path
        )
        record["size"] = len(changed)
        record["sha256"] = hashlib.sha256(changed).hexdigest()
        with self.assertRaisesRegex(installer.InstallerError, "aggregate"):
            self.install(self.bundle_for(manifest, data))
        self.assertEqual(list(self.seals.iterdir()), [])

        manifest, data = self.split_bundle()
        version_path = "offline-cache/work/version"
        data[version_path] = b"7\n"
        record = next(
            item for item in manifest["members"] if item["path"] == version_path
        )
        record["sha256"] = hashlib.sha256(data[version_path]).hexdigest()
        with self.assertRaisesRegex(installer.InstallerError, "work/version|inventory"):
            self.install(self.bundle_for(manifest, data))
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_offline_cache_signer_must_match_pinned_pmbootstrap_key(self):
        manifest, data = self.split_bundle()
        members = copy.deepcopy(manifest["members"])
        trust_key = next(
            item
            for item in members
            if str(item["path"]).startswith("pmbootstrap/pmb/data/keys/")
        )
        trust_key["sha256"] = "0" * 64
        with self.assertRaisesRegex(
            installer.InstallerError, "differs from the pinned pmbootstrap"
        ):
            installer._validate_offline_contract(
                data["offline-cache/offline-cache.manifest.json"],
                members,
                manifest["provenance"],
            )

    def test_standalone_installer_requires_producer_cardinality(self):
        for collection, message in (
            ("http_artifacts", "exactly one apk-tools-static"),
            ("distfiles", "exactly one kernel distfile"),
        ):
            with self.subTest(collection=collection):
                manifest, data = self.split_bundle()
                inner_path = "offline-cache/offline-cache.manifest.json"
                inner = json.loads(data[inner_path])
                removed = inner[collection].pop()
                inner["members"] = [
                    item for item in inner["members"]
                    if item["path"] != removed["path"]
                ]
                preimage = dict(inner)
                del preimage["aggregate_sha256"]
                inner["aggregate_sha256"] = hashlib.sha256(
                    canonical_manifest_bytes(preimage)
                ).hexdigest()
                payload = canonical_manifest_bytes(inner)
                members = [
                    item for item in manifest["members"]
                    if item["path"] != f'offline-cache/{removed["path"]}'
                ]
                provenance = copy.deepcopy(manifest["provenance"])
                provenance["offline_cache"] = {
                    "aggregate_sha256": inner["aggregate_sha256"],
                    "manifest_sha256": hashlib.sha256(payload).hexdigest(),
                    "schema": installer.OFFLINE_CACHE_SCHEMA,
                }
                with self.assertRaisesRegex(installer.InstallerError, message):
                    installer._validate_offline_contract(
                        payload, members, provenance
                    )

    def test_symlink_store_is_rejected_without_writing_target(self):
        target = self.root / "attacker-target"
        target.mkdir(mode=0o700)
        link = self.root / "seal-link"
        link.symlink_to(target, target_is_directory=True)
        with self.assertRaises(installer.InstallerError):
            self.install(root=link)
        self.assertEqual(list(target.iterdir()), [])

    def test_open_dirfd_prevents_late_store_path_swap_from_redirecting_install(self):
        moved = self.root / "original-store"
        attacker = self.root / "attacker-store"
        attacker.mkdir(mode=0o700)
        seals = self.seals

        class SwapStream(io.BytesIO):
            swapped = False

            def read(inner_self, size=-1):
                if not inner_self.swapped:
                    inner_self.swapped = True
                    seals.rename(moved)
                    seals.symlink_to(attacker, target_is_directory=True)
                return super().read(size)

        result = installer._install_stream(
            SwapStream(self.bundle),
            seals_root=str(seals),
            expected_uid=self.uid,
            expected_gid=self.gid,
            verify_ancestry=False,
        )
        self.assertEqual(result, self.policy_id)
        self.assertTrue((moved / self.policy_id).is_dir())
        self.assertEqual(list(attacker.iterdir()), [])

    def test_input_fd_race_is_rejected_before_generation_publication(self):
        stream_path = self.root / "seal.stream"
        stream_path.write_bytes(self.bundle)
        stream_path.chmod(0o600)

        class MutateAfterEof:
            def __init__(inner_self):
                inner_self.stream = stream_path.open("rb")
                inner_self.mutated = False

            def fileno(inner_self):
                return inner_self.stream.fileno()

            def read(inner_self, size=-1):
                block = inner_self.stream.read(size)
                if not block and not inner_self.mutated:
                    inner_self.mutated = True
                    with stream_path.open("ab") as writer:
                        writer.write(b"changed-after-eof")
                        writer.flush()
                        os.fsync(writer.fileno())
                return block

            def close(inner_self):
                inner_self.stream.close()

        racing_stream = MutateAfterEof()
        self.addCleanup(racing_stream.close)
        before = installer._verify_regular_input(racing_stream)
        with self.assertRaisesRegex(installer.InstallerError, "changed while reading"):
            installer._install_stream(
                racing_stream,
                seals_root=str(self.seals),
                expected_uid=self.uid,
                expected_gid=self.gid,
                verify_ancestry=False,
                expected_input_identity=before,
            )
        self.assertEqual(list(self.seals.iterdir()), [])

    def test_installer_is_standalone_with_fixed_store_and_no_destination_cli(self):
        source = Path(installer.__file__).read_text(encoding="utf-8")
        self.assertNotIn("import scripts", source)
        self.assertNotIn("from scripts", source)
        self.assertEqual(installer.SEALS_ROOT, "/opt/lmi-p1/seals")
        self.assertEqual(installer.INSTALLER_PATH, "/usr/local/sbin/lmi-p1-seal-installer")
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                installer.main([installer.INSTALLER_PATH, "/tmp/elsewhere"]), 1
            )


if __name__ == "__main__":
    unittest.main()
