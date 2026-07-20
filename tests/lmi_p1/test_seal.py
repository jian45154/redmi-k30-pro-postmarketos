from __future__ import annotations

import hashlib
import copy
import fcntl
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.seal as seal_module
import scripts.lmi_p1_root_launcher as launcher
import scripts.lmi_p1_seal_installer as installer
from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.seal import (
    GitProvenance,
    MANIFEST_NAME,
    PmbootstrapProvenance,
    SealProvenance,
    SealSources,
    _validate_offline_cache_manifest,
    _validate_manifest_shape,
    _safe_symlink_target,
    activate_policy,
    canonical_manifest_bytes,
    create_seal,
    policy_id_for_manifest,
    offline_cache_aggregate_preimage,
    pack_seal_stream,
    read_active_policy,
    rollback_policy,
    verify_seal,
)
from tests.lmi_p1.offline_cache_fixtures import offline_binding, write_offline_cache
from tests.lmi_p1.seal_policy_contract import (
    POLICY_ABI,
    POLICY_ABI_FINGERPRINT,
    manifest_cases,
)


class SealTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.uid = os.getuid()
        self.gid = os.getgid()
        self.sources_root = self.root / "sources"
        self.sources_root.mkdir(mode=0o700)
        project = self.sources_root / "project"
        pmbootstrap = self.sources_root / "pmbootstrap"
        pmaports = self.sources_root / "pmaports"
        for directory in (project, pmbootstrap, pmaports):
            directory.mkdir(mode=0o755)
        (project / "scripts").mkdir(mode=0o755)
        (project / "scripts/lmi_p1_cli.py").write_text(
            "raise SystemExit('test-only sealed CLI')\n", encoding="utf-8"
        )
        (project / "README").write_bytes(b"project\x00bytes\n")
        (pmbootstrap / "pmbootstrap.py").write_text("print('pmb')\n", encoding="utf-8")
        (pmbootstrap / "nested").mkdir(mode=0o755)
        (pmbootstrap / "nested/complete").write_bytes(b"complete tree\n")
        (pmaports / "pmaports.cfg").write_text("[pmaports]\n", encoding="utf-8")
        (pmaports / "pmaports.alias").symlink_to("./pmaports.cfg")
        authorized_key = self.sources_root / "authorized_key.pub"
        authorized_key.write_text("ssh-ed25519 AAAATEST lmi-p1-test\n", encoding="utf-8")
        offline_cache, offline_manifest = write_offline_cache(self.sources_root)
        self.offline_manifest = offline_manifest
        source_lock = self.sources_root / "source-lock.json"
        source_lock.write_text(
            json.dumps(
                {
                    "schema": "lmi-source-lock/v3",
                    "offline_cache": offline_binding(
                        offline_cache, offline_manifest
                    ),
                    "pmbootstrap": {
                        "remote": "https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git",
                        "commit": "3" * 40,
                        "tree": "4" * 40,
                        "version": "3.11.1",
                        "entrypoint_sha256": hashlib.sha256(
                            (pmbootstrap / "pmbootstrap.py").read_bytes()
                        ).hexdigest(),
                    },
                    "pmaports": {
                        "remote": "https://gitlab.postmarketos.org/postmarketOS/pmaports.git",
                        "commit": "5" * 40,
                        "tree": "6" * 40,
                    },
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        for path in self.sources_root.rglob("*"):
            if path.is_file():
                path.chmod(0o644)
        self.sources = SealSources(
            project=project,
            pmbootstrap=pmbootstrap,
            pmaports=pmaports,
            authorized_key=authorized_key,
            source_lock=source_lock,
            offline_cache=offline_cache,
        )
        self.provenance = SealProvenance(
            generation=7,
            project=GitProvenance(
                remote="https://example.invalid/lmi-project.git",
                commit="1" * 40,
                tree="2" * 40,
            ),
            pmbootstrap=PmbootstrapProvenance(
                remote="https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git",
                commit="3" * 40,
                tree="4" * 40,
                version="3.11.1",
                entrypoint_sha256=hashlib.sha256(
                    (pmbootstrap / "pmbootstrap.py").read_bytes()
                ).hexdigest(),
            ),
            pmaports=GitProvenance(
                remote="https://gitlab.postmarketos.org/postmarketOS/pmaports.git",
                commit="5" * 40,
                tree="6" * 40,
            ),
        )
        self.seals = self.root / "seals"
        self.seals.mkdir(mode=0o700)
        self.verified = create_seal(
            self.seals,
            self.sources,
            self.provenance,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def verify(self):
        return verify_seal(
            self.verified.root,
            self.verified.policy_id,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )

    def create_legacy_v2_seal(
        self, generation: int = 6
    ) -> tuple[Path, str, dict[str, object], bytes]:
        source_link = self.sources.pmaports / "pmaports.alias"
        source_target = os.readlink(source_link)
        source_link.unlink()
        try:
            current = create_seal(
                self.seals,
                self.sources,
                SealProvenance(
                    generation=generation,
                    project=self.provenance.project,
                    pmbootstrap=self.provenance.pmbootstrap,
                    pmaports=self.provenance.pmaports,
                ),
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        finally:
            source_link.symlink_to(source_target)
        manifest = copy.deepcopy(dict(current.manifest))
        manifest["schema"] = 2
        self.assertNotIn(
            "symlink", {str(member["type"]) for member in manifest["members"]}
        )
        payload = canonical_manifest_bytes(manifest)
        policy_id = hashlib.sha256(payload).hexdigest()
        manifest_path = current.root / MANIFEST_NAME
        manifest_path.write_bytes(payload)
        legacy_root = self.seals / policy_id
        current.root.rename(legacy_root)
        return legacy_root, policy_id, manifest, payload

    def test_manifest_is_exact_canonical_json_and_policy_id_is_its_digest(self):
        manifest_path = self.verified.root / MANIFEST_NAME
        payload = manifest_path.read_bytes()
        parsed = json.loads(payload)

        self.assertEqual(payload, canonical_manifest_bytes(parsed))
        self.assertEqual(
            self.verified.policy_id,
            hashlib.sha256(payload).hexdigest(),
        )
        self.assertEqual(self.verified.policy_id, policy_id_for_manifest(parsed))
        members = parsed["members"]
        self.assertEqual(
            [member["path"] for member in members],
            sorted(member["path"] for member in members),
        )
        for member in members:
            expected = {"mode", "path", "sha256", "size", "type"}
            if member["type"] == "symlink":
                expected.add("target")
            self.assertEqual(set(member), expected)
        self.assertIn("pmbootstrap/nested/complete", {item["path"] for item in members})
        by_path = {item["path"]: item for item in members}
        self.assertEqual(
            by_path["pmaports/pmaports.alias"],
            {
                "mode": 0o777,
                "path": "pmaports/pmaports.alias",
                "sha256": hashlib.sha256(b"./pmaports.cfg").hexdigest(),
                "size": len(b"./pmaports.cfg"),
                "target": "./pmaports.cfg",
                "type": "symlink",
            },
        )
        self.assertEqual(
            parsed["inputs"],
            {
                "authorized_key_sha256": by_path["authorized_key.pub"]["sha256"],
                "source_lock_sha256": by_path["source-lock.json"]["sha256"],
            },
        )
        self.assertEqual(parsed["provenance"]["generation"], 7)
        self.assertEqual(
            parsed["provenance"]["offline_cache"],
            offline_binding(self.sources.offline_cache, self.offline_manifest),
        )
        self.assertEqual(parsed["provenance"]["project"]["commit"], "1" * 40)
        self.assertEqual(self.verify().policy_id, self.verified.policy_id)

    def test_policy_abi_fingerprint_and_cardinality_are_exact_across_tcb(self):
        expected_fingerprint = (
            "96aea3fd68aeeba23cd9955cf5996cdc3e6ae14518e2dccdb4c902316696c729"
        )
        self.assertEqual(POLICY_ABI_FINGERPRINT, expected_fingerprint)
        self.assertEqual(
            {
                seal_module.SEAL_POLICY_ABI_FINGERPRINT,
                installer.SEAL_POLICY_ABI_FINGERPRINT,
                launcher.SEAL_POLICY_ABI_FINGERPRINT,
            },
            {expected_fingerprint},
        )
        self.assertEqual(seal_module.READ_SCHEMAS, frozenset({2, 3}))
        self.assertEqual(installer.READ_MANIFEST_SCHEMAS, frozenset({3}))
        self.assertEqual(launcher.READ_MANIFEST_SCHEMAS, frozenset({2, 3}))
        self.assertEqual(
            {
                "directory_inputs": len(POLICY_ABI["directory_inputs"]),
                "input_fields": len(POLICY_ABI["manifest"]["input_fields"]),
                "layout": len(POLICY_ABI["layout"]),
                "manifest_fields": len(POLICY_ABI["manifest"]["fields"]),
                "member_types_v2": len(
                    POLICY_ABI["manifest"]["member_types_by_schema"]["2"]
                ),
                "member_types_v3": len(
                    POLICY_ABI["manifest"]["member_types_by_schema"]["3"]
                ),
                "provenance_shapes": len(POLICY_ABI["provenance_fields"]),
                "symlink_components": len(POLICY_ABI["symlink"]["components"]),
            },
            {
                "directory_inputs": 4,
                "input_fields": 2,
                "layout": 6,
                "manifest_fields": 5,
                "member_types_v2": 2,
                "member_types_v3": 3,
                "provenance_shapes": 4,
                "symlink_components": 3,
            },
        )
        self.assertEqual(seal_module.LAYOUT, installer.LAYOUT)
        self.assertEqual(seal_module.LAYOUT, launcher.LAYOUT)
        self.assertEqual(seal_module.LAYOUT, POLICY_ABI["layout"])
        expected_directories = frozenset(POLICY_ABI["directory_inputs"])
        self.assertEqual(seal_module._DIRECTORY_INPUTS, expected_directories)
        self.assertEqual(installer.DIRECTORY_INPUTS, expected_directories)
        self.assertEqual(launcher._DIRECTORY_INPUTS, expected_directories)
        expected_components = frozenset(POLICY_ABI["symlink"]["components"])
        self.assertEqual(seal_module._SYMLINK_COMPONENTS, expected_components)
        self.assertEqual(installer.SYMLINK_COMPONENTS, expected_components)
        self.assertEqual(launcher._SYMLINK_COMPONENTS, expected_components)
        self.assertEqual(seal_module.SCHEMA, POLICY_ABI["schemas"]["current"])
        self.assertEqual(
            installer.MANIFEST_SCHEMA, POLICY_ABI["schemas"]["current"]
        )
        self.assertEqual(
            launcher.MANIFEST_SCHEMA, POLICY_ABI["schemas"]["current"]
        )
        self.assertEqual(seal_module.STREAM_MAGIC.hex(), POLICY_ABI["stream"]["magic_hex"])
        self.assertEqual(installer.STREAM_MAGIC, seal_module.STREAM_MAGIC)
        self.assertEqual(installer.STREAM_LENGTH_BYTES, seal_module._STREAM_LENGTH_BYTES)

        expected_limits = POLICY_ABI["limits"]
        limit_values = (
            {
                "file_bytes": seal_module._MAX_FILE_BYTES,
                "manifest_bytes": seal_module._MAX_MANIFEST_BYTES,
                "members": seal_module._MAX_MEMBERS,
                "offline_cache_manifest_bytes": (
                    seal_module._MAX_OFFLINE_CACHE_MANIFEST_BYTES
                ),
                "path_bytes": seal_module._MAX_PATH_BYTES,
                "path_depth": seal_module._MAX_DEPTH,
                "symlink_target_bytes": seal_module._MAX_SYMLINK_TARGET_BYTES,
                "symlink_target_depth": seal_module._MAX_SYMLINK_TARGET_DEPTH,
                "total_file_bytes": seal_module._MAX_TOTAL_FILE_BYTES,
            },
            {
                "file_bytes": installer.MAX_FILE_BYTES,
                "manifest_bytes": installer.MAX_MANIFEST_BYTES,
                "members": installer.MAX_MEMBERS,
                "offline_cache_manifest_bytes": (
                    installer.MAX_OFFLINE_CACHE_MANIFEST_BYTES
                ),
                "path_bytes": installer.MAX_PATH_BYTES,
                "path_depth": installer.MAX_DEPTH,
                "symlink_target_bytes": installer.MAX_SYMLINK_TARGET_BYTES,
                "symlink_target_depth": installer.MAX_SYMLINK_TARGET_DEPTH,
                "total_file_bytes": installer.MAX_TOTAL_FILE_BYTES,
            },
            {
                "file_bytes": launcher._MAX_FILE_BYTES,
                "manifest_bytes": launcher._MAX_MANIFEST_BYTES,
                "members": launcher._MAX_MEMBERS,
                "offline_cache_manifest_bytes": (
                    launcher._MAX_OFFLINE_CACHE_MANIFEST_BYTES
                ),
                "path_bytes": launcher._MAX_PATH_BYTES,
                "path_depth": launcher._MAX_DEPTH,
                "symlink_target_bytes": launcher._MAX_SYMLINK_TARGET_BYTES,
                "symlink_target_depth": launcher._MAX_SYMLINK_TARGET_DEPTH,
                "total_file_bytes": launcher._MAX_TOTAL_FILE_BYTES,
            },
        )
        for values in limit_values:
            self.assertEqual(values, expected_limits)

    def test_shared_manifest_policy_corpus_has_identical_tcb_decisions(self):
        validators = {
            "producer": (
                lambda value: seal_module._validate_manifest_shape(value),
                GateError,
            ),
            "installer": (
                lambda value: installer._validated_manifest(
                    canonical_manifest_bytes(value)
                ),
                installer.InstallerError,
            ),
            "launcher": (
                lambda value: launcher._validated_manifest(
                    canonical_manifest_bytes(value)
                ),
                launcher.LauncherError,
            ),
        }
        for case in manifest_cases(self.verified.manifest):
            expected = {
                "producer": case.producer_accepts,
                "installer": case.installer_accepts,
                "launcher": case.launcher_accepts,
            }
            for label, (validate, error_type) in validators.items():
                with self.subTest(case=case.name, validator=label):
                    try:
                        validate(copy.deepcopy(case.manifest))
                    except error_type:
                        accepted = False
                    else:
                        accepted = True
                    self.assertEqual(accepted, expected[label])

    def test_filesystem_hostile_corpus_matches_verifier_and_launcher(self):
        def both_reject() -> None:
            with self.assertRaises(GateError):
                self.verify()
            with self.assertRaises(launcher.LauncherError):
                launcher.verify_seal_standalone(
                    self.verified.root,
                    self.verified.policy_id,
                    seals_root=self.seals,
                    trusted_root=self.root,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )

        regular = self.verified.project / "README"
        hardlink = self.verified.project / "README.contract-hardlink"
        os.link(regular, hardlink)
        try:
            both_reject()
        finally:
            hardlink.unlink()

        fifo = self.verified.project / "contract-fifo"
        os.mkfifo(fifo, 0o600)
        try:
            both_reject()
        finally:
            fifo.unlink()

        if hasattr(os, "setxattr"):
            try:
                os.setxattr(regular, "user.lmi-contract", b"unexpected")
            except OSError:
                pass
            else:
                try:
                    both_reject()
                finally:
                    os.removexattr(regular, "user.lmi-contract")

    def test_provenance_rejects_missing_extra_illegal_hash_and_generation(self):
        cases = []
        missing = copy.deepcopy(dict(self.verified.manifest))
        del missing["provenance"]["project"]
        cases.append(missing)
        extra = copy.deepcopy(dict(self.verified.manifest))
        extra["provenance"]["unexpected"] = "value"
        cases.append(extra)
        invalid_hash = copy.deepcopy(dict(self.verified.manifest))
        invalid_hash["provenance"]["pmbootstrap"]["entrypoint_sha256"] = "z" * 64
        cases.append(invalid_hash)
        invalid_generation = copy.deepcopy(dict(self.verified.manifest))
        invalid_generation["provenance"]["generation"] = 0
        cases.append(invalid_generation)
        boolean_generation = copy.deepcopy(dict(self.verified.manifest))
        boolean_generation["provenance"]["generation"] = True
        cases.append(boolean_generation)

        for manifest in cases:
            with self.subTest(provenance=manifest["provenance"]):
                with self.assertRaisesRegex(GateError, "provenance"):
                    _validate_manifest_shape(manifest)

    def test_bit_flip_is_rejected(self):
        target = self.verified.pmbootstrap / "nested/complete"
        payload = bytearray(target.read_bytes())
        payload[0] ^= 1
        target.write_bytes(payload)

        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            self.verify()

    def test_verified_seal_exposes_strict_offline_cache(self):
        verified = self.verify()
        self.assertEqual(verified.offline_cache, verified.root / "offline-cache")
        self.assertEqual(
            (verified.offline_cache / "work/version").read_bytes(), b"8\n"
        )

    def test_offline_cache_requires_one_http_bootstrap_and_one_kernel_distfile(self):
        for collection, message in (
            ("http_artifacts", "exactly one apk-tools-static"),
            ("distfiles", "exactly one kernel distfile"),
        ):
            with self.subTest(collection=collection):
                value = copy.deepcopy(self.offline_manifest)
                removed = value[collection].pop()
                value["members"] = [
                    item for item in value["members"]
                    if item["path"] != removed["path"]
                ]
                value["aggregate_sha256"] = hashlib.sha256(
                    offline_cache_aggregate_preimage(value)
                ).hexdigest()
                actual = {item["path"]: item for item in value["members"]}
                with self.assertRaisesRegex(GateError, message):
                    _validate_offline_cache_manifest(value, actual)

    def test_cache_signer_must_equal_pinned_pmbootstrap_key_before_packing(self):
        trust_key = next(
            (self.sources.pmbootstrap / "pmb/data/keys").glob("*.rsa.pub")
        )
        trust_key.write_bytes(b"different pinned trust material\n")
        with self.assertRaisesRegex(GateError, "differs from the pinned pmbootstrap"):
            pack_seal_stream(
                io.BytesIO(),
                self.sources,
                self.provenance,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_corrupt_missing_and_extra_offline_cache_members_are_rejected(self):
        target = next(
            (self.verified.offline_cache / "work/cache_apk_aarch64").glob(
                "APKINDEX.*.tar.gz"
            )
        )
        target.write_bytes(target.read_bytes() + b"corrupt")
        with self.assertRaisesRegex(GateError, "inventory mismatch|digest mismatch"):
            self.verify()

    def test_missing_offline_cache_member_is_rejected(self):
        target = next(
            (self.verified.offline_cache / "work/cache_apk_aarch64").glob(
                "APKINDEX.*.tar.gz"
            )
        )
        target.unlink()
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            self.verify()

    def test_extra_offline_cache_directory_is_rejected(self):
        (self.verified.offline_cache / "work/chroot_native").mkdir()
        with self.assertRaisesRegex(GateError, "inventory mismatch|missing or extra"):
            self.verify()

    def test_wrong_offline_work_version_is_rejected_before_packing(self):
        (self.sources.offline_cache / "work/version").write_bytes(b"7\n")
        with self.assertRaisesRegex(GateError, "work/version"):
            pack_seal_stream(
                io.BytesIO(),
                self.sources,
                self.provenance,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_source_lock_offline_aggregate_mismatch_is_rejected(self):
        value = json.loads(self.sources.source_lock.read_bytes())
        value["offline_cache"]["aggregate_sha256"] = "0" * 64
        self.sources.source_lock.write_text(
            json.dumps(value, sort_keys=True) + "\n", encoding="utf-8"
        )
        with self.assertRaisesRegex(GateError, "offline_cache.aggregate_sha256"):
            pack_seal_stream(
                io.BytesIO(),
                self.sources,
                self.provenance,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_extra_member_is_rejected(self):
        (self.verified.project / "extra").write_text("extra", encoding="utf-8")
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            self.verify()

    def test_missing_member_is_rejected(self):
        (self.verified.project / "README").unlink()
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            self.verify()

    def test_hardlink_is_rejected(self):
        os.link(
            self.verified.project / "README",
            self.verified.project / "README.hardlink",
        )
        with self.assertRaisesRegex(GateError, "hardlinked"):
            self.verify()

    def test_undeclared_symlink_is_rejected(self):
        (self.verified.project / "link").symlink_to("README")
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            self.verify()

    def test_declared_symlink_is_copied_and_verified_without_following_it(self):
        link = self.verified.pmaports / "pmaports.alias"
        self.assertTrue(link.is_symlink())
        self.assertEqual(os.readlink(link), "./pmaports.cfg")
        self.assertEqual(self.verify().policy_id, self.verified.policy_id)

        link.unlink()
        link.symlink_to("missing.cfg")
        with self.assertRaisesRegex(GateError, "inventory mismatch|target is absent"):
            self.verify()

    def test_hardlinked_symlink_is_rejected(self):
        link = self.verified.pmaports / "pmaports.alias"
        hardlink = self.verified.pmaports / "pmaports.alias.hardlink"
        os.link(link, hardlink, follow_symlinks=False)
        with self.assertRaisesRegex(GateError, "hardlinked symlink"):
            self.verify()

    def test_source_symlink_rejects_absolute_escape_chain_and_directory_target(self):
        link = self.sources.pmaports / "hostile"
        cases = (
            ("/etc/passwd", "unsafe"),
            ("../authorized_key.pub", "escapes"),
            (".", "not one regular file"),
            ("pmaports.alias", "not one regular file"),
        )
        for target, message in cases:
            with self.subTest(target=target):
                link.symlink_to(target)
                try:
                    with self.assertRaisesRegex(GateError, message):
                        pack_seal_stream(
                            io.BytesIO(),
                            self.sources,
                            self.provenance,
                            expected_uid=self.uid,
                            expected_gid=self.gid,
                        )
                finally:
                    link.unlink()

    def test_symlink_target_bounds_and_utf8_are_fail_closed(self):
        for target, message in (
            ("", "unsafe"),
            ("x\0y", "unsafe"),
            ("a" * 1025, "limits"),
            ("./" * 33 + "pmaports.cfg", "limits"),
        ):
            with self.subTest(target=target[:32]):
                with self.assertRaisesRegex(GateError, message):
                    _safe_symlink_target("pmaports/link", target)

        undecodable = self.sources.pmaports / "undecodable"
        os.symlink(b"\xff", os.fsencode(undecodable))
        self.addCleanup(undecodable.unlink, missing_ok=True)
        with self.assertRaisesRegex(GateError, "UTF-8"):
            pack_seal_stream(
                io.BytesIO(),
                self.sources,
                self.provenance,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_manifest_rejects_symlink_as_member_ancestor(self):
        manifest = copy.deepcopy(dict(self.verified.manifest))
        link = next(
            item
            for item in manifest["members"]
            if item["path"] == "pmaports/pmaports.alias"
        )
        child = {
            "mode": 0o644,
            "path": link["path"] + "/child",
            "sha256": hashlib.sha256(b"child").hexdigest(),
            "size": len(b"child"),
            "type": "file",
        }
        manifest["members"].append(child)
        manifest["members"].sort(key=lambda item: item["path"])
        with self.assertRaisesRegex(GateError, "parent.*not a directory"):
            _validate_manifest_shape(manifest)

    def test_symlink_target_mutation_during_inventory_is_rejected(self):
        import scripts.lmi_p1.seal as seal_module

        link = self.sources.pmaports / "pmaports.alias"
        real_readlink = os.readlink
        calls = 0

        def mutate_between_reads(path):
            nonlocal calls
            value = real_readlink(path)
            if Path(path) == link and calls == 0:
                calls += 1
                link.unlink()
                link.symlink_to("pmaports.cfg")
            return value

        with mock.patch.object(seal_module.os, "readlink", side_effect=mutate_between_reads):
            with self.assertRaisesRegex(GateError, "changed while reading"):
                pack_seal_stream(
                    io.BytesIO(),
                    self.sources,
                    self.provenance,
                    expected_uid=self.uid,
                    expected_gid=self.gid,
                )

    def test_special_file_is_rejected(self):
        os.mkfifo(self.verified.project / "fifo", 0o600)
        with self.assertRaisesRegex(GateError, "special"):
            self.verify()

    def test_mode_change_is_rejected(self):
        (self.verified.project / "README").chmod(0o600)
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            self.verify()

    def test_group_writable_member_is_rejected_before_manifest_comparison(self):
        (self.verified.project / "README").chmod(0o664)
        with self.assertRaisesRegex(GateError, "group/world writable"):
            self.verify()

    def test_non_trusted_owner_policy_is_rejected(self):
        with self.assertRaisesRegex(GateError, "not owned by the trusted account"):
            verify_seal(
                self.verified.root,
                self.verified.policy_id,
                trusted_root=self.root,
                expected_uid=self.uid + 1,
                expected_gid=self.gid,
            )

    def test_dangerous_ancestry_is_rejected(self):
        self.seals.chmod(0o770)
        with self.assertRaisesRegex(GateError, "group/world writable"):
            self.verify()

    @unittest.skipUnless(hasattr(os, "setxattr"), "xattrs unavailable")
    def test_xattr_is_rejected(self):
        target = self.verified.project / "README"
        try:
            os.setxattr(target, "user.lmi-test", b"unexpected")
        except OSError as error:
            self.skipTest(f"test filesystem does not support user xattrs: {error}")
        with self.assertRaisesRegex(GateError, "xattrs"):
            self.verify()

    def test_manifest_byte_change_and_wrong_policy_are_rejected(self):
        manifest = self.verified.root / MANIFEST_NAME
        manifest.write_bytes(manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(GateError, "canonical"):
            self.verify()

        manifest.write_bytes(
            canonical_manifest_bytes(dict(self.verified.manifest))
        )
        with self.assertRaisesRegex(GateError, "policy id"):
            verify_seal(
                self.verified.root,
                "0" * 64,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_duplicate_manifest_member_is_rejected(self):
        manifest_path = self.verified.root / MANIFEST_NAME
        manifest = json.loads(manifest_path.read_bytes())
        manifest["members"].append(dict(manifest["members"][0]))
        manifest_path.write_bytes(canonical_manifest_bytes(manifest))
        new_policy = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        new_root = self.seals / new_policy
        self.verified.root.rename(new_root)
        with self.assertRaisesRegex(GateError, "duplicate member"):
            verify_seal(
                new_root,
                new_policy,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_active_policy_is_exact_root_owned_trust_root(self):
        policy_root = self.root / "policy"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active"
        activate_policy(
            active,
            self.verified.policy_id,
            seals_root=self.seals,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(active.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            read_active_policy(
                active,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            self.verified.policy_id,
        )
        active.write_text("0" * 64 + "\n", encoding="ascii")
        self.assertNotEqual(
            read_active_policy(
                active,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            self.verified.policy_id,
        )

    def test_golden_v2_active_migrates_to_v3_and_explicitly_rolls_back(self):
        legacy_root, legacy_policy, legacy_manifest, legacy_payload = (
            self.create_legacy_v2_seal()
        )
        self.assertEqual(
            legacy_policy,
            "0130949098392542842cb35329401ed43ef71d98b131d579a5aa98db970ae4ed",
        )
        self.assertEqual(len(legacy_payload), 7704)
        self.assertEqual(legacy_manifest["schema"], 2)
        self.assertEqual(hashlib.sha256(legacy_payload).hexdigest(), legacy_policy)
        for member in legacy_manifest["members"]:
            self.assertEqual(
                set(member), {"mode", "path", "sha256", "size", "type"}
            )
            self.assertIn(member["type"], {"directory", "file"})
        verified_legacy = verify_seal(
            legacy_root,
            legacy_policy,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(verified_legacy.manifest["schema"], 2)
        self.assertEqual(
            launcher.verify_seal_standalone(
                legacy_root,
                legacy_policy,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )["schema"],
            2,
        )

        policy_root = self.root / "v2-migration-policy"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active-policy"
        active.write_text(legacy_policy + "\n", encoding="ascii")
        active.chmod(0o600)

        activate_policy(
            active,
            self.verified.policy_id,
            seals_root=self.seals,
            expected_current_policy=legacy_policy,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(
            read_active_policy(
                active,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            self.verified.policy_id,
        )

        rollback_policy(
            active,
            legacy_policy,
            seals_root=self.seals,
            expected_current_policy=self.verified.policy_id,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(
            read_active_policy(
                active,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            legacy_policy,
        )
        self.assertEqual(
            launcher.verify_seal_standalone(
                legacy_root,
                legacy_policy,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )["schema"],
            2,
        )

    def test_v2_is_reader_and_explicit_rollback_only_not_activation_target(self):
        _legacy_root, legacy_policy, _manifest, _payload = (
            self.create_legacy_v2_seal()
        )
        policy_root = self.root / "legacy-target-policy"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active-policy"
        with self.assertRaisesRegex(GateError, "current seal schema"):
            activate_policy(
                active,
                legacy_policy,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        self.assertFalse(active.exists())

    def test_v2_current_is_verified_under_one_nonrecursive_cas_lock(self):
        _legacy_root, legacy_policy, _manifest, _payload = (
            self.create_legacy_v2_seal()
        )
        policy_root = self.root / "legacy-lock-policy"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active-policy"
        active.write_text(legacy_policy + "\n", encoding="ascii")
        active.chmod(0o600)
        original_read = seal_module.read_active_policy
        observed: list[str] = []

        def read_while_locked(*args, **kwargs):
            probe_fd = os.open(
                policy_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe_fd)
            value = original_read(*args, **kwargs)
            observed.append(value)
            return value

        with mock.patch.object(
            seal_module,
            "read_active_policy",
            side_effect=read_while_locked,
        ):
            activate_policy(
                active,
                self.verified.policy_id,
                seals_root=self.seals,
                expected_current_policy=legacy_policy,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        self.assertEqual(observed[0], legacy_policy)
        self.assertEqual(observed[-1], self.verified.policy_id)

    def test_packed_stream_is_deterministic_and_policy_addressed(self):
        first = io.BytesIO()
        second = io.BytesIO()
        first_policy = pack_seal_stream(
            first,
            self.sources,
            self.provenance,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        second_policy = pack_seal_stream(
            second,
            self.sources,
            self.provenance,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(first.getvalue(), second.getvalue())
        self.assertEqual(first_policy, second_policy)
        self.assertEqual(first_policy, self.verified.policy_id)

    def test_source_lock_mismatch_is_rejected_before_packing(self):
        value = json.loads(self.sources.source_lock.read_bytes())
        value["pmaports"]["commit"] = "0" * 40
        self.sources.source_lock.write_text(json.dumps(value) + "\n", encoding="utf-8")
        with self.assertRaisesRegex(GateError, "source lock provenance mismatch"):
            pack_seal_stream(
                io.BytesIO(),
                self.sources,
                self.provenance,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

    def test_activation_is_monotonic_and_rollback_is_explicit_compare_and_swap(self):
        policy_root = self.root / "activation"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active"
        activate_policy(
            active,
            self.verified.policy_id,
            seals_root=self.seals,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        newer = create_seal(
            self.seals,
            self.sources,
            SealProvenance(
                generation=8,
                project=self.provenance.project,
                pmbootstrap=self.provenance.pmbootstrap,
                pmaports=self.provenance.pmaports,
            ),
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        activate_policy(
            active,
            newer.policy_id,
            seals_root=self.seals,
            expected_current_policy=self.verified.policy_id,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        with self.assertRaisesRegex(GateError, "not a newer"):
            activate_policy(
                active,
                self.verified.policy_id,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        with self.assertRaisesRegex(GateError, "changed from the expected"):
            rollback_policy(
                active,
                self.verified.policy_id,
                seals_root=self.seals,
                expected_current_policy="0" * 64,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
        rollback_policy(
            active,
            self.verified.policy_id,
            seals_root=self.seals,
            expected_current_policy=newer.policy_id,
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        self.assertEqual(
            read_active_policy(
                active,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            ),
            self.verified.policy_id,
        )

    def test_activation_and_rollback_verify_active_policy_while_locked(self):
        import scripts.lmi_p1.seal as seal_module

        policy_root = self.root / "locked-activation"
        policy_root.mkdir(mode=0o700)
        active = policy_root / "active"
        newer = create_seal(
            self.seals,
            self.sources,
            SealProvenance(
                generation=8,
                project=self.provenance.project,
                pmbootstrap=self.provenance.pmbootstrap,
                pmaports=self.provenance.pmaports,
            ),
            trusted_root=self.root,
            expected_uid=self.uid,
            expected_gid=self.gid,
        )
        original_read = seal_module.read_active_policy
        observed: list[str] = []

        def read_while_contending(*args, **kwargs):
            probe_fd = os.open(
                policy_root,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0),
            )
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(probe_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(probe_fd)
            value = original_read(*args, **kwargs)
            observed.append(value)
            return value

        with mock.patch.object(
            seal_module,
            "read_active_policy",
            side_effect=read_while_contending,
        ):
            activate_policy(
                active,
                self.verified.policy_id,
                seals_root=self.seals,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
            activate_policy(
                active,
                newer.policy_id,
                seals_root=self.seals,
                expected_current_policy=self.verified.policy_id,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )
            rollback_policy(
                active,
                self.verified.policy_id,
                seals_root=self.seals,
                expected_current_policy=newer.policy_id,
                trusted_root=self.root,
                expected_uid=self.uid,
                expected_gid=self.gid,
            )

        self.assertEqual(observed[-1], self.verified.policy_id)


class RootBoundaryDeploymentTests(unittest.TestCase):
    def test_exact_local_repository_symlink_evidence_when_available(self):
        repository = Path(__file__).resolve().parents[2]
        specifications = (
            (
                "pmbootstrap",
                "LMI_P1_TEST_PMBOOTSTRAP_TREE",
                repository / "private/lmi-p1/calibration/seal-inputs-v1/pmbootstrap",
                "ce76febabd983db6445fa9a8b75d601970b2f436",
                "6ea77f76fe5914d44ed8c85ae51b81f1081e73b7",
                10,
            ),
            (
                "pmaports",
                "LMI_P1_TEST_PMAPORTS_TREE",
                repository / ".work/task2-review-stage",
                "6fb3a1e5eb21c809891645a2ba5ae11fa788e032",
                "749f154b6f154f86133e7c7616074aa9eb876f2e",
                1092,
            ),
        )
        available = []
        for component, environment, fallback, commit, tree, expected_links in specifications:
            configured = os.environ.get(environment)
            path = Path(configured).absolute() if configured else fallback
            if not path.is_dir():
                continue
            actual_commit, actual_tree = subprocess.check_output(
                ["git", "-C", str(path), "rev-parse", "HEAD", "HEAD^{tree}"],
                text=True,
            ).splitlines()
            self.assertEqual(actual_commit, commit, component)
            self.assertEqual(actual_tree, tree, component)
            index = subprocess.check_output(
                ["git", "-C", str(path), "ls-files", "-s", "-z"]
            )
            tracked_links = sum(
                record.startswith(b"120000 ")
                for record in index.split(b"\0")
                if record
            )
            self.assertEqual(tracked_links, expected_links, component)
            records = seal_module._inventory_member(
                path,
                component,
                expected_uid=os.getuid(),
                expected_gid=os.getgid(),
                non_directory_inodes={},
            )
            records.sort(key=lambda item: str(item["path"]))
            seal_module._validate_symlink_graph(records)
            inventory_links = sum(item["type"] == "symlink" for item in records)
            self.assertEqual(inventory_links, expected_links, component)
            available.append(component)
        if not available:
            self.skipTest(
                "exact pinned trees unavailable; set LMI_P1_TEST_PMBOOTSTRAP_TREE "
                "and LMI_P1_TEST_PMAPORTS_TREE"
            )

    def test_sudoers_policy_is_exact_launcher_only_and_offline_validated(self):
        repository = Path(__file__).resolve().parents[2]
        boundary = repository / "config/lmi-p1/root-boundary"
        policy = boundary / "90-lmi-p1-root-launcher"
        validator = boundary / "validate_sudoers.py"
        exact_command = (
            "/usr/bin/python3 -I -S -B "
            "/usr/local/sbin/lmi-p1-root-launcher"
        )
        self.assertEqual(
            policy.read_text(encoding="ascii"),
            "# lmi P1 sealed builder: the only delegated root command.\n"
            f"Cmnd_Alias LMI_P1_ROOT_LAUNCHER = {exact_command}\n"
            "Defaults!LMI_P1_ROOT_LAUNCHER !use_pty\n"
            "%lmi-p1-builders ALL=(root:root) NOPASSWD: NOSETENV: "
            "LMI_P1_ROOT_LAUNCHER\n",
        )
        effective = "\n".join(
            line for line in policy.read_text(encoding="ascii").splitlines()
            if line and not line.startswith("#")
        )
        self.assertEqual(effective.count(exact_command), 1)
        self.assertNotIn("lmi-p1-seal-installer", effective)
        self.assertNotIn("lmi-p1-policy-admin", effective)
        self.assertNotIn(" SETENV:", effective)

        completed = subprocess.run(
            [sys.executable, "-I", "-S", "-B", str(validator), str(policy)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)

        with tempfile.TemporaryDirectory() as temporary:
            broadened = Path(temporary) / "sudoers"
            broadened.write_text(
                policy.read_text(encoding="ascii").replace("NOSETENV", "SETENV"),
                encoding="ascii",
            )
            rejected = subprocess.run(
                [
                    sys.executable,
                    "-I",
                    "-S",
                    "-B",
                    str(validator),
                    str(broadened),
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        self.assertEqual(rejected.returncode, 1)

        visudo = Path("/usr/sbin/visudo")
        if visudo.is_file():
            syntax = subprocess.run(
                [str(visudo), "-c", "-f", str(policy)],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(syntax.returncode, 0, syntax.stderr)


if __name__ == "__main__":
    unittest.main()
