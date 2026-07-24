from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
from pathlib import Path
import shutil
from types import SimpleNamespace
import tempfile
import unittest
from unittest import mock

from scripts.lmi_p1.common import GateError
import scripts.lmi_p1.offline_cache as offline_cache
import scripts.lmi_p1.offline_cache_calibration as calibration


REPO = Path(__file__).resolve().parents[2]


class OfflineCacheCalibrationTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.root.chmod(0o700)
        (self.root / "config/lmi-p1").mkdir(parents=True)
        (self.root / "private/lmi-p1/calibration").mkdir(parents=True)
        (self.root / "private/lmi-p1/calibration").chmod(0o700)
        for relative in calibration._CALIBRATION_RUNTIME_PATHS:
            self._write(relative, f"# {relative}\n".encode("ascii"))
        self.profile_value = {"fixture": "profile"}
        self.profile_payload = offline_cache.canonical_json_bytes(
            self.profile_value
        )
        self._write(calibration._PROFILE_RELATIVE, self.profile_payload)
        self.base = self._base_trust()

    def _write(self, relative: str, payload: bytes, mode: int = 0o600) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(mode)
        return path

    def _directory(self, relative: str) -> Path:
        path = self.root / relative
        path.mkdir(parents=True)
        path.chmod(0o700)
        return path

    @staticmethod
    def _config_hashes(root: Path) -> dict[str, str]:
        config = root / "config/lmi-p1"
        return {
            path.relative_to(root).as_posix(): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in sorted(config.rglob("*"))
            if path.is_file()
        }

    def _base_trust(self) -> calibration._BaseTrust:
        output = {
            "schema": offline_cache.MANIFEST_SCHEMA,
            "manifest_sha256": "1" * 64,
            "aggregate_sha256": "2" * 64,
            "member_count": 588,
        }
        runtime_trust = {
            "implementation": "CPython",
            "python_major_minor": (
                f"{os.sys.version_info.major}.{os.sys.version_info.minor}"
            ),
            "stdlib": "host-interpreter-matched-stdlib-assumed-trusted",
        }
        profile = SimpleNamespace(
            repositories=(),
            http_artifacts=(
                {
                    "path": "work/cache_http/apk-tools-static.apk",
                    "name": "apk-tools-static",
                },
            ),
            distfiles=(),
            as_mapping=lambda: dict(self.profile_value),
        )
        value = {
            "schema": offline_cache.PROMOTION_ATTESTATION_SCHEMA,
            "profile": {
                "path": calibration._PROFILE_RELATIVE,
                "sha256": hashlib.sha256(self.profile_payload).hexdigest(),
            },
            "trusted_pmbootstrap": {
                "commit": "a" * 40,
                "tree": "b" * 40,
                "signer_key_path": (
                    "pmb/data/keys/alpine-devel@lists.alpinelinux.org"
                    "-6165ee59.rsa.pub"
                ),
                "signer_key_sha256": "c" * 64,
            },
            "acquisition": {
                "schema": "lmi-p1-curated-offline-acquisition/v1",
                "inventory_sha256": "d" * 64,
                "member_count": 584,
            },
            "producer_code": {
                "curation": [
                    {
                        "path": "scripts/lmi_p1/acquisition.py",
                        "sha256": "e" * 64,
                    }
                ],
                "promotion_runtime": [],
            },
            "runtime_trust": runtime_trust,
            "apk_static": {
                "extracted_member": "sbin/apk.static",
                "sha256": "f" * 64,
                "size": 10,
                "version": "3.0.6-r0",
            },
            "openssl_runtime": {
                "members": [],
                "review_distribution": "Ubuntu",
                "review_packages": [],
                "version": "3.5.5",
            },
            "published": output,
            "replay_report": {
                "path": calibration._CANONICAL_REPLAY_RELATIVE,
                "sha256": "0" * 64,
            },
        }
        authorization = SimpleNamespace(
            profile=profile,
            profile_sha256=hashlib.sha256(self.profile_payload).hexdigest(),
            trusted_pmbootstrap_commit="a" * 40,
            trusted_pmbootstrap_tree="b" * 40,
            signer_key_path=value["trusted_pmbootstrap"]["signer_key_path"],
            signer_key_sha256="c" * 64,
            acquisition_member_count=584,
            acquisition_inventory_sha256="d" * 64,
            expected_output=output,
            runtime_trust=runtime_trust,
            bootstrap_pins=object(),
        )
        payload = offline_cache.canonical_json_bytes(value)
        return calibration._BaseTrust(value, payload, authorization)

    def _prepare_directories(self) -> tuple[Path, Path, Path]:
        return (
            self._directory("private/lmi-p1/calibration/trusted"),
            self._directory("private/lmi-p1/calibration/cache"),
            self._directory("private/lmi-p1/calibration/acquisition"),
        )

    def _draft_bindings(self) -> calibration._OfflineBindings:
        return calibration._OfflineBindings(
            verifier_factory=mock.Mock(),
            promoter=mock.Mock(),
            cache_reader=mock.Mock(),
        )

    def test_prepare_emits_exact_private_draft_and_never_config(self) -> None:
        trusted, cache, acquisition = self._prepare_directories()
        output = self.root / "private/lmi-p1/calibration/review-draft.json"
        base_output = dict(self.base.authorization.expected_output)
        before = self._config_hashes(self.root)
        with (
            mock.patch.object(
                calibration, "_load_base_trust", return_value=self.base
            ),
            mock.patch.object(calibration, "_validate_trusted_pmbootstrap"),
            mock.patch.object(
                calibration,
                "_validate_base_cache",
                return_value=(object(), base_output),
            ),
            mock.patch.object(
                calibration,
                "_acquisition_identity",
                return_value=(586, "9" * 64),
            ),
        ):
            result = calibration._prepare_calibration(
                self.root,
                bindings=self._draft_bindings(),
                new_acquisition=acquisition,
                base_cache=cache,
                trusted_pmbootstrap=trusted,
                tag="ssh-full-20260724",
                output=output,
            )
        value = json.loads(output.read_bytes())
        self.assertEqual(output.read_bytes(), offline_cache.canonical_json_bytes(value))
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(result["draft"], output)
        self.assertEqual(value["acquisition"]["member_count"], 586)
        self.assertEqual(value["acquisition"]["inventory_sha256"], "9" * 64)
        self.assertEqual(
            value["execution_bundle"]["path"],
            "private/lmi-p1/calibration/ssh-full-20260724",
        )
        self.assertNotIn("published", value)
        self.assertFalse(
            (self.root / calibration._CANONICAL_AUTHORIZATION_RELATIVE).exists()
        )
        self.assertEqual(self._config_hashes(self.root), before)

    def test_prepare_rejects_symlink_and_input_nested_output(self) -> None:
        real = self._directory("private/lmi-p1/calibration/real")
        linked = self.root / "private/lmi-p1/calibration/linked"
        linked.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(GateError, "real directory"):
            calibration._private_relative_directory(
                self.root, linked, label="linked input"
            )
        nested = real / "draft.json"
        _, relative = calibration._new_private_file(
            self.root, nested, label="draft"
        )
        self.assertEqual(
            relative, "private/lmi-p1/calibration/real/draft.json"
        )

    def test_runtime_drift_is_detected_against_authorized_hashes(self) -> None:
        authorized = calibration._calibration_runtime(self.root)
        changed = self.root / calibration._CALIBRATION_RUNTIME_PATHS[-1]
        changed.write_bytes(b"# drifted calibration runtime\n")
        changed.chmod(0o600)
        with self.assertRaisesRegex(GateError, "runtime hash drift"):
            calibration._validate_runtime_record(
                self.root,
                authorized,
                calibration._CALIBRATION_RUNTIME_PATHS,
            )

    def _snapshot_state(self, tag: str) -> calibration._ExecutionState:
        source = self._directory(
            f"private/lmi-p1/calibration/source-{tag}"
        )
        for directory in (
            "cache_apk_aarch64",
            "cache_apk_x86_64",
            "cache_http",
            "cache_distfiles",
        ):
            child = source / directory
            child.mkdir()
            child.chmod(0o700)
        version = source / "version"
        version.write_bytes(b"8\n")
        version.chmod(0o600)
        inventory = [
            {
                "path": "version",
                "size": 2,
                "sha256": hashlib.sha256(b"8\n").hexdigest(),
            }
        ]
        digest = hashlib.sha256(
            offline_cache.canonical_json_bytes(inventory)
        ).hexdigest()
        profile = SimpleNamespace(
            repositories=(),
            http_artifacts=(),
            distfiles=(),
        )
        base = calibration._BaseTrust(
            self.base.value,
            self.base.payload,
            SimpleNamespace(
                **{
                    **vars(self.base.authorization),
                    "profile": profile,
                }
            ),
        )
        authorization_path = self._write(
            calibration._CANONICAL_AUTHORIZATION_RELATIVE,
            b"authorization\n",
        )
        held_authorization = calibration._hold_authorization(
            authorization_path, authorization_path.read_bytes()
        )
        self.addCleanup(held_authorization.close)
        return calibration._ExecutionState(
            root=self.root,
            authorization_path=authorization_path,
            authorization_payload_sha256=hashlib.sha256(
                authorization_path.read_bytes()
            ).hexdigest(),
            authorization_file=held_authorization,
            base=base,
            trusted_pmbootstrap=source,
            base_cache=source,
            acquisition=source,
            acquisition_member_count=1,
            acquisition_inventory_sha256=digest,
            bundle=self.root / "private/lmi-p1/calibration" / tag,
            calibration_runtime=tuple(
                calibration._calibration_runtime(self.root)
            ),
        )

    def test_descriptor_snapshot_detects_member_and_path_rebinding(self) -> None:
        state = self._snapshot_state("snapshot")
        bundle = calibration._create_bundle(state.bundle)
        snapshot = calibration._create_acquisition_snapshot(state, bundle)
        self.addCleanup(snapshot.close)
        self.addCleanup(bundle.close)
        calibration._validate_snapshot(snapshot, label="control snapshot")

        member = snapshot.directory.path / "version"
        member.write_bytes(b"9\n")
        member.chmod(0o600)
        with self.assertRaisesRegex(GateError, "held member changed"):
            calibration._validate_snapshot(snapshot, label="mutated snapshot")

        # Restore bytes by replacing the pathname; the held descriptor still
        # names the original inode and therefore detects the path rebind.
        replacement = snapshot.directory.path / "replacement"
        replacement.write_bytes(b"8\n")
        replacement.chmod(0o600)
        member.unlink()
        replacement.rename(member)
        with self.assertRaisesRegex(GateError, "held member changed|rebound"):
            calibration._validate_snapshot(snapshot, label="rebound snapshot")

    def test_snapshot_root_or_ancestor_swap_fails_binding(self) -> None:
        state = self._snapshot_state("root-swap")
        bundle = calibration._create_bundle(state.bundle)
        snapshot = calibration._create_acquisition_snapshot(state, bundle)
        self.addCleanup(snapshot.close)
        self.addCleanup(bundle.close)
        displaced = state.bundle / "displaced.snapshot"
        snapshot.directory.path.rename(displaced)
        snapshot.directory.path.mkdir(mode=0o700)
        with self.assertRaisesRegex(GateError, "no longer names"):
            calibration._validate_snapshot(snapshot, label="swapped snapshot")

    def test_source_path_swap_after_snapshot_fails_binding(self) -> None:
        state = self._snapshot_state("source-swap")
        bundle = calibration._create_bundle(state.bundle)
        snapshot = calibration._create_acquisition_snapshot(state, bundle)
        self.addCleanup(snapshot.close)
        self.addCleanup(bundle.close)
        displaced = state.acquisition.parent / "displaced.source"
        state.acquisition.rename(displaced)
        state.acquisition.mkdir(mode=0o700)
        with self.assertRaisesRegex(GateError, "no longer names"):
            calibration._validate_snapshot(
                snapshot, label="source-swapped snapshot"
            )

    def test_output_manifest_must_match_held_snapshot_members(self) -> None:
        state = self._snapshot_state("output-bind")
        bundle = calibration._create_bundle(state.bundle)
        snapshot = calibration._create_acquisition_snapshot(state, bundle)
        self.addCleanup(snapshot.close)
        self.addCleanup(bundle.close)
        member = snapshot.files[0]
        manifest = {
            "members": [
                {
                    "path": member.path,
                    "size": member.size,
                    "sha256": member.sha256,
                }
            ]
        }
        verified = SimpleNamespace(manifest=manifest)
        calibration._bind_output_to_snapshot(state, snapshot, verified)
        manifest["members"][0]["sha256"] = "0" * 64
        with self.assertRaisesRegex(GateError, "not byte-bound"):
            calibration._bind_output_to_snapshot(state, snapshot, verified)

    def _transaction_callables(
        self,
        *,
        state: calibration._ExecutionState,
        promote: object,
        revalidate: object,
    ) -> calibration._TransactionCallables:
        return calibration._TransactionCallables(
            load_state=lambda root, bindings: state,
            create_bundle=calibration._create_bundle,
            create_snapshot=calibration._create_acquisition_snapshot,
            validate_snapshot=calibration._validate_snapshot,
            promote=promote,
            revalidate_published=revalidate,
            bind_output=lambda *args: None,
            revalidate_inputs=lambda *args: None,
            candidate_values=lambda *args: ({}, {}),
            write_bundle=calibration._write_bundle_canonical,
            receipt=lambda **kwargs: {},
        )

    def test_mutation_during_each_promotion_blocks_before_candidates(self) -> None:
        for target_call in (1, 2):
            with self.subTest(target_call=target_call):
                state = self._snapshot_state(f"mutation-{target_call}")
                calls = 0

                def promote(**kwargs: object) -> None:
                    nonlocal calls
                    del kwargs
                    calls += 1
                    if calls == target_call:
                        path = (
                            state.bundle
                            / calibration._SNAPSHOT_DIRECTORY
                            / "version"
                        )
                        path.write_bytes(b"9\n")
                        path.chmod(0o600)

                revalidate = mock.Mock(
                    return_value=(
                        SimpleNamespace(manifest={}),
                        b"first\n",
                        {"member_count": 1},
                    )
                )
                callables = self._transaction_callables(
                    state=state,
                    promote=promote,
                    revalidate=revalidate,
                )
                with self.assertRaisesRegex(GateError, "held member changed"):
                    calibration._execute_canonical_transaction(
                        self.root,
                        self._draft_bindings(),
                        callables,
                    )
                self.assertFalse(
                    (
                        state.bundle / calibration._CANDIDATE_ATTESTATION
                    ).exists()
                )

    def test_final_phase_revalidates_both_outputs_again(self) -> None:
        state = self._snapshot_state("final-revalidation")
        output = {
            "schema": offline_cache.MANIFEST_SCHEMA,
            "manifest_sha256": "3" * 64,
            "aggregate_sha256": "4" * 64,
            "member_count": 5,
        }
        verified = SimpleNamespace(manifest={"members": []})
        revalidate = mock.Mock(
            side_effect=[
                (verified, b"same\n", output),
                (verified, b"same\n", output),
                (verified, b"same\n", output),
                GateError("final replay revalidation reached"),
            ]
        )
        callables = self._transaction_callables(
            state=state,
            promote=lambda **kwargs: None,
            revalidate=revalidate,
        )
        with self.assertRaisesRegex(
            GateError, "final replay revalidation reached"
        ):
            calibration._execute_canonical_transaction(
                self.root, self._draft_bindings(), callables
            )
        self.assertEqual(revalidate.call_count, 4)
        self.assertFalse(
            (state.bundle / calibration._CANDIDATE_ATTESTATION).exists()
        )

    def _copy_production_trust_tree(self, destination: Path) -> None:
        attestation = json.loads(
            (REPO / calibration._BASE_ATTESTATION_RELATIVE).read_bytes()
        )
        relatives = {
            calibration._BASE_ATTESTATION_RELATIVE,
            calibration._PROFILE_RELATIVE,
            calibration._CANONICAL_REPLAY_RELATIVE,
            *(
                item["path"]
                for inventory in attestation["producer_code"].values()
                for item in inventory
            ),
            *calibration._CALIBRATION_RUNTIME_PATHS,
        }
        for relative in relatives:
            source = REPO / relative
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o600)

    def test_real_canonical_calibration_authorization_loader_fixture(self) -> None:
        fixture = self.root / "loader-fixture"
        fixture.mkdir(mode=0o700)
        self._copy_production_trust_tree(fixture)
        for relative in (
            "private/lmi-p1/calibration/trusted",
            "private/lmi-p1/calibration/base-cache",
            "private/lmi-p1/calibration/acquisition",
        ):
            path = fixture / relative
            path.mkdir(parents=True)
            path.chmod(0o700)
        base = calibration._load_base_trust(fixture)
        base_output = dict(base.authorization.expected_output)
        value = {
            "schema": calibration.CALIBRATION_AUTHORIZATION_SCHEMA,
            "base_attestation": {
                "path": calibration._BASE_ATTESTATION_RELATIVE,
                "sha256": hashlib.sha256(base.payload).hexdigest(),
            },
            "profile": {
                "path": calibration._PROFILE_RELATIVE,
                "sha256": base.authorization.profile_sha256,
            },
            "trusted_pmbootstrap": {
                "path": "private/lmi-p1/calibration/trusted",
                "commit": base.authorization.trusted_pmbootstrap_commit,
                "tree": base.authorization.trusted_pmbootstrap_tree,
                "signer_key_path": base.authorization.signer_key_path,
                "signer_key_sha256": base.authorization.signer_key_sha256,
            },
            "base_cache": {
                "path": "private/lmi-p1/calibration/base-cache",
                "expected_output": base_output,
            },
            "acquisition": {
                "schema": "lmi-p1-curated-offline-acquisition/v1",
                "path": "private/lmi-p1/calibration/acquisition",
                "member_count": 586,
                "inventory_sha256": "9" * 64,
            },
            "execution_bundle": {
                "path": "private/lmi-p1/calibration/fixture-run"
            },
            "calibration_runtime": calibration._calibration_runtime(fixture),
            "runtime_trust": dict(base.authorization.runtime_trust),
            "apk_static": base.value["apk_static"],
            "openssl_runtime": base.value["openssl_runtime"],
        }
        authorization_path = (
            fixture / calibration._CANONICAL_AUTHORIZATION_RELATIVE
        )
        authorization_path.write_bytes(
            offline_cache.canonical_json_bytes(value)
        )
        authorization_path.chmod(0o600)
        bindings = calibration._OfflineBindings(
            verifier_factory=None,
            promoter=None,
            cache_reader=mock.Mock(),
        )
        with (
            mock.patch.object(calibration, "_validate_trusted_pmbootstrap"),
            mock.patch.object(
                calibration,
                "_validate_base_cache",
                return_value=(object(), base_output),
            ),
            mock.patch.object(
                calibration,
                "_acquisition_identity",
                return_value=(586, "9" * 64),
            ),
        ):
            state = calibration._load_execution_state(fixture, bindings)
        self.addCleanup(state.authorization_file.close)
        self.assertEqual(state.authorization_path, authorization_path)
        self.assertEqual(state.acquisition_member_count, 586)
        self.assertFalse(state.bundle.exists())

    def test_candidate_is_accepted_by_production_v3_loader_fixture(self) -> None:
        fixture = self.root / "candidate-fixture"
        fixture.mkdir(mode=0o700)
        self._copy_production_trust_tree(fixture)
        base = calibration._load_base_trust(fixture)
        authorization_path = (
            fixture / calibration._CANONICAL_AUTHORIZATION_RELATIVE
        )
        authorization_path.write_bytes(b"candidate authorization fixture\n")
        authorization_path.chmod(0o600)
        held_authorization = calibration._hold_authorization(
            authorization_path, authorization_path.read_bytes()
        )
        self.addCleanup(held_authorization.close)
        state = calibration._ExecutionState(
            root=fixture,
            authorization_path=authorization_path,
            authorization_payload_sha256=hashlib.sha256(
                authorization_path.read_bytes()
            ).hexdigest(),
            authorization_file=held_authorization,
            base=base,
            trusted_pmbootstrap=fixture,
            base_cache=fixture,
            acquisition=fixture,
            acquisition_member_count=586,
            acquisition_inventory_sha256="9" * 64,
            bundle=fixture / "private/lmi-p1/calibration/candidate",
            calibration_runtime=tuple(
                calibration._calibration_runtime(fixture)
            ),
        )
        output = {
            "schema": offline_cache.MANIFEST_SCHEMA,
            "manifest_sha256": "6" * 64,
            "aggregate_sha256": "7" * 64,
            "member_count": 590,
        }
        replay, attestation = calibration._candidate_values(state, output)
        replay_path = fixture / calibration._CANONICAL_REPLAY_RELATIVE
        replay_path.write_bytes(offline_cache.canonical_json_bytes(replay))
        replay_path.chmod(0o600)
        attestation_path = fixture / calibration._BASE_ATTESTATION_RELATIVE
        attestation_path.write_bytes(
            offline_cache.canonical_json_bytes(attestation)
        )
        attestation_path.chmod(0o600)
        runtime_files = {
            relative: fixture / relative
            for relative in calibration._PRODUCTION_RUNTIME_PATHS
        }
        loaded = offline_cache._load_promotion_authorization_from_context(
            project_root=fixture,
            attestation_path=attestation_path,
            runtime_files=runtime_files,
        )
        self.assertEqual(dict(loaded.expected_output), output)
        self.assertEqual(loaded.acquisition_member_count, 586)

    def test_execution_receipt_binds_candidates_outputs_and_runtime(self) -> None:
        state = self._snapshot_state("receipt")
        bundle = calibration._create_bundle(state.bundle)
        snapshot = calibration._create_acquisition_snapshot(state, bundle)
        self.addCleanup(snapshot.close)
        self.addCleanup(bundle.close)
        output = {
            "schema": offline_cache.MANIFEST_SCHEMA,
            "manifest_sha256": "3" * 64,
            "aggregate_sha256": "4" * 64,
            "member_count": 5,
        }
        receipt = calibration._execution_receipt(
            state=state,
            snapshot=snapshot,
            first_path=state.bundle / calibration._FIRST_PUBLISHED,
            first_payload=b"manifest\n",
            first_output=output,
            replay_path=state.bundle / calibration._REPLAY_PUBLISHED,
            replay_payload=b"manifest\n",
            replay_output=output,
            candidate_replay_payload=b"replay\n",
            candidate_attestation_payload=b"attestation\n",
        )
        payload = calibration._write_bundle_canonical(
            bundle,
            calibration._EXECUTION_RECEIPT,
            receipt,
            label="test execution receipt",
        )
        self.assertEqual(
            payload, offline_cache.canonical_json_bytes(receipt)
        )
        self.assertEqual(
            receipt["authorization"]["sha256"],
            state.authorization_payload_sha256,
        )
        self.assertEqual(
            receipt["acquisition"]["source"]["inventory_sha256"],
            snapshot.inventory_sha256,
        )
        self.assertTrue(receipt["comparison"]["manifest_bytes_identical"])
        self.assertEqual(
            receipt["assurance"], calibration._RECEIPT_ASSURANCE
        )
        rendered_assurance = json.dumps(receipt["assurance"])
        for required in (
            "byte-equivalent",
            "reopens an ordinary pathname",
            "does not claim",
            "same-UID pathname A-B-A",
            "ptrace",
            "post-exit evidence rewrite",
            "privileged or kernel compromise",
        ):
            self.assertIn(required, rendered_assurance)

    def test_public_execute_rejects_callable_rebinding_before_state_load(self) -> None:
        before = self._config_hashes(REPO)
        missing_authorization = (
            "could not inspect canonical calibration authorization"
        )
        for removed in (
            "_VERIFIER_FACTORY",
            "_PROMOTE_OFFLINE_CACHE",
            "_READ_OFFLINE_CACHE",
        ):
            self.assertFalse(hasattr(calibration, removed))
        with self.assertRaisesRegex(GateError, missing_authorization):
            calibration.execute_calibration()
        self.assertEqual(self._config_hashes(REPO), before)
        for name in (
            "_resolve_local_function",
            "_canonical_function",
            "_resolve_offline_bindings",
            "_load_execution_state",
            "_bootstrap_and_promote",
            "_revalidate_published",
            "_write_bundle_canonical",
        ):
            replacement = mock.Mock()
            with (
                self.subTest(name=name),
                mock.patch.object(calibration, name, replacement),
                self.assertRaisesRegex(GateError, missing_authorization),
            ):
                calibration.execute_calibration()
            replacement.assert_not_called()
            self.assertEqual(self._config_hashes(REPO), before)

        for name in (
            "bootstrap_apk_static_verifier",
            "promote_offline_cache",
            "read_offline_cache_manifest",
        ):
            replacement = mock.Mock()
            with (
                self.subTest(name=name),
                mock.patch.object(offline_cache, name, replacement),
                self.assertRaisesRegex(GateError, missing_authorization),
            ):
                calibration.execute_calibration()
            replacement.assert_not_called()
            self.assertEqual(self._config_hashes(REPO), before)

        replacement_execute = mock.Mock()
        with (
            mock.patch.object(
                calibration, "execute_calibration", replacement_execute
            ),
            mock.patch("sys.stderr", new=io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            calibration.main(["execute"])
        replacement_execute.assert_not_called()
        self.assertEqual(self._config_hashes(REPO), before)

        captured_loader = calibration._load_execution_state
        original_code = captured_loader.__code__
        try:
            captured_loader.__code__ = (lambda: None).__code__
            with self.assertRaisesRegex(GateError, "captured callable code"):
                calibration.execute_calibration()
        finally:
            captured_loader.__code__ = original_code
        self.assertEqual(self._config_hashes(REPO), before)

    def test_public_cli_has_no_authorization_verifier_pin_or_root_seam(self) -> None:
        self.assertEqual(tuple(inspect.signature(calibration.execute_calibration).parameters), ())
        parser = calibration.build_parser()
        for arguments in (
            ["execute", "--authorization", "other.json"],
            ["execute", "--verifier", "fixture"],
            ["execute", "--root", "/tmp/other"],
        ):
            with (
                mock.patch("sys.stderr", new=io.StringIO()),
                self.assertRaises(SystemExit),
            ):
                parser.parse_args(arguments)


if __name__ == "__main__":
    unittest.main()
