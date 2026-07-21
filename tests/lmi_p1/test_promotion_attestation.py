from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.offline_cache as offline_cache_module
import scripts.lmi_p1_cli as cli_module
from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.offline_cache import (
    PROMOTION_ATTESTATION_SCHEMA,
    PROMOTION_REPLAY_SCHEMA,
    canonical_json_bytes,
    load_promotion_authorization,
)


REPO = Path(__file__).resolve().parents[2]
ATTESTATION = REPO / "config/lmi-p1/offline-cache-promotion-attestation.json"
PROFILE = REPO / "config/lmi-p1/offline-cache-promotion.json"
REPLAY = REPO / "config/lmi-p1/offline-cache-promotion-replay.json"
SOURCE_LOCK = REPO / "config/lmi-p1/source-lock.json"
CURATION_PRODUCERS = ("scripts/lmi_p1/acquisition.py",)
PROMOTION_RUNTIME = (
    "scripts/lmi_p1/__init__.py",
    "scripts/lmi_p1/common.py",
    "scripts/lmi_p1/offline_cache.py",
    "scripts/lmi_p1_cli.py",
)
PRODUCERS = (*CURATION_PRODUCERS, *PROMOTION_RUNTIME)


class PromotionAttestationTests(unittest.TestCase):
    @staticmethod
    def _runtime_files(root: Path) -> dict[str, Path]:
        return {relative: root / relative for relative in PROMOTION_RUNTIME}

    def _load_current_authorization(self):
        with mock.patch.object(
            offline_cache_module,
            "_loaded_project_runtime_files",
            return_value=self._runtime_files(REPO),
        ):
            return load_promotion_authorization()

    def _load_copied_authorization(self, attestation: Path):
        project_root = attestation.parents[2]
        return offline_cache_module._load_promotion_authorization_from_context(
            project_root=project_root,
            attestation_path=attestation,
            runtime_files=self._runtime_files(project_root),
        )

    def test_reviewed_attestation_is_canonical_and_exactly_cross_bound(self):
        payload = ATTESTATION.read_bytes()
        value = json.loads(payload)
        self.assertEqual(payload, canonical_json_bytes(value))
        authorization = self._load_current_authorization()

        self.assertEqual(value["schema"], PROMOTION_ATTESTATION_SCHEMA)
        self.assertEqual(
            value["profile"],
            {
                "path": PROFILE.relative_to(REPO).as_posix(),
                "sha256": hashlib.sha256(PROFILE.read_bytes()).hexdigest(),
            },
        )
        self.assertEqual(
            value["acquisition"],
            {
                "schema": "lmi-p1-curated-offline-acquisition/v1",
                "inventory_sha256": "a9b517ee214de026ecd2d8adbbe4e336b129e9703e816929eb06606c702d81b7",
                "member_count": 584,
            },
        )
        self.assertEqual(
            value["producer_code"],
            {
                "curation": [
                    {
                        "path": relative,
                        "sha256": hashlib.sha256(
                            (REPO / relative).read_bytes()
                        ).hexdigest(),
                    }
                    for relative in CURATION_PRODUCERS
                ],
                "promotion_runtime": [
                {
                    "path": relative,
                    "sha256": hashlib.sha256((REPO / relative).read_bytes()).hexdigest(),
                }
                    for relative in PROMOTION_RUNTIME
                ],
            },
        )
        self.assertEqual(
            value["runtime_trust"],
            {
                "implementation": "CPython",
                "python_major_minor": "3.14",
                "stdlib": "host-interpreter-matched-stdlib-assumed-trusted",
            },
        )
        source_lock = json.loads(SOURCE_LOCK.read_bytes())
        self.assertEqual(
            value["published"],
            {**source_lock["offline_cache"], "member_count": 588},
        )
        self.assertEqual(
            authorization.trusted_pmbootstrap_commit,
            authorization.profile.pins["pmbootstrap"]["commit"],
        )
        bootstrap = authorization.profile.http_artifacts[0]
        self.assertEqual(
            Path(authorization.signer_key_path).name,
            Path(str(bootstrap["signer_key_path"])).name,
        )
        self.assertEqual(
            authorization.signer_key_sha256, bootstrap["signer_key_sha256"]
        )

    def test_runtime_closure_is_exact_and_records_review_only_ubuntu_provenance(self):
        value = json.loads(ATTESTATION.read_bytes())
        runtime = value["openssl_runtime"]
        self.assertEqual(runtime["review_distribution"], "Ubuntu")
        self.assertEqual(
            [(item["name"], item["version"]) for item in runtime["review_packages"]],
            [
                ("libc6", "2.43-2ubuntu2"),
                ("libssl3t64", "3.5.5-1ubuntu3.2"),
                ("libzstd1", "1.5.7+dfsg-3"),
                ("openssl", "3.5.5-1ubuntu3.2"),
                ("zlib1g", "1:1.3.dfsg+really1.3.1-1ubuntu3"),
            ],
        )
        self.assertEqual(
            {item["role"]: item["destination_basename"] for item in runtime["members"]},
            {
                "openssl": "openssl",
                "loader": "ld-linux-x86-64.so.2",
                "libssl": "libssl.so.3",
                "libcrypto": "libcrypto.so.3",
                "libc": "libc.so.6",
                "libz": "libz.so.1",
                "libzstd": "libzstd.so.1",
            },
        )
        self.assertEqual(len(runtime["members"]), 7)
        self.assertEqual(len({item["source_path"] for item in runtime["members"]}), 7)

    def test_replay_report_is_canonical_public_safe_same_acquisition_evidence(self):
        payload = REPLAY.read_bytes()
        report = json.loads(payload)
        self.assertEqual(payload, canonical_json_bytes(report))
        self.assertEqual(report["schema"], PROMOTION_REPLAY_SCHEMA)
        self.assertEqual(
            report["scope"], "same-curated-acquisition-reproducibility-replay"
        )
        self.assertEqual(report["first_promotion"], report["replay_promotion"])
        self.assertIs(report["comparison"]["byte_identical"], True)
        rendered = payload.decode("ascii")
        for forbidden in ("/home/", "private/", "secret", "token", "password"):
            self.assertNotIn(forbidden, rendered.lower())

    def _copy_authorization_tree(self, destination: Path) -> Path:
        paths = (*PRODUCERS, PROFILE.relative_to(REPO).as_posix(), REPLAY.relative_to(REPO).as_posix(), ATTESTATION.relative_to(REPO).as_posix())
        for relative in paths:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / relative, target)
            target.chmod(0o600)
        return destination / ATTESTATION.relative_to(REPO)

    def _mutated_tree(self) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, object]]:
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        root.chmod(0o700)
        attestation = self._copy_authorization_tree(root)
        return temporary, attestation, json.loads(attestation.read_bytes())

    def test_foreign_project_attestation_cannot_authorize_executing_module(self):
        temporary, attestation, _value = self._mutated_tree()
        self.addCleanup(temporary.cleanup)
        foreign_cli = attestation.parents[2] / "scripts/lmi_p1_cli.py"
        foreign_module = mock.Mock(__file__=str(foreign_cli))
        with (
            mock.patch.dict(
                "sys.modules", {"scripts.lmi_p1_cli": foreign_module}
            ),
            self.assertRaisesRegex(GateError, "not executing from its project root"),
        ):
            load_promotion_authorization()

    def test_runtime_inventory_detects_new_eager_local_module_without_allowlist_edit(self):
        temporary, attestation, _value = self._mutated_tree()
        self.addCleanup(temporary.cleanup)
        project_root = attestation.parents[2]
        runtime_files = self._runtime_files(project_root)
        runtime_files["scripts/lmi_p1/acquisition.py"] = (
            project_root / "scripts/lmi_p1/acquisition.py"
        )
        with self.assertRaisesRegex(GateError, "runtime producer inventory is incomplete"):
            offline_cache_module._load_promotion_authorization_from_context(
                project_root=project_root,
                attestation_path=attestation,
                runtime_files=runtime_files,
            )

    def test_runtime_discovery_covers_local_modules_outside_scripts(self):
        temporary, attestation, _value = self._mutated_tree()
        self.addCleanup(temporary.cleanup)
        project_root = attestation.parents[2]
        helper = project_root / "promotion_helper.py"
        helper.write_text("# synthetic eager project module\n", encoding="ascii")
        helper.chmod(0o600)
        files = {
            **self._runtime_files(project_root),
            "promotion_helper.py": helper,
        }
        modules = {
            f"_promotion_tcb_fixture_{index}": mock.Mock(__file__=str(path))
            for index, path in enumerate(files.values())
        }
        with mock.patch.dict(sys.modules, modules):
            discovered = offline_cache_module._loaded_project_runtime_files(
                project_root
            )
        self.assertEqual(discovered, files)

    def test_rejects_noncanonical_and_cross_binding_drift(self):
        mutations = {
            "profile hash": lambda value: value["profile"].__setitem__("sha256", "0" * 64),
            "pmbootstrap commit": lambda value: value["trusted_pmbootstrap"].__setitem__("commit", "0" * 40),
            "signer key": lambda value: value["trusted_pmbootstrap"].__setitem__("signer_key_sha256", "0" * 64),
            "producer code": lambda value: value["producer_code"][
                "promotion_runtime"
            ][0].__setitem__("sha256", "0" * 64),
            "published output": lambda value: value["published"].__setitem__("member_count", 587),
            "runtime trust": lambda value: value["runtime_trust"].__setitem__(
                "stdlib", "unreviewed-host-stdlib"
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                temporary, attestation, value = self._mutated_tree()
                self.addCleanup(temporary.cleanup)
                mutate(value)
                attestation.write_bytes(canonical_json_bytes(value))
                attestation.chmod(0o600)
                with self.assertRaises(GateError):
                    self._load_copied_authorization(attestation)

        temporary, attestation, value = self._mutated_tree()
        self.addCleanup(temporary.cleanup)
        attestation.write_text(json.dumps(value, indent=2) + "\n")
        attestation.chmod(0o600)
        with self.assertRaisesRegex(GateError, "not canonical"):
            self._load_copied_authorization(attestation)

    def test_rejects_runtime_missing_extra_duplicate_and_path_drift(self):
        for case in ("missing", "extra", "duplicate", "path"):
            with self.subTest(case=case):
                temporary, attestation, value = self._mutated_tree()
                self.addCleanup(temporary.cleanup)
                members = value["openssl_runtime"]["members"]
                if case == "missing":
                    members.pop()
                elif case == "extra":
                    members.append(dict(members[0], role="unexpected"))
                elif case == "duplicate":
                    members[1]["role"] = members[0]["role"]
                else:
                    member = next(item for item in members if item["role"] == "openssl")
                    member["source_path"] = "/usr/bin/../bin/openssl"
                attestation.write_bytes(canonical_json_bytes(value))
                attestation.chmod(0o600)
                with self.assertRaisesRegex(GateError, "runtime|source path"):
                    self._load_copied_authorization(attestation)

    def test_rejects_replay_claiming_independent_supply_chain_reproduction(self):
        temporary, attestation, value = self._mutated_tree()
        self.addCleanup(temporary.cleanup)
        project_root = attestation.parents[2]
        replay_path = project_root / value["replay_report"]["path"]
        replay = json.loads(replay_path.read_bytes())
        replay["scope"] = "independent-supply-chain-reproduction"
        replay_payload = canonical_json_bytes(replay)
        replay_path.write_bytes(replay_payload)
        replay_path.chmod(0o600)
        value["replay_report"]["sha256"] = hashlib.sha256(replay_payload).hexdigest()
        attestation.write_bytes(canonical_json_bytes(value))
        attestation.chmod(0o600)
        with self.assertRaisesRegex(GateError, "same-acquisition"):
            self._load_copied_authorization(attestation)


if __name__ == "__main__":
    unittest.main()
