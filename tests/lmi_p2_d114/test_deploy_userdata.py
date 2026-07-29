from __future__ import annotations

import base64
import contextlib
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import tempfile
import unittest
from unittest import mock

from scripts.lmi_p2_d114 import deploy_userdata as deploy
from tests.lmi_p2_d114 import host_bound


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def sha(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sparse(raw: bytes) -> bytes:
    if not raw or len(raw) % 4096:
        raise ValueError("fixture raw must contain complete sparse blocks")
    blocks = len(raw) // 4096
    return (
        deploy.SPARSE_HEADER.pack(deploy.SPARSE_MAGIC, 1, 0, 28, 12, 4096, blocks, 1, 0)
        + deploy.CHUNK_HEADER.pack(deploy.CHUNK_RAW, 0, blocks, 12 + len(raw))
        + raw
    )


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.chmod(0o700)
        for directory in (
            "artifacts",
            "config/lmi-p2-d114",
            "logs",
            "private/lmi-p1/recovery/d110-d114",
        ):
            path = root / directory
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

        self.serial = "fixture-device-01"
        self.nonce = "11" * 32
        self.identity = sha(self.nonce.encode("ascii") + b"\0" + self.serial.encode("ascii"))
        self.root_uuid = "12345678-1234-4234-9234-123456789abc"
        self.boot_uuid = "87654321-4321-4321-8321-cba987654321"
        self.candidate_raw = b"C" * 4096 + b"D" * 4096
        self.rollback_raw = b"R" * 8192
        self.candidate_sparse = sparse(self.candidate_raw)
        self.rollback_sparse = sparse(self.rollback_raw)
        self.p2_sha = "22" * 32
        self.boot_sha = "33" * 32

        self.bundle = self.root / "artifacts/candidate.bundle"
        self.bundle.mkdir()
        self.bundle.chmod(0o700)
        self.write("artifacts/candidate.bundle/userdata.raw", self.candidate_raw)
        self.write("artifacts/candidate.bundle/userdata.android-sparse.img", self.candidate_sparse)
        self.write("artifacts/rollback.android-sparse.img", self.rollback_sparse)

        source_lock = {
            "baseline": {
                "boot_sha256": self.boot_sha,
                "boot_size": 4096,
                "boot_uuid": self.boot_uuid,
                "gpt_logical_sector_size": 4096,
                "root_uuid": self.root_uuid,
                "userdata_raw_sha256": sha(self.rollback_raw),
                "userdata_raw_size": len(self.rollback_raw),
                "userdata_sparse_sha256": sha(self.rollback_sparse),
                "userdata_sparse_size": len(self.rollback_sparse),
            },
            "schema": "lmi-p2-d114-terminal-source-lock/v1",
        }
        source_bytes = canonical(source_lock)
        self.write("config/lmi-p2-d114/source-lock.json", source_bytes)

        evidence_values: dict[str, bytes] = {
            "runtime_storage_log": (
                "/dev/block/by-name/userdata -> ../../sda34\n"
                "/dev/disk/by-partlabel/userdata -> ../../sda34\n"
                "brw-r--r--    1 0        0         259,  61 Nov 27 17:27 /dev/sda34\n"
                "Disk /dev/sda34: 224411608 sectors, 63.8M\n"
                "Logical sector size: 4096\n"
                "Mount subpartitions of /dev/sda34\n"
                "SUBPARTITION_DEV=/dev/sda34\n"
                "/dev/loop0: [0002]:570 (/dev/sda34)\n"
                "/dev/sda34: PTTYPE=\"gpt\" PARTLABEL=\"userdata\"\n"
            ).encode("ascii"),
            "d198_contract": canonical(
                {
                    "attempt": {"result": "success"},
                    "evidence_report": "private/lmi-p1/recovery/d110-d114/d198_write_report",
                    "evidence_route_status": "DEPLOY_USERDATA_WRITE_COMPLETED_POSTVERIFY_FAILED_STAY_IN_BOOTLOADER",
                    "execution_contract": {"artifact_sha256": sha(self.rollback_sparse), "target": "userdata"},
                    "experiment_id": "d198-userdata-d114-splash-recursion-fix",
                    "status": "completed",
                }
            ),
            "d198_write_report": (
                "write_command_started=1\nwrite_command_exit=0\n"
                "route_status=DEPLOY_USERDATA_WRITE_COMPLETED_POSTVERIFY_FAILED_STAY_IN_BOOTLOADER\n"
            ).encode("ascii"),
            "d199_preflight_report": (
                f"product=lmi\nuserdata_capacity_bytes={deploy.USERDATA_CAPACITY}\n"
                "postwrite_userdata_write_sha256={d198_sha}\n"
                "route_status=DEPLOY_PREFLIGHT_PASSED_NO_STATE_CHANGE\n"
            ),
            "private_identity_policy": canonical(
                {
                    "device": {"product": "lmi"},
                    "historical_identity": {
                        "expected_nonce_scoped_serial_sha256": self.identity,
                        "privacy_nonce": self.nonce,
                    },
                    "schema": "lmi-d110-recovery-policy/v2",
                }
            ),
        }
        d198_report_sha = sha(evidence_values["d198_write_report"])
        evidence_values["d199_preflight_report"] = evidence_values["d199_preflight_report"].format(d198_sha=d198_report_sha).encode("ascii")
        evidence_values["d199_replug_attestation"] = canonical(
            {
                "evidence_report": "private/lmi-p1/recovery/d110-d114/d199_preflight_report",
                "evidence_route_status": "DEPLOY_PREFLIGHT_PASSED_NO_STATE_CHANGE",
                "execution_contract": {"profile_sha256": "44" * 32},
                "experiment_id": "d199-d114-postwrite-replug-fastboot-attestation",
                "gates": {"rollback": {"evidence_sha256": d198_report_sha}},
                "outcome": "positive",
                "status": "completed",
            }
        )
        evidence_specs: dict[str, dict[str, object]] = {}
        for name, payload in evidence_values.items():
            relative = f"private/lmi-p1/recovery/d110-d114/{name}"
            if name == "runtime_storage_log":
                relative = "logs/runtime-storage.log"
            self.write(relative, payload)
            evidence_specs[name] = {"path": relative, "sha256": sha(payload), "size": len(payload)}

        mapping = {
            "cross_bindings": {
                "d198": {
                    "artifact_sha256": sha(self.rollback_sparse),
                    "evidence_report_path": "private/lmi-p1/recovery/d110-d114/d198_write_report",
                    "evidence_report_sha256": evidence_specs["d198_write_report"]["sha256"],
                    "evidence_route_status": "DEPLOY_USERDATA_WRITE_COMPLETED_POSTVERIFY_FAILED_STAY_IN_BOOTLOADER",
                    "experiment_id": "d198-userdata-d114-splash-recursion-fix",
                    "target": "userdata",
                },
                "d199": {
                    "evidence_report_path": "private/lmi-p1/recovery/d110-d114/d199_preflight_report",
                    "evidence_report_sha256": evidence_specs["d199_preflight_report"]["sha256"],
                    "evidence_route_status": "DEPLOY_PREFLIGHT_PASSED_NO_STATE_CHANGE",
                    "execution_profile_sha256": "44" * 32,
                    "experiment_id": "d199-d114-postwrite-replug-fastboot-attestation",
                    "prior_d198_write_report_sha256": evidence_specs["d198_write_report"]["sha256"],
                },
                "runtime": {
                    "block_device": "/dev/sda34", "block_major": 259, "block_minor": 61,
                    "capacity_bytes": deploy.USERDATA_CAPACITY, "logical_sector_size": 4096,
                    "partlabel": "userdata",
                },
            },
            "evidence": evidence_specs,
            "identity_binding": {
                "current_device_must_match_nonce_scoped_private_policy": True,
                "public_stable_fingerprint_forbidden": True,
            },
            "override": {
                "allowed_getvar_result": "unsupported",
                "fastboot_mode": "bootloader",
                "partition": "userdata",
                "partition_type": "f2fs",
                "super_or_fastbootd_fallback_allowed": False,
            },
            "schema": deploy.MAPPING_SCHEMA,
            "userdata": {
                "backup_gpt_entries": {
                    "first_lba": 28051446,
                    "last_lba": 28051449,
                    "sector_count": 4,
                },
                "backup_gpt_header_lba": 28051450,
                "block_device": "/dev/sda34",
                "block_major": 259,
                "block_minor": 61,
                "by_name_path": "/dev/block/by-name/userdata",
                "by_name_target": "../../sda34",
                "by_partlabel_path": "/dev/disk/by-partlabel/userdata",
                "by_partlabel_target": "../../sda34",
                "capacity_bytes": deploy.USERDATA_CAPACITY,
                "disk_sector_count": 28051451,
                "gpt_logical_sector_size": 4096,
                "last_lba": 28051450,
                "loop_backing_device": "/dev/sda34",
                "partlabel": "userdata",
                "partition_entry_count": 128,
                "partition_entry_size": 128,
                "reported_512_byte_sectors": 224411608,
            },
        }
        mapping_bytes = canonical(mapping)
        self.write("config/lmi-p2-d114/physical-userdata-mapping.json", mapping_bytes)

        helper_bytes = deploy.HELPER.read_bytes()
        self.write("scripts/lmi_p2_d114/deploy_userdata_helper.ps1", helper_bytes)
        archive_bytes = (deploy.REPO / deploy.FASTBOOT_ARCHIVE_PATH).read_bytes()
        self.write(deploy.FASTBOOT_ARCHIVE_PATH, archive_bytes)
        acquisition = canonical(
            {
                "archive": {
                    "official_sha1": deploy.FASTBOOT_ARCHIVE_OFFICIAL_SHA1,
                    "sha256": deploy.FASTBOOT_ARCHIVE_SHA256,
                    "size": deploy.FASTBOOT_ARCHIVE_SIZE,
                    "url": deploy.FASTBOOT_ARCHIVE_URL,
                },
                "installed_copy": {
                    "byte_identical_to_archive_member": True,
                    "path": deploy.FASTBOOT_PATH,
                    "sha256": deploy.FASTBOOT_SHA256,
                    "size": deploy.FASTBOOT_SIZE,
                },
                "member": {
                    "path": "platform-tools/fastboot.exe",
                    "sha256": deploy.FASTBOOT_SHA256,
                    "size": deploy.FASTBOOT_SIZE,
                },
                "schema": "lmi-d110-fastboot-official-acquisition/v1",
            }
        )
        acquisition_path = "private/lmi-p1/recovery/d110-d114/fastboot-acquisition.json"
        self.write(acquisition_path, acquisition)
        binding_specs: dict[str, dict[str, object]] = {}
        for name in (
            "apk_build_attestation", "assembler", "candidate_rebuild_lock",
            "injection_policy_lock", "injector", "injector_launcher",
            "injector_runtime_lock", "public_key", "sixrow_apk_build_attestation",
            "sixrow_public_key", "sparse_tools_lock",
        ):
            payload = (name + "\n").encode("ascii")
            relative = f"policy/{name}"
            self.write(relative, payload)
            binding_specs[name] = {"path": relative, "sha256": sha(payload), "size": len(payload)}
        provenance = (
            deploy.REPO / "config/lmi-p2-d114/fastboot-windows-provenance-lock.json"
        ).read_bytes()
        provenance_path = "policy/fastboot_windows_provenance_lock"
        self.write(provenance_path, provenance)
        binding_specs["fastboot_windows_provenance_lock"] = {
            "path": provenance_path,
            "sha256": sha(provenance),
            "size": len(provenance),
        }
        binding_specs["physical_userdata_mapping"] = {
            "path": "config/lmi-p2-d114/physical-userdata-mapping.json",
            "sha256": sha(mapping_bytes),
            "size": len(mapping_bytes),
        }
        profile_template = (
            deploy.REPO / "config/lmi-p2-d114/userdata-deploy-profile.template.json"
        ).read_bytes()
        profile_template_path = "config/lmi-p2-d114/userdata-deploy-profile.template.json"
        self.write(profile_template_path, profile_template)
        binding_specs["userdata_deploy_profile_template"] = {
            "path": profile_template_path,
            "sha256": sha(profile_template),
            "size": len(profile_template),
        }
        deploy_policy = {
            "acquisition": {
                "archive": {
                    "official_sha1": deploy.FASTBOOT_ARCHIVE_OFFICIAL_SHA1,
                    "path": deploy.FASTBOOT_ARCHIVE_PATH,
                    "sha256": deploy.FASTBOOT_ARCHIVE_SHA256,
                    "size": deploy.FASTBOOT_ARCHIVE_SIZE,
                    "url": deploy.FASTBOOT_ARCHIVE_URL,
                },
                "evidence": {"path": acquisition_path, "sha256": sha(acquisition), "size": len(acquisition)},
                "evidence_scope": "fastboot-exe-member-only-does-not-attest-the-two-dll-members",
                "schema": "lmi-d110-fastboot-official-acquisition/v1",
            },
            "fastboot": {
                "authenticode": {
                    "applies_to": "all-three-extracted-members",
                    "revocation_policy": "online-entire-chain-no-ignore-flags-for-signer-and-timestamp",
                    "runtime_gate": "require-windows-status-valid-before-any-device-query",
                    "signer_leaf_certificate_sha256": "2029505d14baf18af60a0d1a7d8b56447db643b32faa849d4c08d2ab1ff3a4fd",
                    "signer_subject_cn": "Google LLC",
                },
                "executable": {"path": deploy.FASTBOOT_PATH, "sha256": deploy.FASTBOOT_SHA256, "size": deploy.FASTBOOT_SIZE},
                "bundled_android_dll_closure": [
                    {"archive_member": f"platform-tools/{name}", "filename": name, "sha256": digest, "size": size}
                    for name, size, digest in deploy.FASTBOOT_DLLS
                ],
                "closure_scope": "application-local-non-system-payload-only",
            },
            "hardware_test_only": True,
            "helper": {"path": "scripts/lmi_p2_d114/deploy_userdata_helper.ps1", "sha256": sha(helper_bytes), "size": len(helper_bytes)},
            "native_staging": {
                "acl_policy": "protected-current-user-and-local-system-full-control-only",
                "filename": "userdata.android-sparse.img",
                "identity_semantics": "profile-sha256/candidate-sha256/fixed-filename",
                "lifecycle": "preflight-prepare-or-reuse-execute-revalidate-only",
                "report_path_policy": "semantic-only-no-absolute-user-path",
                "root_semantics": "localappdata/lmi-p2-d114/userdata-staging",
                "volume_policy": "fixed-ntfs-without-reparse-directory-ancestors",
            },
            "hardware_test_readiness": {
                "accepted_residual_risks": [
                    "official-exact-r37-source-commit-and-build-manifest-unavailable",
                    "windows-system-and-runtime-module-closure-not-attested",
                    "d110-is-an-operator-owned-external-compatibility-prerequisite-not-a-release-asset",
                    "d110-boot-is-separately-approved-ram-boot-only-never-flash-boot",
                ],
                "blocking_gates": [],
                "closure_scope": "application-local-non-system-payload-only",
                "production_claim": False,
                "reproducibility_claim": False,
                "status": "ready-for-explicitly-approved-hardware-test-only",
            },
            "repo_bindings": binding_specs,
            "schema": deploy.DEPLOY_POLICY_SCHEMA,
            "tool_staging": {
                "acl_policy": "protected-current-user-and-local-system-full-control-only",
                "contents": ["AdbWinApi.dll", "AdbWinUsbApi.dll", "fastboot.exe"],
                "reuse_policy": "reuse-only-after-full-revalidation-and-read-lock",
                "root_semantics": "localappdata/lmi-p2-d114/fastboot-r37.0.0",
                "volume_policy": "fixed-ntfs-without-reparse-directory-ancestors",
            },
        }
        deploy_policy_bytes = canonical(deploy_policy)
        self.write("config/lmi-p2-d114/userdata-deploy-policy-lock.json", deploy_policy_bytes)

        self.contract = deploy.Contract(
            source_lock_sha256=sha(source_bytes),
            mapping_sha256=sha(mapping_bytes),
            mapping_size=len(mapping_bytes),
            deploy_policy_sha256=sha(deploy_policy_bytes),
            deploy_policy_size=len(deploy_policy_bytes),
            helper_sha256=sha(helper_bytes),
            helper_size=len(helper_bytes),
            d110_boot_sha256=self.boot_sha,
            d110_boot_size=4096,
            d110_boot_uuid=self.boot_uuid,
            root_uuid=self.root_uuid,
            baseline_raw_sha256=sha(self.rollback_raw),
            baseline_raw_size=len(self.rollback_raw),
            rollback_sparse_sha256=sha(self.rollback_sparse),
            rollback_sparse_size=len(self.rollback_sparse),
            p2_ext4_size=4096,
            logical_sector_size=4096,
            disk_lbas=2,
            p1_lbas=(0, 0),
            p2_lbas=(1, 1),
            p2_byte_range=(4096, 8192),
            suffix_bytes=0,
            userdata_capacity=deploy.USERDATA_CAPACITY,
        )

        injection = {
            "claims": {
                "hardware_test_only": True,
                "production": False,
                "release_eligible": False,
            },
            "commands": {},
            "input": {},
            "normalization": {
                "allocated_only_command": ["e2image", "-r", "-a", "-p"],
                "all_free_blocks_zero": True,
                "inactive_journal": {
                    "block_count": 16_383,
                    "first_block": 327_681,
                    "sha256": "40b4947fd669bcb849e47705c797e2484a4d406a596017fa889987d2614008b3",
                },
                "journal_extent": {"block_count": 16_384, "first_block": 327_680},
                "pre_normalization_sha256": "44" * 32,
                "proof": "second-e2image-byte-identical",
                "proof_sha256": self.p2_sha,
                "reviewed_freed_blocks": [586_227, 661_606],
                "sparse_st_blocks": 8,
                "tree_identity_sha256": "55" * 32,
            },
            "output": {
                "sha256": self.p2_sha,
                "size": 4096,
                "uuid": self.root_uuid,
            },
            "runtime": {},
            "sanitization": {},
            "schema": "lmi-p2-d114-rootfs-injection-attestation/v3",
            "tools": {},
        }
        injection_bytes = canonical(injection)
        self.write("artifacts/candidate.bundle/injection-attestation.json", injection_bytes)

        assembly = {
            "bindings": {
                "p2_injection_attestation_sha256": sha(injection_bytes),
                "source_lock_sha256": sha(source_bytes),
                "sparse_tools_lock_sha256": "55" * 32,
            },
            "compatibility": {
                "d110": {
                    "boot_sha256": self.boot_sha,
                    "boot_size": 4096,
                    "boot_uuid": self.boot_uuid,
                    "root_uuid": self.root_uuid,
                }
            },
            "geometry": {
                "disk_lbas": 2,
                "logical_sector_size": 4096,
                "p1_lbas": [0, 0],
                "p2_byte_range": [4096, 8192],
                "p2_lbas": [1, 1],
                "suffix_bytes": 0,
            },
            "input": {
                "baseline": {"sha256": sha(self.rollback_raw), "size": len(self.rollback_raw)},
                "p2": {
                    "filesystem": {
                        "block_count": 1,
                        "block_size": 4096,
                        "size": 4096,
                        "uuid": self.root_uuid,
                    },
                    "sha256": self.p2_sha,
                    "size": 4096,
                    "uuid": self.root_uuid,
                },
            },
            "output": {
                "raw": {"filename": "userdata.raw", "path": "userdata.raw", "sha256": sha(self.candidate_raw), "size": len(self.candidate_raw)},
                "sparse": {
                    "filename": "userdata.android-sparse.img",
                    "logical_size": len(self.candidate_raw),
                    "path": "userdata.android-sparse.img",
                    "sha256": sha(self.candidate_sparse),
                    "size": len(self.candidate_sparse),
                },
            },
            "schema": deploy.ASSEMBLY_SCHEMA,
            "tools": {"commands": [], "lock_sha256": "55" * 32, "package": "fixture"},
            "verification": {
                "expanded": {"raw_sha256": sha(self.candidate_raw), "raw_size": len(self.candidate_raw)},
                "expanded_byte_identical": True,
                "gates": {
                    name: True
                    for name in (
                        "expanded",
                        "geometry",
                        "gpt",
                        "injection_attestation",
                        "p2_range",
                        "prefix",
                        "roundtrip",
                        "suffix",
                    )
                },
                "raw": {"raw_sha256": sha(self.candidate_raw), "raw_size": len(self.candidate_raw)},
                "roundtrip_raw_sha256": sha(self.candidate_raw),
                "sparse_static": {
                    "block_size": 4096,
                    "decoded_sha256": sha(self.candidate_raw),
                    "file_sha256": sha(self.candidate_sparse),
                    "file_size": len(self.candidate_sparse),
                    "output_blocks": 2,
                },
            },
        }
        assembly_bytes = canonical(assembly)
        self.write("artifacts/candidate.bundle/assembly-attestation.json", assembly_bytes)

        self.profile_value = {
            "artifacts": {
                "assembly_attestation": {"path": "artifacts/candidate.bundle/assembly-attestation.json", "sha256": sha(assembly_bytes), "size": len(assembly_bytes)},
                "candidate": {
                    "logical_size": len(self.candidate_raw),
                    "path": "artifacts/candidate.bundle/userdata.android-sparse.img",
                    "representation": "android-sparse",
                    "roundtrip_raw_sha256": sha(self.candidate_raw),
                    "sha256": sha(self.candidate_sparse),
                    "size": len(self.candidate_sparse),
                },
                "candidate_raw": {
                    "path": "artifacts/candidate.bundle/userdata.raw",
                    "sha256": sha(self.candidate_raw),
                    "size": len(self.candidate_raw),
                },
                "deploy_policy_lock": {
                    "path": "config/lmi-p2-d114/userdata-deploy-policy-lock.json",
                    "sha256": sha(deploy_policy_bytes),
                    "size": len(deploy_policy_bytes),
                },
                "p2_injection_attestation": {
                    "path": "artifacts/candidate.bundle/injection-attestation.json",
                    "sha256": sha(injection_bytes),
                    "size": len(injection_bytes),
                },
                "physical_mapping_evidence": {
                    "path": "config/lmi-p2-d114/physical-userdata-mapping.json",
                    "sha256": sha(mapping_bytes),
                    "size": len(mapping_bytes),
                },
                "rollback": {
                    "logical_size": len(self.rollback_raw),
                    "path": "artifacts/rollback.android-sparse.img",
                    "representation": "android-sparse",
                    "roundtrip_raw_sha256": sha(self.rollback_raw),
                    "sha256": sha(self.rollback_sparse),
                    "size": len(self.rollback_sparse),
                },
                "source_lock": {"path": "config/lmi-p2-d114/source-lock.json", "sha256": sha(source_bytes), "size": len(source_bytes)},
            },
            "compatibility": {
                "d110": {"boot_sha256": self.boot_sha, "boot_size": 4096, "boot_uuid": self.boot_uuid, "root_uuid": self.root_uuid},
                "d114": {
                    "baseline_raw_sha256": sha(self.rollback_raw),
                    "baseline_raw_size": len(self.rollback_raw),
                    "logical_sector_size": 4096,
                    "root_uuid": self.root_uuid,
                },
                "p2": {"injected_ext4_sha256": self.p2_sha, "injected_ext4_size": 4096, "root_uuid": self.root_uuid},
            },
            "device": {
                "expected_product": "lmi",
                "expected_userdata_capacity": deploy.USERDATA_CAPACITY,
                "minimum_battery_mv": 3800,
                "minimum_max_download_size": deploy.MIN_MAX_DOWNLOAD_SIZE,
                "partition_type": "f2fs",
                "require_soc_ok": True,
            },
            "execution": {
                "automatic_retry": False,
                "command": ["-s", "<identity-policy-matched-device>", "flash", "userdata", "<candidate-path>"],
                "max_attempts": 1,
                "operation": "flash",
                "partition": "userdata",
                "write_timeout_seconds": 300,
            },
            "fastboot": {"path": deploy.FASTBOOT_PATH, "sha256": deploy.FASTBOOT_SHA256, "size": deploy.FASTBOOT_SIZE},
            "profile_id": "synthetic-p2-d114",
            "schema": deploy.PROFILE_SCHEMA,
        }
        self.profile = root / "profile.json"
        self.write_profile()

    def write(self, relative: str, payload: bytes) -> Path:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
        path.chmod(0o600)
        return path

    def write_profile(self, payload: bytes | None = None) -> None:
        self.profile.write_bytes(canonical(self.profile_value) if payload is None else payload)
        self.profile.chmod(0o600)

    def set_production_readiness(self, status: str, gates: list[str]) -> None:
        policy_path = self.root / "config/lmi-p2-d114/userdata-deploy-policy-lock.json"
        policy = json.loads(policy_path.read_text(encoding="ascii"))
        policy["hardware_test_readiness"]["blocking_gates"] = gates
        policy["hardware_test_readiness"]["status"] = status
        payload = canonical(policy)
        policy_path.write_bytes(payload)
        policy_path.chmod(0o600)
        self.contract = replace(
            self.contract,
            deploy_policy_sha256=sha(payload),
            deploy_policy_size=len(payload),
        )
        self.profile_value["artifacts"]["deploy_policy_lock"].update(
            sha256=sha(payload), size=len(payload)
        )
        self.write_profile()

    def set_mapping(self, mapping: dict[str, object]) -> None:
        mapping_path = self.root / "config/lmi-p2-d114/physical-userdata-mapping.json"
        payload = canonical(mapping)
        mapping_path.write_bytes(payload)
        mapping_path.chmod(0o600)
        policy_path = self.root / "config/lmi-p2-d114/userdata-deploy-policy-lock.json"
        policy = json.loads(policy_path.read_text(encoding="ascii"))
        policy["repo_bindings"]["physical_userdata_mapping"].update(
            sha256=sha(payload), size=len(payload)
        )
        policy_payload = canonical(policy)
        policy_path.write_bytes(policy_payload)
        policy_path.chmod(0o600)
        self.contract = replace(
            self.contract,
            mapping_sha256=sha(payload),
            mapping_size=len(payload),
            deploy_policy_sha256=sha(policy_payload),
            deploy_policy_size=len(policy_payload),
        )
        self.profile_value["artifacts"]["physical_mapping_evidence"].update(
            sha256=sha(payload), size=len(payload)
        )
        self.profile_value["artifacts"]["deploy_policy_lock"].update(
            sha256=sha(policy_payload), size=len(policy_payload)
        )
        self.write_profile()


class FakeFastboot:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.device_count = 1
        self.logical = "unsupported"
        self.flash = "verified"
        self.calls: list[tuple[str, ...]] = []


class FakePowerShell:
    def __init__(self, fastboot: FakeFastboot) -> None:
        self.fastboot = fastboot
        self.lock_busy = False
        self.mutate_candidate = False
        self.refuse_after_attempt = False
        self.omit_journal = False
        self.intent_seen_before_call = False
        self.windows_now_unix: int | None = None

    def _hashes(self, audit: deploy.Audit) -> dict[str, str]:
        return {
            name: audit.held[name].sha256
            for name in (
                "profile",
                "assembly_attestation",
                "candidate",
                "candidate_raw",
                "deploy_policy_lock",
                "p2_injection_attestation",
                "physical_mapping_evidence",
                "rollback",
                "source_lock",
            )
        }

    def _device(self, audit: deploy.Audit) -> dict[str, object]:
        return {
            "battery_mv": 4200,
            "identity_match": True,
            "is_logical_userdata": self.fastboot.logical,
            "max_download_size": 805306368,
            "partition_size": audit.profile["device"]["expected_userdata_capacity"],
            "partition_type": "f2fs",
            "physical_mapping_evidence_override": self.fastboot.logical == "unsupported",
            "product": "lmi",
            "soc_ok": "yes",
            "unlocked": "yes",
            "userspace": "no",
        }

    def _append_terminal(
        self,
        audit: deploy.Audit,
        context: deploy.RunContext,
        reason: str,
    ) -> None:
        terminal = canonical(
            {
                "approval_claim_sha256": context.approval_claim_sha256,
                "helper_sha256": audit.held["policy:helper"].sha256,
                "intent_initial_sha256": context.intent_initial_sha256,
                "reason": reason,
                "schema": deploy.INTENT_TERMINAL_SCHEMA,
                "state": "HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY",
            }
        )
        with context.journal_path.open("ab", buffering=0) as stream:
            stream.write(terminal)
            os.fsync(stream.fileno())

    def __call__(self, mode: str, audit: deploy.Audit, context: deploy.RunContext) -> dict[str, object]:
        device = self._device(audit)
        flash = {
            "assignment_confirmed": False,
            "attempts": 0,
            "exit_code": None,
            "sending_okay": 0,
            "started": False,
            "timed_out": False,
            "transport_completed": False,
            "tree_quiescent": False,
            "writing_okay": 0,
        }
        native_stage = None
        reason = None
        route = {"Preflight": "PREFLIGHT_PASSED_NO_STATE_CHANGE", "Postwrite": "POSTWRITE_DEVICE_REVALIDATED_NO_STATE_CHANGE"}.get(mode)
        if mode == "Preflight":
            native_stage = {
                "acl_verified": True,
                "deny_write_delete_handle_held": True,
                "path_semantics": context.native_stage_path,
                "sha256": audit.profile["artifacts"]["candidate"]["sha256"],
                "size": audit.profile["artifacts"]["candidate"]["size"],
            }
        self.fastboot.calls.append(("devices",))
        if self.lock_busy:
            route, reason = "REFUSED_NO_STATE_CHANGE", "DEVICE_LOCK_BUSY"
        elif self.fastboot.device_count != 1:
            route, reason = "REFUSED_NO_STATE_CHANGE", "DEVICE_COUNT_NOT_ONE"
            device = {key: (False if key in {"identity_match", "physical_mapping_evidence_override"} else None) for key in device}
        elif self.fastboot.logical not in {"no", "unsupported"}:
            route, reason = "REFUSED_NO_STATE_CHANGE", "LOGICAL_USERDATA_FORBIDDEN" if self.fastboot.logical == "yes" else "IS_LOGICAL_UNKNOWN"
        elif mode == "Execute":
            initial = context.journal_path.read_bytes()
            intent = json.loads(initial)
            self.intent_seen_before_call = (
                context.intent_initial_sha256 == sha(initial)
                and len(initial.splitlines()) == 1
            )
            if not self.intent_seen_before_call:
                raise AssertionError("durable initial intent was not present before helper entry")
            if self.windows_now_unix is not None:
                approval_window = intent["approval_window"]
                issued = approval_window["issued_at_unix"]
                expires = approval_window["expires_at_unix"]
                preflight_created = intent["preflight_created_at_unix"]
                fresh = (
                    expires - issued == deploy.APPROVAL_TTL_SECONDS
                    and self.windows_now_unix >= issued - 5
                    and self.windows_now_unix <= expires
                    and self.windows_now_unix >= preflight_created - 5
                    and self.windows_now_unix - preflight_created
                    <= deploy.APPROVAL_TTL_SECONDS
                )
                if not fresh:
                    reason = "APPROVAL_WINDOW_EXPIRED_BEFORE_FLASH"
                    self._append_terminal(audit, context, reason)
                    return {
                        "approval_claim_sha256": context.approval_claim_sha256,
                        "artifact_hashes": self._hashes(audit),
                        "attempt_journal_durable": False,
                        "device": device,
                        "flash": flash,
                        "intent_initial_sha256": context.intent_initial_sha256,
                        "locked_inputs_intact": True,
                        "mode": mode,
                        "native_stage": None,
                        "reason": reason,
                        "recovered_from_intent_journal": False,
                        "route_status": "REFUSED_NO_STATE_CHANGE",
                        "schema": deploy.HELPER_SCHEMA,
                        "windows_validation_scope": "small-repository-contract-and-prepared-candidate",
                    }
            self.fastboot.calls.append(
                (
                    "-s",
                    self.fastboot.fixture.serial,
                    "flash",
                    "userdata",
                    str(context.native_stage_path),
                )
            )
            native_stage = {
                "acl_verified": True,
                "deny_write_delete_handle_held": True,
                "path_semantics": context.native_stage_path,
                "sha256": audit.profile["artifacts"]["candidate"]["sha256"],
                "size": audit.profile["artifacts"]["candidate"]["size"],
            }
            if not self.omit_journal:
                transition = canonical(
                    {
                        "approval_claim_sha256": context.approval_claim_sha256,
                        "containment_confirmed": True,
                        "identity_match": True,
                        "native_stage_path_semantics": context.native_stage_path,
                        "schema": deploy.INTENT_TRANSITION_SCHEMA,
                        "snapshot_identity_confirmed": True,
                        "state": "ATTEMPT_STARTING_CONSERVATIVE",
                    }
                )
                with context.journal_path.open("ab", buffering=0) as stream:
                    stream.write(transition)
                    os.fsync(stream.fileno())
            flash.update(
                assignment_confirmed=True,
                attempts=1,
                started=True,
                tree_quiescent=True,
            )
            if self.fastboot.flash == "timeout":
                flash["timed_out"] = True
                route, reason = "WRITE_ATTEMPTED_RESULT_UNKNOWN", "PROCESS_TREE_TIMEOUT_SAME_CLAIM_CONSUMED"
            elif self.fastboot.flash == "partial":
                flash.update(exit_code=0, sending_okay=1, writing_okay=1)
                route, reason = "WRITE_ATTEMPTED_RESULT_UNKNOWN", "TRANSPORT_TRANSCRIPT_INCOMPLETE_SAME_CLAIM_CONSUMED"
            else:
                flash.update(
                    exit_code=0,
                    sending_okay=2,
                    transport_completed=True,
                    writing_okay=2,
                )
                if self.fastboot.flash == "post-loss":
                    route, reason = (
                        "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING",
                        "DEVICE_REVALIDATION_UNAVAILABLE_OR_MISMATCH",
                    )
                else:
                    route = "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED"
            if self.refuse_after_attempt:
                route, reason = "REFUSED_NO_STATE_CHANGE", "INJECTED_POST_ATTEMPT_FAULT"
        if self.mutate_candidate:
            candidate = audit.held["candidate"].path
            candidate.write_bytes(b"X" * candidate.stat().st_size)
        return {
            "approval_claim_sha256": context.approval_claim_sha256 if mode == "Execute" else None,
            "artifact_hashes": self._hashes(audit),
            "attempt_journal_durable": mode == "Execute" and flash["attempts"] == 1 and not self.omit_journal,
            "device": device,
            "flash": flash,
            "intent_initial_sha256": context.intent_initial_sha256 if mode == "Execute" else None,
            "locked_inputs_intact": True,
            "mode": mode,
            "native_stage": native_stage,
            "reason": reason,
            "recovered_from_intent_journal": False,
            "route_status": route,
            "schema": deploy.HELPER_SCHEMA,
            "windows_validation_scope": (
                "small-repository-contract-and-prepared-candidate"
                if mode == "Execute"
                else "full-repository-artifacts-and-prepared-candidate"
                if mode == "Preflight"
                else "full-repository-artifacts"
            ),
        }


class DeployUserdataTests(unittest.TestCase):
    def setUp(self) -> None:
        host_bound.require_path(deploy.REPO / deploy.FASTBOOT_ARCHIVE_PATH)
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)
        self.fastboot = FakeFastboot(self.fixture)
        self.powershell = FakePowerShell(self.fastboot)
        self.execution_counter = 0

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def operate(self, mode: str, name: str, **kwargs: object) -> tuple[str, str]:
        powershell_runner = kwargs.pop("powershell_runner", self.powershell)
        if mode == "execute" and "approval_claim" not in kwargs:
            self.execution_counter += 1
            preflight = self.root / f"approval-preflight-{self.execution_counter}.json"
            _, preflight_sha = deploy.operate(
                "preflight", self.fixture.profile, preflight,
                repo_root=self.root, contract=self.fixture.contract,
                powershell_runner=self.powershell,
            )
            claim = self.root / f"approval-{self.execution_counter}.json"
            deploy.create_approval(
                self.fixture.profile, preflight, preflight_sha, claim,
                repo_root=self.root, contract=self.fixture.contract,
            )
            kwargs.update(
                preflight_report=preflight,
                preflight_report_sha256=preflight_sha,
                approval_claim=claim,
            )
        return deploy.operate(
            mode,
            self.fixture.profile,
            self.root / name,
            repo_root=self.root,
            contract=self.fixture.contract,
            powershell_runner=powershell_runner,
            **kwargs,
        )

    def approval(self, prefix: str, *, now_unix: int | None = None) -> tuple[Path, str, Path]:
        preflight = self.root / f"{prefix}-preflight.json"
        _, preflight_sha = deploy.operate(
            "preflight", self.fixture.profile, preflight,
            repo_root=self.root, contract=self.fixture.contract,
            powershell_runner=self.powershell, now_unix=now_unix,
        )
        claim = self.root / f"{prefix}-claim.json"
        deploy.create_approval(
            self.fixture.profile, preflight, preflight_sha, claim,
            repo_root=self.root, contract=self.fixture.contract, now_unix=now_unix,
        )
        return preflight, preflight_sha, claim

    def corrupt_native_result_execute(
        self, kind: str, report_name: str
    ) -> tuple[str, dict[str, object]]:
        def fake_subprocess_run(command: list[str], **_: object) -> object:
            self.assertEqual(command[10], "Execute")
            result_path = Path(command[13])
            journal_path = Path(command[14])
            if kind == "partial-journal":
                with journal_path.open("ab", buffering=0) as stream:
                    stream.write(b'{"approval_claim_sha256":"partial')
                    os.fsync(stream.fileno())
            elif kind == "terminal-malformed-result":
                terminal = canonical(
                    {
                        "approval_claim_sha256": command[17],
                        "helper_sha256": command[9],
                        "intent_initial_sha256": command[18],
                        "reason": "DEVICE_LOCK_BUSY",
                        "schema": deploy.INTENT_TERMINAL_SCHEMA,
                        "state": "HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY",
                    }
                )
                with journal_path.open("ab", buffering=0) as stream:
                    stream.write(terminal)
                    os.fsync(stream.fileno())
            elif kind != "initial-malformed-result":
                transition = canonical(
                    {
                        "approval_claim_sha256": command[17],
                        "containment_confirmed": True,
                        "identity_match": True,
                        "native_stage_path_semantics": command[19],
                        "schema": deploy.INTENT_TRANSITION_SCHEMA,
                        "snapshot_identity_confirmed": True,
                        "state": "ATTEMPT_STARTING_CONSERVATIVE",
                    }
                )
                with journal_path.open("ab", buffering=0) as stream:
                    stream.write(transition)
                    os.fsync(stream.fileno())

            payload = {
                "empty": b"",
                "partial": b'{"schema":',
                "malformed": b"not-json\n",
                "dual-mismatch": b"{}\n",
                "unexpected-exit": b"{}\n",
                "partial-journal": b"",
                "initial-malformed-result": b'{"schema":',
                "terminal-malformed-result": b'{"schema":',
            }[kind]
            result_path.write_bytes(payload)
            result_path.chmod(0o600)
            stdout_payload = (
                b'{"different":true}\n'
                if kind == "dual-mismatch"
                else payload
            )
            stdout = deploy.RESULT_PREFIX + base64.b64encode(stdout_payload) + b"\n"
            return deploy.subprocess.CompletedProcess(
                command,
                99 if kind == "unexpected-exit" else 3,
                stdout=stdout,
                stderr=b"",
            )

        with (
            mock.patch.object(deploy, "_windows_path", side_effect=lambda path: str(path)),
            mock.patch.object(deploy.subprocess, "run", side_effect=fake_subprocess_run),
        ):
            route, _ = self.operate(
                "execute", report_name, powershell_runner=deploy.run_powershell
            )
        return route, json.loads((self.root / report_name).read_text())

    def test_production_deploy_policy_hash_propagation_is_current(self) -> None:
        policy_path = deploy.REPO / "config/lmi-p2-d114/userdata-deploy-policy-lock-r1.json"
        payload = policy_path.read_bytes()
        self.assertEqual((sha(payload), len(payload)), (deploy.DEPLOY_POLICY_SHA256, deploy.DEPLOY_POLICY_SIZE))
        policy = json.loads(payload)

        helper_path = deploy.REPO / policy["helper"]["path"]
        helper_payload = helper_path.read_bytes()
        self.assertEqual(
            (sha(helper_payload), len(helper_payload)),
            (deploy.HELPER_SHA256, deploy.HELPER_SIZE),
        )
        self.assertEqual(
            (policy["helper"]["sha256"], policy["helper"]["size"]),
            (deploy.HELPER_SHA256, deploy.HELPER_SIZE),
        )

        for name in (
            "apk_build_attestation",
            "assembler",
            "fastboot_windows_provenance_lock",
            "injection_policy_lock",
            "injector",
            "injector_launcher",
            "public_key",
            "physical_userdata_mapping",
            "sixrow_apk_build_attestation",
            "sixrow_public_key",
            "userdata_deploy_profile_template",
        ):
            with self.subTest(binding=name):
                binding = policy["repo_bindings"][name]
                bound_payload = (deploy.REPO / binding["path"]).read_bytes()
                self.assertEqual(
                    (sha(bound_payload), len(bound_payload)),
                    (binding["sha256"], binding["size"]),
                )
        archive = policy["acquisition"]["archive"]
        archive_payload = (deploy.REPO / archive["path"]).read_bytes()
        self.assertEqual(
            (sha(archive_payload), len(archive_payload)),
            (deploy.FASTBOOT_ARCHIVE_SHA256, deploy.FASTBOOT_ARCHIVE_SIZE),
        )
        self.assertEqual(archive["path"], deploy.FASTBOOT_ARCHIVE_PATH)

    def test_production_physical_mapping_v2_geometry_and_pins_are_current(self) -> None:
        mapping_path = deploy.REPO / "config/lmi-p2-d114/physical-userdata-mapping.json"
        payload = mapping_path.read_bytes()
        self.assertEqual(
            (sha(payload), len(payload)),
            (deploy.MAPPING_SHA256, deploy.MAPPING_SIZE),
        )
        mapping = json.loads(payload)
        self.assertEqual(mapping["schema"], "lmi-d114-physical-userdata-mapping/v2")
        userdata = mapping["userdata"]
        self.assertNotIn("gpt_disk_lbas", userdata)
        self.assertEqual(userdata["capacity_bytes"], 114_898_743_296)
        self.assertEqual(userdata["disk_sector_count"], 28_051_451)
        self.assertEqual(userdata["last_lba"], 28_051_450)
        self.assertEqual(userdata["backup_gpt_header_lba"], 28_051_450)
        self.assertEqual(
            userdata["backup_gpt_entries"],
            {"first_lba": 28_051_446, "last_lba": 28_051_449, "sector_count": 4},
        )
        self.assertEqual(
            userdata["capacity_bytes"],
            userdata["disk_sector_count"] * userdata["gpt_logical_sector_size"],
        )
        template = json.loads(
            (
                deploy.REPO
                / "config/lmi-p2-d114/userdata-deploy-profile.template.json"
            ).read_text(encoding="ascii")
        )
        self.assertEqual(
            template["artifacts"]["physical_mapping_evidence"],
            {
                "path": "config/lmi-p2-d114/physical-userdata-mapping.json",
                "sha256": deploy.MAPPING_SHA256,
                "size": deploy.MAPPING_SIZE,
            },
        )

    def test_windows_mapping_geometry_uses_exact_integer_arithmetic(self) -> None:
        source = deploy.HELPER.read_text(encoding="utf-8")
        start = source.index("$mappingUInt64MaxBig =")
        end = source.index("    if (\n        $Mapping.schema", start)
        arithmetic = source[start:end]
        self.assertIn("[System.Numerics.BigInteger]::Divide", arithmetic)
        self.assertIn("[System.Numerics.BigInteger]::One", arithmetic)
        self.assertNotIn(" / ", arithmetic)
        self.assertNotIn("[uint64]::MaxValue /", source)
        self.assertNotIn("$mappingCapacity / $mappingSectorSize", source)
        self.assertNotIn("$mappingReported512Sectors * 512L", source)

    def test_windows_helper_state_propagates_to_child_scriptblock_caller(self) -> None:
        source = deploy.HELPER.read_text(encoding="utf-8")
        self.assertNotIn("$script:", source)
        for name in (
            "Device",
            "FastbootPath",
            "IntentApprovalIssuedAtUnix",
            "IntentApprovalExpiresAtUnix",
            "IntentPreflightCreatedAtUnix",
            "NativeStagePath",
        ):
            with self.subTest(state=name):
                self.assertIn(f"Set-Variable -Name {name} -Scope 1", source)

    def test_windows_getvar_parser_accepts_both_strict_output_forms(self) -> None:
        source = deploy.HELPER.read_text(encoding="utf-8")
        value_literal = re.search(r'^    \$valuePattern = "([^"]+)"$', source, re.MULTILINE)
        failure_literal = re.search(r'^    \$failurePattern = "([^"]+)"$', source, re.MULTILINE)
        footer_literal = re.search(r"^    \$footerPattern = '([^']+)'$", source, re.MULTILINE)
        self.assertIsNotNone(value_literal)
        self.assertIsNotNone(failure_literal)
        self.assertIsNotNone(footer_literal)

        def classify(transcript: str, name: str, allow_unsupported: bool) -> str | None:
            escaped = re.escape(name)
            value_pattern = value_literal.group(1).replace("${escaped}", escaped)
            failure_pattern = failure_literal.group(1).replace("${escaped}", escaped)
            footer_pattern = footer_literal.group(1)
            values = list(re.finditer(value_pattern, transcript))
            failures = list(re.finditer(failure_pattern, transcript))
            footers = list(re.finditer(footer_pattern, transcript))
            if len(values) > 1 or len(failures) > 1 or len(footers) != 1:
                return None
            if len(values) == 1 and not failures:
                remainder = re.sub(value_pattern, "", transcript)
                remainder = re.sub(footer_pattern, "", remainder)
                value = values[0].group(1).strip()
                return value if not remainder.strip() and value else None
            if allow_unsupported and not values and len(failures) == 1:
                remainder = re.sub(failure_pattern, "", transcript)
                remainder = re.sub(footer_pattern, "", remainder)
                return "unsupported" if not remainder.strip() else None
            return None

        footer = "Finished. Total time: 0.002s"
        self.assertEqual(classify(f"\nproduct: lmi\n{footer}\n", "product", False), "lmi")
        self.assertEqual(
            classify(f"\n(bootloader) product: lmi\n{footer}\n", "product", False),
            "lmi",
        )
        self.assertIsNone(classify(f"product: lmi\nproduct: lmi\n{footer}", "product", False))
        self.assertIsNone(classify(f"product:   \n{footer}", "product", False))
        self.assertIsNone(classify(f"serialno: hidden\n{footer}", "product", False))
        self.assertIsNone(classify(f"(bootloader)\nproduct: lmi\n{footer}", "product", False))
        self.assertIsNone(classify(f"(bootloader)product: lmi\n{footer}", "product", False))

        failure = "getvar:is-logical:userdata FAILED (remote: 'GetVar Variable Not found')"
        transcript = f"\n{failure}\n{footer}\n"
        self.assertEqual(classify(transcript, "is-logical:userdata", True), "unsupported")
        self.assertIsNone(classify(transcript, "is-logical:userdata", False))
        self.assertIsNone(
            classify(f"INFO unsupported\n{failure}\n{footer}", "is-logical:userdata", True)
        )
        self.assertIsNone(
            classify(f"{failure}\n{failure}\n{footer}", "is-logical:userdata", True)
        )
        self.assertEqual(
            classify(f"is-logical:userdata: unsupported\n{footer}", "is-logical:userdata", True),
            "unsupported",
        )
        self.assertIsNone(
            classify(
                f"is-logical:userdata: unsupported\nis-logical:userdata: unsupported\n{footer}",
                "is-logical:userdata",
                True,
            )
        )

        self.assertIn("$valueMatches.Count -gt 1", source)
        self.assertIn("$failureMatches.Count -gt 1", source)
        self.assertIn("$valueMatches.Count -eq 0 -and $failureMatches.Count -eq 1", source)
        self.assertNotIn("$result.output -match '(?i)(unsupported", source)
        self.assertIn(
            "$reasonName = $Name.ToUpperInvariant() -replace '[^A-Z0-9]', '_'",
            source,
        )
        self.assertIn('Fail ("GETVAR_FAILED_" + $reasonName)', source)

    def test_physical_mapping_rejects_legacy_or_inconsistent_lba_semantics(self) -> None:
        mapping_path = self.root / "config/lmi-p2-d114/physical-userdata-mapping.json"
        baseline = json.loads(mapping_path.read_text(encoding="ascii"))

        legacy = json.loads(json.dumps(baseline))
        legacy["userdata"]["gpt_disk_lbas"] = legacy["userdata"].pop(
            "disk_sector_count"
        )
        self.fixture.set_mapping(legacy)
        with self.assertRaisesRegex(deploy.DeployError, "fields mismatch"):
            self.operate("local-audit", "legacy-mapping.json")

        for name, mutate in (
            (
                "sector-count",
                lambda userdata: userdata.update(disk_sector_count=28_051_446),
            ),
            ("last-lba", lambda userdata: userdata.update(last_lba=28_051_449)),
            (
                "backup-entries",
                lambda userdata: userdata["backup_gpt_entries"].update(
                    first_lba=28_051_445
                ),
            ),
        ):
            with self.subTest(name=name):
                mapping = json.loads(json.dumps(baseline))
                mutate(mapping["userdata"])
                self.fixture.set_mapping(mapping)
                with self.assertRaisesRegex(
                    deploy.DeployError,
                    "GPT geometry relationship mismatch",
                ):
                    self.operate("local-audit", f"{name}-mapping.json")
        self.assertEqual(self.fastboot.calls, [])

    def test_local_audit_verifies_sparse_roundtrip_without_powershell(self) -> None:
        route, digest = self.operate("local-audit", "audit.json")
        self.assertEqual(route, "LOCAL_AUDIT_PASSED_NO_DEVICE_ACCESS")
        self.assertRegex(digest, r"^[0-9a-f]{64}$")
        self.assertEqual(self.fastboot.calls, [])

    def test_retained_fastboot_archive_identity_is_fail_closed(self) -> None:
        path = self.root / deploy.FASTBOOT_ARCHIVE_PATH
        payload = bytearray(path.read_bytes())
        payload[0] ^= 0x01
        path.write_bytes(payload)
        path.chmod(0o600)
        with self.assertRaisesRegex(deploy.DeployError, "archive identity mismatch"):
            self.operate("local-audit", "archive-tampered.json")
        self.assertEqual(self.fastboot.calls, [])

    def test_non_executable_profile_template_is_rejected_by_schema(self) -> None:
        template = json.loads(
            (deploy.REPO / "config/lmi-p2-d114/userdata-deploy-profile.template.json").read_text(
                encoding="ascii"
            )
        )
        with self.assertRaisesRegex(deploy.DeployError, "fields mismatch"):
            deploy._parse_profile(template, deploy.PRODUCTION)

    def test_blocked_production_readiness_prevents_approval_and_execute(self) -> None:
        self.fixture.set_production_readiness(
            "blocked", ["fixture-production-profile-not-released"]
        )
        preflight = self.root / "blocked-preflight.json"
        _, preflight_sha = deploy.operate(
            "preflight",
            self.fixture.profile,
            preflight,
            repo_root=self.root,
            contract=self.fixture.contract,
            powershell_runner=self.powershell,
        )
        claim = self.root / "blocked-claim.json"
        with self.assertRaisesRegex(deploy.DeployError, "readiness is blocked"):
            deploy.create_approval(
                self.fixture.profile,
                preflight,
                preflight_sha,
                claim,
                repo_root=self.root,
                contract=self.fixture.contract,
            )
        self.assertFalse(claim.exists())
        self.assertFalse(any("flash" in call for call in self.fastboot.calls))

    def test_preflight_zero_one_and_two_devices_never_flash(self) -> None:
        for count, expected in ((0, "REFUSED_NO_STATE_CHANGE"), (1, "PREFLIGHT_PASSED_NO_STATE_CHANGE"), (2, "REFUSED_NO_STATE_CHANGE")):
            with self.subTest(count=count):
                self.fastboot.device_count = count
                route, _ = self.operate("preflight", f"preflight-{count}.json")
                self.assertEqual(route, expected)
        self.assertFalse(any("flash" in call for call in self.fastboot.calls))

    def test_preflight_prepares_deterministic_stage_and_timestamps_after_helper(self) -> None:
        with mock.patch.object(deploy.time, "time", side_effect=[5000, 5100]):
            route, digest = self.operate("preflight", "prepared-preflight.json")
        self.assertEqual(route, "PREFLIGHT_PASSED_NO_STATE_CHANGE")
        report = json.loads((self.root / "prepared-preflight.json").read_text())
        expected = (
            "localappdata/lmi-p2-d114/userdata-staging/"
            f"{report['profile']['sha256']}/"
            f"{self.fixture.profile_value['artifacts']['candidate']['sha256']}/"
            "userdata.android-sparse.img"
        )
        self.assertEqual(report["created_at_unix"], 5100)
        self.assertEqual(
            report["result"]["native_stage"]["path_semantics"], expected
        )
        self.assertEqual(
            report["result"]["windows_validation_scope"],
            "full-repository-artifacts-and-prepared-candidate",
        )
        claim = self.root / "prepared-claim.json"
        deploy.create_approval(
            self.fixture.profile,
            self.root / "prepared-preflight.json",
            digest,
            claim,
            repo_root=self.root,
            contract=self.fixture.contract,
            now_unix=5101,
        )
        self.assertEqual(
            json.loads(claim.read_text())["binding"]["staged_candidate_path"],
            expected,
        )
        self.assertEqual(deploy.APPROVAL_TTL_SECONDS, 120)

    def test_unsupported_physical_override_is_narrow(self) -> None:
        route, _ = self.operate("preflight", "unsupported.json")
        self.assertEqual(route, "PREFLIGHT_PASSED_NO_STATE_CHANGE")
        report = json.loads((self.root / "unsupported.json").read_text())
        self.assertTrue(report["result"]["device"]["physical_mapping_evidence_override"])
        for value in ("yes", "maybe", ""):
            self.fastboot.logical = value
            route, _ = self.operate("preflight", f"logical-{value or 'empty'}.json")
            self.assertEqual(route, "REFUSED_NO_STATE_CHANGE")

    def test_execute_issues_at_most_one_fixed_flash(self) -> None:
        route, _ = self.operate("execute", "execute.json")
        self.assertEqual(route, "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED")
        writes = [call for call in self.fastboot.calls if "flash" in call]
        self.assertEqual(len(writes), 1)
        report = json.loads((self.root / "execute.json").read_text())
        self.assertEqual(report["schema"], "lmi-p2-d114-userdata-deploy-report/v6")
        self.assertEqual(
            writes[0],
            (
                "-s",
                self.fixture.serial,
                "flash",
                "userdata",
            report["result"]["native_stage"]["path_semantics"],
            ),
        )
        self.assertTrue(self.powershell.intent_seen_before_call)
        self.assertEqual(
            report["result"]["windows_validation_scope"],
            "small-repository-contract-and-prepared-candidate",
        )
        self.assertEqual(
            report["safety"],
            {
                "automatic_retry": False,
                "boot_partition_write_attempted": False,
                "command_attempt_limit": 1,
                "current_boot_sha256_measured": False,
                "d110_boot_preservation": "inferred-from-no-boot-write-not-freshly-measured",
                "expected_d110_boot_sha256": self.fixture.boot_sha,
                "partition": "userdata",
                "retry_scope": deploy.RETRY_SCOPE,
                "serial_disclosed": False,
                "unknown_followup": deploy.UNKNOWN_FOLLOWUP,
                "userdata_content_readback_verified": False,
            },
        )

    def test_partial_okay_and_timeout_are_unknown_without_same_claim_retry(self) -> None:
        for result in ("partial", "timeout"):
            with self.subTest(result=result):
                self.fastboot.flash = result
                before = len([call for call in self.fastboot.calls if "flash" in call])
                route, _ = self.operate("execute", f"{result}.json")
                after = len([call for call in self.fastboot.calls if "flash" in call])
                self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
                self.assertEqual(after - before, 1)

    def test_postwrite_loss_is_recorded_then_replug_mode_is_read_only(self) -> None:
        self.fastboot.flash = "post-loss"
        route, write_hash = self.operate("execute", "pending.json")
        self.assertEqual(route, "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING")
        writes_before = len([call for call in self.fastboot.calls if "flash" in call])
        route, _ = self.operate(
            "postwrite",
            "postwrite.json",
            prior_report=self.root / "pending.json",
            prior_report_sha256=write_hash,
            replug_confirmed=True,
        )
        self.assertEqual(route, "POSTWRITE_REVALIDATED_PRIOR_COMPLETED_NO_STATE_CHANGE")
        self.assertEqual(len([call for call in self.fastboot.calls if "flash" in call]), writes_before)

    def test_competing_device_lock_refuses_without_flash(self) -> None:
        preflight = self.root / "busy-preflight.json"
        _, preflight_sha = self.operate("preflight", preflight.name)
        claim = self.root / "busy-claim.json"
        deploy.create_approval(self.fixture.profile, preflight, preflight_sha, claim, repo_root=self.root, contract=self.fixture.contract)
        self.powershell.lock_busy = True
        route, _ = self.operate("execute", "busy.json", preflight_report=preflight, preflight_report_sha256=preflight_sha, approval_claim=claim)
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        self.assertFalse(any("flash" in call for call in self.fastboot.calls))

    def test_artifact_drift_after_powershell_is_detected(self) -> None:
        self.powershell.mutate_candidate = True
        with self.assertRaisesRegex(deploy.DeployError, "candidate (?:identity|content) changed"):
            self.operate("preflight", "drift.json")
        self.assertFalse((self.root / "drift.json").exists())

    def test_postattempt_input_drift_is_durably_reported_as_pending(self) -> None:
        preflight, preflight_sha, claim = self.approval("attempt-drift")
        self.powershell.mutate_candidate = True
        route, _ = self.operate(
            "execute", "attempt-drift.json", preflight_report=preflight,
            preflight_report_sha256=preflight_sha, approval_claim=claim,
        )
        self.assertEqual(route, "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING")
        value = json.loads((self.root / "attempt-drift.json").read_text())
        self.assertEqual(value["result"]["post_helper_input_recheck"], False)
        self.assertEqual(value["result"]["reason"], "POST_HELPER_INPUT_IDENTITY_MISMATCH")

    def test_profile_rejects_unknown_duplicate_escape_symlink_and_hardlink(self) -> None:
        unknown = dict(self.fixture.profile_value)
        unknown["unknown"] = True
        self.fixture.write_profile(canonical(unknown))
        with self.assertRaisesRegex(deploy.DeployError, "fields mismatch"):
            deploy.local_audit(self.fixture.profile, repo_root=self.root, contract=self.fixture.contract)

        self.fixture.write_profile(b'{"schema":"x","schema":"y"}\n')
        with self.assertRaisesRegex(deploy.DeployError, "duplicate JSON field"):
            deploy.local_audit(self.fixture.profile, repo_root=self.root, contract=self.fixture.contract)

        self.fixture.write_profile()
        self.fixture.profile_value["artifacts"]["candidate"]["path"] = "../escape.img"
        self.fixture.write_profile()
        with self.assertRaisesRegex(deploy.DeployError, "canonical repository-relative"):
            deploy.local_audit(self.fixture.profile, repo_root=self.root, contract=self.fixture.contract)

        self.fixture.profile_value["artifacts"]["candidate"]["path"] = "artifacts/candidate-link.img"
        target = self.root / "artifacts/candidate.bundle/userdata.android-sparse.img"
        link = self.root / "artifacts/candidate.bundle/candidate-link.img"
        link.symlink_to(target.name)
        self.fixture.profile_value["artifacts"]["candidate"]["path"] = "artifacts/candidate.bundle/candidate-link.img"
        self.fixture.write_profile()
        with self.assertRaisesRegex(deploy.DeployError, "single-link"):
            deploy.local_audit(self.fixture.profile, repo_root=self.root, contract=self.fixture.contract)
        link.unlink()

        hard = self.root / "artifacts/candidate.bundle/candidate-link.img"
        os.link(target, hard)
        self.fixture.write_profile()
        with self.assertRaisesRegex(deploy.DeployError, "single-link"):
            deploy.local_audit(self.fixture.profile, repo_root=self.root, contract=self.fixture.contract)

    def test_candidate_bundle_is_exact_private_and_atomic(self) -> None:
        self.fixture.bundle.chmod(0o755)
        with self.assertRaisesRegex(deploy.DeployError, "mode-0700"):
            deploy.local_audit(
                self.fixture.profile,
                repo_root=self.root,
                contract=self.fixture.contract,
            )
        self.fixture.bundle.chmod(0o700)
        extra = self.fixture.write("artifacts/candidate.bundle/extra", b"not-approved")
        with self.assertRaisesRegex(deploy.DeployError, "exactly the four"):
            deploy.local_audit(
                self.fixture.profile,
                repo_root=self.root,
                contract=self.fixture.contract,
            )
        extra.unlink()
        raw = self.fixture.bundle / "userdata.raw"
        raw.chmod(0o644)
        with self.assertRaisesRegex(deploy.DeployError, "mode 0600"):
            deploy.local_audit(
                self.fixture.profile,
                repo_root=self.root,
                contract=self.fixture.contract,
            )

    def test_report_is_fsynced_no_overwrite_and_contains_no_serial(self) -> None:
        report = self.root / "report.json"
        self.operate("preflight", report.name)
        content = report.read_text(encoding="ascii")
        self.assertNotIn(self.fixture.serial, content)
        self.assertEqual(report.stat().st_nlink, 1)
        self.assertEqual(report.stat().st_mode & 0o777, 0o600)
        with self.assertRaisesRegex(deploy.DeployError, "overwrite is forbidden"):
            self.operate("preflight", report.name)

    def test_private_reports_expose_only_identity_match_boolean(self) -> None:
        report = self.root / "privacy.json"
        self.operate("preflight", report.name)
        content = report.read_text(encoding="ascii")
        value = json.loads(content)
        self.assertEqual(value["result"]["device"]["identity_match"], True)
        self.assertNotIn("identity_sha256", content)
        self.assertNotIn(self.fixture.serial, content)
        self.assertNotIn(self.fixture.nonce, content)
        self.assertNotIn(self.fixture.identity, content)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(deploy.DeployError, "mode-0700"):
            self.operate("preflight", "public-parent.json")

    def test_approval_is_fresh_bound_consumed_and_not_reusable(self) -> None:
        preflight, preflight_sha, claim = self.approval("one-use", now_unix=1000)
        route, _ = self.operate(
            "execute", "one-use-execute.json", preflight_report=preflight,
            preflight_report_sha256=preflight_sha, approval_claim=claim,
            now_unix=1001,
        )
        self.assertEqual(route, "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED")
        self.assertFalse(claim.exists())
        self.assertTrue(claim.with_name(claim.name + ".consumed.json").exists())
        with self.assertRaisesRegex(deploy.DeployError, "already consumed"):
            self.operate(
                "execute", "one-use-replay.json", preflight_report=preflight,
                preflight_report_sha256=preflight_sha, approval_claim=claim,
                now_unix=1002,
            )

    def test_stale_preflight_and_expired_claim_fail_before_attempt(self) -> None:
        preflight, preflight_sha, claim = self.approval("expired", now_unix=2000)
        before = len([call for call in self.fastboot.calls if "flash" in call])
        with self.assertRaisesRegex(deploy.DeployError, "not fresh"):
            self.operate(
                "execute", "stale.json", preflight_report=preflight,
                preflight_report_sha256=preflight_sha, approval_claim=claim,
                now_unix=2121,
            )
        self.assertEqual(before, len([call for call in self.fastboot.calls if "flash" in call]))

    def test_windows_expiry_after_long_snapshot_is_terminal_without_flash(self) -> None:
        preflight, preflight_sha, claim = self.approval(
            "windows-expired-after-copy", now_unix=4000
        )
        self.powershell.windows_now_unix = 4121
        before = len([call for call in self.fastboot.calls if "flash" in call])
        route, _ = self.operate(
            "execute",
            "windows-expired-after-copy.json",
            preflight_report=preflight,
            preflight_report_sha256=preflight_sha,
            approval_claim=claim,
            now_unix=4001,
        )
        self.assertEqual(route, "REFUSED_NO_STATE_CHANGE")
        self.assertEqual(
            before, len([call for call in self.fastboot.calls if "flash" in call])
        )
        source = json.loads(
            (self.root / "windows-expired-after-copy.json").read_text()
        )
        journal = self.root / source["result"]["attempt_journal"]["path"]
        records = [json.loads(line) for line in journal.read_text().splitlines()]
        self.assertEqual(records[0]["approval_window"], {
            "expires_at_unix": 4120,
            "issued_at_unix": 4000,
        })
        self.assertEqual(records[0]["preflight_created_at_unix"], 4000)
        self.assertEqual(
            records[1]["state"], "HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY"
        )
        recovered_route, _ = deploy.recover_intent(
            self.fixture.profile,
            journal,
            source["result"]["attempt_journal"]["initial_sha256"],
            self.root / "windows-expired-recovery.json",
            repo_root=self.root,
            contract=self.fixture.contract,
        )
        self.assertEqual(recovered_route, "REFUSED_NO_STATE_CHANGE")
        recovered = json.loads(
            (self.root / "windows-expired-recovery.json").read_text()
        )
        self.assertEqual(recovered["result"]["flash"]["attempts"], 0)
        self.assertEqual(
            recovered["result"]["reason"],
            "HELPER_TERMINAL_NO_ATTEMPT_INTENT_RECOVERY",
        )

    def test_claim_lifetime_and_command_binding_are_schema_checked(self) -> None:
        preflight, preflight_sha, claim = self.approval("bad-lifetime", now_unix=3000)
        value = json.loads(claim.read_text())
        value["expires_at_unix"] += 1
        claim.write_bytes(canonical(value))
        claim.chmod(0o600)
        with self.assertRaisesRegex(deploy.DeployError, "invalid lifetime"):
            self.operate(
                "execute", "bad-lifetime.json", preflight_report=preflight,
                preflight_report_sha256=preflight_sha, approval_claim=claim,
                now_unix=3001,
            )

        preflight, preflight_sha, claim = self.approval("bad-command", now_unix=3002)
        value = json.loads(claim.read_text())
        value["binding"]["command"][-1] = "artifacts/not-the-candidate.img"
        claim.write_bytes(canonical(value))
        claim.chmod(0o600)
        with self.assertRaisesRegex(deploy.DeployError, "binding mismatch"):
            self.operate(
                "execute", "bad-command.json", preflight_report=preflight,
                preflight_report_sha256=preflight_sha, approval_claim=claim,
                now_unix=3003,
            )

    def test_postattempt_refusal_and_missing_transition_fall_back_unknown(self) -> None:
        self.powershell.refuse_after_attempt = True
        route, _ = self.operate("execute", "bad-refusal.json")
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        self.powershell.refuse_after_attempt = False
        self.powershell.omit_journal = True
        route, _ = self.operate("execute", "missing-journal.json")
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")

    def test_postwrite_preserves_unknown_prior_state(self) -> None:
        self.fastboot.flash = "timeout"
        route, write_sha = self.operate("execute", "unknown-write.json")
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        self.fastboot.flash = "verified"
        route, _ = self.operate(
            "postwrite", "unknown-postwrite.json",
            prior_report=self.root / "unknown-write.json",
            prior_report_sha256=write_sha, replug_confirmed=True,
        )
        self.assertEqual(route, "POSTWRITE_REVALIDATED_PRIOR_UNKNOWN_NO_STATE_CHANGE")
        value = json.loads((self.root / "unknown-postwrite.json").read_text())
        self.assertEqual(value["result"]["prior_write"]["route_status"], "WRITE_ATTEMPTED_RESULT_UNKNOWN")

    def test_restart_recovery_transition_is_unknown_without_same_claim_retry(self) -> None:
        route, _ = self.operate("execute", "recover-transition-source.json")
        self.assertEqual(route, "USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATED")
        source = json.loads((self.root / "recover-transition-source.json").read_text())
        journal = self.root / source["result"]["attempt_journal"]["path"]
        initial_sha256 = source["result"]["attempt_journal"]["initial_sha256"]
        writes_before = len([call for call in self.fastboot.calls if "flash" in call])
        route, _ = deploy.recover_intent(
            self.fixture.profile,
            journal,
            initial_sha256,
            self.root / "recover-transition-report.json",
            repo_root=self.root,
            contract=self.fixture.contract,
        )
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        recovered = json.loads((self.root / "recover-transition-report.json").read_text())
        self.assertEqual(recovered["result"]["reason"], "PROCESS_RESTART_INTENT_RECOVERY")
        self.assertFalse(recovered["result"]["native_stage"]["deny_write_delete_handle_held"])
        self.assertEqual(
            writes_before,
            len([call for call in self.fastboot.calls if "flash" in call]),
        )

    def test_restart_recovery_initial_only_consumes_same_claim_attempt(self) -> None:
        preflight, preflight_sha, claim = self.approval("recover-initial")
        self.powershell.lock_busy = True
        route, _ = self.operate(
            "execute",
            "recover-initial-source.json",
            preflight_report=preflight,
            preflight_report_sha256=preflight_sha,
            approval_claim=claim,
        )
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        source = json.loads((self.root / "recover-initial-source.json").read_text())
        journal = self.root / source["result"]["attempt_journal"]["path"]
        initial_sha256 = source["result"]["attempt_journal"]["initial_sha256"]
        writes_before = len([call for call in self.fastboot.calls if "flash" in call])
        route, _ = deploy.recover_intent(
            self.fixture.profile,
            journal,
            initial_sha256,
            self.root / "recover-initial-report.json",
            repo_root=self.root,
            contract=self.fixture.contract,
        )
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        recovered = json.loads((self.root / "recover-initial-report.json").read_text())
        self.assertEqual(recovered["result"]["flash"]["attempts"], 1)
        self.assertFalse(recovered["result"]["flash"]["started"])
        self.assertFalse(recovered["result"]["flash"]["assignment_confirmed"])
        self.assertIsNone(recovered["result"]["native_stage"])
        self.assertEqual(
            recovered["result"]["reason"],
            "HELPER_MAY_STILL_START_OR_WRITE_STATE_UNKNOWN_CLAIM_CONSUMED",
        )
        self.assertFalse(recovered["safety"]["automatic_retry"])
        self.assertEqual(
            writes_before,
            len([call for call in self.fastboot.calls if "flash" in call]),
        )
        self.assertTrue(claim.with_name(claim.name + ".consumed.json").exists())

    def test_restart_recovery_rejects_tampered_canonical_intent(self) -> None:
        preflight, preflight_sha, claim = self.approval("recover-tamper")
        self.powershell.lock_busy = True
        self.operate(
            "execute",
            "recover-tamper-source.json",
            preflight_report=preflight,
            preflight_report_sha256=preflight_sha,
            approval_claim=claim,
        )
        source = json.loads((self.root / "recover-tamper-source.json").read_text())
        journal = self.root / source["result"]["attempt_journal"]["path"]
        intent = json.loads(journal.read_text(encoding="ascii"))
        intent["state"] = "TAMPERED"
        payload = canonical(intent)
        journal.write_bytes(payload)
        journal.chmod(0o600)
        with self.assertRaisesRegex(
            deploy.ExecuteIntentIndeterminate, "recovery remains indeterminate"
        ):
            deploy.recover_intent(
                self.fixture.profile,
                journal,
                sha(payload),
                self.root / "recover-tamper-report.json",
                repo_root=self.root,
                contract=self.fixture.contract,
            )

    def test_helper_schema_rejects_unknown_fields(self) -> None:
        audit = deploy.local_audit(self.fixture.profile, repo_root=self.root, contract=self.fixture.contract)
        try:
            context = deploy.RunContext(self.root / "unused.json")
            result = self.powershell("Preflight", audit, context)
            result["unexpected"] = True
            with self.assertRaisesRegex(deploy.DeployError, "fields mismatch"):
                deploy._validate_helper(result, "Preflight", audit, context)
            del result["unexpected"]
            result["recovered_from_intent_journal"] = True
            with self.assertRaisesRegex(deploy.DeployError, "forged"):
                deploy._validate_helper(result, "Preflight", audit, context)
            safety = deploy._report_safety(audit)
            deploy._validate_report_safety(safety, audit)
            safety["unexpected"] = True
            with self.assertRaisesRegex(deploy.DeployError, "fields mismatch"):
                deploy._validate_report_safety(safety, audit)
        finally:
            audit.close()

    def test_dual_result_channel_rejects_missing_corrupt_and_divergent_stdout(self) -> None:
        payload = b'{"schema":"fixture"}\n'
        good = deploy.RESULT_PREFIX + base64.b64encode(payload) + b"\n"
        deploy._validate_dual_result(good, payload)
        for stdout in (b"", deploy.RESULT_PREFIX + b"%%%\n", good + good):
            with self.subTest(stdout=stdout):
                with self.assertRaises(deploy.DeployError):
                    deploy._validate_dual_result(stdout, payload)
        with self.assertRaisesRegex(deploy.DeployError, "disagree"):
            deploy._validate_dual_result(good, b"different\n")

    def test_execute_corruption_is_unknown_without_same_claim_retry(self) -> None:
        cases = (
            "empty",
            "partial",
            "malformed",
            "dual-mismatch",
            "unexpected-exit",
            "partial-journal",
            "initial-malformed-result",
        )
        for kind in cases:
            with self.subTest(kind=kind):
                writes_before = len(
                    [call for call in self.fastboot.calls if "flash" in call]
                )
                route, report = self.corrupt_native_result_execute(
                    kind, f"corrupt-{kind}.json"
                )
                self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
                self.assertEqual(report["route_status"], route)
                self.assertEqual(report["result"]["flash"]["attempts"], 1)
                self.assertFalse(report["result"]["flash"]["started"])
                self.assertFalse(report["result"]["flash"]["transport_completed"])
                self.assertIsNone(report["result"]["device"]["product"])
                self.assertEqual(report["safety"]["retry_scope"], deploy.RETRY_SCOPE)
                self.assertEqual(
                    report["safety"]["unknown_followup"], deploy.UNKNOWN_FOLLOWUP
                )
                self.assertEqual(
                    writes_before,
                    len([call for call in self.fastboot.calls if "flash" in call]),
                )

    def test_corrupt_first_intent_is_unknown_and_cli_maps_indeterminate_to_exit3(self) -> None:
        preflight, preflight_sha, claim = self.approval("corrupt-first")

        def corrupt_first_runner(
            mode: str, audit: deploy.Audit, context: deploy.RunContext
        ) -> dict[str, object]:
            self.assertEqual(mode, "Execute")
            terminal = canonical(
                {
                    "approval_claim_sha256": context.approval_claim_sha256,
                    "helper_sha256": audit.held["policy:helper"].sha256,
                    "intent_initial_sha256": context.intent_initial_sha256,
                    "reason": "DEVICE_LOCK_BUSY",
                    "schema": deploy.INTENT_TERMINAL_SCHEMA,
                    "state": "HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY",
                }
            )
            context.journal_path.write_bytes(b'{"broken":true}\n' + terminal)
            context.journal_path.chmod(0o600)
            raise deploy.DeployError("injected result failure")

        route, _ = self.operate(
            "execute",
            "corrupt-first.json",
            preflight_report=preflight,
            preflight_report_sha256=preflight_sha,
            approval_claim=claim,
            powershell_runner=corrupt_first_runner,
        )
        self.assertEqual(route, "WRITE_ATTEMPTED_RESULT_UNKNOWN")
        report = json.loads((self.root / "corrupt-first.json").read_text())
        self.assertEqual(report["result"]["flash"]["attempts"], 1)
        self.assertIsNone(report["result"]["native_stage"])
        self.assertEqual(
            report["result"]["attempt_journal"]["sha256"],
            sha(
                (
                    self.root
                    / report["result"]["attempt_journal"]["path"]
                ).read_bytes()
            ),
        )

        stdout = io.StringIO()
        stderr = io.StringIO()
        argv = [
            "deploy_userdata.py",
            "execute",
            "--profile",
            "profile.json",
            "--report",
            "report.json",
            "--preflight-report",
            "preflight.json",
            "--preflight-report-sha256",
            "11" * 32,
            "--approval-claim",
            "claim.json",
        ]
        with (
            mock.patch.object(deploy.os.sys, "argv", argv),
            mock.patch.object(
                deploy,
                "operate",
                side_effect=deploy.ExecuteIntentIndeterminate("injected crash"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(deploy.main(), 3)
        self.assertIn("route_status=WRITE_ATTEMPTED_RESULT_UNKNOWN", stdout.getvalue())
        self.assertIn("indeterminate_no_same_claim_retry", stderr.getvalue())

        stdout = io.StringIO()
        stderr = io.StringIO()
        recover_argv = [
            "deploy_userdata.py",
            "recover-intent",
            "--profile",
            "profile.json",
            "--intent-journal",
            "intent.json",
            "--intent-initial-sha256",
            "22" * 32,
            "--report",
            "recovery.json",
        ]
        with (
            mock.patch.object(deploy.os.sys, "argv", recover_argv),
            mock.patch.object(
                deploy,
                "recover_intent",
                side_effect=deploy.DeployError("untrusted first record"),
            ),
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            self.assertEqual(deploy.main(), 3)
        self.assertIn("route_status=WRITE_ATTEMPTED_RESULT_UNKNOWN", stdout.getvalue())

    def test_complete_terminal_is_only_corrupt_result_no_state_recovery(self) -> None:
        writes_before = len([call for call in self.fastboot.calls if "flash" in call])
        route, report = self.corrupt_native_result_execute(
            "terminal-malformed-result", "terminal-corrupt-result.json"
        )
        self.assertEqual(route, "REFUSED_NO_STATE_CHANGE")
        self.assertEqual(report["result"]["flash"]["attempts"], 0)
        self.assertEqual(
            report["result"]["reason"],
            "HELPER_TERMINAL_NO_ATTEMPT_INTENT_RECOVERY",
        )
        self.assertEqual(
            writes_before,
            len([call for call in self.fastboot.calls if "flash" in call]),
        )

    def test_helper_contract_has_only_one_state_change_shape(self) -> None:
        source = deploy.HELPER.read_text(encoding="utf-8")
        self.assertIn("[System.IO.FileShare]::Read", source)
        self.assertIn("[System.IO.FileShare]::None", source)
        self.assertIn("$QueryTimeoutMs = 10000", source)
        self.assertIn("$WriteTimeoutMs = 300000", source)
        self.assertIn("AssignProcessToJobObject", source)
        self.assertIn("IsProcessInJob", source)
        self.assertIn("TerminateJobObject", source)
        self.assertIn("CreateProcessW", source)
        self.assertIn("CREATE_SUSPENDED", source)
        self.assertIn("transitionStream.Flush(true);", source)
        self.assertLess(
            source.index("AssignProcessToJobObject(job, process.hProcess)"),
            source.index("transitionStream.Flush(true);"),
        )
        self.assertLess(
            source.index("transitionStream.Flush(true);"),
            source.index("ResumeThread(process.hThread)"),
        )
        self.assertIn("DateTimeOffset.UtcNow.ToUnixTimeSeconds()", source)
        self.assertIn("[System.DateTimeOffset]::UtcNow.ToUnixTimeSeconds()", source)
        self.assertLess(
            source.index("APPROVAL_WINDOW_EXPIRED_BEFORE_TRANSITION"),
            source.index("transitionStream.Write(transitionBytes"),
        )
        self.assertLess(
            source.index("transitionStream.Flush(true);"),
            source.index("APPROVAL_WINDOW_EXPIRED_BEFORE_RESUME"),
        )
        self.assertLess(
            source.index("APPROVAL_WINDOW_EXPIRED_BEFORE_RESUME"),
            source.index("ResumeThread(process.hThread)"),
        )
        self.assertLess(
            source.rindex("$candidatePath = Open-And-ValidatePreparedCandidate $Profile $false"),
            source.rindex("        Assert-ApprovalWindowFresh"),
        )
        self.assertIn("HELPER_TERMINATED_BEFORE_FLASH_BOUNDARY", source)
        self.assertIn("Write-TerminalNoAttempt $Reason", source)
        self.assertIn("Open-And-ValidateIntent", source)
        self.assertIn("Open-And-ValidatePreparedCandidate", source)
        first_device_query = source.rindex("    $serial = Check-Device")
        self.assertLess(
            source.rindex("$candidatePath = Open-And-ValidatePreparedCandidate $Profile $true"),
            first_device_query,
        )
        self.assertLess(
            source.rindex("$candidatePath = Open-And-ValidatePreparedCandidate $Profile $false"),
            first_device_query,
        )
        execute_scope = source[source.index("$windowsArtifactNames = if ($Mode -eq 'Execute')"):source.index("    foreach ($name in $windowsArtifactNames)")]
        self.assertNotIn("'candidate'", execute_scope)
        self.assertNotIn("'candidate_raw'", execute_scope)
        self.assertNotIn("'rollback'", execute_scope)
        self.assertIn("Set-And-AssertPrivateAcl", source)
        self.assertIn("Assert-NativeNtfsDirectory", source)
        self.assertIn("Assert-Authenticode", source)
        self.assertIn("Assert-SafeFastbootZip", source)
        self.assertIn("ZIP_ENCRYPTED_OR_UNSUPPORTED_FLAGS", source)
        self.assertIn("ZIP_DUPLICATE_PATH", source)
        self.assertIn("ZIP_CASE_COLLISION", source)
        self.assertIn("ZIP_PATH_UNSAFE", source)
        self.assertIn("FASTBOOT_STAGE_NOT_EXACTLY_THREE_FILES", source)
        self.assertIn("FASTBOOT_ACQUISITION_REPOSITORY_FIELDS_MISMATCH", source)
        self.assertIn("$Acquisition.archive.sha1", source)
        self.assertIn("$Acquisition.device_action_performed -ne $false", source)
        self.assertIn("CREATE_UNICODE_ENVIRONMENT", source)
        self.assertIn("$environmentBlock", source)
        runtime_gate = source.rindex("    Initialize-RuntimeFastboot")
        first_device_query = source.index("    $serial = Check-Device", runtime_gate)
        self.assertLess(runtime_gate, first_device_query)
        self.assertIn(
            '$MappingSchema = "lmi-d114-physical-userdata-mapping/v2"', source
        )
        self.assertIn("'disk_sector_count'", source)
        self.assertIn("'backup_gpt_entries'", source)
        self.assertIn("MAPPING_GEOMETRY_MISMATCH", source)
        self.assertNotIn("$Mapping.userdata.gpt_disk_lbas", source)
        mapping_validation = source.index(
            "$Mapping = Read-JsonLocked $Locked.physical_mapping_evidence"
        )
        self.assertLess(
            source.index("MAPPING_GEOMETRY_MISMATCH", mapping_validation),
            source.index("$serial = Check-Device", mapping_validation),
        )
        self.assertNotIn("ProcessStartInfo", source)
        self.assertNotIn(".Result", source)
        self.assertNotIn(".Kill(", source)
        self.assertNotIn("Write-PreAttemptJournal", source)
        self.assertIn("LMI_P2_D114_RESULT_JSON_BASE64=", source)
        self.assertNotIn("identity_sha256", source)
        self.assertIn(deploy.FASTBOOT_SHA256, source)
        self.assertIn("Invoke-Fastboot @('-s', $serial, 'flash', 'userdata', $candidatePath)", source)
        self.assertEqual(
            source.count(
                "Invoke-Fastboot @('-s', $serial, 'flash', 'userdata', $candidatePath)"
            ),
            1,
        )
        for forbidden in ("'erase'", "'format'", "'reboot'", "'boot'", "'--force'", "'-S'"):
            self.assertNotIn(forbidden, source)

    def test_public_windows_contract_is_private_path_free_and_hardware_test_only(self) -> None:
        paths = (
            deploy.REPO / "scripts/lmi_p2_d114/deploy_userdata.py",
            deploy.REPO / "scripts/lmi_p2_d114/deploy_userdata_helper.ps1",
            deploy.REPO / "config/lmi-p2-d114/userdata-deploy-policy-lock-r1.json",
            deploy.REPO / "config/lmi-p2-d114/fastboot-windows-provenance-lock.json",
            deploy.REPO / "config/lmi-p2-d114/userdata-deploy-profile.template.json",
        )
        for path in paths:
            with self.subTest(path=path.name):
                payload = path.read_text(encoding="utf-8")
                self.assertNotIn(r"C:\Users\microstar", payload)
        policy = json.loads(paths[2].read_text(encoding="ascii"))
        readiness = policy["hardware_test_readiness"]
        self.assertEqual(readiness["blocking_gates"], [])
        self.assertFalse(readiness["production_claim"])
        self.assertFalse(readiness["reproducibility_claim"])
        self.assertEqual(
            readiness["closure_scope"], "application-local-non-system-payload-only"
        )
        self.assertEqual(
            readiness["accepted_residual_risks"],
            [
                "official-exact-r37-source-commit-and-build-manifest-unavailable",
                "windows-system-and-runtime-module-closure-not-attested",
                "d110-is-an-operator-owned-external-compatibility-prerequisite-not-a-release-asset",
                "d110-boot-is-separately-approved-ram-boot-only-never-flash-boot",
            ],
        )

    def test_windows_bootstrap_is_a_staged_file_not_command_text_with_arguments(self) -> None:
        source = (
            deploy.REPO / "scripts/lmi_p2_d114/deploy_userdata.py"
        ).read_text(encoding="utf-8")
        self.assertIn('staged_bootstrap = temporary_path / "bootstrap.ps1"', source)
        self.assertIn('"-File",\n            _windows_path(staged_bootstrap)', source)
        self.assertNotIn('"-Command",\n            POWERSHELL_BOOTSTRAP', source)
        self.assertIn('staged_bootstrap.read_bytes() != bootstrap_bytes', source)
        self.assertIn("-ceq '__EMPTY__'", deploy.POWERSHELL_BOOTSTRAP)
        self.assertIn(";& $sb -Mode", deploy.POWERSHELL_BOOTSTRAP)
        self.assertNotIn(";. $sb -Mode", deploy.POWERSHELL_BOOTSTRAP)
        self.assertNotIn('context.approval_claim_sha256 or "-"', source)


if __name__ == "__main__":
    unittest.main()
