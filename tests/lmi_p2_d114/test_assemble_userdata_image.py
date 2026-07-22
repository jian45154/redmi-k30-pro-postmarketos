from __future__ import annotations

import binascii
import copy
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import struct
import tempfile
import unittest
from unittest import mock
import uuid

import scripts.lmi_p2_d114.assemble_userdata_image as assembler
from tests.lmi_p2_d114 import host_bound
from scripts.lmi_p2_d114.assemble_userdata_image import (
    ARM64_ROOT_GUID,
    ESP_GUID,
    GPT_ENTRY_COUNT,
    GPT_ENTRY_SIZE,
    GPT_HEADER_SIZE,
    GPT_TABLE_LBAS,
    SECTOR_SIZE,
    AssemblyError,
    AssemblyPolicy,
    OUTPUT_ASSEMBLY_ATTESTATION_NAME,
    OUTPUT_BUNDLE_FILES,
    OUTPUT_INJECTION_ATTESTATION_NAME,
    OUTPUT_RAW_NAME,
    OUTPUT_SPARSE_NAME,
    assemble_userdata_image,
    load_injection_policy_lock,
    parse_sparse_image,
    validate_gpt,
    verify_composition,
    StableFile,
)


DISK_GUID = uuid.UUID("21b3874c-fea9-42e8-8062-1285a33298c2")
P1_GUID = uuid.UUID("71129e5f-f872-49f9-812e-d7cc9831013b")
P2_GUID = uuid.UUID("f84b1ed9-233d-4747-8886-8c08781a932d")
ROOT_UUID = "f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f"


def _partition_entry(
    type_guid: uuid.UUID, unique_guid: uuid.UUID, first: int, last: int
) -> bytes:
    entry = bytearray(GPT_ENTRY_SIZE)
    entry[:16] = type_guid.bytes_le
    entry[16:32] = unique_guid.bytes_le
    struct.pack_into("<QQQ", entry, 32, first, last, 0)
    name = "primary".encode("utf-16-le") + b"\0\0"
    entry[56 : 56 + len(name)] = name
    return bytes(entry)


def _gpt_header(
    *, current: int, backup: int, entries_lba: int, last_usable: int, table_crc: int
) -> bytes:
    block = bytearray(SECTOR_SIZE)
    struct.pack_into(
        "<8sIIIIQQQQ16sQIII",
        block,
        0,
        b"EFI PART",
        0x00010000,
        GPT_HEADER_SIZE,
        0,
        0,
        current,
        backup,
        2 + GPT_TABLE_LBAS,
        last_usable,
        DISK_GUID.bytes_le,
        entries_lba,
        GPT_ENTRY_COUNT,
        GPT_ENTRY_SIZE,
        table_crc,
    )
    checked = bytearray(block[:GPT_HEADER_SIZE])
    struct.pack_into("<I", checked, 16, 0)
    struct.pack_into("<I", block, 16, binascii.crc32(checked) & 0xFFFFFFFF)
    return bytes(block)


def _rootfs(size: int, marker: int) -> bytes:
    value = bytearray([marker]) * size
    superblock = bytearray(1024)
    struct.pack_into("<I", superblock, 0x04, size // SECTOR_SIZE)
    struct.pack_into("<I", superblock, 0x18, 2)
    struct.pack_into("<H", superblock, 0x38, 0xEF53)
    struct.pack_into("<I", superblock, 0x60, 0x40)
    superblock[0x68:0x78] = uuid.UUID(ROOT_UUID).bytes
    value[1024:2048] = superblock
    return bytes(value)


def _fixture_bytes() -> tuple[bytes, bytes, AssemblyPolicy]:
    disk_lbas = 32
    p1_first, p1_last = 6, 7
    p2_first, p2_last = 8, 25
    last_usable = disk_lbas - GPT_TABLE_LBAS - 2
    table = bytearray(GPT_ENTRY_COUNT * GPT_ENTRY_SIZE)
    table[:GPT_ENTRY_SIZE] = _partition_entry(ESP_GUID, P1_GUID, p1_first, p1_last)
    table[GPT_ENTRY_SIZE : 2 * GPT_ENTRY_SIZE] = _partition_entry(
        ARM64_ROOT_GUID, P2_GUID, p2_first, p2_last
    )
    table_crc = binascii.crc32(table) & 0xFFFFFFFF
    disk = bytearray(disk_lbas * SECTOR_SIZE)
    pmbr = bytearray(512)
    struct.pack_into(
        "<B3sB3sII",
        pmbr,
        446,
        0,
        b"\x00\x02\x00",
        0xEE,
        b"\xff\xff\xff",
        1,
        disk_lbas - 1,
    )
    pmbr[510:512] = b"\x55\xaa"
    disk[:512] = pmbr
    disk[SECTOR_SIZE : 2 * SECTOR_SIZE] = _gpt_header(
        current=1,
        backup=disk_lbas - 1,
        entries_lba=2,
        last_usable=last_usable,
        table_crc=table_crc,
    )
    disk[2 * SECTOR_SIZE : (2 + GPT_TABLE_LBAS) * SECTOR_SIZE] = table
    backup_table_lba = disk_lbas - GPT_TABLE_LBAS - 1
    disk[
        backup_table_lba * SECTOR_SIZE : (backup_table_lba + GPT_TABLE_LBAS)
        * SECTOR_SIZE
    ] = table
    disk[(disk_lbas - 1) * SECTOR_SIZE :] = _gpt_header(
        current=disk_lbas - 1,
        backup=1,
        entries_lba=backup_table_lba,
        last_usable=last_usable,
        table_crc=table_crc,
    )
    p2_size = (p2_last - p2_first + 1) * SECTOR_SIZE
    baseline_p2 = _rootfs(p2_size, 0x41)
    disk[p2_first * SECTOR_SIZE : (p2_last + 1) * SECTOR_SIZE] = baseline_p2
    baseline = bytes(disk)
    p2 = _rootfs(p2_size, 0x5A)
    policy = AssemblyPolicy(
        baseline_size=len(baseline),
        baseline_sha256=hashlib.sha256(baseline).hexdigest(),
        p2_size=p2_size,
        p2_uuid=ROOT_UUID,
        p1_first_lba=p1_first,
        p1_last_lba=p1_last,
        p2_first_lba=p2_first,
        p2_last_lba=p2_last,
    )
    return baseline, p2, policy


class AssembleUserdataImageTests(unittest.TestCase):
    @staticmethod
    def canonical(value: dict[str, object]) -> bytes:
        return (
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")

    @staticmethod
    def fixture_sha(label: str) -> str:
        return hashlib.sha256(label.encode("ascii")).hexdigest()

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        baseline, p2, self.policy = _fixture_bytes()
        self.baseline = self.root / "baseline.raw"
        self.baseline.write_bytes(baseline)
        self.baseline.chmod(0o600)
        self.input_bundle = self.root / "input.bundle"
        self.input_bundle.mkdir(mode=0o700)
        self.p2 = self.input_bundle / "rootfs.ext4"
        self.p2_attestation = self.input_bundle / "attestation.json"
        self.p2.write_bytes(p2)
        self.p2.chmod(0o600)

        policy_value = json.loads(assembler.INJECTION_POLICY_LOCK.read_text())
        policy_value["input"]["candidate_size"] = len(p2)
        policy_value["input"]["candidate_uuid"] = ROOT_UUID
        policy_value["output"]["fixed"]["size"] = len(p2)
        policy_value["output"]["fixed"]["uuid"] = ROOT_UUID
        policy_value["runtime"]["sealed_injector_script_sha256"] = self.fixture_sha(
            "sealed-injector"
        )
        self.injection_policy_value = policy_value
        self.injection_policy_lock = self.root / "fixture-injection-policy-lock.json"
        policy_payload = self.canonical(policy_value)
        self.injection_policy_lock.write_bytes(policy_payload)
        self.injection_policy_lock.chmod(0o600)
        self.injection_policy_sha256 = hashlib.sha256(policy_payload).hexdigest()

        output = dict(policy_value["output"]["fixed"])
        for field in policy_value["output"]["sha256_fields"]:
            output[field] = self.fixture_sha(field)
        output["sha256"] = hashlib.sha256(p2).hexdigest()
        output["owner"] = f"0:{os.getgid()}"
        self.attestation_value = {
            "claims": copy.deepcopy(policy_value["claims"]),
            "commands": copy.deepcopy(policy_value["commands"]),
            "input": copy.deepcopy(policy_value["input"]),
            "normalization": {
                **copy.deepcopy(policy_value["normalization"]["fixed"]),
                "pre_normalization_sha256": self.fixture_sha("pre-normalization"),
                "proof_sha256": hashlib.sha256(p2).hexdigest(),
                "sparse_st_blocks": max(1, len(p2) // 1024),
                "tree_identity_sha256": self.fixture_sha("tree-identity"),
            },
            "output": output,
            "runtime": {
                **copy.deepcopy(policy_value["runtime"]["fixed"]),
                "kernel_release": "6.14.0-fixture",
                "mount_loop": {
                    "backing_identity": "123:456",
                    "block_identity": "7:0:1792",
                    "mount_options": "ext4 rw,nosuid,nodev,relatime",
                },
                "namespaces": {
                    field: f"{field}:[{index + 100}]"
                    for index, field in enumerate(("ipc", "mnt", "net", "pid", "uts"))
                },
                "proc_version_sha256": self.fixture_sha("proc-version"),
                "sealed_script_sha256": policy_value["runtime"][
                    "sealed_injector_script_sha256"
                ],
            },
            "sanitization": copy.deepcopy(policy_value["sanitization"]),
            "schema": policy_value["attestation_schema"],
            "tools": copy.deepcopy(policy_value["tools"]),
        }
        self.write_attestation(self.attestation_value)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_attestation(self, value: dict[str, object]) -> None:
        self.p2_attestation.write_bytes(self.canonical(value))
        self.p2_attestation.chmod(0o600)

    @property
    def output_bundle(self) -> Path:
        return self.root / "assembled.bundle"

    def bundle_file(self, name: str) -> Path:
        return self.output_bundle / name

    def assemble(self) -> dict[str, object]:
        try:
            return assemble_userdata_image(
                self.baseline,
                self.p2,
                self.p2_attestation,
                self.output_bundle,
                policy=self.policy,
                injection_policy_lock_path=self.injection_policy_lock,
                test_only_allow_unprivileged_input_bundle=True,
                test_only_injection_policy_lock_sha256=self.injection_policy_sha256,
            )
        except AssemblyError as error:
            if "pinned sparse runtime" in str(error):
                host_bound.require(
                    False, f"host sparse toolchain differs from lock: {error}"
                )
            raise

    def validate_attestation(self) -> None:
        injection_policy = load_injection_policy_lock(
            self.injection_policy_lock,
            expected_sha256=self.injection_policy_sha256,
        )
        with StableFile(self.p2, "fixture P2") as p2:
            with StableFile(self.p2_attestation, "fixture injection attestation") as attestation:
                assembler._validate_injection_attestation(
                    attestation, p2.digest(), self.policy, injection_policy
                )

    def assert_attestation_rejected(
        self, mutation: object, message: str = "P2 injection"
    ) -> None:
        value = copy.deepcopy(self.attestation_value)
        mutation(value)
        self.write_attestation(value)
        with self.assertRaisesRegex(AssemblyError, message):
            self.validate_attestation()

    def test_synthetic_4096_gpt_assembles_sparse_roundtrips_and_attests(self) -> None:
        upstream = self.p2_attestation.read_bytes()
        result = self.assemble()
        expected = bytearray(self.baseline.read_bytes())
        expected[self.policy.p2_offset : self.policy.p2_end] = self.p2.read_bytes()
        self.assertEqual(
            self.bundle_file(OUTPUT_RAW_NAME).read_bytes(), bytes(expected)
        )
        self.assertGreater(self.bundle_file(OUTPUT_SPARSE_NAME).stat().st_size, 0)
        self.assertEqual(stat.S_IMODE(self.output_bundle.stat().st_mode), 0o700)
        self.assertEqual(
            {path.name for path in self.output_bundle.iterdir()}, OUTPUT_BUNDLE_FILES
        )
        for path in self.output_bundle.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(path.stat().st_nlink, 1)
        self.assertEqual(
            self.bundle_file(OUTPUT_INJECTION_ATTESTATION_NAME).read_bytes(), upstream
        )
        assembly_payload = self.bundle_file(
            OUTPUT_ASSEMBLY_ATTESTATION_NAME
        ).read_bytes()
        parsed = json.loads(assembly_payload)
        self.assertEqual(assembly_payload, self.canonical(parsed))
        self.assertEqual(
            parsed["schema"], "lmi-p2-d114-userdata-assembly-attestation/v1"
        )
        self.assertEqual(parsed["output"]["sparse"]["logical_size"], len(expected))
        self.assertEqual(
            parsed["verification"]["roundtrip_raw_sha256"],
            hashlib.sha256(expected).hexdigest(),
        )
        self.assertTrue(all(parsed["verification"]["gates"].values()))
        self.assertEqual(
            parsed["bindings"]["p2_injection_attestation_sha256"],
            hashlib.sha256(upstream).hexdigest(),
        )
        self.assertNotIn("simg_dump", json.dumps(parsed))
        self.assertEqual(parsed["compatibility"]["d110"]["root_uuid"], ROOT_UUID)
        self.assertEqual(result, parsed)

    def test_attestation_rejects_minimal_missing_unknown_and_nested_field_drift(self) -> None:
        mutations = {
            "minimal": lambda value: value.clear(),
            "top missing": lambda value: value.pop("runtime"),
            "top unknown": lambda value: value.__setitem__("unknown", True),
            "command missing": lambda value: value["commands"].pop("apk"),
            "command unknown": lambda value: value["commands"].__setitem__("x", []),
            "input missing": lambda value: value["input"].pop("apks"),
            "input unknown": lambda value: value["input"].__setitem__("x", 1),
            "APK nested unknown": lambda value: value["input"]["apks"]["p2"].__setitem__(
                "x", 1
            ),
            "output missing": lambda value: value["output"].pop("geometry_sha256"),
            "output unknown": lambda value: value["output"].__setitem__("x", 1),
            "runtime missing": lambda value: value["runtime"].pop("mount_loop"),
            "mount unknown": lambda value: value["runtime"]["mount_loop"].__setitem__("x", 1),
            "namespace missing": lambda value: value["runtime"]["namespaces"].pop("ipc"),
            "tool missing": lambda value: value["tools"].pop("bash_sha256"),
            "tool unknown": lambda value: value["tools"].__setitem__("x", "0" * 64),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.write_attestation(self.attestation_value)
                self.assert_attestation_rejected(mutation)

    def test_attestation_rejects_fixed_command_input_output_and_tool_drift(self) -> None:
        mutations = {
            "command": lambda value: value["commands"]["apk"].append("--drift"),
            "input": lambda value: value["input"]["apks"].__setitem__(
                "p2",
                {
                    **value["input"]["apks"]["p2"],
                    "sha256": self.fixture_sha("drift"),
                },
            ),
            "output": lambda value: value["output"].__setitem__("packages", ["drift"]),
            "owner": lambda value: value["output"].__setitem__("owner", "0:99999"),
            "tool": lambda value: value["tools"].__setitem__(
                "bash_sha256", self.fixture_sha("drift")
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.write_attestation(self.attestation_value)
                self.assert_attestation_rejected(mutation, "fixed")

    def test_attestation_rejects_invalid_dynamic_hash_namespace_and_runtime(self) -> None:
        mutations = {
            "dynamic hash": lambda value: value["output"].__setitem__(
                "geometry_sha256", "0" * 64
            ),
            "P2 binding": lambda value: value["output"].__setitem__(
                "sha256", self.fixture_sha("wrong-p2")
            ),
            "kernel": lambda value: value["runtime"].__setitem__(
                "kernel_release", "bad/release"
            ),
            "proc hash": lambda value: value["runtime"].__setitem__(
                "proc_version_sha256", "0" * 64
            ),
            "sealed script": lambda value: value["runtime"].__setitem__(
                "sealed_script_sha256", self.fixture_sha("other-script")
            ),
            "runtime lock": lambda value: value["runtime"].__setitem__(
                "injector_runtime_lock_sha256", self.fixture_sha("other-lock")
            ),
            "sandbox entry": lambda value: value["runtime"].__setitem__(
                "sandbox_entry_sha256", self.fixture_sha("other-entry")
            ),
            "namespace": lambda value: value["runtime"]["namespaces"].__setitem__(
                "mnt", "pid:[102]"
            ),
            "mount options": lambda value: value["runtime"]["mount_loop"].__setitem__(
                "mount_options", "ext4 rw,nosuid,relatime"
            ),
            "mount identity": lambda value: value["runtime"]["mount_loop"].__setitem__(
                "backing_identity", "0:2"
            ),
        }
        for label, mutation in mutations.items():
            with self.subTest(label=label):
                self.write_attestation(self.attestation_value)
                self.assert_attestation_rejected(mutation)

    def test_noncanonical_attestation_json_is_rejected(self) -> None:
        self.p2_attestation.write_text(
            json.dumps(self.attestation_value, indent=2) + "\n", encoding="ascii"
        )
        self.p2_attestation.chmod(0o600)
        with self.assertRaisesRegex(AssemblyError, "not canonical"):
            self.validate_attestation()

    def test_effective_root_is_refused_before_any_artifact_work(self) -> None:
        with mock.patch.object(assembler.os, "geteuid", return_value=0):
            with self.assertRaisesRegex(AssemblyError, "effective uid 0"):
                self.assemble()
        self.assertFalse(self.output_bundle.exists())

    def test_fixture_input_bundle_metadata_and_inventory_are_exact(self) -> None:
        self.p2.chmod(0o640)
        with self.assertRaisesRegex(AssemblyError, "metadata contract"):
            self.assemble()
        self.p2.chmod(0o600)
        extra = self.input_bundle / "extra"
        extra.write_bytes(b"x")
        extra.chmod(0o600)
        with self.assertRaisesRegex(AssemblyError, "exactly image and attestation"):
            self.assemble()

    def test_p2_paths_must_be_canonical_and_stay_identity_stable(self) -> None:
        alias = self.input_bundle / "rootfs-alias.ext4"
        alias.symlink_to(self.p2.name)
        with self.assertRaisesRegex(AssemblyError, "absolute and canonical"):
            assemble_userdata_image(
                self.baseline,
                alias,
                self.p2_attestation,
                self.output_bundle,
                policy=self.policy,
                injection_policy_lock_path=self.injection_policy_lock,
                test_only_allow_unprivileged_input_bundle=True,
                test_only_injection_policy_lock_sha256=self.injection_policy_sha256,
            )
        alias.unlink()
        original = assembler._copy_then_pwrite

        def copy_then_touch(*args: object) -> None:
            original(*args)
            before = self.p2.stat()
            os.utime(
                self.p2,
                ns=(before.st_atime_ns, before.st_mtime_ns + 1_000_000_000),
            )

        with mock.patch.object(assembler, "_copy_then_pwrite", copy_then_touch):
            with self.assertRaisesRegex(AssemblyError, "P2 input changed"):
                self.assemble()
        self.assertFalse(self.output_bundle.exists())

    def test_injection_policy_lock_pin_and_exact_structure_are_enforced(self) -> None:
        production_payload = assembler.INJECTION_POLICY_LOCK.read_bytes()
        self.assertEqual(
            assembler.INJECTION_POLICY_LOCK_SHA256,
            hashlib.sha256(production_payload).hexdigest(),
        )
        with self.assertRaisesRegex(AssemblyError, "SHA256 mismatch"):
            load_injection_policy_lock(
                self.injection_policy_lock,
                expected_sha256=self.fixture_sha("wrong-policy"),
            )
        value = copy.deepcopy(self.injection_policy_value)
        value["unknown"] = True
        payload = self.canonical(value)
        self.injection_policy_lock.write_bytes(payload)
        with self.assertRaisesRegex(AssemblyError, "top-level fields"):
            load_injection_policy_lock(
                self.injection_policy_lock,
                expected_sha256=hashlib.sha256(payload).hexdigest(),
            )

    def test_production_input_metadata_contract_is_root_primary_group_0750_0640(self) -> None:
        gid = os.getgid()
        bundle = SimpleNamespace(
            before=SimpleNamespace(st_mode=stat.S_IFDIR | 0o750, st_uid=0, st_gid=gid),
            fd=123,
        )
        p2 = SimpleNamespace(
            path=Path("rootfs.ext4"),
            label="P2 input",
            before=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=gid, st_nlink=1
            ),
        )
        attestation = SimpleNamespace(
            path=Path("attestation.json"),
            label="P2 injection attestation",
            before=SimpleNamespace(
                st_mode=stat.S_IFREG | 0o640, st_uid=0, st_gid=gid, st_nlink=1
            ),
        )
        with mock.patch.object(assembler.os, "listdir", return_value=["rootfs.ext4", "attestation.json"]):
            assembler._validate_p2_bundle_metadata(
                bundle, p2, attestation, test_fixture=False
            )
            p2.before.st_mode = stat.S_IFREG | 0o660
            with self.assertRaisesRegex(AssemblyError, "metadata contract"):
                assembler._validate_p2_bundle_metadata(
                    bundle, p2, attestation, test_fixture=False
                )

    def test_primary_header_crc_damage_is_rejected(self) -> None:
        damaged = bytearray(self.baseline.read_bytes())
        damaged[SECTOR_SIZE + 24] ^= 1
        self.baseline.write_bytes(damaged)
        policy = AssemblyPolicy(
            baseline_size=len(damaged),
            baseline_sha256=hashlib.sha256(damaged).hexdigest(),
            p2_size=self.policy.p2_size,
            p2_uuid=self.policy.p2_uuid,
            p1_first_lba=self.policy.p1_first_lba,
            p1_last_lba=self.policy.p1_last_lba,
            p2_first_lba=self.policy.p2_first_lba,
            p2_last_lba=self.policy.p2_last_lba,
        )
        with StableFile(self.baseline, "damaged GPT") as reader:
            with self.assertRaisesRegex(AssemblyError, "header CRC mismatch"):
                validate_gpt(reader, policy)

    def _verify_drift(self, offset: int, message: str) -> None:
        raw = self.root / "drifted.raw"
        expected = bytearray(self.baseline.read_bytes())
        expected[self.policy.p2_offset : self.policy.p2_end] = self.p2.read_bytes()
        expected[offset] ^= 0xFF
        raw.write_bytes(expected)
        raw.chmod(0o600)
        with self.assertRaisesRegex(AssemblyError, message):
            verify_composition(self.baseline, self.p2, raw, self.policy)

    def test_prefix_p2_and_tail_drift_are_rejected(self) -> None:
        for offset, message in (
            (self.policy.p2_offset - 1, "prefix drift"),
            (self.policy.p2_offset + 4096, "P2 drift"),
            (self.policy.p2_end, "tail/suffix drift"),
        ):
            with self.subTest(message=message):
                self._verify_drift(offset, message)

    def test_sparse_malformed_eof_and_blocksum_are_rejected(self) -> None:
        header = struct.pack(
            "<IHHHHIIII", 0xED26FF3A, 1, 0, 28, 12, SECTOR_SIZE, 2, 1, 0
        )
        zero_hash = hashlib.sha256(b"\0" * 2 * SECTOR_SIZE).hexdigest()
        malformed = self.root / "bad-blocksum.sparse"
        malformed.write_bytes(header + struct.pack("<HHII", 0xCAC3, 0, 1, 12))
        malformed.chmod(0o600)
        with self.assertRaisesRegex(AssemblyError, "blocksum|trailing"):
            parse_sparse_image(malformed, 2 * SECTOR_SIZE, zero_hash)
        eof_header = bytearray(header)
        struct.pack_into("<I", eof_header, 16, 1)
        trailing = self.root / "bad-eof.sparse"
        trailing.write_bytes(
            bytes(eof_header) + struct.pack("<HHII", 0xCAC3, 0, 1, 12) + b"x"
        )
        trailing.chmod(0o600)
        with self.assertRaisesRegex(AssemblyError, "trailing bytes"):
            parse_sparse_image(
                trailing,
                SECTOR_SIZE,
                hashlib.sha256(b"\0" * SECTOR_SIZE).hexdigest(),
            )

    def test_occupied_output_bundle_is_never_overwritten(self) -> None:
        self.output_bundle.mkdir()
        marker = self.output_bundle / "KEEP"
        marker.write_bytes(b"existing")
        with self.assertRaisesRegex(AssemblyError, "refusing to overwrite"):
            self.assemble()
        self.assertEqual(marker.read_bytes(), b"existing")

    def test_raced_occupied_destination_fails_at_renameat2_without_partial_bundle(self) -> None:
        original = assembler._renameat2_noreplace

        def occupy_then_rename(*args: object) -> None:
            self.output_bundle.mkdir(mode=0o700)
            (self.output_bundle / "KEEP").write_bytes(b"raced")
            original(*args)

        with mock.patch.object(assembler, "_renameat2_noreplace", occupy_then_rename):
            with self.assertRaisesRegex(AssemblyError, "refusing to overwrite"):
                self.assemble()
        self.assertEqual(
            {path.name for path in self.output_bundle.iterdir()}, {"KEEP"}
        )

    def test_publication_boundary_contains_all_four_sealed_files(self) -> None:
        original = assembler._renameat2_noreplace
        observed: list[set[str]] = []

        def inspect_then_rename(source_fd: int, source: str, *args: object) -> None:
            observed.append(set(os.listdir(f"/proc/self/fd/{source_fd}/{source}")))
            original(source_fd, source, *args)

        with mock.patch.object(assembler, "_renameat2_noreplace", inspect_then_rename):
            self.assemble()
        self.assertEqual(observed, [set(OUTPUT_BUNDLE_FILES)])

    def test_async_exception_after_atomic_rename_exposes_only_complete_bundle(self) -> None:
        original = assembler._renameat2_noreplace

        def rename_then_interrupt(*args: object) -> None:
            original(*args)
            raise KeyboardInterrupt

        with mock.patch.object(assembler, "_renameat2_noreplace", rename_then_interrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.assemble()
        self.assertEqual(
            {path.name for path in self.output_bundle.iterdir()}, OUTPUT_BUNDLE_FILES
        )
        for path in self.output_bundle.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
