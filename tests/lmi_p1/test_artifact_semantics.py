from __future__ import annotations

import binascii
import dataclasses
import gzip
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tempfile
import unittest

from scripts.lmi_p1.artifact_semantics import (
    ArtifactExpectations,
    PartitionLimits,
    _parse_deviceinfo,
    _parse_newc,
    calibrate_initramfs_manifest,
    load_initramfs_manifest,
    recheck_input_identities,
    validate_artifact_pair,
)
from scripts.lmi_p1.common import GateError
from tests.lmi_p1.image_fixtures import (
    ARM64_ROOT_GUID,
    BOOT_FIRST_LBA,
    BOOT_LAST_LBA,
    BOOT_PART_GUID,
    BOOT_UUID,
    DEVICEINFO,
    INIT_2ND,
    INIT_FUNCTIONS,
    NETWORKMANAGER_PROFILE,
    ROOT_UUID,
    ROOT_FIRST_LBA,
    ROOT_LAST_LBA,
    SECTOR,
    SSHD_CONFIG,
    UNUDHCPD_CONFIG,
    USB_DHCP_SERVICE,
    USB_DHCP_WRAPPER,
    create_fixture,
    fixture_dtb_sha256,
    make_boot,
    make_cpio,
    make_dtb,
    make_member_bomb,
    _newc_member,
    update_gpt_crcs,
)


class ArtifactSemanticsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = create_fixture(Path(self.temporary.name) / "fixture")
        tool_stat = Path("/usr/sbin/e2fsck").stat()
        self.expectations = ArtifactExpectations(
            profile="fixture-test",
            kernel_sha256=hashlib.sha256(self.fixture.vmlinuz.read_bytes()).hexdigest(),
            dtb_sha256=fixture_dtb_sha256(),
            initramfs_manifest=calibrate_initramfs_manifest(self.fixture.initramfs),
            minimum_userdata_bytes=self.fixture.userdata_img.stat().st_size,
            userdata_size_alignment=SECTOR,
            boot_first_lba=BOOT_FIRST_LBA,
            boot_last_lba=BOOT_LAST_LBA,
            root_first_lba=ROOT_FIRST_LBA,
            tool_uid=tool_stat.st_uid,
            tool_gid=tool_stat.st_gid,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def validate(
        self, expectations: ArtifactExpectations | None = None
    ) -> dict[str, object]:
        return validate_artifact_pair(
            *self.fixture.arguments(),
            rootfs_bindings=self.fixture.rootfs_bindings(),
            expectations=self.expectations if expectations is None else expectations,
        )

    def expectations_for(self, dtb: bytes, **changes: object) -> ArtifactExpectations:
        return dataclasses.replace(
            self.expectations,
            dtb_sha256=hashlib.sha256(dtb).hexdigest(),
            **changes,
        )

    def rewrite_boot(
        self,
        *,
        kernel: bytes | None = None,
        ramdisk: bytes | None = None,
        dtb: bytes | None = None,
        cmdline: str | None = None,
    ) -> None:
        kernel = self.fixture.vmlinuz.read_bytes() if kernel is None else kernel
        ramdisk = self.fixture.initramfs.read_bytes() if ramdisk is None else ramdisk
        dtb = self.fixture.dtb.read_bytes() if dtb is None else dtb
        self.fixture.boot_img.write_bytes(make_boot(kernel, ramdisk, dtb, cmdline=cmdline))

    def rewrite_cpio(self, cpio: bytes) -> None:
        ramdisk = gzip.compress(cpio, compresslevel=9, mtime=0)
        self.fixture.initramfs.write_bytes(ramdisk)
        self.rewrite_boot(ramdisk=ramdisk)

    def mutate_userdata(self, offset: int, value: bytes) -> bytearray:
        image = bytearray(self.fixture.userdata_img.read_bytes())
        image[offset : offset + len(value)] = value
        self.fixture.userdata_img.write_bytes(image)
        return image

    def rewrite_bound_root_file(
        self, path: Path, old: bytes, new: bytes
    ) -> None:
        self.assertEqual(len(old), len(new))
        value = path.read_bytes()
        self.assertEqual(value.count(old), 1)
        path.write_bytes(value.replace(old, new))
        image = self.fixture.userdata_img.read_bytes()
        self.assertEqual(image.count(old), 1)
        self.fixture.userdata_img.write_bytes(image.replace(old, new))

    def rewrite_rootfs_with_debugfs(self, commands: tuple[str, ...]) -> None:
        image = bytearray(self.fixture.userdata_img.read_bytes())
        start = ROOT_FIRST_LBA * SECTOR
        end = (ROOT_LAST_LBA + 1) * SECTOR
        rootfs = Path(self.temporary.name) / "mutated-rootfs.ext4"
        rootfs.write_bytes(image[start:end])
        for command in commands:
            subprocess.run(
                ["/usr/sbin/debugfs", "-w", "-R", command, str(rootfs)],
                check=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                timeout=30,
                env={
                    "HOME": "/nonexistent",
                    "LANG": "C",
                    "LC_ALL": "C",
                    "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                },
            )
        repaired = subprocess.run(
            ["/usr/sbin/e2fsck", "-fy", str(rootfs)],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=30,
            env={
                "HOME": "/nonexistent",
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            },
        )
        self.assertIn(repaired.returncode, {0, 1})
        image[start:end] = rootfs.read_bytes()
        self.fixture.userdata_img.write_bytes(image)

    def test_partition_limits_are_the_recorded_lmi_capacities(self) -> None:
        self.assertEqual(PartitionLimits().boot_bytes, 0x08000000)
        self.assertEqual(PartitionLimits().userdata_bytes, 0x1AC07FB000)
        with self.assertRaisesRegex(GateError, "positive integer"):
            PartitionLimits(boot_bytes=0)
        with self.assertRaisesRegex(GateError, "recorded hardware capacity"):
            PartitionLimits(boot_bytes=0x08000001)
        with self.assertRaisesRegex(GateError, "recorded hardware capacity"):
            PartitionLimits(userdata_bytes=0x1AC07FB001)
        self.assertEqual(
            ArtifactExpectations().dtb_sha256,
            "aee89cc172734de955a11ec335b16d3a1b5da51667083b919271c2b6902d57a6",
        )
        self.assertEqual(
            ArtifactExpectations().kernel_sha256,
            "38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e",
        )
        self.assertEqual(ArtifactExpectations().minimum_userdata_bytes, 1_818_230_784)
        smaller = PartitionLimits(
            boot_bytes=self.fixture.boot_img.stat().st_size + 1,
            userdata_bytes=self.fixture.userdata_img.stat().st_size + SECTOR,
        )
        self.assertEqual(
            validate_artifact_pair(
                *self.fixture.arguments(),
                rootfs_bindings=self.fixture.rootfs_bindings(),
                limits=smaller,
                expectations=self.expectations,
            )["limits"]["boot_bytes"],
            smaller.boot_bytes,
        )

    def test_committed_initramfs_manifest_loader_round_trips_canonical_json(self) -> None:
        path = Path(self.temporary.name) / "initramfs-manifest.json"
        value = {
            "entries": [dataclasses.asdict(entry) for entry in self.expectations.initramfs_manifest],
            "schema": "lmi-p1-initramfs-manifest/v1",
        }
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n",
            encoding="ascii",
        )
        self.assertEqual(load_initramfs_manifest(path), self.expectations.initramfs_manifest)

    def test_committed_initramfs_manifest_loader_rejects_noncanonical_json_and_duplicates(self) -> None:
        path = Path(self.temporary.name) / "initramfs-manifest.json"
        path.write_text(
            json.dumps(
                {
                    "schema": "lmi-p1-initramfs-manifest/v1",
                    "entries": [dataclasses.asdict(self.expectations.initramfs_manifest[0])],
                },
                indent=2,
            )
            + "\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(GateError, "not canonical"):
            load_initramfs_manifest(path)

        path.write_text(
            '{"entries":[],"entries":[],"schema":"lmi-p1-initramfs-manifest/v1"}\n',
            encoding="ascii",
        )
        with self.assertRaisesRegex(GateError, "duplicate key"):
            load_initramfs_manifest(path)

    def test_committed_initramfs_manifest_loader_rejects_shape_types_and_order(self) -> None:
        path = Path(self.temporary.name) / "initramfs-manifest.json"

        def write(value: object) -> None:
            path.write_text(
                json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
                + "\n",
                encoding="ascii",
            )

        entry = dataclasses.asdict(self.expectations.initramfs_manifest[0])
        cases = (
            (
                {"entries": [entry], "schema": "wrong"},
                "schema mismatch",
            ),
            (
                {"entries": [{key: value for key, value in entry.items() if key != "mode"}],
                 "schema": "lmi-p1-initramfs-manifest/v1"},
                "unexpected or missing fields",
            ),
            (
                {"entries": [{**entry, "mode": True}],
                 "schema": "lmi-p1-initramfs-manifest/v1"},
                "non-integer metadata",
            ),
            (
                {"entries": [dataclasses.asdict(self.expectations.initramfs_manifest[1]), entry],
                 "schema": "lmi-p1-initramfs-manifest/v1"},
                "sorted and path-unique",
            ),
            (
                {"entries": [entry, entry], "schema": "lmi-p1-initramfs-manifest/v1"},
                "sorted and path-unique",
            ),
        )
        for value, message in cases:
            with self.subTest(message=message):
                write(value)
                with self.assertRaisesRegex(GateError, message):
                    load_initramfs_manifest(path)

    def test_valid_pair_returns_fixed_path_free_json_evidence(self) -> None:
        report = self.validate()
        self.assertEqual(report["schema"], "lmi-artifact-semantics-v3")
        self.assertEqual(report["boot"]["header_size"], 1660)
        self.assertEqual(report["boot"]["kernel"]["magic"], "ARMd")
        self.assertEqual(report["boot"]["dtb"]["version"], 17)
        self.assertEqual(
            report["boot"]["dtb"]["model"],
            "Qualcomm Technologies, Inc. kona v2.1 SoC",
        )
        self.assertEqual(report["boot"]["dtb"]["compatible"], ["qcom,kona"])
        self.assertTrue(report["deviceinfo"]["copies_equal"])
        self.assertEqual(report["userdata"]["logical_block_size"], 4096)
        self.assertEqual(
            [item["name"] for item in report["userdata"]["partitions"]],
            ["pmOS_boot", "pmOS_root"],
        )
        root_features = report["userdata"]["partitions"][1]["filesystem"][
            "feature_masks"
        ]
        self.assertEqual(root_features["required_compat"], 0x103C)
        self.assertEqual(root_features["required_incompat"], 0x2C2)
        self.assertEqual(root_features["forbidden_incompat"], 0x2004)
        self.assertEqual(root_features["forbidden_ro_compat"], 0x400)
        encoded = json.dumps(report, sort_keys=True)
        self.assertNotIn(self.temporary.name, encoded)
        self.assertNotIn("boot.img", encoded)

    def test_boot_limit_is_enforced(self) -> None:
        for limit in (
            self.fixture.boot_img.stat().st_size - 1,
            self.fixture.boot_img.stat().st_size,
        ):
            with self.subTest(limit=limit), self.assertRaisesRegex(
                GateError, "outside its recorded limit"
            ):
                validate_artifact_pair(
                    *self.fixture.arguments(),
                    rootfs_bindings=self.fixture.rootfs_bindings(),
                    limits=PartitionLimits(boot_bytes=limit),
                    expectations=self.expectations,
                )
        with self.assertRaisesRegex(GateError, "outside its recorded limit"):
            validate_artifact_pair(
                *self.fixture.arguments(),
                rootfs_bindings=self.fixture.rootfs_bindings(),
                limits=PartitionLimits(
                    userdata_bytes=self.fixture.userdata_img.stat().st_size
                ),
                expectations=self.expectations,
            )

    def test_android_boot_header_mutations_fail_closed(self) -> None:
        cases = (
            (0, b"ATTACK!!", "magic"),
            (36, struct.pack("<I", 2048), "page size"),
            (40, struct.pack("<I", 1), "header version"),
            (1644, struct.pack("<I", 1648), "header size"),
            (12, struct.pack("<I", 0x9000), "kernel address"),
            (24, struct.pack("<I", 1), "second"),
            (1632, struct.pack("<I", 1), "recovery"),
        )
        original = self.fixture.boot_img.read_bytes()
        for offset, replacement, message in cases:
            with self.subTest(offset=offset):
                mutated = bytearray(original)
                mutated[offset : offset + len(replacement)] = replacement
                self.fixture.boot_img.write_bytes(mutated)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
        self.fixture.boot_img.write_bytes(original)

    def test_boot_padding_and_trailing_data_must_be_zero(self) -> None:
        original = bytearray(self.fixture.boot_img.read_bytes())
        original[2000] = 1
        self.fixture.boot_img.write_bytes(original)
        with self.assertRaisesRegex(GateError, "header padding"):
            self.validate()
        self.rewrite_boot()
        self.fixture.boot_img.write_bytes(self.fixture.boot_img.read_bytes() + b"attack")
        with self.assertRaisesRegex(GateError, "trailing bytes"):
            self.validate()

    def test_embedded_components_must_equal_exports(self) -> None:
        for path, message in (
            (self.fixture.vmlinuz, "embedded kernel"),
            (self.fixture.initramfs, "embedded ramdisk"),
            (self.fixture.dtb, "embedded DTB"),
        ):
            with self.subTest(path=path.name):
                original = path.read_bytes()
                path.write_bytes(original[:-1] + bytes([original[-1] ^ 1]))
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
                path.write_bytes(original)

    def test_arm64_header_magic_text_offset_and_flags_are_strict(self) -> None:
        original = self.fixture.vmlinuz.read_bytes()
        cases = (
            (56, b"NOPE", "magic"),
            (8, struct.pack("<Q", 0), "text offset"),
            (24, struct.pack("<Q", 0), "flags"),
        )
        for offset, replacement, message in cases:
            with self.subTest(offset=offset):
                kernel = bytearray(original)
                kernel[offset : offset + len(replacement)] = replacement
                self.fixture.vmlinuz.write_bytes(kernel)
                self.rewrite_boot(kernel=bytes(kernel))
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
        self.fixture.vmlinuz.write_bytes(original)
        self.rewrite_boot(kernel=original)

    def test_kernel_digest_and_declared_size_are_exact(self) -> None:
        original = self.fixture.vmlinuz.read_bytes()
        for declared, message in (
            (0, "declared size is zero"),
            (len(original) - 1, "does not exactly match"),
            (len(original) + 1, "does not exactly match"),
        ):
            with self.subTest(declared=declared):
                kernel = bytearray(original)
                struct.pack_into("<Q", kernel, 16, declared)
                self.fixture.vmlinuz.write_bytes(kernel)
                self.rewrite_boot(kernel=bytes(kernel))
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
        kernel = bytearray(original)
        kernel[-1] ^= 1
        self.fixture.vmlinuz.write_bytes(kernel)
        self.rewrite_boot(kernel=bytes(kernel))
        with self.assertRaisesRegex(GateError, "kernel sha256"):
            self.validate()

    def test_android_boot_v2_canonical_os_name_and_id_are_bound(self) -> None:
        original = self.fixture.boot_img.read_bytes()
        for offset, replacement, message in (
            (44, struct.pack("<I", 1), "OS version"),
            (48, b"lmi\0", "board name"),
            (576, b"X", "ID does not bind"),
        ):
            with self.subTest(offset=offset):
                image = bytearray(original)
                image[offset : offset + len(replacement)] = replacement
                self.fixture.boot_img.write_bytes(image)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
        self.fixture.boot_img.write_bytes(original)

    def test_fdt_version_totalsize_and_structure_are_strict(self) -> None:
        original = self.fixture.dtb.read_bytes()
        off_struct = struct.unpack_from(">I", original, 8)[0]
        size_struct = struct.unpack_from(">I", original, 36)[0]
        cases = (
            (4, struct.pack(">I", len(original) - 4), "totalsize"),
            (20, struct.pack(">I", 16), "version"),
            (
                off_struct + size_struct - 4,
                struct.pack(">I", 0xDEADBEEF),
                "unknown token",
            ),
        )
        for offset, replacement, message in cases:
            with self.subTest(offset=offset):
                dtb = bytearray(original)
                dtb[offset : offset + len(replacement)] = replacement
                self.fixture.dtb.write_bytes(dtb)
                self.rewrite_boot(dtb=bytes(dtb))
                with self.assertRaisesRegex(GateError, message):
                    self.validate(self.expectations_for(bytes(dtb)))
        self.fixture.dtb.write_bytes(original)
        self.rewrite_boot(dtb=original)

    def test_dtb_hash_model_compatible_and_chosen_policy_bind_lmi(self) -> None:
        with self.assertRaisesRegex(GateError, "DTB sha256"):
            self.validate(
                dataclasses.replace(
                    self.expectations,
                    dtb_sha256=ArtifactExpectations().dtb_sha256,
                )
            )

        wrong = make_dtb(model="Valid Other Device", compatible=("vendor,other",))
        self.fixture.dtb.write_bytes(wrong)
        self.rewrite_boot(dtb=wrong)
        with self.assertRaisesRegex(GateError, "root model"):
            self.validate(self.expectations_for(wrong))

        wrong_compatible = make_dtb(compatible=("qcom,kona", "xiaomi,lmi"))
        self.fixture.dtb.write_bytes(wrong_compatible)
        self.rewrite_boot(dtb=wrong_compatible)
        with self.assertRaisesRegex(GateError, "compatible"):
            self.validate(self.expectations_for(wrong_compatible))

        chosen = make_dtb(bootargs="console=ttyMSM0")
        self.fixture.dtb.write_bytes(chosen)
        self.rewrite_boot(dtb=chosen)
        with self.assertRaisesRegex(GateError, "forbidden /chosen/bootargs"):
            self.validate(self.expectations_for(chosen))
        allowed = self.expectations_for(chosen, chosen_bootargs="console=ttyMSM0")
        self.assertEqual(
            self.validate(allowed)["boot"]["dtb"]["chosen_bootargs"],
            "console=ttyMSM0",
        )

        debug = make_dtb(bootargs="pmos.debug-shell")
        self.fixture.dtb.write_bytes(debug)
        self.rewrite_boot(dtb=debug)
        with self.assertRaisesRegex(GateError, "debug shell"):
            self.validate(self.expectations_for(debug, chosen_bootargs="pmos.debug-shell"))

    def test_gzip_must_be_single_complete_bounded_stream(self) -> None:
        ramdisk = self.fixture.initramfs.read_bytes() + b"second-stream"
        self.fixture.initramfs.write_bytes(ramdisk)
        self.rewrite_boot(ramdisk=ramdisk)
        with self.assertRaisesRegex(GateError, "trailing|concatenated"):
            self.validate()

    def test_newc_must_be_complete_and_contain_required_utilities(self) -> None:
        cpio = gzip.decompress(self.fixture.initramfs.read_bytes())
        missing = cpio.replace(b"sbin/blkid\0", b"sbin/blkiX\0", 1)
        self.rewrite_cpio(missing)
        with self.assertRaisesRegex(GateError, "dangling symlink"):
            self.validate()
        self.rewrite_cpio(cpio[:-112])
        with self.assertRaisesRegex(GateError, "truncated|TRAILER"):
            self.validate()

    def test_newc_rejects_init_symlink_and_invalid_archive_ancestry(self) -> None:
        self.rewrite_cpio(
            make_cpio(init_mode=stat.S_IFLNK | 0o777, init_data=b"/bin/sh")
        )
        with self.assertRaisesRegex(GateError, "required initramfs member"):
            self.validate()

        malformed = bytearray()
        malformed.extend(_newc_member(".", stat.S_IFDIR | 0o755, b"", 1))
        malformed.extend(_newc_member("missing/file", stat.S_IFREG | 0o644, b"x", 2))
        malformed.extend(_newc_member("TRAILER!!!", 0, b"", 3))
        with self.assertRaisesRegex(GateError, "before its parent directory"):
            _parse_newc(bytes(malformed))

    def test_newc_resolves_usrmerge_ancestor_and_deviceinfo_symlinks(self) -> None:
        entries = (
            (".", stat.S_IFDIR | 0o755, b""),
            ("bin", stat.S_IFLNK | 0o777, b"usr/bin"),
            ("sbin", stat.S_IFLNK | 0o777, b"usr/bin"),
            ("usr", stat.S_IFDIR | 0o755, b""),
            ("usr/bin", stat.S_IFDIR | 0o755, b""),
            ("usr/sbin", stat.S_IFLNK | 0o777, b"bin"),
            ("usr/share", stat.S_IFDIR | 0o755, b""),
            ("usr/share/deviceinfo", stat.S_IFDIR | 0o755, b""),
            ("usr/share/misc", stat.S_IFDIR | 0o755, b""),
            ("init", stat.S_IFREG | 0o755, b"init"),
            ("init_2nd.sh", stat.S_IFREG | 0o755, b"second"),
            ("init_functions.sh", stat.S_IFREG | 0o644, b"functions"),
            ("usr/bin/busybox", stat.S_IFREG | 0o755, b"busybox"),
            ("usr/bin/blkid", stat.S_IFREG | 0o755, b"blkid"),
            ("usr/bin/losetup", stat.S_IFREG | 0o755, b"losetup"),
            (
                "usr/share/deviceinfo/device-xiaomi-lmi",
                stat.S_IFREG | 0o644,
                DEVICEINFO,
            ),
            (
                "usr/share/deviceinfo/deviceinfo",
                stat.S_IFLNK | 0o777,
                b"device-xiaomi-lmi",
            ),
            (
                "usr/share/misc/source_deviceinfo",
                stat.S_IFREG | 0o644,
                b"source",
            ),
        )
        archive = bytearray()
        for ino, (name, mode, data) in enumerate(entries, 1):
            archive.extend(_newc_member(name, mode, data, ino))
        archive.extend(_newc_member("TRAILER!!!", 0, b"", len(entries) + 1))
        members = _parse_newc(bytes(archive))
        self.assertEqual(bytes(members["usr/bin/busybox"].data), b"busybox")

    def test_newc_rejects_ancestor_symlink_loops_and_non_directories(self) -> None:
        for entries, message in (
            (
                (
                    (".", stat.S_IFDIR | 0o755, b""),
                    ("bin", stat.S_IFLNK | 0o777, b"sbin"),
                    ("sbin", stat.S_IFLNK | 0o777, b"bin"),
                ),
                "symlink loop",
            ),
            (
                (
                    (".", stat.S_IFDIR | 0o755, b""),
                    ("bin", stat.S_IFREG | 0o755, b"not-a-directory"),
                ),
                "traverses a non-directory",
            ),
        ):
            with self.subTest(message=message):
                archive = bytearray()
                for ino, (name, mode, data) in enumerate(entries, 1):
                    archive.extend(_newc_member(name, mode, data, ino))
                archive.extend(
                    _newc_member("TRAILER!!!", 0, b"", len(entries) + 1)
                )
                with self.assertRaisesRegex(GateError, message):
                    _parse_newc(bytes(archive))

    def test_newc_rejects_noncanonical_or_escaping_symlink_targets(self) -> None:
        for target, message in (
            (b"usr//bin", "unsafe"),
            (b"./usr/bin", "unsafe"),
            (b"usr/./bin", "unsafe"),
            (b"usr/bin/", "unsafe"),
            (b"//usr/bin", "unsafe"),
            (b"../../outside", "escapes the archive"),
        ):
            with self.subTest(target=target):
                archive = bytearray()
                archive.extend(_newc_member(".", stat.S_IFDIR | 0o755, b"", 1))
                archive.extend(
                    _newc_member("bin", stat.S_IFLNK | 0o777, target, 2)
                )
                archive.extend(_newc_member("TRAILER!!!", 0, b"", 3))
                with self.assertRaisesRegex(GateError, message):
                    _parse_newc(bytes(archive))

    def test_newc_member_and_cumulative_name_bombs_are_bounded(self) -> None:
        with self.assertRaisesRegex(GateError, "exceeds 65536 members"):
            _parse_newc(make_member_bomb(65_536))
        with self.assertRaisesRegex(GateError, "names exceed 8 MiB"):
            _parse_newc(make_member_bomb(55_000, name_width=160))

    def test_newc_required_symlink_depth_is_bounded(self) -> None:
        chain = [
            (
                f"sbin/link{index:02d}",
                stat.S_IFLNK | 0o777,
                f"link{index + 1:02d}".encode() if index < 63 else b"real-blkid",
            )
            for index in range(64)
        ]
        chain.append(("sbin/real-blkid", stat.S_IFREG | 0o755, b"real"))
        archive = make_cpio(
            blkid_mode=stat.S_IFLNK | 0o777,
            blkid_data=b"link00",
            extra_entries=chain,
        )
        with self.assertRaisesRegex(GateError, "symlink depth 64"):
            _parse_newc(archive)

    def test_complete_initramfs_inventory_rejects_extras_and_hardlinks(self) -> None:
        self.rewrite_cpio(
            make_cpio(extra_entries=(("unexpected", stat.S_IFREG | 0o644, b"x"),))
        )
        with self.assertRaisesRegex(GateError, "logical inventory"):
            self.validate()

        archive = bytearray()
        archive.extend(_newc_member(".", stat.S_IFDIR | 0o755, b"", 1))
        archive.extend(
            _newc_member("hardlink", stat.S_IFREG | 0o644, b"x", 2, nlink=2)
        )
        archive.extend(_newc_member("TRAILER!!!", 0, b"", 3))
        with self.assertRaisesRegex(GateError, "unmodeled hardlink"):
            _parse_newc(bytes(archive))

    def test_newc_requires_canonical_link_counts_and_unique_inodes(self) -> None:
        for name, mode, data, nlink in (
            (".", stat.S_IFDIR | 0o755, b"", 1),
            ("link", stat.S_IFLNK | 0o777, b"target", 1),
            ("file", stat.S_IFREG | 0o644, b"x", 0),
        ):
            with self.subTest(name=name, nlink=nlink):
                archive = bytearray()
                archive.extend(_newc_member(".", stat.S_IFDIR | 0o755, b"", 1))
                if name != ".":
                    archive.extend(_newc_member(name, mode, data, 2, nlink=nlink))
                else:
                    archive = bytearray(
                        _newc_member(name, mode, data, 1, nlink=nlink)
                    )
                archive.extend(_newc_member("TRAILER!!!", 0, b"", 3))
                with self.assertRaisesRegex(GateError, "non-canonical link count"):
                    _parse_newc(bytes(archive))

        duplicate_inode = bytearray()
        duplicate_inode.extend(_newc_member(".", stat.S_IFDIR | 0o755, b"", 1))
        duplicate_inode.extend(
            _newc_member("file", stat.S_IFREG | 0o644, b"x", 1)
        )
        duplicate_inode.extend(_newc_member("TRAILER!!!", 0, b"", 3))
        with self.assertRaisesRegex(GateError, "aliases an inode"):
            _parse_newc(bytes(duplicate_inode))

    def test_release_mode_requires_manifest_and_calibration_is_never_eligible(self) -> None:
        no_manifest = dataclasses.replace(self.expectations, initramfs_manifest=None)
        with self.assertRaisesRegex(GateError, "committed initramfs manifest"):
            self.validate(no_manifest)
        report = validate_artifact_pair(
            *self.fixture.arguments(),
            rootfs_bindings=self.fixture.rootfs_bindings(),
            expectations=no_manifest,
            calibration=True,
        )
        self.assertTrue(report["release"]["calibration"])
        self.assertFalse(report["release"]["eligible"])
        self.assertGreater(len(report["boot"]["initramfs"]["inventory"]), 1)

    def test_archived_patched_scripts_must_match_staged_files(self) -> None:
        self.fixture.init_functions.write_bytes(INIT_FUNCTIONS + b"# changed\n")
        with self.assertRaisesRegex(GateError, "archived init_functions"):
            self.validate()
        self.fixture.init_functions.write_bytes(INIT_FUNCTIONS)
        self.fixture.init_2nd.write_bytes(INIT_2ND + b"# changed\n")
        with self.assertRaisesRegex(GateError, "archived init_2nd"):
            self.validate()

    def test_deviceinfo_is_parsed_without_shell_evaluation(self) -> None:
        malicious = self.fixture.deviceinfo.read_bytes() + b'x="$(touch /tmp/nope)"\n'
        self.fixture.deviceinfo.write_bytes(malicious)
        self.fixture.staged_deviceinfo.write_bytes(malicious)
        self.rewrite_cpio(make_cpio(deviceinfo=malicious))
        with self.assertRaisesRegex(GateError, "shell expansion"):
            self.validate()

    def test_deviceinfo_locks_flash_target_method_and_usb_gadget(self) -> None:
        mutations = (
            (b'deviceinfo_flash_fastboot_partition_rootfs="userdata"', b'deviceinfo_flash_fastboot_partition_rootfs="super"'),
            (b'deviceinfo_flash_method="fastboot"', b'deviceinfo_flash_method="heimdall"'),
            (b'deviceinfo_usb_network_function="rndis.usb0"', b'deviceinfo_usb_network_function="ecm.usb0"'),
            (b'deviceinfo_usb_idVendor="0x0525"', b'deviceinfo_usb_idVendor="0x18d1"'),
            (b'deviceinfo_usb_idProduct="0xA4A2"', b'deviceinfo_usb_idProduct="0x4ee7"'),
        )
        for original, replacement in mutations:
            with self.subTest(replacement=replacement):
                self.assertIn(original, DEVICEINFO)
                with self.assertRaisesRegex(GateError, "installed deviceinfo mismatch"):
                    _parse_deviceinfo(DEVICEINFO.replace(original, replacement))

    def test_staged_installed_and_archived_deviceinfo_must_be_identical(self) -> None:
        self.fixture.staged_deviceinfo.write_bytes(DEVICEINFO + b"# staged mutation\n")
        with self.assertRaisesRegex(GateError, "installed deviceinfo differs"):
            self.validate()
        self.fixture.staged_deviceinfo.write_bytes(DEVICEINFO)
        self.rewrite_cpio(make_cpio(deviceinfo=DEVICEINFO + b"# archive mutation\n"))
        with self.assertRaisesRegex(GateError, "archived deviceinfo differs"):
            self.validate()

    def test_cmdline_requires_exact_tokens_uuids_and_no_debug_shell(self) -> None:
        from tests.lmi_p1.image_fixtures import BASE_CMDLINE

        cases = (
            (
                f"{BASE_CMDLINE} pmos.debug-shell pmos_boot_uuid={BOOT_UUID} "
                f"pmos_root_uuid={ROOT_UUID} pmos_rootfsopts=defaults",
                "exact deviceinfo base tokens|debug",
            ),
            (
                f"{BASE_CMDLINE} pmos_boot_uuid={BOOT_UUID} "
                f"pmos_root_uuid={ROOT_UUID.upper()} pmos_rootfsopts=defaults",
                "canonical",
            ),
            (
                f"{BASE_CMDLINE} pmos_boot_uuid={BOOT_UUID} "
                f"pmos_root_uuid={ROOT_UUID} pmos_rootfsopts=rw",
                "rootfs options",
            ),
        )
        for cmdline, message in cases:
            with self.subTest(cmdline=cmdline[-40:]):
                self.rewrite_boot(cmdline=cmdline)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()

    def test_raw_userdata_geometry_and_protective_mbr_are_required(self) -> None:
        self.fixture.userdata_img.write_bytes(self.fixture.userdata_img.read_bytes()[:-1])
        with self.assertRaisesRegex(GateError, "multiple of 4096"):
            self.validate()
        self.fixture.userdata_img.write_bytes(
            self.fixture.userdata_img.read_bytes().ljust(32 * SECTOR, b"\0")
        )
        # Re-create, then break only the MBR signature.
        self.fixture = create_fixture(Path(self.temporary.name) / "fixture2")
        self.mutate_userdata(510, b"\0\0")
        with self.assertRaisesRegex(GateError, "protective MBR signature"):
            self.validate()

    def test_primary_and_backup_gpt_crcs_and_tables_are_verified(self) -> None:
        self.mutate_userdata(SECTOR + 56, b"\x01")
        with self.assertRaisesRegex(GateError, "header CRC"):
            self.validate()
        self.fixture = create_fixture(Path(self.temporary.name) / "fixture3")
        image = bytearray(self.fixture.userdata_img.read_bytes())
        backup_lba = len(image) // SECTOR - 1
        backup_entries_lba = backup_lba - 4
        image[backup_entries_lba * SECTOR + 127] = 1
        table = bytes(image[backup_entries_lba * SECTOR : backup_lba * SECTOR])
        table_crc = binascii.crc32(table) & 0xFFFFFFFF
        header = bytearray(image[backup_lba * SECTOR : (backup_lba + 1) * SECTOR])
        struct.pack_into("<I", header, 88, table_crc)
        struct.pack_into("<I", header, 16, 0)
        struct.pack_into("<I", header, 16, binascii.crc32(header[:92]) & 0xFFFFFFFF)
        image[backup_lba * SECTOR : (backup_lba + 1) * SECTOR] = header
        self.fixture.userdata_img.write_bytes(image)
        with self.assertRaisesRegex(GateError, "headers disagree"):
            self.validate()

    def test_gpt_types_unique_guids_and_nonoverlap_are_strict(self) -> None:
        cases = (
            (0, ARM64_ROOT_GUID.bytes_le, "type mismatch"),
            (128 + 16, BOOT_PART_GUID.bytes_le, "not unique"),
            (128 + 32, struct.pack("<Q", 9), "overlap"),
        )
        original = self.fixture.userdata_img.read_bytes()
        for table_offset, replacement, message in cases:
            with self.subTest(table_offset=table_offset):
                image = bytearray(original)
                absolute = 2 * SECTOR + table_offset
                image[absolute : absolute + len(replacement)] = replacement
                update_gpt_crcs(image)
                self.fixture.userdata_img.write_bytes(image)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
        self.fixture.userdata_img.write_bytes(original)

    def test_ext_superblock_clean_extent_and_metadata_checksum_policy(self) -> None:
        boot_super = BOOT_FIRST_LBA * SECTOR + 1024
        root_super = ROOT_FIRST_LBA * SECTOR + 1024
        cases = (
            (boot_super + 0x3A, struct.pack("<H", 2), "not clean"),
            (root_super + 0x5C, struct.pack("<I", 0x38), "allowlist"),
            (root_super + 0x60, struct.pack("<I", 0x282), "allowlist"),
            (root_super + 0x60, struct.pack("<I", 0x2C6), "allowlist"),
            (root_super + 0x60, struct.pack("<I", 0x22C2), "allowlist"),
            (root_super + 0x64, struct.pack("<I", 0x46B), "allowlist"),
            (root_super + 0x68, bytes.fromhex(BOOT_UUID.replace("-", "")), "not distinct"),
        )
        original = self.fixture.userdata_img.read_bytes()
        for offset, replacement, message in cases:
            with self.subTest(offset=offset):
                image = bytearray(original)
                image[offset : offset + len(replacement)] = replacement
                self.fixture.userdata_img.write_bytes(image)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()
        self.fixture.userdata_img.write_bytes(original)

    def test_real_ext_filesystems_are_checked_read_only_and_corruption_fails(self) -> None:
        report = self.validate()
        checks = report["userdata"]["read_only_e2fsck"]
        self.assertEqual(checks["pmOS_boot"]["arguments"], ["-fn"])
        self.assertEqual(checks["pmOS_root"]["returncode"], 0)
        self.assertEqual(
            report["userdata"]["root_files"]["/etc/ssh/sshd_config"]["mode"],
            0o600,
        )

        image = bytearray(self.fixture.userdata_img.read_bytes())
        # Corrupt the root group descriptor's free-block count.  The bounded
        # superblock parser cannot prove this internal relation; e2fsck must.
        descriptor_free_blocks = ROOT_FIRST_LBA * SECTOR + SECTOR + 12
        image[descriptor_free_blocks] ^= 1
        self.fixture.userdata_img.write_bytes(image)
        with self.assertRaisesRegex(GateError, "e2fsck read-only consistency"):
            self.validate()

    def test_root_image_critical_files_and_ssh_policy_are_bound(self) -> None:
        image = bytearray(self.fixture.userdata_img.read_bytes())
        start = image.find(SSHD_CONFIG)
        self.assertGreaterEqual(start, 0)
        image[start + len("Port ")] ^= 1
        self.fixture.userdata_img.write_bytes(image)
        with self.assertRaisesRegex(GateError, "sshd_config.*trusted input"):
            self.validate()

        self.fixture = create_fixture(Path(self.temporary.name) / "fixture-root-policy")
        self.fixture.sshd_config.write_bytes(
            SSHD_CONFIG.replace(b"PasswordAuthentication no", b"PasswordAuthentication yes")
        )
        self.fixture.sshd_config.chmod(0o600)
        with self.assertRaisesRegex(GateError, "passwordauthentication policy"):
            self.validate()

    def test_usb_management_profile_rejects_shared_mode_and_bad_interface(self) -> None:
        cases = (
            (
                self.fixture.networkmanager_profile,
                b"method=manual",
                b"method=shared",
                "fixed lmi USB policy",
            ),
            (
                self.fixture.usb_dhcp_wrapper,
                b"interface=usb0",
                b"interface=wlan",
                "fixed lmi USB policy",
            ),
        )
        for path, old, new, message in cases:
            with self.subTest(path=path.name):
                self.fixture = create_fixture(
                    Path(self.temporary.name) / f"fixture-usb-{path.name}"
                )
                target = getattr(
                    self.fixture,
                    "networkmanager_profile"
                    if path.name.endswith("nmconnection")
                    else "usb_dhcp_wrapper",
                )
                self.rewrite_bound_root_file(target, old, new)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()

    def test_usb_management_rejects_bad_range_and_openrc_order(self) -> None:
        cases = (
            (
                "unudhcpd_config",
                b"-c 172.16.42.2",
                b"-c 172.16.42.3",
            ),
            (
                "usb_dhcp_service",
                b"after networkmanager",
                b"after NetworkManageR",
            ),
        )
        for field, old, new in cases:
            with self.subTest(field=field):
                self.fixture = create_fixture(
                    Path(self.temporary.name) / f"fixture-usb-{field}"
                )
                self.rewrite_bound_root_file(getattr(self.fixture, field), old, new)
                with self.assertRaisesRegex(GateError, "fixed lmi USB policy"):
                    self.validate()

    def test_usb_management_rejects_missing_package_and_second_dhcp_owner(self) -> None:
        cases = (
            (b"unudhcpd-openrc", b"notdhcpd-openrc", "does not contain unudhcpd-openrc"),
            (b"notdhcp", b"dnsmasq", "second DHCP owner"),
        )
        for old, new, message in cases:
            with self.subTest(new=new):
                self.fixture = create_fixture(
                    Path(self.temporary.name) / f"fixture-db-{new.decode()}"
                )
                self.rewrite_bound_root_file(self.fixture.apk_installed, old, new)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()

    def test_usb_management_rejects_bad_runlevel_and_instance_symlinks(self) -> None:
        cases = (
            (
                (
                    "unlink /etc/runlevels/default/networkmanager",
                    "symlink /etc/runlevels/default/networkmanager /etc/init.d/NetworkManageR",
                ),
                "runlevels/default/networkmanager",
            ),
            (("unlink /etc/init.d/unudhcpd.usb0",), "unudhcpd.usb0"),
            (
                (
                    "symlink /etc/runlevels/default/unudhcpd.usb0 /etc/init.d/unudhcpd.usb0",
                ),
                "second DHCP runlevel owner",
            ),
        )
        for index, (commands, message) in enumerate(cases):
            with self.subTest(commands=commands):
                self.fixture = create_fixture(
                    Path(self.temporary.name) / f"fixture-link-{index}"
                )
                self.rewrite_rootfs_with_debugfs(commands)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()

    def test_tool_pins_geometry_and_input_identity_recheck_are_fail_closed(self) -> None:
        with self.assertRaisesRegex(GateError, "e2fsck binary sha256"):
            self.validate(
                dataclasses.replace(self.expectations, e2fsck_sha256="0" * 64)
            )
        with self.assertRaisesRegex(GateError, "ownership or mode"):
            self.validate(
                dataclasses.replace(
                    self.expectations,
                    tool_uid=self.expectations.tool_uid + 1,
                )
            )
        with self.assertRaisesRegex(GateError, "userdata image is smaller"):
            self.validate(
                dataclasses.replace(
                    self.expectations,
                    minimum_userdata_bytes=self.fixture.userdata_img.stat().st_size
                    + SECTOR,
                )
            )
        with self.assertRaisesRegex(GateError, "trusted size alignment"):
            self.validate(
                dataclasses.replace(
                    self.expectations,
                    userdata_size_alignment=1024 * 1024,
                )
            )
        report = self.validate()
        self.assertFalse(report["release"]["eligible"])
        recheck_input_identities(report["inputs"], self.fixture.input_paths())
        before = self.fixture.vmlinuz.stat()
        os.utime(
            self.fixture.vmlinuz,
            ns=(before.st_atime_ns, before.st_mtime_ns + 1),
        )
        with self.assertRaisesRegex(GateError, "changed before publication"):
            recheck_input_identities(report["inputs"], self.fixture.input_paths())

    def test_fstab_uuid_type_and_options_are_exact(self) -> None:
        original = self.fixture.fstab.read_text()
        cases = (
            (original.replace("defaults", "rw", 1), "not canonical"),
            (original.replace(" ext2 ", " ext4 "), "not canonical"),
            (original.replace(ROOT_UUID, ROOT_UUID.upper()), "not canonical"),
            (original + "tmpfs /tmp tmpfs defaults 0 0\n", "exactly root and boot"),
        )
        for value, message in cases:
            with self.subTest(value=value[-30:]):
                self.fixture.fstab.write_text(value)
                with self.assertRaisesRegex(GateError, message):
                    self.validate()

    def test_os_errors_do_not_disclose_input_paths(self) -> None:
        secret_name = "private-workspace-secret-vmlinuz"
        arguments = list(self.fixture.arguments())
        arguments[2] = Path(self.temporary.name) / secret_name
        with self.assertRaises(GateError) as raised:
            validate_artifact_pair(
                *arguments,
                rootfs_bindings=self.fixture.rootfs_bindings(),
                expectations=self.expectations,
            )
        message = str(raised.exception)
        self.assertIn("errno 2", message)
        self.assertNotIn(secret_name, message)
        self.assertNotIn(self.temporary.name, message)


if __name__ == "__main__":
    unittest.main()
