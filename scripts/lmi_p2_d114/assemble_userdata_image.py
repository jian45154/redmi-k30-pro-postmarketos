#!/usr/bin/env python3
"""Offline, fail-closed D114 userdata image assembler.

The production operation is intentionally narrow: copy the reviewed D110 raw
userdata image in full, then pwrite exactly the D114 P2 root filesystem over
the recorded P2 byte range.  No loop device, mount, privilege, network, or
device operation is used.
"""

from __future__ import annotations

import argparse
import binascii
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
from typing import Any, Iterable
import uuid


SECTOR_SIZE = 4096
GPT_HEADER_SIZE = 92
GPT_ENTRY_COUNT = 128
GPT_ENTRY_SIZE = 128
GPT_TABLE_BYTES = GPT_ENTRY_COUNT * GPT_ENTRY_SIZE
GPT_TABLE_LBAS = GPT_TABLE_BYTES // SECTOR_SIZE
COPY_CHUNK = 4 * 1024 * 1024
TEST_FIXTURE_MAX_BYTES = 64 * 1024 * 1024
SPARSE_MAGIC = 0xED26FF3A
SPARSE_HEADER_SIZE = 28
SPARSE_CHUNK_HEADER_SIZE = 12
SPARSE_RAW = 0xCAC1
SPARSE_FILL = 0xCAC2
SPARSE_DONT_CARE = 0xCAC3
SPARSE_CRC32 = 0xCAC4
ESP_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
ARM64_ROOT_GUID = uuid.UUID("b921b045-1df0-41c3-af44-4c6f280d3fae")
BASELINE_SHA256 = "b108f581426c644319396fe5d5cdafd2f490151f2ac2b63bd2ef5275567d0721"
BASELINE_SIZE = 3_436_183_552
P2_SIZE = 2_923_429_888
P2_UUID = "f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f"
SPARSE_TOOL_LOCK_SHA256 = (
    "e8258f018496761191a4643bd3c516ae277c65b1a8b1ec2eedeff59cc1f386d0"
)
INJECTION_POLICY_LOCK_SHA256 = (
    "df5c69759ae0ebb5339b7712e4b404b16b8b476d03110d1f8526e987623d9bee"
)
SOURCE_LOCK_SHA256 = "0046a432b961fef3f1c5900ee9b4e26351e87d87bd058ed4824f897a2def04fb"
D110_BOOT_SHA256 = "2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487"
D110_BOOT_SIZE = 52_944_896
D110_BOOT_UUID = "d4f78f7d-f5b5-4edc-94d5-ba5e6c877888"
SPARSE_TOOL_LOCK = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "lmi-p2-d114"
    / "sparse-tools-lock.json"
)
INJECTION_POLICY_LOCK = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "lmi-p2-d114"
    / "injection-policy-lock.json"
)
SOURCE_LOCK = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "lmi-p2-d114"
    / "source-lock.json"
)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
KERNEL_RELEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$")
BACKING_IDENTITY_RE = re.compile(r"^[1-9][0-9]*:[1-9][0-9]*$")
BLOCK_IDENTITY_RE = re.compile(r"^[0-9a-f]+:[0-9a-f]+:[1-9][0-9]*$")
NAMESPACE_RE = re.compile(
    r"^(?P<kind>ipc|mnt|net|pid|uts):\[(?P<inode>[1-9][0-9]*)\]$"
)
OUTPUT_RAW_NAME = "userdata.raw"
OUTPUT_SPARSE_NAME = "userdata.android-sparse.img"
OUTPUT_ASSEMBLY_ATTESTATION_NAME = "assembly-attestation.json"
OUTPUT_INJECTION_ATTESTATION_NAME = "injection-attestation.json"
OUTPUT_BUNDLE_FILES = frozenset(
    {
        OUTPUT_RAW_NAME,
        OUTPUT_SPARSE_NAME,
        OUTPUT_ASSEMBLY_ATTESTATION_NAME,
        OUTPUT_INJECTION_ATTESTATION_NAME,
    }
)


class AssemblyError(ValueError):
    """A fail-closed D114 assembly or verification gate failed."""


@dataclass(frozen=True)
class AssemblyPolicy:
    """Exact disk contract; non-production values exist only for fixtures."""

    baseline_size: int = BASELINE_SIZE
    baseline_sha256: str = BASELINE_SHA256
    p2_size: int = P2_SIZE
    p2_uuid: str = P2_UUID
    p1_first_lba: int = 2048
    p1_last_lba: int = 124927
    p2_first_lba: int = 124928
    p2_last_lba: int = 838655
    partition_names: tuple[str, str] = ("primary", "primary")

    def __post_init__(self) -> None:
        if (
            not isinstance(self.baseline_size, int)
            or isinstance(self.baseline_size, bool)
            or self.baseline_size <= 0
            or self.baseline_size % SECTOR_SIZE
        ):
            raise AssemblyError("baseline size must be a positive 4096-byte multiple")
        if not isinstance(self.baseline_sha256, str) or not SHA256_RE.fullmatch(
            self.baseline_sha256
        ):
            raise AssemblyError("baseline sha256 is invalid")
        if (
            not isinstance(self.p2_size, int)
            or isinstance(self.p2_size, bool)
            or self.p2_size <= 0
            or self.p2_size % SECTOR_SIZE
        ):
            raise AssemblyError("P2 size must be a positive 4096-byte multiple")
        try:
            root_uuid = uuid.UUID(self.p2_uuid)
        except (AttributeError, ValueError):
            raise AssemblyError("P2 UUID is invalid") from None
        if (
            str(root_uuid) != self.p2_uuid
            or root_uuid.version != 4
            or root_uuid.variant != uuid.RFC_4122
        ):
            raise AssemblyError("P2 UUID must be a canonical RFC v4 UUID")
        lbas = self.baseline_size // SECTOR_SIZE
        numeric = (
            self.p1_first_lba,
            self.p1_last_lba,
            self.p2_first_lba,
            self.p2_last_lba,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) for value in numeric):
            raise AssemblyError("GPT partition LBAs must be integers")
        if not (
            self.first_usable_lba
            <= self.p1_first_lba
            <= self.p1_last_lba
            and self.p1_last_lba + 1 == self.p2_first_lba
            and self.p2_first_lba <= self.p2_last_lba <= self.last_usable_lba
        ):
            raise AssemblyError("GPT partition/free-space geometry is invalid")
        if (self.p2_last_lba - self.p2_first_lba + 1) * SECTOR_SIZE != self.p2_size:
            raise AssemblyError("P2 size does not match its GPT range")
        if lbas < 2 * GPT_TABLE_LBAS + 3:
            raise AssemblyError("disk is too small for dual GPT")
        if (
            not isinstance(self.partition_names, tuple)
            or len(self.partition_names) != 2
            or any(name != "primary" for name in self.partition_names)
        ):
            raise AssemblyError("GPT partition names must be the reviewed pair")

    @property
    def disk_lbas(self) -> int:
        return self.baseline_size // SECTOR_SIZE

    @property
    def first_usable_lba(self) -> int:
        return 2 + GPT_TABLE_LBAS

    @property
    def last_usable_lba(self) -> int:
        return self.disk_lbas - GPT_TABLE_LBAS - 2

    @property
    def p2_offset(self) -> int:
        return self.p2_first_lba * SECTOR_SIZE

    @property
    def p2_end(self) -> int:
        return (self.p2_last_lba + 1) * SECTOR_SIZE

    @property
    def suffix_size(self) -> int:
        return self.baseline_size - self.p2_end


PRODUCTION_POLICY = AssemblyPolicy()
assert PRODUCTION_POLICY.p2_offset == 511_705_088
assert PRODUCTION_POLICY.p2_end == 3_435_134_976
assert PRODUCTION_POLICY.suffix_size == 1_048_576


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _pread_exact(fd: int, size: int, offset: int, label: str) -> bytes:
    if size < 0 or offset < 0:
        raise AssemblyError(f"invalid read range for {label}")
    result = bytearray()
    while len(result) < size:
        try:
            block = os.pread(fd, size - len(result), offset + len(result))
        except OSError as error:
            raise AssemblyError(f"could not read {label}: {error}") from None
        if not block:
            raise AssemblyError(f"short read while reading {label}")
        result.extend(block)
    return bytes(result)


def _pwrite_all(fd: int, payload: bytes, offset: int, label: str) -> None:
    cursor = 0
    while cursor < len(payload):
        try:
            written = os.pwrite(fd, payload[cursor:], offset + cursor)
        except OSError as error:
            raise AssemblyError(f"could not write {label}: {error}") from None
        if written <= 0:
            raise AssemblyError(f"short write while writing {label}")
        cursor += written


def _write_all(fd: int, payload: bytes, label: str) -> None:
    cursor = 0
    while cursor < len(payload):
        try:
            written = os.write(fd, payload[cursor:])
        except OSError as error:
            raise AssemblyError(f"could not write {label}: {error}") from None
        if written <= 0:
            raise AssemblyError(f"short write while writing {label}")
        cursor += written


def _sha256_fd(fd: int, size: int, label: str) -> str:
    digest = hashlib.sha256()
    offset = 0
    while offset < size:
        amount = min(COPY_CHUNK, size - offset)
        digest.update(_pread_exact(fd, amount, offset, label))
        offset += amount
    return digest.hexdigest()


class StableFile:
    """One regular, non-symlink inode held and rechecked for the whole use."""

    def __init__(self, path: Path, label: str, *, expected_size: int | None = None):
        self.path = Path(path)
        self.label = label
        self.expected_size = expected_size
        self.fd = -1
        self.before: os.stat_result | None = None
        self.path_before: os.stat_result | None = None
        self._digest: str | None = None

    def __enter__(self) -> "StableFile":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        try:
            path_before = self.path.lstat()
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise AssemblyError(f"could not securely open {self.label}: {error}") from None
        if (
            not stat.S_ISREG(path_before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or _identity(path_before) != _identity(opened)
        ):
            os.close(descriptor)
            raise AssemblyError(f"{self.label} must be one stable regular non-symlink inode")
        if self.expected_size is not None and opened.st_size != self.expected_size:
            os.close(descriptor)
            raise AssemblyError(
                f"{self.label} size mismatch: {opened.st_size} != {self.expected_size}"
            )
        self.fd = descriptor
        self.before = opened
        self.path_before = path_before
        return self

    @property
    def size(self) -> int:
        assert self.before is not None
        return self.before.st_size

    def pread(self, size: int, offset: int, label: str | None = None) -> bytes:
        if offset > self.size or size > self.size - offset:
            raise AssemblyError(f"{label or self.label} range is outside the file")
        return _pread_exact(self.fd, size, offset, label or self.label)

    def digest(self) -> str:
        if self._digest is None:
            self._digest = _sha256_fd(self.fd, self.size, self.label)
        return self._digest

    def verify_unchanged(self) -> None:
        assert self.before is not None and self.path_before is not None
        try:
            opened = os.fstat(self.fd)
            current = self.path.lstat()
        except OSError as error:
            raise AssemblyError(f"could not restat {self.label}: {error}") from None
        if (
            _identity(opened) != _identity(self.before)
            or _identity(current) != _identity(self.path_before)
            or _identity(current) != _identity(opened)
        ):
            raise AssemblyError(f"{self.label} changed while it was in use")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc is None:
                self.verify_unchanged()
        finally:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1


class StableDirectory:
    """One canonical directory inode held and rechecked for the whole use."""

    def __init__(self, path: Path, label: str):
        self.path = Path(path)
        self.label = label
        self.fd = -1
        self.before: os.stat_result | None = None
        self.path_before: os.stat_result | None = None

    def __enter__(self) -> "StableDirectory":
        flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = -1
        try:
            if self.path.resolve(strict=True) != self.path:
                raise AssemblyError(f"{self.label} path must be absolute and canonical")
            path_before = self.path.lstat()
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
        except AssemblyError:
            if descriptor >= 0:
                os.close(descriptor)
            raise
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise AssemblyError(f"could not securely open {self.label}: {error}") from None
        if (
            not stat.S_ISDIR(path_before.st_mode)
            or not stat.S_ISDIR(opened.st_mode)
            or _identity(path_before) != _identity(opened)
        ):
            os.close(descriptor)
            raise AssemblyError(f"{self.label} must be one stable real directory inode")
        self.fd = descriptor
        self.before = opened
        self.path_before = path_before
        return self

    def verify_unchanged(self) -> None:
        assert self.before is not None and self.path_before is not None
        try:
            opened = os.fstat(self.fd)
            current = self.path.lstat()
        except OSError as error:
            raise AssemblyError(f"could not restat {self.label}: {error}") from None
        if (
            _identity(opened) != _identity(self.before)
            or _identity(current) != _identity(self.path_before)
            or _identity(current) != _identity(opened)
        ):
            raise AssemblyError(f"{self.label} changed while it was in use")

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        try:
            if exc is None:
                self.verify_unchanged()
        finally:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1


@dataclass(frozen=True)
class GptHeader:
    current_lba: int
    backup_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: uuid.UUID
    entries_lba: int
    entries_crc32: int


@dataclass(frozen=True)
class Partition:
    type_guid: uuid.UUID
    unique_guid: uuid.UUID
    first_lba: int
    last_lba: int
    attributes: int
    name: str


@dataclass(frozen=True)
class GptLayout:
    disk_guid: uuid.UUID
    partitions: tuple[Partition, Partition]
    table_sha256: str
    first_usable_lba: int
    last_usable_lba: int

    def evidence(self, policy: AssemblyPolicy) -> dict[str, Any]:
        return {
            "disk_guid": str(self.disk_guid),
            "entry_count": GPT_ENTRY_COUNT,
            "entry_size": GPT_ENTRY_SIZE,
            "first_usable_lba": self.first_usable_lba,
            "last_usable_lba": self.last_usable_lba,
            "leading_usable_gap_lbas": policy.p1_first_lba - self.first_usable_lba,
            "partition_guids": [str(item.unique_guid) for item in self.partitions],
            "partitions": [
                {
                    "first_lba": item.first_lba,
                    "last_lba": item.last_lba,
                    "name": item.name,
                    "type_guid": str(item.type_guid),
                }
                for item in self.partitions
            ],
            "table_sha256": self.table_sha256,
            "tail_usable_gap_lbas": self.last_usable_lba - policy.p2_last_lba,
        }


def _validate_pmbr(reader: StableFile, policy: AssemblyPolicy) -> None:
    lba = reader.pread(SECTOR_SIZE, 0, "protective MBR LBA")
    mbr = lba[:512]
    if any(lba[512:]):
        raise AssemblyError("protective MBR 4096-byte LBA padding is not zero")
    if any(mbr[:446]) or mbr[510:512] != b"\x55\xaa":
        raise AssemblyError("protective MBR bootstrap/signature is invalid")
    entries = [mbr[446 + index * 16 : 462 + index * 16] for index in range(4)]
    if any(any(entries[index]) for index in range(1, 4)):
        raise AssemblyError("protective MBR has unexpected partition entries")
    entry = entries[0]
    expected_sectors = min(policy.disk_lbas - 1, 0xFFFFFFFF)
    start_lba, sectors = struct.unpack_from("<II", entry, 8)
    if (
        entry[0] != 0
        or entry[1:4] != b"\x00\x02\x00"
        or entry[4] != 0xEE
        or entry[5:8] != b"\xff\xff\xff"
        or start_lba != 1
        or sectors != expected_sectors
    ):
        raise AssemblyError("protective MBR entry is not canonical")


def _parse_gpt_header(
    block: bytes, expected_lba: int, expected_backup: int, entries_lba: int,
    policy: AssemblyPolicy, label: str
) -> GptHeader:
    if len(block) != SECTOR_SIZE or block[:8] != b"EFI PART":
        raise AssemblyError(f"{label} GPT header magic mismatch")
    revision, header_size, stored_crc, reserved = struct.unpack_from("<IIII", block, 8)
    if revision != 0x00010000 or header_size != GPT_HEADER_SIZE or reserved != 0:
        raise AssemblyError(f"{label} GPT header fields are non-canonical")
    if any(block[GPT_HEADER_SIZE:]):
        raise AssemblyError(f"{label} GPT header padding is not zero")
    checked = bytearray(block[:GPT_HEADER_SIZE])
    checked[16:20] = b"\0" * 4
    if binascii.crc32(checked) & 0xFFFFFFFF != stored_crc:
        raise AssemblyError(f"{label} GPT header CRC mismatch")
    current, backup, first, last = struct.unpack_from("<QQQQ", block, 24)
    if current != expected_lba or backup != expected_backup:
        raise AssemblyError(f"{label} GPT current/backup pointers are invalid")
    disk_guid = uuid.UUID(bytes_le=block[56:72])
    table_lba = struct.unpack_from("<Q", block, 72)[0]
    entry_count, entry_size, table_crc = struct.unpack_from("<III", block, 80)
    if (
        disk_guid.int == 0
        or disk_guid.version != 4
        or disk_guid.variant != uuid.RFC_4122
    ):
        raise AssemblyError(f"{label} GPT disk GUID is not RFC v4")
    if (
        first != policy.first_usable_lba
        or last != policy.last_usable_lba
        or table_lba != entries_lba
        or entry_count != GPT_ENTRY_COUNT
        or entry_size != GPT_ENTRY_SIZE
    ):
        raise AssemblyError(f"{label} GPT geometry is not the exact reviewed geometry")
    return GptHeader(current, backup, first, last, disk_guid, table_lba, table_crc)


def _read_gpt_table(reader: StableFile, header: GptHeader, label: str) -> bytes:
    table = reader.pread(
        GPT_TABLE_BYTES, header.entries_lba * SECTOR_SIZE, f"{label} GPT table"
    )
    if binascii.crc32(table) & 0xFFFFFFFF != header.entries_crc32:
        raise AssemblyError(f"{label} GPT table CRC mismatch")
    return table


def _decode_partition(entry: bytes, index: int) -> Partition:
    type_guid = uuid.UUID(bytes_le=entry[:16])
    unique_guid = uuid.UUID(bytes_le=entry[16:32])
    first, last, attributes = struct.unpack_from("<QQQ", entry, 32)
    raw_name = entry[56:128]
    try:
        name = raw_name.decode("utf-16-le").split("\0", 1)[0]
    except UnicodeError:
        raise AssemblyError(f"GPT partition {index} name is not UTF-16LE") from None
    encoded = name.encode("utf-16-le") + b"\0\0"
    if raw_name[: len(encoded)] != encoded or any(raw_name[len(encoded) :]):
        raise AssemblyError(f"GPT partition {index} name is not canonically terminated")
    if (
        unique_guid.int == 0
        or unique_guid.version != 4
        or unique_guid.variant != uuid.RFC_4122
        or first > last
    ):
        raise AssemblyError(f"GPT partition {index} identity/range is invalid")
    return Partition(type_guid, unique_guid, first, last, attributes, name)


def validate_gpt(reader: StableFile, policy: AssemblyPolicy) -> GptLayout:
    """Strictly validate PMBR plus both complete 4096-byte GPT copies."""

    if reader.size != policy.baseline_size:
        raise AssemblyError("GPT image size does not match the assembly policy")
    _validate_pmbr(reader, policy)
    backup_lba = policy.disk_lbas - 1
    primary = _parse_gpt_header(
        reader.pread(SECTOR_SIZE, SECTOR_SIZE, "primary GPT header"),
        1,
        backup_lba,
        2,
        policy,
        "primary",
    )
    backup = _parse_gpt_header(
        reader.pread(SECTOR_SIZE, backup_lba * SECTOR_SIZE, "backup GPT header"),
        backup_lba,
        1,
        backup_lba - GPT_TABLE_LBAS,
        policy,
        "backup",
    )
    if primary.disk_guid != backup.disk_guid:
        raise AssemblyError("primary/backup GPT disk GUIDs disagree")
    primary_table = _read_gpt_table(reader, primary, "primary")
    backup_table = _read_gpt_table(reader, backup, "backup")
    if primary_table != backup_table:
        raise AssemblyError("primary/backup GPT tables differ")
    entries = [
        primary_table[index * GPT_ENTRY_SIZE : (index + 1) * GPT_ENTRY_SIZE]
        for index in range(GPT_ENTRY_COUNT)
    ]
    if uuid.UUID(bytes_le=entries[0][:16]).int == 0 or uuid.UUID(
        bytes_le=entries[1][:16]
    ).int == 0:
        raise AssemblyError("GPT P1/P2 entries are missing")
    if any(any(entry) for entry in entries[2:]):
        raise AssemblyError("unused GPT entries are not zero")
    p1, p2 = _decode_partition(entries[0], 1), _decode_partition(entries[1], 2)
    expected = (
        (
            ESP_GUID,
            policy.p1_first_lba,
            policy.p1_last_lba,
            policy.partition_names[0],
        ),
        (
            ARM64_ROOT_GUID,
            policy.p2_first_lba,
            policy.p2_last_lba,
            policy.partition_names[1],
        ),
    )
    for index, (partition, wanted) in enumerate(zip((p1, p2), expected), 1):
        type_guid, first, last, name = wanted
        if (
            partition.type_guid != type_guid
            or partition.first_lba != first
            or partition.last_lba != last
            or partition.attributes != 0
            or partition.name != name
        ):
            raise AssemblyError(f"GPT P{index} contract mismatch")
    if len({primary.disk_guid, p1.unique_guid, p2.unique_guid}) != 3:
        raise AssemblyError("GPT disk and partition GUIDs are not distinct")
    return GptLayout(
        primary.disk_guid,
        (p1, p2),
        hashlib.sha256(primary_table).hexdigest(),
        primary.first_usable_lba,
        primary.last_usable_lba,
    )


def _validate_p2(reader: StableFile, policy: AssemblyPolicy) -> dict[str, Any]:
    if reader.size != policy.p2_size:
        raise AssemblyError("P2 input size mismatch")
    superblock = reader.pread(1024, 1024, "P2 ext superblock")
    if struct.unpack_from("<H", superblock, 0x38)[0] != 0xEF53:
        raise AssemblyError("P2 ext superblock magic mismatch")
    log_block_size = struct.unpack_from("<I", superblock, 0x18)[0]
    if log_block_size > 6 or (1024 << log_block_size) != SECTOR_SIZE:
        raise AssemblyError("P2 ext block size is not 4096")
    incompat = struct.unpack_from("<I", superblock, 0x60)[0]
    blocks = struct.unpack_from("<I", superblock, 0x04)[0]
    if incompat & 0x80:
        blocks |= struct.unpack_from("<I", superblock, 0x150)[0] << 32
    if blocks * SECTOR_SIZE != policy.p2_size:
        raise AssemblyError("P2 ext block count does not fill the GPT partition")
    filesystem_uuid = uuid.UUID(bytes=superblock[0x68:0x78])
    if str(filesystem_uuid) != policy.p2_uuid:
        raise AssemblyError("P2 filesystem UUID mismatch")
    return {
        "block_count": blocks,
        "block_size": SECTOR_SIZE,
        "size": reader.size,
        "uuid": str(filesystem_uuid),
    }


def _compare_ranges(
    left: StableFile,
    left_offset: int,
    right: StableFile,
    right_offset: int,
    size: int,
    label: str,
) -> None:
    cursor = 0
    while cursor < size:
        amount = min(COPY_CHUNK, size - cursor)
        if left.pread(amount, left_offset + cursor, label) != right.pread(
            amount, right_offset + cursor, label
        ):
            raise AssemblyError(f"{label} is not byte-identical")
        cursor += amount


def _same_gpt_identity(baseline: GptLayout, output: GptLayout) -> bool:
    return (
        baseline.disk_guid == output.disk_guid
        and baseline.partitions == output.partitions
        and baseline.table_sha256 == output.table_sha256
    )


def _verify_composition_readers(
    baseline: StableFile,
    p2: StableFile,
    output: StableFile,
    policy: AssemblyPolicy,
    *,
    require_baseline_hash: bool = True,
) -> dict[str, Any]:
    baseline_hash = baseline.digest()
    if require_baseline_hash and baseline_hash != policy.baseline_sha256:
        raise AssemblyError("baseline raw SHA256 mismatch")
    baseline_gpt = validate_gpt(baseline, policy)
    output_gpt = validate_gpt(output, policy)
    if not _same_gpt_identity(baseline_gpt, output_gpt):
        raise AssemblyError("output GPT does not preserve baseline GUIDs and entries")
    p2_fs = _validate_p2(p2, policy)
    _compare_ranges(baseline, 0, output, 0, policy.p2_offset, "prefix drift")
    _compare_ranges(p2, 0, output, policy.p2_offset, policy.p2_size, "P2 drift")
    _compare_ranges(
        baseline,
        policy.p2_end,
        output,
        policy.p2_end,
        policy.suffix_size,
        "tail/suffix drift",
    )
    return {
        "baseline_gpt": baseline_gpt.evidence(policy),
        "byte_identity": {
            "p2_bytes": policy.p2_size,
            "prefix_bytes": policy.p2_offset,
            "suffix_bytes": policy.suffix_size,
        },
        "gpt_guid_preservation": True,
        "output_gpt": output_gpt.evidence(policy),
        "p2_filesystem": p2_fs,
        "raw_sha256": output.digest(),
        "raw_size": output.size,
    }


def verify_composition(
    baseline_path: Path,
    p2_path: Path,
    output_path: Path,
    policy: AssemblyPolicy = PRODUCTION_POLICY,
) -> dict[str, Any]:
    """Public offline verifier used by focused tests and later review gates."""

    with StableFile(baseline_path, "baseline raw", expected_size=policy.baseline_size) as baseline:
        with StableFile(p2_path, "P2 input", expected_size=policy.p2_size) as p2:
            with StableFile(output_path, "assembled raw", expected_size=policy.baseline_size) as output:
                return _verify_composition_readers(baseline, p2, output, policy)


def _update_repeated(
    digest: Any, crc: int, pattern: bytes, total: int
) -> int:
    if not pattern or total % len(pattern):
        raise AssemblyError("internal sparse repeat geometry is invalid")
    unit_size = min(COPY_CHUNK, total)
    unit_size -= unit_size % len(pattern)
    unit = pattern * (unit_size // len(pattern)) if unit_size else b""
    remaining = total
    while remaining:
        block = unit if remaining >= len(unit) else pattern * (remaining // len(pattern))
        digest.update(block)
        crc = binascii.crc32(block, crc)
        remaining -= len(block)
    return crc


def _parse_sparse_reader(
    reader: StableFile, expected_raw_size: int, expected_raw_sha256: str
) -> dict[str, Any]:
    if reader.size < SPARSE_HEADER_SIZE:
        raise AssemblyError("sparse image is shorter than its header")
    header = reader.pread(SPARSE_HEADER_SIZE, 0, "sparse header")
    (
        magic,
        major,
        minor,
        file_header_size,
        chunk_header_size,
        block_size,
        total_blocks,
        total_chunks,
        image_checksum,
    ) = struct.unpack("<IHHHHIIII", header)
    if magic != SPARSE_MAGIC or major != 1 or minor != 0:
        raise AssemblyError("sparse v1 header magic/version mismatch")
    if file_header_size != SPARSE_HEADER_SIZE or chunk_header_size != SPARSE_CHUNK_HEADER_SIZE:
        raise AssemblyError("sparse header sizes are not canonical")
    if block_size != SECTOR_SIZE:
        raise AssemblyError("sparse block size is not 4096")
    if total_blocks <= 0 or total_blocks * block_size != expected_raw_size:
        raise AssemblyError("sparse output size/blocksum mismatch")
    if total_chunks <= 0 or total_chunks > total_blocks * 2 + 1:
        raise AssemblyError("sparse chunk count is invalid")
    offset = SPARSE_HEADER_SIZE
    emitted_blocks = 0
    decoded_hash = hashlib.sha256()
    decoded_crc = 0
    counts = {"crc32": 0, "dont_care": 0, "fill": 0, "raw": 0}
    for index in range(total_chunks):
        if offset > reader.size or SPARSE_CHUNK_HEADER_SIZE > reader.size - offset:
            raise AssemblyError(f"sparse chunk {index + 1} header crosses EOF")
        chunk_header = reader.pread(
            SPARSE_CHUNK_HEADER_SIZE, offset, f"sparse chunk {index + 1} header"
        )
        chunk_type, reserved, chunk_blocks, total_size = struct.unpack(
            "<HHII", chunk_header
        )
        if reserved != 0 or total_size < SPARSE_CHUNK_HEADER_SIZE:
            raise AssemblyError(f"sparse chunk {index + 1} header is malformed")
        data_offset = offset + SPARSE_CHUNK_HEADER_SIZE
        payload_size = total_size - SPARSE_CHUNK_HEADER_SIZE
        if total_size > reader.size - offset:
            raise AssemblyError(f"sparse chunk {index + 1} crosses EOF")
        if chunk_type != SPARSE_CRC32 and chunk_blocks <= 0:
            raise AssemblyError(f"sparse chunk {index + 1} has zero output blocks")
        if chunk_type != SPARSE_CRC32 and chunk_blocks > total_blocks - emitted_blocks:
            raise AssemblyError("sparse chunk blocksum exceeds the header total")
        logical_bytes = chunk_blocks * block_size
        if chunk_type == SPARSE_RAW:
            if payload_size != logical_bytes:
                raise AssemblyError("sparse RAW chunk size mismatch")
            counts["raw"] += 1
            cursor = 0
            while cursor < payload_size:
                amount = min(COPY_CHUNK, payload_size - cursor)
                block = reader.pread(amount, data_offset + cursor, "sparse RAW payload")
                decoded_hash.update(block)
                decoded_crc = binascii.crc32(block, decoded_crc)
                cursor += amount
            emitted_blocks += chunk_blocks
        elif chunk_type == SPARSE_FILL:
            if payload_size != 4:
                raise AssemblyError("sparse FILL chunk size mismatch")
            counts["fill"] += 1
            pattern = reader.pread(4, data_offset, "sparse FILL payload")
            decoded_crc = _update_repeated(decoded_hash, decoded_crc, pattern, logical_bytes)
            emitted_blocks += chunk_blocks
        elif chunk_type == SPARSE_DONT_CARE:
            if payload_size != 0:
                raise AssemblyError("sparse DONT_CARE chunk has a payload")
            counts["dont_care"] += 1
            decoded_crc = _update_repeated(decoded_hash, decoded_crc, b"\0" * 4, logical_bytes)
            emitted_blocks += chunk_blocks
        elif chunk_type == SPARSE_CRC32:
            if chunk_blocks != 0 or payload_size != 4:
                raise AssemblyError("sparse CRC32 chunk geometry is invalid")
            counts["crc32"] += 1
            recorded_crc = struct.unpack(
                "<I", reader.pread(4, data_offset, "sparse CRC32 payload")
            )[0]
            if recorded_crc != decoded_crc & 0xFFFFFFFF:
                raise AssemblyError("sparse CRC32 chunk does not match decoded blocks")
        else:
            raise AssemblyError(f"unsupported sparse chunk type: 0x{chunk_type:04x}")
        offset += total_size
    if emitted_blocks != total_blocks:
        raise AssemblyError("sparse chunk output blocksum mismatch")
    if offset != reader.size:
        raise AssemblyError("sparse image has trailing bytes after its final chunk")
    decoded_crc &= 0xFFFFFFFF
    if image_checksum and image_checksum != decoded_crc:
        raise AssemblyError("sparse header image checksum mismatch")
    decoded_sha256 = decoded_hash.hexdigest()
    if decoded_sha256 != expected_raw_sha256:
        raise AssemblyError("statically decoded sparse SHA256 differs from raw")
    return {
        "block_size": block_size,
        "chunk_counts": counts,
        "decoded_crc32": f"{decoded_crc:08x}",
        "decoded_sha256": decoded_sha256,
        "file_sha256": reader.digest(),
        "file_size": reader.size,
        "header_image_checksum": f"{image_checksum:08x}",
        "output_blocks": emitted_blocks,
        "version": "1.0",
    }


def parse_sparse_image(
    path: Path, expected_raw_size: int, expected_raw_sha256: str
) -> dict[str, Any]:
    """Strict static Android sparse-v1 parser; it never expands to a mount."""

    if not SHA256_RE.fullmatch(expected_raw_sha256):
        raise AssemblyError("expected raw SHA256 is invalid")
    with StableFile(path, "sparse image") as reader:
        return _parse_sparse_reader(reader, expected_raw_size, expected_raw_sha256)


def _duplicate_object_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AssemblyError(f"duplicate JSON object field: {key}")
        value[key] = item
    return value


@dataclass(frozen=True)
class SparseToolLock:
    value: dict[str, Any]
    sha256: str


def load_sparse_tool_lock(path: Path = SPARSE_TOOL_LOCK) -> SparseToolLock:
    with StableFile(path, "sparse tool lock") as reader:
        payload = reader.pread(reader.size, 0)
        digest = reader.digest()
    if digest != SPARSE_TOOL_LOCK_SHA256:
        raise AssemblyError("sparse tool lock SHA256 mismatch")
    try:
        value = json.loads(
            payload.decode("ascii"), object_pairs_hook=_duplicate_object_fields
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssemblyError(f"invalid sparse tool lock JSON: {error}") from None
    if not isinstance(value, dict) or set(value) != {
        "interpreter",
        "libraries",
        "package",
        "schema",
        "tools",
    }:
        raise AssemblyError("sparse tool lock top-level fields mismatch")
    if value["schema"] != "lmi-p2-d114-sparse-tools-lock/v1" or value["package"] != {
        "name": "android-sdk-libsparse-utils",
        "version": "1:34.0.5-12build1",
    }:
        raise AssemblyError("sparse tool lock package/schema mismatch")
    if not isinstance(value["tools"], dict) or set(value["tools"]) != {
        "img2simg",
        "simg2img",
    }:
        raise AssemblyError("sparse tool lock tool set mismatch")
    return SparseToolLock(value, digest)


def _decode_json_object(payload: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            payload.decode("utf-8"), object_pairs_hook=_duplicate_object_fields
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssemblyError(f"invalid {label} JSON: {error}") from None
    if not isinstance(value, dict):
        raise AssemblyError(f"{label} must contain one JSON object")
    return value


def _load_json_input(path: Path, label: str) -> tuple[dict[str, Any], str]:
    with StableFile(path, label) as reader:
        payload = reader.pread(reader.size, 0)
        digest = reader.digest()
    return _decode_json_object(payload, label), digest


def _load_source_contract(path: Path) -> dict[str, Any]:
    value, digest = _load_json_input(path, "D114 source lock")
    if digest != SOURCE_LOCK_SHA256:
        raise AssemblyError("D114 source lock SHA256 mismatch")
    baseline = value.get("baseline")
    if (
        value.get("schema") != "lmi-p2-d114-terminal-source-lock/v1"
        or not isinstance(baseline, dict)
        or baseline.get("userdata_raw_sha256") != BASELINE_SHA256
        or baseline.get("userdata_raw_size") != BASELINE_SIZE
        or baseline.get("boot_sha256") != D110_BOOT_SHA256
        or baseline.get("boot_size") != D110_BOOT_SIZE
        or baseline.get("boot_uuid") != D110_BOOT_UUID
    ):
        raise AssemblyError("D114 source lock baseline/boot contract mismatch")
    return {
        "baseline_userdata_sha256": BASELINE_SHA256,
        "baseline_userdata_size": BASELINE_SIZE,
        "schema": value["schema"],
        "sha256": digest,
    }


@dataclass(frozen=True)
class InjectionPolicyLock:
    value: dict[str, Any]
    sha256: str


@dataclass(frozen=True)
class InjectionAttestation:
    value: dict[str, Any]
    payload: bytes
    sha256: str


_INJECTION_INPUT_FIELDS = {
    "apks",
    "base_sha256",
    "candidate_rebuild_lock_schema",
    "candidate_rebuild_lock_sha256",
    "candidate_sha256",
    "candidate_size",
    "candidate_uuid",
    "keys",
    "raw_sha256",
    "repair_epoch",
    "repair_log_sha256",
    "sparse_sha256",
    "verify_log_sha256",
}
_INJECTION_OUTPUT_FIXED_FIELDS = {
    "mode",
    "packages",
    "path",
    "size",
    "triggers_sha256",
    "uuid",
    "world_sha256",
}
_INJECTION_OUTPUT_CALLER_FIELDS = {"owner"}
_INJECTION_OUTPUT_SHA256_FIELDS = {
    "filesystem_delta_sha256",
    "geometry_sha256",
    "installed_db_sha256",
    "key_inventory_sha256",
    "p2_package_record_sha256",
    "scripts_db_sha256",
    "sha256",
    "sixrow_package_record_sha256",
}
_INJECTION_TOOL_FIELDS = {
    "apk_static_sha256",
    "bash_sha256",
    "bubblewrap_sha256",
    "debugfs_sha256",
    "dumpe2fs_sha256",
    "e2fsck_sha256",
    "e2image_sha256",
    "getfattr_sha256",
    "host_libc_sha256",
    "host_loader_sha256",
    "lsattr_libe2p_sha256",
    "lsattr_libcom_err_sha256",
    "lsattr_sha256",
    "proot_libtalloc_sha256",
    "proot_sha256",
    "qemu_aarch64_sha256",
    "simg2img_sha256",
}
_NAMESPACE_FIELDS = ("ipc", "mnt", "net", "pid", "uts")


def _valid_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and SHA256_RE.fullmatch(value) is not None
        and value != "0" * 64
    )


def load_injection_policy_lock(
    path: Path = INJECTION_POLICY_LOCK,
    *,
    expected_sha256: str = INJECTION_POLICY_LOCK_SHA256,
) -> InjectionPolicyLock:
    """Load the independently reviewed, assembler-SHA-pinned injector policy."""

    if not _valid_sha256(expected_sha256):
        raise AssemblyError("injection policy lock expected SHA256 is not frozen")
    value, digest = _load_json_input(path, "injection policy lock")
    if digest != expected_sha256:
        raise AssemblyError("injection policy lock SHA256 mismatch")
    if set(value) != {
        "attestation_schema",
        "claims",
        "commands",
        "input",
        "normalization",
        "output",
        "runtime",
        "sanitization",
        "schema",
        "tools",
    }:
        raise AssemblyError("injection policy lock top-level fields mismatch")
    if (
        value["schema"] != "lmi-p2-d114-injection-policy-lock/v2"
        or value["attestation_schema"]
        != "lmi-p2-d114-rootfs-injection-attestation/v3"
    ):
        raise AssemblyError("injection policy lock schema mismatch")
    commands = value["commands"]
    if (
        not isinstance(commands, dict)
        or set(commands) != {"apk", "lifecycle"}
        or any(
            not isinstance(command, list)
            or not command
            or any(not isinstance(item, str) or not item for item in command)
            for command in commands.values()
        )
    ):
        raise AssemblyError("injection policy command arrays are malformed")
    fixed_input = value["input"]
    if not isinstance(fixed_input, dict) or set(fixed_input) != _INJECTION_INPUT_FIELDS:
        raise AssemblyError("injection policy input fields mismatch")
    if value["claims"] != {
        "hardware_test_only": True,
        "production": False,
        "release_eligible": False,
    }:
        raise AssemblyError("injection policy claims mismatch")
    if value["sanitization"] != {
        "apk_cache": "exact-four-index-members-removed",
        "apk_log": "empty",
        "authorized_keys": "absent-in-base",
        "machine_id": "baked-fixed-hardware-test",
        "resolv_conf": "empty",
        "shadow_backup": "exact-copy-of-locked-active-shadow",
        "ssh_password_authentication": "disabled-by-locked-drop-in",
    }:
        raise AssemblyError("injection policy sanitization mismatch")
    normalization = value["normalization"]
    if (
        not isinstance(normalization, dict)
        or set(normalization) != {"fixed", "positive_integer_fields", "sha256_fields"}
        or normalization["positive_integer_fields"] != ["sparse_st_blocks"]
        or normalization["sha256_fields"]
        != ["pre_normalization_sha256", "proof_sha256", "tree_identity_sha256"]
        or normalization["fixed"]
        != {
            "allocated_only_command": ["e2image", "-r", "-a", "-p"],
            "all_free_blocks_zero": True,
            "inactive_journal": {
                "block_count": 16383,
                "first_block": 327681,
                "sha256": "40b4947fd669bcb849e47705c797e2484a4d406a596017fa889987d2614008b3",
            },
            "journal_extent": {"block_count": 16384, "first_block": 327680},
            "proof": "second-e2image-byte-identical",
            "reviewed_freed_blocks": [],
        }
    ):
        raise AssemblyError("injection policy normalization mismatch")
    fixed_output = value["output"]
    if (
        not isinstance(fixed_output, dict)
        or set(fixed_output)
        != {"caller_primary_group_fields", "fixed", "sha256_fields"}
        or not isinstance(fixed_output["fixed"], dict)
        or set(fixed_output["fixed"]) != _INJECTION_OUTPUT_FIXED_FIELDS
        or fixed_output["caller_primary_group_fields"] != ["owner"]
        or not isinstance(fixed_output["sha256_fields"], list)
        or set(fixed_output["sha256_fields"]) != _INJECTION_OUTPUT_SHA256_FIELDS
        or len(fixed_output["sha256_fields"]) != len(_INJECTION_OUTPUT_SHA256_FIELDS)
    ):
        raise AssemblyError("injection policy output fields mismatch")
    runtime = value["runtime"]
    if (
        not isinstance(runtime, dict)
        or set(runtime)
        != {
            "fixed",
            "mount_required_options",
            "namespace_fields",
            "sealed_injector_script_sha256",
        }
        or not isinstance(runtime["fixed"], dict)
        or set(runtime["fixed"])
        != {
            "injector_runtime_lock_schema",
            "injector_runtime_lock_sha256",
            "sandbox_entry_sha256",
        }
        or runtime["namespace_fields"] != list(_NAMESPACE_FIELDS)
        or runtime["mount_required_options"] != ["rw", "nosuid", "nodev"]
        or not _valid_sha256(runtime["sealed_injector_script_sha256"])
    ):
        raise AssemblyError("injection policy runtime fields mismatch")
    tools = value["tools"]
    if (
        not isinstance(tools, dict)
        or set(tools) != _INJECTION_TOOL_FIELDS
        or any(not _valid_sha256(item) for item in tools.values())
    ):
        raise AssemblyError("injection policy tool fields mismatch")
    apks = fixed_input["apks"]
    if not isinstance(apks, dict) or set(apks) != {"p2", "sixrow"}:
        raise AssemblyError("injection policy nested APK inputs are malformed")
    for name, sandbox_path in (("p2", "/tools/p2.apk"), ("sixrow", "/tools/sixrow.apk")):
        apk = apks[name]
        if (
            not isinstance(apk, dict)
            or set(apk)
            != {"build_attestation_sha256", "sandbox_path", "sha256", "source_path"}
            or apk["sandbox_path"] != sandbox_path
            or not _valid_sha256(apk["build_attestation_sha256"])
            or not _valid_sha256(apk["sha256"])
            or not isinstance(apk["source_path"], str)
            or not apk["source_path"].startswith("private/")
        ):
            raise AssemblyError(f"injection policy nested {name} APK input is malformed")
    keys = fixed_input["keys"]
    if (
        not isinstance(keys, dict)
        or set(keys) != {"p2_sha256", "sixrow_sha256"}
        or any(not _valid_sha256(item) for item in keys.values())
    ):
        raise AssemblyError("injection policy nested key inputs are malformed")
    for key, item in fixed_input.items():
        if key not in {"apks", "keys"} and key.endswith("_sha256") and not _valid_sha256(item):
            raise AssemblyError(f"injection policy input SHA256 is invalid: {key}")
    for key in ("triggers_sha256", "world_sha256"):
        if not _valid_sha256(fixed_output["fixed"][key]):
            raise AssemblyError(f"injection policy output SHA256 is invalid: {key}")
    for key in ("injector_runtime_lock_sha256", "sandbox_entry_sha256"):
        if not _valid_sha256(runtime["fixed"][key]):
            raise AssemblyError(f"injection policy runtime SHA256 is invalid: {key}")
    return InjectionPolicyLock(value, digest)


def _validate_mount_runtime(value: object, required: list[str]) -> None:
    if not isinstance(value, dict) or set(value) != {
        "backing_identity",
        "block_identity",
        "mount_options",
    }:
        raise AssemblyError("P2 injection mount runtime fields mismatch")
    if (
        not isinstance(value["backing_identity"], str)
        or BACKING_IDENTITY_RE.fullmatch(value["backing_identity"]) is None
        or not isinstance(value["block_identity"], str)
        or BLOCK_IDENTITY_RE.fullmatch(value["block_identity"]) is None
        or not isinstance(value["mount_options"], str)
        or not value["mount_options"].startswith("ext4 ")
    ):
        raise AssemblyError("P2 injection mount runtime identity is invalid")
    option_text = value["mount_options"][len("ext4 ") :]
    options = option_text.split(",")
    if (
        not options
        or any(re.fullmatch(r"[a-z0-9][a-z0-9._=-]*", item) is None for item in options)
        or len(options) != len(set(options))
        or any(item not in options for item in required)
        or any(item in options for item in ("ro", "suid", "dev"))
    ):
        raise AssemblyError("P2 injection mount options are invalid")


def _validate_injection_attestation(
    reader: StableFile,
    p2_sha256: str,
    policy: AssemblyPolicy,
    injection_policy: InjectionPolicyLock,
) -> InjectionAttestation:
    payload = reader.pread(reader.size, 0)
    value = _decode_json_object(payload, "P2 injection attestation")
    if payload != _canonical_json(value):
        raise AssemblyError("P2 injection attestation JSON is not canonical")
    if set(value) != {
        "claims",
        "commands",
        "input",
        "normalization",
        "output",
        "runtime",
        "sanitization",
        "schema",
        "tools",
    }:
        raise AssemblyError("P2 injection attestation top-level fields mismatch")
    expected = injection_policy.value
    if value["schema"] != expected["attestation_schema"]:
        raise AssemblyError("P2 injection attestation schema mismatch")
    for field in ("claims", "commands", "input", "sanitization", "tools"):
        if value[field] != expected[field]:
            raise AssemblyError(f"P2 injection attestation fixed {field} mismatch")
    if (
        expected["input"]["candidate_size"] != policy.p2_size
        or expected["input"]["candidate_uuid"] != policy.p2_uuid
    ):
        raise AssemblyError("injection policy input does not match the assembly policy")
    output = value["output"]
    output_fixed = expected["output"]["fixed"]
    if (
        not isinstance(output, dict)
        or set(output)
        != (
            _INJECTION_OUTPUT_FIXED_FIELDS
            | _INJECTION_OUTPUT_SHA256_FIELDS
            | _INJECTION_OUTPUT_CALLER_FIELDS
        )
        or any(output.get(key) != item for key, item in output_fixed.items())
        or output.get("owner") != f"0:{os.getgid()}"
        or output_fixed["size"] != policy.p2_size
        or output_fixed["uuid"] != policy.p2_uuid
    ):
        raise AssemblyError("P2 injection attestation fixed output mismatch")
    for key in _INJECTION_OUTPUT_SHA256_FIELDS:
        if not _valid_sha256(output[key]):
            raise AssemblyError(f"P2 injection attestation dynamic SHA256 is invalid: {key}")
    if output["sha256"] != p2_sha256:
        raise AssemblyError("P2 injection attestation does not bind the P2 input")
    normalization = value["normalization"]
    normalization_policy = expected["normalization"]
    if (
        not isinstance(normalization, dict)
        or set(normalization)
        != (
            set(normalization_policy["fixed"])
            | set(normalization_policy["positive_integer_fields"])
            | set(normalization_policy["sha256_fields"])
        )
        or any(
            normalization.get(key) != item
            for key, item in normalization_policy["fixed"].items()
        )
        or any(
            not isinstance(normalization.get(key), int) or normalization[key] <= 0
            for key in normalization_policy["positive_integer_fields"]
        )
        or any(
            not _valid_sha256(normalization.get(key))
            for key in normalization_policy["sha256_fields"]
        )
        or normalization.get("proof_sha256") != output["sha256"]
        or normalization.get("sparse_st_blocks", 0) * 512 >= output["size"]
    ):
        raise AssemblyError("P2 injection normalization proof mismatch")
    runtime = value["runtime"]
    if not isinstance(runtime, dict) or set(runtime) != {
        "injector_runtime_lock_schema",
        "injector_runtime_lock_sha256",
        "kernel_release",
        "mount_loop",
        "namespaces",
        "proc_version_sha256",
        "sandbox_entry_sha256",
        "sealed_script_sha256",
    }:
        raise AssemblyError("P2 injection attestation runtime fields mismatch")
    if (
        not isinstance(runtime["kernel_release"], str)
        or KERNEL_RELEASE_RE.fullmatch(runtime["kernel_release"]) is None
        or not _valid_sha256(runtime["proc_version_sha256"])
        or runtime["sealed_script_sha256"]
        != expected["runtime"]["sealed_injector_script_sha256"]
        or any(
            runtime.get(key) != item
            for key, item in expected["runtime"]["fixed"].items()
        )
    ):
        raise AssemblyError("P2 injection attestation runtime identity mismatch")
    namespaces = runtime["namespaces"]
    if not isinstance(namespaces, dict) or tuple(namespaces) != _NAMESPACE_FIELDS:
        raise AssemblyError("P2 injection namespace fields mismatch")
    for kind, identity in namespaces.items():
        match = NAMESPACE_RE.fullmatch(identity) if isinstance(identity, str) else None
        if match is None or match.group("kind") != kind:
            raise AssemblyError(f"P2 injection namespace identity is invalid: {kind}")
    _validate_mount_runtime(
        runtime["mount_loop"], expected["runtime"]["mount_required_options"]
    )
    return InjectionAttestation(value, payload, reader.digest())


class VerifiedToolchain:
    """Hold and recheck every pinned tool/runtime inode across executions."""

    def __init__(self, lock: SparseToolLock):
        self.lock = lock
        self.files: dict[str, StableFile] = {}

    @staticmethod
    def _records(lock: SparseToolLock) -> Iterable[dict[str, Any]]:
        yield lock.value["interpreter"]
        yield from lock.value["libraries"]
        yield from lock.value["tools"].values()

    def __enter__(self) -> "VerifiedToolchain":
        try:
            for record in self._records(self.lock):
                if (
                    not isinstance(record, dict)
                    or set(record) not in ({"path", "sha256", "size"}, {"dynamic", "path", "sha256", "size"})
                    or not isinstance(record["path"], str)
                    or not record["path"].startswith("/")
                    or not isinstance(record["size"], int)
                    or record["size"] <= 0
                    or not isinstance(record["sha256"], str)
                    or not SHA256_RE.fullmatch(record["sha256"])
                ):
                    raise AssemblyError("sparse tool lock file record is malformed")
                path = Path(record["path"])
                if path.resolve(strict=True) != path:
                    raise AssemblyError(f"pinned sparse runtime path is not canonical: {path}")
                opened = StableFile(path, f"pinned sparse runtime {path}", expected_size=record["size"])
                opened.__enter__()
                self.files[record["path"]] = opened
                assert opened.before is not None
                if opened.before.st_mode & 0o022:
                    raise AssemblyError(f"pinned sparse runtime is group/world writable: {path}")
                if opened.digest() != record["sha256"]:
                    raise AssemblyError(f"pinned sparse runtime SHA256 mismatch: {path}")
        except Exception:
            self.__exit__(*sys.exc_info())
            raise
        return self

    def _proc_path(self, path: str) -> str:
        return f"/proc/self/fd/{self.files[path].fd}"

    def run(
        self,
        tool_name: str,
        arguments: list[str],
        *,
        pass_fds: tuple[int, ...] = (),
        timeout: int = 1800,
    ) -> subprocess.CompletedProcess[bytes]:
        tool = self.lock.value["tools"][tool_name]
        tool_fd = self.files[tool["path"]].fd
        inherited = {tool_fd, *pass_fds}
        if tool["dynamic"]:
            interpreter = self.lock.value["interpreter"]["path"]
            loader_fd = self.files[interpreter].fd
            inherited.add(loader_fd)
            library_dirs = []
            for record in self.lock.value["libraries"]:
                directory = str(Path(record["path"]).parent)
                if directory not in library_dirs:
                    library_dirs.append(directory)
            command = [
                self._proc_path(interpreter),
                "--inhibit-cache",
                "--library-path",
                ":".join(library_dirs),
                self._proc_path(tool["path"]),
                *arguments,
            ]
        else:
            command = [self._proc_path(tool["path"]), *arguments]
        try:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                env={"LANG": "C", "LC_ALL": "C"},
                pass_fds=tuple(sorted(inherited)),
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise AssemblyError(f"{tool_name} execution failed: {error}") from None
        for opened in self.files.values():
            opened.verify_unchanged()
        if completed.returncode != 0:
            detail = completed.stderr[:4096].decode("utf-8", "replace").strip()
            raise AssemblyError(f"{tool_name} exited {completed.returncode}: {detail}")
        return completed

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        failure: Exception | None = None
        for opened in reversed(tuple(self.files.values())):
            try:
                opened.__exit__(exc_type, exc, traceback)
            except Exception as error:  # retain the first close/recheck failure
                if failure is None:
                    failure = error
        self.files.clear()
        if exc is None and failure is not None:
            raise failure


def _create_private_file(path: Path) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        return os.open(path, flags, 0o600)
    except OSError as error:
        raise AssemblyError(f"could not create private staging file: {error}") from None


def _copy_then_pwrite(
    baseline: StableFile, p2: StableFile, output_path: Path, policy: AssemblyPolicy
) -> None:
    descriptor = _create_private_file(output_path)
    try:
        offset = 0
        while offset < baseline.size:
            amount = min(COPY_CHUNK, baseline.size - offset)
            block = baseline.pread(amount, offset, "baseline copy")
            _write_all(descriptor, block, "baseline copy")
            offset += amount
        if os.lseek(descriptor, 0, os.SEEK_CUR) != baseline.size:
            raise AssemblyError("baseline full-copy length mismatch")
        p2_offset = 0
        while p2_offset < p2.size:
            amount = min(COPY_CHUNK, p2.size - p2_offset)
            block = p2.pread(amount, p2_offset, "P2 input")
            _pwrite_all(descriptor, block, policy.p2_offset + p2_offset, "P2 range")
            p2_offset += amount
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(output_path, 0o600, follow_symlinks=False)


def _canonical_json(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def _write_private(path: Path, payload: bytes) -> None:
    descriptor = _create_private_file(path)
    try:
        _write_all(descriptor, payload, "attestation")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600, follow_symlinks=False)


def _require_p2_bundle_paths(
    p2_path: Path,
    attestation_path: Path,
    *,
    test_fixture: bool,
) -> Path:
    p2_path, attestation_path = Path(p2_path), Path(attestation_path)
    try:
        p2_resolved = p2_path.resolve(strict=True)
        attestation_resolved = attestation_path.resolve(strict=True)
    except OSError as error:
        raise AssemblyError(f"could not resolve P2 input bundle: {error}") from None
    if p2_resolved != p2_path or attestation_resolved != attestation_path:
        raise AssemblyError("P2 input bundle paths must be absolute and canonical")
    if p2_path.parent != attestation_path.parent or p2_path == attestation_path:
        raise AssemblyError("P2 input and attestation must be distinct files in one bundle")
    if not test_fixture and (
        p2_path.name != "rootfs.ext4" or attestation_path.name != "attestation.json"
    ):
        raise AssemblyError("production P2 bundle filenames do not match the contract")
    return p2_path.parent


def _validate_p2_bundle_metadata(
    bundle: StableDirectory,
    p2: StableFile,
    attestation: StableFile,
    *,
    test_fixture: bool,
) -> None:
    assert bundle.before is not None
    expected_names = {p2.path.name, attestation.path.name}
    try:
        names = set(os.listdir(bundle.fd))
    except OSError as error:
        raise AssemblyError(f"could not inventory P2 input bundle: {error}") from None
    if names != expected_names:
        raise AssemblyError("P2 input bundle must contain exactly image and attestation")
    if test_fixture:
        directory_contract = (0o700, os.geteuid(), os.getegid())
        file_contract = (0o600, os.geteuid(), os.getegid())
    else:
        directory_contract = (0o750, 0, os.getgid())
        file_contract = (0o640, 0, os.getgid())
    directory_actual = (
        stat.S_IMODE(bundle.before.st_mode),
        bundle.before.st_uid,
        bundle.before.st_gid,
    )
    if directory_actual != directory_contract:
        raise AssemblyError("P2 input bundle directory metadata contract mismatch")
    for reader in (p2, attestation):
        assert reader.before is not None
        actual = (
            stat.S_IMODE(reader.before.st_mode),
            reader.before.st_uid,
            reader.before.st_gid,
        )
        if actual != file_contract or reader.before.st_nlink != 1:
            raise AssemblyError(f"{reader.label} metadata contract mismatch")


def _require_output_bundle_path(path: Path) -> tuple[Path, Path]:
    output = Path(path)
    try:
        parent = output.parent.resolve(strict=True)
    except OSError as error:
        raise AssemblyError(f"output bundle parent is unavailable: {error}") from None
    if output != parent / output.name or output.name in {"", ".", ".."}:
        raise AssemblyError("output bundle path must be an absolute canonical direct child")
    if os.path.lexists(output):
        raise AssemblyError(f"refusing to overwrite output bundle: {output.name}")
    return parent, output


def _directory_path_identity(path: Path, fd: int) -> tuple[int, int, int, int, int]:
    try:
        current = path.lstat()
        opened = os.fstat(fd)
    except OSError as error:
        raise AssemblyError(f"could not verify output parent identity: {error}") from None
    current_identity = (
        current.st_dev,
        current.st_ino,
        current.st_mode,
        current.st_uid,
        current.st_gid,
    )
    opened_identity = (
        opened.st_dev,
        opened.st_ino,
        opened.st_mode,
        opened.st_uid,
        opened.st_gid,
    )
    if not stat.S_ISDIR(current.st_mode) or current_identity != opened_identity:
        raise AssemblyError("output parent path identity changed")
    return current_identity


def _fsync_regular(path: Path, label: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1:
            raise AssemblyError(f"{label} is not one regular staging inode")
        os.fsync(descriptor)
    except OSError as error:
        raise AssemblyError(f"could not fsync {label}: {error}") from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)


def _seal_staged_bundle(path: Path) -> dict[str, tuple[int, int]]:
    try:
        directory = path.lstat()
        names = set(os.listdir(path))
    except OSError as error:
        raise AssemblyError(f"could not inventory staged output bundle: {error}") from None
    if (
        not stat.S_ISDIR(directory.st_mode)
        or stat.S_IMODE(directory.st_mode) != 0o700
        or directory.st_uid != os.geteuid()
        or directory.st_gid != os.getegid()
        or directory.st_nlink != 2
        or names != OUTPUT_BUNDLE_FILES
    ):
        raise AssemblyError("staged output bundle metadata/inventory mismatch")
    identities = {".": (directory.st_dev, directory.st_ino)}
    for name in sorted(OUTPUT_BUNDLE_FILES):
        item = (path / name).lstat()
        if (
            not stat.S_ISREG(item.st_mode)
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_uid != os.geteuid()
            or item.st_gid != os.getegid()
            or item.st_nlink != 1
        ):
            raise AssemblyError(f"staged output file metadata mismatch: {name}")
        identities[name] = (item.st_dev, item.st_ino)
        _fsync_regular(path / name, f"staged {name}")
    directory_fd = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
    return identities


def _renameat2_noreplace(
    source_directory_fd: int,
    source_name: str,
    destination_directory_fd: int,
    destination_name: str,
) -> None:
    """Perform the one Linux no-replace rename that publishes the bundle."""

    libc = ctypes.CDLL(None, use_errno=True)
    try:
        renameat2 = libc.renameat2
    except AttributeError:
        raise AssemblyError("Linux renameat2 is unavailable; refusing publication") from None
    renameat2.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    renameat2.restype = ctypes.c_int
    result = renameat2(
        source_directory_fd,
        os.fsencode(source_name),
        destination_directory_fd,
        os.fsencode(destination_name),
        1,  # RENAME_NOREPLACE
    )
    if result == 0:
        return
    error_number = ctypes.get_errno()
    if error_number in {errno.EEXIST, errno.ENOTEMPTY}:
        raise AssemblyError(
            f"refusing to overwrite output bundle: {destination_name}"
        ) from None
    raise AssemblyError(
        f"atomic no-replace bundle publication failed: {os.strerror(error_number)}"
    ) from None


def _verify_published_bundle(
    path: Path, identities: dict[str, tuple[int, int]]
) -> None:
    directory = path.lstat()
    if (
        not stat.S_ISDIR(directory.st_mode)
        or (directory.st_dev, directory.st_ino) != identities["."]
        or stat.S_IMODE(directory.st_mode) != 0o700
        or directory.st_nlink != 2
        or set(os.listdir(path)) != OUTPUT_BUNDLE_FILES
    ):
        raise AssemblyError("published output bundle identity/inventory mismatch")
    for name, identity in identities.items():
        if name == ".":
            continue
        item = (path / name).lstat()
        if (
            not stat.S_ISREG(item.st_mode)
            or (item.st_dev, item.st_ino) != identity
            or stat.S_IMODE(item.st_mode) != 0o600
            or item.st_nlink != 1
        ):
            raise AssemblyError(f"published output identity mismatch: {name}")


def _assert_byte_identical(left: StableFile, right: StableFile, label: str) -> None:
    if left.size != right.size:
        raise AssemblyError(f"{label} size mismatch")
    _compare_ranges(left, 0, right, 0, left.size, label)


def assemble_userdata_image(
    baseline_path: Path,
    p2_path: Path,
    p2_attestation_path: Path,
    output_bundle: Path,
    *,
    policy: AssemblyPolicy = PRODUCTION_POLICY,
    tool_lock_path: Path = SPARSE_TOOL_LOCK,
    source_lock_path: Path = SOURCE_LOCK,
    injection_policy_lock_path: Path = INJECTION_POLICY_LOCK,
    test_only_allow_unprivileged_input_bundle: bool = False,
    test_only_injection_policy_lock_sha256: str | None = None,
) -> dict[str, Any]:
    """Assemble and atomically publish one complete, private output bundle."""

    if os.geteuid() == 0:
        raise AssemblyError("refusing to run the userdata assembler with effective uid 0")
    if test_only_allow_unprivileged_input_bundle:
        if (
            policy == PRODUCTION_POLICY
            or policy.baseline_size > TEST_FIXTURE_MAX_BYTES
            or policy.p2_size > TEST_FIXTURE_MAX_BYTES
        ):
            raise AssemblyError(
                "test-only input policy is forbidden for production-sized geometry"
            )
        if not _valid_sha256(test_only_injection_policy_lock_sha256):
            raise AssemblyError("test-only injection policy requires an explicit SHA256 pin")
        injection_policy_sha256 = test_only_injection_policy_lock_sha256
    else:
        if os.getuid() != os.geteuid() or os.getgid() != os.getegid():
            raise AssemblyError(
                "production assembly requires matching real/effective caller credentials"
            )
        if test_only_injection_policy_lock_sha256 is not None:
            raise AssemblyError("test-only injection policy SHA256 is forbidden in production")
        injection_policy_sha256 = INJECTION_POLICY_LOCK_SHA256
    assert injection_policy_sha256 is not None

    p2_bundle_path = _require_p2_bundle_paths(
        p2_path,
        p2_attestation_path,
        test_fixture=test_only_allow_unprivileged_input_bundle,
    )
    output_parent, output_bundle = _require_output_bundle_path(output_bundle)
    if output_parent == p2_bundle_path:
        raise AssemblyError("output bundle parent must differ from the sealed P2 input bundle")
    tool_lock = load_sparse_tool_lock(tool_lock_path)
    injection_policy = load_injection_policy_lock(
        injection_policy_lock_path, expected_sha256=injection_policy_sha256
    )
    source_contract = _load_source_contract(source_lock_path)
    old_umask = os.umask(0o077)
    output_parent_fd = -1
    scratch: Path | None = None
    scratch_identity: tuple[int, int] | None = None
    published = False
    try:
        parent_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        output_parent_fd = os.open(output_parent, parent_flags)
        parent_identity = _directory_path_identity(output_parent, output_parent_fd)
        scratch = Path(
            tempfile.mkdtemp(prefix=".lmi-d114-assemble-", dir=output_parent)
        )
        os.chmod(scratch, 0o700, follow_symlinks=False)
        scratch_stat = scratch.lstat()
        scratch_identity = (scratch_stat.st_dev, scratch_stat.st_ino)
        if _directory_path_identity(output_parent, output_parent_fd) != parent_identity:
            raise AssemblyError("output parent changed during scratch creation")
        staged_bundle = scratch / "publish.bundle"
        staged_bundle.mkdir(mode=0o700)
        raw_stage = staged_bundle / OUTPUT_RAW_NAME
        sparse_stage = staged_bundle / OUTPUT_SPARSE_NAME
        assembly_attestation_stage = (
            staged_bundle / OUTPUT_ASSEMBLY_ATTESTATION_NAME
        )
        injection_attestation_stage = (
            staged_bundle / OUTPUT_INJECTION_ATTESTATION_NAME
        )
        expanded_stage = scratch / "roundtrip.raw"

        with StableDirectory(p2_bundle_path, "P2 input bundle") as p2_bundle:
            with StableFile(
                p2_path, "P2 input", expected_size=policy.p2_size
            ) as p2:
                with StableFile(
                    p2_attestation_path, "P2 injection attestation"
                ) as p2_attestation:
                    _validate_p2_bundle_metadata(
                        p2_bundle,
                        p2,
                        p2_attestation,
                        test_fixture=test_only_allow_unprivileged_input_bundle,
                    )
                    p2_fs = _validate_p2(p2, policy)
                    p2_sha256 = p2.digest()
                    p2_injection = _validate_injection_attestation(
                        p2_attestation, p2_sha256, policy, injection_policy
                    )
                    with StableFile(
                        baseline_path,
                        "baseline raw",
                        expected_size=policy.baseline_size,
                    ) as baseline:
                        if baseline.digest() != policy.baseline_sha256:
                            raise AssemblyError("baseline raw SHA256 mismatch")
                        baseline_gpt = validate_gpt(baseline, policy)
                        _copy_then_pwrite(baseline, p2, raw_stage, policy)
                        with StableFile(
                            raw_stage,
                            "staged assembled raw",
                            expected_size=policy.baseline_size,
                        ) as raw:
                            raw_verification = _verify_composition_readers(
                                baseline, p2, raw, policy
                            )
                            raw_sha256 = raw_verification["raw_sha256"]
                            with VerifiedToolchain(tool_lock) as tools:
                                tools.run(
                                    "img2simg",
                                    [
                                        f"/proc/self/fd/{raw.fd}",
                                        str(sparse_stage),
                                        str(SECTOR_SIZE),
                                    ],
                                    pass_fds=(raw.fd,),
                                )
                                if (
                                    not sparse_stage.is_file()
                                    or sparse_stage.is_symlink()
                                ):
                                    raise AssemblyError(
                                        "img2simg did not create one regular sparse file"
                                    )
                                os.chmod(sparse_stage, 0o600, follow_symlinks=False)
                                _fsync_regular(sparse_stage, "staged sparse")
                                with StableFile(
                                    sparse_stage, "staged sparse"
                                ) as sparse:
                                    sparse_verification = _parse_sparse_reader(
                                        sparse, policy.baseline_size, raw_sha256
                                    )
                                    tools.run(
                                        "simg2img",
                                        [
                                            f"/proc/self/fd/{sparse.fd}",
                                            str(expanded_stage),
                                        ],
                                        pass_fds=(sparse.fd,),
                                    )
                                if (
                                    not expanded_stage.is_file()
                                    or expanded_stage.is_symlink()
                                ):
                                    raise AssemblyError(
                                        "simg2img did not create one regular raw file"
                                    )
                                os.chmod(expanded_stage, 0o600, follow_symlinks=False)
                                _fsync_regular(expanded_stage, "sparse round-trip raw")
                                with StableFile(
                                    expanded_stage,
                                    "sparse round-trip raw",
                                    expected_size=policy.baseline_size,
                                ) as expanded:
                                    if expanded.digest() != raw_sha256:
                                        raise AssemblyError(
                                            "sparse round-trip raw SHA256 mismatch"
                                        )
                                    _assert_byte_identical(
                                        raw, expanded, "sparse round-trip cmp"
                                    )
                                    expanded_verification = (
                                        _verify_composition_readers(
                                            baseline, p2, expanded, policy
                                        )
                                    )
                        expanded_stage.unlink()
                        attestation = {
                            "bindings": {
                                "injection_policy_lock_sha256": injection_policy.sha256,
                                "p2_injection_attestation_sha256": p2_injection.sha256,
                                "source_lock_sha256": source_contract["sha256"],
                                "sparse_tools_lock_sha256": tool_lock.sha256,
                            },
                            "compatibility": {
                                "d110": {
                                    "boot_sha256": D110_BOOT_SHA256,
                                    "boot_size": D110_BOOT_SIZE,
                                    "boot_uuid": D110_BOOT_UUID,
                                    "root_uuid": policy.p2_uuid,
                                },
                                "d110_boot": {
                                    "required_unchanged": True,
                                    "sha256": D110_BOOT_SHA256,
                                    "size": D110_BOOT_SIZE,
                                    "uuid": D110_BOOT_UUID,
                                },
                                "d114_source_lock": source_contract,
                            },
                            "geometry": {
                                "disk_lbas": policy.disk_lbas,
                                "logical_sector_size": SECTOR_SIZE,
                                "p1_lbas": [
                                    policy.p1_first_lba,
                                    policy.p1_last_lba,
                                ],
                                "p2_byte_range": [policy.p2_offset, policy.p2_end],
                                "p2_lbas": [
                                    policy.p2_first_lba,
                                    policy.p2_last_lba,
                                ],
                                "suffix_bytes": policy.suffix_size,
                            },
                            "input": {
                                "baseline": {
                                    "gpt": baseline_gpt.evidence(policy),
                                    "sha256": policy.baseline_sha256,
                                    "size": policy.baseline_size,
                                },
                                "p2": {
                                    "filesystem": p2_fs,
                                    "injection_attestation": {
                                        "copied_filename": OUTPUT_INJECTION_ATTESTATION_NAME,
                                        "schema": p2_injection.value["schema"],
                                        "sha256": p2_injection.sha256,
                                    },
                                    "sha256": p2_sha256,
                                    "size": policy.p2_size,
                                    "uuid": policy.p2_uuid,
                                },
                            },
                            "output": {
                                "bundle": {
                                    "directory_mode": "0700",
                                    "files": sorted(OUTPUT_BUNDLE_FILES),
                                    "path": output_bundle.name,
                                },
                                "raw": {
                                    "filename": OUTPUT_RAW_NAME,
                                    "path": OUTPUT_RAW_NAME,
                                    "sha256": raw_sha256,
                                    "size": policy.baseline_size,
                                },
                                "sparse": {
                                    "filename": OUTPUT_SPARSE_NAME,
                                    "logical_size": policy.baseline_size,
                                    "path": OUTPUT_SPARSE_NAME,
                                    "sha256": sparse_verification["file_sha256"],
                                    "size": sparse_verification["file_size"],
                                },
                            },
                            "schema": "lmi-p2-d114-userdata-assembly-attestation/v1",
                            "status": "private-d114-hardware-test-candidate",
                            "tools": {
                                "commands": [
                                    [
                                        "img2simg",
                                        "RAW_FD",
                                        "SPARSE_STAGE",
                                        "4096",
                                    ],
                                    [
                                        "simg2img",
                                        "SPARSE_FD",
                                        "ROUNDTRIP_RAW_STAGE",
                                    ],
                                ],
                                "lock_sha256": tool_lock.sha256,
                                "package": tool_lock.value["package"],
                            },
                            "verification": {
                                "expanded": expanded_verification,
                                "expanded_byte_identical": True,
                                "gates": {
                                    "expanded": True,
                                    "geometry": True,
                                    "gpt": True,
                                    "injection_attestation": True,
                                    "p2_range": True,
                                    "prefix": True,
                                    "roundtrip": True,
                                    "suffix": True,
                                },
                                "raw": raw_verification,
                                "roundtrip_raw_sha256": raw_sha256,
                                "sparse_static": sparse_verification,
                            },
                        }
                        _write_private(
                            injection_attestation_stage, p2_injection.payload
                        )
                        _write_private(
                            assembly_attestation_stage, _canonical_json(attestation)
                        )
                    p2_attestation.verify_unchanged()
                    p2.verify_unchanged()
                    p2_bundle.verify_unchanged()

                    staged_identities = _seal_staged_bundle(staged_bundle)
                    scratch_fd = os.open(scratch, parent_flags)
                    try:
                        os.fsync(scratch_fd)
                        if (
                            _directory_path_identity(
                                output_parent, output_parent_fd
                            )
                            != parent_identity
                        ):
                            raise AssemblyError(
                                "output parent changed before publication"
                            )
                        _renameat2_noreplace(
                            scratch_fd,
                            staged_bundle.name,
                            output_parent_fd,
                            output_bundle.name,
                        )
                        published = True
                        os.fsync(scratch_fd)
                    finally:
                        os.close(scratch_fd)
                    _verify_published_bundle(output_bundle, staged_identities)
                    os.fsync(output_parent_fd)
        try:
            scratch.rmdir()
        except OSError as error:
            raise AssemblyError(
                "complete bundle was atomically published, but private scratch "
                f"cleanup failed: {error}"
            ) from None
        scratch = None
        os.fsync(output_parent_fd)
        return attestation
    finally:
        os.umask(old_umask)
        if output_parent_fd >= 0:
            os.close(output_parent_fd)
        if scratch is not None and os.path.lexists(scratch):
            try:
                current = scratch.lstat()
                if (
                    scratch_identity is not None
                    and stat.S_ISDIR(current.st_mode)
                    and not scratch.is_symlink()
                    and (current.st_dev, current.st_ino) == scratch_identity
                ):
                    shutil.rmtree(scratch)
            except OSError:
                if not published:
                    raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="offline assemble and verify the complete D114 lmi userdata image"
    )
    parser.add_argument("--baseline-raw", required=True, type=Path)
    parser.add_argument("--p2-raw", required=True, type=Path)
    parser.add_argument("--p2-attestation", required=True, type=Path)
    parser.add_argument("--output-bundle", required=True, type=Path)
    parser.add_argument("--tool-lock", type=Path, default=SPARSE_TOOL_LOCK)
    parser.add_argument(
        "--injection-policy-lock", type=Path, default=INJECTION_POLICY_LOCK
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        result = assemble_userdata_image(
            arguments.baseline_raw,
            arguments.p2_raw,
            arguments.p2_attestation,
            arguments.output_bundle,
            tool_lock_path=arguments.tool_lock,
            injection_policy_lock_path=arguments.injection_policy_lock,
        )
    except (AssemblyError, OSError) as error:
        print(f"assemble_userdata_image: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "raw_sha256": result["output"]["raw"]["sha256"],
                "schema": result["schema"],
                "sparse_sha256": result["output"]["sparse"]["sha256"],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
