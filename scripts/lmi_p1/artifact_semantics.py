"""Fail-closed semantic validation for the lmi P1 boot/userdata artifacts.

This module deliberately parses the small set of on-disk formats used by the
lmi build instead of trusting host utilities or mounting an untrusted image.
All paths are inputs only; successful evidence is safe to serialize as JSON and
does not disclose workspace paths.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import resource
import signal
import stat
import struct
import subprocess
import tempfile
from typing import BinaryIO, Mapping, Sequence
import uuid
import zlib

from .common import GateError


_BOOT_MAGIC = b"ANDROID!"
_BOOT_HEADER_SIZE = 1660
_PAGE_SIZE = 4096
_MAX_INITRAMFS_OUTPUT = 256 * 1024 * 1024
_MAX_INITRAMFS_MANIFEST_BYTES = 16 * 1024 * 1024
_MAX_SMALL_INPUT = 256 * 1024 * 1024
_MAX_CPIO_MEMBERS = 65_536
_MAX_CPIO_NAME_BYTES = 8 * 1024 * 1024
_MAX_CPIO_SYMLINK_DEPTH = 64
_MAX_TOOL_OUTPUT = 1024 * 1024
_E2FSCK_TIMEOUT_SECONDS = 300
_DEBUGFS_TIMEOUT_SECONDS = 30
_COPY_CHUNK = 4 * 1024 * 1024
_GPT_HEADER_SIZE = 92
_GPT_ENTRY_SIZE = 128
_MAX_GPT_ENTRIES = 4096
_RECORDED_BOOT_BYTES = 0x08000000
_RECORDED_USERDATA_BYTES = 0x1AC07FB000
_PRODUCTION_DTB_SHA256 = "aee89cc172734de955a11ec335b16d3a1b5da51667083b919271c2b6902d57a6"
_PRODUCTION_KERNEL_SHA256 = "38c38390ca9a474b4d29d24fb25ad9139bb58e2ad9cd88b5b601abad2f8c2d5e"
_PRODUCTION_MIN_USERDATA_BYTES = 1_818_230_784
_PRODUCTION_GPT_ENTRIES = 128
_PRODUCTION_BOOT_FIRST_LBA = 2048
_PRODUCTION_BOOT_LAST_LBA = 124927
_PRODUCTION_ROOT_FIRST_LBA = 124928
_E2FSCK = Path("/usr/sbin/e2fsck")
_DEBUGFS = Path("/usr/sbin/debugfs")
_E2FSCK_SHA256 = "2e51f521c676729920eaba694933d9d4048645f1a5789556fd0027e62d11ecc8"
_DEBUGFS_SHA256 = "864e1d7b445e7b5bfc831da78330dbcafc590fa82b89ea9de60b7527f989954f"
_E2FSPROGS_VERSION = "1.47.2"
_LMI_DTB_MODEL = "Qualcomm Technologies, Inc. kona v2.1 SoC"
_LMI_DTB_COMPATIBLE = ("qcom,kona",)
_INITRAMFS_MANIFEST_SCHEMA = "lmi-p1-initramfs-manifest/v1"
_ESP_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
_ARM64_ROOT_GUID = uuid.UUID("b921b045-1df0-41c3-af44-4c6f280d3fae")
_EXT_COMPAT_HAS_JOURNAL = 0x0004
_EXT_INCOMPAT_RECOVER = 0x0004
_EXT_INCOMPAT_EXTENTS = 0x0040
_EXT_INCOMPAT_CSUM_SEED = 0x2000
_EXT_RO_COMPAT_METADATA_CSUM = 0x0400
_EXT_INCOMPAT_64BIT = 0x0080
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"
)
_DEVICEINFO_ASSIGNMENT_RE = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)="([^"\\]*)"$')
_REQUIRED_INITRAMFS = (
    "bin/busybox",
    "init",
    "init_2nd.sh",
    "init_functions.sh",
    "sbin/blkid",
    "usr/sbin/losetup",
    "usr/share/deviceinfo/deviceinfo",
    "usr/share/misc/source_deviceinfo",
)
_ROOTFS_FILE_SPECS: tuple[tuple[str, str, int, int], ...] = (
    ("/etc/fstab", "fstab", 0o644, 1024 * 1024),
    (
        "/usr/share/deviceinfo/device-xiaomi-lmi",
        "deviceinfo",
        0o644,
        1024 * 1024,
    ),
    ("/lib/apk/db/installed", "apk_installed", 0o644, 64 * 1024 * 1024),
    ("/etc/ssh/sshd_config", "sshd_config", 0o600, 1024 * 1024),
    ("/etc/init.d/sshd", "sshd_service", 0o755, 4 * 1024 * 1024),
    ("/usr/sbin/sshd.pam", "sshd_pam", 0o755, 32 * 1024 * 1024),
    ("/home/lmi/.ssh/authorized_keys", "authorized_keys", 0o600, 1024 * 1024),
    ("/etc/lmi-release-identity", "release_identity", 0o644, 1024 * 1024),
    (
        "/etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
        "networkmanager_profile",
        0o600,
        1024 * 1024,
    ),
    (
        "/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
        "networkmanager_takeover",
        0o644,
        1024 * 1024,
    ),
    ("/usr/bin/unudhcpd", "unudhcpd", 0o755, 8 * 1024 * 1024),
    ("/etc/init.d/unudhcpd", "unudhcpd_service", 0o755, 1024 * 1024),
    ("/etc/conf.d/unudhcpd.usb0", "unudhcpd_config", 0o644, 1024 * 1024),
    ("/usr/sbin/lmi-usb0-dhcp", "usb_dhcp_wrapper", 0o755, 1024 * 1024),
    ("/etc/init.d/lmi-usb0-dhcp", "usb_dhcp_service", 0o755, 1024 * 1024),
)
_ROOT_OWNED_MANAGEMENT_KEYS = {
    "networkmanager_profile",
    "networkmanager_takeover",
    "unudhcpd",
    "unudhcpd_service",
    "unudhcpd_config",
    "usb_dhcp_wrapper",
    "usb_dhcp_service",
}
_EXPECTED_NETWORKMANAGER_PROFILE = b"""[connection]
id=lmi-usb0
type=ethernet
interface-name=usb0
autoconnect=true
autoconnect-priority=100

[ethernet]

[ipv4]
method=manual
address1=172.16.42.1/24
never-default=true

[ipv6]
method=disabled
"""
_EXPECTED_NETWORKMANAGER_TAKEOVER = b"""[device-lmi-usb0]
match-device=interface-name:usb0
managed=1
keep-configuration=no
"""
_EXPECTED_UNUDHCPD_CONFIG = b"""# The OpenRC instance name also binds the service to usb0. Keep every option
# explicit so this full-userland DHCP server can lease only the management host.
command_args="-i usb0 -s 172.16.42.1 -c 172.16.42.2"
"""
_EXPECTED_USB_DHCP_WRAPPER = b"""#!/bin/sh
set -eu

profile=lmi-usb0
interface=usb0
dhcp_service=unudhcpd.usb0

activate() {
\t[ "$(/usr/bin/nmcli -g connection.id connection show "$profile")" = "$profile" ]
\t[ "$(/usr/bin/nmcli -g connection.interface-name connection show "$profile")" = "$interface" ]
\t/usr/bin/nmcli --wait 30 connection up id "$profile" ifname "$interface"
\t/sbin/rc-service "$dhcp_service" start
}

deactivate() {
\t/sbin/rc-service "$dhcp_service" stop
}

case "${1:-}" in
\tstart) activate ;;
\tstop) deactivate ;;
\t*) exit 64 ;;
esac
"""
_EXPECTED_USB_DHCP_SERVICE = b"""#!/sbin/openrc-run

description="Activate the fixed lmi USB management link and its DHCP server"
command=/usr/sbin/lmi-usb0-dhcp
command_args=start

depend() {
\tneed net
\tafter networkmanager
}

stop() {
\tebegin "Stopping the lmi USB management DHCP server"
\t/usr/sbin/lmi-usb0-dhcp stop
\teend $?
}
"""
_EXPECTED_DEVICEINFO: Mapping[str, str] = {
    "deviceinfo_append_dtb": "false",
    "deviceinfo_arch": "aarch64",
    "deviceinfo_bootimg_qcdt": "false",
    "deviceinfo_codename": "xiaomi-lmi",
    "deviceinfo_dtb": "qcom/kona-v2.1-lmi",
    "deviceinfo_flash_offset_base": "0x00000000",
    "deviceinfo_flash_offset_dtb": "0x01f00000",
    "deviceinfo_flash_offset_kernel": "0x00008000",
    "deviceinfo_flash_offset_ramdisk": "0x01000000",
    "deviceinfo_flash_offset_second": "0x00000000",
    "deviceinfo_flash_offset_tags": "0x00000100",
    "deviceinfo_flash_pagesize": "4096",
    "deviceinfo_flash_fastboot_partition_rootfs": "userdata",
    "deviceinfo_flash_method": "fastboot",
    "deviceinfo_generate_bootimg": "true",
    "deviceinfo_header_version": "2",
    "deviceinfo_rootfs_image_sector_size": "4096",
    "deviceinfo_usb_idProduct": "0xA4A2",
    "deviceinfo_usb_idVendor": "0x0525",
    "deviceinfo_usb_network_function": "rndis.usb0",
}


@dataclass(frozen=True)
class PartitionLimits:
    """Recorded byte capacities of the lmi partitions targeted by P1."""

    boot_bytes: int = _RECORDED_BOOT_BYTES
    userdata_bytes: int = _RECORDED_USERDATA_BYTES

    def __post_init__(self) -> None:
        for name, value, recorded in (
            ("boot", self.boot_bytes, _RECORDED_BOOT_BYTES),
            ("userdata", self.userdata_bytes, _RECORDED_USERDATA_BYTES),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise GateError(f"{name} partition limit must be a positive integer")
            if value > recorded:
                raise GateError(f"{name} partition limit exceeds the recorded hardware capacity")


@dataclass(frozen=True, order=True)
class InitramfsManifestEntry:
    """One complete, logical newc member expected in the release initramfs."""

    path: str
    type: str
    mode: int
    size: int
    sha256: str
    link_target: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, str) or not self.path:
            raise GateError("initramfs manifest path must be nonempty")
        if self.path != ".":
            parsed = PurePosixPath(self.path)
            if (
                self.path.startswith("/")
                or parsed.as_posix() != self.path
                or any(part in {"", ".", ".."} for part in parsed.parts)
            ):
                raise GateError("initramfs manifest path is not canonical")
        if self.type not in {"file", "directory", "symlink"}:
            raise GateError("initramfs manifest type is unsupported")
        if (
            not isinstance(self.mode, int)
            or isinstance(self.mode, bool)
            or self.mode < 0
            or self.mode > 0o7777
        ):
            raise GateError("initramfs manifest mode is invalid")
        if (
            not isinstance(self.size, int)
            or isinstance(self.size, bool)
            or self.size < 0
            or self.size > _MAX_INITRAMFS_OUTPUT
        ):
            raise GateError("initramfs manifest size is invalid")
        if not isinstance(self.sha256, str) or re.fullmatch(
            r"[0-9a-f]{64}", self.sha256
        ) is None:
            raise GateError("initramfs manifest sha256 is invalid")
        if self.type == "directory" and (self.size != 0 or self.link_target is not None):
            raise GateError("initramfs manifest directory is malformed")
        if self.type == "symlink":
            if not isinstance(self.link_target, str) or not self.link_target:
                raise GateError("initramfs manifest symlink target is missing")
        elif self.link_target is not None:
            raise GateError("non-symlink initramfs manifest entry has a link target")


@dataclass(frozen=True)
class RootfsBindings:
    """Trusted host-side copies of critical files required inside pmOS_root."""

    apk_installed: Path
    sshd_config: Path
    sshd_service: Path
    sshd_pam: Path
    authorized_keys: Path
    release_identity: Path
    networkmanager_profile: Path
    networkmanager_takeover: Path
    unudhcpd: Path
    unudhcpd_service: Path
    unudhcpd_config: Path
    usb_dhcp_wrapper: Path
    usb_dhcp_service: Path

    def __post_init__(self) -> None:
        for field_name in (
            "apk_installed",
            "sshd_config",
            "sshd_service",
            "sshd_pam",
            "authorized_keys",
            "release_identity",
            "networkmanager_profile",
            "networkmanager_takeover",
            "unudhcpd",
            "unudhcpd_service",
            "unudhcpd_config",
            "usb_dhcp_wrapper",
            "usb_dhcp_service",
        ):
            if not isinstance(getattr(self, field_name), Path):
                raise GateError(f"rootfs binding {field_name} must be a Path")


@dataclass(frozen=True)
class ArtifactExpectations:
    """Trusted production pins; tests must override them explicitly."""

    profile: str = "lmi-p1-production"
    kernel_sha256: str = _PRODUCTION_KERNEL_SHA256
    kernel_size: int | None = None
    dtb_sha256: str = _PRODUCTION_DTB_SHA256
    dtb_model: str = _LMI_DTB_MODEL
    dtb_compatible: tuple[str, ...] = _LMI_DTB_COMPATIBLE
    chosen_bootargs: str | None = None
    initramfs_manifest: tuple[InitramfsManifestEntry, ...] | None = None
    minimum_userdata_bytes: int = _PRODUCTION_MIN_USERDATA_BYTES
    userdata_size_alignment: int = 1024 * 1024
    gpt_entry_count: int = _PRODUCTION_GPT_ENTRIES
    boot_first_lba: int = _PRODUCTION_BOOT_FIRST_LBA
    boot_last_lba: int = _PRODUCTION_BOOT_LAST_LBA
    root_first_lba: int = _PRODUCTION_ROOT_FIRST_LBA
    gpt_partition_names: tuple[str, str] = ("primary", "primary")
    boot_feature_masks: tuple[int, int, int] = (0x0038, 0x0002, 0x0003)
    root_feature_masks: tuple[int, int, int] = (0x103C, 0x02C2, 0x006B)
    e2fsck_sha256: str = _E2FSCK_SHA256
    debugfs_sha256: str = _DEBUGFS_SHA256
    e2fsprogs_version: str = _E2FSPROGS_VERSION
    tool_uid: int = 0
    tool_gid: int = 0
    tool_mode: int = 0o755

    def __post_init__(self) -> None:
        if (
            not isinstance(self.profile, str)
            or not self.profile
            or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", self.profile) is None
        ):
            raise GateError("artifact expectation profile is invalid")
        for label, digest in (
            ("kernel", self.kernel_sha256),
            ("DTB", self.dtb_sha256),
            ("e2fsck", self.e2fsck_sha256),
            ("debugfs", self.debugfs_sha256),
        ):
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise GateError(f"expected {label} sha256 must be 64 lowercase hexadecimal digits")
        if self.kernel_size is not None and (
            not isinstance(self.kernel_size, int)
            or isinstance(self.kernel_size, bool)
            or not 64 <= self.kernel_size <= 64 * 1024 * 1024
        ):
            raise GateError("expected kernel size is invalid")
        if not isinstance(self.dtb_sha256, str) or re.fullmatch(
            r"[0-9a-f]{64}", self.dtb_sha256
        ) is None:
            raise GateError("expected DTB sha256 must be 64 lowercase hexadecimal digits")
        if (
            not isinstance(self.dtb_model, str)
            or not self.dtb_model
            or "\0" in self.dtb_model
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in self.dtb_model
            )
        ):
            raise GateError("expected DTB model must be one nonempty string")
        if (
            not isinstance(self.dtb_compatible, tuple)
            or not self.dtb_compatible
            or any(
                not isinstance(item, str) or not item or "\0" in item
                or any(
                    ord(character) < 0x20 or ord(character) == 0x7F
                    for character in item
                )
                for item in self.dtb_compatible
            )
            or len(set(self.dtb_compatible)) != len(self.dtb_compatible)
        ):
            raise GateError("expected DTB compatible must be a nonempty tuple of strings")
        if self.chosen_bootargs is not None and (
            not isinstance(self.chosen_bootargs, str)
            or not self.chosen_bootargs
            or "\0" in self.chosen_bootargs
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in self.chosen_bootargs
            )
        ):
            raise GateError("expected /chosen/bootargs is unsafe")
        if self.chosen_bootargs is not None and "debug-shell" in self.chosen_bootargs:
            raise GateError("expected /chosen/bootargs enables a debug shell")
        if self.initramfs_manifest is not None:
            if (
                not isinstance(self.initramfs_manifest, tuple)
                or not self.initramfs_manifest
                or any(
                    not isinstance(item, InitramfsManifestEntry)
                    for item in self.initramfs_manifest
                )
                or tuple(sorted(self.initramfs_manifest)) != self.initramfs_manifest
                or len({item.path for item in self.initramfs_manifest})
                != len(self.initramfs_manifest)
            ):
                raise GateError("expected initramfs manifest must be a sorted unique tuple")
        for label, value in (
            ("minimum userdata bytes", self.minimum_userdata_bytes),
            ("userdata size alignment", self.userdata_size_alignment),
            ("GPT entry count", self.gpt_entry_count),
            ("boot first LBA", self.boot_first_lba),
            ("boot last LBA", self.boot_last_lba),
            ("root first LBA", self.root_first_lba),
            ("tool mode", self.tool_mode),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise GateError(f"expected {label} must be a positive integer")
        if (
            self.minimum_userdata_bytes % _PAGE_SIZE
            or self.userdata_size_alignment % _PAGE_SIZE
            or not 2 <= self.gpt_entry_count <= _MAX_GPT_ENTRIES
            or self.boot_first_lba > self.boot_last_lba
            or self.root_first_lba != self.boot_last_lba + 1
        ):
            raise GateError("expected userdata geometry is non-canonical")
        for label, value in (("tool uid", self.tool_uid), ("tool gid", self.tool_gid)):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise GateError(f"expected {label} must be a nonnegative integer")
        if self.tool_mode > 0o7777:
            raise GateError("expected tool mode is invalid")
        if (
            not isinstance(self.gpt_partition_names, tuple)
            or len(self.gpt_partition_names) != 2
            or any(
                not isinstance(name, str)
                or not name
                or len(name.encode("utf-16-le")) > 70
                for name in self.gpt_partition_names
            )
        ):
            raise GateError("expected GPT partition names are invalid")
        for label, masks in (
            ("boot", self.boot_feature_masks),
            ("root", self.root_feature_masks),
        ):
            if (
                not isinstance(masks, tuple)
                or len(masks) != 3
                or any(
                    not isinstance(mask, int)
                    or isinstance(mask, bool)
                    or not 0 <= mask <= 0xFFFFFFFF
                    for mask in masks
                )
            ):
                raise GateError(f"expected {label} ext feature masks are invalid")
        if self.boot_feature_masks[0] & _EXT_COMPAT_HAS_JOURNAL:
            raise GateError("expected boot feature mask enables a journal")
        if not self.root_feature_masks[0] & _EXT_COMPAT_HAS_JOURNAL:
            raise GateError("expected root feature mask omits a journal")
        if not self.root_feature_masks[1] & _EXT_INCOMPAT_EXTENTS:
            raise GateError("expected root feature mask omits extents")
        for label, masks in (("boot", self.boot_feature_masks), ("root", self.root_feature_masks)):
            if masks[1] & (_EXT_INCOMPAT_RECOVER | _EXT_INCOMPAT_CSUM_SEED):
                raise GateError(
                    f"expected {label} feature mask enables unsafe recovery/checksum seed"
                )
            if masks[2] & _EXT_RO_COMPAT_METADATA_CSUM:
                raise GateError(f"expected {label} feature mask enables metadata_csum")
        if self.e2fsprogs_version != _E2FSPROGS_VERSION:
            if not isinstance(self.e2fsprogs_version, str) or re.fullmatch(
                r"[0-9]+\.[0-9]+\.[0-9]+", self.e2fsprogs_version
            ) is None:
                raise GateError("expected e2fsprogs version is invalid")
        if self.profile == "lmi-p1-production" and (
            self.kernel_sha256 != _PRODUCTION_KERNEL_SHA256
            or self.dtb_sha256 != _PRODUCTION_DTB_SHA256
            or self.dtb_model != _LMI_DTB_MODEL
            or self.dtb_compatible != _LMI_DTB_COMPATIBLE
            or self.minimum_userdata_bytes != _PRODUCTION_MIN_USERDATA_BYTES
            or self.userdata_size_alignment != 1024 * 1024
            or self.gpt_entry_count != _PRODUCTION_GPT_ENTRIES
            or self.boot_first_lba != _PRODUCTION_BOOT_FIRST_LBA
            or self.boot_last_lba != _PRODUCTION_BOOT_LAST_LBA
            or self.root_first_lba != _PRODUCTION_ROOT_FIRST_LBA
            or self.gpt_partition_names != ("primary", "primary")
            or self.boot_feature_masks != (0x0038, 0x0002, 0x0003)
            or self.root_feature_masks != (0x103C, 0x02C2, 0x006B)
            or self.e2fsck_sha256 != _E2FSCK_SHA256
            or self.debugfs_sha256 != _DEBUGFS_SHA256
            or self.e2fsprogs_version != _E2FSPROGS_VERSION
            or self.tool_uid != 0
            or self.tool_gid != 0
            or self.tool_mode != 0o755
        ):
            raise GateError("production artifact expectations may not relax trusted pins")


@dataclass(frozen=True)
class _CpioMember:
    mode: int
    data: memoryview
    ino: int
    devmajor: int
    devminor: int
    nlink: int


@dataclass(frozen=True)
class _GptHeader:
    current_lba: int
    backup_lba: int
    first_usable_lba: int
    last_usable_lba: int
    disk_guid: uuid.UUID
    entries_lba: int
    entry_count: int
    entry_size: int
    entries_crc32: int


@dataclass(frozen=True)
class _Partition:
    type_guid: uuid.UUID
    unique_guid: uuid.UUID
    first_lba: int
    last_lba: int
    attributes: int
    name: str


def _os_failure(action: str, label: str, error: OSError) -> GateError:
    """Describe an OS failure without including either filename attribute."""

    number = error.errno if error.errno is not None else "unknown"
    detail = error.strerror or "unknown OS error"
    detail = detail.replace("\r", " ").replace("\n", " ")
    return GateError(f"could not {action} {label}: errno {number}: {detail}")


def _close_descriptor(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        pass


class _ImageReader:
    """One-inode reader which detects replacement during validation."""

    def __init__(self, path: Path, label: str, limit: int, *, raw: bool = False):
        self.path = Path(path)
        self.label = label
        self.limit = limit
        self.raw = raw
        self.stream: BinaryIO | None = None
        self.before: os.stat_result | None = None
        self.path_before: os.stat_result | None = None
        self._digest: str | None = None

    def __enter__(self) -> "_ImageReader":
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor: int | None = None
        try:
            path_before = self.path.lstat()
            descriptor = os.open(self.path, flags)
            opened = os.fstat(descriptor)
        except OSError as error:
            if descriptor is not None:
                _close_descriptor(descriptor)
            raise _os_failure("securely open", self.label, error) from None
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if (
            not stat.S_ISREG(path_before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or identity(path_before) != identity(opened)
        ):
            _close_descriptor(descriptor)
            raise GateError(f"{self.label} must be one regular non-symlink inode")
        if opened.st_size <= 0 or opened.st_size >= self.limit:
            _close_descriptor(descriptor)
            raise GateError(f"{self.label} size is outside its recorded limit")
        if self.raw and opened.st_blocks * 512 < opened.st_size:
            _close_descriptor(descriptor)
            raise GateError(f"{self.label} must be a non-sparse raw image")
        self.before = opened
        self.path_before = path_before
        try:
            self.stream = os.fdopen(descriptor, "rb")
        except OSError as error:
            _close_descriptor(descriptor)
            raise _os_failure("wrap", self.label, error) from None
        return self

    @property
    def size(self) -> int:
        assert self.before is not None
        return self.before.st_size

    def pread(self, size: int, offset: int, label: str) -> bytes:
        if size < 0 or offset < 0 or offset > self.size or size > self.size - offset:
            raise GateError(f"{label} range is outside the image")
        assert self.stream is not None
        try:
            value = os.pread(self.stream.fileno(), size, offset)
        except OSError as error:
            raise _os_failure("read", label, error) from None
        if len(value) != size:
            raise GateError(f"short read while reading {label}")
        return value

    def digest(self) -> str:
        if self._digest is not None:
            return self._digest
        assert self.stream is not None
        digest = hashlib.sha256()
        try:
            self.stream.seek(0)
            for block in iter(lambda: self.stream.read(1024 * 1024), b""):
                digest.update(block)
        except OSError as error:
            raise _os_failure("hash", self.label, error) from None
        self._digest = digest.hexdigest()
        return self._digest

    def identity(self, digest: str | None = None) -> dict[str, int | str]:
        """Return path-free freeze evidence for the inode being read."""

        assert self.before is not None
        return {
            "device": self.before.st_dev,
            "gid": self.before.st_gid,
            "inode": self.before.st_ino,
            "mode": stat.S_IMODE(self.before.st_mode),
            "mtime_ns": self.before.st_mtime_ns,
            "sha256": self.digest() if digest is None else digest,
            "size": self.before.st_size,
            "uid": self.before.st_uid,
        }

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        if self.stream is None or self.before is None or self.path_before is None:
            return
        try:
            after = os.fstat(self.stream.fileno())
            path_after = self.path.lstat()
        except OSError as error:
            try:
                self.stream.close()
            except OSError:
                pass
            if exc is None:
                raise _os_failure("restat", self.label, error) from None
            return
        try:
            self.stream.close()
        except OSError as error:
            if exc is None:
                raise _os_failure("close", self.label, error) from None
            return
        identity = lambda item: (
            item.st_dev,
            item.st_ino,
            item.st_mode,
            item.st_nlink,
            item.st_size,
            item.st_mtime_ns,
            item.st_ctime_ns,
        )
        if exc is None and (
            identity(after) != identity(self.before)
            or identity(path_after) != identity(self.path_before)
            or identity(path_after) != identity(after)
        ):
            raise GateError(f"{self.label} changed while it was being validated")


def _read_small(
    path: Path,
    label: str,
    limit: int = _MAX_SMALL_INPUT,
    *,
    identities: dict[str, dict[str, int | str]] | None = None,
    identity_label: str | None = None,
) -> bytes:
    with _ImageReader(Path(path), label, limit) as reader:
        value = reader.pread(reader.size, 0, label)
        digest = reader.digest()
        if identities is not None:
            if identity_label is None or identity_label in identities:
                raise GateError("internal input identity label is missing or duplicated")
            identities[identity_label] = reader.identity(digest)
        return value


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _u32le(value: bytes, offset: int) -> int:
    return struct.unpack_from("<I", value, offset)[0]


def _u64le(value: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", value, offset)[0]


def _align_up(value: int, alignment: int, limit: int, label: str) -> int:
    if value < 0 or alignment <= 0 or alignment & (alignment - 1):
        raise GateError(f"invalid {label} alignment")
    if value > limit:
        raise GateError(f"{label} overflows its container")
    remainder = value % alignment
    addition = 0 if remainder == 0 else alignment - remainder
    if addition > limit - value:
        raise GateError(f"{label} alignment overflows its container")
    return value + addition


def _region(
    image: bytes, start: int, size: int, alignment: int, label: str
) -> tuple[bytes, int]:
    if size <= 0 or start < 0 or start > len(image) or size > len(image) - start:
        raise GateError(f"{label} region is outside the boot image")
    content_end = start + size
    aligned_end = _align_up(content_end, alignment, len(image), label)
    if any(image[content_end:aligned_end]):
        raise GateError(f"{label} alignment padding is not zero")
    return image[start:content_end], aligned_end


def _android_boot_id(kernel: bytes, ramdisk: bytes, dtb: bytes) -> bytes:
    digest = hashlib.sha1(usedforsecurity=False)
    for component in (kernel, ramdisk, b"", b"", dtb):
        digest.update(component)
        digest.update(struct.pack("<I", len(component)))
    return digest.digest() + b"\0" * 12


def _decode_c_string(value: bytes, label: str) -> str:
    first_nul = value.find(b"\0")
    if first_nul < 0:
        raise GateError(f"{label} is not NUL terminated")
    if any(value[first_nul + 1 :]):
        raise GateError(f"{label} contains nonzero bytes after its terminator")
    try:
        text = value[:first_nul].decode("ascii")
    except UnicodeError:
        raise GateError(f"{label} is not ASCII") from None
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise GateError(f"{label} contains a control character")
    return text


def _canonical_uuid(value: str, label: str) -> str:
    if _UUID_RE.fullmatch(value) is None:
        raise GateError(f"{label} is not a canonical RFC UUID")
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        raise GateError(f"{label} is not a valid RFC UUID") from None
    if (
        parsed.int == 0
        or str(parsed) != value
        or parsed.version != 4
        or parsed.variant != uuid.RFC_4122
    ):
        raise GateError(f"{label} is not a canonical nonzero RFC v4 UUID")
    return value


def _parse_deviceinfo(value: bytes) -> dict[str, str]:
    try:
        text = value.decode("utf-8")
    except UnicodeError:
        raise GateError("installed deviceinfo is not UTF-8") from None
    if "\0" in text:
        raise GateError("installed deviceinfo contains NUL")
    result: dict[str, str] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _DEVICEINFO_ASSIGNMENT_RE.fullmatch(stripped)
        if match is None:
            raise GateError(f"unsafe installed deviceinfo syntax on line {line_number}")
        name, assigned = match.groups()
        if name in result:
            raise GateError(f"duplicate installed deviceinfo assignment: {name}")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in assigned):
            raise GateError(f"installed deviceinfo value contains a control character: {name}")
        if "$" in assigned or "`" in assigned:
            raise GateError(f"installed deviceinfo value contains shell expansion: {name}")
        result[name] = assigned
    for name, expected in _EXPECTED_DEVICEINFO.items():
        if result.get(name) != expected:
            raise GateError(
                f"installed deviceinfo mismatch for {name}: expected {expected!r}"
            )
    if result.get("deviceinfo_boot_filesystem", "ext2") != "ext2":
        raise GateError("installed deviceinfo boot filesystem is not ext2")
    base = result.get("deviceinfo_kernel_cmdline")
    if base is None or not base or base != " ".join(base.split()):
        raise GateError("installed deviceinfo kernel cmdline is missing or non-canonical")
    base_tokens = base.split(" ")
    if len(base_tokens) != len(set(base_tokens)):
        raise GateError("installed deviceinfo kernel cmdline contains duplicate tokens")
    if any(
        token == "pmos.debug-shell"
        or token.startswith(("pmos_boot_uuid=", "pmos_root_uuid=", "pmos_rootfsopts="))
        for token in base_tokens
    ):
        raise GateError("installed deviceinfo kernel cmdline contains a forbidden P1 token")
    return result


def _validate_cmdline(header: bytes, deviceinfo: Mapping[str, str]) -> tuple[str, str, list[str]]:
    cmdline = _decode_c_string(header[64:576] + header[608:1632], "boot cmdline")
    tokens = cmdline.split(" ") if cmdline else []
    if not tokens or any(not token for token in tokens):
        raise GateError("boot cmdline tokenization is not canonical")
    base_tokens = deviceinfo["deviceinfo_kernel_cmdline"].split(" ")
    if tokens[: len(base_tokens)] != base_tokens or len(tokens) != len(base_tokens) + 3:
        raise GateError("boot cmdline does not contain the exact deviceinfo base tokens")
    dynamic = tokens[len(base_tokens) :]
    expected_prefixes = ("pmos_boot_uuid=", "pmos_root_uuid=", "pmos_rootfsopts=")
    if any(not token.startswith(prefix) for token, prefix in zip(dynamic, expected_prefixes)):
        raise GateError("boot cmdline P1 tokens are missing, duplicated, or out of order")
    boot_uuid = _canonical_uuid(dynamic[0].split("=", 1)[1], "boot cmdline boot UUID")
    root_uuid = _canonical_uuid(dynamic[1].split("=", 1)[1], "boot cmdline root UUID")
    if dynamic[2] != "pmos_rootfsopts=defaults":
        raise GateError("boot cmdline rootfs options are not exactly defaults")
    if any(token == "pmos.debug-shell" or "debug-shell" in token for token in tokens):
        raise GateError("boot cmdline enables a debug shell")
    return boot_uuid, root_uuid, tokens


def _validate_arm64_image(
    kernel: bytes, expectations: ArtifactExpectations
) -> dict[str, int | str]:
    if len(kernel) < 64:
        raise GateError("kernel is too short for an ARM64 Image header")
    if kernel[56:60] != b"ARMd":
        raise GateError("kernel ARM64 Image magic mismatch")
    text_offset = _u64le(kernel, 8)
    flags = _u64le(kernel, 24)
    if text_offset != 0x80000:
        raise GateError("kernel ARM64 Image text offset mismatch")
    if flags != 0xA:
        raise GateError("kernel ARM64 Image flags mismatch")
    image_size = _u64le(kernel, 16)
    if image_size == 0:
        raise GateError("kernel ARM64 Image declared size is zero")
    if image_size != len(kernel):
        raise GateError("kernel ARM64 Image declared size does not exactly match the artifact")
    digest = _sha256(kernel)
    if digest != expectations.kernel_sha256:
        raise GateError("kernel sha256 does not match the trusted lmi expectation")
    if expectations.kernel_size is not None and len(kernel) != expectations.kernel_size:
        raise GateError("kernel size does not match the trusted lmi expectation")
    return {
        "flags": flags,
        "image_size": image_size,
        "magic": "ARMd",
        "sha256_expectation": expectations.kernel_sha256,
        "text_offset": text_offset,
    }


def _be32(value: bytes, offset: int) -> int:
    return struct.unpack_from(">I", value, offset)[0]


def _fdt_single_string(value: bytes, label: str) -> str:
    if not value or value[-1:] != b"\0" or b"\0" in value[:-1]:
        raise GateError(f"DTB {label} is not exactly one NUL-terminated string")
    try:
        text = value[:-1].decode("utf-8")
    except UnicodeError:
        raise GateError(f"DTB {label} is not UTF-8") from None
    if not text or any(ord(character) < 0x20 or ord(character) == 0x7F for character in text):
        raise GateError(f"DTB {label} contains an unsafe string")
    return text


def _fdt_string_list(value: bytes, label: str) -> tuple[str, ...]:
    if not value or value[-1:] != b"\0":
        raise GateError(f"DTB {label} is not a terminated string list")
    encoded = value[:-1].split(b"\0")
    if not encoded or any(not item for item in encoded):
        raise GateError(f"DTB {label} contains an empty string")
    try:
        result = tuple(item.decode("ascii") for item in encoded)
    except UnicodeError:
        raise GateError(f"DTB {label} is not ASCII") from None
    if any(
        any(ord(character) < 0x20 or ord(character) == 0x7F for character in item)
        for item in result
    ):
        raise GateError(f"DTB {label} contains an unsafe string")
    return result


def _validate_fdt(blob: bytes, expectations: ArtifactExpectations) -> dict[str, object]:
    digest = _sha256(blob)
    if digest != expectations.dtb_sha256:
        raise GateError("DTB sha256 does not match the trusted lmi expectation")
    if len(blob) < 40 or _be32(blob, 0) != 0xD00DFEED:
        raise GateError("DTB has invalid FDT magic or header")
    totalsize = _be32(blob, 4)
    off_struct = _be32(blob, 8)
    off_strings = _be32(blob, 12)
    off_reserve = _be32(blob, 16)
    version = _be32(blob, 20)
    last_compatible = _be32(blob, 24)
    size_strings = _be32(blob, 32)
    size_struct = _be32(blob, 36)
    if totalsize != len(blob):
        raise GateError("DTB totalsize does not equal the exported DTB size")
    if version != 17 or last_compatible != 16:
        raise GateError("DTB version is not 17 with last-compatible version 16")
    for offset, size, alignment, label in (
        (off_struct, size_struct, 4, "structure"),
        (off_strings, size_strings, 1, "strings"),
    ):
        if offset < 40 or offset % alignment or offset > totalsize or size > totalsize - offset:
            raise GateError(f"DTB {label} block is out of range")
    struct_range = (off_struct, off_struct + size_struct)
    strings_range = (off_strings, off_strings + size_strings)
    if max(struct_range[0], strings_range[0]) < min(struct_range[1], strings_range[1]):
        raise GateError("DTB structure and strings blocks overlap")
    if off_reserve < 40 or off_reserve % 8 or off_reserve > totalsize - 16:
        raise GateError("DTB memory reservation block is out of range")
    reserve_end = off_reserve
    while True:
        if reserve_end > totalsize - 16:
            raise GateError("DTB memory reservation map is unterminated")
        address, size = struct.unpack_from(">QQ", blob, reserve_end)
        reserve_end += 16
        if address == 0 and size == 0:
            break
        if size > 0xFFFFFFFFFFFFFFFF - address:
            raise GateError("DTB memory reservation range overflows")
    for start, end in (struct_range, strings_range):
        if max(off_reserve, start) < min(reserve_end, end):
            raise GateError("DTB memory reservation map overlaps another block")

    strings = blob[off_strings : off_strings + size_strings]
    cursor = off_struct
    structure_end = off_struct + size_struct
    node_stack: list[str] = []
    property_stack: list[set[str]] = []
    child_started: list[bool] = []
    saw_root = False
    saw_end = False
    model: str | None = None
    compatible: tuple[str, ...] | None = None
    chosen_bootargs: str | None = None
    chosen_bootargs_present = False
    chosen_nodes = 0
    while cursor < structure_end:
        if cursor > structure_end - 4:
            raise GateError("DTB structure token is truncated")
        token = _be32(blob, cursor)
        cursor += 4
        if token == 1:  # FDT_BEGIN_NODE
            terminator = blob.find(b"\0", cursor, structure_end)
            if terminator < 0:
                raise GateError("DTB node name is unterminated")
            try:
                node_name = blob[cursor:terminator].decode("ascii")
            except UnicodeError:
                raise GateError("DTB node name is not ASCII") from None
            if "/" in node_name or any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in node_name
            ):
                raise GateError("DTB node name is unsafe")
            if not node_stack:
                if saw_root:
                    raise GateError("DTB structure contains multiple root nodes")
                if terminator != cursor:
                    raise GateError("DTB root node name is not empty")
                saw_root = True
            elif not node_name:
                raise GateError("DTB non-root node has an empty name")
            if child_started:
                child_started[-1] = True
            node_stack.append(node_name)
            property_stack.append(set())
            child_started.append(False)
            if node_stack == ["", "chosen"]:
                chosen_nodes += 1
                if chosen_nodes > 1:
                    raise GateError("DTB contains multiple /chosen nodes")
            cursor = _align_up(terminator + 1, 4, structure_end, "DTB node name")
        elif token == 2:  # FDT_END_NODE
            if not node_stack:
                raise GateError("DTB closes a node that is not open")
            node_stack.pop()
            property_stack.pop()
            child_started.pop()
        elif token == 3:  # FDT_PROP
            if not node_stack or cursor > structure_end - 8:
                raise GateError("DTB property is outside a node or truncated")
            length, name_offset = struct.unpack_from(">II", blob, cursor)
            cursor += 8
            name_end = strings.find(b"\0", name_offset) if name_offset < len(strings) else -1
            if name_end < 0 or name_end == name_offset:
                raise GateError("DTB property name is outside the strings block")
            try:
                property_name = strings[name_offset:name_end].decode("ascii")
            except UnicodeError:
                raise GateError("DTB property name is not ASCII") from None
            if any(
                ord(character) < 0x20 or ord(character) == 0x7F
                for character in property_name
            ):
                raise GateError("DTB property name is unsafe")
            if property_name in property_stack[-1]:
                raise GateError(f"DTB node contains a duplicate property: {property_name}")
            if child_started[-1]:
                raise GateError("DTB property appears after a child node")
            property_stack[-1].add(property_name)
            if length > structure_end - cursor:
                raise GateError("DTB property value is out of range")
            value = blob[cursor : cursor + length]
            value_end = cursor + length
            cursor = _align_up(value_end, 4, structure_end, "DTB property")
            if any(blob[value_end:cursor]):
                raise GateError("DTB property padding is not zero")
            path = "/" if len(node_stack) == 1 else "/" + "/".join(node_stack[1:])
            if path == "/" and property_name == "model":
                model = _fdt_single_string(value, "root model")
            elif path == "/" and property_name == "compatible":
                compatible = _fdt_string_list(value, "root compatible")
            elif path == "/chosen" and property_name == "bootargs":
                chosen_bootargs_present = True
                chosen_bootargs = _fdt_single_string(value, "/chosen/bootargs")
        elif token == 4:  # FDT_NOP
            continue
        elif token == 9:  # FDT_END
            if not saw_root or node_stack:
                raise GateError("DTB structure ends with unbalanced nodes")
            if any(blob[cursor:structure_end]):
                raise GateError("DTB structure has nonzero bytes after FDT_END")
            saw_end = True
            cursor = structure_end
        else:
            raise GateError("DTB structure contains an unknown token")
    if not saw_end:
        raise GateError("DTB structure is missing FDT_END")
    if model != expectations.dtb_model:
        raise GateError("DTB root model does not match the trusted lmi expectation")
    if compatible != expectations.dtb_compatible:
        raise GateError("DTB root compatible does not exactly match qcom,kona")
    if chosen_bootargs_present:
        if expectations.chosen_bootargs is None:
            raise GateError("DTB contains forbidden /chosen/bootargs")
        if chosen_bootargs != expectations.chosen_bootargs:
            raise GateError("DTB /chosen/bootargs does not match its trusted expectation")
        if "debug-shell" in chosen_bootargs:
            raise GateError("DTB /chosen/bootargs enables a debug shell")
    elif expectations.chosen_bootargs is not None:
        raise GateError("DTB is missing expected /chosen/bootargs")
    return {
        "chosen_bootargs": chosen_bootargs,
        "compatible": list(compatible),
        "last_compatible_version": last_compatible,
        "model": model,
        "sha256_expectation": expectations.dtb_sha256,
        "strings_size": size_strings,
        "structure_size": size_struct,
        "totalsize": totalsize,
        "version": version,
    }


def _gunzip_bounded(value: bytes) -> bytes:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    pending = value
    try:
        while pending:
            block = inflater.decompress(pending, _MAX_INITRAMFS_OUTPUT - len(output) + 1)
            output.extend(block)
            if len(output) > _MAX_INITRAMFS_OUTPUT:
                raise GateError("initramfs exceeds the 256 MiB decompression bound")
            if inflater.eof:
                if inflater.unused_data:
                    raise GateError("initramfs gzip has trailing or concatenated data")
                pending = b""
            else:
                next_pending = inflater.unconsumed_tail
                if next_pending == pending and not block:
                    raise GateError("initramfs gzip decompressor made no progress")
                pending = next_pending
        flushed = inflater.flush(_MAX_INITRAMFS_OUTPUT - len(output) + 1)
        output.extend(flushed)
    except zlib.error as error:
        raise GateError(f"initramfs gzip is invalid: {error}") from None
    if len(output) > _MAX_INITRAMFS_OUTPUT:
        raise GateError("initramfs exceeds the 256 MiB decompression bound")
    if not inflater.eof or inflater.unused_data:
        raise GateError("initramfs gzip stream is incomplete or has trailing data")
    return bytes(output)


def _parse_hex(field: bytes, label: str) -> int:
    if len(field) != 8 or re.fullmatch(rb"[0-9A-Fa-f]{8}", field) is None:
        raise GateError(f"newc {label} is not eight hexadecimal digits")
    return int(field, 16)


def _cpio_name(value: bytes) -> str:
    try:
        raw = value.decode("utf-8")
    except UnicodeError:
        raise GateError("newc member name is not UTF-8") from None
    if raw == ".":
        return "."
    while raw.startswith("./"):
        raw = raw[2:]
    path = PurePosixPath(raw)
    if (
        not raw
        or raw.startswith("/")
        or path.is_absolute()
        or any(part in {"", ".", ".."} for part in path.parts)
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw)
    ):
        raise GateError("newc archive contains an unsafe member name")
    return path.as_posix()


def _cpio_link_target(name: str, value: bytes | memoryview) -> str:
    try:
        raw = bytes(value).decode("utf-8")
    except UnicodeError:
        raise GateError(f"newc symlink target is not UTF-8: {name}") from None
    if (
        not raw
        or "\0" in raw
        or raw.startswith("//")
        or "//" in raw
        or raw.endswith("/")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw)
    ):
        raise GateError(f"newc symlink target is unsafe: {name}")
    raw_parts = raw.split("/")
    if raw.startswith("/"):
        raw_parts.pop(0)
    if any(part in {"", "."} for part in raw_parts):
        raise GateError(f"newc symlink target is unsafe: {name}")
    parts = [] if raw.startswith("/") else list(PurePosixPath(name).parent.parts)
    for part in raw_parts:
        if part == "..":
            if not parts:
                raise GateError(f"newc symlink target escapes the archive: {name}")
            parts.pop()
        else:
            parts.append(part)
    if not parts:
        raise GateError(f"newc symlink target is unsafe: {name}")
    return PurePosixPath(*parts).as_posix()


def _resolve_cpio_member(members: Mapping[str, _CpioMember], name: str) -> _CpioMember:
    seen: set[tuple[str, tuple[str, ...]]] = set()
    pending = list(PurePosixPath(name).parts)
    resolved: list[str] = []
    symlink_depth = 0
    member: _CpioMember | None = None
    while pending:
        resolved.append(pending.pop(0))
        current = PurePosixPath(*resolved).as_posix()
        state = (current, tuple(pending))
        if state in seen:
            raise GateError(f"required initramfs utility has a symlink loop: {name}")
        seen.add(state)
        member = members.get(current)
        if member is None:
            raise GateError(f"required initramfs utility has a dangling symlink: {name}")
        file_type = stat.S_IFMT(member.mode)
        if file_type == stat.S_IFLNK:
            symlink_depth += 1
            if symlink_depth > _MAX_CPIO_SYMLINK_DEPTH:
                raise GateError(
                    f"required initramfs utility exceeds symlink depth 64: {name}"
                )
            target = _cpio_link_target(current, member.data)
            pending = [*PurePosixPath(target).parts, *pending]
            resolved = []
        elif pending and file_type != stat.S_IFDIR:
            raise GateError(
                f"required initramfs utility traverses a non-directory: {name}"
            )
    if member is None:  # Defensive: callers supply only nonempty required paths.
        raise GateError(f"required initramfs utility has an empty path: {name}")
    return member


def _validate_cpio_ancestry(
    name: str, file_type: int, members: Mapping[str, _CpioMember]
) -> None:
    if name == ".":
        if members or file_type != stat.S_IFDIR:
            raise GateError("newc archive root must be its first directory member")
        return
    root = members.get(".")
    if root is None or stat.S_IFMT(root.mode) != stat.S_IFDIR:
        raise GateError("newc archive is missing its leading root directory")
    parts = PurePosixPath(name).parts[:-1]
    current: list[str] = []
    for part in parts:
        current.append(part)
        parent_name = PurePosixPath(*current).as_posix()
        parent = members.get(parent_name)
        if parent is None:
            raise GateError(f"newc member appears before its parent directory: {name}")
        if stat.S_IFMT(parent.mode) != stat.S_IFDIR:
            raise GateError(f"newc member has a non-directory or symlink parent: {name}")


def _parse_newc(value: bytes) -> dict[str, _CpioMember]:
    cursor = 0
    members: dict[str, _CpioMember] = {}
    saw_trailer = False
    cumulative_name_bytes = 0
    file_inodes: set[tuple[int, int, int]] = set()
    archive = memoryview(value)
    while cursor < len(value):
        if cursor > len(value) - 110:
            raise GateError("newc archive header is truncated")
        header = value[cursor : cursor + 110]
        if header[:6] not in {b"070701", b"070702"}:
            raise GateError("initramfs is not a complete newc CPIO archive")
        fields = [
            _parse_hex(header[offset : offset + 8], f"field {index}")
            for index, offset in enumerate(range(6, 110, 8), 1)
        ]
        ino = fields[0]
        mode = fields[1]
        uid = fields[2]
        gid = fields[3]
        nlink = fields[4]
        file_size = fields[6]
        name_size = fields[11]
        check = fields[12]
        devmajor = fields[7]
        devminor = fields[8]
        rdevmajor = fields[9]
        rdevminor = fields[10]
        if name_size < 2 or name_size > 4096:
            raise GateError("newc member name size is unsafe")
        cumulative_name_bytes += name_size
        if cumulative_name_bytes > _MAX_CPIO_NAME_BYTES:
            raise GateError("newc cumulative member names exceed 8 MiB")
        name_start = cursor + 110
        if name_size > len(value) - name_start:
            raise GateError("newc member name is truncated")
        encoded_name = value[name_start : name_start + name_size]
        if encoded_name[-1:] != b"\0" or b"\0" in encoded_name[:-1]:
            raise GateError("newc member name is not exactly NUL terminated")
        name = _cpio_name(encoded_name[:-1])
        data_start = _align_up(name_start + name_size, 4, len(value), "newc name")
        if any(value[name_start + name_size : data_start]):
            raise GateError("newc member name padding is not zero")
        if file_size > len(value) - data_start:
            raise GateError("newc member payload is truncated")
        data_end = data_start + file_size
        next_cursor = _align_up(data_end, 4, len(value), "newc payload")
        if any(value[data_end:next_cursor]):
            raise GateError("newc member payload padding is not zero")
        data = archive[data_start:data_end]
        if header[:6] == b"070702" and (sum(data) & 0xFFFFFFFF) != check:
            raise GateError("newc CRC member checksum mismatch")
        if header[:6] == b"070701" and check != 0:
            raise GateError("newc non-CRC member has a nonzero checksum")
        if name == "TRAILER!!!":
            if file_size != 0 or mode != 0 or nlink not in {0, 1}:
                raise GateError("newc trailer is malformed")
            if any(value[next_cursor:]):
                raise GateError("newc archive has nonzero bytes after its trailer")
            saw_trailer = True
            cursor = len(value)
            break
        if name in members:
            raise GateError(f"newc archive contains duplicate member: {name}")
        if len(members) >= _MAX_CPIO_MEMBERS:
            raise GateError("newc archive exceeds 65536 members")
        file_type = stat.S_IFMT(mode)
        if file_type not in {stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK}:
            raise GateError(f"newc archive contains an unsafe file type: {name}")
        if file_type == stat.S_IFREG and nlink > 1:
            raise GateError(f"newc archive contains an unmodeled hardlink: {name}")
        expected_nlink = 1 if file_type == stat.S_IFREG else 0
        if nlink != expected_nlink:
            raise GateError(f"newc member has a non-canonical link count: {name}")
        if uid != 0 or gid != 0 or rdevmajor != 0 or rdevminor != 0:
            raise GateError(f"newc member ownership or device fields are unsafe: {name}")
        inode_key = (devmajor, devminor, ino)
        if inode_key in file_inodes:
            raise GateError(f"newc archive aliases an inode without a hardlink model: {name}")
        file_inodes.add(inode_key)
        if file_type == stat.S_IFDIR and file_size != 0:
            raise GateError(f"newc directory has a payload: {name}")
        if file_type == stat.S_IFLNK:
            link_data = bytes(data)
            if not link_data or b"\0" in link_data or len(link_data) > 4096:
                raise GateError(f"newc symlink payload is unsafe: {name}")
            _cpio_link_target(name, link_data)
        _validate_cpio_ancestry(name, file_type, members)
        members[name] = _CpioMember(
            mode=mode,
            data=data,
            ino=ino,
            devmajor=devmajor,
            devminor=devminor,
            nlink=nlink,
        )
        cursor = next_cursor
    if not saw_trailer:
        raise GateError("newc archive is missing TRAILER!!!")
    for name in _REQUIRED_INITRAMFS:
        resolved = _resolve_cpio_member(members, name)
        if stat.S_IFMT(resolved.mode) != stat.S_IFREG or not resolved.data:
            raise GateError(f"required initramfs utility is not a nonempty file: {name}")
        if name in {
            "bin/busybox",
            "init",
            "init_2nd.sh",
            "sbin/blkid",
            "usr/sbin/losetup",
        } and not resolved.mode & 0o111:
            raise GateError(f"required initramfs utility is not executable: {name}")
    for name in ("init", "init_2nd.sh", "init_functions.sh"):
        if stat.S_IFMT(members[name].mode) != stat.S_IFREG or not members[name].data:
            raise GateError(f"required initramfs member is not a nonempty regular file: {name}")
    return members


def _initramfs_inventory(
    members: Mapping[str, _CpioMember],
) -> tuple[InitramfsManifestEntry, ...]:
    result: list[InitramfsManifestEntry] = []
    for name, member in members.items():
        file_type = stat.S_IFMT(member.mode)
        if file_type == stat.S_IFREG:
            kind = "file"
            target = None
        elif file_type == stat.S_IFDIR:
            kind = "directory"
            target = None
        elif file_type == stat.S_IFLNK:
            kind = "symlink"
            # Record the literal target as well as validating its logical resolution.
            try:
                target = bytes(member.data).decode("utf-8")
            except UnicodeError:
                raise GateError(f"newc symlink target is not UTF-8: {name}") from None
        else:  # Already rejected by _parse_newc; keep this helper fail closed.
            raise GateError(f"newc archive contains an unsafe file type: {name}")
        result.append(
            InitramfsManifestEntry(
                path=name,
                type=kind,
                mode=stat.S_IMODE(member.mode),
                size=len(member.data),
                sha256=hashlib.sha256(member.data).hexdigest(),
                link_target=target,
            )
        )
    return tuple(sorted(result))


def calibrate_initramfs_manifest(initramfs: Path) -> tuple[InitramfsManifestEntry, ...]:
    """Inventory an initramfs for human audit; never marks an artifact releasable."""

    compressed = _read_small(Path(initramfs), "calibration initramfs", _MAX_SMALL_INPUT)
    return _initramfs_inventory(_parse_newc(_gunzip_bounded(compressed)))


def load_initramfs_manifest(path: Path) -> tuple[InitramfsManifestEntry, ...]:
    """Load the one canonical, complete initramfs inventory approved for P1."""

    payload = _read_small(
        Path(path),
        "committed initramfs manifest",
        _MAX_INITRAMFS_MANIFEST_BYTES,
    )

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise GateError(f"initramfs manifest contains duplicate key: {key!r}")
            result[key] = value
        return result

    try:
        decoded = payload.decode("ascii")
        value = json.loads(decoded, object_pairs_hook=reject_duplicates)
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"initramfs manifest is not strict ASCII JSON: {error}") from None
    try:
        canonical = (
            json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("ascii")
    except (TypeError, ValueError) as error:
        raise GateError(f"initramfs manifest is not canonical JSON data: {error}") from None
    if canonical != payload:
        raise GateError("initramfs manifest bytes are not canonical")
    if not isinstance(value, dict) or set(value) != {"schema", "entries"}:
        raise GateError("initramfs manifest has unexpected or missing top-level fields")
    if value["schema"] != _INITRAMFS_MANIFEST_SCHEMA:
        raise GateError("initramfs manifest schema mismatch")
    raw_entries = value["entries"]
    if not isinstance(raw_entries, list) or not raw_entries:
        raise GateError("initramfs manifest entries must be one nonempty array")
    if len(raw_entries) > _MAX_CPIO_MEMBERS:
        raise GateError("initramfs manifest contains too many entries")
    entries: list[InitramfsManifestEntry] = []
    expected_fields = {"path", "type", "mode", "size", "sha256", "link_target"}
    for index, raw in enumerate(raw_entries):
        if not isinstance(raw, dict) or set(raw) != expected_fields:
            raise GateError(
                f"initramfs manifest entry {index} has unexpected or missing fields"
            )
        if type(raw["mode"]) is not int or type(raw["size"]) is not int:
            raise GateError(f"initramfs manifest entry {index} has non-integer metadata")
        try:
            entry = InitramfsManifestEntry(
                path=raw["path"],
                type=raw["type"],
                mode=raw["mode"],
                size=raw["size"],
                sha256=raw["sha256"],
                link_target=raw["link_target"],
            )
        except TypeError:
            raise GateError(f"initramfs manifest entry {index} has invalid value types") from None
        entries.append(entry)
    result = tuple(entries)
    if tuple(sorted(result)) != result or len({entry.path for entry in result}) != len(result):
        raise GateError("initramfs manifest entries must be sorted and path-unique")
    return result


@dataclass(frozen=True)
class _ToolResult:
    returncode: int
    output: bytes


def _limit_tool_process() -> None:
    # stdout and stderr each get half of the aggregate output allowance.
    per_file = _MAX_TOOL_OUTPUT // 2
    resource.setrlimit(resource.RLIMIT_FSIZE, (per_file, per_file))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def _run_tool(
    binary: Path,
    arguments: Sequence[str],
    label: str,
    work: Path,
    timeout: int,
) -> _ToolResult:
    """Run one exact binary with bounded file-backed output and a deadline."""

    stdout_path = work / f"{label}.stdout"
    stderr_path = work / f"{label}.stderr"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    stdout_fd: int | None = None
    stderr_fd: int | None = None
    process: subprocess.Popen[bytes] | None = None
    try:
        stdout_fd = os.open(stdout_path, flags, 0o600)
        stderr_fd = os.open(stderr_path, flags, 0o600)
        process = subprocess.Popen(
            [str(binary), *arguments],
            stdin=subprocess.DEVNULL,
            stdout=stdout_fd,
            stderr=stderr_fd,
            cwd=work,
            env={
                "E2FSCK_CONFIG": "/dev/null",
                "HOME": str(work),
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "TMPDIR": str(work),
            },
            close_fds=True,
            preexec_fn=_limit_tool_process,
            start_new_session=True,
        )
        try:
            returncode = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()
            raise GateError(f"{label} exceeded its validation deadline") from None
    except OSError as error:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait()
        raise _os_failure("execute", label, error) from None
    finally:
        if stdout_fd is not None:
            _close_descriptor(stdout_fd)
        if stderr_fd is not None:
            _close_descriptor(stderr_fd)
    try:
        stdout_size = stdout_path.stat().st_size
        stderr_size = stderr_path.stat().st_size
    except OSError as error:
        raise _os_failure("inspect output from", label, error) from None
    if stdout_size + stderr_size > _MAX_TOOL_OUTPUT:
        raise GateError(f"{label} output exceeds the 1 MiB validation bound")
    try:
        output = stdout_path.read_bytes() + stderr_path.read_bytes()
    except OSError as error:
        raise _os_failure("read output from", label, error) from None
    return _ToolResult(returncode=returncode, output=output)


def _validate_toolchain(
    expectations: ArtifactExpectations, work: Path
) -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for binary, label, expected_hash in (
        (_E2FSCK, "e2fsck-version", expectations.e2fsck_sha256),
        (_DEBUGFS, "debugfs-version", expectations.debugfs_sha256),
    ):
        try:
            metadata = binary.lstat()
        except OSError as error:
            raise _os_failure("inspect", label[:-8], error) from None
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expectations.tool_uid
            or metadata.st_gid != expectations.tool_gid
            or stat.S_IMODE(metadata.st_mode) != expectations.tool_mode
        ):
            raise GateError(f"{label[:-8]} binary ownership or mode does not match its trusted pin")
        value = _read_small(binary, label, 64 * 1024 * 1024)
        actual_hash = _sha256(value)
        if actual_hash != expected_hash:
            raise GateError(f"{label[:-8]} binary sha256 does not match its trusted pin")
        run = _run_tool(binary, ["-V"], label, work, _DEBUGFS_TIMEOUT_SECONDS)
        if run.returncode != 0:
            raise GateError(f"{label[:-8]} version command failed")
        tool_name = "e2fsck" if binary == _E2FSCK else "debugfs"
        if re.search(
            rb"(?:^|\n)" + tool_name.encode("ascii") + rb" "
            + re.escape(expectations.e2fsprogs_version.encode("ascii"))
            + rb"(?: |\()",
            run.output,
        ) is None:
            raise GateError(f"{tool_name} version does not match its trusted pin")
        result[tool_name] = {
            "absolute_path": str(binary),
            "gid": metadata.st_gid,
            "mode": stat.S_IMODE(metadata.st_mode),
            "sha256": actual_hash,
            "uid": metadata.st_uid,
            "version": expectations.e2fsprogs_version,
        }
    return result


def _extract_partition(
    reader: _ImageReader, partition: _Partition, destination: Path
) -> str:
    """Copy one partition to a private sparse file without mounting or loop devices."""

    offset = partition.first_lba * _PAGE_SIZE
    size = (partition.last_lba - partition.first_lba + 1) * _PAGE_SIZE
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor: int | None = None
    digest = hashlib.sha256()
    try:
        descriptor = os.open(destination, flags, 0o600)
        os.ftruncate(descriptor, size)
        cursor = 0
        while cursor < size:
            amount = min(_COPY_CHUNK, size - cursor)
            block = reader.pread(amount, offset + cursor, f"{partition.name} partition")
            digest.update(block)
            if any(block):
                written = os.pwrite(descriptor, block, cursor)
                if written != len(block):
                    raise GateError(f"short write while extracting {partition.name}")
            cursor += amount
        os.fsync(descriptor)
    except OSError as error:
        raise _os_failure("extract", partition.name, error) from None
    finally:
        if descriptor is not None:
            _close_descriptor(descriptor)
    return digest.hexdigest()


def _debugfs_stat(
    image: Path, internal_path: str, label: str, work: Path
) -> tuple[str, int, int, int, int, int, str | None]:
    run = _run_tool(
        _DEBUGFS,
        ["-R", f"stat {internal_path}", str(image)],
        label,
        work,
        _DEBUGFS_TIMEOUT_SECONDS,
    )
    if run.returncode != 0:
        raise GateError(f"debugfs failed while inspecting {label}")
    header = re.search(
        rb"Inode:\s+[0-9]+\s+Type:\s+([a-z]+)\s+Mode:\s+([0-7]{4})\b",
        run.output,
    )
    size = re.search(rb"(?:^|\n).*?\bSize:\s+([0-9]+)\b", run.output)
    links = re.search(rb"(?:^|\n)Links:\s+([0-9]+)\b", run.output)
    owner = re.search(rb"(?:^|\n)User:\s+([0-9]+)\s+Group:\s+([0-9]+)\b", run.output)
    if header is None or size is None or links is None or owner is None:
        raise GateError(f"debugfs returned malformed stat data for {label}")
    target_match = re.search(rb'Fast link dest:\s+"([^"\r\n]+)"', run.output)
    try:
        target = target_match.group(1).decode("utf-8") if target_match else None
    except UnicodeError:
        raise GateError(f"debugfs returned an invalid symlink target for {label}") from None
    return (
        header.group(1).decode("ascii"),
        int(header.group(2), 8),
        int(size.group(1)),
        int(links.group(1)),
        int(owner.group(1)),
        int(owner.group(2)),
        target,
    )


def _debugfs_extract_regular(
    image: Path,
    internal_path: str,
    expected: bytes,
    expected_mode: int,
    maximum: int,
    expected_uid: int,
    expected_gid: int,
    label: str,
    work: Path,
) -> dict[str, object]:
    kind, mode, size, links, uid, gid, target = _debugfs_stat(
        image, internal_path, f"debugfs-stat-{label}", work
    )
    if kind != "regular" or target is not None or links != 1:
        raise GateError(f"root filesystem {internal_path} is not one regular inode")
    if mode != expected_mode:
        raise GateError(f"root filesystem {internal_path} mode is not {expected_mode:04o}")
    if uid != expected_uid or gid != expected_gid:
        raise GateError(f"root filesystem {internal_path} ownership differs from its trusted input")
    if size != len(expected) or size <= 0 or size > maximum:
        raise GateError(f"root filesystem {internal_path} size differs from its trusted input")
    destination = work / f"root-file-{label}"
    run = _run_tool(
        _DEBUGFS,
        ["-R", f"dump -p {internal_path} {destination}", str(image)],
        f"debugfs-dump-{label}",
        work,
        _DEBUGFS_TIMEOUT_SECONDS,
    )
    if run.returncode != 0:
        raise GateError(f"debugfs failed while extracting {label}")
    extracted = _read_small(destination, f"extracted root file {label}", maximum + 1)
    if extracted != expected:
        raise GateError(f"root filesystem {internal_path} differs from its trusted input")
    return {
        "mode": mode,
        "gid": gid,
        "sha256": _sha256(extracted),
        "size": size,
        "type": kind,
        "uid": uid,
    }


def _validate_ssh_policy(config: bytes, authorized_keys: bytes) -> None:
    try:
        text = config.decode("utf-8")
        keys = authorized_keys.decode("utf-8")
    except UnicodeError:
        raise GateError("SSH policy inputs are not UTF-8") from None
    directives: dict[str, list[str]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        key = fields[0].lower()
        if key in directives or len(fields) < 2:
            raise GateError("sshd_config policy is duplicated or malformed")
        directives[key] = fields[1:]
    required = {
        "permitrootlogin": ["no"],
        "pubkeyauthentication": ["yes"],
        "passwordauthentication": ["no"],
        "kbdinteractiveauthentication": ["no"],
        "authenticationmethods": ["publickey"],
        "authorizedkeysfile": [".ssh/authorized_keys"],
        "allowusers": ["lmi"],
        "usepam": ["yes"],
    }
    for key, expected in required.items():
        actual = directives.get(key)
        if actual is None or [item.lower() for item in actual] != [
            item.lower() for item in expected
        ]:
            raise GateError(f"sshd_config does not enforce the required {key} policy")
    key_lines = [line.strip() for line in keys.splitlines() if line.strip()]
    if len(key_lines) != 1 or key_lines[0].startswith(("#", "-----BEGIN")):
        raise GateError("authorized_keys must contain exactly one public key")
    key_fields = key_lines[0].split()
    if len(key_fields) not in {2, 3} or key_fields[0] != "ssh-ed25519":
        raise GateError("authorized_keys does not contain an allowed Ed25519 public key")
    try:
        blob = base64.b64decode(key_fields[1], validate=True)
    except (ValueError, binascii.Error):
        raise GateError("authorized_keys public key encoding is invalid") from None
    if len(blob) < 8:
        raise GateError("authorized_keys public key blob is truncated")
    algorithm_size = struct.unpack_from(">I", blob, 0)[0]
    if algorithm_size > len(blob) - 8:
        raise GateError("authorized_keys public key blob is malformed")
    algorithm_end = 4 + algorithm_size
    key_size = struct.unpack_from(">I", blob, algorithm_end)[0]
    key_blob = blob[algorithm_end + 4 :]
    if (
        blob[4:algorithm_end] != key_fields[0].encode("ascii")
        or key_size != len(key_blob)
        or key_size != 32
    ):
        raise GateError("authorized_keys public key blob does not match its key type")


def _validate_dhcp_package_policy(installed: bytes) -> None:
    try:
        text = installed.decode("utf-8")
    except UnicodeError:
        raise GateError("trusted APK database is not UTF-8") from None
    packages: dict[str, tuple[str | None, set[str]]] = {}
    for block in re.split(r"\n\s*\n", text.strip()):
        name: str | None = None
        architecture: str | None = None
        directory: PurePosixPath | None = None
        files: set[str] = set()
        for line in block.splitlines():
            if line.startswith("P:"):
                if name is not None:
                    raise GateError("trusted APK database has a duplicate package name field")
                name = line[2:]
            elif line.startswith("A:"):
                if architecture is not None:
                    raise GateError("trusted APK database has a duplicate architecture field")
                architecture = line[2:]
            elif line.startswith("F:"):
                directory = PurePosixPath(line[2:])
            elif line.startswith("R:"):
                member = PurePosixPath(line[2:])
                if directory is None or len(member.parts) != 1:
                    raise GateError("trusted APK database has malformed file ownership")
                files.add("/" + (directory / member).as_posix())
        if name is None or not name or name in packages:
            raise GateError("trusted APK database has malformed or duplicate packages")
        packages[name] = (architecture, files)
    for name in ("openssh-server-pam", "unudhcpd", "unudhcpd-openrc"):
        if name not in packages:
            raise GateError(f"trusted APK database does not contain {name}")
    if packages["unudhcpd"][0] != "aarch64":
        raise GateError("trusted unudhcpd package is not aarch64")
    owners = {
        path: sorted(name for name, (_arch, files) in packages.items() if path in files)
        for path in ("/usr/bin/unudhcpd", "/etc/init.d/unudhcpd")
    }
    if owners["/usr/bin/unudhcpd"] != ["unudhcpd"]:
        raise GateError("trusted APK database has a second unudhcpd binary owner")
    if owners["/etc/init.d/unudhcpd"] != ["unudhcpd-openrc"]:
        raise GateError("trusted APK database has a noncanonical unudhcpd OpenRC owner")
    forbidden = sorted(
        {
            "dhcp",
            "dhcp-server",
            "dnsmasq",
            "dnsmasq-dnssec",
            "dnsmasq-dnssec-dbus",
            "kea-dhcp4",
            "networkmanager-dnsmasq",
            "udhcpd",
        }
        & set(packages)
    )
    if forbidden:
        raise GateError(f"trusted APK database has a second DHCP owner: {forbidden!r}")


def _validate_management_policy(trusted: Mapping[str, bytes]) -> None:
    exact = {
        "networkmanager_profile": _EXPECTED_NETWORKMANAGER_PROFILE,
        "networkmanager_takeover": _EXPECTED_NETWORKMANAGER_TAKEOVER,
        "unudhcpd_config": _EXPECTED_UNUDHCPD_CONFIG,
        "usb_dhcp_wrapper": _EXPECTED_USB_DHCP_WRAPPER,
        "usb_dhcp_service": _EXPECTED_USB_DHCP_SERVICE,
    }
    for key, expected in exact.items():
        if trusted[key] != expected:
            raise GateError(f"trusted {key} does not match the fixed lmi USB policy")
    forbidden = (b"method=shared", b"shared-dhcp-range", b"iptables", b"nft ")
    custom_policy = b"\n".join(exact.values())
    if any(marker in custom_policy for marker in forbidden):
        raise GateError("lmi USB policy contains shared-mode or NAT configuration")
    binary = trusted["unudhcpd"]
    if (
        len(binary) < 20
        or binary[:7] != b"\x7fELF\x02\x01\x01"
        or int.from_bytes(binary[18:20], "little") != 183
    ):
        raise GateError("trusted unudhcpd is not an AArch64 ELF executable")
    if not trusted["unudhcpd_service"].startswith(b"#!/sbin/openrc-run\n"):
        raise GateError("trusted unudhcpd OpenRC service is not canonical")
    _validate_dhcp_package_policy(trusted["apk_installed"])


def _debugfs_validate_symlink(
    image: Path,
    internal_path: str,
    expected_target: str,
    label: str,
    work: Path,
) -> dict[str, object]:
    kind, mode, size, links, uid, gid, target = _debugfs_stat(
        image, internal_path, f"debugfs-stat-{label}", work
    )
    if (
        kind != "symlink"
        or mode != 0o777
        or links != 1
        or size != len(expected_target)
        or target != expected_target
        or (uid, gid) != (0, 0)
    ):
        raise GateError(f"root filesystem {internal_path} symlink is not canonical")
    return {
        "link_target": target,
        "mode": mode,
        "gid": gid,
        "size": size,
        "type": kind,
        "uid": uid,
    }


def _debugfs_require_absent(
    image: Path, internal_path: str, label: str, work: Path
) -> None:
    run = _run_tool(
        _DEBUGFS,
        ["-R", f"stat {internal_path}", str(image)],
        f"debugfs-absent-{label}",
        work,
        _DEBUGFS_TIMEOUT_SECONDS,
    )
    if re.search(rb"Inode:\s+[0-9]+\s+Type:", run.output) is not None:
        raise GateError(f"root filesystem has a second DHCP runlevel owner: {internal_path}")
    if b"File not found" not in run.output:
        raise GateError(f"debugfs could not prove {internal_path} absent")


def _validate_rootfs_files(
    root_image: Path,
    trusted: Mapping[str, bytes],
    trusted_owners: Mapping[str, tuple[int, int]],
    work: Path,
) -> dict[str, object]:
    _validate_ssh_policy(trusted["sshd_config"], trusted["authorized_keys"])
    _validate_management_policy(trusted)
    if not trusted["sshd_service"].startswith(b"#!"):
        raise GateError("trusted sshd service is not a script")
    if not trusted["sshd_pam"].startswith(b"\x7fELF"):
        raise GateError("trusted sshd.pam is not an ELF executable")
    if not trusted["release_identity"].startswith(
        b"schema=lmi-p1-release-identity/v2\n"
    ):
        raise GateError("trusted release identity has the wrong schema")
    files: dict[str, object] = {}
    for internal_path, key, mode, maximum in _ROOTFS_FILE_SPECS:
        files[internal_path] = _debugfs_extract_regular(
            root_image,
            internal_path,
            trusted[key],
            mode,
            maximum,
            trusted_owners[key][0],
            trusted_owners[key][1],
            key.replace("_", "-"),
            work,
        )
    symlinks = {
        "/etc/init.d/unudhcpd.usb0": "unudhcpd",
        "/etc/runlevels/default/networkmanager": "/etc/init.d/networkmanager",
        "/etc/runlevels/default/lmi-usb0-dhcp": "/etc/init.d/lmi-usb0-dhcp",
        "/etc/runlevels/default/sshd": "/etc/init.d/sshd",
    }
    for internal_path, target in symlinks.items():
        label = internal_path.strip("/").replace("/", "-").replace(".", "-")
        files[internal_path] = _debugfs_validate_symlink(
            root_image, internal_path, target, label, work
        )
    for forbidden_path in (
        "/etc/runlevels/default/unudhcpd",
        "/etc/runlevels/default/unudhcpd.usb0",
        "/etc/runlevels/default/dnsmasq",
        "/etc/runlevels/default/dhcpd",
        "/etc/runlevels/default/kea-dhcp4",
    ):
        _debugfs_require_absent(
            root_image,
            forbidden_path,
            forbidden_path.rsplit("/", 1)[-1].replace(".", "-"),
            work,
        )
    return files


def _parse_gpt_header(block: bytes, expected_lba: int, image_lbas: int, label: str) -> _GptHeader:
    if len(block) != _PAGE_SIZE or block[:8] != b"EFI PART":
        raise GateError(f"{label} GPT header magic mismatch")
    revision, header_size, stored_crc, reserved = struct.unpack_from("<IIII", block, 8)
    if revision != 0x00010000 or header_size != _GPT_HEADER_SIZE or reserved != 0:
        raise GateError(f"{label} GPT header fields are non-canonical")
    if any(block[header_size:]):
        raise GateError(f"{label} GPT header padding is not zero")
    checked = bytearray(block[:header_size])
    checked[16:20] = b"\0" * 4
    if binascii.crc32(checked) & 0xFFFFFFFF != stored_crc:
        raise GateError(f"{label} GPT header CRC mismatch")
    current, backup, first, last = struct.unpack_from("<QQQQ", block, 24)
    if current != expected_lba or backup >= image_lbas or current == backup:
        raise GateError(f"{label} GPT current/backup pointers are invalid")
    disk_guid = uuid.UUID(bytes_le=block[56:72])
    entries_lba = _u64le(block, 72)
    entry_count, entry_size, entries_crc = struct.unpack_from("<III", block, 80)
    if (
        disk_guid.int == 0
        or disk_guid.version != 4
        or disk_guid.variant != uuid.RFC_4122
    ):
        raise GateError(f"{label} GPT disk GUID is not RFC v4")
    if not 2 <= entry_count <= _MAX_GPT_ENTRIES or entry_size != _GPT_ENTRY_SIZE:
        raise GateError(f"{label} GPT entry geometry is unsupported")
    table_bytes = entry_count * entry_size
    table_lbas = (table_bytes + _PAGE_SIZE - 1) // _PAGE_SIZE
    if entries_lba >= image_lbas or table_lbas > image_lbas - entries_lba:
        raise GateError(f"{label} GPT entry array is out of range")
    if first > last or first < 2 or last >= image_lbas:
        raise GateError(f"{label} GPT usable LBA range is invalid")
    return _GptHeader(
        current_lba=current,
        backup_lba=backup,
        first_usable_lba=first,
        last_usable_lba=last,
        disk_guid=disk_guid,
        entries_lba=entries_lba,
        entry_count=entry_count,
        entry_size=entry_size,
        entries_crc32=entries_crc,
    )


def _read_gpt_table(reader: _ImageReader, header: _GptHeader, label: str) -> bytes:
    table_size = header.entry_count * header.entry_size
    table = reader.pread(table_size, header.entries_lba * _PAGE_SIZE, f"{label} GPT table")
    if binascii.crc32(table) & 0xFFFFFFFF != header.entries_crc32:
        raise GateError(f"{label} GPT entry-array CRC mismatch")
    return table


def _parse_partitions(
    table: bytes, header: _GptHeader, expectations: ArtifactExpectations
) -> list[_Partition]:
    result: list[_Partition] = []
    for index in range(header.entry_count):
        entry = table[index * header.entry_size : (index + 1) * header.entry_size]
        type_guid = uuid.UUID(bytes_le=entry[:16])
        if type_guid.int == 0:
            if any(entry):
                raise GateError("unused GPT entry contains nonzero data")
            continue
        unique_guid = uuid.UUID(bytes_le=entry[16:32])
        first, last, attributes = struct.unpack_from("<QQQ", entry, 32)
        try:
            name = entry[56:128].decode("utf-16-le").split("\0", 1)[0]
        except UnicodeError:
            raise GateError("GPT partition name is not valid UTF-16LE") from None
        encoded_name = name.encode("utf-16-le") + b"\0\0"
        if entry[56 : 56 + len(encoded_name)] != encoded_name or any(
            entry[56 + len(encoded_name) : 128]
        ):
            raise GateError("GPT partition name is not canonically terminated")
        if (
            unique_guid.int == 0
            or unique_guid.version != 4
            or unique_guid.variant != uuid.RFC_4122
            or first > last
        ):
            raise GateError("GPT partition has a non-v4 GUID or inverted range")
        if first < header.first_usable_lba or last > header.last_usable_lba:
            raise GateError("GPT partition lies outside the usable range")
        result.append(_Partition(type_guid, unique_guid, first, last, attributes, name))
    if len(result) != 2:
        raise GateError("GPT must contain exactly two populated entries")
    if len({partition.unique_guid for partition in result}) != 2:
        raise GateError("GPT partition unique GUIDs are not unique")
    if header.disk_guid in {partition.unique_guid for partition in result}:
        raise GateError("GPT disk and partition GUIDs are not unique")
    ordered = sorted(result, key=lambda partition: partition.first_lba)
    if ordered[0].last_lba >= ordered[1].first_lba:
        raise GateError("GPT partitions overlap")
    if result != ordered:
        raise GateError("GPT populated entries are not in ascending partition order")
    for index, (partition, type_guid, expected_name) in enumerate(
        zip(
            result,
            (_ESP_GUID, _ARM64_ROOT_GUID),
            expectations.gpt_partition_names,
        ),
        1,
    ):
        if partition.type_guid != type_guid:
            raise GateError(f"GPT partition type mismatch for entry {index}")
        if partition.name != expected_name:
            raise GateError(f"GPT partition name mismatch for entry {index}")
        if partition.attributes != 0:
            raise GateError(f"GPT partition attributes are nonzero for entry {index}")
    return result


def _validate_mbr(reader: _ImageReader, image_lbas: int) -> None:
    sector = reader.pread(512, 0, "protective MBR")
    if sector[510:512] != b"\x55\xaa":
        raise GateError("protective MBR signature mismatch")
    if any(sector[:446]):
        raise GateError("protective MBR bootstrap area is not zero")
    entries = [sector[446 + index * 16 : 462 + index * 16] for index in range(4)]
    populated = [entry for entry in entries if any(entry)]
    if len(populated) != 1:
        raise GateError("protective MBR must contain exactly one partition entry")
    entry = populated[0]
    start_lba, sectors = struct.unpack_from("<II", entry, 8)
    expected_sectors = min(image_lbas - 1, 0xFFFFFFFF)
    if (
        entry[0] != 0
        or entry[1:4] != b"\x00\x02\x00"
        or entry[4] != 0xEE
        or entry[5:8] != b"\xff\xff\xff"
        or start_lba != 1
        or sectors != expected_sectors
    ):
        raise GateError("protective MBR partition entry is invalid")
    if any(reader.pread(_PAGE_SIZE - 512, 512, "protective MBR padding")):
        raise GateError("protective MBR 4096-byte LBA padding is not zero")


def _validate_superblock(
    reader: _ImageReader,
    partition: _Partition,
    expected_kind: str,
    expected_masks: tuple[int, int, int],
) -> dict[str, int | str | bool]:
    filesystem_label = "pmOS_boot" if expected_kind == "ext2" else "pmOS_root"
    partition_bytes = (partition.last_lba - partition.first_lba + 1) * _PAGE_SIZE
    if partition_bytes < 2048:
        raise GateError(f"{partition.name} is too small for an ext superblock")
    superblock = reader.pread(
        1024, partition.first_lba * _PAGE_SIZE + 1024, f"{partition.name} superblock"
    )
    if struct.unpack_from("<H", superblock, 0x38)[0] != 0xEF53:
        raise GateError(f"{partition.name} ext superblock magic mismatch")
    state = struct.unpack_from("<H", superblock, 0x3A)[0]
    if state != 1:
        raise GateError(f"{partition.name} filesystem is not clean")
    log_block_size = _u32le(superblock, 0x18)
    if log_block_size > 6:
        raise GateError(f"{partition.name} ext block size is invalid")
    block_size = 1024 << log_block_size
    if block_size != _PAGE_SIZE:
        raise GateError(f"{partition.name} ext block size is not 4096 bytes")
    if _u32le(superblock, 0x48) != 0 or _u32le(superblock, 0x4C) != 1:
        raise GateError(f"{partition.name} ext creator/revision fields are non-canonical")
    incompat = _u32le(superblock, 0x60)
    ro_compat = _u32le(superblock, 0x64)
    compat = _u32le(superblock, 0x5C)
    if (compat, incompat, ro_compat) != expected_masks:
        raise GateError(f"{partition.name} ext feature masks do not match the exact allowlist")
    blocks = _u32le(superblock, 0x04)
    reserved_blocks = _u32le(superblock, 0x08)
    free_blocks = _u32le(superblock, 0x0C)
    inodes = _u32le(superblock, 0x00)
    free_inodes = _u32le(superblock, 0x10)
    first_data_block = _u32le(superblock, 0x14)
    blocks_per_group = _u32le(superblock, 0x20)
    inodes_per_group = _u32le(superblock, 0x28)
    inode_size = struct.unpack_from("<H", superblock, 0x58)[0]
    descriptor_size = struct.unpack_from("<H", superblock, 0xFE)[0]
    if incompat & _EXT_INCOMPAT_64BIT:
        blocks |= _u32le(superblock, 0x150) << 32
        reserved_blocks |= _u32le(superblock, 0x154) << 32
        free_blocks |= _u32le(superblock, 0x158) << 32
        if descriptor_size < 64 or descriptor_size % 8:
            raise GateError(f"{partition.name} has incoherent 64-bit group descriptors")
    elif any(superblock[offset : offset + 4] != b"\0" * 4 for offset in (0x150, 0x154, 0x158)):
        raise GateError(f"{partition.name} has high block counts without the 64-bit feature")
    if blocks <= 0 or blocks * block_size != partition_bytes:
        raise GateError(f"{partition.name} ext block geometry does not fill its GPT partition")
    if (
        reserved_blocks > blocks
        or free_blocks > blocks
        or not 0 < inodes
        or free_inodes > inodes
        or first_data_block >= blocks
        or not 0 < blocks_per_group <= 8 * block_size
        or not 0 < inodes_per_group
        or inode_size < 128
        or inode_size > block_size
        or inode_size & (inode_size - 1)
    ):
        raise GateError(f"{partition.name} ext block/inode geometry is incoherent")
    groups = (blocks - first_data_block + blocks_per_group - 1) // blocks_per_group
    if groups <= 0 or inodes != groups * inodes_per_group:
        raise GateError(f"{partition.name} ext inode-group geometry is incoherent")
    filesystem_uuid = uuid.UUID(bytes=superblock[0x68:0x78])
    if (
        filesystem_uuid.int == 0
        or filesystem_uuid.version != 4
        or filesystem_uuid.variant != uuid.RFC_4122
    ):
        raise GateError(f"{partition.name} filesystem UUID is not RFC v4")
    raw_label = superblock[0x78:0x88]
    label = raw_label.rstrip(b"\0")
    if b"\0" in label or any(raw_label[len(label) :]):
        raise GateError(f"{partition.name} filesystem label is malformed")
    try:
        decoded_label = label.decode("ascii")
    except UnicodeError:
        raise GateError(f"{partition.name} filesystem label is not ASCII") from None
    if decoded_label != filesystem_label:
        raise GateError(f"{partition.name} filesystem label mismatch")
    if incompat & _EXT_INCOMPAT_RECOVER:
        raise GateError(f"{partition.name} enables the ext RECOVER incompat feature")
    if incompat & _EXT_INCOMPAT_CSUM_SEED:
        raise GateError(f"{partition.name} enables the ext CSUM_SEED incompat feature")
    if ro_compat & _EXT_RO_COMPAT_METADATA_CSUM:
        raise GateError(f"{partition.name} enables unsupported ext metadata_csum")
    has_extents = bool(incompat & _EXT_INCOMPAT_EXTENTS)
    required_compat = expected_masks[0]
    required_incompat = expected_masks[1]
    required_ro_compat = expected_masks[2]
    forbidden_compat = (~expected_masks[0]) & 0xFFFFFFFF
    forbidden_incompat = _EXT_INCOMPAT_RECOVER | _EXT_INCOMPAT_CSUM_SEED
    forbidden_ro_compat = _EXT_RO_COMPAT_METADATA_CSUM
    if expected_kind == "ext2":
        if incompat & _EXT_INCOMPAT_EXTENTS or compat & _EXT_COMPAT_HAS_JOURNAL:
            raise GateError("pmOS_boot is not an ext2 filesystem")
    elif expected_kind == "ext4":
        # pmbootstrap formats this partition with mkfs.ext4; the upstream ext4
        # profile used by that command enables both HAS_JOURNAL and EXTENTS.
        if not compat & _EXT_COMPAT_HAS_JOURNAL:
            raise GateError("pmOS_root does not enable the ext4 journal feature")
        if not incompat & _EXT_INCOMPAT_EXTENTS:
            raise GateError("pmOS_root does not enable the ext4 extent feature")
    else:
        raise AssertionError(expected_kind)
    return {
        "block_size": block_size,
        "block_count": blocks,
        "clean": True,
        "extent": has_extents,
        "feature_masks": {
            "compat": compat,
            "forbidden_compat": forbidden_compat,
            "forbidden_incompat": forbidden_incompat,
            "forbidden_ro_compat": forbidden_ro_compat,
            "incompat": incompat,
            "required_compat": required_compat,
            "required_incompat": required_incompat,
            "required_ro_compat": required_ro_compat,
            "ro_compat": ro_compat,
        },
        "filesystem": expected_kind,
        "journal": bool(compat & _EXT_COMPAT_HAS_JOURNAL),
        "label": decoded_label,
        "metadata_csum": bool(ro_compat & _EXT_RO_COMPAT_METADATA_CSUM),
        "inode_count": inodes,
        "inode_size": inode_size,
        "uuid": str(filesystem_uuid),
    }


def _validate_userdata(
    reader: _ImageReader,
    expectations: ArtifactExpectations,
    trusted_rootfs: Mapping[str, bytes],
    trusted_rootfs_owners: Mapping[str, tuple[int, int]],
    work: Path,
) -> tuple[dict[str, object], str, str]:
    if reader.size % _PAGE_SIZE:
        raise GateError("userdata image size is not a multiple of 4096 bytes")
    if reader.size < expectations.minimum_userdata_bytes:
        raise GateError("userdata image is smaller than the trusted geometry minimum")
    if reader.size % expectations.userdata_size_alignment:
        raise GateError("userdata image does not have the trusted size alignment")
    if reader.pread(4, 0, "userdata image magic") == struct.pack("<I", 0xED26FF3A):
        raise GateError("userdata image is Android sparse instead of raw")
    image_lbas = reader.size // _PAGE_SIZE
    if image_lbas < 8:
        raise GateError("userdata image is too small for primary and backup GPT")
    _validate_mbr(reader, image_lbas)
    primary = _parse_gpt_header(
        reader.pread(_PAGE_SIZE, _PAGE_SIZE, "primary GPT header"), 1, image_lbas, "primary"
    )
    backup_lba = image_lbas - 1
    backup = _parse_gpt_header(
        reader.pread(_PAGE_SIZE, backup_lba * _PAGE_SIZE, "backup GPT header"),
        backup_lba,
        image_lbas,
        "backup",
    )
    if primary.backup_lba != backup.current_lba or backup.backup_lba != primary.current_lba:
        raise GateError("primary and backup GPT cross-pointers do not agree")
    comparable = (
        "first_usable_lba",
        "last_usable_lba",
        "disk_guid",
        "entry_count",
        "entry_size",
        "entries_crc32",
    )
    if any(getattr(primary, field) != getattr(backup, field) for field in comparable):
        raise GateError("primary and backup GPT headers disagree")
    if primary.entry_count != expectations.gpt_entry_count:
        raise GateError("GPT entry count does not match the trusted geometry")
    table_bytes = primary.entry_count * primary.entry_size
    table_lbas = (table_bytes + _PAGE_SIZE - 1) // _PAGE_SIZE
    if primary.entries_lba != 2 or backup.entries_lba != backup_lba - table_lbas:
        raise GateError("GPT entry arrays are not at their canonical primary/backup locations")
    if (
        primary.first_usable_lba != 2 + table_lbas
        or primary.last_usable_lba != backup.entries_lba - 1
    ):
        raise GateError("GPT usable range does not exclude both entry arrays")
    primary_table = _read_gpt_table(reader, primary, "primary")
    backup_table = _read_gpt_table(reader, backup, "backup")
    if primary_table != backup_table:
        raise GateError("primary and backup GPT entry arrays differ")
    boot_partition, root_partition = _parse_partitions(
        primary_table, primary, expectations
    )
    if (
        boot_partition.first_lba != expectations.boot_first_lba
        or boot_partition.last_lba != expectations.boot_last_lba
        or root_partition.first_lba != expectations.root_first_lba
        or root_partition.last_lba != primary.last_usable_lba
        or boot_partition.last_lba + 1 != root_partition.first_lba
    ):
        raise GateError("GPT partition offsets/sizes/free-space geometry is non-canonical")
    if primary.first_usable_lba > boot_partition.first_lba:
        raise GateError("GPT boot partition precedes the usable range")
    boot_fs = _validate_superblock(
        reader, boot_partition, "ext2", expectations.boot_feature_masks
    )
    root_fs = _validate_superblock(
        reader, root_partition, "ext4", expectations.root_feature_masks
    )
    if boot_fs["uuid"] == root_fs["uuid"]:
        raise GateError("pmOS_boot and pmOS_root filesystem UUIDs are not distinct")
    partition_files = {
        "pmOS_boot": work / "pmOS_boot.ext2",
        "pmOS_root": work / "pmOS_root.ext4",
    }
    partition_hashes = {
        "pmOS_boot": _extract_partition(
            reader, boot_partition, partition_files["pmOS_boot"]
        ),
        "pmOS_root": _extract_partition(
            reader, root_partition, partition_files["pmOS_root"]
        ),
    }
    fsck: dict[str, dict[str, object]] = {}
    for filesystem_label in ("pmOS_boot", "pmOS_root"):
        check = _run_tool(
            _E2FSCK,
            ["-fn", str(partition_files[filesystem_label])],
            f"e2fsck-{filesystem_label}",
            work,
            _E2FSCK_TIMEOUT_SECONDS,
        )
        # e2fsck uses a bitmask; any bit means the release artifact is not a
        # proven clean, internally consistent, read-only filesystem.
        if check.returncode != 0:
            raise GateError(
                f"e2fsck read-only consistency check failed for {filesystem_label} "
                f"with status {check.returncode}"
            )
        fsck[filesystem_label] = {
            "arguments": ["-fn"],
            "output_sha256": _sha256(check.output),
            "returncode": check.returncode,
        }
    root_files = _validate_rootfs_files(
        partition_files["pmOS_root"], trusted_rootfs, trusted_rootfs_owners, work
    )
    report_partitions: list[dict[str, object]] = []
    for partition, filesystem in (
        (boot_partition, boot_fs),
        (root_partition, root_fs),
    ):
        report_partitions.append(
            {
                "attributes": partition.attributes,
                "first_lba": partition.first_lba,
                "filesystem": filesystem,
                "gpt_name": partition.name,
                "last_lba": partition.last_lba,
                "name": str(filesystem["label"]),
                "partition_sha256": partition_hashes[str(filesystem["label"])],
                "size": (partition.last_lba - partition.first_lba + 1) * _PAGE_SIZE,
                "type_guid": str(partition.type_guid),
                "unique_guid": str(partition.unique_guid),
            }
        )
    return (
        {
            "disk_guid": str(primary.disk_guid),
            "gpt_entry_count": primary.entry_count,
            "logical_block_size": _PAGE_SIZE,
            "partitions": report_partitions,
            "free_space": {
                "alignment_lbas_before_boot": (
                    boot_partition.first_lba - primary.first_usable_lba
                ),
                "between_partitions_lbas": 0,
                "usable_lbas_after_root": 0,
            },
            "protective_mbr": True,
            "raw": True,
            "read_only_e2fsck": fsck,
            "root_files": root_files,
            "sha256": reader.digest(),
            "size": reader.size,
        },
        str(boot_fs["uuid"]),
        str(root_fs["uuid"]),
    )


def _validate_fstab(value: bytes, boot_uuid: str, root_uuid: str) -> list[dict[str, object]]:
    try:
        text = value.decode("utf-8")
    except UnicodeError:
        raise GateError("installed fstab is not UTF-8") from None
    if "\0" in text:
        raise GateError("installed fstab contains NUL")
    entries: list[list[str]] = []
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "#" in stripped:
            raise GateError(f"installed fstab has an inline comment on line {line_number}")
        fields = stripped.split()
        if len(fields) != 6:
            raise GateError(f"installed fstab line {line_number} does not have six fields")
        entries.append(fields)
    expected = {
        "/": [f"UUID={root_uuid}", "/", "ext4", "defaults", "0", "0"],
        "/boot": [
            f"UUID={boot_uuid}",
            "/boot",
            "ext2",
            "nodev,nosuid,noexec",
            "0",
            "0",
        ],
    }
    if len(entries) != 2 or {fields[1] for fields in entries} != set(expected):
        raise GateError("installed fstab must contain exactly root and boot entries")
    for fields in entries:
        if fields != expected[fields[1]]:
            raise GateError(f"installed fstab entry is not canonical for {fields[1]}")
        _canonical_uuid(fields[0][5:], f"fstab UUID for {fields[1]}")
    return [
        {
            "dump": 0,
            "filesystem": expected[mount][2],
            "mount": mount,
            "options": expected[mount][3],
            "pass": 0,
            "uuid": expected[mount][0][5:],
        }
        for mount in ("/", "/boot")
    ]


def validate_artifact_pair(
    boot_img: Path,
    userdata_img: Path,
    vmlinuz: Path,
    initramfs: Path,
    dtb: Path,
    deviceinfo: Path,
    staged_deviceinfo: Path,
    staged_init_functions: Path,
    staged_init_2nd: Path,
    fstab: Path,
    *,
    rootfs_bindings: RootfsBindings,
    limits: PartitionLimits = PartitionLimits(),
    expectations: ArtifactExpectations = ArtifactExpectations(),
    calibration: bool = False,
) -> dict[str, object]:
    """Validate a final lmi artifact pair and return path-free JSON evidence.

    ``deviceinfo`` and ``fstab`` are installed files from the final rootfs.
    ``staged_deviceinfo``, ``staged_init_functions``, and ``staged_init_2nd``
    are already-verified pmaports source files.  The remaining component paths
    are the exact files exported alongside the Android boot image.
    ``rootfs_bindings`` supplies trusted host-side copies of the other critical
    files which are extracted from pmOS_root using read-only debugfs.  Release
    mode is the default and requires a committed complete initramfs manifest;
    explicit calibration mode can only produce non-release audit evidence.
    """

    if not isinstance(rootfs_bindings, RootfsBindings):
        raise GateError("rootfs_bindings must be a RootfsBindings instance")
    if not isinstance(limits, PartitionLimits):
        raise GateError("limits must be a PartitionLimits instance")
    if not isinstance(expectations, ArtifactExpectations):
        raise GateError("expectations must be an ArtifactExpectations instance")
    if not isinstance(calibration, bool):
        raise GateError("calibration must be a boolean")
    if not calibration and expectations.initramfs_manifest is None:
        raise GateError("release validation requires a committed initramfs manifest")
    identities: dict[str, dict[str, int | str]] = {}
    kernel_export = _read_small(
        vmlinuz,
        "exported vmlinuz",
        min(limits.boot_bytes, 64 * 1024 * 1024 + 1),
        identities=identities,
        identity_label="vmlinuz",
    )
    initramfs_export = _read_small(
        initramfs,
        "exported initramfs",
        min(limits.boot_bytes, 64 * 1024 * 1024 + 1),
        identities=identities,
        identity_label="initramfs",
    )
    dtb_export = _read_small(
        dtb,
        "exported DTB",
        min(limits.boot_bytes, 4 * 1024 * 1024 + 1),
        identities=identities,
        identity_label="dtb",
    )
    installed_deviceinfo = _read_small(
        deviceinfo,
        "installed deviceinfo",
        1024 * 1024,
        identities=identities,
        identity_label="deviceinfo",
    )
    staged_deviceinfo_bytes = _read_small(
        staged_deviceinfo,
        "staged deviceinfo",
        1024 * 1024,
        identities=identities,
        identity_label="staged_deviceinfo",
    )
    if installed_deviceinfo != staged_deviceinfo_bytes:
        raise GateError("final installed deviceinfo differs from staged deviceinfo")
    staged_functions = _read_small(
        staged_init_functions,
        "staged init_functions.sh",
        4 * 1024 * 1024,
        identities=identities,
        identity_label="staged_init_functions",
    )
    staged_second = _read_small(
        staged_init_2nd,
        "staged init_2nd.sh",
        4 * 1024 * 1024,
        identities=identities,
        identity_label="staged_init_2nd",
    )
    installed_fstab = _read_small(
        fstab,
        "installed fstab",
        1024 * 1024,
        identities=identities,
        identity_label="fstab",
    )
    trusted_rootfs: dict[str, bytes] = {
        "fstab": installed_fstab,
        "deviceinfo": installed_deviceinfo,
    }
    trusted_rootfs_owners: dict[str, tuple[int, int]] = {
        "fstab": (int(identities["fstab"]["uid"]), int(identities["fstab"]["gid"])),
        "deviceinfo": (
            int(identities["deviceinfo"]["uid"]),
            int(identities["deviceinfo"]["gid"]),
        ),
    }
    for _internal_path, key, mode, maximum in _ROOTFS_FILE_SPECS:
        if key in trusted_rootfs:
            continue
        source = getattr(rootfs_bindings, key)
        trusted_rootfs[key] = _read_small(
            source,
            f"trusted rootfs {key}",
            maximum + 1,
            identities=identities,
            identity_label=f"rootfs_{key}",
        )
        if identities[f"rootfs_{key}"]["mode"] != mode:
            raise GateError(f"trusted rootfs {key} mode is not {mode:04o}")
        if key in _ROOT_OWNED_MANAGEMENT_KEYS:
            trusted_rootfs_owners[key] = (0, 0)
        else:
            trusted_rootfs_owners[key] = (
                int(identities[f"rootfs_{key}"]["uid"]),
                int(identities[f"rootfs_{key}"]["gid"]),
            )
    for identity_label, expected_mode in (("deviceinfo", 0o644), ("fstab", 0o644)):
        if identities[identity_label]["mode"] != expected_mode:
            raise GateError(f"trusted rootfs {identity_label} mode is not {expected_mode:04o}")
    parsed_deviceinfo = _parse_deviceinfo(installed_deviceinfo)

    with _ImageReader(Path(boot_img), "boot image", limits.boot_bytes, raw=True) as boot_reader:
        boot = boot_reader.pread(boot_reader.size, 0, "boot image")
        boot_sha256 = boot_reader.digest()
        identities["boot_img"] = boot_reader.identity(boot_sha256)
    if len(boot) < _PAGE_SIZE or boot[:8] != _BOOT_MAGIC:
        raise GateError("Android boot v2 magic mismatch")
    header = boot[:_BOOT_HEADER_SIZE]
    if len(header) != _BOOT_HEADER_SIZE:
        raise GateError("Android boot v2 header is truncated")
    kernel_size = _u32le(header, 8)
    kernel_addr = _u32le(header, 12)
    ramdisk_size = _u32le(header, 16)
    ramdisk_addr = _u32le(header, 20)
    second_size = _u32le(header, 24)
    second_addr = _u32le(header, 28)
    tags_addr = _u32le(header, 32)
    page_size = _u32le(header, 36)
    header_version = _u32le(header, 40)
    os_version = _u32le(header, 44)
    recovery_size = _u32le(header, 1632)
    recovery_offset = _u64le(header, 1636)
    header_size = _u32le(header, 1644)
    dtb_size = _u32le(header, 1648)
    dtb_addr = _u64le(header, 1652)
    expected_fields = {
        "kernel address": (kernel_addr, 0x00008000),
        "ramdisk address": (ramdisk_addr, 0x01000000),
        "second address": (second_addr, 0x00000000),
        "tags address": (tags_addr, 0x00000100),
        "DTB address": (dtb_addr, 0x01F00000),
        "page size": (page_size, _PAGE_SIZE),
        "header version": (header_version, 2),
        "header size": (header_size, _BOOT_HEADER_SIZE),
    }
    for label, (actual, expected) in expected_fields.items():
        if actual != expected:
            raise GateError(f"Android boot v2 {label} mismatch")
    if not kernel_size or not ramdisk_size or not dtb_size:
        raise GateError("Android boot v2 kernel, ramdisk, and DTB must be nonempty")
    if kernel_size > 64 * 1024 * 1024:
        raise GateError("Android boot v2 kernel exceeds the 64 MiB bound")
    if ramdisk_size > 64 * 1024 * 1024:
        raise GateError("Android boot v2 ramdisk exceeds the 64 MiB bound")
    if dtb_size > 4 * 1024 * 1024:
        raise GateError("Android boot v2 DTB exceeds the 4 MiB bound")
    if second_size != 0 or recovery_size != 0 or recovery_offset != 0:
        raise GateError("Android boot v2 second or recovery DTBO payload is nonzero")
    if os_version != 0:
        raise GateError("Android boot v2 OS version/patch field is nonzero")
    if any(header[48:64]):
        raise GateError("Android boot v2 board name is nonempty")
    if any(boot[_BOOT_HEADER_SIZE:_PAGE_SIZE]):
        raise GateError("Android boot v2 header padding is not zero")
    cursor = _PAGE_SIZE
    kernel, cursor = _region(boot, cursor, kernel_size, _PAGE_SIZE, "kernel")
    ramdisk, cursor = _region(boot, cursor, ramdisk_size, _PAGE_SIZE, "ramdisk")
    dtb_blob, cursor = _region(boot, cursor, dtb_size, _PAGE_SIZE, "DTB")
    if any(boot[cursor:]):
        raise GateError("Android boot image trailing bytes are not zero")
    if kernel != kernel_export:
        raise GateError("embedded kernel differs from exported vmlinuz")
    if ramdisk != initramfs_export:
        raise GateError("embedded ramdisk differs from exported initramfs")
    if dtb_blob != dtb_export:
        raise GateError("embedded DTB differs from exported DTB")
    if header[576:608] != _android_boot_id(kernel, ramdisk, dtb_blob):
        raise GateError("Android boot v2 ID does not bind all payload components")
    cmd_boot_uuid, cmd_root_uuid, cmdline_tokens = _validate_cmdline(header, parsed_deviceinfo)
    # Validate the trusted fstab against the boot image UUIDs before expensive
    # filesystem extraction; the same UUID pair is bound to ext metadata below.
    fstab_report = _validate_fstab(installed_fstab, cmd_boot_uuid, cmd_root_uuid)
    arm64 = _validate_arm64_image(kernel, expectations)
    fdt = _validate_fdt(dtb_blob, expectations)
    unpacked = _gunzip_bounded(ramdisk)
    cpio = _parse_newc(unpacked)
    inventory = _initramfs_inventory(cpio)
    if cpio["init_functions.sh"].data != staged_functions:
        raise GateError("archived init_functions.sh differs from the staged patched file")
    if cpio["init_2nd.sh"].data != staged_second:
        raise GateError("archived init_2nd.sh differs from the staged patched file")
    archived_deviceinfo = _resolve_cpio_member(
        cpio, "usr/share/deviceinfo/deviceinfo"
    )
    if archived_deviceinfo.data != installed_deviceinfo:
        raise GateError("archived deviceinfo differs from staged and installed deviceinfo")
    if (
        expectations.initramfs_manifest is not None
        and inventory != expectations.initramfs_manifest
    ):
        raise GateError("initramfs logical inventory differs from the committed manifest")

    try:
        temporary = tempfile.TemporaryDirectory(prefix="lmi-artifact-semantics-")
    except OSError as error:
        raise _os_failure("create", "private validation directory", error) from None
    with temporary:
        work = Path(temporary.name)
        try:
            work_stat = work.lstat()
        except OSError as error:
            raise _os_failure("inspect", "private validation directory", error) from None
        if not stat.S_ISDIR(work_stat.st_mode) or stat.S_IMODE(work_stat.st_mode) != 0o700:
            raise GateError("private validation directory permissions are unsafe")
        toolchain_report = _validate_toolchain(expectations, work)
        with _ImageReader(
            Path(userdata_img), "userdata image", limits.userdata_bytes, raw=True
        ) as userdata_reader:
            userdata_report, fs_boot_uuid, fs_root_uuid = _validate_userdata(
                userdata_reader,
                expectations,
                trusted_rootfs,
                trusted_rootfs_owners,
                work,
            )
            userdata_digest = str(userdata_report["sha256"])
            identities["userdata_img"] = userdata_reader.identity(userdata_digest)
    if (cmd_boot_uuid, cmd_root_uuid) != (fs_boot_uuid, fs_root_uuid):
        raise GateError("boot cmdline UUIDs do not match the userdata filesystems")

    manifest_digest = hashlib.sha256()
    for entry in inventory:
        manifest_digest.update(
            b"\0".join(
                (
                    entry.path.encode("utf-8"),
                    entry.type.encode("ascii"),
                    f"{entry.mode:o}".encode("ascii"),
                    str(entry.size).encode("ascii"),
                    entry.sha256.encode("ascii"),
                    (entry.link_target or "").encode("utf-8"),
                )
            )
        )
        manifest_digest.update(b"\n")
    production_pins = (
        expectations.profile == "lmi-p1-production"
        and expectations.kernel_sha256 == _PRODUCTION_KERNEL_SHA256
        and expectations.dtb_sha256 == _PRODUCTION_DTB_SHA256
        and expectations.minimum_userdata_bytes == _PRODUCTION_MIN_USERDATA_BYTES
        and expectations.userdata_size_alignment == 1024 * 1024
        and expectations.gpt_entry_count == _PRODUCTION_GPT_ENTRIES
        and expectations.boot_first_lba == _PRODUCTION_BOOT_FIRST_LBA
        and expectations.boot_last_lba == _PRODUCTION_BOOT_LAST_LBA
        and expectations.root_first_lba == _PRODUCTION_ROOT_FIRST_LBA
        and expectations.gpt_partition_names == ("primary", "primary")
        and expectations.boot_feature_masks == (0x0038, 0x0002, 0x0003)
        and expectations.root_feature_masks == (0x103C, 0x02C2, 0x006B)
        and expectations.e2fsck_sha256 == _E2FSCK_SHA256
        and expectations.debugfs_sha256 == _DEBUGFS_SHA256
        and expectations.e2fsprogs_version == _E2FSPROGS_VERSION
        and expectations.tool_uid == 0
        and expectations.tool_gid == 0
        and expectations.tool_mode == 0o755
    )
    release_eligible = bool(
        not calibration
        and expectations.initramfs_manifest is not None
        and production_pins
    )
    return {
        "boot": {
            "board_name": "",
            "cmdline_tokens": cmdline_tokens,
            "dtb": {
                **fdt,
                "load_address": dtb_addr,
                "sha256": _sha256(dtb_blob),
                "size": len(dtb_blob),
            },
            "header_size": header_size,
            "header_version": header_version,
            "image_id_sha1": header[576:596].hex(),
            "initramfs": {
                "compressed_sha256": _sha256(ramdisk),
                "compressed_size": len(ramdisk),
                "entry_count": len(cpio),
                "inventory": [asdict(entry) for entry in inventory],
                "inventory_sha256": manifest_digest.hexdigest(),
                "init_2nd_sha256": _sha256(staged_second),
                "init_functions_sha256": _sha256(staged_functions),
                "required_entries": list(_REQUIRED_INITRAMFS),
                "uncompressed_sha256": _sha256(unpacked),
                "uncompressed_size": len(unpacked),
            },
            "kernel": {
                **arm64,
                "load_address": kernel_addr,
                "sha256": _sha256(kernel),
                "size": len(kernel),
            },
            "page_size": page_size,
            "os_version_patch": os_version,
            "recovery_dtbo_size": recovery_size,
            "second_size": second_size,
            "sha256": boot_sha256,
            "size": len(boot),
        },
        "deviceinfo": {
            "arch": parsed_deviceinfo["deviceinfo_arch"],
            "codename": parsed_deviceinfo["deviceinfo_codename"],
            "copies_equal": True,
            "dtb": parsed_deviceinfo["deviceinfo_dtb"],
            "sha256": _sha256(installed_deviceinfo),
        },
        "fstab": fstab_report,
        "limits": {
            "boot_bytes": limits.boot_bytes,
            "recorded_boot_bytes": _RECORDED_BOOT_BYTES,
            "recorded_userdata_bytes": _RECORDED_USERDATA_BYTES,
            "userdata_bytes": limits.userdata_bytes,
        },
        "inputs": dict(sorted(identities.items())),
        "release": {
            "calibration": calibration,
            "eligible": release_eligible,
            "expectation_profile": expectations.profile,
            "production_pins": production_pins,
        },
        "schema": "lmi-artifact-semantics-v3",
        "tools": toolchain_report,
        "userdata": userdata_report,
    }


_INPUT_IDENTITY_LABELS = frozenset(
    {
        "boot_img",
        "userdata_img",
        "vmlinuz",
        "initramfs",
        "dtb",
        "deviceinfo",
        "staged_deviceinfo",
        "staged_init_functions",
        "staged_init_2nd",
        "fstab",
        "rootfs_apk_installed",
        "rootfs_sshd_config",
        "rootfs_sshd_service",
        "rootfs_sshd_pam",
        "rootfs_authorized_keys",
        "rootfs_release_identity",
        "rootfs_networkmanager_profile",
        "rootfs_networkmanager_takeover",
        "rootfs_unudhcpd",
        "rootfs_unudhcpd_service",
        "rootfs_unudhcpd_config",
        "rootfs_usb_dhcp_wrapper",
        "rootfs_usb_dhcp_service",
    }
)


def recheck_input_identities(
    expected: Mapping[str, object], paths: Mapping[str, Path]
) -> None:
    """Re-hash and re-stat every validated input immediately before publication."""

    if set(expected) != _INPUT_IDENTITY_LABELS or set(paths) != _INPUT_IDENTITY_LABELS:
        raise GateError("artifact input identity label set is incomplete")
    for label in sorted(_INPUT_IDENTITY_LABELS):
        evidence = expected[label]
        if not isinstance(evidence, Mapping) or set(evidence) != {
            "device",
            "gid",
            "inode",
            "mode",
            "mtime_ns",
            "sha256",
            "size",
            "uid",
        }:
            raise GateError(f"artifact input identity evidence is malformed for {label}")
        size = evidence["size"]
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise GateError(f"artifact input identity size is malformed for {label}")
        with _ImageReader(
            Path(paths[label]),
            label,
            size + 1,
            raw=label in {"boot_img", "userdata_img"},
        ) as reader:
            actual = reader.identity(reader.digest())
        if actual != dict(evidence):
            raise GateError(f"artifact input changed before publication: {label}")


__all__ = [
    "ArtifactExpectations",
    "InitramfsManifestEntry",
    "PartitionLimits",
    "RootfsBindings",
    "calibrate_initramfs_manifest",
    "load_initramfs_manifest",
    "recheck_input_identities",
    "validate_artifact_pair",
]
