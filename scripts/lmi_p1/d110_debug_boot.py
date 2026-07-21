#!/usr/bin/env python3
"""Build and verify a pinned D110 initramfs debug-shell RAM-boot image.

The production transformation changes only the Android boot v2 cmdline fields.
Kernel, ramdisk, DTB, boot ID, padding, and total image size stay byte-identical
to the already accepted D110 image.  The resulting shell is unauthenticated
telnet on the point-to-point USB network; the public key is only a binding for a
separately reviewed repair action and is not embedded in the boot image.  No
command in this module accesses a phone.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
from typing import NamedTuple


REPO = Path(__file__).resolve().parents[2]
DEFAULT_SOURCE = (
    REPO
    / "private/lmi-p1/recovery/d110-d114/"
    "pmos-lmi-normalboot-v110-bpf-fs-context-enoparam-r15-20260713.img"
)
DEFAULT_KEY = REPO / "private/lmi-p1/owner-test-ed25519.pub"
DEFAULT_OUTPUT = (
    REPO
    / "private/lmi-p1/recovery/d110-d114/"
    "pmos-lmi-ramboot-d111-debug-shell-key-recovery-20260720.img"
)
DEFAULT_MANIFEST = DEFAULT_OUTPUT.with_suffix(".manifest.json")

BOOT_MAGIC = b"ANDROID!"
BOOT_HEADER_SIZE = 1660
PAGE_SIZE = 4096
CMDLINE_FIRST = slice(64, 576)
CMDLINE_EXTRA = slice(608, 1632)
BOOT_ID = slice(576, 608)
DEBUG_TOKEN = b"pmos.debug-shell"
MAX_BOOT_SIZE = 64 * 1024 * 1024


class RecoveryError(RuntimeError):
    """A fail-closed recovery artifact validation error."""


class Profile(NamedTuple):
    source_size: int
    source_sha256: str
    source_cmdline_sha256: str
    recovery_cmdline_sha256: str
    kernel_sha256: str
    ramdisk_sha256: str
    dtb_sha256: str


PRODUCTION = Profile(
    source_size=52_944_896,
    source_sha256="2b264d64d2ed22f0ab5c3c2615b0bda9ed821fa5d8d5d691ea513e5d2f071487",
    source_cmdline_sha256="ee1ecf60d86685369c4e72c47fed83499dbdb717de716754293b88097f0572d2",
    recovery_cmdline_sha256="71beb8057a96fdf0a1699c4b0de798aa7985cfa06854a02f81a31dccae6b8602",
    kernel_sha256="3bdb26129d4910170d29d492802ff246b9847a997e81b2037c217df1dec61945",
    ramdisk_sha256="c86301b7727e8e18af5328dffe6acc19e13f23cb794c2842a720b2c69ffa4361",
    dtb_sha256="aee89cc172734de955a11ec335b16d3a1b5da51667083b919271c2b6902d57a6",
)


class BootParts(NamedTuple):
    header: bytes
    kernel: bytes
    ramdisk: bytes
    dtb: bytes
    payload_offset: int


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _u32(value: bytes, offset: int) -> int:
    return struct.unpack_from("<I", value, offset)[0]


def _u64(value: bytes, offset: int) -> int:
    return struct.unpack_from("<Q", value, offset)[0]


def _align(value: int, alignment: int) -> int:
    return (value + alignment - 1) // alignment * alignment


def _boot_id(kernel: bytes, ramdisk: bytes, dtb: bytes) -> bytes:
    digest = hashlib.sha1(usedforsecurity=False)
    for component in (kernel, ramdisk, b"", b"", dtb):
        digest.update(component)
        digest.update(struct.pack("<I", len(component)))
    return digest.digest() + b"\0" * 12


def _stable_read(
    path: Path,
    *,
    label: str,
    maximum: int,
    allowed_modes: frozenset[int],
) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise RecoveryError(f"cannot inspect {label}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise RecoveryError(f"{label} must be a single-link regular file")
    if before.st_uid != os.geteuid():
        raise RecoveryError(f"{label} must be owned by the current user")
    if stat.S_IMODE(before.st_mode) not in allowed_modes:
        raise RecoveryError(f"{label} has an unsafe mode")
    if before.st_size <= 0 or before.st_size > maximum:
        raise RecoveryError(f"{label} has an invalid size")

    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise RecoveryError(f"cannot open {label}") from error
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_nlink,
            before.st_uid,
            before.st_gid,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            raise RecoveryError(f"{label} changed while opening")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise RecoveryError(f"{label} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise RecoveryError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_nlink,
            after.st_uid,
            after.st_gid,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_nlink,
            opened.st_uid,
            opened.st_gid,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise RecoveryError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _decode_cmdline(header: bytes, *, require_canonical_spacing: bool = True) -> bytes:
    raw = header[CMDLINE_FIRST] + header[CMDLINE_EXTRA]
    terminator = raw.find(b"\0")
    if terminator < 0 or any(raw[terminator + 1 :]):
        raise RecoveryError("boot cmdline fields are not canonically terminated")
    cmdline = raw[:terminator]
    if not cmdline or any(byte < 0x20 or byte >= 0x7F for byte in cmdline):
        raise RecoveryError("boot cmdline is empty or non-ASCII")
    if require_canonical_spacing and cmdline != b" ".join(cmdline.split()):
        raise RecoveryError("boot cmdline spacing is not canonical")
    return cmdline


def _encode_cmdline(header: bytearray, cmdline: bytes) -> None:
    capacity = (CMDLINE_FIRST.stop - CMDLINE_FIRST.start) + (
        CMDLINE_EXTRA.stop - CMDLINE_EXTRA.start
    )
    if len(cmdline) + 1 > capacity:
        raise RecoveryError("recovery cmdline exceeds Android boot v2 capacity")
    raw = cmdline + b"\0" * (capacity - len(cmdline))
    first_length = CMDLINE_FIRST.stop - CMDLINE_FIRST.start
    header[CMDLINE_FIRST] = raw[:first_length]
    header[CMDLINE_EXTRA] = raw[first_length:]


def _region(image: bytes, cursor: int, size: int, label: str) -> tuple[bytes, int]:
    end = cursor + size
    padded = cursor + _align(size, PAGE_SIZE)
    if end > len(image) or padded > len(image):
        raise RecoveryError(f"boot {label} is truncated")
    if any(image[end:padded]):
        raise RecoveryError(f"boot {label} padding is nonzero")
    return image[cursor:end], padded


def _inspect_source(image: bytes, profile: Profile) -> BootParts:
    if len(image) != profile.source_size or _sha256(image) != profile.source_sha256:
        raise RecoveryError("source D110 image identity mismatch")
    if len(image) < PAGE_SIZE or image[:8] != BOOT_MAGIC:
        raise RecoveryError("source is not the expected Android boot image")
    header = image[:BOOT_HEADER_SIZE]
    fields = {
        "kernel address": (_u32(header, 12), 0x00008000),
        "ramdisk address": (_u32(header, 20), 0x01000000),
        "second size": (_u32(header, 24), 0),
        "second address": (_u32(header, 28), 0),
        "tags address": (_u32(header, 32), 0x00000100),
        "page size": (_u32(header, 36), PAGE_SIZE),
        "header version": (_u32(header, 40), 2),
        "OS version": (_u32(header, 44), 0),
        "recovery DTBO size": (_u32(header, 1632), 0),
        "recovery DTBO offset": (_u64(header, 1636), 0),
        "header size": (_u32(header, 1644), BOOT_HEADER_SIZE),
        "DTB address": (_u64(header, 1652), 0x01F00000),
    }
    for label, (actual, expected) in fields.items():
        if actual != expected:
            raise RecoveryError(f"source Android boot v2 {label} mismatch")
    if any(header[48:64]) or any(image[BOOT_HEADER_SIZE:PAGE_SIZE]):
        raise RecoveryError("source Android boot v2 header padding mismatch")

    kernel_size = _u32(header, 8)
    ramdisk_size = _u32(header, 16)
    dtb_size = _u32(header, 1648)
    if not kernel_size or not ramdisk_size or not dtb_size:
        raise RecoveryError("source boot payload is incomplete")
    cursor = PAGE_SIZE
    kernel, cursor = _region(image, cursor, kernel_size, "kernel")
    ramdisk, cursor = _region(image, cursor, ramdisk_size, "ramdisk")
    dtb, cursor = _region(image, cursor, dtb_size, "DTB")
    if any(image[cursor:]):
        raise RecoveryError("source boot trailing bytes are nonzero")
    for label, value, expected in (
        ("kernel", kernel, profile.kernel_sha256),
        ("ramdisk", ramdisk, profile.ramdisk_sha256),
        ("DTB", dtb, profile.dtb_sha256),
    ):
        if _sha256(value) != expected:
            raise RecoveryError(f"source {label} identity mismatch")
    if header[BOOT_ID] != _boot_id(kernel, ramdisk, dtb):
        raise RecoveryError("source boot ID does not bind the payload")
    # The exact accepted D110 cmdline contains one historical double-space
    # run.  Its full image and cmdline identities are pinned above, so retain
    # those bytes instead of silently normalizing a boot-critical field.
    cmdline = _decode_cmdline(header, require_canonical_spacing=False)
    if _sha256(cmdline) != profile.source_cmdline_sha256:
        raise RecoveryError("source boot cmdline identity mismatch")
    if cmdline.split().count(DEBUG_TOKEN) != 0:
        raise RecoveryError("source boot unexpectedly enables debug shell")
    return BootParts(header, kernel, ramdisk, dtb, PAGE_SIZE)


def _transform(image: bytes, profile: Profile) -> bytes:
    parts = _inspect_source(image, profile)
    source_cmdline = _decode_cmdline(
        parts.header, require_canonical_spacing=False
    )
    recovery_cmdline = source_cmdline + b" " + DEBUG_TOKEN
    if _sha256(recovery_cmdline) != profile.recovery_cmdline_sha256:
        raise RecoveryError("derived recovery cmdline identity mismatch")
    header = bytearray(parts.header)
    _encode_cmdline(header, recovery_cmdline)
    candidate = bytes(header) + image[BOOT_HEADER_SIZE:]
    if len(candidate) != len(image):
        raise RecoveryError("recovery transformation changed image size")
    if candidate[PAGE_SIZE:] != image[PAGE_SIZE:]:
        raise RecoveryError("recovery transformation changed a boot payload byte")
    if candidate[BOOT_ID] != image[BOOT_ID]:
        raise RecoveryError("recovery transformation changed the payload boot ID")
    if (
        _decode_cmdline(
            candidate[:BOOT_HEADER_SIZE], require_canonical_spacing=False
        )
        .split()
        .count(DEBUG_TOKEN)
        != 1
    ):
        raise RecoveryError("recovery image does not contain one debug-shell token")
    return candidate


def _read_u32_string(blob: bytes, cursor: int) -> tuple[bytes, int]:
    if cursor + 4 > len(blob):
        raise RecoveryError("SSH public key blob is truncated")
    length = struct.unpack_from(">I", blob, cursor)[0]
    cursor += 4
    if length > len(blob) - cursor:
        raise RecoveryError("SSH public key blob has an invalid length")
    return blob[cursor : cursor + length], cursor + length


def _key_binding(path: Path) -> tuple[dict[str, object], bytes]:
    source = _stable_read(
        path,
        label="recovery SSH public key",
        maximum=4096,
        allowed_modes=frozenset((0o600, 0o644)),
    )
    try:
        text = source.decode("ascii")
    except UnicodeError as error:
        raise RecoveryError("recovery SSH public key is not ASCII") from error
    lines = [line for line in text.splitlines() if line]
    if len(lines) != 1:
        raise RecoveryError("recovery SSH public key must contain one line")
    fields = lines[0].split()
    if len(fields) < 2 or fields[0] != "ssh-ed25519":
        raise RecoveryError("recovery SSH public key is not Ed25519")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, binascii.Error) as error:
        raise RecoveryError("recovery SSH public key encoding is invalid") from error
    key_type, cursor = _read_u32_string(blob, 0)
    key_value, cursor = _read_u32_string(blob, cursor)
    if key_type != b"ssh-ed25519" or len(key_value) != 32 or cursor != len(blob):
        raise RecoveryError("recovery SSH public key blob is malformed")
    canonical = f"ssh-ed25519 {fields[1]}\n".encode("ascii")
    fingerprint = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return (
        {
            "algorithm": "ssh-ed25519",
            "canonical_line_sha256": _sha256(canonical),
            "canonical_line_size": len(canonical),
            "fingerprint": f"SHA256:{fingerprint}",
            "source_sha256": _sha256(source),
            "source_size": len(source),
        },
        canonical,
    )


def _manifest(
    source_name: str,
    candidate_name: str,
    candidate: bytes,
    profile: Profile,
    key: dict[str, object],
) -> bytes:
    value = {
        "authorized_key_repair_intent": {
            **key,
            "embedded_in_boot_image": False,
            "replacement_is_automatic": False,
        },
        "candidate": {
            "cmdline_sha256": profile.recovery_cmdline_sha256,
            "debug_shell_token_count": 1,
            "dtb_sha256": profile.dtb_sha256,
            "kernel_sha256": profile.kernel_sha256,
            "name": candidate_name,
            "ramdisk_sha256": profile.ramdisk_sha256,
            "sha256": _sha256(candidate),
            "size": len(candidate),
        },
        "execution": {
            "automatic_retry": False,
            "automatic_persistent_storage_mutation": False,
            "debug_shell_holds_before_subpartition_discovery": True,
            "explicit_partition_write": False,
            "network_authentication": "none",
            "network_scope": "point-to-point-usb",
            "operation": "fastboot boot",
            "service": "telnet/23",
        },
        "schema": "lmi-d110-debug-shell-boot/v1",
        "source": {
            "cmdline_sha256": profile.source_cmdline_sha256,
            "name": source_name,
            "sha256": profile.source_sha256,
            "size": profile.source_size,
        },
        "transformation": {
            "added_cmdline_tokens": [DEBUG_TOKEN.decode("ascii")],
            "android_boot_id_changed": False,
            "header_bytes_changed_only": True,
            "payload_bytes_changed": False,
            "source_cmdline_bytes_preserved_verbatim": True,
            "total_size_changed": False,
        },
    }
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode(
        "ascii"
    )


def _safe_parent(path: Path) -> tuple[Path, os.stat_result]:
    parent = path.parent
    try:
        parent_stat = parent.lstat()
    except OSError as error:
        raise RecoveryError("cannot inspect private output directory") from error
    if (
        not stat.S_ISDIR(parent_stat.st_mode)
        or stat.S_IMODE(parent_stat.st_mode) != 0o700
        or parent_stat.st_uid != os.geteuid()
    ):
        raise RecoveryError("private output directory must be user-owned mode 0700")
    return parent, parent_stat


def _write_all(descriptor: int, value: bytes) -> None:
    cursor = 0
    while cursor < len(value):
        written = os.write(descriptor, value[cursor:])
        if written <= 0:
            raise RecoveryError("short write while publishing recovery artifact")
        cursor += written
    os.fsync(descriptor)


def _publish_pair(output: Path, candidate: bytes, manifest_path: Path, manifest: bytes) -> None:
    if output == manifest_path or output.parent != manifest_path.parent:
        raise RecoveryError("candidate and manifest must be distinct siblings")
    parent, parent_stat = _safe_parent(output)
    for target in (output, manifest_path):
        try:
            target.lstat()
        except FileNotFoundError:
            pass
        except OSError as error:
            raise RecoveryError("cannot inspect recovery output target") from error
        else:
            raise RecoveryError("recovery output target already exists")

    temp_paths: list[Path] = []
    published: list[tuple[Path, tuple[int, int]]] = []
    try:
        for label, value in (("image", candidate), ("manifest", manifest)):
            descriptor, name = tempfile.mkstemp(prefix=f".d111-{label}-", dir=parent)
            temp_path = Path(name)
            temp_paths.append(temp_path)
            try:
                os.fchmod(descriptor, 0o600)
                _write_all(descriptor, value)
                identity_stat = os.fstat(descriptor)
            finally:
                os.close(descriptor)
            target = output if label == "image" else manifest_path
            os.link(temp_path, target, follow_symlinks=False)
            published.append((target, (identity_stat.st_dev, identity_stat.st_ino)))

        directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            current_parent = os.fstat(directory_fd)
            if (current_parent.st_dev, current_parent.st_ino) != (
                parent_stat.st_dev,
                parent_stat.st_ino,
            ):
                raise RecoveryError("private output directory changed during publication")
            for temp_path in temp_paths:
                temp_path.unlink()
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        temp_paths.clear()
    except BaseException:
        for target, identity in reversed(published):
            try:
                current = target.lstat()
                if (current.st_dev, current.st_ino) == identity:
                    target.unlink()
            except OSError:
                pass
        raise
    finally:
        for temp_path in temp_paths:
            try:
                temp_path.unlink()
            except OSError:
                pass

    for target in (output, manifest_path):
        final = target.lstat()
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_nlink != 1
            or final.st_uid != os.geteuid()
            or stat.S_IMODE(final.st_mode) != 0o600
        ):
            raise RecoveryError("published recovery artifact metadata mismatch")


def _derive(source_path: Path, key_path: Path, profile: Profile) -> tuple[bytes, bytes]:
    source = _stable_read(
        source_path,
        label="source D110 boot image",
        maximum=MAX_BOOT_SIZE,
        allowed_modes=frozenset((0o600,)),
    )
    candidate = _transform(source, profile)
    key, _canonical_key = _key_binding(key_path)
    manifest = _manifest(source_path.name, DEFAULT_OUTPUT.name, candidate, profile, key)
    return candidate, manifest


def build(source_path: Path, key_path: Path, output: Path, manifest_path: Path) -> None:
    candidate, _default_manifest = _derive(source_path, key_path, PRODUCTION)
    key, _canonical_key = _key_binding(key_path)
    manifest = _manifest(source_path.name, output.name, candidate, PRODUCTION, key)
    _publish_pair(output, candidate, manifest_path, manifest)
    print(f"candidate_sha256={_sha256(candidate)}")
    print(f"candidate_size={len(candidate)}")
    print(f"manifest_sha256={_sha256(manifest)}")
    print("debug_shell_token_count=1")
    print("network_service=unauthenticated-telnet-over-point-to-point-usb")
    print("authorized_key_embedded=no")
    print("automatic_persistent_storage_mutation=no")
    print("execution=temporary-fastboot-boot-only")
    print("explicit_partition_write=no")


def verify(
    source_path: Path,
    key_path: Path,
    candidate_path: Path,
    manifest_path: Path,
) -> None:
    expected_candidate, _default_manifest = _derive(source_path, key_path, PRODUCTION)
    candidate = _stable_read(
        candidate_path,
        label="D111 recovery boot image",
        maximum=MAX_BOOT_SIZE,
        allowed_modes=frozenset((0o600,)),
    )
    if candidate != expected_candidate:
        raise RecoveryError("D111 recovery boot image differs from the exact transformation")
    key, _canonical_key = _key_binding(key_path)
    expected_manifest = _manifest(
        source_path.name, candidate_path.name, candidate, PRODUCTION, key
    )
    manifest = _stable_read(
        manifest_path,
        label="D111 recovery manifest",
        maximum=64 * 1024,
        allowed_modes=frozenset((0o600,)),
    )
    if manifest != expected_manifest:
        raise RecoveryError("D111 recovery manifest is not canonical or is stale")
    print("verification=D111_DEBUG_SHELL_RAMBOOT_VERIFIED")
    print(f"candidate_sha256={_sha256(candidate)}")
    print(f"manifest_sha256={_sha256(manifest)}")
    print("explicit_partition_write=no")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in ("build", "verify"):
        selected = subparsers.add_parser(command)
        selected.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
        selected.add_argument("--authorized-key", type=Path, default=DEFAULT_KEY)
        selected.add_argument(
            "--candidate",
            type=Path,
            default=DEFAULT_OUTPUT,
            help="private D111 output path",
        )
        selected.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    return parser


def main() -> int:
    arguments = _parser().parse_args()
    try:
        if arguments.command == "build":
            build(
                arguments.source,
                arguments.authorized_key,
                arguments.candidate,
                arguments.manifest,
            )
        else:
            verify(
                arguments.source,
                arguments.authorized_key,
                arguments.candidate,
                arguments.manifest,
            )
    except (OSError, RecoveryError) as error:
        print(f"refused: {error}", file=os.sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
