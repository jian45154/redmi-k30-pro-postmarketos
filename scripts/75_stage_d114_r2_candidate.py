#!/usr/bin/env python3
"""Stage the D114 P2 r2 candidate from the freshly built base rootfs.

Takes the raw userdata image produced by scripts/74_build_pmos_d114_r2_rootfs.sh
and derives, without root:

1. UUID normalization inside the raw image so the hardware-validated D110
   normalboot (2b264d64) keeps finding both filesystems: the boot subpartition
   (p1) gets the pinned pmos_boot_uuid and the root subpartition (p2) gets the
   pinned pmos_root_uuid from that boot image's cmdline.
2. The base ext4 (p2 extracted from the normalized raw).
3. The candidate ext4: sparse copy of the base, e2fsck -f -y repair,
   e2fsck -f -n verify (exit 0 required), then the two wall-clock superblock
   fields (s_wtime, s_lastcheck) stamped with a recorded epoch so the
   derivation is reproducible byte-for-byte.
4. The baseline android-sparse image of the normalized raw (img2simg).
5. A JSON staging manifest with every hash, size, and geometry value the
   lock rewrites (source-lock, candidate-rebuild-lock, injector constants,
   assembler contract) need.

Nothing here touches the device; this is host-side derivation only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

SECTOR = 4096  # GPT logical sector size on lmi userdata (gpt_logical_sector_size)
PMOS_BOOT_UUID = "d4f78f7d-f5b5-4edc-94d5-ba5e6c877888"
PMOS_ROOT_UUID = "f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f"
# Absolute byte offsets of the two wall-clock fields in the primary ext4
# superblock (1024-byte superblock start + 48 / + 64).
S_WTIME_OFFSET = 1072
S_LASTCHECK_OFFSET = 1088

TUNE2FS = "/usr/sbin/tune2fs"
E2FSCK = "/usr/sbin/e2fsck"
DUMPE2FS = "/usr/sbin/dumpe2fs"
IMG2SIMG = "/usr/bin/img2simg"
SIMG2IMG = "/usr/bin/simg2img"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def parse_gpt(image: Path) -> dict:
    """Parse the primary GPT (4096-byte logical sectors) of the raw image."""
    size = image.stat().st_size
    if size % SECTOR:
        raise SystemExit(f"raw image size {size} is not a multiple of {SECTOR}")
    with image.open("rb") as handle:
        handle.seek(1 * SECTOR)
        header = handle.read(SECTOR)
        if header[0:8] != b"EFI PART":
            raise SystemExit("primary GPT header signature missing")
        current_lba, backup_lba, first_usable, last_usable = struct.unpack_from(
            "<QQQQ", header, 24
        )
        entries_lba, entry_count, entry_size = struct.unpack_from("<QII", header, 72)
        (entries_crc,) = struct.unpack_from("<I", header, 88)
        handle.seek(entries_lba * SECTOR)
        table = handle.read(entry_count * entry_size)
    partitions = []
    for index in range(entry_count):
        entry = table[index * entry_size : (index + 1) * entry_size]
        type_guid = entry[0:16]
        if type_guid == b"\x00" * 16:
            continue
        first_lba, last_lba = struct.unpack_from("<QQ", entry, 32)
        name = entry[56:entry_size].decode("utf-16-le").rstrip("\x00")
        partitions.append(
            {
                "index": index + 1,
                "first_lba": first_lba,
                "last_lba": last_lba,
                "sector_count": last_lba - first_lba + 1,
                "byte_offset": first_lba * SECTOR,
                "byte_length": (last_lba - first_lba + 1) * SECTOR,
                "name": name,
            }
        )
    return {
        "disk_size": size,
        "disk_sector_count": size // SECTOR,
        "logical_sector_size": SECTOR,
        "primary_gpt_header_lba": current_lba,
        "backup_gpt_header_lba": backup_lba,
        "first_usable_lba": first_usable,
        "last_usable_lba": last_usable,
        "partition_entry_count": entry_count,
        "partition_entry_size": entry_size,
        "entries_lba": entries_lba,
        "entries_crc32": entries_crc,
        "partitions": partitions,
    }


def extract(image: Path, offset: int, length: int, destination: Path) -> None:
    with image.open("rb") as source, destination.open("wb") as sink:
        source.seek(offset)
        remaining = length
        while remaining:
            block = source.read(min(1 << 20, remaining))
            if not block:
                raise SystemExit("short read while extracting partition")
            sink.write(block)
            remaining -= len(block)
    destination.chmod(0o600)


def splice(image: Path, offset: int, payload: Path) -> None:
    with payload.open("rb") as source, image.open("r+b") as sink:
        sink.seek(offset)
        for block in iter(lambda: source.read(1 << 20), b""):
            sink.write(block)


def run_logged(command: list[str], log_path: Path, expected: tuple[int, ...]) -> int:
    with log_path.open("wb") as log:
        result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
    log_path.chmod(0o600)
    if result.returncode not in expected:
        raise SystemExit(
            f"{command[0]} exited {result.returncode}, expected one of {expected}; "
            f"log: {log_path}"
        )
    return result.returncode


def stamp_epoch(path: Path, epoch: int) -> None:
    payload = struct.pack("<I", epoch)
    with path.open("r+b") as handle:
        handle.seek(S_WTIME_OFFSET)
        handle.write(payload)
        handle.seek(S_LASTCHECK_OFFSET)
        handle.write(payload)


def fs_uuid(path: Path) -> str:
    output = subprocess.run(
        [DUMPE2FS, "-h", str(path)], capture_output=True, text=True, check=True
    ).stdout
    for line in output.splitlines():
        if line.startswith("Filesystem UUID:"):
            return line.split(":", 1)[1].strip()
    raise SystemExit(f"no filesystem UUID reported for {path}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", required=True, type=Path)
    parser.add_argument("--raw", required=True, type=Path, help="raw userdata from script 74")
    parser.add_argument("--tag", default="20260722")
    parser.add_argument(
        "--epoch",
        type=int,
        default=0,
        help="superblock normalization epoch (default: current time, recorded)",
    )
    args = parser.parse_args()

    build_dir: Path = args.build_dir
    raw_in: Path = args.raw
    tag = args.tag
    epoch = args.epoch or int(time.time())
    if not raw_in.is_file():
        raise SystemExit(f"missing raw userdata: {raw_in}")
    build_dir.mkdir(parents=True, exist_ok=True)
    build_dir.chmod(0o700)

    raw = build_dir / f"xiaomi-lmi-d114-r2-most-complete-userdata-{tag}.normalized.img"
    base = build_dir / "lmi-d114-rootfs-base.ext4"
    candidate = build_dir / f"lmi-d114-rootfs-p2-candidate-{tag}.ext4"
    sparse = build_dir / f"xiaomi-lmi-d114-r2-most-complete-userdata-{tag}.android-sparse.img"
    repair_log = build_dir / "candidate-preinstall-e2fsck-repair.log"
    verify_log = build_dir / "candidate-preinstall-e2fsck-verify.log"
    manifest_path = build_dir / f"d114-r2-staging-manifest-{tag}.json"
    for output in (raw, base, candidate, sparse, manifest_path, repair_log, verify_log):
        if output.exists():
            raise SystemExit(f"refusing to overwrite output: {output}")

    print(f"copying raw image for normalization: {raw}")
    subprocess.run(
        ["cp", "--reflink=never", "--sparse=always", str(raw_in), str(raw)], check=True
    )
    raw.chmod(0o600)

    geometry = parse_gpt(raw)
    if len(geometry["partitions"]) != 2:
        raise SystemExit(f"expected 2 partitions, found {len(geometry['partitions'])}")
    p1, p2 = geometry["partitions"]

    print("normalizing p1 (boot) filesystem UUID")
    p1_tmp = build_dir / ".p1-normalize.ext"
    extract(raw, p1["byte_offset"], p1["byte_length"], p1_tmp)
    subprocess.run([TUNE2FS, "-U", PMOS_BOOT_UUID, str(p1_tmp)], check=True)
    run_logged(
        [E2FSCK, "-f", "-p", str(p1_tmp)], build_dir / "p1-e2fsck-normalize.log", (0, 1)
    )
    assert fs_uuid(p1_tmp) == PMOS_BOOT_UUID
    splice(raw, p1["byte_offset"], p1_tmp)
    p1_tmp.unlink()

    print("normalizing p2 (root) filesystem UUID")
    p2_tmp = build_dir / ".p2-normalize.ext"
    extract(raw, p2["byte_offset"], p2["byte_length"], p2_tmp)
    subprocess.run([TUNE2FS, "-U", PMOS_ROOT_UUID, str(p2_tmp)], check=True)
    run_logged(
        [E2FSCK, "-f", "-p", str(p2_tmp)], build_dir / "p2-e2fsck-normalize.log", (0, 1)
    )
    assert fs_uuid(p2_tmp) == PMOS_ROOT_UUID
    stamp_epoch(p2_tmp, epoch)
    splice(raw, p2["byte_offset"], p2_tmp)
    p2_tmp.unlink()

    print("extracting base ext4 from normalized raw")
    extract(raw, p2["byte_offset"], p2["byte_length"], base)

    print("deriving candidate: copy + e2fsck repair + verify + epoch stamp")
    subprocess.run(
        ["cp", "--reflink=never", "--sparse=always", str(base), str(candidate)],
        check=True,
    )
    candidate.chmod(0o600)
    repair_exit = run_logged([E2FSCK, "-f", "-y", str(candidate)], repair_log, (0, 1))
    verify_exit = run_logged([E2FSCK, "-f", "-n", str(candidate)], verify_log, (0,))
    stamp_epoch(candidate, epoch)

    print("building baseline android-sparse image")
    subprocess.run([IMG2SIMG, str(raw), str(sparse), str(SECTOR)], check=True)
    sparse.chmod(0o600)
    expanded_check = build_dir / ".sparse-expand-check.img"
    subprocess.run([SIMG2IMG, str(sparse), str(expanded_check)], check=True)
    if sha256_file(expanded_check) != sha256_file(raw):
        expanded_check.unlink()
        raise SystemExit("sparse image does not round-trip to the normalized raw")
    expanded_check.unlink()

    manifest = {
        "schema": "lmi-p2-d114-r2-staging-manifest/v1",
        "tag": tag,
        "input_raw": {"path": str(raw_in), "sha256": sha256_file(raw_in), "size": raw_in.stat().st_size},
        "normalized_raw": {"path": str(raw), "sha256": sha256_file(raw), "size": raw.stat().st_size},
        "base_ext4": {"path": str(base), "sha256": sha256_file(base), "size": base.stat().st_size},
        "candidate": {
            "path": str(candidate),
            "sha256": sha256_file(candidate),
            "size": candidate.stat().st_size,
            "uuid": fs_uuid(candidate),
            "repair_epoch": epoch,
            "e2fsck_repair_exit": repair_exit,
            "e2fsck_verify_exit": verify_exit,
            "repair_log_sha256": sha256_file(repair_log),
            "verify_log_sha256": sha256_file(verify_log),
        },
        "sparse": {"path": str(sparse), "sha256": sha256_file(sparse), "size": sparse.stat().st_size},
        "uuids": {"pmos_boot_uuid": PMOS_BOOT_UUID, "pmos_root_uuid": PMOS_ROOT_UUID},
        "geometry": geometry,
        "tools": {
            name: sha256_file(Path(path))
            for name, path in (
                ("tune2fs", TUNE2FS),
                ("e2fsck", E2FSCK),
                ("dumpe2fs", DUMPE2FS),
                ("img2simg", IMG2SIMG),
                ("simg2img", SIMG2IMG),
            )
        },
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    manifest_path.chmod(0o600)
    print(json.dumps({k: manifest[k] for k in ("normalized_raw", "base_ext4", "candidate", "sparse")}, indent=2))
    print(f"staging manifest: {manifest_path}")


if __name__ == "__main__":
    main()
