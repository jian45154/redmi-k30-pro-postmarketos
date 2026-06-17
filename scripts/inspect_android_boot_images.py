#!/usr/bin/env python3
import os
import struct
import sys
import zipfile
from pathlib import Path


def read_cstr(blob: bytes) -> str:
    return blob.split(b"\0", 1)[0].decode("utf-8", "replace")


def decode_os_version(value: int) -> str:
    # Android boot image stores A.B.C and YYYY-MM security patch in bit fields.
    a = (value >> 25) & 0x7f
    b = (value >> 18) & 0x7f
    c = (value >> 11) & 0x7f
    year = ((value >> 4) & 0x7f) + 2000
    month = value & 0x0f
    if value == 0:
        return "0"
    return f"{a}.{b}.{c} patch={year:04d}-{month:02d}"


def align(value: int, page_size: int) -> int:
    return (value + page_size - 1) // page_size * page_size


def inspect_boot_image(path: Path) -> None:
    data = path.read_bytes()
    if data[:8] != b"ANDROID!":
        print(f"{path.name}: not an Android boot image")
        return

    fields = struct.unpack_from("<10I", data, 8)
    kernel_size = fields[0]
    kernel_addr = fields[1]
    ramdisk_size = fields[2]
    ramdisk_addr = fields[3]
    second_size = fields[4]
    second_addr = fields[5]
    tags_addr = fields[6]
    page_size = fields[7]
    header_version = fields[8]
    os_version = fields[9]

    name = read_cstr(data[48:64])
    cmdline = read_cstr(data[64:64 + 512])
    extra_cmdline = read_cstr(data[608:608 + 1024])
    full_cmdline = " ".join(x for x in [cmdline, extra_cmdline] if x).strip()

    print(f"## {path.name}")
    print(f"type=android_boot_image")
    print(f"file_size={path.stat().st_size}")
    print(f"header_version={header_version}")
    print(f"page_size={page_size}")
    print(f"os_version={decode_os_version(os_version)}")
    print(f"kernel_size={kernel_size}")
    print(f"ramdisk_size={ramdisk_size}")
    print(f"second_size={second_size}")
    print(f"kernel_addr=0x{kernel_addr:08x}")
    print(f"ramdisk_addr=0x{ramdisk_addr:08x}")
    print(f"second_addr=0x{second_addr:08x}")
    print(f"tags_addr=0x{tags_addr:08x}")
    print(f"name={name!r}")
    print(f"cmdline={full_cmdline!r}")

    offset = page_size
    kernel_offset = offset
    offset += align(kernel_size, page_size)
    ramdisk_offset = offset
    offset += align(ramdisk_size, page_size)
    second_offset = offset
    offset += align(second_size, page_size)
    print(f"kernel_offset={kernel_offset}")
    print(f"ramdisk_offset={ramdisk_offset}")
    print(f"second_offset={second_offset}")

    if header_version >= 1 and len(data) >= 1648:
        recovery_dtbo_size, recovery_dtbo_offset, header_size = struct.unpack_from("<IQI", data, 1632)
        print(f"recovery_dtbo_size={recovery_dtbo_size}")
        print(f"recovery_dtbo_offset={recovery_dtbo_offset}")
        print(f"header_size={header_size}")
    if header_version >= 2 and len(data) >= 1660:
        dtb_size, dtb_addr = struct.unpack_from("<IQ", data, 1648)
        print(f"dtb_size={dtb_size}")
        print(f"dtb_addr=0x{dtb_addr:016x}")
    print()


def inspect_zip(path: Path) -> None:
    print(f"## {path.name}")
    print("type=zip")
    print(f"file_size={path.stat().st_size}")
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist()[:80]:
            print(f"{info.file_size:>12} {info.filename}")
    print()


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: inspect_android_boot_images.py <image-dir>", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    for path in sorted(root.iterdir(), key=lambda p: p.name.lower()):
        if not path.is_file():
            continue
        if zipfile.is_zipfile(path):
            inspect_zip(path)
            continue
        inspect_boot_image(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
