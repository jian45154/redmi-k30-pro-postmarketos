"""Small deterministic binary fixtures for artifact semantic validation tests."""

from __future__ import annotations

import binascii
from dataclasses import dataclass
import gzip
import hashlib
import os
from pathlib import Path
import stat
import struct
import subprocess
from typing import Iterable
import uuid


SECTOR = 4096
BOOT_UUID = "11111111-2222-4333-8444-555555555555"
ROOT_UUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
DISK_GUID = uuid.UUID("01234567-89ab-4cde-8f01-23456789abcd")
BOOT_PART_GUID = uuid.UUID("10000000-0000-4000-8000-000000000001")
ROOT_PART_GUID = uuid.UUID("20000000-0000-4000-8000-000000000002")
ESP_GUID = uuid.UUID("c12a7328-f81f-11d2-ba4b-00a0c93ec93b")
ARM64_ROOT_GUID = uuid.UUID("b921b045-1df0-41c3-af44-4c6f280d3fae")
GPT_ENTRY_COUNT = 128
BOOT_FIRST_LBA = 256
BOOT_LAST_LBA = 2303
ROOT_FIRST_LBA = 2304
ROOT_LAST_LBA = 10495
USERDATA_LBAS = 10501
E2FS_TOOL_SHA256 = "e42e49656dfc308efeed86f9bfad7746fc22ad1d4a3b0d508b5dba7a4b9a904f"
BASE_CMDLINE = (
    "androidboot.hardware=qcom androidboot.console=ttyMSM0 androidboot.memcg=1 "
    "lpm_levels.sleep_disabled=1 msm_rtb.filter=0x237 service_locator.enable=1 "
    "androidboot.usbcontroller=a600000.dwc3 swiotlb=2048 loop.max_part=7 "
    "cgroup.memory=nokmem,nosocket reboot=panic_warm androidboot.fstab_suffix=qcom "
    "androidboot.init_fatal_reboot_target=recovery"
)
INIT_FUNCTIONS = b"#!/bin/busybox ash\nmount_subpartitions() { :; }\n"
INIT_2ND = b"#!/bin/busybox ash\n. /init_functions.sh\n"
DEVICEINFO = f'''# deterministic installed lmi deviceinfo
deviceinfo_arch="aarch64"
deviceinfo_codename="xiaomi-lmi"
deviceinfo_dtb="qcom/kona-v2.1-lmi"
deviceinfo_rootfs_image_sector_size="4096"
deviceinfo_usb_network_function="rndis.usb0"
deviceinfo_usb_idVendor="0x0525"
deviceinfo_usb_idProduct="0xA4A2"
deviceinfo_flash_method="fastboot"
deviceinfo_flash_fastboot_partition_rootfs="userdata"
deviceinfo_kernel_cmdline="{BASE_CMDLINE}"
deviceinfo_generate_bootimg="true"
deviceinfo_flash_pagesize="4096"
deviceinfo_bootimg_qcdt="false"
deviceinfo_header_version="2"
deviceinfo_append_dtb="false"
deviceinfo_flash_offset_dtb="0x01f00000"
deviceinfo_flash_offset_base="0x00000000"
deviceinfo_flash_offset_kernel="0x00008000"
deviceinfo_flash_offset_ramdisk="0x01000000"
deviceinfo_flash_offset_second="0x00000000"
deviceinfo_flash_offset_tags="0x00000100"
deviceinfo_boot_filesystem="ext2"
'''.encode()
APK_INSTALLED = b"""P:openssh-server-pam
V:9.9_p2-r0
A:aarch64

P:unudhcpd
V:0.1.4-r0
A:aarch64
F:usr/bin
R:unudhcpd
Z:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA

P:unudhcpd-openrc
V:0.1.4-r0
A:aarch64
F:etc/init.d
R:unudhcpd
Z:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA

P:notdhcp
V:1-r0
A:noarch

"""
SSHD_CONFIG = b"""Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_ed25519_key
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
AuthenticationMethods publickey
AuthorizedKeysFile .ssh/authorized_keys
AllowUsers lmi
UsePAM yes
X11Forwarding no
AllowTcpForwarding no
PermitTunnel no
LogLevel VERBOSE
Subsystem sftp internal-sftp
"""
SSHD_SERVICE = b"#!/sbin/openrc-run\ncommand=/usr/sbin/sshd.pam\n"
SSHD_PAM = b"\x7fELF\x02\x01\x01fixture-sshd-pam\n"
AUTHORIZED_KEYS = (
    b"ssh-ed25519 "
    b"AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f "
    b"lmi@test\n"
)
RELEASE_IDENTITY = b"schema=lmi-p1-release-identity/v2\nscope=lmi-p1-ssh\n"
NETWORKMANAGER_PROFILE = b"""[connection]
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
NETWORKMANAGER_TAKEOVER = b"""[device-lmi-usb0]
match-device=interface-name:usb0
managed=1
keep-configuration=no
"""
UNUDHCPD_CONFIG = b"""# The OpenRC instance name also binds the service to usb0. Keep every option
# explicit so this full-userland DHCP server can lease only the management host.
command_args="-i usb0 -s 172.16.42.1 -c 172.16.42.2"
"""
UNUDHCPD_SERVICE = b"#!/sbin/openrc-run\ncommand=/usr/bin/unudhcpd\n"
UNUDHCPD = bytearray(128)
UNUDHCPD[:7] = b"\x7fELF\x02\x01\x01"
UNUDHCPD[16:18] = (2).to_bytes(2, "little")
UNUDHCPD[18:20] = (183).to_bytes(2, "little")
UNUDHCPD = bytes(UNUDHCPD)
USB_DHCP_WRAPPER = b"""#!/bin/sh
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
USB_DHCP_SERVICE = b"""#!/sbin/openrc-run

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


@dataclass(frozen=True)
class ArtifactFixture:
    boot_img: Path
    userdata_img: Path
    vmlinuz: Path
    initramfs: Path
    dtb: Path
    deviceinfo: Path
    staged_deviceinfo: Path
    init_functions: Path
    init_2nd: Path
    fstab: Path
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

    def arguments(self) -> tuple[Path, ...]:
        return (
            self.boot_img,
            self.userdata_img,
            self.vmlinuz,
            self.initramfs,
            self.dtb,
            self.deviceinfo,
            self.staged_deviceinfo,
            self.init_functions,
            self.init_2nd,
            self.fstab,
        )

    def rootfs_bindings(self):
        from scripts.lmi_p1.artifact_semantics import RootfsBindings

        return RootfsBindings(
            apk_installed=self.apk_installed,
            sshd_config=self.sshd_config,
            sshd_service=self.sshd_service,
            sshd_pam=self.sshd_pam,
            authorized_keys=self.authorized_keys,
            release_identity=self.release_identity,
            networkmanager_profile=self.networkmanager_profile,
            networkmanager_takeover=self.networkmanager_takeover,
            unudhcpd=self.unudhcpd,
            unudhcpd_service=self.unudhcpd_service,
            unudhcpd_config=self.unudhcpd_config,
            usb_dhcp_wrapper=self.usb_dhcp_wrapper,
            usb_dhcp_service=self.usb_dhcp_service,
        )

    def input_paths(self) -> dict[str, Path]:
        return {
            "boot_img": self.boot_img,
            "userdata_img": self.userdata_img,
            "vmlinuz": self.vmlinuz,
            "initramfs": self.initramfs,
            "dtb": self.dtb,
            "deviceinfo": self.deviceinfo,
            "staged_deviceinfo": self.staged_deviceinfo,
            "staged_init_functions": self.init_functions,
            "staged_init_2nd": self.init_2nd,
            "fstab": self.fstab,
            "rootfs_apk_installed": self.apk_installed,
            "rootfs_sshd_config": self.sshd_config,
            "rootfs_sshd_service": self.sshd_service,
            "rootfs_sshd_pam": self.sshd_pam,
            "rootfs_authorized_keys": self.authorized_keys,
            "rootfs_release_identity": self.release_identity,
            "rootfs_networkmanager_profile": self.networkmanager_profile,
            "rootfs_networkmanager_takeover": self.networkmanager_takeover,
            "rootfs_unudhcpd": self.unudhcpd,
            "rootfs_unudhcpd_service": self.unudhcpd_service,
            "rootfs_unudhcpd_config": self.unudhcpd_config,
            "rootfs_usb_dhcp_wrapper": self.usb_dhcp_wrapper,
            "rootfs_usb_dhcp_service": self.usb_dhcp_service,
        }


def _pad4(value: bytearray) -> None:
    value.extend(b"\0" * (-len(value) % 4))


def _newc_member(
    name: str, mode: int, data: bytes, ino: int, *, nlink: int | None = None
) -> bytes:
    if nlink is None:
        nlink = 1 if name == "TRAILER!!!" or stat.S_ISREG(mode) else 0
    name_bytes = name.encode() + b"\0"
    fields = (
        ino,
        mode,
        0,
        0,
        nlink,
        0,
        len(data),
        0,
        0,
        0,
        0,
        len(name_bytes),
        0,
    )
    output = bytearray(b"070701" + b"".join(f"{field:08x}".encode() for field in fields))
    output.extend(name_bytes)
    _pad4(output)
    output.extend(data)
    _pad4(output)
    return bytes(output)


def make_cpio(
    *,
    init_functions: bytes = INIT_FUNCTIONS,
    init_2nd: bytes = INIT_2ND,
    deviceinfo: bytes = DEVICEINFO,
    init_mode: int = stat.S_IFREG | 0o755,
    init_data: bytes = b"#!/bin/busybox ash\n",
    blkid_mode: int = stat.S_IFREG | 0o755,
    blkid_data: bytes = b"blkid",
    extra_entries: Iterable[tuple[str, int, bytes]] = (),
) -> bytes:
    entries = (
        (".", stat.S_IFDIR | 0o755, b""),
        ("bin", stat.S_IFDIR | 0o755, b""),
        ("bin/busybox", stat.S_IFREG | 0o755, b"busybox"),
        ("bin/sh", stat.S_IFLNK | 0o777, b"/bin/busybox"),
        ("sbin", stat.S_IFDIR | 0o755, b""),
        ("usr", stat.S_IFDIR | 0o755, b""),
        ("usr/sbin", stat.S_IFDIR | 0o755, b""),
        ("usr/share", stat.S_IFDIR | 0o755, b""),
        ("usr/share/deviceinfo", stat.S_IFDIR | 0o755, b""),
        ("usr/share/misc", stat.S_IFDIR | 0o755, b""),
        ("init", init_mode, init_data),
        ("init_2nd.sh", stat.S_IFREG | 0o755, init_2nd),
        ("init_functions.sh", stat.S_IFREG | 0o644, init_functions),
        ("sbin/blkid", blkid_mode, blkid_data),
        ("usr/sbin/losetup", stat.S_IFREG | 0o755, b"losetup"),
        ("usr/share/deviceinfo/deviceinfo", stat.S_IFREG | 0o644, deviceinfo),
        ("usr/share/misc/source_deviceinfo", stat.S_IFREG | 0o755, b"source"),
    )
    output = bytearray()
    ino = 1
    for name, mode, data in entries:
        output.extend(_newc_member(name, mode, data, ino))
        ino += 1
    for name, mode, data in extra_entries:
        output.extend(_newc_member(name, mode, data, ino))
        ino += 1
    output.extend(_newc_member("TRAILER!!!", 0, b"", ino))
    return bytes(output)


def make_member_bomb(count: int, *, name_width: int = 24) -> bytes:
    def entries() -> Iterable[tuple[str, int, bytes]]:
        yield ("bomb", stat.S_IFDIR | 0o755, b"")
        for index in range(count):
            prefix = f"bomb/{index:08d}-"
            name = prefix + "x" * max(0, name_width - len(prefix))
            yield (name, stat.S_IFREG | 0o644, b"")

    return make_cpio(extra_entries=entries())


def make_kernel() -> bytes:
    kernel = bytearray(256)
    struct.pack_into("<Q", kernel, 8, 0x80000)
    struct.pack_into("<Q", kernel, 16, len(kernel))
    struct.pack_into("<Q", kernel, 24, 0xA)
    kernel[56:60] = b"ARMd"
    kernel[64:] = bytes(range(192))
    return bytes(kernel)


def make_dtb(
    *,
    model: str = "Qualcomm Technologies, Inc. kona v2.1 SoC",
    compatible: tuple[str, ...] = ("qcom,kona",),
    bootargs: str | None = None,
) -> bytes:
    names = ["model", "compatible"]
    if bootargs is not None:
        names.append("bootargs")
    strings = bytearray()
    offsets: dict[str, int] = {}
    for name in names:
        offsets[name] = len(strings)
        strings.extend(name.encode("ascii") + b"\0")

    def begin_node(name: str) -> bytes:
        value = bytearray(struct.pack(">I", 1) + name.encode("ascii") + b"\0")
        _pad4(value)
        return bytes(value)

    def prop(name: str, value: bytes) -> bytes:
        output = bytearray(struct.pack(">III", 3, len(value), offsets[name]))
        output.extend(value)
        _pad4(output)
        return bytes(output)

    reserve = b"\0" * 16
    structure = bytearray(begin_node(""))
    structure.extend(prop("model", model.encode("utf-8") + b"\0"))
    structure.extend(
        prop("compatible", b"".join(item.encode("ascii") + b"\0" for item in compatible))
    )
    if bootargs is not None:
        structure.extend(begin_node("chosen"))
        structure.extend(prop("bootargs", bootargs.encode("ascii") + b"\0"))
        structure.extend(struct.pack(">I", 2))
    structure.extend(struct.pack(">II", 2, 9))
    off_struct = 40 + len(reserve)
    off_strings = off_struct + len(structure)
    totalsize = off_strings + len(strings)
    header = struct.pack(
        ">10I",
        0xD00DFEED,
        totalsize,
        off_struct,
        off_strings,
        40,
        17,
        16,
        0,
        len(strings),
        len(structure),
    )
    return header + reserve + bytes(structure) + bytes(strings)


def fixture_dtb_sha256(dtb: bytes | None = None) -> str:
    return hashlib.sha256(make_dtb() if dtb is None else dtb).hexdigest()


def make_boot(kernel: bytes, ramdisk: bytes, dtb: bytes, *, cmdline: str | None = None) -> bytes:
    if cmdline is None:
        cmdline = (
            f"{BASE_CMDLINE} pmos_boot_uuid={BOOT_UUID} "
            f"pmos_root_uuid={ROOT_UUID} pmos_rootfsopts=defaults"
        )
    header = bytearray(1660)
    header[:8] = b"ANDROID!"
    struct.pack_into(
        "<IIIIIIIIII",
        header,
        8,
        len(kernel),
        0x8000,
        len(ramdisk),
        0x1000000,
        0,
        0,
        0x100,
        SECTOR,
        2,
        0,
    )
    encoded = cmdline.encode("ascii") + b"\0"
    if len(encoded) > 1536:
        raise ValueError("fixture cmdline is too long")
    header[64:576] = encoded[:512].ljust(512, b"\0")
    header[608:1632] = encoded[512:].ljust(1024, b"\0")
    image_id = hashlib.sha1(usedforsecurity=False)
    for component in (kernel, ramdisk, b"", b"", dtb):
        image_id.update(component)
        image_id.update(struct.pack("<I", len(component)))
    header[576:608] = image_id.digest() + b"\0" * 12
    struct.pack_into("<I", header, 1632, 0)
    struct.pack_into("<Q", header, 1636, 0)
    struct.pack_into("<I", header, 1644, 1660)
    struct.pack_into("<I", header, 1648, len(dtb))
    struct.pack_into("<Q", header, 1652, 0x1F00000)
    output = bytearray(header)
    output.extend(b"\0" * (-len(output) % SECTOR))
    for component in (kernel, ramdisk, dtb):
        output.extend(component)
        output.extend(b"\0" * (-len(output) % SECTOR))
    return bytes(output)


def _gpt_entry(
    type_guid: uuid.UUID,
    unique_guid: uuid.UUID,
    first: int,
    last: int,
    name: str,
) -> bytes:
    entry = bytearray(128)
    entry[:16] = type_guid.bytes_le
    entry[16:32] = unique_guid.bytes_le
    struct.pack_into("<QQQ", entry, 32, first, last, 0)
    encoded_name = name.encode("utf-16-le") + b"\0\0"
    entry[56 : 56 + len(encoded_name)] = encoded_name
    return bytes(entry)


def _gpt_header(
    current: int,
    backup: int,
    first_usable: int,
    last_usable: int,
    entries_lba: int,
    entries_crc: int,
) -> bytes:
    header = bytearray(SECTOR)
    header[:8] = b"EFI PART"
    struct.pack_into("<IIII", header, 8, 0x10000, 92, 0, 0)
    struct.pack_into("<QQQQ", header, 24, current, backup, first_usable, last_usable)
    header[56:72] = DISK_GUID.bytes_le
    struct.pack_into("<QIII", header, 72, entries_lba, 128, 128, entries_crc)
    checked = bytearray(header[:92])
    checked[16:20] = b"\0" * 4
    struct.pack_into("<I", header, 16, binascii.crc32(checked) & 0xFFFFFFFF)
    return bytes(header)


def _write_fixture_file(path: Path, value: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(mode)
    os.utime(path, ns=(1_700_000_000_000_000_000,) * 2)


def _run_pinned_mkfs(arguments: list[str]) -> None:
    binary = Path(arguments[0])
    if hashlib.sha256(binary.read_bytes()).hexdigest() != E2FS_TOOL_SHA256:
        raise RuntimeError(f"untrusted fixture mkfs binary: {binary.name}")
    subprocess.run(
        arguments,
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=30,
        env={
            "E2FSPROGS_FAKE_TIME": "1700000000",
            "HOME": "/nonexistent",
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        },
    )


def _make_filesystems(root: Path, source_tree: Path) -> tuple[bytes, bytes]:
    boot = root / "fixture-pmOS_boot.ext2"
    rootfs = root / "fixture-pmOS_root.ext4"
    with boot.open("wb") as stream:
        stream.truncate((BOOT_LAST_LBA - BOOT_FIRST_LBA + 1) * SECTOR)
    with rootfs.open("wb") as stream:
        stream.truncate((ROOT_LAST_LBA - ROOT_FIRST_LBA + 1) * SECTOR)
    _run_pinned_mkfs(
        [
            "/usr/sbin/mkfs.ext2",
            "-F",
            "-q",
            "-b",
            "4096",
            "-E",
            "hash_seed=01234567-89ab-4cde-8f01-23456789abcd,lazy_itable_init=0",
            "-U",
            BOOT_UUID,
            "-L",
            "pmOS_boot",
            str(boot),
        ]
    )
    _run_pinned_mkfs(
        [
            "/usr/sbin/mkfs.ext4",
            "-F",
            "-q",
            "-b",
            "4096",
            "-i",
            "8192",
            "-O",
            "^metadata_csum",
            "-E",
            "hash_seed=01234567-89ab-4cde-8f01-23456789abcd,lazy_itable_init=0,lazy_journal_init=0",
            "-U",
            ROOT_UUID,
            "-L",
            "pmOS_root",
            "-d",
            str(source_tree),
            str(rootfs),
        ]
    )
    root_owned = (
        "/etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
        "/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
        "/usr/bin/unudhcpd",
        "/etc/init.d/unudhcpd",
        "/etc/init.d/unudhcpd.usb0",
        "/etc/conf.d/unudhcpd.usb0",
        "/usr/sbin/lmi-usb0-dhcp",
        "/etc/init.d/lmi-usb0-dhcp",
        "/etc/runlevels/default/networkmanager",
        "/etc/runlevels/default/lmi-usb0-dhcp",
        "/etc/runlevels/default/sshd",
    )
    for internal_path in root_owned:
        for field in ("uid", "gid"):
            subprocess.run(
                [
                    "/usr/sbin/debugfs",
                    "-w",
                    "-R",
                    f"set_inode_field {internal_path} {field} 0",
                    str(rootfs),
                ],
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
    return boot.read_bytes(), rootfs.read_bytes()


def make_userdata(boot_fs: bytes, root_fs: bytes) -> bytes:
    lbas = USERDATA_LBAS
    image = bytearray(lbas * SECTOR)
    protective = bytearray(512)
    protective[446 + 1 : 446 + 4] = b"\x00\x02\x00"
    protective[446 + 4] = 0xEE
    protective[446 + 5 : 446 + 8] = b"\xff\xff\xff"
    struct.pack_into("<II", protective, 446 + 8, 1, lbas - 1)
    protective[510:512] = b"\x55\xaa"
    image[:512] = protective

    table = bytearray(128 * 128)
    table[:128] = _gpt_entry(
        ESP_GUID, BOOT_PART_GUID, BOOT_FIRST_LBA, BOOT_LAST_LBA, "primary"
    )
    table[128:256] = _gpt_entry(
        ARM64_ROOT_GUID, ROOT_PART_GUID, ROOT_FIRST_LBA, ROOT_LAST_LBA, "primary"
    )
    table_crc = binascii.crc32(table) & 0xFFFFFFFF
    image[2 * SECTOR : 2 * SECTOR + len(table)] = table
    backup_entries_lba = lbas - 5
    image[backup_entries_lba * SECTOR : backup_entries_lba * SECTOR + len(table)] = table
    image[SECTOR : 2 * SECTOR] = _gpt_header(
        1, lbas - 1, 6, lbas - 6, 2, table_crc
    )
    image[(lbas - 1) * SECTOR : lbas * SECTOR] = _gpt_header(
        lbas - 1, 1, 6, lbas - 6, backup_entries_lba, table_crc
    )
    image[BOOT_FIRST_LBA * SECTOR : (BOOT_LAST_LBA + 1) * SECTOR] = boot_fs
    image[ROOT_FIRST_LBA * SECTOR : (ROOT_LAST_LBA + 1) * SECTOR] = root_fs
    return bytes(image)


def create_fixture(root: Path) -> ArtifactFixture:
    root.mkdir()
    kernel = make_kernel()
    cpio = make_cpio()
    ramdisk = gzip.compress(cpio, compresslevel=9, mtime=0)
    dtb = make_dtb()
    boot = make_boot(kernel, ramdisk, dtb)
    source = root / "rootfs-source"
    source.mkdir()
    fstab_value = (
        "# <file system> <mount point> <type> <options> <dump> <pass>\n"
        f"UUID={ROOT_UUID} / ext4 defaults 0 0\n"
        f"UUID={BOOT_UUID} /boot ext2 nodev,nosuid,noexec 0 0\n"
    ).encode()
    source_files = {
        "deviceinfo": (
            source / "usr/share/deviceinfo/device-xiaomi-lmi",
            DEVICEINFO,
            0o644,
        ),
        "fstab": (source / "etc/fstab", fstab_value, 0o644),
        "apk_installed": (source / "lib/apk/db/installed", APK_INSTALLED, 0o644),
        "sshd_config": (source / "etc/ssh/sshd_config", SSHD_CONFIG, 0o600),
        "sshd_service": (source / "etc/init.d/sshd", SSHD_SERVICE, 0o755),
        "sshd_pam": (source / "usr/sbin/sshd.pam", SSHD_PAM, 0o755),
        "authorized_keys": (
            source / "home/lmi/.ssh/authorized_keys",
            AUTHORIZED_KEYS,
            0o600,
        ),
        "release_identity": (
            source / "etc/lmi-release-identity",
            RELEASE_IDENTITY,
            0o644,
        ),
        "networkmanager_profile": (
            source / "etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
            NETWORKMANAGER_PROFILE,
            0o600,
        ),
        "networkmanager_takeover": (
            source / "etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
            NETWORKMANAGER_TAKEOVER,
            0o644,
        ),
        "unudhcpd": (source / "usr/bin/unudhcpd", UNUDHCPD, 0o755),
        "unudhcpd_service": (
            source / "etc/init.d/unudhcpd",
            UNUDHCPD_SERVICE,
            0o755,
        ),
        "unudhcpd_config": (
            source / "etc/conf.d/unudhcpd.usb0",
            UNUDHCPD_CONFIG,
            0o644,
        ),
        "usb_dhcp_wrapper": (
            source / "usr/sbin/lmi-usb0-dhcp",
            USB_DHCP_WRAPPER,
            0o755,
        ),
        "usb_dhcp_service": (
            source / "etc/init.d/lmi-usb0-dhcp",
            USB_DHCP_SERVICE,
            0o755,
        ),
        "networkmanager_service": (
            source / "etc/init.d/networkmanager",
            b"#!/sbin/openrc-run\n",
            0o755,
        ),
    }
    for path, value, mode in source_files.values():
        _write_fixture_file(path, value, mode)
    runlevel = source / "etc/runlevels/default"
    runlevel.mkdir(parents=True)
    (runlevel / "sshd").symlink_to("/etc/init.d/sshd")
    (runlevel / "networkmanager").symlink_to("/etc/init.d/networkmanager")
    (runlevel / "lmi-usb0-dhcp").symlink_to("/etc/init.d/lmi-usb0-dhcp")
    (source / "etc/init.d/unudhcpd.usb0").symlink_to("unudhcpd")
    fixture_timestamp = 1_700_000_000_000_000_000
    for item in sorted(source.rglob("*"), key=lambda candidate: len(candidate.parts), reverse=True):
        os.utime(item, ns=(fixture_timestamp, fixture_timestamp), follow_symlinks=False)
    os.utime(source, ns=(fixture_timestamp, fixture_timestamp))
    boot_fs, root_fs = _make_filesystems(root, source)
    paths = {
        "boot_img": root / "boot.img",
        "userdata_img": root / "userdata.img",
        "vmlinuz": root / "vmlinuz",
        "initramfs": root / "initramfs",
        "dtb": root / "lmi.dtb",
        "deviceinfo": source_files["deviceinfo"][0],
        "staged_deviceinfo": root / "staged-deviceinfo",
        "init_functions": root / "init_functions.sh",
        "init_2nd": root / "init_2nd.sh",
        "fstab": source_files["fstab"][0],
        "apk_installed": source_files["apk_installed"][0],
        "sshd_config": source_files["sshd_config"][0],
        "sshd_service": source_files["sshd_service"][0],
        "sshd_pam": source_files["sshd_pam"][0],
        "authorized_keys": source_files["authorized_keys"][0],
        "release_identity": source_files["release_identity"][0],
        "networkmanager_profile": source_files["networkmanager_profile"][0],
        "networkmanager_takeover": source_files["networkmanager_takeover"][0],
        "unudhcpd": source_files["unudhcpd"][0],
        "unudhcpd_service": source_files["unudhcpd_service"][0],
        "unudhcpd_config": source_files["unudhcpd_config"][0],
        "usb_dhcp_wrapper": source_files["usb_dhcp_wrapper"][0],
        "usb_dhcp_service": source_files["usb_dhcp_service"][0],
    }
    paths["boot_img"].write_bytes(boot)
    paths["userdata_img"].write_bytes(make_userdata(boot_fs, root_fs))
    paths["vmlinuz"].write_bytes(kernel)
    paths["initramfs"].write_bytes(ramdisk)
    paths["dtb"].write_bytes(dtb)
    paths["staged_deviceinfo"].write_bytes(DEVICEINFO)
    paths["init_functions"].write_bytes(INIT_FUNCTIONS)
    paths["init_2nd"].write_bytes(INIT_2ND)
    return ArtifactFixture(**paths)


def update_gpt_crcs(image: bytearray) -> None:
    """Recompute both table/header CRCs after a deliberate table mutation."""

    table_size = 128 * 128
    primary_table = bytes(image[2 * SECTOR : 2 * SECTOR + table_size])
    backup_header_lba = len(image) // SECTOR - 1
    backup_header = image[
        backup_header_lba * SECTOR : (backup_header_lba + 1) * SECTOR
    ]
    backup_entries_lba = struct.unpack_from("<Q", backup_header, 72)[0]
    image[
        backup_entries_lba * SECTOR : backup_entries_lba * SECTOR + table_size
    ] = primary_table
    crc = binascii.crc32(primary_table) & 0xFFFFFFFF
    for header_lba in (1, backup_header_lba):
        header = bytearray(image[header_lba * SECTOR : (header_lba + 1) * SECTOR])
        struct.pack_into("<I", header, 88, crc)
        struct.pack_into("<I", header, 16, 0)
        struct.pack_into("<I", header, 16, binascii.crc32(header[:92]) & 0xFFFFFFFF)
        image[header_lba * SECTOR : (header_lba + 1) * SECTOR] = header
