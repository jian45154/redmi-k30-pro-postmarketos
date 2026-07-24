"""Small deterministic binary fixtures for artifact semantic validation tests."""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
import gzip
import hashlib
import os
from pathlib import Path
import unittest
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


def _make_aarch64_elf(tag: bytes) -> bytes:
    size = 120 + len(tag)
    value = bytearray(size)
    value[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", value, 16, 2, 183, 1)
    struct.pack_into("<QQQ", value, 24, 0x400040, 64, 0)
    struct.pack_into("<IHHHHHH", value, 48, 0, 64, 56, 1, 0, 0, 0)
    struct.pack_into(
        "<IIQQQQQQ",
        value,
        64,
        1,
        5,
        0,
        0x400000,
        0x400000,
        size,
        size,
        4096,
    )
    value[120:] = tag
    return bytes(value)


SSH_CLIENTS = {
    name: _make_aarch64_elf(name.encode("ascii"))
    for name in ("ssh", "scp", "sftp", "ssh-add", "ssh-agent", "ssh-keyscan")
}
BUSYBOX = _make_aarch64_elf(b"busybox")
NMCLI = _make_aarch64_elf(b"nmcli")
NETWORKMANAGER_DAEMON = _make_aarch64_elf(b"NetworkManager")
NETWORKMANAGER_WIFI_PLUGIN = _make_aarch64_elf(
    b"libnm-device-plugin-wifi.so"
)
NETWORKMANAGER_SERVICE = b"#!/sbin/openrc-run\ncommand=/usr/sbin/NetworkManager\n"
NETWORKMANAGER_VENDOR_INTERFACES = (
    b"[main]\nplugins=keyfile\n\n[ifupdown]\nmanaged=true\n"
)
NETWORKMANAGER_VENDOR_DHCP = b"[main]\ndhcp=internal\n"


def _apk_q1(value: bytes) -> str:
    return "Q1" + base64.b64encode(
        hashlib.sha1(value, usedforsecurity=False).digest()
    ).decode("ascii").rstrip("=")


SSH_KEYGEN = _make_aarch64_elf(b"ssh-keygen")
SSHD_PAM = _make_aarch64_elf(b"sshd.pam")
SSHD_AUTH = _make_aarch64_elf(b"sshd-auth.pam")
SSHD_SESSION = _make_aarch64_elf(b"sshd-session.pam")
SSHD_PAM_CONFIG = b"auth required pam_unix.so\naccount required pam_unix.so\n"
SSHD_SERVICE = b"#!/sbin/openrc-run\ncommand=/usr/sbin/sshd.pam\n"
SSHD_CONFD = b"# OpenSSH daemon options are intentionally unset.\n"
PAM_BASE_AUTH = b"auth required pam_unix.so nullok\nauth required pam_nologin.so\nauth required pam_env.so\n"
PAM_BASE_ACCOUNT = b"account required pam_unix.so\naccount required pam_nologin.so\n"
PAM_BASE_PASSWORD = b"password required pam_unix.so nullok sha512 shadow\n"
PAM_BASE_SESSION = b"session include base-session-noninteractive\n"
PAM_BASE_SESSION_NONINTERACTIVE = b"session required pam_env.so\nsession required pam_limits.so\nsession required pam_unix.so\n"
PAM_UNIX = _make_aarch64_elf(b"pam_unix.so")
PAM_NOLOGIN = _make_aarch64_elf(b"pam_nologin.so")
PAM_ENV = _make_aarch64_elf(b"pam_env.so")
PAM_LIMITS = _make_aarch64_elf(b"pam_limits.so")
LIBPAM = _make_aarch64_elf(b"libpam.so.0.85.1")


APK_INSTALLED = f"""P:openssh-keygen
V:9.9_p2-r0
A:aarch64
F:usr/bin
R:ssh-keygen
Z:{_apk_q1(SSH_KEYGEN)}

P:openssh-server-common
V:9.9_p2-r0
A:aarch64
F:etc/ssh
R:sshd_config
Z:{_apk_q1(SSHD_CONFIG if "SSHD_CONFIG" in globals() else b"packaged-sshd-config")}

P:openssh-server-common-openrc
V:9.9_p2-r0
A:aarch64
F:etc/conf.d
R:sshd
Z:{_apk_q1(SSHD_CONFD)}
F:etc/init.d
R:sshd
Z:{_apk_q1(SSHD_SERVICE)}

P:openssh-server-pam
V:9.9_p2-r0
A:aarch64
F:etc/pam.d
R:sshd
Z:{_apk_q1(SSHD_PAM_CONFIG)}
F:usr/lib/ssh
R:sshd-auth.pam
Z:{_apk_q1(SSHD_AUTH)}
R:sshd-session.pam
Z:{_apk_q1(SSHD_SESSION)}
F:usr/sbin
R:sshd.pam
Z:{_apk_q1(SSHD_PAM)}

P:linux-pam
V:1.7.1-r2
A:aarch64
F:usr/lib
R:libpam.so.0
Z:Q1AAAAAAAAAAAAAAAAAAAAAAAAAAA
R:libpam.so.0.85.1
Z:{_apk_q1(LIBPAM)}
F:usr/lib/pam.d
R:base-auth
Z:{_apk_q1(PAM_BASE_AUTH)}
R:base-account
Z:{_apk_q1(PAM_BASE_ACCOUNT)}
R:base-password
Z:{_apk_q1(PAM_BASE_PASSWORD)}
R:base-session
Z:{_apk_q1(PAM_BASE_SESSION)}
R:base-session-noninteractive
Z:{_apk_q1(PAM_BASE_SESSION_NONINTERACTIVE)}
F:usr/lib/security
R:pam_unix.so
Z:{_apk_q1(PAM_UNIX)}
R:pam_nologin.so
Z:{_apk_q1(PAM_NOLOGIN)}
R:pam_env.so
Z:{_apk_q1(PAM_ENV)}
R:pam_limits.so
Z:{_apk_q1(PAM_LIMITS)}

P:openssh-client-default
V:9.9_p2-r0
A:aarch64
F:usr/bin
R:ssh
Z:{_apk_q1(SSH_CLIENTS["ssh"])}

P:openssh-client-common
V:9.9_p2-r0
A:aarch64
F:usr/bin
R:scp
Z:{_apk_q1(SSH_CLIENTS["scp"])}
R:sftp
Z:{_apk_q1(SSH_CLIENTS["sftp"])}
R:ssh-add
Z:{_apk_q1(SSH_CLIENTS["ssh-add"])}
R:ssh-agent
Z:{_apk_q1(SSH_CLIENTS["ssh-agent"])}
R:ssh-keyscan
Z:{_apk_q1(SSH_CLIENTS["ssh-keyscan"])}

P:networkmanager
V:1.52.2-r0
A:aarch64
F:usr/sbin
R:NetworkManager
Z:{_apk_q1(NETWORKMANAGER_DAEMON)}
F:usr/lib/NetworkManager/conf.d
R:00-interfaces.conf
Z:{_apk_q1(NETWORKMANAGER_VENDOR_INTERFACES)}
R:20-dhcp-internal.conf
Z:{_apk_q1(NETWORKMANAGER_VENDOR_DHCP)}

P:networkmanager-openrc
V:1.52.2-r0
A:aarch64
F:etc/init.d
R:networkmanager
Z:{_apk_q1(NETWORKMANAGER_SERVICE)}

P:networkmanager-cli
V:1.52.2-r0
A:aarch64
F:usr/bin
R:nmcli
Z:{_apk_q1(NMCLI)}

P:networkmanager-wifi
V:1.52.2-r0
A:aarch64
F:usr/lib/NetworkManager/1.52.2
R:libnm-device-plugin-wifi.so
Z:{_apk_q1(NETWORKMANAGER_WIFI_PLUGIN)}

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

""".encode()
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
DisableForwarding no
PermitTTY yes
AllowAgentForwarding yes
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
PermitOpen any
PermitListen any
GatewayPorts no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
LogLevel VERBOSE
Subsystem sftp internal-sftp
"""
AUTHORIZED_KEYS = (
    b"ssh-ed25519 "
    b"AAAAC3NzaC1lZDI1NTE5AAAAIAABAgMEBQYHCAkKCwwNDg8QERITFBUWFxgZGhscHR4f "
    b"lmi@test\n"
)
RELEASE_IDENTITY = b"schema=lmi-p1-release-identity/v2\nscope=lmi-p1-ssh\n"
ROOTCTL = b"#!/bin/sh\nexec /bin/false\n"
SUDOERS = b"root ALL=(ALL) ALL\n@includedir /etc/sudoers.d\n"
SUDOERS_DROPIN = b"lmi ALL=(root) NOPASSWD: /usr/sbin/lmi-rootctl\n"
PASSWD = (
    b"root:x:0:0:root:/root:/bin/ash\n"
    b"lmi:x:10000:10000::/home/lmi:/bin/ash\n"
)
GROUP = (
    b"root:x:0:root\n"
    b"wheel:x:10:root\n"
    b"shadow:x:42:\n"
    b"lmi:x:10000:\n"
)
SHADOW = (
    b"root:!:20000:0:99999:7:::\n"
    b"lmi:!::0:99999:7:::\n"
    b"daemon:$6$private-shadow-fixture:20000:0:99999:7:::\n"
)
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
    busybox: Path
    rootctl: Path
    sudoers: Path
    sudoers_dropin: Path
    nmcli: Path
    networkmanager_daemon: Path
    networkmanager_service: Path
    networkmanager_wifi_plugin: Path
    networkmanager_vendor_interfaces: Path
    networkmanager_vendor_dhcp: Path
    sshd_config: Path
    sshd_service: Path
    sshd_pam: Path
    sshd_pam_config: Path
    sshd_confd: Path
    sshd_auth: Path
    sshd_session: Path
    ssh_keygen: Path
    pam_base_auth: Path
    pam_base_account: Path
    pam_base_password: Path
    pam_base_session: Path
    pam_base_session_noninteractive: Path
    pam_unix: Path
    pam_nologin: Path
    pam_env: Path
    pam_limits: Path
    libpam: Path
    ssh: Path
    scp: Path
    sftp: Path
    ssh_add: Path
    ssh_agent: Path
    ssh_keyscan: Path
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
            busybox=self.busybox,
            rootctl=self.rootctl,
            sudoers=self.sudoers,
            sudoers_dropin=self.sudoers_dropin,
            nmcli=self.nmcli,
            networkmanager_daemon=self.networkmanager_daemon,
            networkmanager_service=self.networkmanager_service,
            networkmanager_wifi_plugin=self.networkmanager_wifi_plugin,
            networkmanager_vendor_interfaces=self.networkmanager_vendor_interfaces,
            networkmanager_vendor_dhcp=self.networkmanager_vendor_dhcp,
            sshd_config=self.sshd_config,
            sshd_service=self.sshd_service,
            sshd_pam=self.sshd_pam,
            sshd_pam_config=self.sshd_pam_config,
            sshd_confd=self.sshd_confd,
            sshd_auth=self.sshd_auth,
            sshd_session=self.sshd_session,
            ssh_keygen=self.ssh_keygen,
            pam_base_auth=self.pam_base_auth,
            pam_base_account=self.pam_base_account,
            pam_base_password=self.pam_base_password,
            pam_base_session=self.pam_base_session,
            pam_base_session_noninteractive=self.pam_base_session_noninteractive,
            pam_unix=self.pam_unix,
            pam_nologin=self.pam_nologin,
            pam_env=self.pam_env,
            pam_limits=self.pam_limits,
            libpam=self.libpam,
            ssh=self.ssh,
            scp=self.scp,
            sftp=self.sftp,
            ssh_add=self.ssh_add,
            ssh_agent=self.ssh_agent,
            ssh_keyscan=self.ssh_keyscan,
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
            "rootfs_busybox": self.busybox,
            "rootfs_rootctl": self.rootctl,
            "rootfs_sudoers": self.sudoers,
            "rootfs_sudoers_dropin": self.sudoers_dropin,
            "rootfs_nmcli": self.nmcli,
            "rootfs_networkmanager_daemon": self.networkmanager_daemon,
            "rootfs_networkmanager_service": self.networkmanager_service,
            "rootfs_networkmanager_wifi_plugin": (
                self.networkmanager_wifi_plugin
            ),
            "rootfs_networkmanager_vendor_interfaces": (
                self.networkmanager_vendor_interfaces
            ),
            "rootfs_networkmanager_vendor_dhcp": self.networkmanager_vendor_dhcp,
            "rootfs_sshd_config": self.sshd_config,
            "rootfs_sshd_service": self.sshd_service,
            "rootfs_sshd_pam": self.sshd_pam,
            "rootfs_sshd_pam_config": self.sshd_pam_config,
            "rootfs_sshd_confd": self.sshd_confd,
            "rootfs_sshd_auth": self.sshd_auth,
            "rootfs_sshd_session": self.sshd_session,
            "rootfs_ssh_keygen": self.ssh_keygen,
            "rootfs_pam_base_auth": self.pam_base_auth,
            "rootfs_pam_base_account": self.pam_base_account,
            "rootfs_pam_base_password": self.pam_base_password,
            "rootfs_pam_base_session": self.pam_base_session,
            "rootfs_pam_base_session_noninteractive": (
                self.pam_base_session_noninteractive
            ),
            "rootfs_pam_unix": self.pam_unix,
            "rootfs_pam_nologin": self.pam_nologin,
            "rootfs_pam_env": self.pam_env,
            "rootfs_pam_limits": self.pam_limits,
            "rootfs_libpam": self.libpam,
            "rootfs_ssh": self.ssh,
            "rootfs_scp": self.scp,
            "rootfs_sftp": self.sftp,
            "rootfs_ssh_add": self.ssh_add,
            "rootfs_ssh_agent": self.ssh_agent,
            "rootfs_ssh_keyscan": self.ssh_keyscan,
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
    try:
        actual_digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    except OSError:
        actual_digest = None
    if actual_digest != E2FS_TOOL_SHA256:
        # Fixture bytes are only reproducible with the pinned e2fsprogs build;
        # on other hosts these tests skip instead of failing so the public CI
        # can run the portable remainder of the suite.
        if os.environ.get("LMI_P1_REQUIRE_PINNED_FIXTURE_TOOLS") == "1":
            raise RuntimeError(f"untrusted fixture mkfs binary: {binary.name}")
        raise unittest.SkipTest(
            f"fixture mkfs binary is not the pinned e2fsprogs build: {binary}; "
            "set LMI_P1_REQUIRE_PINNED_FIXTURE_TOOLS=1 to fail instead"
        )
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
        "/",
        "/bin",
        "/etc",
        "/etc/conf.d",
        "/etc/doas.d",
        "/etc/init.d",
        "/etc/NetworkManager",
        "/etc/NetworkManager/conf.d",
        "/etc/NetworkManager/system-connections",
        "/etc/pam.d",
        "/etc/ssh",
        "/etc/sudoers.d",
        "/home",
        "/run",
        "/var",
        "/var/run",
        "/usr",
        "/usr/bin",
        "/usr/lib",
        "/usr/lib/NetworkManager",
        "/usr/lib/NetworkManager/1.52.2",
        "/usr/lib/NetworkManager/conf.d",
        "/usr/lib/ssh",
        "/usr/lib/pam.d",
        "/usr/lib/security",
        "/usr/sbin",
        "/usr/bin/ash",
        "/usr/bin/busybox",
        "/usr/sbin/NetworkManager",
        "/usr/bin/ssh-keygen",
        "/etc/pam.d/sshd",
        "/etc/ssh/sshd_config",
        "/etc/init.d/sshd",
        "/usr/sbin/sshd.pam",
        "/etc/conf.d/sshd",
        "/usr/lib/ssh/sshd-auth.pam",
        "/usr/lib/ssh/sshd-session.pam",
        "/usr/lib/pam.d/base-auth",
        "/usr/lib/pam.d/base-account",
        "/usr/lib/pam.d/base-password",
        "/usr/lib/pam.d/base-session",
        "/usr/lib/pam.d/base-session-noninteractive",
        "/usr/lib/security/pam_unix.so",
        "/usr/lib/security/pam_nologin.so",
        "/usr/lib/security/pam_env.so",
        "/usr/lib/security/pam_limits.so",
        "/usr/lib/libpam.so.0",
        "/usr/lib/libpam.so.0.85.1",
        "/etc/passwd",
        "/etc/group",
        "/etc/sudoers",
        "/etc/sudoers.d/90-lmi-rootctl",
        "/usr/sbin/lmi-rootctl",
        "/usr/bin/nmcli",
        "/etc/init.d/networkmanager",
        "/usr/lib/NetworkManager/1.52.2/libnm-device-plugin-wifi.so",
        "/usr/lib/NetworkManager/conf.d/00-interfaces.conf",
        "/usr/lib/NetworkManager/conf.d/20-dhcp-internal.conf",
        "/etc/NetworkManager/system-connections/lmi-usb0.nmconnection",
        "/etc/NetworkManager/conf.d/90-lmi-usb0-takeover.conf",
        "/usr/bin/ssh",
        "/usr/bin/scp",
        "/usr/bin/sftp",
        "/usr/bin/ssh-add",
        "/usr/bin/ssh-agent",
        "/usr/bin/ssh-keyscan",
        "/usr/bin/unudhcpd",
        "/etc/init.d/unudhcpd",
        "/etc/init.d/unudhcpd.usb0",
        "/etc/conf.d/unudhcpd.usb0",
        "/usr/sbin/lmi-usb0-dhcp",
        "/etc/init.d/lmi-usb0-dhcp",
        "/etc/runlevels/default/networkmanager",
        "/etc/runlevels/default/lmi-usb0-dhcp",
        "/etc/runlevels/default/sshd",
        "/etc/runlevels/default/lmi-qrtr-ns",
        "/etc/runlevels/default/lmi-cnss-daemon",
        "/etc/runlevels/default/pd-mapper",
        "/etc/runlevels/default/rmtfs",
        "/etc/runlevels/default/tqftpserv",
        "/etc/runlevels/default/lmi-cnss-fs-ready",
        "/etc/runlevels/default/lmi-wlan-on",
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
    for internal_path in ("/etc/shadow", "/etc/shadow-"):
        for field, value in (("uid", 0), ("gid", 42)):
            subprocess.run(
                [
                    "/usr/sbin/debugfs",
                    "-w",
                    "-R",
                    f"set_inode_field {internal_path} {field} {value}",
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
    for internal_path in (
        "/home/lmi",
        "/home/lmi/.ssh",
        "/home/lmi/.ssh/authorized_keys",
    ):
        for field, value in (("uid", 10000), ("gid", 10000)):
            subprocess.run(
                [
                    "/usr/sbin/debugfs",
                    "-w",
                    "-R",
                    f"set_inode_field {internal_path} {field} {value}",
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
        "busybox": (source / "usr/bin/busybox", BUSYBOX, 0o755),
        "rootctl": (source / "usr/sbin/lmi-rootctl", ROOTCTL, 0o755),
        "sudoers": (source / "etc/sudoers", SUDOERS, 0o440),
        "sudoers_dropin": (
            source / "etc/sudoers.d/90-lmi-rootctl",
            SUDOERS_DROPIN,
            0o440,
        ),
        "passwd": (source / "etc/passwd", PASSWD, 0o644),
        "group": (source / "etc/group", GROUP, 0o644),
        "shadow": (source / "etc/shadow", SHADOW, 0o640),
        "shadow_backup": (source / "etc/shadow-", SHADOW, 0o640),
        "nmcli": (source / "usr/bin/nmcli", NMCLI, 0o755),
        "networkmanager_daemon": (
            source / "usr/sbin/NetworkManager",
            NETWORKMANAGER_DAEMON,
            0o755,
        ),
        "networkmanager_wifi_plugin": (
            source
            / "usr/lib/NetworkManager/1.52.2/libnm-device-plugin-wifi.so",
            NETWORKMANAGER_WIFI_PLUGIN,
            0o755,
        ),
        "networkmanager_vendor_interfaces": (
            source / "usr/lib/NetworkManager/conf.d/00-interfaces.conf",
            NETWORKMANAGER_VENDOR_INTERFACES,
            0o644,
        ),
        "networkmanager_vendor_dhcp": (
            source / "usr/lib/NetworkManager/conf.d/20-dhcp-internal.conf",
            NETWORKMANAGER_VENDOR_DHCP,
            0o644,
        ),
        "sshd_config": (source / "etc/ssh/sshd_config", SSHD_CONFIG, 0o600),
        "sshd_service": (source / "etc/init.d/sshd", SSHD_SERVICE, 0o755),
        "sshd_pam": (source / "usr/sbin/sshd.pam", SSHD_PAM, 0o755),
        "sshd_pam_config": (
            source / "etc/pam.d/sshd",
            SSHD_PAM_CONFIG,
            0o644,
        ),
        "sshd_confd": (source / "etc/conf.d/sshd", SSHD_CONFD, 0o644),
        "sshd_auth": (source / "usr/lib/ssh/sshd-auth.pam", SSHD_AUTH, 0o755),
        "sshd_session": (
            source / "usr/lib/ssh/sshd-session.pam",
            SSHD_SESSION,
            0o755,
        ),
        "ssh_keygen": (source / "usr/bin/ssh-keygen", SSH_KEYGEN, 0o755),
        "pam_base_auth": (source / "usr/lib/pam.d/base-auth", PAM_BASE_AUTH, 0o644),
        "pam_base_account": (source / "usr/lib/pam.d/base-account", PAM_BASE_ACCOUNT, 0o644),
        "pam_base_password": (source / "usr/lib/pam.d/base-password", PAM_BASE_PASSWORD, 0o644),
        "pam_base_session": (source / "usr/lib/pam.d/base-session", PAM_BASE_SESSION, 0o644),
        "pam_base_session_noninteractive": (
            source / "usr/lib/pam.d/base-session-noninteractive",
            PAM_BASE_SESSION_NONINTERACTIVE,
            0o644,
        ),
        "pam_unix": (source / "usr/lib/security/pam_unix.so", PAM_UNIX, 0o755),
        "pam_nologin": (source / "usr/lib/security/pam_nologin.so", PAM_NOLOGIN, 0o755),
        "pam_env": (source / "usr/lib/security/pam_env.so", PAM_ENV, 0o755),
        "pam_limits": (source / "usr/lib/security/pam_limits.so", PAM_LIMITS, 0o755),
        "libpam": (source / "usr/lib/libpam.so.0.85.1", LIBPAM, 0o755),
        "ssh": (source / "usr/bin/ssh", SSH_CLIENTS["ssh"], 0o755),
        "scp": (source / "usr/bin/scp", SSH_CLIENTS["scp"], 0o755),
        "sftp": (source / "usr/bin/sftp", SSH_CLIENTS["sftp"], 0o755),
        "ssh_add": (source / "usr/bin/ssh-add", SSH_CLIENTS["ssh-add"], 0o755),
        "ssh_agent": (
            source / "usr/bin/ssh-agent",
            SSH_CLIENTS["ssh-agent"],
            0o755,
        ),
        "ssh_keyscan": (
            source / "usr/bin/ssh-keyscan",
            SSH_CLIENTS["ssh-keyscan"],
            0o755,
        ),
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
            NETWORKMANAGER_SERVICE,
            0o755,
        ),
    }
    for path, value, mode in source_files.values():
        _write_fixture_file(path, value, mode)
    (source / "home").chmod(0o755)
    (source / "home/lmi").chmod(0o755)
    (source / "home/lmi/.ssh").chmod(0o700)
    (source / "bin").symlink_to("usr/bin")
    (source / "usr/bin/ash").symlink_to("/usr/bin/busybox")
    (source / "usr/lib/libpam.so.0").symlink_to("libpam.so.0.85.1")
    (source / "run").mkdir()
    (source / "var").mkdir()
    (source / "var/run").symlink_to("../run")
    (source / "etc/doas.d").mkdir(parents=True)
    runlevel = source / "etc/runlevels/default"
    runlevel.mkdir(parents=True)
    (runlevel / "sshd").symlink_to("/etc/init.d/sshd")
    (runlevel / "networkmanager").symlink_to("/etc/init.d/networkmanager")
    (runlevel / "lmi-usb0-dhcp").symlink_to("/etc/init.d/lmi-usb0-dhcp")
    for name, target in (
        ("lmi-qrtr-ns", "/etc/init.d/lmi-qrtr-ns"),
        ("lmi-cnss-daemon", "/etc/init.d/lmi-cnss-daemon"),
        ("pd-mapper", "/etc/init.d/pd-mapper"),
        ("rmtfs", "/etc/init.d/rmtfs"),
        ("tqftpserv", "/etc/init.d/tqftpserv"),
        ("lmi-cnss-fs-ready", "/etc/init.d/lmi-cnss-fs-ready"),
        ("lmi-wlan-on", "/etc/init.d/lmi-wlan-on"),
    ):
        (runlevel / name).symlink_to(target)
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
        "busybox": source_files["busybox"][0],
        "rootctl": source_files["rootctl"][0],
        "sudoers": source_files["sudoers"][0],
        "sudoers_dropin": source_files["sudoers_dropin"][0],
        "nmcli": source_files["nmcli"][0],
        "networkmanager_daemon": source_files["networkmanager_daemon"][0],
        "networkmanager_service": source_files["networkmanager_service"][0],
        "networkmanager_wifi_plugin": source_files[
            "networkmanager_wifi_plugin"
        ][0],
        "networkmanager_vendor_interfaces": source_files[
            "networkmanager_vendor_interfaces"
        ][0],
        "networkmanager_vendor_dhcp": source_files[
            "networkmanager_vendor_dhcp"
        ][0],
        "sshd_config": source_files["sshd_config"][0],
        "sshd_service": source_files["sshd_service"][0],
        "sshd_pam": source_files["sshd_pam"][0],
        "sshd_pam_config": source_files["sshd_pam_config"][0],
        "sshd_confd": source_files["sshd_confd"][0],
        "sshd_auth": source_files["sshd_auth"][0],
        "sshd_session": source_files["sshd_session"][0],
        "ssh_keygen": source_files["ssh_keygen"][0],
        "pam_base_auth": source_files["pam_base_auth"][0],
        "pam_base_account": source_files["pam_base_account"][0],
        "pam_base_password": source_files["pam_base_password"][0],
        "pam_base_session": source_files["pam_base_session"][0],
        "pam_base_session_noninteractive": source_files[
            "pam_base_session_noninteractive"
        ][0],
        "pam_unix": source_files["pam_unix"][0],
        "pam_nologin": source_files["pam_nologin"][0],
        "pam_env": source_files["pam_env"][0],
        "pam_limits": source_files["pam_limits"][0],
        "libpam": source_files["libpam"][0],
        "ssh": source_files["ssh"][0],
        "scp": source_files["scp"][0],
        "sftp": source_files["sftp"][0],
        "ssh_add": source_files["ssh_add"][0],
        "ssh_agent": source_files["ssh_agent"][0],
        "ssh_keyscan": source_files["ssh_keyscan"][0],
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
