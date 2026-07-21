from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import signal
import shlex
import shutil
import stat
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-p3"
P1_FILES = REPO / "files/lmi-p1"
CONFIRMATION = "lmi-p3:boot-adsp=1"
EXPECTED_KERNEL_RELEASE = "4.19.325-cip128-st12-perf"
EXPECTED_SUBSYSTEM_NAMES = (
    "a650_zap",
    "adsp",
    "cdsp",
    "cvpss",
    "esoc0",
    "ipa_fws",
    "ipa_uc",
    "npu",
    "slpi",
    "spss",
    "venus",
    "wlan",
)
SENSITIVE_MARKERS = (
    "SERIAL-LEAK-123",
    "CPUID-LEAK-456",
    "123e4567-e89b-12d3-a456-426614174000",
    "builder-leak",
    "host-leak",
    "aa:bb:cc:dd:ee:ff",
    "192.0.2.44",
    "2001:db8::1234",
    "SecretWifiMarker",
    "private-user",
)
SERVICES = (
    "lmi-firmware-mount",
    "lmi-qrtr-ns",
    "pd-mapper",
    "rmtfs",
    "tqftpserv",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_executable(path: Path, payload: str) -> None:
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o755)


def replace_exact(payload: str, replacements: dict[str, str]) -> str:
    for old, new in replacements.items():
        if payload.count(old) != 1:
            raise AssertionError(f"fixture injection point changed: {old}")
        payload = payload.replace(old, new)
    return payload


def fake_id_payload() -> str:
    return (
        "#!/bin/sh\n"
        "case \"${1:-}\" in\n"
        "  -u) printf '%s\\n' \"${LMI_P3_FAKE_UID:-0}\" ;;\n"
        "  -g) printf '%s\\n' \"${LMI_P3_FAKE_GID:-0}\" ;;\n"
        "  *) exit 64 ;;\n"
        "esac\n"
    )


def fake_stat_payload(
    *, sysfs_path: Path | None = None, sysfs_drift_marker: Path | None = None
) -> str:
    sysfs = shlex.quote(str(sysfs_path)) if sysfs_path is not None else "''"
    drift_marker = (
        shlex.quote(str(sysfs_drift_marker))
        if sysfs_drift_marker is not None
        else "''"
    )
    return (
        "#!/bin/sh\n"
        f"sysfs_path={sysfs}\n"
        f"sysfs_drift_marker={drift_marker}\n"
        "if [ \"$#\" -eq 3 ] && [ \"$1\" = -c ]; then\n"
        "  path=$3\n"
        "  owner=0:0\n"
        "  mode_override=\n"
        "  [ \"$path\" != \"$sysfs_path\" ] || mode_override=220\n"
        "  [ \"${LMI_P3_NONROOT_PATH:-}\" != \"$path\" ] || owner=1000:1000\n"
        "  if [ \"${LMI_P3_STAT_OVERRIDE_PATH:-}\" = \"$path\" ]; then\n"
        "    owner=${LMI_P3_STAT_OVERRIDE_OWNER:-$owner}\n"
        "    mode_override=${LMI_P3_STAT_OVERRIDE_MODE:-$mode_override}\n"
        "  fi\n"
        "  if [ \"$path\" = \"$sysfs_path\" ] && [ -r \"$sysfs_drift_marker\" ]; then\n"
        "    case \"$(sed -n '1p' \"$sysfs_drift_marker\")\" in\n"
        "      group) owner=0:1000 ;;\n"
        "      owner) owner=1000:0 ;;\n"
        "      mode) mode_override=660 ;;\n"
        "      *) exit 95 ;;\n"
        "    esac\n"
        "  fi\n"
        "  mode=$(/usr/bin/stat -c '%a' \"$path\") || exit\n"
        "  [ -z \"$mode_override\" ] || mode=$mode_override\n"
        "  case \"$2\" in\n"
        "    '%u:%g:%a:%h:%F')\n"
        "      rest=$(/usr/bin/stat -c '%h:%F' \"$path\") || exit\n"
        "      printf '%s:%s:%s\\n' \"$owner\" \"$mode\" \"$rest\"\n"
        "      exit 0\n"
        "      ;;\n"
        "    '%u:%g:%a:%F')\n"
        "      type=$(/usr/bin/stat -c '%F' \"$path\") || exit\n"
        "      printf '%s:%s:%s\\n' \"$owner\" \"$mode\" \"$type\"\n"
        "      exit 0\n"
        "      ;;\n"
        "  esac\n"
        "fi\n"
        "exec /usr/bin/stat \"$@\"\n"
    )


class ControlFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.boot = self.root / "sys/kernel/boot_adsp/boot"
        self.dt = self.root / "sys/firmware/devicetree/base"
        self.deviceinfo = self.root / "usr/share/deviceinfo/device-xiaomi-lmi"
        self.identity = self.root / "etc/lmi-release-identity"
        self.subsystems = self.root / "sys/bus/msm_subsys/devices"
        self.adsp = self.subsystems / "subsys7"
        self.firmware = self.root / "lib/firmware"
        self.firmware_source = self.root / "mnt/vendor/firmware_mnt/image"
        self.inventory = self.root / "etc/lmi-p3/adsp-firmware.inventory"
        self.provenance = self.root / "etc/lmi-p3/adsp-firmware.provenance"
        self.started = self.root / "run/openrc/started"
        self.runtime_root = self.root / "run"
        self.runtime_directory = self.runtime_root / "lmi-p3"
        self.lock_directory = self.runtime_directory / "adsp-transition.lock"
        self.attempt_latch = self.runtime_directory / "adsp-boot-attempted"
        self.bin = self.root / "bin"
        self.route_guard = self.bin / "lmi-p3-route-guard"
        self.rc_service = self.bin / "rc-service"
        self.id = self.bin / "id"
        self.stat = self.bin / "stat"
        self.sha256sum = self.bin / "sha256sum"
        self.uname = self.bin / "uname"
        self.sleep = self.bin / "sleep"
        self.control = self.root / "lmi-adsp-control"
        self.sleep_count = self.root / "sleep-count"
        self.hash_mutation_done = self.root / "hash-mutation-done"
        self.service_failure_marker = self.root / "service-failure"
        self.boot_metadata_drift = self.root / "boot-metadata-drift"

        for directory in (
            self.boot.parent,
            self.dt,
            self.deviceinfo.parent,
            self.identity.parent,
            self.adsp,
            self.firmware,
            self.firmware_source,
            self.inventory.parent,
            self.started,
            self.runtime_root,
            self.bin,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        self.boot.write_text("0\n", encoding="utf-8")
        self.dt.joinpath("model").write_bytes(
            b"Qualcomm Technologies, Inc. xiaomi lmi\0"
        )
        self.dt.joinpath("compatible").write_bytes(
            b"qcom,kona-mtp\0qcom,kona\0qcom,mtp\0"
        )
        self.deviceinfo.write_text(
            'deviceinfo_codename="xiaomi-lmi"\n'
            'deviceinfo_dtb="qcom/kona-v2.1-lmi"\n',
            encoding="utf-8",
        )
        self.identity.write_text(
            "schema=lmi-p1-release-identity/v2\n"
            "scope=lmi-p1-ssh\n"
            "candidate_id=fixture\n"
            "device_xiaomi_lmi=1-r107\n"
            "linux_xiaomi_lmi=4.19.325-r8\n",
            encoding="utf-8",
        )
        self.adsp.joinpath("name").write_text("adsp\n", encoding="utf-8")
        self.adsp.joinpath("firmware_name").write_text("adsp\n", encoding="utf-8")
        self.adsp.joinpath("state").write_text("OFFLINE\n", encoding="utf-8")

        firmware_payloads = {
            "adsp.mdt": b"fixture mdt\n",
            "adsp.b00": b"fixture segment zero\n",
            "adsp.b02": b"fixture segment two\n",
        }
        for name, payload in firmware_payloads.items():
            source = self.firmware_source / name
            source.write_bytes(payload)
            (self.firmware / name).symlink_to(source)

        self.provenance.write_text(
            "schema=lmi-p3-adsp-firmware-provenance/v1\n"
            "source_kind=stock-readonly-firmware-partition\n"
            f"source_root={self.firmware_source}\n"
            f"source_evidence_sha256={'e' * 64}\n"
            "review_id=fixture-review\n",
            encoding="utf-8",
        )
        self.provenance.chmod(0o600)
        self.provenance_sha256 = sha256(self.provenance)
        inventory_lines = [
            "schema=lmi-p3-adsp-firmware-inventory/v1",
            f"provenance_sha256={self.provenance_sha256}",
        ]
        for name in ("adsp.mdt", "adsp.b00", "adsp.b02"):
            source = self.firmware_source / name
            inventory_lines.append(f"file:{name}:{source.stat().st_size}:{sha256(source)}")
        self.inventory.write_text("\n".join(inventory_lines) + "\n", encoding="utf-8")
        self.inventory.chmod(0o600)
        self.inventory_sha256 = sha256(self.inventory)

        for service in SERVICES:
            self.started.joinpath(service).touch()
        write_executable(
            self.route_guard,
            "#!/bin/sh\n[ \"${LMI_P3_FAIL_ROUTE_GUARD:-0}\" = 0 ]\n",
        )
        write_executable(
            self.rc_service,
            "#!/bin/sh\n"
            "[ \"$#\" -eq 2 ] && [ \"$2\" = status ] || exit 91\n"
            f"[ ! -e {shlex.quote(str(self.service_failure_marker))} ] || exit 93\n"
            "[ \"${LMI_P3_FAIL_SERVICE:-}\" != \"$1\" ]\n",
        )
        write_executable(self.id, fake_id_payload())
        write_executable(
            self.stat,
            fake_stat_payload(
                sysfs_path=self.boot,
                sysfs_drift_marker=self.boot_metadata_drift,
            ),
        )
        write_executable(
            self.sha256sum,
            "#!/bin/sh\n"
            "result=$(/usr/bin/sha256sum \"$@\") || exit\n"
            f"mutation_done={shlex.quote(str(self.hash_mutation_done))}\n"
            f"state_file={shlex.quote(str(self.adsp / 'state'))}\n"
            f"service_failure={shlex.quote(str(self.service_failure_marker))}\n"
            f"boot_metadata_drift={shlex.quote(str(self.boot_metadata_drift))}\n"
            "if [ ! -e \"$mutation_done\" ]; then\n"
            "  case \"${LMI_P3_HASH_MUTATION:-}\" in\n"
            "    state) printf '%s\\n' ONLINE > \"$state_file\" ;;\n"
            "    service) : > \"$service_failure\" ;;\n"
            "    boot-group) printf '%s\\n' group > \"$boot_metadata_drift\" ;;\n"
            "    boot-owner) printf '%s\\n' owner > \"$boot_metadata_drift\" ;;\n"
            "    boot-mode) printf '%s\\n' mode > \"$boot_metadata_drift\" ;;\n"
            "    '') ;;\n"
            "    *) exit 94 ;;\n"
            "  esac\n"
            "  case \"${LMI_P3_HASH_MUTATION:-}\" in\n"
            "    state|service|boot-group|boot-owner|boot-mode) : > \"$mutation_done\" ;;\n"
            "  esac\n"
            "fi\n"
            "if [ -n \"${LMI_P3_HASH_HOLD:-}\" ]; then\n"
            "  : > \"${LMI_P3_HASH_HOLD}.ready\"\n"
            "  while [ -e \"${LMI_P3_HASH_HOLD}\" ]; do /bin/sleep 0.01; done\n"
            "fi\n"
            "printf '%s\\n' \"$result\"\n",
        )
        write_executable(
            self.uname,
            "#!/bin/sh\n"
            "case \"$1\" in\n"
            "  -m) echo aarch64 ;;\n"
            f"  -r) echo \"${{LMI_P3_KERNEL_RELEASE:-{EXPECTED_KERNEL_RELEASE}}}\" ;;\n"
            "  *) exit 64 ;;\n"
            "esac\n",
        )
        write_executable(
            self.sleep,
            "#!/bin/sh\n"
            f"count_file={shlex.quote(str(self.sleep_count))}\n"
            f"state_file={shlex.quote(str(self.adsp / 'state'))}\n"
            "count=0\n"
            "[ ! -r \"$count_file\" ] || count=$(cat \"$count_file\")\n"
            "count=$((count + 1))\n"
            "printf '%s\\n' \"$count\" > \"$count_file\"\n"
            "case \"${LMI_P3_POST_STATE:-ONLINE}\" in\n"
            "  ONLINE) printf '%s\\n' ONLINE > \"$state_file\" ;;\n"
            "  CRASHED) printf '%s\\n' CRASHED > \"$state_file\" ;;\n"
            "  OFFLINE) : ;;\n"
            "  *) exit 92 ;;\n"
            "esac\n",
        )

        payload = (FILES / "lmi-adsp-control").read_text(encoding="utf-8")
        replacements = {
            "BOOT_CONTROL=/sys/kernel/boot_adsp/boot": f"BOOT_CONTROL={shlex.quote(str(self.boot))}",
            "DT_BASE=/sys/firmware/devicetree/base": f"DT_BASE={shlex.quote(str(self.dt))}",
            "DEVICEINFO=/usr/share/deviceinfo/device-xiaomi-lmi": f"DEVICEINFO={shlex.quote(str(self.deviceinfo))}",
            "RELEASE_IDENTITY=/etc/lmi-release-identity": f"RELEASE_IDENTITY={shlex.quote(str(self.identity))}",
            "MSM_SUBSYS_BASE=/sys/bus/msm_subsys/devices": f"MSM_SUBSYS_BASE={shlex.quote(str(self.subsystems))}",
            "FIRMWARE_BASE=/lib/firmware": f"FIRMWARE_BASE={shlex.quote(str(self.firmware))}",
            "FIRMWARE_SOURCE_ROOT=/mnt/vendor/firmware_mnt/image": f"FIRMWARE_SOURCE_ROOT={shlex.quote(str(self.firmware_source))}",
            "FIRMWARE_INVENTORY=/etc/lmi-p3/adsp-firmware.inventory": f"FIRMWARE_INVENTORY={shlex.quote(str(self.inventory))}",
            "FIRMWARE_PROVENANCE=/etc/lmi-p3/adsp-firmware.provenance": f"FIRMWARE_PROVENANCE={shlex.quote(str(self.provenance))}",
            "RC_STARTED_BASE=/run/openrc/started": f"RC_STARTED_BASE={shlex.quote(str(self.started))}",
            "RUNTIME_ROOT=/run": f"RUNTIME_ROOT={shlex.quote(str(self.runtime_root))}",
            "RUNTIME_DIRECTORY=/run/lmi-p3": f"RUNTIME_DIRECTORY={shlex.quote(str(self.runtime_directory))}",
            "LOCK_DIRECTORY=/run/lmi-p3/adsp-transition.lock": f"LOCK_DIRECTORY={shlex.quote(str(self.lock_directory))}",
            "ATTEMPT_LATCH=/run/lmi-p3/adsp-boot-attempted": f"ATTEMPT_LATCH={shlex.quote(str(self.attempt_latch))}",
            "ROUTE_GUARD=/usr/libexec/lmi-p3-route-guard": f"ROUTE_GUARD={shlex.quote(str(self.route_guard))}",
            "RC_SERVICE=/sbin/rc-service": f"RC_SERVICE={shlex.quote(str(self.rc_service))}",
            "ID=/usr/bin/id": f"ID={shlex.quote(str(self.id))}",
            "SHA256SUM=/usr/bin/sha256sum": f"SHA256SUM={shlex.quote(str(self.sha256sum))}",
            "STAT=/usr/bin/stat": f"STAT={shlex.quote(str(self.stat))}",
            "UNAME=/bin/uname": f"UNAME={shlex.quote(str(self.uname))}",
            "SLEEP=/bin/sleep": f"SLEEP={shlex.quote(str(self.sleep))}",
        }
        self.control.write_text(replace_exact(payload, replacements), encoding="utf-8")
        self.control.chmod(0o755)

    def close(self) -> None:
        self.temporary.cleanup()

    def run(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if environment:
            env.update(environment)
        return subprocess.run(
            ["/bin/sh", str(self.control), *arguments],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
            env=env,
        )

    def full_probe_arguments(self) -> tuple[str, ...]:
        return (
            "probe",
            "--inventory-sha256",
            self.inventory_sha256,
            "--provenance-sha256",
            self.provenance_sha256,
        )

    def boot_arguments(self) -> tuple[str, ...]:
        return (
            "boot",
            "--confirm-exact",
            CONFIRMATION,
            "--inventory-sha256",
            self.inventory_sha256,
            "--provenance-sha256",
            self.provenance_sha256,
        )


class RouteGuardFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.rootctl = self.root / "usr/sbin/lmi-rootctl"
        self.sudoers = self.root / "etc/sudoers"
        self.sudoers_dir = self.root / "etc/sudoers.d"
        self.rule = self.sudoers_dir / "90-lmi-rootctl"
        self.doas_conf = self.root / "etc/doas.conf"
        self.doas_dir = self.root / "etc/doas.d"
        self.init_dir = self.root / "etc/init.d"
        self.runlevels = self.root / "etc/runlevels"
        self.systemd_etc = self.root / "etc/systemd/system"
        self.systemd_usr = self.root / "usr/lib/systemd/system"
        self.bin = self.root / "bin"
        self.id = self.bin / "id"
        self.stat = self.bin / "stat"
        self.guard = self.root / "lmi-p3-route-guard"
        for directory in (
            self.rootctl.parent,
            self.sudoers_dir,
            self.doas_dir,
            self.init_dir,
            self.runlevels,
            self.systemd_etc,
            self.systemd_usr,
            self.bin,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(P1_FILES / "lmi-rootctl", self.rootctl)
        shutil.copyfile(P1_FILES / "sudoers", self.sudoers)
        shutil.copyfile(P1_FILES / "90-lmi-rootctl", self.rule)
        self.rootctl.chmod(0o755)
        self.sudoers.chmod(0o440)
        self.rule.chmod(0o440)
        write_executable(self.id, fake_id_payload())
        write_executable(self.stat, fake_stat_payload())

        payload = (FILES / "lmi-p3-route-guard").read_text(encoding="utf-8")
        replacements = {
            "ROOTCTL=/usr/sbin/lmi-rootctl": f"ROOTCTL={shlex.quote(str(self.rootctl))}",
            "SUDOERS=/etc/sudoers": f"SUDOERS={shlex.quote(str(self.sudoers))}",
            "SUDOERS_DIRECTORY=/etc/sudoers.d": f"SUDOERS_DIRECTORY={shlex.quote(str(self.sudoers_dir))}",
            "ROOTCTL_RULE=/etc/sudoers.d/90-lmi-rootctl": f"ROOTCTL_RULE={shlex.quote(str(self.rule))}",
            "DOAS_CONF=/etc/doas.conf": f"DOAS_CONF={shlex.quote(str(self.doas_conf))}",
            "DOAS_DIRECTORY=/etc/doas.d": f"DOAS_DIRECTORY={shlex.quote(str(self.doas_dir))}",
            "INIT_DIRECTORY=/etc/init.d": f"INIT_DIRECTORY={shlex.quote(str(self.init_dir))}",
            "RUNLEVEL_DIRECTORY=/etc/runlevels": f"RUNLEVEL_DIRECTORY={shlex.quote(str(self.runlevels))}",
            "SYSTEMD_ETC_DIRECTORY=/etc/systemd/system": f"SYSTEMD_ETC_DIRECTORY={shlex.quote(str(self.systemd_etc))}",
            "SYSTEMD_USR_DIRECTORY=/usr/lib/systemd/system": f"SYSTEMD_USR_DIRECTORY={shlex.quote(str(self.systemd_usr))}",
            "ID=/usr/bin/id": f"ID={shlex.quote(str(self.id))}",
            "STAT=/usr/bin/stat": f"STAT={shlex.quote(str(self.stat))}",
        }
        self.guard.write_text(replace_exact(payload, replacements), encoding="utf-8")
        self.guard.chmod(0o755)

    def close(self) -> None:
        self.temporary.cleanup()

    def run(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if environment:
            env.update(environment)
        return subprocess.run(
            ["/bin/sh", str(self.guard), *arguments],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
            env=env,
        )


class ProbeFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sys = self.root / "sys"
        self.proc = self.root / "proc"
        self.dev = self.root / "dev"
        self.etc = self.root / "etc"
        self.boot = self.root / "boot"
        self.run_root = self.root / "run"
        self.firmware = self.root / "lib/firmware"
        self.review = self.etc / "lmi-p3"
        self.archive_root = self.root / "var/log"
        self.archive_directory = self.archive_root / "lmi-p3"
        self.fake_bin = self.root / "fake-bin"
        self.id = self.fake_bin / "id"
        self.stat = self.fake_bin / "stat"
        self.probe = self.root / "lmi-audio-probe"
        for directory in (
            self.sys,
            self.proc / "asound",
            self.proc / "net",
            self.dev / "snd",
            self.etc,
            self.boot,
            self.run_root / "openrc/started",
            self.firmware,
            self.review,
            self.archive_root,
            self.fake_bin,
        ):
            directory.mkdir(parents=True, exist_ok=True)

        dt = self.sys / "firmware/devicetree/base"
        sound = dt / "soc/sound"
        sound.mkdir(parents=True)
        dt.joinpath("model").write_bytes(b"Qualcomm Technologies, Inc. xiaomi lmi\0")
        dt.joinpath("compatible").write_bytes(b"qcom,kona-mtp\0qcom,kona\0qcom,mtp\0")
        sound.joinpath("compatible").write_bytes(b"qcom,kona-asoc-snd\0")
        sound.joinpath("qcom,model").write_bytes(b"Kona-LMI\0")

        boot_control = self.sys / "kernel/boot_adsp/boot"
        boot_control.parent.mkdir(parents=True)
        boot_control.write_text("write-only-fixture\n", encoding="utf-8")
        subsystem = self.sys / "bus/msm_subsys/devices/subsys7"
        subsystem.mkdir(parents=True)
        for name, value in {
            "name": "adsp\n",
            "state": "OFFLINE\n",
            "firmware_name": "adsp\n",
            "crash_count": "0\n",
            "restart_level": "RELATED\n",
        }.items():
            subsystem.joinpath(name).write_text(value, encoding="utf-8")

        swr = self.sys / "bus/swr/devices/swr0"
        swr.mkdir(parents=True)
        swr.joinpath("name").write_text("swr-slave\n", encoding="utf-8")
        swr.joinpath("driver").symlink_to(self.root / "drivers/swr-fixture")
        i2c = self.sys / "bus/i2c/devices/3-0034"
        i2c.joinpath("of_node").mkdir(parents=True)
        i2c.joinpath("name").write_text("tfa9874\n", encoding="utf-8")
        i2c.joinpath("modalias").write_text("i2c:tfa9874\n", encoding="utf-8")
        i2c.joinpath("of_node/compatible").write_bytes(b"nxp,tfa98xx\0")
        i2c.joinpath("driver").symlink_to(self.root / "drivers/tfa98xx")
        rpmsg = self.sys / "bus/rpmsg/devices/apr-audio"
        rpmsg.mkdir(parents=True)

        self.proc.joinpath("version").write_text(
            "Linux fixture (builder-leak@host-leak) "
            "uuid=123e4567-e89b-12d3-a456-426614174000 "
            "/home/private-user/build\n",
            encoding="utf-8",
        )
        self.proc.joinpath("config.gz").write_text(
            "CONFIG_QRTR=y\nCONFIG_MSM_SUBSYSTEM_RESTART=y\nCONFIG_SND_SOC=y\n",
            encoding="utf-8",
        )
        self.proc.joinpath("net/qrtr").write_text("qrtr fixture\n", encoding="utf-8")
        for name in ("cards", "devices", "pcm"):
            self.proc.joinpath("asound", name).write_text(f"{name} fixture\n", encoding="utf-8")
        self.dev.joinpath("snd/controlC0").touch()
        self.dev.joinpath("subsys_adsp").touch()

        self.etc.joinpath("lmi-release-identity").write_text(
            "device_xiaomi_lmi=1-r107\n"
            "linux_xiaomi_lmi=4.19.325-r8\n"
            "serial=SERIAL-LEAK-123\n"
            "cpuid=CPUID-LEAK-456\n"
            "build_user=builder-leak\n"
            "build_host=host-leak\n"
            "mac=aa:bb:cc:dd:ee:ff\n"
            "ip=192.0.2.44\n"
            "ssid=SecretWifiMarker\n",
            encoding="utf-8",
        )
        for service in SERVICES:
            self.run_root.joinpath("openrc/started", service).touch()
        source = self.root / "mnt/vendor/firmware_mnt/image"
        source.mkdir(parents=True)
        for name in ("adsp.mdt", "adsp.b00"):
            source.joinpath(name).write_text(f"{name} fixture\n", encoding="utf-8")
            self.firmware.joinpath(name).symlink_to(source / name)
        self.review.joinpath("adsp-firmware.inventory").write_text(
            "schema=lmi-p3-adsp-firmware-inventory/v1\n", encoding="utf-8"
        )
        self.review.joinpath("adsp-firmware.provenance").write_text(
            "schema=lmi-p3-adsp-firmware-provenance/v1\n", encoding="utf-8"
        )

        write_executable(
            self.fake_bin / "uname",
            "#!/bin/sh\n"
            "case \"${1:-}\" in\n"
            "  -s) echo Linux ;;\n"
            f"  -r) echo {EXPECTED_KERNEL_RELEASE} ;;\n"
            "  -m) echo aarch64 ;;\n"
            f"  *) echo 'Linux host-leak {EXPECTED_KERNEL_RELEASE} aarch64' ;;\n"
            "esac\n",
        )
        write_executable(self.id, fake_id_payload())
        write_executable(self.stat, fake_stat_payload())
        write_executable(self.fake_bin / "zcat", "#!/bin/sh\ncat \"$1\"\n")
        for command in ("ss", "aplay", "arecord", "amixer"):
            write_executable(
                self.fake_bin / command,
                f"#!/bin/sh\nprintf '%s\\n' '{command} fixture'\n",
            )
        write_executable(
            self.fake_bin / "dmesg",
            "#!/bin/sh\ni=1\nwhile [ \"$i\" -le 300 ]; do\n"
            "  case \"$i\" in\n"
            "    290) printf '%s\\n' 'dmesg-line-290 serialno=SERIAL-LEAK-123' ;;\n"
            "    291) printf '%s\\n' 'dmesg-line-291 cpuid=CPUID-LEAK-456' ;;\n"
            "    292) printf '%s\\n' 'dmesg-line-292 wifi aa:bb:cc:dd:ee:ff 192.0.2.44' ;;\n"
            "    293) printf '%s\\n' 'dmesg-line-293 ipv6 2001:db8::1234' ;;\n"
            "    294) printf '%s\\n' 'dmesg-line-294 SSID=SecretWifiMarker' ;;\n"
            "    295) printf '%s\\n' 'dmesg-line-295 built by builder-leak@host-leak' ;;\n"
            "    *) printf 'dmesg-line-%s\\n' \"$i\" ;;\n"
            "  esac\n"
            "  i=$((i + 1))\ndone\n",
        )

        payload = (FILES / "lmi-audio-probe").read_text(encoding="utf-8")
        replacements = {
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin": f"PATH={shlex.quote(str(self.fake_bin))}:/usr/sbin:/usr/bin:/sbin:/bin",
            "SYS_BASE=/sys": f"SYS_BASE={shlex.quote(str(self.sys))}",
            "PROC_BASE=/proc": f"PROC_BASE={shlex.quote(str(self.proc))}",
            "DEV_BASE=/dev": f"DEV_BASE={shlex.quote(str(self.dev))}",
            "ETC_BASE=/etc": f"ETC_BASE={shlex.quote(str(self.etc))}",
            "BOOT_BASE=/boot": f"BOOT_BASE={shlex.quote(str(self.boot))}",
            "RUN_BASE=/run": f"RUN_BASE={shlex.quote(str(self.run_root))}",
            "FIRMWARE_BASE=/lib/firmware": f"FIRMWARE_BASE={shlex.quote(str(self.firmware))}",
            "FIRMWARE_REVIEW_BASE=/etc/lmi-p3": f"FIRMWARE_REVIEW_BASE={shlex.quote(str(self.review))}",
            "ARCHIVE_ROOT=/var/log": f"ARCHIVE_ROOT={shlex.quote(str(self.archive_root))}",
            "ARCHIVE_DIRECTORY=/var/log/lmi-p3": f"ARCHIVE_DIRECTORY={shlex.quote(str(self.archive_directory))}",
            "ID=/usr/bin/id": f"ID={shlex.quote(str(self.id))}",
            "STAT=/usr/bin/stat": f"STAT={shlex.quote(str(self.stat))}",
        }
        self.probe.write_text(replace_exact(payload, replacements), encoding="utf-8")
        self.probe.chmod(0o755)

    def close(self) -> None:
        self.temporary.cleanup()

    def snapshot(self) -> dict[str, tuple[str, bytes | str]]:
        result: dict[str, tuple[str, bytes | str]] = {}
        for path in sorted(self.root.rglob("*")):
            relative = path.relative_to(self.root).as_posix()
            if path.is_symlink():
                result[relative] = ("link", os.readlink(path))
            elif path.is_file():
                result[relative] = ("file", path.read_bytes())
            elif path.is_dir():
                result[relative] = ("dir", "")
        return result

    def run(
        self, *arguments: str, environment: dict[str, str] | None = None
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        if environment:
            env.update(environment)
        return subprocess.run(
            ["/bin/sh", str(self.probe), *arguments],
            text=True,
            capture_output=True,
            check=False,
            timeout=10,
            env=env,
        )


class RuntimePolicyTests(unittest.TestCase):
    def control_fixture(self) -> ControlFixture:
        fixture = ControlFixture()
        self.addCleanup(fixture.close)
        return fixture

    def route_fixture(self) -> RouteGuardFixture:
        fixture = RouteGuardFixture()
        self.addCleanup(fixture.close)
        return fixture

    def probe_fixture(self) -> ProbeFixture:
        fixture = ProbeFixture()
        self.addCleanup(fixture.close)
        return fixture

    def test_default_and_full_probe_are_read_only(self) -> None:
        fixture = self.control_fixture()
        for arguments in ((), ("probe",), fixture.full_probe_arguments()):
            with self.subTest(arguments=arguments):
                fixture.boot.write_text("0\n", encoding="utf-8")
                result = fixture.run(*arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("no write performed", result.stdout)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")
                self.assertFalse(fixture.attempt_latch.exists())

    def test_boot_requires_exact_confirmation_digest_flags_and_no_extras(self) -> None:
        fixture = self.control_fixture()
        rejected = (
            ("boot",),
            ("boot", "--confirm-exact", "yes"),
            ("boot", "--confirm", CONFIRMATION),
            fixture.boot_arguments() + ("extra",),
            (
                "boot",
                "--confirm-exact",
                CONFIRMATION,
                "--inventory-sha256",
                "0" * 64,
                "--provenance-sha256",
                fixture.provenance_sha256,
            ),
        )
        for arguments in rejected:
            with self.subTest(arguments=arguments):
                result = fixture.run(*arguments)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_exact_identity_services_and_route_guard_fail_before_write(self) -> None:
        cases = (
            "boot-control",
            "device-version",
            "kernel-package",
            "kernel-release",
            "dt-model",
            "dt-compatible",
            "route-guard",
            *SERVICES,
        )
        for missing in cases:
            with self.subTest(missing=missing):
                fixture = self.control_fixture()
                environment: dict[str, str] = {}
                if missing == "boot-control":
                    fixture.boot.unlink()
                elif missing == "device-version":
                    fixture.identity.write_text(
                        fixture.identity.read_text().replace("1-r107", "1-r139"),
                        encoding="utf-8",
                    )
                elif missing == "kernel-package":
                    fixture.identity.write_text(
                        fixture.identity.read_text().replace("4.19.325-r8", "4.19.325-r9"),
                        encoding="utf-8",
                    )
                elif missing == "kernel-release":
                    environment["LMI_P3_KERNEL_RELEASE"] = (
                        f"{EXPECTED_KERNEL_RELEASE}-drift"
                    )
                elif missing == "dt-model":
                    fixture.dt.joinpath("model").write_bytes(b"not-lmi\0")
                elif missing == "dt-compatible":
                    fixture.dt.joinpath("compatible").write_bytes(b"qcom,kona\0")
                elif missing == "route-guard":
                    environment["LMI_P3_FAIL_ROUTE_GUARD"] = "1"
                else:
                    environment["LMI_P3_FAIL_SERVICE"] = missing
                result = fixture.run(*fixture.boot_arguments(), environment=environment)
                self.assertNotEqual(result.returncode, 0)
                if fixture.boot.exists():
                    self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_boot_control_requires_exact_root_sysfs_metadata_during_probe(self) -> None:
        for mutation in ("owner", "group", "mode", "symlink", "directory"):
            with self.subTest(mutation=mutation):
                fixture = self.control_fixture()
                environment: dict[str, str] = {}
                if mutation in {"owner", "group", "mode"}:
                    environment["LMI_P3_STAT_OVERRIDE_PATH"] = str(fixture.boot)
                    if mutation == "owner":
                        environment["LMI_P3_STAT_OVERRIDE_OWNER"] = "1000:0"
                    elif mutation == "group":
                        environment["LMI_P3_STAT_OVERRIDE_OWNER"] = "0:1000"
                    else:
                        environment["LMI_P3_STAT_OVERRIDE_OWNER"] = "0:0"
                        environment["LMI_P3_STAT_OVERRIDE_MODE"] = "660"
                elif mutation == "symlink":
                    target = fixture.root / "hostile-boot-control"
                    target.write_text("0\n", encoding="utf-8")
                    fixture.boot.unlink()
                    fixture.boot.symlink_to(target)
                else:
                    fixture.boot.unlink()
                    fixture.boot.mkdir()

                result = fixture.run("probe", environment=environment)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(fixture.runtime_directory.exists())
                self.assertFalse(fixture.attempt_latch.exists())

    def test_prewrite_state_rejects_repeat_ambiguous_and_nonexact_states(self) -> None:
        for state in ("ONLINE", "offline", "CRASHED", "OFFLINING"):
            with self.subTest(state=state):
                fixture = self.control_fixture()
                fixture.adsp.joinpath("state").write_text(f"{state}\n", encoding="utf-8")
                result = fixture.run(*fixture.boot_arguments())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

        fixture = self.control_fixture()
        duplicate = fixture.subsystems / "subsys9"
        duplicate.mkdir()
        duplicate.joinpath("name").write_text("adsp\n", encoding="utf-8")
        duplicate.joinpath("state").write_text("OFFLINE\n", encoding="utf-8")
        duplicate.joinpath("firmware_name").write_text("adsp\n", encoding="utf-8")
        result = fixture.run(*fixture.boot_arguments())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exactly one", result.stderr)
        self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_deviceinfo_rejects_duplicate_and_conflicting_identity_assignments(self) -> None:
        additions = (
            'deviceinfo_codename="xiaomi-lmi"\n',
            'deviceinfo_codename="not-lmi"\n',
            'export deviceinfo_codename="not-lmi"\n',
            'deviceinfo_dtb="qcom/kona-v2.1-lmi"\n',
            'deviceinfo_dtb="qcom/not-lmi"\n',
            ' deviceinfo_dtb="qcom/not-lmi"\n',
        )
        for addition in additions:
            with self.subTest(addition=addition.strip()):
                fixture = self.control_fixture()
                with fixture.deviceinfo.open("a", encoding="utf-8") as stream:
                    stream.write(addition)
                result = fixture.run(*fixture.boot_arguments())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")
                self.assertFalse(fixture.attempt_latch.exists())

    def test_every_subsystem_candidate_has_one_recognized_name_and_one_adsp(self) -> None:
        for mutation in ("missing-name", "unreadable-name", "unknown-name", "not-directory"):
            with self.subTest(mutation=mutation):
                fixture = self.control_fixture()
                if mutation == "missing-name":
                    fixture.adsp.joinpath("name").unlink()
                elif mutation == "unreadable-name":
                    fixture.adsp.joinpath("name").unlink()
                    fixture.adsp.joinpath("name").symlink_to(fixture.root / "missing-name")
                elif mutation == "unknown-name":
                    fixture.adsp.joinpath("name").write_text("mystery\n", encoding="utf-8")
                else:
                    fixture.subsystems.joinpath("subsys8").write_text(
                        "not a directory\n", encoding="utf-8"
                    )
                result = fixture.run(*fixture.boot_arguments())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

        fixture = self.control_fixture()
        for index, name in enumerate(EXPECTED_SUBSYSTEM_NAMES, start=20):
            if name == "adsp":
                continue
            candidate = fixture.subsystems / f"subsys{index}"
            candidate.mkdir()
            candidate.joinpath("name").write_text(f"{name}\n", encoding="utf-8")
        result = fixture.run(*fixture.full_probe_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)

        fixture = self.control_fixture()
        for index in (20, 21):
            candidate = fixture.subsystems / f"subsys{index}"
            candidate.mkdir()
            candidate.joinpath("name").write_text("wlan\n", encoding="utf-8")
        result = fixture.run(*fixture.boot_arguments())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("duplicate msm_subsys name", result.stderr)
        self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_firmware_inventory_is_complete_nonempty_sorted_and_provenance_bound(self) -> None:
        mutations = ("empty", "extra", "missing", "wrong-source", "unsorted", "provenance")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = self.control_fixture()
                if mutation == "empty":
                    fixture.firmware_source.joinpath("adsp.b00").write_bytes(b"")
                elif mutation == "extra":
                    extra = fixture.firmware_source / "adsp.b03"
                    extra.write_bytes(b"extra\n")
                    fixture.firmware.joinpath("adsp.b03").symlink_to(extra)
                elif mutation == "missing":
                    fixture.firmware.joinpath("adsp.b02").unlink()
                elif mutation == "wrong-source":
                    wrong = fixture.root / "other/adsp.b00"
                    wrong.parent.mkdir()
                    wrong.write_bytes(fixture.firmware_source.joinpath("adsp.b00").read_bytes())
                    fixture.firmware.joinpath("adsp.b00").unlink()
                    fixture.firmware.joinpath("adsp.b00").symlink_to(wrong)
                elif mutation == "unsorted":
                    lines = fixture.inventory.read_text().splitlines()
                    lines[-1], lines[-2] = lines[-2], lines[-1]
                    fixture.inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    fixture.inventory_sha256 = sha256(fixture.inventory)
                else:
                    fixture.provenance.write_text(
                        fixture.provenance.read_text().replace(
                            "stock-readonly-firmware-partition", "unknown"
                        ),
                        encoding="utf-8",
                    )
                    fixture.provenance_sha256 = sha256(fixture.provenance)
                    lines = fixture.inventory.read_text().splitlines()
                    lines[1] = f"provenance_sha256={fixture.provenance_sha256}"
                    fixture.inventory.write_text("\n".join(lines) + "\n", encoding="utf-8")
                    fixture.inventory_sha256 = sha256(fixture.inventory)
                result = fixture.run(*fixture.boot_arguments())
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_one_write_reaches_online_and_repeat_is_rejected(self) -> None:
        fixture = self.control_fixture()
        result = fixture.run(*fixture.boot_arguments())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "1\n")
        self.assertEqual(fixture.adsp.joinpath("state").read_text(), "ONLINE\n")
        self.assertIn("exact ONLINE", result.stdout)
        self.assertFalse(fixture.lock_directory.exists())
        self.assertTrue(fixture.attempt_latch.is_dir())

        fixture.boot.write_text("0\n", encoding="utf-8")
        fixture.adsp.joinpath("state").write_text("OFFLINE\n", encoding="utf-8")
        repeat = fixture.run(*fixture.boot_arguments())
        self.assertNotEqual(repeat.returncode, 0)
        self.assertIn("already been attempted", repeat.stderr)
        self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_private_runtime_boundary_ignores_openrc_run_lock(self) -> None:
        fixture = self.control_fixture()
        openrc_lock = fixture.runtime_root / "lock"
        openrc_lock.mkdir()
        openrc_lock.chmod(0o775)
        result = fixture.run(
            *fixture.boot_arguments(),
            environment={"LMI_P3_NONROOT_PATH": str(openrc_lock)},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(stat.S_IMODE(openrc_lock.stat().st_mode), 0o775)
        self.assertEqual(stat.S_IMODE(fixture.runtime_directory.stat().st_mode), 0o700)
        self.assertFalse(fixture.lock_directory.exists())
        self.assertTrue(fixture.attempt_latch.is_dir())

    def test_runtime_boundary_rejects_hostile_parents_and_stale_entries(self) -> None:
        mutations = (
            "runtime-root-owner",
            "runtime-root-mode",
            "runtime-directory-owner",
            "runtime-directory-mode",
            "runtime-directory-symlink",
            "runtime-directory-file",
            "stale-lock-symlink",
            "stale-latch-symlink",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = self.control_fixture()
                environment: dict[str, str] = {}
                if mutation == "runtime-root-owner":
                    environment["LMI_P3_NONROOT_PATH"] = str(fixture.runtime_root)
                elif mutation == "runtime-root-mode":
                    fixture.runtime_root.chmod(0o777)
                elif mutation == "runtime-directory-owner":
                    fixture.runtime_directory.mkdir(mode=0o700)
                    environment["LMI_P3_NONROOT_PATH"] = str(
                        fixture.runtime_directory
                    )
                elif mutation == "runtime-directory-mode":
                    fixture.runtime_directory.mkdir(mode=0o755)
                elif mutation == "runtime-directory-symlink":
                    hostile = fixture.root / "hostile-runtime"
                    hostile.mkdir(mode=0o700)
                    fixture.runtime_directory.symlink_to(hostile)
                elif mutation == "runtime-directory-file":
                    fixture.runtime_directory.write_text("hostile\n", encoding="utf-8")
                else:
                    fixture.runtime_directory.mkdir(mode=0o700)
                    target = fixture.root / "hostile-entry"
                    target.mkdir()
                    if mutation == "stale-lock-symlink":
                        fixture.lock_directory.symlink_to(target)
                    else:
                        fixture.attempt_latch.symlink_to(target)

                result = fixture.run(
                    *fixture.boot_arguments(), environment=environment
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")
                if mutation == "stale-lock-symlink":
                    self.assertTrue(fixture.lock_directory.is_symlink())
                if mutation == "stale-latch-symlink":
                    self.assertTrue(fixture.attempt_latch.is_symlink())

    def test_hash_time_mutable_inputs_are_rechecked_before_write(self) -> None:
        for mutation in (
            "state",
            "service",
            "boot-group",
            "boot-owner",
            "boot-mode",
        ):
            with self.subTest(mutation=mutation):
                fixture = self.control_fixture()
                result = fixture.run(
                    *fixture.boot_arguments(),
                    environment={"LMI_P3_HASH_MUTATION": mutation},
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")
                self.assertTrue(fixture.attempt_latch.is_dir())

                fixture.adsp.joinpath("state").write_text("OFFLINE\n", encoding="utf-8")
                if fixture.service_failure_marker.exists():
                    fixture.service_failure_marker.unlink()
                if fixture.boot_metadata_drift.exists():
                    fixture.boot_metadata_drift.unlink()
                retry = fixture.run(*fixture.boot_arguments())
                self.assertNotEqual(retry.returncode, 0)
                self.assertIn("already been attempted", retry.stderr)
                self.assertEqual(fixture.boot.read_text(encoding="utf-8"), "0\n")

    def test_postwrite_state_rejects_crash_and_has_bounded_timeout(self) -> None:
        fixture = self.control_fixture()
        crashed = fixture.run(
            *fixture.boot_arguments(), environment={"LMI_P3_POST_STATE": "CRASHED"}
        )
        self.assertNotEqual(crashed.returncode, 0)
        self.assertIn("unexpected post-write state", crashed.stderr)
        self.assertEqual(fixture.boot.read_text(), "1\n")
        self.assertFalse(fixture.lock_directory.exists())
        self.assertTrue(fixture.attempt_latch.is_dir())
        fixture.boot.write_text("0\n", encoding="utf-8")
        fixture.adsp.joinpath("state").write_text("OFFLINE\n", encoding="utf-8")
        retry = fixture.run(*fixture.boot_arguments())
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn("already been attempted", retry.stderr)
        self.assertEqual(fixture.boot.read_text(), "0\n")

        fixture = self.control_fixture()
        timeout = fixture.run(
            *fixture.boot_arguments(), environment={"LMI_P3_POST_STATE": "OFFLINE"}
        )
        self.assertNotEqual(timeout.returncode, 0)
        self.assertIn("50 bounded checks", timeout.stderr)
        self.assertEqual(fixture.sleep_count.read_text(), "49\n")
        self.assertFalse(fixture.lock_directory.exists())
        self.assertTrue(fixture.attempt_latch.is_dir())
        fixture.boot.write_text("0\n", encoding="utf-8")
        retry = fixture.run(*fixture.boot_arguments())
        self.assertNotEqual(retry.returncode, 0)
        self.assertIn("already been attempted", retry.stderr)
        self.assertEqual(fixture.boot.read_text(), "0\n")

    def test_control_requires_uid_zero_and_root_owned_trusted_inputs(self) -> None:
        fixture = self.control_fixture()
        rejected = fixture.run(
            *fixture.boot_arguments(), environment={"LMI_P3_FAKE_UID": "1000"}
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("uid 0", rejected.stderr)
        self.assertEqual(fixture.boot.read_text(), "0\n")

        for attribute in (
            "route_guard",
            "identity",
            "deviceinfo",
            "provenance",
            "inventory",
        ):
            with self.subTest(nonroot_input=attribute):
                fixture = self.control_fixture()
                path = getattr(fixture, attribute)
                rejected = fixture.run(
                    *fixture.boot_arguments(),
                    environment={"LMI_P3_NONROOT_PATH": str(path)},
                )
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(fixture.boot.read_text(), "0\n")

    def test_signal_traps_exit_fail_closed_and_hold_lock_until_exit(self) -> None:
        fixture = self.control_fixture()
        hold = fixture.root / "hold-hash"
        hold.touch()
        ready = Path(f"{hold}.ready")
        env = os.environ.copy()
        env["LMI_P3_HASH_HOLD"] = str(hold)
        process = subprocess.Popen(
            ["/bin/sh", str(fixture.control), *fixture.boot_arguments()],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
        deadline = time.monotonic() + 2
        while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
            time.sleep(0.01)
        self.assertTrue(ready.exists(), "control did not enter the held hash operation")
        self.assertTrue(fixture.lock_directory.is_dir())

        concurrent = fixture.run(*fixture.boot_arguments())
        self.assertNotEqual(concurrent.returncode, 0)
        self.assertIn("another lmi ADSP transition", concurrent.stderr)
        self.assertEqual(fixture.boot.read_text(), "0\n")

        process.send_signal(signal.SIGTERM)
        time.sleep(0.05)
        if process.poll() is None:
            self.assertTrue(fixture.lock_directory.is_dir())
        hold.unlink()
        stdout, stderr = process.communicate(timeout=2)
        self.assertEqual(process.returncode, 143, (stdout, stderr))
        self.assertFalse(fixture.lock_directory.exists())
        self.assertFalse(fixture.attempt_latch.exists())
        self.assertEqual(fixture.boot.read_text(), "0\n")

    def test_route_guard_enforces_exact_p1_boundary_and_no_legacy_route(self) -> None:
        fixture = self.route_fixture()
        result = fixture.run()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("no packaged ADSP bypass", result.stdout)

        mutations = ("rootctl", "sudoers-extra", "doas", "legacy-init", "runlevel", "systemd")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                fixture = self.route_fixture()
                if mutation == "rootctl":
                    fixture.rootctl.write_text(fixture.rootctl.read_text() + "# drift\n")
                elif mutation == "sudoers-extra":
                    fixture.sudoers_dir.joinpath("91-extra").write_text("lmi ALL=(ALL) ALL\n")
                elif mutation == "doas":
                    fixture.doas_conf.write_text("permit nopass lmi\n")
                elif mutation == "legacy-init":
                    fixture.init_dir.joinpath("adsp-audio").touch()
                elif mutation == "runlevel":
                    default = fixture.runlevels / "default"
                    default.mkdir()
                    default.joinpath("lmi-adsp-boot").symlink_to("../../init.d/lmi-adsp-boot")
                else:
                    fixture.systemd_usr.joinpath("adsp-audio.service").touch()
                rejected = fixture.run()
                self.assertNotEqual(rejected.returncode, 0)

    def test_route_guard_requires_uid_zero_and_fixed_root_ownership(self) -> None:
        fixture = self.route_fixture()
        rejected = fixture.run(environment={"LMI_P3_FAKE_UID": "1000"})
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn("uid 0", rejected.stderr)

        for attribute in ("rootctl", "sudoers", "rule"):
            with self.subTest(nonroot_input=attribute):
                fixture = self.route_fixture()
                path = getattr(fixture, attribute)
                rejected = fixture.run(
                    environment={"LMI_P3_NONROOT_PATH": str(path)}
                )
                self.assertNotEqual(rejected.returncode, 0)

    def test_generated_post_install_executes_route_guard_and_fails_closed(self) -> None:
        fixture = self.route_fixture()
        post_install = fixture.root / "post-install"
        payload = (FILES / "device-xiaomi-lmi-audio.post-install").read_text(
            encoding="utf-8"
        )
        payload = replace_exact(
            payload,
            {
                "ROUTE_GUARD=/usr/libexec/lmi-p3-route-guard": (
                    f"ROUTE_GUARD={shlex.quote(str(fixture.guard))}"
                )
            },
        )
        write_executable(post_install, payload)
        accepted = subprocess.run(
            ["/bin/sh", str(post_install), "0.2.0-r0"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        fixture.init_dir.joinpath("adsp-audio").touch()
        rejected = subprocess.run(
            ["/bin/sh", str(post_install), "0.2.0-r0"],
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )
        self.assertNotEqual(rejected.returncode, 0)

    def test_openrc_service_is_disabled_and_uses_exact_need_ordering(self) -> None:
        initd = (FILES / "lmi-adsp-boot.initd").read_text(encoding="utf-8")
        confd = (FILES / "lmi-adsp-boot.confd").read_text(encoding="utf-8")
        self.assertRegex(
            initd,
            r"(?m)^\s*need lmi-firmware-mount lmi-qrtr-ns pd-mapper rmtfs tqftpserv$",
        )
        self.assertNotRegex(initd, r"(?m)^\s*(?:want|use|after)\s")
        self.assertIn("start_pre()", initd)
        self.assertIn("--inventory-sha256", initd)
        self.assertIn("--provenance-sha256", initd)
        for variable in (
            'lmi_adsp_boot_confirmation=""',
            'lmi_adsp_inventory_sha256=""',
            'lmi_adsp_provenance_sha256=""',
        ):
            self.assertIn(variable, confd)
        self.assertNotIn("/etc/runlevels", initd)

    def test_control_contains_one_sysfs_write_and_exact_state_machine(self) -> None:
        control = (FILES / "lmi-adsp-control").read_text(encoding="utf-8")
        for required in (
            f"EXPECTED_KERNEL_RELEASE='{EXPECTED_KERNEL_RELEASE}'",
            "EXPECTED_BOOT_CONTROL_METADATA='0:0:220:regular file'",
            "$STAT -c '%u:%g:%a:%F' \"$BOOT_CONTROL\"",
            "EXPECTED_DT_MODEL='Qualcomm Technologies, Inc. xiaomi lmi'",
            "MSM_SUBSYS_BASE=/sys/bus/msm_subsys/devices",
            "FIRMWARE_INVENTORY=/etc/lmi-p3/adsp-firmware.inventory",
            "FIRMWARE_PROVENANCE=/etc/lmi-p3/adsp-firmware.provenance",
            '"$ADSP_STATE" = OFFLINE',
            "ONLINE)",
            "POSTCHECK_ATTEMPTS=50",
            "check_boot_control",
            "RUNTIME_DIRECTORY=/run/lmi-p3",
            "LOCK_DIRECTORY=/run/lmi-p3/adsp-transition.lock",
            "ATTEMPT_LATCH=/run/lmi-p3/adsp-boot-attempted",
            "trap 'trap - HUP INT TERM; exit 129' HUP",
            "trap 'trap - HUP INT TERM; exit 130' INT",
            "trap 'trap - HUP INT TERM; exit 143' TERM",
            'printf \'%s\\n\' 1 > "$BOOT_CONTROL"',
        ):
            self.assertIn(required, control)
        for name in EXPECTED_SUBSYSTEM_NAMES:
            self.assertIn(name, control)
        self.assertNotIn("/run/lock", control)
        self.assertEqual(control.count('> "$BOOT_CONTROL"'), 1)

    def test_expanded_probe_executes_only_against_temp_fixture_and_is_read_only(self) -> None:
        fixture = self.probe_fixture()
        before = fixture.snapshot()
        result = fixture.run()
        after = fixture.snapshot()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, after)
        for required in (
            "evidence_class=redacted-shareable",
            "release, running kernel, and exact DT identity inputs",
            "downstream subsystem state",
            "/bus/swr/devices/swr0",
            "I2C TFA98xx bindings",
            "tfa9874",
            "CONFIG_QRTR=y",
            "qrtr fixture",
            "ss fixture",
            "dmesg-line-61",
            "dmesg-line-300",
            "probe_complete=readonly-inventory-only",
        ):
            self.assertIn(required, result.stdout)
        for marker in SENSITIVE_MARKERS:
            self.assertNotIn(marker, result.stdout)
        self.assertIn("redacted>", result.stdout)
        self.assertNotIn("dmesg-line-60\n", result.stdout)

    def test_probe_private_archive_is_mode_0600_and_emits_redacted_evidence(self) -> None:
        fixture = self.probe_fixture()
        result = fixture.run("--archive-private")
        self.assertEqual(result.returncode, 0, result.stderr)
        raw_files = list(fixture.archive_directory.glob("*.raw"))
        redacted_files = list(fixture.archive_directory.glob("*.redacted"))
        self.assertEqual(len(raw_files), 1)
        self.assertEqual(len(redacted_files), 1)
        raw = raw_files[0]
        redacted = redacted_files[0]
        self.assertEqual(stat.S_IMODE(fixture.archive_directory.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(raw.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(redacted.stat().st_mode), 0o600)
        raw_payload = raw.read_text(encoding="utf-8")
        redacted_payload = redacted.read_text(encoding="utf-8")
        self.assertIn("evidence_class=raw-private-do-not-share", raw_payload)
        self.assertIn("evidence_class=redacted-shareable", redacted_payload)
        for marker in SENSITIVE_MARKERS:
            self.assertIn(marker, raw_payload)
            self.assertNotIn(marker, redacted_payload)
        self.assertIn(str(redacted), result.stdout)

    def test_probe_private_archive_rejects_unsafe_identity_and_parents(self) -> None:
        for mutation in (
            "nonroot",
            "archive-root-owner",
            "archive-root-mode",
            "archive-directory-owner",
            "archive-directory-mode",
            "archive-directory-symlink",
        ):
            with self.subTest(mutation=mutation):
                fixture = self.probe_fixture()
                environment: dict[str, str] = {}
                if mutation == "nonroot":
                    environment["LMI_P3_FAKE_UID"] = "1000"
                elif mutation == "archive-root-owner":
                    environment["LMI_P3_NONROOT_PATH"] = str(fixture.archive_root)
                elif mutation == "archive-root-mode":
                    fixture.archive_root.chmod(0o777)
                elif mutation == "archive-directory-owner":
                    fixture.archive_directory.mkdir(mode=0o700)
                    environment["LMI_P3_NONROOT_PATH"] = str(
                        fixture.archive_directory
                    )
                elif mutation == "archive-directory-mode":
                    fixture.archive_directory.mkdir(mode=0o755)
                else:
                    hostile = fixture.root / "hostile-archive"
                    hostile.mkdir(mode=0o700)
                    fixture.archive_directory.symlink_to(hostile)

                result = fixture.run(
                    "--archive-private", environment=environment
                )
                self.assertNotEqual(result.returncode, 0)
                if fixture.archive_directory.is_dir() and not fixture.archive_directory.is_symlink():
                    self.assertEqual(list(fixture.archive_directory.glob("*.raw")), [])

    def test_probe_source_has_bounded_dmesg_and_no_active_audio_or_service_actions(self) -> None:
        probe = (FILES / "lmi-audio-probe").read_text(encoding="utf-8")
        for required in (
            'for bus in swr soundwire slimbus',
            '"$SYS_BASE/bus/i2c/devices"',
            '"$SYS_BASE"/bus/msm_subsys/devices/subsys*',
            "MSM_SUBSYSTEM_RESTART",
            '"$PROC_BASE/net/qrtr"',
            "run_readonly ss -a -A qrtr",
            "dmesg 2>&1 | tail -n 240",
            "evidence_class=redacted-shareable",
            "evidence_class=raw-private-do-not-share",
            "redact_stream",
            "--archive-private",
        ):
            self.assertIn(required, probe)
        for forbidden in (
            "speaker-test",
            "tinyplay",
            "pw-play",
            "pacat",
            "amixer set",
            "amixer sset",
            "amixer cset",
            "rc-service start",
            "rc-service stop",
        ):
            self.assertNotIn(forbidden, probe)
        self.assertNotRegex(probe, r">\s*\"?\$SYS_BASE")
        self.assertEqual(re.findall(r"run_readonly aplay (\S+)", probe), ["-l", "-L"])
        self.assertEqual(re.findall(r"run_readonly arecord (\S+)", probe), ["-l", "-L"])

    def test_package_sources_have_no_kernel_firmware_or_ucm_payload(self) -> None:
        self.assertEqual(
            {path.name for path in FILES.iterdir()},
            {
                "device-xiaomi-lmi-audio.post-install",
                "lmi-adsp-boot.confd",
                "lmi-adsp-boot.initd",
                "lmi-adsp-control",
                "lmi-audio-probe",
                "lmi-p3-route-guard",
            },
        )
        payload = "\n".join(path.read_text() for path in sorted(FILES.iterdir()))
        self.assertNotIn("CONFIG_QCOM_APR=y", payload)
        self.assertNotIn("CONFIG_SND_SOC_QCOM=y", payload)
        self.assertFalse(any("ucm" in path.name.lower() for path in FILES.iterdir()))
        self.assertFalse(any(path.suffix in {".bin", ".mbn", ".mdt"} for path in FILES.iterdir()))

    def test_all_packaged_shell_sources_parse(self) -> None:
        for path in sorted(FILES.iterdir()):
            with self.subTest(path=path.name):
                result = subprocess.run(
                    ["/bin/sh", "-n", str(path)],
                    text=True,
                    capture_output=True,
                    check=False,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
