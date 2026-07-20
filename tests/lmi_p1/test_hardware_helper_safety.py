from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tempfile
import time
import unittest


REPO = Path(__file__).resolve().parents[2]
STAGE_SCRIPT = REPO / "scripts/72_stage_downstream_ssh_wifi_test.sh"
LOOP_SCRIPT = REPO / "scripts/68_mainline_progress_loop.sh"
CLAIM = (
    "No explicit fastboot partition flash; "
    "the booted OS may mutate persisted userdata."
)
PRODUCTION_RECEIPT_TTL_SECONDS = 30
LEGACY_TRUST_ENV = (
    "REPO",
    "FASTBOOT",
    "DOWNSTREAM_BOOT_IMG",
    "DOWNSTREAM_USERDATA_IMG",
    "DOWNSTREAM_MANIFEST",
    "DOWNSTREAM_FASTBOOT_SHA256",
    "DOWNSTREAM_EXPECTED_BOOT_UUID",
    "DOWNSTREAM_EXPECTED_ROOT_UUID",
    "DOWNSTREAM_MIN_BATTERY_MV",
    "DOWNSTREAM_FASTBOOT_TIMEOUT",
    "DOWNSTREAM_FASTBOOT_ACTION_TIMEOUT",
    "DOWNSTREAM_RAMBOOT_CONFIRM",
    "DOWNSTREAM_ROOTFS_CONFIRM",
)


class D110GateFixture:
    serial = "SYNTHETIC-LMI-01"
    boot_uuid = "11111111-2222-4333-8444-555555555555"
    root_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

    def __init__(self, root: Path, *, windows: bool = False) -> None:
        self.root = root
        self.repo = root / "repo"
        self.scripts = self.repo / "scripts"
        self.base = self.repo / "private/lmi-p1/recovery/d110-d114"
        self.scripts.mkdir(parents=True)
        self.base.mkdir(parents=True)
        for directory in (
            self.repo / "private",
            self.repo / "private/lmi-p1",
            self.repo / "private/lmi-p1/recovery",
            self.base,
        ):
            directory.chmod(0o700)

        self.boot = self.base / "fixture-d110.img"
        self.boot_manifest = self.base / "fixture-d110.manifest"
        self.pair_manifest = self.base / "fixture-d114-pair.manifest"
        self.d199 = self.base / "d199.json"
        self.d200 = self.base / "d200.json"
        self.acquisition = self.base / "fastboot-acquisition.json"
        self.policy = self.base / "d110-recovery-policy.json"
        self.fastboot_log = self.root / "fastboot.log"
        self.fastboot_log.write_text("", encoding="utf-8")
        self.fake_fastboot = self.root / ("fastboot.exe" if windows else "fastboot")
        self.write_fake_fastboot()
        self.write_boot_image(self.boot, self.boot_uuid, self.root_uuid)
        self.component_hashes = self.inspect_fixture_components(self.boot)
        self.write_manifests()
        self.write_history()
        self.write_acquisition_attestation()
        self.windows = windows
        self.fake_wslpath: Path | None = None
        self.fake_powershell: Path | None = None
        self.write_policy(host_kind="windows" if windows else "linux")
        self.install_script(windows=windows)

    @staticmethod
    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    @staticmethod
    def private_write(path: Path, payload: str | bytes) -> None:
        if isinstance(payload, str):
            path.write_text(payload, encoding="utf-8")
        else:
            path.write_bytes(payload)
        path.chmod(0o600)

    def write_fake_fastboot(self) -> None:
        self.fake_fastboot.write_text(
            """#!/usr/bin/env bash
set -eu
for arg in "$@"; do
    printf '<%s>' "$arg" >> "$FAKE_FASTBOOT_LOG"
done
printf '\n' >> "$FAKE_FASTBOOT_LOG"

emit_line() {
    if [ "${FAKE_CRLF:-}" = 1 ]; then
        printf '%s\\r\\n' "$1"
    else
        printf '%s\\n' "$1"
    fi
}

if [ "$#" -eq 1 ] && [ "$1" = devices ]; then
    if [ -n "${FAKE_DEVICES_OUTPUT:-}" ]; then
        printf '%b' "$FAKE_DEVICES_OUTPUT"
    else
        emit_line "${FAKE_SERIAL:-SYNTHETIC-LMI-01}\tfastboot"
    fi
    exit 0
fi

if [ "${1:-}" != -s ] || [ "$#" -lt 3 ]; then
    exit 40
fi
selected=$2
action=$3
if [ "$selected" != "${FAKE_SERIAL:-SYNTHETIC-LMI-01}" ]; then
    exit 41
fi

case "$action" in
    getvar)
        key=${4:-}
        if [ -n "${FAKE_QUERY_DELAY:-}" ] && \
            { [ -z "${FAKE_DELAY_KEY:-}" ] || [ "$FAKE_DELAY_KEY" = "$key" ]; }; then
            /bin/sleep "$FAKE_QUERY_DELAY"
        fi
        case "$key" in
            serialno) value=${FAKE_GETVAR_SERIAL:-${FAKE_SERIAL:-SYNTHETIC-LMI-01}} ;;
            product) value=${FAKE_PRODUCT:-lmi} ;;
            unlocked) value=${FAKE_UNLOCKED:-yes} ;;
            is-userspace) value=${FAKE_USERSPACE:-no} ;;
            battery-voltage) value=${FAKE_BATTERY_VOLTAGE:-4200} ;;
            battery-soc-ok) value=${FAKE_BATTERY_SOC_OK:-yes} ;;
            max-download-size) value=${FAKE_MAX_DOWNLOAD_SIZE:-0x10000000} ;;
            *) exit 42 ;;
        esac
        if [ "${FAKE_CRLF:-}" = 1 ]; then
            printf '%s: %s\\r\\n' "$key" "$value" >&2
        else
            printf '%s: %s\\n' "$key" "$value" >&2
        fi
        if [ "${FAKE_MUTATE_ON_GETVAR:-}" = "$key" ]; then
            printf 'mutation\n' >> "$FAKE_MUTATE_PATH"
        fi
        ;;
    boot)
        [ "$#" -eq 4 ] || exit 43
        [ "${FAKE_ACTION_FAIL:-}" != 1 ] || exit 44
        ;;
    flash|erase|format)
        exit 90
        ;;
    *) exit 46 ;;
esac
""",
            encoding="utf-8",
        )
        self.fake_fastboot.chmod(0o755)

    @staticmethod
    def write_boot_image(path: Path, boot_uuid: str, root_uuid: str) -> None:
        page_size = 4096
        kernel = b"fixture arm64 kernel\n"
        ramdisk = b"fixture gzip-shaped ramdisk\n"
        dtb = b"fixture lmi dtb\n"
        cmdline = (
            "androidboot.hardware=qcom "
            "androidboot.usbcontroller=a600000.dwc3 "
            f"pmos_boot_uuid={boot_uuid} "
            f"pmos_root_uuid={root_uuid} "
            "pmos_rootfsopts=defaults"
        ).encode("ascii")
        header = bytearray(page_size)
        header[:8] = b"ANDROID!"
        struct.pack_into("<I", header, 8, len(kernel))
        struct.pack_into("<I", header, 12, 0x00008000)
        struct.pack_into("<I", header, 16, len(ramdisk))
        struct.pack_into("<I", header, 20, 0x01000000)
        struct.pack_into("<I", header, 24, 0)
        struct.pack_into("<I", header, 28, 0)
        struct.pack_into("<I", header, 32, 0x00000100)
        struct.pack_into("<I", header, 36, page_size)
        struct.pack_into("<I", header, 40, 2)
        struct.pack_into("<I", header, 44, 0)
        header[64 : 64 + len(cmdline)] = cmdline
        image_id = hashlib.sha1(usedforsecurity=False)
        for component in (kernel, ramdisk, b"", b"", dtb):
            image_id.update(component)
            image_id.update(struct.pack("<I", len(component)))
        header[576:608] = image_id.digest() + b"\0" * 12
        struct.pack_into("<I", header, 1644, 1660)
        struct.pack_into("<I", header, 1648, len(dtb))
        struct.pack_into("<Q", header, 1652, 0x01F00000)

        def padded(value: bytes) -> bytes:
            return value + b"\0" * ((-len(value)) % page_size)

        path.write_bytes(bytes(header) + padded(kernel) + padded(ramdisk) + padded(dtb))
        path.chmod(0o600)

    @staticmethod
    def inspect_fixture_components(path: Path) -> dict[str, str]:
        data = path.read_bytes()
        page = 4096
        kernel_size = struct.unpack_from("<I", data, 8)[0]
        ramdisk_size = struct.unpack_from("<I", data, 16)[0]
        dtb_size = struct.unpack_from("<I", data, 1648)[0]
        kernel = data[page : page + kernel_size]
        cursor = page + ((kernel_size + page - 1) // page * page)
        ramdisk = data[cursor : cursor + ramdisk_size]
        cursor += (ramdisk_size + page - 1) // page * page
        dtb = data[cursor : cursor + dtb_size]
        return {
            "kernel": hashlib.sha256(kernel).hexdigest(),
            "ramdisk": hashlib.sha256(ramdisk).hexdigest(),
            "dtb": hashlib.sha256(dtb).hexdigest(),
        }

    def write_manifests(self) -> None:
        cmdline = (
            "androidboot.hardware=qcom "
            "androidboot.usbcontroller=a600000.dwc3 "
            f"pmos_boot_uuid={self.boot_uuid} "
            f"pmos_root_uuid={self.root_uuid} "
            "pmos_rootfsopts=defaults"
        )
        boot_text = "\n".join(
            (
                f"artifact_boot={self.boot.name}",
                f"artifact_boot_sha256={self.digest(self.boot)}",
                f"artifact_boot_size={self.boot.stat().st_size}",
                f"kernel_sha256={self.component_hashes['kernel']}",
                f"source_ramdisk_sha256={self.component_hashes['ramdisk']}",
                f"dtb_sha256={self.component_hashes['dtb']}",
                f"cmdline={cmdline}",
                "",
            )
        )
        pair_text = "\n".join(
            (
                f"artifact_boot={self.boot.name}",
                f"artifact_boot_sha256={self.digest(self.boot)}",
                f"artifact_boot_size={self.boot.stat().st_size}",
                f"artifact_userdata_sha256={'9' * 64}",
                "",
            )
        )
        self.private_write(self.boot_manifest, boot_text)
        self.private_write(self.pair_manifest, pair_text)

    def write_history(self) -> None:
        legacy = hashlib.sha256(self.serial.encode("ascii")).hexdigest()[:16]
        d199 = {
            "gates": {
                "identity": {
                    "expected_device_fingerprint": legacy,
                    "expected_product": "lmi",
                }
            }
        }
        d200 = {
            "gates": {
                "identity": {
                    "expected_device_fingerprint": legacy,
                    "expected_product": "lmi",
                },
                "artifact": {"manifest_sha256": self.digest(self.pair_manifest)},
            },
            "execution_contract": {"artifact_sha256": self.digest(self.boot)},
        }
        self.private_write(self.d199, json.dumps(d199, sort_keys=True) + "\n")
        self.private_write(self.d200, json.dumps(d200, sort_keys=True) + "\n")

    def write_acquisition_attestation(self) -> None:
        host_path = (
            r"C:\Pinned\fastboot.exe" if self.fake_fastboot.suffix == ".exe" else str(self.fake_fastboot)
        )
        record = {
            "archive": {
                "filename": "platform-tools_r37.0.0-win.zip",
                "sha1": "a" * 40,
                "sha256": "b" * 64,
                "size": self.fake_fastboot.stat().st_size + 1,
                "url": "https://dl.google.com/android/repository/platform-tools_r37.0.0-win.zip",
            },
            "device_action_performed": False,
            "installed_copy": {
                "byte_identical_to_archive_member": True,
                "path": host_path,
                "sha256": self.digest(self.fake_fastboot),
                "size": self.fake_fastboot.stat().st_size,
            },
            "member": {
                "path": "platform-tools/fastboot.exe",
                "sha256": self.digest(self.fake_fastboot),
                "size": self.fake_fastboot.stat().st_size,
            },
            "observed_local_date": "2026-07-20",
            "repository_metadata": {
                "package": "fixture",
                "url": "https://dl.google.com/android/repository/repository2-3.xml",
            },
            "schema": "lmi-d110-fastboot-official-acquisition/v1",
        }
        self.private_write(
            self.acquisition, json.dumps(record, indent=2, sort_keys=True) + "\n"
        )

    def make_policy(self, *, host_kind: str) -> dict[str, object]:
        nonce = "1" * 64
        legacy = hashlib.sha256(self.serial.encode("ascii")).hexdigest()[:16]
        scoped = hashlib.sha256(
            nonce.encode("ascii") + b"\0" + self.serial.encode("ascii")
        ).hexdigest()
        host_path = (
            r"C:\Pinned\fastboot.exe" if host_kind == "windows" else str(self.fake_fastboot)
        )
        return {
            "schema": "lmi-d110-recovery-policy/v1",
            "policy_id": "fixture-pinned-policy",
            "claim": CLAIM,
            "historical_identity": {
                "privacy_nonce": nonce,
                "expected_nonce_scoped_serial_sha256": scoped,
                "legacy_fingerprint": legacy,
                "d199_path": str(self.d199.relative_to(self.repo)),
                "d199_sha256": self.digest(self.d199),
                "d200_path": str(self.d200.relative_to(self.repo)),
                "d200_sha256": self.digest(self.d200),
            },
            "artifact": {
                "boot_path": str(self.boot.relative_to(self.repo)),
                "boot_sha256": self.digest(self.boot),
                "boot_size": self.boot.stat().st_size,
                "boot_manifest_path": str(self.boot_manifest.relative_to(self.repo)),
                "boot_manifest_sha256": self.digest(self.boot_manifest),
                "pair_manifest_path": str(self.pair_manifest.relative_to(self.repo)),
                "pair_manifest_sha256": self.digest(self.pair_manifest),
                "kernel_sha256": self.component_hashes["kernel"],
                "ramdisk_sha256": self.component_hashes["ramdisk"],
                "dtb_sha256": self.component_hashes["dtb"],
                "boot_uuid": self.boot_uuid,
                "root_uuid": self.root_uuid,
                "historical_persisted_userdata_release": "D114",
                "historical_persisted_userdata_sha256": "9" * 64,
            },
            "fastboot": {
                "acquisition_attestation_path": str(
                    self.acquisition.relative_to(self.repo)
                ),
                "acquisition_attestation_sha256": self.digest(self.acquisition),
                "host_path_kind": host_kind,
                "host_path": host_path,
                "sha256": self.digest(self.fake_fastboot),
                "size": self.fake_fastboot.stat().st_size,
            },
            "device": {
                "product": "lmi",
                "unlocked": "yes",
                "is_userspace": "no",
                "minimum_battery_mv": 3800,
                "battery_soc_ok": "yes",
                "minimum_max_download_size": self.boot.stat().st_size,
            },
            "execution": {
                "operation": "fastboot boot",
                "explicit_fastboot_partition_flash": False,
                "booted_os_may_mutate_persisted_userdata": True,
                "receipt_ttl_seconds": PRODUCTION_RECEIPT_TTL_SECONDS,
                "max_action_attempts": 1,
                "automatic_retry": False,
                "action_timeout_seconds": 2,
                "receipt_dir": str(
                    (self.base / "d110-recovery-receipts").relative_to(self.repo)
                ),
            },
        }

    def write_policy(self, *, host_kind: str, mutate=None) -> None:
        policy = self.make_policy(host_kind=host_kind)
        if mutate is not None:
            mutate(policy)
        self.private_write(
            self.policy,
            json.dumps(policy, indent=2, sort_keys=True) + "\n",
        )

    def install_script(self, *, windows: bool) -> None:
        script = STAGE_SCRIPT.read_text(encoding="utf-8")
        production_anchor = self.production_anchor(script)
        script = script.replace(production_anchor, self.digest(self.policy), 1)
        if windows:
            self.fake_wslpath = self.root / "wslpath"
            self.fake_powershell = self.root / "powershell.exe"
            self.write_windows_helpers()
            script = script.replace("/usr/bin/wslpath", str(self.fake_wslpath))
            script = script.replace(
                "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe",
                str(self.fake_powershell),
            )
        self.stage_script = self.scripts / STAGE_SCRIPT.name
        self.stage_script.write_text(script, encoding="utf-8")
        self.stage_script.chmod(0o755)

    @staticmethod
    def production_anchor(script: str) -> str:
        prefix = "readonly TRUSTED_POLICY_SHA256='"
        start = script.index(prefix) + len(prefix)
        anchor = script[start : start + 64]
        if len(anchor) != 64 or any(c not in "0123456789abcdef" for c in anchor):
            raise AssertionError("production policy anchor is not a literal SHA-256")
        return anchor

    def repin_script(self) -> None:
        script = self.stage_script.read_text(encoding="utf-8")
        script = script.replace(self.production_anchor(script), self.digest(self.policy), 1)
        self.stage_script.write_text(script, encoding="utf-8")
        self.stage_script.chmod(0o755)

    def write_windows_helpers(self) -> None:
        assert self.fake_wslpath is not None and self.fake_powershell is not None
        windows_host = r"C:\Pinned\fastboot.exe"
        unc_boot = r"\\wsl.localhost\Fixture\repo\private\d110.img"
        self.fake_wslpath.write_text(
            f"""#!/usr/bin/env bash
set -eu
if [ "$1" = -u ] && [ "$2" = '{windows_host}' ]; then
    printf '%s\\r\\n' '{self.fake_fastboot}'
elif [ "$1" = -w ] && [ "$2" = '{self.fake_fastboot}' ]; then
    printf '%s\\r\\n' '{windows_host}'
elif [ "$1" = -w ] && [ "$2" = '{self.boot}' ]; then
    printf '%s\\r\\n' '{unc_boot}'
else
    exit 2
fi
""",
            encoding="utf-8",
        )
        self.fake_wslpath.chmod(0o755)
        self.fake_powershell.write_text(
            f"""#!/usr/bin/env bash
set -eu
printf '%s %s\\r\\n' '{self.boot.stat().st_size}' '{self.digest(self.boot)}'
""",
            encoding="utf-8",
        )
        self.fake_powershell.chmod(0o755)

    def env(self, **updates: str) -> dict[str, str]:
        env = os.environ.copy()
        for key in LEGACY_TRUST_ENV:
            env.pop(key, None)
        env.update(
            {
                "FAKE_FASTBOOT_LOG": str(self.fastboot_log),
                "LC_ALL": "C",
            }
        )
        env.update(updates)
        return env

    def run(
        self,
        mode: str,
        *,
        receipt: str | None = None,
        confirmation: str | None = None,
        extra_env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str]:
        args = [str(self.stage_script), "--stage", "ramboot", mode]
        if receipt is not None:
            args.extend(("--receipt", receipt))
        if confirmation is not None:
            args.extend(("--confirm", confirmation))
        return subprocess.run(
            args,
            cwd=self.repo,
            env=self.env(**(extra_env or {})),
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )

    def clear_log(self) -> None:
        self.fastboot_log.write_text("", encoding="utf-8")

    def calls(self) -> str:
        return self.fastboot_log.read_text(encoding="utf-8")

    def preflight(self, **env: str) -> tuple[str, str, subprocess.CompletedProcess[str]]:
        result = self.run("--preflight", extra_env=env)
        receipt = ""
        confirmation = ""
        for line in result.stdout.splitlines():
            if line.startswith("receipt="):
                receipt = line.split("=", 1)[1]
            elif line.startswith("required_confirmation="):
                confirmation = line.split("=", 1)[1]
        return receipt, confirmation, result


class DownstreamStageSafetyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.fixture = D110GateFixture(Path(self.temp_dir.name))

    def test_script_is_executable_and_usage_matches_ramboot_modes(self) -> None:
        self.assertTrue(STAGE_SCRIPT.stat().st_mode & 0o111)
        result = subprocess.run(
            [str(STAGE_SCRIPT), "--help"],
            cwd=REPO,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--stage ramboot --preflight", result.stdout)
        self.assertNotIn("--stage rootfs", result.stdout)
        self.assertIn(CLAIM, result.stdout)

    def test_dry_run_is_local_only_and_refuses_rootfs(self) -> None:
        result = self.fixture.run("--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("local-only; no phone query or hardware command", result.stdout)
        self.assertIn(self.fixture.digest(self.fixture.boot), result.stdout)
        self.assertEqual(self.fixture.calls(), "")
        refused = subprocess.run(
            [str(self.fixture.stage_script), "--stage", "rootfs", "--dry-run"],
            cwd=self.fixture.repo,
            env=self.fixture.env(),
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(refused.returncode, 2)
        self.assertEqual(self.fixture.calls(), "")

    def test_preflight_creates_private_short_lived_receipt_and_no_action(self) -> None:
        receipt, confirmation, result = self.fixture.preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(receipt)
        self.assertEqual(
            confirmation,
            "boot-d110-" + self.fixture.digest(self.fixture.boot) + "-" + confirmation.rsplit("-", 1)[1],
        )
        path = Path(receipt)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
        record = json.loads(path.read_text(encoding="ascii"))
        self.assertEqual(
            record["expires_at_epoch"] - record["issued_at_epoch"],
            PRODUCTION_RECEIPT_TTL_SECONDS,
        )
        self.assertNotIn(self.fixture.serial, path.read_text(encoding="ascii"))
        self.assertNotIn("<boot><", self.fixture.calls())

    def test_execute_consumes_receipt_before_exactly_one_boot_and_replay_fails(self) -> None:
        receipt, confirmation, preflight = self.fixture.preflight()
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.fixture.clear_log()
        result = self.fixture.run(
            "--execute", receipt=receipt, confirmation=confirmation
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("receipt=consumed-before-execution", result.stdout)
        self.assertIn("fastboot_boot_attempts=1", result.stdout)
        calls = self.fixture.calls()
        self.assertEqual(calls.count("<boot>"), 1)
        self.assertNotIn("<flash>", calls)
        self.fixture.clear_log()
        replay = self.fixture.run(
            "--execute", receipt=receipt, confirmation=confirmation
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(self.fixture.calls(), "")

    def test_receipt_is_consumed_when_post_claim_gate_fails_and_never_retried(self) -> None:
        receipt, confirmation, preflight = self.fixture.preflight()
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.fixture.clear_log()
        failed = self.fixture.run(
            "--execute",
            receipt=receipt,
            confirmation=confirmation,
            extra_env={"FAKE_PRODUCT": "other"},
        )
        self.assertEqual(failed.returncode, 2)
        self.assertFalse(Path(receipt).exists())
        self.assertTrue(list((Path(receipt).parents[1] / "consumed").glob("*.json")))
        self.assertNotIn("<boot>", self.fixture.calls())
        self.fixture.clear_log()
        replay = self.fixture.run(
            "--execute", receipt=receipt, confirmation=confirmation
        )
        self.assertEqual(replay.returncode, 2)
        self.assertEqual(self.fixture.calls(), "")

    def test_action_failure_is_one_attempt_and_receipt_stays_consumed(self) -> None:
        receipt, confirmation, preflight = self.fixture.preflight()
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.fixture.clear_log()
        result = self.fixture.run(
            "--execute",
            receipt=receipt,
            confirmation=confirmation,
            extra_env={"FAKE_ACTION_FAIL": "1"},
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("no retry", result.stderr)
        self.assertEqual(self.fixture.calls().count("<boot>"), 1)
        self.assertFalse(Path(receipt).exists())

    def test_slow_execute_query_crossing_receipt_expiry_never_boots(self) -> None:
        receipt, confirmation, preflight = self.fixture.preflight()
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        record = json.loads(Path(receipt).read_text(encoding="ascii"))
        now = int(time.time())
        record["issued_at_epoch"] = now - (
            PRODUCTION_RECEIPT_TTL_SECONDS - 2
        )
        record["expires_at_epoch"] = now + 2
        Path(receipt).write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        Path(receipt).chmod(0o600)
        os.utime(receipt, (record["issued_at_epoch"], record["issued_at_epoch"]))
        self.fixture.clear_log()
        result = self.fixture.run(
            "--execute",
            receipt=receipt,
            confirmation=confirmation,
            extra_env={
                "FAKE_QUERY_DELAY": "4",
                "FAKE_DELAY_KEY": "serialno",
            },
        )
        self.assertEqual(result.returncode, 2)
        self.assertFalse(Path(receipt).exists())
        self.assertTrue(
            list((Path(receipt).parents[1] / "consumed").glob("*.json"))
        )
        self.assertNotIn("<boot>", self.fixture.calls())
        self.assertIn("expired", result.stderr)

    def test_full_hash_and_nonce_confirmation_and_ttl_are_enforced(self) -> None:
        receipt, confirmation, preflight = self.fixture.preflight()
        self.assertEqual(preflight.returncode, 0, preflight.stderr)
        self.fixture.clear_log()
        wrong = self.fixture.run(
            "--execute",
            receipt=receipt,
            confirmation=confirmation[:-1]
            + ("0" if confirmation[-1] != "0" else "1"),
        )
        self.assertEqual(wrong.returncode, 2)
        self.assertTrue(Path(receipt).exists())
        self.assertEqual(self.fixture.calls(), "")

        record = json.loads(Path(receipt).read_text(encoding="ascii"))
        record["issued_at_epoch"] = int(time.time()) - 100
        record["expires_at_epoch"] = (
            record["issued_at_epoch"] + PRODUCTION_RECEIPT_TTL_SECONDS
        )
        Path(receipt).write_text(
            json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="ascii",
        )
        Path(receipt).chmod(0o600)
        os.utime(receipt, (record["issued_at_epoch"], record["issued_at_epoch"]))
        expired = self.fixture.run(
            "--execute", receipt=receipt, confirmation=confirmation
        )
        self.assertEqual(expired.returncode, 2)
        self.assertEqual(self.fixture.calls(), "")

    def test_devices_counts_every_nonempty_line_and_normalizes_crlf(self) -> None:
        bad_outputs = (
            "SYNTHETIC-LMI-01\\tfastboot\\nwarning\\n",
            "SYNTHETIC-LMI-01\\tfastboot\\nOTHER\\toffline\\n",
            "warning only\\n",
            "   \\nSYNTHETIC-LMI-01\\tfastboot\\n",
        )
        for output in bad_outputs:
            with self.subTest(output=output):
                self.fixture.clear_log()
                result = self.fixture.run(
                    "--preflight", extra_env={"FAKE_DEVICES_OUTPUT": output}
                )
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("<getvar>", self.fixture.calls())
        self.fixture.clear_log()
        receipt, _, valid = self.fixture.preflight(FAKE_CRLF="1")
        self.assertEqual(valid.returncode, 0, valid.stderr)
        self.assertTrue(receipt)

    def test_enumerated_serial_getvar_and_private_history_must_all_match(self) -> None:
        cases = (
            {"FAKE_GETVAR_SERIAL": "DIFFERENT"},
            {"FAKE_SERIAL": "OTHER-HANDSET"},
        )
        for env in cases:
            with self.subTest(env=env):
                self.fixture.clear_log()
                result = self.fixture.run("--preflight", extra_env=env)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("<boot>", self.fixture.calls())
                self.assertNotIn(self.fixture.serial, result.stdout + result.stderr)

    def test_pinned_product_battery_unlock_mode_and_download_policy(self) -> None:
        cases = (
            {"FAKE_PRODUCT": "other"},
            {"FAKE_UNLOCKED": "no"},
            {"FAKE_USERSPACE": "yes"},
            {"FAKE_BATTERY_VOLTAGE": "3799"},
            {"FAKE_BATTERY_SOC_OK": "no"},
            {"FAKE_MAX_DOWNLOAD_SIZE": "1"},
        )
        for env in cases:
            with self.subTest(env=env):
                self.fixture.clear_log()
                result = self.fixture.run("--preflight", extra_env=env)
                self.assertEqual(result.returncode, 2)
                self.assertNotIn("<boot>", self.fixture.calls())

    def test_caller_cannot_substitute_an_internally_consistent_image_or_tool(self) -> None:
        alternate = self.fixture.root / "alternate.img"
        self.fixture.write_boot_image(alternate, self.fixture.boot_uuid, self.fixture.root_uuid)
        result = self.fixture.run(
            "--dry-run",
            extra_env={
                "DOWNSTREAM_BOOT_IMG": str(alternate),
                "FASTBOOT": str(self.fixture.fake_fastboot),
                "DOWNSTREAM_FASTBOOT_SHA256": self.fixture.digest(self.fixture.fake_fastboot),
            },
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("not accepted", result.stderr)
        self.assertEqual(self.fixture.calls(), "")

        policy = json.loads(self.fixture.policy.read_text(encoding="utf-8"))
        policy["artifact"]["boot_sha256"] = "0" * 64
        self.fixture.private_write(
            self.fixture.policy, json.dumps(policy, indent=2, sort_keys=True) + "\n"
        )
        tampered = self.fixture.run("--dry-run")
        self.assertEqual(tampered.returncode, 2)
        self.assertEqual(self.fixture.calls(), "")

    def test_wrong_manifest_component_uuid_and_fastboot_pins_fail_locally(self) -> None:
        mutations = (
            lambda p: p["artifact"].__setitem__("boot_manifest_sha256", "0" * 64),
            lambda p: p["artifact"].__setitem__("kernel_sha256", "0" * 64),
            lambda p: p["artifact"].__setitem__(
                "boot_uuid", "99999999-2222-4333-8444-555555555555"
            ),
            lambda p: p["fastboot"].__setitem__("sha256", "0" * 64),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = D110GateFixture(Path(temporary))
                    fixture.write_policy(host_kind="linux", mutate=mutate)
                    fixture.repin_script()
                    result = fixture.run("--preflight")
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(fixture.calls(), "")

    def test_symlink_hardlink_and_mid_preflight_path_changes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = D110GateFixture(Path(temporary))
            original = fixture.boot.read_bytes()
            fixture.boot.unlink()
            target = fixture.base / "elsewhere.img"
            fixture.private_write(target, original)
            fixture.boot.symlink_to(target)
            result = fixture.run("--preflight")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(fixture.calls(), "")

        with tempfile.TemporaryDirectory() as temporary:
            fixture = D110GateFixture(Path(temporary))
            hardlink = fixture.base / "second-link.img"
            os.link(fixture.boot, hardlink)
            result = fixture.run("--preflight")
            self.assertEqual(result.returncode, 2)
            self.assertEqual(fixture.calls(), "")

        self.fixture.clear_log()
        changed = self.fixture.run(
            "--preflight",
            extra_env={
                "FAKE_MUTATE_ON_GETVAR": "max-download-size",
                "FAKE_MUTATE_PATH": str(self.fixture.boot),
            },
        )
        self.assertEqual(changed.returncode, 2)
        self.assertNotIn("<boot>", self.fixture.calls())

    def test_absolute_coreutils_ignore_hostile_path(self) -> None:
        hostile = self.fixture.root / "hostile-bin"
        hostile.mkdir()
        marker = self.fixture.root / "path-command-ran"
        for name in ("sha256sum", "stat", "python3", "timeout"):
            path = hostile / name
            path.write_text(
                f"#!/usr/bin/env bash\nprintf hit >> '{marker}'\nexit 99\n",
                encoding="utf-8",
            )
            path.chmod(0o755)
        result = self.fixture.run(
            "--dry-run", extra_env={"PATH": str(hostile)}
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())

    def test_windows_exe_powershell_unc_and_crlf_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = D110GateFixture(Path(temporary), windows=True)
            receipt, confirmation, preflight = fixture.preflight(FAKE_CRLF="1")
            self.assertEqual(preflight.returncode, 0, preflight.stderr)
            self.assertTrue(receipt)
            fixture.clear_log()
            execute = fixture.run(
                "--execute",
                receipt=receipt,
                confirmation=confirmation,
                extra_env={"FAKE_CRLF": "1"},
            )
            self.assertEqual(execute.returncode, 0, execute.stderr)
            calls = fixture.calls()
            self.assertEqual(calls.count("<boot>"), 1)
            self.assertIn(r"<\\wsl.localhost\Fixture", calls)

    def test_windows_non_unc_candidate_and_powershell_hash_mismatch_fail_closed(self) -> None:
        for break_kind in ("unc", "hash"):
            with self.subTest(break_kind=break_kind), tempfile.TemporaryDirectory() as temporary:
                fixture = D110GateFixture(Path(temporary), windows=True)
                assert fixture.fake_wslpath is not None
                assert fixture.fake_powershell is not None
                if break_kind == "unc":
                    text = fixture.fake_wslpath.read_text(encoding="utf-8")
                    text = text.replace(
                        r"\\wsl.localhost\Fixture\repo\private\d110.img",
                        r"C:\Untrusted\d110.img",
                    )
                    fixture.fake_wslpath.write_text(text, encoding="utf-8")
                    fixture.fake_wslpath.chmod(0o755)
                else:
                    fixture.fake_powershell.write_text(
                        f"#!/usr/bin/env bash\nprintf '%s %s\\r\\n' '{fixture.boot.stat().st_size}' '{'0' * 64}'\n",
                        encoding="utf-8",
                    )
                    fixture.fake_powershell.chmod(0o755)
                result = fixture.run("--preflight")
                self.assertEqual(result.returncode, 2)
                self.assertEqual(fixture.calls(), "")

    def test_private_policy_has_noncaller_anchor_and_no_raw_serial(self) -> None:
        script = STAGE_SCRIPT.read_text(encoding="utf-8")
        anchor = D110GateFixture.production_anchor(script)
        policy_path = (
            REPO
            / "private/lmi-p1/recovery/d110-d114/d110-recovery-policy.json"
        )
        self.assertEqual(anchor, self.fixture.production_anchor(script))
        self.assertEqual(anchor, hashlib.sha256(policy_path.read_bytes()).hexdigest())
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        d199 = json.loads(
            (
                REPO
                / "private/lmi-p1/recovery/d110-d114/"
                "d199-d114-postwrite-replug-fastboot-attestation.json"
            ).read_text(encoding="utf-8")
        )
        d200 = json.loads(
            (
                REPO
                / "private/lmi-p1/recovery/d110-d114/"
                "d200-ramboot-d110-d114-splash-recursion-fix.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(
            d199["gates"]["identity"]["expected_device_fingerprint"],
            d200["gates"]["identity"]["expected_device_fingerprint"],
        )
        self.assertNotIn(
            d199["gates"]["identity"]["expected_device_fingerprint"], script
        )
        self.assertEqual(policy["claim"], CLAIM)
        acquisition_path = REPO / policy["fastboot"]["acquisition_attestation_path"]
        self.assertEqual(
            policy["fastboot"]["acquisition_attestation_sha256"],
            hashlib.sha256(acquisition_path.read_bytes()).hexdigest(),
        )
        acquisition = json.loads(acquisition_path.read_text(encoding="utf-8"))
        self.assertTrue(
            acquisition["installed_copy"]["byte_identical_to_archive_member"]
        )
        self.assertEqual(
            acquisition["installed_copy"]["sha256"], policy["fastboot"]["sha256"]
        )
        self.assertEqual(acquisition_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(policy_path.stat().st_mode & 0o777, 0o600)

    def test_public_intended_tree_has_no_private_historical_serial_match(self) -> None:
        base = REPO / "private/lmi-p1/recovery/d110-d114"
        d199 = json.loads(
            (base / "d199-d114-postwrite-replug-fastboot-attestation.json").read_text(
                encoding="utf-8"
            )
        )
        legacy = d199["gates"]["identity"]["expected_device_fingerprint"]
        listed = subprocess.check_output(
            ["git", "ls-files", "-co", "--exclude-standard", "-z"], cwd=REPO
        ).decode("utf-8").split("\0")
        matching_paths: set[str] = set()
        for relative in listed:
            if (
                not relative
                or relative == "private"
                or relative.startswith("private/")
            ):
                continue
            path = REPO / relative
            try:
                data = path.read_bytes()
            except OSError:
                continue
            if b"\0" in data:
                continue
            text = data.decode("utf-8", errors="ignore")
            for token in re.findall(
                r"(?<![A-Za-z0-9._:-])[A-Za-z0-9._:-]{4,128}"
                r"(?![A-Za-z0-9._:-])",
                text,
            ):
                if hashlib.sha256(token.encode("utf-8")).hexdigest()[:16] == legacy:
                    matching_paths.add(relative)
        self.assertEqual(
            matching_paths,
            set(),
            "private historical device identity remains in public paths: "
            + ", ".join(sorted(matching_paths)),
        )

    def test_real_policy_fixture_and_attestation_pin_the_same_30_second_ttl(self) -> None:
        base = REPO / "private/lmi-p1/recovery/d110-d114"
        policy_path = base / "d110-recovery-policy.json"
        policy = json.loads(policy_path.read_text(encoding="utf-8"))
        fixture_policy = self.fixture.make_policy(host_kind="linux")
        attestation = json.loads(
            (base / "recovery-attestation.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            policy["execution"]["receipt_ttl_seconds"],
            PRODUCTION_RECEIPT_TTL_SECONDS,
        )
        self.assertEqual(
            fixture_policy["execution"]["receipt_ttl_seconds"],
            policy["execution"]["receipt_ttl_seconds"],
        )
        self.assertEqual(
            attestation["execution_gate"]["receipt_ttl_seconds"],
            PRODUCTION_RECEIPT_TTL_SECONDS,
        )
        self.assertEqual(
            attestation["execution_gate"]["recovery_policy_sha256"],
            hashlib.sha256(policy_path.read_bytes()).hexdigest(),
        )
        self.assertTrue(
            attestation["execution_gate"][
                "receipt_expiry_rechecked_immediately_before_action"
            ]
        )
        self.assertTrue(
            attestation["execution_gate"]["execute_queries_share_receipt_deadline"]
        )


class MainlineProgressPasswordTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        self.root = Path(self.temp_dir.name)
        self.repo = self.root / "repo"
        self.scripts = self.repo / "scripts"
        self.scripts.mkdir(parents=True)
        self.loop_script = self.scripts / LOOP_SCRIPT.name
        shutil.copyfile(LOOP_SCRIPT, self.loop_script)
        self.loop_script.chmod(0o755)
        self.fake_bin = self.root / "bin"
        self.fake_bin.mkdir()
        self.pmbootstrap_log = self.root / "pmbootstrap.log"
        self.pmbootstrap_log.write_text("", encoding="utf-8")

    def install_fake_build_commands(self) -> None:
        helper_names = (
            "40_prepare_mainline_lmi_overlay.sh",
            "45_build_lmi_copydown_boot.sh",
            "46_verify_lmi_copydown_boot.sh",
            "47_make_lmi_release_bundle.sh",
            "62_refresh_lmi_release_docs.sh",
            "69_audit_lmi_resources.sh",
            "59_release_static_ci.sh",
        )
        helper = """#!/usr/bin/env bash
set -eu
printf 'helper-password=%s\\n' "${LMI_PMOS_TEST_PASSWORD-unset}"
"""
        for name in helper_names:
            path = self.scripts / name
            path.write_text(helper, encoding="utf-8")
            path.chmod(0o755)

        fake_pmbootstrap = self.fake_bin / "pmbootstrap"
        fake_pmbootstrap.write_text(
            """#!/usr/bin/env bash
set -eu
for arg in "$@"; do
    printf '<%s>' "$arg" >> "$FAKE_PMBOOTSTRAP_LOG"
done
printf '\n' >> "$FAKE_PMBOOTSTRAP_LOG"
printf 'stdout arguments: %s\\n' "$*"
printf 'stderr arguments: %s env-password=%s\\n' \\
    "$*" "${LMI_PMOS_TEST_PASSWORD-unset}" >&2
""",
            encoding="utf-8",
        )
        fake_pmbootstrap.chmod(0o755)

    def run_loop(
        self, *, password: str | None, report: Path
    ) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env.update(
            {
                "PATH": f"{self.fake_bin}:/usr/bin:/bin",
                "FAKE_PMBOOTSTRAP_LOG": str(self.pmbootstrap_log),
                "LMI_RELEASE_BUNDLE_DIR": str(self.root / "bundle"),
                "OUT_DIR": str(self.root / "copydown"),
                "LC_ALL": "C",
            }
        )
        if password is None:
            env.pop("LMI_PMOS_TEST_PASSWORD", None)
        else:
            env["LMI_PMOS_TEST_PASSWORD"] = password
        return subprocess.run(
            [
                "/usr/bin/bash",
                str(self.loop_script),
                "--once",
                "--build",
                "--report",
                str(report),
            ],
            cwd=self.repo,
            env=env,
            text=True,
            capture_output=True,
            timeout=10,
            check=False,
        )

    def test_build_without_local_password_fails_before_running_helpers(self) -> None:
        report = self.root / "missing-password-report.txt"
        result = self.run_loop(password=None, report=report)
        self.assertEqual(result.returncode, 2)
        self.assertIn("must be set locally", result.stderr)
        self.assertFalse(report.exists())
        self.assertEqual(self.pmbootstrap_log.read_text(encoding="utf-8"), "")

    def test_password_is_used_only_by_redacted_install_step(self) -> None:
        self.install_fake_build_commands()
        password = "private-test-password-9341"
        report = self.root / "progress-report.txt"
        result = self.run_loop(password=password, report=report)
        self.assertEqual(result.returncode, 0, result.stderr)
        report_text = report.read_text(encoding="utf-8")
        visible_output = result.stdout + result.stderr + report_text
        self.assertNotIn(password, visible_output)
        self.assertNotIn("147147", LOOP_SCRIPT.read_text(encoding="utf-8"))
        self.assertIn(
            "output=withheld because this command receives a credential", report_text
        )
        self.assertIn("helper-password=unset", report_text)
        calls = self.pmbootstrap_log.read_text(encoding="utf-8")
        self.assertIn(f"<install><--password><{password}><--zap>", calls)
        self.assertEqual(calls.count(password), 1)


if __name__ == "__main__":
    unittest.main()
