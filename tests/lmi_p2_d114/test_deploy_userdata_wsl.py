from __future__ import annotations

import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
import unittest
from unittest import mock

from scripts.lmi_p2_d114 import deploy_userdata_wsl as deploy


SERIAL = "SYNTHETIC-LMI-0001"
NONCE = "a" * 64
IDENTITY = hashlib.sha256(f"{NONCE}:{SERIAL}".encode("ascii")).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


class FakeFastboot:
    def __init__(
        self,
        *,
        write_result: deploy.CommandResult | Exception | None = None,
        battery_values: tuple[int, ...] = (4373,),
        devices_stdout: bytes | None = None,
        on_write: object | None = None,
        partition_size_value: str = " 0x1AC07FB000",
    ) -> None:
        self.calls: list[tuple[tuple[str, ...], int, tuple[int, ...], dict[str, str]]] = []
        self.write_result = write_result or deploy.CommandResult(
            0,
            b"",
            b"Sending sparse 'userdata' 1/1 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  2.000s]\n"
            b"Finished. Total time: 3.000s\n",
        )
        self.battery_values = battery_values
        self.devices_stdout = (
            f"{SERIAL}\tfastboot\n".encode("ascii")
            if devices_stdout is None
            else devices_stdout
        )
        self.device_round = -1
        self.on_write = on_write
        self.partition_size_value = partition_size_value

    def __call__(
        self,
        argv: tuple[str, ...] | list[str],
        timeout: int,
        pass_fds: tuple[int, ...],
        environment: dict[str, str],
    ) -> deploy.CommandResult:
        call = (tuple(argv), timeout, pass_fds, dict(environment))
        self.calls.append(call)
        if "flash" in argv:
            if callable(self.on_write):
                self.on_write()
            if isinstance(self.write_result, Exception):
                raise self.write_result
            return self.write_result
        if argv[-1] == "devices":
            self.device_round += 1
            return deploy.CommandResult(0, self.devices_stdout, b"")
        name = argv[-1]
        values = {
            "serialno": SERIAL,
            "product": "lmi",
            "unlocked": "yes",
            "is-userspace": "no",
            "partition-type:userdata": "f2fs",
            "partition-size:userdata": self.partition_size_value,
            "battery-voltage": str(self.battery_values[min(self.device_round, len(self.battery_values) - 1)]),
            "battery-soc-ok": "yes",
            "max-download-size": "805306368",
        }
        finished = b"Finished. Total time: 0.007s\n"
        if name == "is-logical:userdata":
            return deploy.CommandResult(
                0,
                b"",
                b"getvar:is-logical:userdata                         FAILED (remote: 'GetVar Variable Not found')\n" + finished,
            )
        return deploy.CommandResult(0, b"", f"{name}: {values[name]}\n".encode("ascii") + finished)

    @property
    def write_calls(self) -> list[tuple[tuple[str, ...], int, tuple[int, ...], dict[str, str]]]:
        return [call for call in self.calls if "flash" in call[0]]


class Fixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.private = root / "private" / "reports"
        self.private.mkdir(parents=True)
        os.chmod(root / "private", 0o700)
        os.chmod(self.private, 0o700)
        for name in ("attempt-ledger", "claim-ledger"):
            directory = self.private / name
            directory.mkdir()
            os.chmod(directory, 0o700)
        self.candidate_path = root / "private" / "candidate.img"
        self.candidate_path.write_bytes(b"candidate")
        os.chmod(self.candidate_path, 0o600)

    def profile(self, candidate_sha: str = deploy.PRODUCTION.sparse_sha256) -> dict[str, object]:
        artifacts: dict[str, object] = {
            "assembly_attestation": {"path": "private/a.json", "sha256": deploy.PRODUCTION.assembly_sha256, "size": deploy.PRODUCTION.assembly_size},
            "candidate": {"logical_size": deploy.PRODUCTION.raw_size, "path": "private/candidate.img", "representation": "android-sparse", "roundtrip_raw_sha256": deploy.PRODUCTION.raw_sha256, "sha256": candidate_sha, "size": deploy.PRODUCTION.sparse_size},
            "candidate_raw": {"path": "private/raw.img", "sha256": deploy.PRODUCTION.raw_sha256, "size": deploy.PRODUCTION.raw_size},
            "completed_actions_lock": {"path": "config/completed.json", "sha256": deploy.PRODUCTION.completed_sha256, "size": deploy.PRODUCTION.completed_size},
            "deploy_policy_lock": {"path": "config/policy.json", "sha256": "1" * 64, "size": 1},
            "fastboot_runtime_lock": {"path": "config/runtime.json", "sha256": deploy.PRODUCTION.runtime_sha256, "size": deploy.PRODUCTION.runtime_size},
            "p2_injection_attestation": {"path": "private/i.json", "sha256": deploy.PRODUCTION.injection_sha256, "size": deploy.PRODUCTION.injection_size},
            "p2_rootfs": {"path": "private/rootfs", "sha256": deploy.PRODUCTION.rootfs_sha256, "size": deploy.PRODUCTION.rootfs_size},
            "physical_mapping_evidence": {"path": "config/mapping.json", "sha256": deploy.PRODUCTION.mapping_sha256, "size": deploy.PRODUCTION.mapping_size},
            "rollback": {"logical_size": deploy.PRODUCTION.raw_size, "path": "private/rollback.img", "representation": "android-sparse", "roundtrip_raw_sha256": deploy.PRODUCTION.baseline_raw_sha256, "sha256": deploy.PRODUCTION.rollback_sha256, "size": deploy.PRODUCTION.rollback_size},
        }
        return {
            "artifacts": artifacts,
            "compatibility": {"d110_boot": {"authorization": False, "sha256": deploy.PRODUCTION.d110_boot_sha256, "size": deploy.PRODUCTION.d110_boot_size}},
            "device": {"expected_product": "lmi", "expected_userdata_capacity": deploy.PRODUCTION.userdata_capacity, "minimum_battery_mv": 3800, "minimum_max_download_size": deploy.PRODUCTION.d110_boot_size, "partition_type": "f2fs"},
            "execution": {"automatic_retry": False, "claim_kind": "flash-userdata", "max_attempts": 1, "operation": "flash", "partition": "userdata", "slot_layout_claim": "not-proven", "write_timeout_seconds": 1800},
            "identity": {"expected_nonce_scoped_serial_sha256": IDENTITY, "expected_serial": SERIAL, "privacy_nonce": NONCE},
            "ledgers": {"candidate_attempts": "private/reports/attempt-ledger", "claim_consumption": "private/reports/claim-ledger"},
            "profile_id": "test-wsl-r1",
            "schema": deploy.PROFILE_SCHEMA,
        }

    def audit(self, candidate_sha: str = deploy.PRODUCTION.sparse_sha256) -> deploy.Audit:
        item = deploy._open_regular(self.candidate_path, self.root, "candidate")
        completed = json.loads((deploy.REPO / "config/lmi-p2-d114/completed-userdata-actions-lock.json").read_text())
        mapping = {
            "override": {
                "allowed_getvar_result": "unsupported",
                "fastboot_mode": "bootloader",
                "partition": "userdata",
                "partition_type": "f2fs",
                "super_or_fastbootd_fallback_allowed": False,
            }
        }
        profile = self.profile(candidate_sha)
        return deploy.Audit(
            self.root,
            profile,
            hashlib.sha256(canonical(profile)).hexdigest(),
            {},
            mapping,
            completed,
            {},
            {"candidate": item},
            ("/runtime/ld-linux.so", "--inhibit-cache", "--library-path", "/runtime/lib", "/runtime/fastboot"),
        )

    def path(self, name: str) -> Path:
        return self.private / name

    def consumed_path(self, approval_sha256: str) -> Path:
        return self.private / "claim-ledger" / f"{approval_sha256}.consumed.json"

    def attempt_path(self) -> Path:
        return self.private / "attempt-ledger" / f"{deploy.PRODUCTION.sparse_sha256}.attempt.json"


class DeployUserdataWslTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.fixture = Fixture(Path(self.temporary.name))

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_production_locks_pin_exact_artifacts_runtime_and_timeout(self) -> None:
        root = deploy.REPO
        specs = {
            "fastboot-wsl-runtime-lock.json": (deploy.PRODUCTION.runtime_sha256, deploy.PRODUCTION.runtime_size),
            "completed-userdata-actions-lock.json": (deploy.PRODUCTION.completed_sha256, deploy.PRODUCTION.completed_size),
            "userdata-deploy-profile-wsl.template.json": (deploy.PRODUCTION.template_sha256, deploy.PRODUCTION.template_size),
        }
        for name, (digest, size) in specs.items():
            payload = (root / "config/lmi-p2-d114" / name).read_bytes()
            self.assertEqual((hashlib.sha256(payload).hexdigest(), len(payload)), (digest, size))
        runtime = json.loads((root / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text())
        self.assertEqual(runtime["schema"], deploy.RUNTIME_SCHEMA)
        self.assertEqual(runtime["symlink"]["lstat_size"], 42)
        self.assertEqual(runtime["executable"]["size"], 506488)
        self.assertEqual(runtime["executable"]["sha256"], "4d90c8ff8569476a76ea1f6a2c86e54e833e0e1c0e82af13a10277c7b617c506")
        sonames = {item["soname"] for item in runtime["libraries"]}
        self.assertFalse(set(runtime["executable"]["dt_needed"]) - sonames)
        for item in runtime["libraries"]:
            self.assertFalse(set(item["dt_needed"]) - sonames - {"ld-linux-x86-64.so.2"})
        self.assertEqual(
            runtime["interpreter"]["usrmerge_chain"],
            [
                {"lstat_size": 9, "path": "/lib64", "target": "usr/lib64", "type": "symbolic-link"},
                {
                    "lstat_size": 44,
                    "path": "/usr/lib64/ld-linux-x86-64.so.2",
                    "target": "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
                    "type": "symbolic-link",
                },
            ],
        )
        self.assertEqual(runtime["executable"]["interpreter"], runtime["interpreter"]["lookup_path"])
        self.assertEqual(runtime["execution"]["argv_prefix"][0], runtime["interpreter"]["resolved_path"])
        policy = json.loads((root / "config/lmi-p2-d114/userdata-deploy-policy-lock-wsl-r1.json").read_text())
        self.assertEqual(policy["execution"]["write_timeout_seconds"], 1800)
        self.assertFalse(policy["historical_actions"]["d110_boot_authorization"])
        self.assertFalse(policy["historical_actions"]["new_sparse_precompleted"])
        self.assertEqual(
            policy["runtime"]["ancestor_symlink_policy"],
            "reject-except-exact-locked-interpreter-usrmerge-chain",
        )
        profile_path = root / "private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/lmi-d114-userdata-p2-r1-sixrow-wsl-deploy-profile-20260722.json"
        profile = json.loads(profile_path.read_text())
        for name, path in (
            ("fastboot_runtime_lock", root / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json"),
            ("deploy_policy_lock", root / "config/lmi-p2-d114/userdata-deploy-policy-lock-wsl-r1.json"),
        ):
            payload = path.read_bytes()
            self.assertEqual(
                profile["artifacts"][name],
                {
                    "path": path.relative_to(root).as_posix(),
                    "sha256": hashlib.sha256(payload).hexdigest(),
                    "size": len(payload),
                },
            )

    def test_current_wsl_runtime_lock_accepts_exact_usrmerge_without_device_command(self) -> None:
        runtime = json.loads((deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text())
        calls: list[tuple[str, ...]] = []

        def runtime_only_runner(
            argv: tuple[str, ...] | list[str],
            timeout: int,
            pass_fds: tuple[int, ...],
            environment: dict[str, str],
        ) -> deploy.CommandResult:
            command = tuple(argv)
            self.assertNotIn("devices", command)
            self.assertFalse(any(value.startswith("getvar:") for value in command))
            self.assertNotIn("flash", command)
            calls.append(command)
            return deploy.run_bounded(command, timeout, pass_fds, environment)

        prefix, held = deploy._validate_runtime(runtime, runtime_only_runner)
        try:
            self.assertEqual(prefix[0], "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
            self.assertEqual([command[-1] for command in calls], ["--version", "fastboot"])
        finally:
            for item in reversed(held):
                item.close()

    def test_usrmerge_lock_mutations_fail_closed_before_runner(self) -> None:
        locked = json.loads((deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text())
        variants: list[dict[str, object]] = []
        v1 = copy.deepcopy(locked)
        v1["schema"] = "lmi-p2-d114-fastboot-wsl-runtime-lock/v1"
        variants.append(v1)
        for index, field, value in (
            (0, "target", "/usr/lib64"),
            (0, "type", "directory"),
            (0, "lstat_size", 10),
            (1, "target", "ld-linux-x86-64.so.2"),
            (1, "type", "regular-file"),
            (1, "lstat_size", 43),
        ):
            changed = copy.deepcopy(locked)
            changed["interpreter"]["usrmerge_chain"][index][field] = value
            variants.append(changed)
        extra_hop = copy.deepcopy(locked)
        extra_hop["interpreter"]["usrmerge_chain"].append(
            {"lstat_size": 1, "path": "/unexpected", "target": "x", "type": "symbolic-link"}
        )
        variants.append(extra_hop)
        wrong_resolved = copy.deepcopy(locked)
        wrong_resolved["interpreter"]["resolved_path"] = "/lib64/ld-linux-x86-64.so.2"
        variants.append(wrong_resolved)
        wrong_pt_interp = copy.deepcopy(locked)
        wrong_pt_interp["executable"]["interpreter"] = "/usr/lib64/ld-linux-x86-64.so.2"
        variants.append(wrong_pt_interp)
        wrong_argv = copy.deepcopy(locked)
        wrong_argv["execution"]["argv_prefix"][0] = "/lib64/ld-linux-x86-64.so.2"
        variants.append(wrong_argv)

        for index, runtime in enumerate(variants):
            with self.subTest(index=index):
                runner = mock.Mock(side_effect=AssertionError("runtime runner must not be reached"))
                with self.assertRaises(deploy.DeployError):
                    deploy._validate_runtime(runtime, runner)
                runner.assert_not_called()

    def test_usrmerge_writable_or_symlink_canonical_ancestor_fails_before_runner(self) -> None:
        runtime = json.loads((deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text())
        original_lstat = Path.lstat
        for replacement_mode in (stat.S_IFDIR | 0o775, stat.S_IFLNK | 0o777):
            def altered_lstat(path: Path, *, _mode: int = replacement_mode) -> os.stat_result:
                info = original_lstat(path)
                if path == Path("/usr/lib64"):
                    values = list(info)
                    values[0] = _mode
                    return os.stat_result(values)
                return info

            runner = mock.Mock(side_effect=AssertionError("runtime runner must not be reached"))
            with self.subTest(mode=oct(replacement_mode)), mock.patch.object(Path, "lstat", altered_lstat):
                with self.assertRaises(deploy.DeployError):
                    deploy._validate_runtime(runtime, runner)
            runner.assert_not_called()

    def test_usrmerge_alias_or_leaf_identity_drift_fails_before_runner(self) -> None:
        runtime = json.loads((deploy.REPO / "config/lmi-p2-d114/fastboot-wsl-runtime-lock.json").read_text())
        original_lstat = Path.lstat
        for drift_path in (
            Path("/lib64"),
            Path("/usr/lib64/ld-linux-x86-64.so.2"),
        ):
            observed = 0

            def drifting_lstat(path: Path) -> os.stat_result:
                nonlocal observed
                info = original_lstat(path)
                if path == drift_path:
                    observed += 1
                    if observed == 2:
                        values = list(info)
                        values[8] += 1
                        return os.stat_result(values)
                return info

            runner = mock.Mock(side_effect=AssertionError("runtime runner must not be reached"))
            with self.subTest(path=drift_path), mock.patch.object(Path, "lstat", drifting_lstat):
                with self.assertRaises(deploy.DeployError):
                    deploy._validate_runtime(runtime, runner)
            runner.assert_not_called()

    def test_non_interpreter_ancestor_symlink_remains_rejected(self) -> None:
        actual = self.fixture.root / "actual"
        actual.mkdir()
        ordinary = actual / "library.so"
        ordinary.write_bytes(b"ordinary-runtime-object")
        alias = self.fixture.root / "alias"
        alias.symlink_to(actual.name)
        runner = mock.Mock(side_effect=AssertionError("runner must not be reached"))
        with self.assertRaisesRegex(deploy.DeployError, "symlink or non-directory ancestor"):
            deploy._open_regular(alias / ordinary.name, self.fixture.root, "ordinary runtime library")
        runner.assert_not_called()

    def test_runtime_gate_precedes_opening_large_artifacts(self) -> None:
        source = (deploy.REPO / "scripts/lmi_p2_d114/deploy_userdata_wsl.py").read_text()
        function = source[source.index("def local_audit("):source.index("def _strict_devices(")]
        self.assertLess(
            function.index("argv_prefix, runtime_held = _validate_runtime"),
            function.index("candidate = _open_spec"),
        )

    def test_open_spec_accepts_exact_sparse_schema_only_when_explicit(self) -> None:
        rollback_path = self.fixture.root / "private" / "rollback.img"
        rollback_path.write_bytes(b"rollback")
        os.chmod(rollback_path, 0o600)
        specs = {
            "candidate": {
                "logical_size": 16,
                "path": "private/candidate.img",
                "representation": "android-sparse",
                "roundtrip_raw_sha256": "1" * 64,
                "sha256": hashlib.sha256(b"candidate").hexdigest(),
                "size": len(b"candidate"),
            },
            "rollback": {
                "logical_size": 16,
                "path": "private/rollback.img",
                "representation": "android-sparse",
                "roundtrip_raw_sha256": "2" * 64,
                "sha256": hashlib.sha256(b"rollback").hexdigest(),
                "size": len(b"rollback"),
            },
        }
        held: dict[str, deploy.HeldFile] = {}
        try:
            for name, spec in specs.items():
                item = deploy._open_spec(
                    spec, self.fixture.root, name, held, name, sparse=True,
                )
                self.assertEqual(item.sha256, spec["sha256"])
            plain = {key: specs["candidate"][key] for key in ("path", "sha256", "size")}
            item = deploy._open_spec(
                plain, self.fixture.root, "plain artifact", held, "plain",
            )
            self.assertEqual(item.sha256, plain["sha256"])
        finally:
            for item in reversed(tuple(held.values())):
                item.close()

        malformed = (
            {**specs["candidate"], "unexpected": False},
            {key: value for key, value in specs["rollback"].items() if key != "representation"},
        )
        for spec in malformed:
            with self.assertRaises(deploy.DeployError):
                deploy._open_spec(
                    spec, self.fixture.root, "sparse artifact", {}, "sparse", sparse=True,
                )
        with self.assertRaises(deploy.DeployError):
            deploy._open_spec(
                specs["candidate"], self.fixture.root, "plain artifact", {}, "plain",
            )

    def test_malformed_sparse_profile_refuses_before_any_runner_call(self) -> None:
        variants: list[dict[str, object]] = []
        extra = self.fixture.profile()
        candidate = extra["artifacts"]["candidate"]
        candidate["unexpected"] = False
        variants.append(extra)
        missing = self.fixture.profile()
        rollback = missing["artifacts"]["rollback"]
        del rollback["representation"]
        variants.append(missing)

        for index, profile in enumerate(variants):
            profile_path = self.fixture.path(f"malformed-profile-{index}.json")
            profile_path.write_bytes(canonical(profile))
            os.chmod(profile_path, 0o600)
            runner = FakeFastboot()
            with self.assertRaises(deploy.DeployError):
                deploy.local_audit(
                    profile_path, repo_root=self.fixture.root, process_runner=runner,
                )
            self.assertEqual(runner.calls, [])

    def test_linux_getvar_parser_accepts_only_exact_stderr_shapes(self) -> None:
        okay = deploy.CommandResult(0, b"", b"(bootloader) product: lmi\nFinished. Total time: 1.25s\n")
        self.assertEqual(deploy._strict_getvar("product", okay), ("lmi", False))
        unsupported = deploy.CommandResult(0, b"", b"getvar:is-logical:userdata   FAILED (remote: 'GetVar Variable Not found')\nFinished. Total time: 0.001s\n")
        self.assertEqual(deploy._strict_getvar("is-logical:userdata", unsupported, allow_unsupported=True), (None, True))
        for corrupt in (
            deploy.CommandResult(0, b"product: lmi\n", b"Finished. Total time: 0.1s\n"),
            deploy.CommandResult(0, b"", b"product: lmi\n"),
            deploy.CommandResult(0, b"", b"product: lmi\nFinished. Total time: 0.1s\nEXTRA\n"),
            deploy.CommandResult(0, b"", b"getvar:is-logical:userdata FAILED (remote: 'GetVar Variable Not found')\nFinished. Total time: 0.1s\n"),
        ):
            with self.assertRaises(deploy.DeployError):
                deploy._strict_getvar("product", corrupt)
        with self.assertRaises(deploy.DeployError):
            deploy._strict_getvar(
                "is-logical:userdata",
                deploy.CommandResult(1, b"", b"getvar:is-logical:userdata   FAILED (remote: 'GetVar Variable Not found')\nFinished. Total time: 0.1s\n"),
                allow_unsupported=True,
            )
        exact_unsupported = b"getvar:is-logical:userdata   FAILED (remote: 'GetVar Variable Not found')\nFinished. Total time: 0.1s\n"
        for corrupt in (
            b"getvar:is-logical:userdata   FAILED (remote: 'unknown variable')\nFinished. Total time: 0.1s\n",
            exact_unsupported + b"NOISE\n",
            exact_unsupported + exact_unsupported,
        ):
            with self.assertRaises(deploy.DeployError):
                deploy._strict_getvar(
                    "is-logical:userdata",
                    deploy.CommandResult(0, b"", corrupt),
                    allow_unsupported=True,
                )

    def test_partition_size_parser_accepts_canonical_and_observed_shapes_only(self) -> None:
        expected = deploy.PRODUCTION.userdata_capacity
        for value in ("0x1AC07FB000", " 0x1AC07FB000"):
            with self.subTest(value=value):
                self.assertEqual(
                    deploy._parse_integer(
                        value,
                        "partition size",
                        allow_one_leading_space=True,
                    ),
                    expected,
                )

        for value in (
            "\t0x1AC07FB000",
            "  0x1AC07FB000",
            "0x1AC07FB000 ",
            "+0x1AC07FB000",
            "-0x1AC07FB000",
            "",
            "garbage",
        ):
            with self.subTest(value=value), self.assertRaises(deploy.DeployError):
                deploy._parse_integer(
                    value,
                    "partition size",
                    allow_one_leading_space=True,
                )

        for value in (" 4373", " 805306368"):
            with self.subTest(value=value), self.assertRaises(deploy.DeployError):
                deploy._parse_integer(value, "non-partition integer")

    def test_malformed_partition_size_refuses_before_publication_or_write(self) -> None:
        malformed = (
            "\t0x1AC07FB000",
            "  0x1AC07FB000",
            "0x1AC07FB000 ",
            "+0x1AC07FB000",
            "-0x1AC07FB000",
            "",
            "garbage",
        )
        for value in malformed:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                runner = FakeFastboot(partition_size_value=value)
                with self.assertRaises(deploy.DeployError):
                    deploy.operate(
                        "deploy-once",
                        fixture.path("profile.json"),
                        fixture.path("execute.json"),
                        preflight_path=fixture.path("preflight.json"),
                        approval_path=fixture.path("approval.json"),
                        intent_path=fixture.path("intent.json"),
                        approved_operation="flash-userdata",
                        approved_sparse_sha256=deploy.PRODUCTION.sparse_sha256,
                        repo_root=fixture.root,
                        process_runner=runner,
                        audit_factory=lambda *_args, **_kwargs: fixture.audit(),
                        now_unix=1000,
                    )
                self.assertEqual(runner.write_calls, [])
                for name in ("preflight.json", "approval.json", "intent.json", "execute.json"):
                    self.assertFalse(fixture.path(name).exists())
                self.assertEqual(list((fixture.private / "claim-ledger").iterdir()), [])
                self.assertEqual(list((fixture.private / "attempt-ledger").iterdir()), [])

    def test_devices_parser_accepts_only_standard_or_observed_exact_shape(self) -> None:
        accepted = (
            f"{SERIAL}\tfastboot\n".encode("ascii"),
            f"{SERIAL}\tfastboot\r\n".encode("ascii"),
            f"{SERIAL}\t fastboot\n\n".encode("ascii"),
            f"{SERIAL}\t fastboot\r\n\r\n".encode("ascii"),
        )
        for stdout in accepted:
            with self.subTest(stdout=stdout):
                self.assertEqual(
                    deploy._strict_devices(deploy.CommandResult(0, stdout, b"")),
                    SERIAL,
                )

        rejected = (
            b"",
            f"{SERIAL}\tfastboot".encode("ascii"),
            f"{SERIAL}\tfastboot\nSECOND-SYNTHETIC\tfastboot\n".encode("ascii"),
            f" {SERIAL}\tfastboot\n".encode("ascii"),
            f"{SERIAL}\tfastboot\n\n".encode("ascii"),
            f"{SERIAL}\tfastboot \n".encode("ascii"),
            f"{SERIAL}\tfastboot \n\n".encode("ascii"),
            f"{SERIAL}\t  fastboot\n\n".encode("ascii"),
            f"{SERIAL}\t fastboot\n".encode("ascii"),
            f"{SERIAL}\tfastbootd\n".encode("ascii"),
            f"{SERIAL}  fastboot\n".encode("ascii"),
            f"{SERIAL}\t fastboot\r\n\n".encode("ascii"),
            f"{SERIAL}\tfastboot\nEXTRA\n".encode("ascii"),
        )
        for stdout in rejected:
            with self.subTest(stdout=stdout), self.assertRaises(deploy.DeployError):
                deploy._strict_devices(deploy.CommandResult(0, stdout, b""))

        for result in (
            deploy.CommandResult(1, accepted[0], b""),
            deploy.CommandResult(0, accepted[0], b"unexpected stderr"),
            deploy.CommandResult(0, b"synthetic\tfastboot\n\xff", b""),
            deploy.CommandResult(0, accepted[0], b"", timed_out=True),
            deploy.CommandResult(0, accepted[0], b"", output_limited=True),
            deploy.CommandResult(0, accepted[0], b"", started=False),
        ):
            with self.subTest(result=result), self.assertRaises(deploy.DeployError):
                deploy._strict_devices(result)

    def test_observed_devices_shape_passes_preflight_without_persisting_serial(self) -> None:
        runner = FakeFastboot(
            devices_stdout=f"{SERIAL}\t fastboot\n\n".encode("ascii"),
        )
        audit = self.fixture.audit()
        try:
            route, _digest = deploy.preflight(
                audit,
                self.fixture.path("observed-shape-preflight.json"),
                process_runner=runner,
                now_unix=1000,
            )
        finally:
            audit.close()
        self.assertEqual(route, deploy.PREFLIGHT_ROUTE)
        payload = self.fixture.path("observed-shape-preflight.json").read_bytes()
        self.assertNotIn(SERIAL.encode("ascii"), payload)

    def test_devices_shape_refusal_precedes_all_deploy_once_publication_and_write(self) -> None:
        runner = FakeFastboot(
            devices_stdout=f"{SERIAL}\t  fastboot\n\n".encode("ascii"),
        )
        with self.assertRaises(deploy.DeployError):
            deploy.operate(
                "deploy-once",
                self.fixture.path("profile.json"),
                self.fixture.path("execute.json"),
                preflight_path=self.fixture.path("preflight.json"),
                approval_path=self.fixture.path("approval.json"),
                intent_path=self.fixture.path("intent.json"),
                approved_operation="flash-userdata",
                approved_sparse_sha256=deploy.PRODUCTION.sparse_sha256,
                repo_root=self.fixture.root,
                process_runner=runner,
                audit_factory=lambda *_args, **_kwargs: self.fixture.audit(),
                now_unix=1000,
            )
        self.assertEqual(runner.write_calls, [])
        self.assertEqual([call[0][-1] for call in runner.calls], ["devices"])
        for name in ("preflight.json", "approval.json", "intent.json", "execute.json"):
            self.assertFalse(self.fixture.path(name).exists())
        self.assertEqual(list((self.fixture.private / "claim-ledger").iterdir()), [])
        self.assertEqual(list((self.fixture.private / "attempt-ledger").iterdir()), [])

    def test_transport_parser_rejects_partial_fraction_even_with_rc0_and_finished(self) -> None:
        partial = deploy.CommandResult(
            0,
            b"",
            b"Sending sparse 'userdata' 1/3 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  2.000s]\n"
            b"Finished. Total time: 3.000s\n",
        )
        self.assertFalse(deploy._transport_completed(partial))
        self.assertTrue(deploy._transport_completed(FakeFastboot().write_result))

    def test_preflight_uses_exact_fixed_read_only_queries_and_redacts_serial(self) -> None:
        audit = self.fixture.audit()
        runner = FakeFastboot()
        try:
            route, digest = deploy.preflight(audit, self.fixture.path("preflight.json"), process_runner=runner, now_unix=1000)
        finally:
            audit.close()
        self.assertEqual(route, deploy.PREFLIGHT_ROUTE)
        self.assertEqual(len(runner.calls), len(deploy.QUERY_NAMES))
        self.assertEqual(runner.write_calls, [])
        self.assertEqual([call[0][-1] if call[0][-1] == "devices" else f"getvar:{call[0][-1]}" for call in runner.calls], list(deploy.QUERY_NAMES))
        payload = self.fixture.path("preflight.json").read_bytes()
        self.assertNotIn(SERIAL.encode(), payload)
        self.assertNotIn(str(self.fixture.root).encode(), payload)
        self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)

    def _preflight_and_approval(self, runner: FakeFastboot, now: int = 1000, prefix: str = "") -> tuple[Path, str, Path, str]:
        preflight_path = self.fixture.path(f"{prefix}preflight.json")
        audit = self.fixture.audit()
        try:
            _route, preflight_sha = deploy.preflight(audit, preflight_path, process_runner=runner, now_unix=now)
        finally:
            audit.close()
        approval_path = self.fixture.path(f"{prefix}approval.json")
        audit = self.fixture.audit()
        try:
            _route, approval_sha = deploy.approve(audit, preflight_path, preflight_sha, approval_path, now_unix=now + 1)
        finally:
            audit.close()
        return preflight_path, preflight_sha, approval_path, approval_sha

    def test_approve_execute_consumes_claim_intent_first_and_passes_candidate_fd_once(self) -> None:
        runner = FakeFastboot()
        preflight_path, preflight_sha, approval_path, approval_sha = self._preflight_and_approval(runner)
        audit = self.fixture.audit()
        candidate_fd = audit.candidate.descriptor
        try:
            route, report_sha = deploy.execute(
                audit,
                preflight_path,
                preflight_sha,
                approval_path,
                approval_sha,
                self.fixture.consumed_path(approval_sha),
                self.fixture.path("intent.json"),
                self.fixture.path("execute.json"),
                process_runner=runner,
                clock=lambda: 1002,
            )
        finally:
            audit.close()
        self.assertEqual(route, deploy.COMPLETED_ROUTE)
        self.assertEqual(len(runner.write_calls), 1)
        argv, timeout, pass_fds, environment = runner.write_calls[0]
        self.assertEqual(argv[-3:], ("flash", "userdata", f"/proc/self/fd/{candidate_fd}"))
        self.assertEqual(argv[-4], SERIAL)
        self.assertEqual(timeout, 1800)
        self.assertEqual(pass_fds, (candidate_fd,))
        self.assertEqual(environment, deploy.SAFE_ENV)
        for path in (self.fixture.consumed_path(approval_sha), self.fixture.attempt_path(), self.fixture.path("intent.json"), self.fixture.path("execute.json")):
            payload = path.read_bytes()
            self.assertNotIn(SERIAL.encode(), payload)
            self.assertNotIn(str(self.fixture.root).encode(), payload)
        self.assertEqual(hashlib.sha256(self.fixture.path("execute.json").read_bytes()).hexdigest(), report_sha)

    def test_timeout_is_attempt_one_unknown_and_same_claim_cannot_retry(self) -> None:
        runner = FakeFastboot(write_result=deploy.CommandResult(-9, b"partial", b"", timed_out=True))
        preflight_path, preflight_sha, approval_path, approval_sha = self._preflight_and_approval(runner)
        audit = self.fixture.audit()
        try:
            route, _digest = deploy.execute(
                audit, preflight_path, preflight_sha, approval_path, approval_sha,
                self.fixture.consumed_path(approval_sha), self.fixture.path("intent.json"),
                self.fixture.path("execute.json"), process_runner=runner, clock=lambda: 1002,
            )
        finally:
            audit.close()
        self.assertEqual(route, deploy.UNKNOWN_ROUTE)
        report = json.loads(self.fixture.path("execute.json").read_text())
        self.assertEqual(report["result"]["attempts"], 1)
        self.assertTrue(report["result"]["timed_out"])
        self.assertEqual(len(runner.write_calls), 1)
        audit = self.fixture.audit()
        try:
            with self.assertRaises(deploy.DeployError):
                deploy.execute(
                    audit, preflight_path, preflight_sha, approval_path, approval_sha,
                    self.fixture.consumed_path(approval_sha), self.fixture.path("intent-2.json"),
                    self.fixture.path("execute-2.json"), process_runner=runner, clock=lambda: 1003,
                )
        finally:
            audit.close()
        self.assertEqual(len(runner.write_calls), 1)

    def test_stale_preflight_and_expired_approval_fail_before_consumption(self) -> None:
        runner = FakeFastboot()
        preflight_path, preflight_sha, approval_path, approval_sha = self._preflight_and_approval(runner)
        audit = self.fixture.audit()
        try:
            with self.assertRaises(deploy.DeployError):
                deploy.execute(
                    audit, preflight_path, preflight_sha, approval_path, approval_sha,
                    self.fixture.consumed_path(approval_sha), self.fixture.path("intent.json"),
                    self.fixture.path("execute.json"), process_runner=runner, clock=lambda: 1122,
                )
        finally:
            audit.close()
        self.assertFalse(self.fixture.consumed_path(approval_sha).exists())
        self.assertEqual(runner.write_calls, [])

    def test_completed_sparse_and_boot_claim_are_cross_rejected(self) -> None:
        completed = json.loads((deploy.REPO / "config/lmi-p2-d114/completed-userdata-actions-lock.json").read_text())
        with self.assertRaises(deploy.DeployError):
            deploy._validate_completed(completed, deploy.PRODUCTION, deploy.PRODUCTION.old_sparse_sha256)
        audit = self.fixture.audit()
        runner = FakeFastboot()
        try:
            device = deploy.query_device(audit, runner)
            binding = deploy._preflight_binding(audit, device)
            approval = {
                "authorization": {"approved": True, "automatic_retry": False, "claim_kind": "boot", "max_attempts": 1, "operation": "boot", "partition": "boot"},
                "binding": binding,
                "created_at_unix": 1000,
                "expires_at_unix": 1120,
                "ledger": {
                    "claim_consumption_directory": audit.profile["ledgers"]["claim_consumption"],
                    "consumed_filename_semantics": "<approval-sha256>.consumed.json",
                    "noreplace": True,
                },
                "preflight_sha256": "a" * 64,
                "schema": deploy.APPROVAL_SCHEMA,
            }
            with self.assertRaises(deploy.DeployError):
                deploy._validate_approval(approval, audit, "a" * 64, binding, 1001)
        finally:
            audit.close()

    def test_deploy_once_audits_once_publishes_all_evidence_and_writes_once(self) -> None:
        runner = FakeFastboot()
        audit_calls = 0

        def audit_factory(*_args: object, **_kwargs: object) -> deploy.Audit:
            nonlocal audit_calls
            audit_calls += 1
            return self.fixture.audit()

        route, _digest = deploy.operate(
            "deploy-once",
            self.fixture.path("unused-profile.json"),
            self.fixture.path("execute.json"),
            preflight_path=self.fixture.path("preflight.json"),
            approval_path=self.fixture.path("approval.json"),
            intent_path=self.fixture.path("intent.json"),
            approved_operation="flash-userdata",
            approved_sparse_sha256=deploy.PRODUCTION.sparse_sha256,
            repo_root=self.fixture.root,
            process_runner=runner,
            audit_factory=audit_factory,
            now_unix=1000,
        )
        self.assertEqual(route, deploy.COMPLETED_ROUTE)
        self.assertEqual(audit_calls, 1)
        self.assertEqual(len(runner.write_calls), 1)
        evidence = [self.fixture.path(name) for name in ("preflight.json", "approval.json", "intent.json", "execute.json")]
        evidence.extend((next((self.fixture.private / "claim-ledger").iterdir()), self.fixture.attempt_path()))
        for path in evidence:
            self.assertTrue(path.is_file())
            payload = path.read_bytes()
            self.assertNotIn(SERIAL.encode(), payload)
            if path.name == "execute.json":
                self.assertNotIn(b"flash-userdata", payload)

    def test_deploy_once_wrong_operation_or_hash_refuses_before_any_device_query(self) -> None:
        for operation, digest in (
            ("boot", deploy.PRODUCTION.sparse_sha256),
            ("flash-userdata", "0" * 64),
        ):
            runner = FakeFastboot()
            audit_calls = 0

            def audit_factory(*_args: object, **_kwargs: object) -> deploy.Audit:
                nonlocal audit_calls
                audit_calls += 1
                return self.fixture.audit()

            suffix = operation.replace("-", "_") + digest[:2]
            with self.assertRaises(deploy.DeployError):
                deploy.operate(
                    "deploy-once",
                    self.fixture.path("unused-profile.json"),
                    self.fixture.path(f"execute-{suffix}.json"),
                    preflight_path=self.fixture.path(f"preflight-{suffix}.json"),
                    approval_path=self.fixture.path(f"approval-{suffix}.json"),
                    intent_path=self.fixture.path(f"intent-{suffix}.json"),
                    approved_operation=operation,
                    approved_sparse_sha256=digest,
                    repo_root=self.fixture.root,
                    process_runner=runner,
                    audit_factory=audit_factory,
                    now_unix=1000,
                )
            self.assertEqual(audit_calls, 1)
            self.assertEqual(runner.calls, [])

    def test_deploy_once_rechecks_ttl_after_final_query_before_attempt_or_intent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Fixture(Path(temporary))
            runner = FakeFastboot()
            values = iter([1000, 1001, 1002, 1122])
            with self.assertRaises(deploy.DeployError):
                deploy.operate(
                    "deploy-once",
                    fixture.path("profile.json"),
                    fixture.path("execute.json"),
                    preflight_path=fixture.path("preflight.json"),
                    approval_path=fixture.path("approval.json"),
                    intent_path=fixture.path("intent.json"),
                    approved_operation="flash-userdata",
                    approved_sparse_sha256=deploy.PRODUCTION.sparse_sha256,
                    repo_root=fixture.root,
                    process_runner=runner,
                    audit_factory=lambda *_args, **_kwargs: fixture.audit(),
                    clock=lambda: next(values),
                )
            self.assertEqual(runner.write_calls, [])
            self.assertFalse(fixture.path("intent.json").exists())
            self.assertFalse(fixture.attempt_path().exists())

    def test_final_dynamic_values_may_change_but_must_stay_above_threshold(self) -> None:
        runner = FakeFastboot(battery_values=(4373, 4201))
        deploy.operate(
            "deploy-once",
            self.fixture.path("profile.json"),
            self.fixture.path("execute.json"),
            preflight_path=self.fixture.path("preflight.json"),
            approval_path=self.fixture.path("approval.json"),
            intent_path=self.fixture.path("intent.json"),
            approved_operation="flash-userdata",
            approved_sparse_sha256=deploy.PRODUCTION.sparse_sha256,
            repo_root=self.fixture.root,
            process_runner=runner,
            audit_factory=lambda *_args, **_kwargs: self.fixture.audit(),
            now_unix=1000,
        )
        report = json.loads(self.fixture.path("execute.json").read_text())
        self.assertEqual(report["result"]["device"]["battery_mv"], 4201)
        self.assertEqual(len(runner.write_calls), 1)

    def test_same_claim_alternate_consumed_path_and_new_claim_same_candidate_cannot_rewrite(self) -> None:
        runner = FakeFastboot()
        preflight, preflight_sha, approval, approval_sha = self._preflight_and_approval(runner)
        audit = self.fixture.audit()
        try:
            deploy.execute(
                audit, preflight, preflight_sha, approval, approval_sha,
                self.fixture.consumed_path(approval_sha), self.fixture.path("intent.json"),
                self.fixture.path("execute.json"), process_runner=runner, clock=lambda: 1002,
            )
        finally:
            audit.close()
        writes = len(runner.write_calls)
        audit = self.fixture.audit()
        try:
            with self.assertRaises(deploy.DeployError):
                deploy.execute(
                    audit, preflight, preflight_sha, approval, approval_sha,
                    self.fixture.path("alternate-consumed.json"), self.fixture.path("intent-alt.json"),
                    self.fixture.path("execute-alt.json"), process_runner=runner, clock=lambda: 1003,
                )
        finally:
            audit.close()
        _preflight2, preflight_sha2, approval2, approval_sha2 = self._preflight_and_approval(runner, now=1004, prefix="new-")
        audit = self.fixture.audit()
        try:
            with self.assertRaises(deploy.DeployError):
                deploy.execute(
                    audit, _preflight2, preflight_sha2, approval2, approval_sha2,
                    self.fixture.consumed_path(approval_sha2), self.fixture.path("intent-new.json"),
                    self.fixture.path("execute-new.json"), process_runner=runner, clock=lambda: 1006,
                )
        finally:
            audit.close()
        self.assertEqual(len(runner.write_calls), writes)
        self.assertFalse(self.fixture.consumed_path(approval_sha2).exists())

    def test_evidence_path_aliases_fail_before_audit_or_runner(self) -> None:
        names = ["preflight", "approval", "consumed", "intent", "report"]
        base = {name: self.fixture.path(f"{name}.json") for name in names}
        for left in range(len(names)):
            for right in range(left + 1, len(names)):
                paths = dict(base)
                paths[names[right]] = paths[names[left]]
                audit_calls = 0

                def audit_factory(*_args: object, **_kwargs: object) -> deploy.Audit:
                    nonlocal audit_calls
                    audit_calls += 1
                    return self.fixture.audit()

                runner = FakeFastboot()
                with self.assertRaises(deploy.DeployError):
                    deploy.operate(
                        "execute",
                        self.fixture.path("profile.json"),
                        paths["report"],
                        preflight_path=paths["preflight"],
                        preflight_sha256="1" * 64,
                        approval_path=paths["approval"],
                        approval_sha256="2" * 64,
                        consumed_path=paths["consumed"],
                        intent_path=paths["intent"],
                        repo_root=self.fixture.root,
                        process_runner=runner,
                        audit_factory=audit_factory,
                        now_unix=1000,
                    )
                self.assertEqual(audit_calls, 0)
                self.assertEqual(runner.calls, [])

    def test_runner_failures_publish_unknown_after_consumed_attempt_and_intent(self) -> None:
        variants: tuple[deploy.CommandResult | Exception, ...] = (
            RuntimeError("synthetic runner failure"),
            deploy.CommandResult(-9, b"", b"truncated", output_limited=True),
            deploy.CommandResult(None, b"", b"", started=False),
            deploy.CommandResult(0, b"", b"Finished. Total time: 1.000s\n"),
            deploy.CommandResult(1, b"", b"FAILED\n"),
        )
        for index, variant in enumerate(variants):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as temporary:
                fixture = Fixture(Path(temporary))
                preflight_runner = FakeFastboot()
                preflight = fixture.path("preflight.json")
                audit = fixture.audit()
                try:
                    _route, preflight_sha = deploy.preflight(audit, preflight, process_runner=preflight_runner, now_unix=1000)
                finally:
                    audit.close()
                approval = fixture.path("approval.json")
                audit = fixture.audit()
                try:
                    _route, approval_sha = deploy.approve(audit, preflight, preflight_sha, approval, now_unix=1001)
                finally:
                    audit.close()
                checked_order = False

                def on_write() -> None:
                    nonlocal checked_order
                    checked_order = (
                        fixture.consumed_path(approval_sha).is_file()
                        and fixture.attempt_path().is_file()
                        and fixture.path("intent.json").is_file()
                    )

                runner = FakeFastboot(write_result=variant, on_write=on_write)
                audit = fixture.audit()
                try:
                    route, _digest = deploy.execute(
                        audit, preflight, preflight_sha, approval, approval_sha,
                        fixture.consumed_path(approval_sha), fixture.path("intent.json"),
                        fixture.path("execute.json"), process_runner=runner, clock=lambda: 1002,
                    )
                finally:
                    audit.close()
                self.assertEqual(route, deploy.UNKNOWN_ROUTE, index)
                self.assertTrue(checked_order, index)
                report = json.loads(fixture.path("execute.json").read_text())
                self.assertEqual(report["result"]["attempts"], 1)
                self.assertFalse(report["result"]["transport_completed"])

    def test_atomic_ledgers_allow_only_one_concurrent_creator(self) -> None:
        for kind in ("claim", "attempt"):
            barrier = threading.Barrier(2)
            outcomes: list[str] = []

            def worker() -> None:
                audit = self.fixture.audit()
                try:
                    barrier.wait()
                    if kind == "claim":
                        deploy._consume_claim(audit, "f" * 64, self.fixture.consumed_path("f" * 64), 1000)
                    else:
                        deploy._publish_candidate_attempt(audit, "f" * 64, IDENTITY, 1000)
                except deploy.DeployError:
                    outcomes.append("refused")
                else:
                    outcomes.append("created")
                finally:
                    audit.close()

            threads = [threading.Thread(target=worker) for _ in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sorted(outcomes), ["created", "refused"])

    def test_static_process_contract_is_shell_free_bounded_and_group_reaped(self) -> None:
        source_path = deploy.REPO / "scripts/lmi_p2_d114/deploy_userdata_wsl.py"
        source = source_path.read_text()
        tree = ast.parse(source)
        popen_calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "Popen"]
        self.assertEqual(len(popen_calls), 1)
        keywords = {item.arg: item.value for item in popen_calls[0].keywords}
        self.assertIsInstance(keywords["shell"], ast.Constant)
        self.assertFalse(keywords["shell"].value)
        self.assertIsInstance(keywords["start_new_session"], ast.Constant)
        self.assertTrue(keywords["start_new_session"].value)
        self.assertIn("pass_fds=pass_fds", source)
        self.assertIn("os.killpg", source)
        self.assertIn("/proc/self/fd/", source)
        self.assertNotIn("fastbootd", " ".join(deploy._parser()._actions[-1].choices or ()))


if __name__ == "__main__":
    unittest.main()
