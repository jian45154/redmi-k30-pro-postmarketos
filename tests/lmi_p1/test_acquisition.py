from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1_cli as cli
import scripts.lmi_p1.acquisition as acquisition
from scripts.lmi_p1.acquisition import (
    CuratedAcquisition,
    curate_offline_cache_acquisition,
)
from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.offline_cache import canonical_json_bytes


REPOSITORIES = (
    "http://dl-cdn.alpinelinux.org/alpine/edge/community",
    "http://dl-cdn.alpinelinux.org/alpine/edge/main",
    "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
    "http://mirror.postmarketos.org/postmarketos/main",
)


def _tar(entries: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in entries:
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            member.mode = 0o644
            member.uid = member.gid = member.mtime = 0
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _gzip(payload: bytes) -> bytes:
    return gzip.compress(payload, compresslevel=9, mtime=0)


def _apk(
    name: str,
    version: str,
    architecture: str,
    signer: str,
    *,
    extra_pkginfo: bytes = b"",
) -> tuple[bytes, bytes]:
    signature = _gzip(_tar([(f".SIGN.RSA.{signer}", b"fixture signature")]))
    pkginfo = (
        f"pkgname = {name}\npkgver = {version}\narch = {architecture}\n".encode()
        + extra_pkginfo
    )
    control = _gzip(_tar([(".PKGINFO", pkginfo)]))
    data = _gzip(_tar([("usr/share/fixture", f"{name}\n".encode())]))
    return signature + control + data, hashlib.sha1(
        control, usedforsecurity=False
    ).digest()


def _q1(checksum: bytes) -> str:
    import base64

    return "Q1" + base64.b64encode(checksum).decode("ascii")


def _index(
    signer: str,
    packages: list[tuple[str, str, str, int, bytes]],
) -> bytes:
    blocks = []
    for name, version, architecture, size, checksum in packages:
        blocks.append(
            f"C:{_q1(checksum)}\nP:{name}\nV:{version}\n"
            f"A:{architecture}\nS:{size}\n"
        )
    index_text = "\n".join(blocks).encode("utf-8")
    return _gzip(
        _tar(
            [
                (f".SIGN.RSA.{signer}", b"fixture index signature"),
                ("DESCRIPTION", b"fixture\n"),
                ("APKINDEX", index_text),
            ]
        )
    )


class AcquisitionFixture:
    def __init__(self, root: Path):
        self.root = root
        self.source = root / "source"
        self.source.mkdir(mode=0o700)
        self.work = self.source / "work-proot-chroot2"
        for name in (
            "cache_apk_aarch64",
            "cache_apk_x86_64",
            "cache_http",
            "cache_distfiles",
        ):
            (self.work / name).mkdir(parents=True, mode=0o755)
        self.arm_closure = self.source / "fetched-aarch64-closure"
        self.x86_closure = self.source / "fetched-x86_64-closure"
        self.arm_closure.mkdir(mode=0o755)
        self.x86_closure.mkdir(mode=0o755)

        self.signers = {
            "aarch64": "alpine-devel@lists.alpinelinux.org-616ae350.rsa.pub",
            "x86_64": "alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub",
        }
        self.pmos_signer = "build.postmarketos.org.rsa.pub"
        self.arm_apk, self.arm_checksum = _apk(
            "fixture-arm", "1.2-r3", "noarch", self.signers["aarch64"]
        )
        self.x86_apk, self.x86_checksum = _apk(
            "fixture-host", "4.5-r6", "x86_64", self.signers["x86_64"]
        )
        self.http_apk, self.http_checksum = _apk(
            "apk-tools-static", "3.0.6-r0", "x86_64", self.signers["x86_64"]
        )
        (self.arm_closure / "fixture-arm-1.2-r3.apk").write_bytes(self.arm_apk)
        (self.x86_closure / "fixture-host-4.5-r6.apk").write_bytes(self.x86_apk)

        exclusions = (
            ("device-xiaomi-lmi", "1-r107", "aarch64"),
            ("linux-xiaomi-lmi", "4.19.325-r8", "aarch64"),
            ("postmarketos-initramfs", "3.12.0-r0", "aarch64"),
        )
        self.exclusion_packages = {}
        for name, version, architecture in exclusions:
            signer = (
                self.pmos_signer
                if name == "postmarketos-initramfs"
                else "lmi-local.rsa.pub"
            )
            payload, checksum = _apk(name, version, architecture, signer)
            (self.arm_closure / f"{name}-{version}.apk").write_bytes(payload)
            self.exclusion_packages[name] = (payload, checksum)

        repositories = []
        for architecture in ("aarch64", "x86_64"):
            for number, url in enumerate(REPOSITORIES):
                signer = self.pmos_signer if "postmarketos.org" in url else self.signers[architecture]
                packages: list[tuple[str, str, str, int, bytes]] = []
                if architecture == "aarch64" and url.endswith("community"):
                    packages.append(
                        (
                            "fixture-arm",
                            "1.2-r3",
                            "aarch64",
                            len(self.arm_apk),
                            self.arm_checksum,
                        )
                    )
                if architecture == "aarch64" and "postmarketos.org" in url:
                    payload, checksum = self.exclusion_packages["postmarketos-initramfs"]
                    packages.append(
                        (
                            "postmarketos-initramfs",
                            "3.12.0-r0",
                            "aarch64",
                            len(payload),
                            checksum,
                        )
                    )
                if architecture == "x86_64" and url.endswith("community"):
                    packages.append(
                        (
                            "fixture-host",
                            "4.5-r6",
                            "x86_64",
                            len(self.x86_apk),
                            self.x86_checksum,
                        )
                    )
                if architecture == "x86_64" and url.endswith("main") and "alpinelinux" in url:
                    packages.append(
                        (
                            "apk-tools-static",
                            "3.0.6-r0",
                            "x86_64",
                            len(self.http_apk),
                            self.http_checksum,
                        )
                    )
                dummy, dummy_checksum = _apk(
                    f"index-only-{architecture}-{number}",
                    "1-r0",
                    architecture,
                    signer,
                )
                packages.append(
                    (
                        f"index-only-{architecture}-{number}",
                        "1-r0",
                        architecture,
                        len(dummy),
                        dummy_checksum,
                    )
                )
                index_payload = _index(signer, packages)
                index_suffix = hashlib.sha1(
                    url.encode(), usedforsecurity=False
                ).hexdigest()[:8]
                index_path = self.work / f"cache_apk_{architecture}/APKINDEX.{index_suffix}.tar.gz"
                index_path.write_bytes(index_payload)
                signer_path = f"work/cache_apk_{architecture}/{signer}"
                signer_payload = f"fixture key {signer}\n".encode()
                repositories.append(
                    {
                        "architecture": architecture,
                        "index_path": f"work/cache_apk_{architecture}/{index_path.name}",
                        "index_sha256": hashlib.sha256(index_payload).hexdigest(),
                        "index_size": len(index_payload),
                        "signer_key_path": signer_path,
                        "signer_key_sha256": hashlib.sha256(signer_payload).hexdigest(),
                        "url": url,
                    }
                )

        http_name = (
            "apk-tools-static-3.0.6-r0.apk_"
            "f0b8bf03fd823a64c20575ac2e1285dd2ffd1708e98fcb8e5ff18d8ea418564e"
        )
        (self.work / "cache_http" / http_name).write_bytes(self.http_apk)
        dist_payload = b"fixture kernel source archive\n"
        dist_name = "linux-xiaomi-lmi-a5b3099017ae581aae8bf597b2f9c8c765026af1.tar.gz"
        (self.work / "cache_distfiles" / dist_name).write_bytes(dist_payload)

        x86_signer_payload = f"fixture key {self.signers['x86_64']}\n".encode()
        self.profile = {
            "distfiles": [
                {
                    "apkbuild_sha512": "a" * 128,
                    "path": f"work/cache_distfiles/{dist_name}",
                    "sha256": hashlib.sha256(dist_payload).hexdigest(),
                    "size": len(dist_payload),
                    "url": (
                        "https://github.com/LineageOS/android_kernel_xiaomi_sm8250/"
                        "archive/a5b3099017ae581aae8bf597b2f9c8c765026af1.tar.gz"
                    ),
                }
            ],
            "http_artifacts": [
                {
                    "kind": "apk-tools-static",
                    "name": "apk-tools-static",
                    "path": f"work/cache_http/{http_name}",
                    "sha256": hashlib.sha256(self.http_apk).hexdigest(),
                    "signer_key_path": (
                        "work/cache_apk_x86_64/"
                        f"{self.signers['x86_64']}"
                    ),
                    "signer_key_sha256": hashlib.sha256(x86_signer_payload).hexdigest(),
                    "size": len(self.http_apk),
                    "url": (
                        "http://dl-cdn.alpinelinux.org/alpine/edge/main/x86_64/"
                        "apk-tools-static-3.0.6-r0.apk"
                    ),
                    "version": "3.0.6-r0",
                }
            ],
            "pins": {
                "pmaports": {
                    "channel": "edge",
                    "commit": "1" * 40,
                    "tree": "2" * 40,
                },
                "pmbootstrap": {
                    "commit": "3" * 40,
                    "version": "3.11.1",
                    "work_version": 8,
                },
            },
            "repositories": sorted(
                repositories, key=lambda item: (item["architecture"], item["url"])
            ),
            "schema": "lmi-p1-offline-cache-promotion/v1",
        }
        self.profile_path = root / "promotion.json"
        self.write_profile()

    def write_profile(self, *, canonical: bool = True) -> None:
        if canonical:
            self.profile_path.write_bytes(canonical_json_bytes(self.profile))
        else:
            self.profile_path.write_text(json.dumps(self.profile, indent=2) + "\n")


class AcquisitionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.fixture = AcquisitionFixture(self.root)
        self.output = self.root / "curated"

    def curate(self, output: Path | None = None) -> CuratedAcquisition:
        return curate_offline_cache_acquisition(
            self.fixture.source,
            self.output if output is None else output,
            self.fixture.profile_path,
        )

    def test_curates_exact_promotion_layout_and_is_reproducible(self) -> None:
        result = self.curate()
        self.assertEqual(
            sorted(path.name for path in self.output.iterdir()),
            [
                "cache_apk_aarch64",
                "cache_apk_x86_64",
                "cache_distfiles",
                "cache_http",
                "version",
            ],
        )
        self.assertFalse((self.output / "offline-cache.manifest.json").exists())
        self.assertEqual((self.output / "version").read_bytes(), b"8\n")
        arm_name = f"fixture-arm-1.2-r3.{self.fixture.arm_checksum.hex()[:8]}.apk"
        x86_name = f"fixture-host-4.5-r6.{self.fixture.x86_checksum.hex()[:8]}.apk"
        self.assertEqual(
            (self.output / "cache_apk_aarch64" / arm_name).read_bytes(),
            self.fixture.arm_apk,
        )
        self.assertEqual(
            (self.output / "cache_apk_x86_64" / x86_name).read_bytes(),
            self.fixture.x86_apk,
        )
        self.assertEqual(result.aarch64_packages, 1)
        self.assertEqual(result.x86_64_packages, 1)
        self.assertEqual(
            result.excluded_aarch64_packages,
            (
                "device-xiaomi-lmi-1-r107",
                "linux-xiaomi-lmi-4.19.325-r8",
                "postmarketos-initramfs-3.12.0-r0",
            ),
        )
        for excluded in result.excluded_aarch64_packages:
            self.assertFalse(any(path.name.startswith(excluded) for path in self.output.rglob("*.apk")))
        for path in self.output.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)

        second = self.curate(self.root / "curated-second")
        self.assertEqual(result.inventory_sha256, second.inventory_sha256)

    def test_missing_x86_closure_evidence_fails_before_output(self) -> None:
        for path in self.fixture.x86_closure.iterdir():
            path.unlink()
        self.fixture.x86_closure.rmdir()
        with self.assertRaisesRegex(
            GateError,
            r"missing exact closure evidence: x86_64 APK closure directory "
            r"\(fetched-x86_64-closure\)",
        ):
            self.curate()
        self.assertFalse(self.output.exists())

    def test_lists_each_missing_closure_evidence_category(self) -> None:
        for directory in (self.fixture.arm_closure, self.fixture.x86_closure):
            for path in directory.iterdir():
                path.unlink()
            directory.rmdir()
        with self.assertRaises(GateError) as caught:
            self.curate()
        message = str(caught.exception)
        self.assertIn("aarch64 APK closure directory (fetched-aarch64-closure)", message)
        self.assertIn("x86_64 APK closure directory (fetched-x86_64-closure)", message)
        self.assertFalse(self.output.exists())

    def test_rejects_noncanonical_profile_before_output(self) -> None:
        self.fixture.write_profile(canonical=False)
        with self.assertRaisesRegex(GateError, "not canonical"):
            self.curate()
        self.assertFalse(self.output.exists())

    def test_rejects_closure_checksum_not_bound_to_c_q1(self) -> None:
        changed, _checksum = _apk(
            "fixture-arm",
            "1.2-r3",
            "aarch64",
            self.fixture.signers["aarch64"],
            extra_pkginfo=b"license = fixture\n",
        )
        (self.fixture.arm_closure / "fixture-arm-1.2-r3.apk").write_bytes(changed)
        with self.assertRaisesRegex(GateError, "C:Q1"):
            self.curate()
        self.assertFalse(self.output.exists())

    def test_accepts_arbitrary_builder_signer_when_index_identity_still_matches(self) -> None:
        wrong_signer = "alpine-devel@lists.alpinelinux.org-616ae351.rsa.pub"
        changed, checksum = _apk(
            "fixture-arm", "1.2-r3", "noarch", wrong_signer
        )
        self.assertEqual(checksum, self.fixture.arm_checksum)
        self.assertEqual(len(changed), len(self.fixture.arm_apk))
        (self.fixture.arm_closure / "fixture-arm-1.2-r3.apk").write_bytes(changed)

        result = self.curate()

        self.assertEqual(result.aarch64_packages, 1)
        self.assertTrue(
            any(
                path.name.startswith("fixture-arm-1.2-r3.")
                for path in (self.output / "cache_apk_aarch64").glob("*.apk")
            )
        )

    def test_rejects_unindexed_extra_missing_duplicate_and_unsafe_entries(self) -> None:
        cases = (
            "extra",
            "unindexed",
            "hardlink",
            "symlink",
            "writable",
            "directory_writable",
        )
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = AcquisitionFixture(Path(temporary))
                    output = Path(temporary) / "out"
                    target = fixture.x86_closure / "fixture-host-4.5-r6.apk"
                    if case == "extra":
                        (fixture.x86_closure / "README").write_text("not an APK\n")
                    elif case == "unindexed":
                        payload, _checksum = _apk(
                            "not-indexed", "1-r0", "x86_64", fixture.signers["x86_64"]
                        )
                        (fixture.x86_closure / "not-indexed-1-r0.apk").write_bytes(payload)
                    elif case == "hardlink":
                        duplicate = fixture.x86_closure / "hardlink-1-r0.apk"
                        os.link(target, duplicate)
                    elif case == "symlink":
                        target.unlink()
                        target.symlink_to(fixture.profile_path)
                    elif case == "writable":
                        target.chmod(0o666)
                    else:
                        (fixture.work / "cache_distfiles").chmod(0o775)
                    with self.assertRaises(GateError):
                        curate_offline_cache_acquisition(
                            fixture.source, output, fixture.profile_path
                        )
                    self.assertFalse(output.exists())

    def test_rejects_pinned_index_http_distfile_tamper_and_existing_output(self) -> None:
        records = (
            self.fixture.profile["repositories"][0],
            self.fixture.profile["http_artifacts"][0],
            self.fixture.profile["distfiles"][0],
        )
        for record in records:
            record_path = record.get("path", record.get("index_path"))
            with self.subTest(path=record_path):
                with tempfile.TemporaryDirectory() as temporary:
                    fixture = AcquisitionFixture(Path(temporary))
                    matching = next(
                        item
                        for group in (
                            fixture.profile["repositories"],
                            fixture.profile["http_artifacts"],
                            fixture.profile["distfiles"],
                        )
                        for item in group
                        if item.get("path", item.get("index_path")) == record_path
                    )
                    relative = Path(
                        matching.get("path", matching.get("index_path"))
                    ).relative_to("work")
                    path = fixture.work / relative
                    path.write_bytes(path.read_bytes() + b"tamper")
                    with self.assertRaisesRegex(GateError, "size/SHA-256 mismatch"):
                        curate_offline_cache_acquisition(
                            fixture.source,
                            Path(temporary) / "out",
                            fixture.profile_path,
                        )

        self.output.mkdir()
        with self.assertRaisesRegex(GateError, "new absent path"):
            self.curate()

    def test_rejects_source_change_between_validation_and_copy(self) -> None:
        target = self.fixture.x86_closure / "fixture-host-4.5-r6.apk"
        original_prepare = acquisition._prepare_output

        def mutate_then_prepare(output, *, expected_uid, expected_gid):
            target.write_bytes(target.read_bytes() + b"changed-after-validation")
            return original_prepare(
                output, expected_uid=expected_uid, expected_gid=expected_gid
            )

        with mock.patch.object(
            acquisition, "_prepare_output", side_effect=mutate_then_prepare
        ), self.assertRaisesRegex(GateError, "changed before copying"):
            self.curate()
        self.assertFalse(self.output.exists())
        self.assertEqual(
            list(self.output.parent.glob(f".{self.output.name}.curation-*")), []
        )

    def test_cli_routes_only_explicit_curation_paths(self) -> None:
        result = CuratedAcquisition(
            root=self.output,
            aarch64_packages=10,
            x86_64_packages=20,
            excluded_aarch64_packages=("device-xiaomi-lmi-1-r107",),
            members=39,
            inventory_sha256="a" * 64,
        )
        output = io.StringIO()
        argv = [
            "curate-offline-cache",
            "--profile",
            str(self.fixture.profile_path),
            "--acquisition-root",
            str(self.fixture.source),
            "--output",
            str(self.output),
        ]
        with mock.patch.object(
            cli, "curate_offline_cache_acquisition", return_value=result
        ) as curate, redirect_stdout(output):
            self.assertEqual(cli.main(argv), 0)
        curate.assert_called_once_with(
            self.fixture.source, self.output, self.fixture.profile_path
        )
        self.assertEqual(json.loads(output.getvalue())["inventory_sha256"], "a" * 64)

    def test_cli_failure_rejects_malformed_builder_signer_without_local_key_bytes(self) -> None:
        wrong_signer = "malformed/nested-builder.rsa.pub"
        changed, _checksum = _apk(
            "fixture-arm", "1.2-r3", "noarch", wrong_signer
        )
        (self.fixture.arm_closure / "fixture-arm-1.2-r3.apk").write_bytes(changed)
        stderr = io.StringIO()
        argv = [
            "curate-offline-cache",
            "--profile",
            str(self.fixture.profile_path),
            "--acquisition-root",
            str(self.fixture.source),
            "--output",
            str(self.output),
        ]
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as caught:
            cli.main(argv)
        self.assertEqual(caught.exception.code, 1)
        rendered = stderr.getvalue()
        self.assertIn("ambiguous signature member", rendered)
        self.assertNotIn("fixture key", rendered)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
