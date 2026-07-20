from __future__ import annotations

import copy
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock
import zlib

from scripts.lmi_p1.common import GateError
import scripts.lmi_p1.offline_cache as offline_cache_module
from scripts.lmi_p1.offline_cache import (
    MANIFEST_NAME,
    MANIFEST_SCHEMA,
    PROMOTION_PROFILE_SCHEMA,
    PRODUCTION_REPOSITORY_URLS,
    ApkStaticBootstrapPins,
    IndexedPackage,
    OpenSslRuntimePins,
    PackageIdentity,
    PinnedApkStaticVerifier,
    PromotionAuthorization,
    RuntimeClosureMember,
    VerifiedIndex,
    VerifiedPackage,
    aggregate_sha256,
    bootstrap_apk_static_verifier,
    canonical_json_bytes,
    load_promotion_profile,
    promote_offline_cache,
    read_offline_cache_manifest,
    validate_promotion_profile,
)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def index_name(url: str) -> str:
    digest = hashlib.sha1(url.encode("utf-8"), usedforsecurity=False).hexdigest()
    return f"APKINDEX.{digest[:8]}.tar.gz"


def write_tar(path: Path, members: list[tuple[str, bytes]], *, gzip: bool = True):
    with tarfile.open(path, "w:gz" if gzip else "w") as archive:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    path.chmod(0o600)


def tar_bytes(members: list[tuple[str, bytes]]) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, payload in members:
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return output.getvalue()


def v2_apk_payload(
    identity: PackageIdentity,
    builder_signer: str,
    *,
    data_members: list[tuple[str, bytes]] | None = None,
) -> tuple[bytes, str]:
    if data_members is None:
        data_members = [("usr/share/fixture", f"{identity.name}\n".encode())]
    signature = gzip.compress(
        tar_bytes([(f".SIGN.RSA.{builder_signer}", b"fixture signature")]),
        mtime=0,
    )
    data = gzip.compress(tar_bytes(data_members), mtime=0)
    pkginfo = (
        f"pkgname = {identity.name}\n"
        f"pkgver = {identity.version}\n"
        f"arch = {identity.architecture}\n"
        f"datahash = {hashlib.sha256(data).hexdigest()}\n"
    ).encode("ascii")
    control = gzip.compress(tar_bytes([(".PKGINFO", pkginfo)]), mtime=0)
    checksum = "Q1" + base64.b64encode(
        hashlib.sha1(control, usedforsecurity=False).digest()
    ).decode("ascii")
    return signature + control + data, checksum


def _split_first_gzip_member(payload: bytes) -> tuple[bytes, bytes]:
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    decompressor.decompress(payload)
    consumed = len(payload) - len(decompressor.unused_data)
    return payload[:consumed], payload[consumed:]


class FixtureVerifier:
    """Deterministic signature-verifier stand-in; it never trusts filenames."""

    def __init__(self, index_packages):
        self.index_packages = index_packages
        self.index_calls = []
        self.package_calls = []

    def verify_index(
        self,
        index_path,
        *,
        repository_url,
        architecture,
        signer_key_path,
        trusted_key_root,
    ):
        expected = (
            f"signed-index:{architecture}:{repository_url}:{signer_key_path}\n"
        ).encode("ascii")
        if index_path.read_bytes() != expected:
            raise GateError("fixture index signature failed")
        key = trusted_key_root.joinpath(*Path(signer_key_path).parts)
        if not key.is_file():
            raise GateError("fixture index key is absent")
        self.index_calls.append((repository_url, architecture, signer_key_path))
        return VerifiedIndex(
            architecture,
            tuple(self.index_packages.get((architecture, repository_url), ())),
        )

    def verify_package(
        self,
        package_path,
        *,
        expected_cache_architecture,
        allowed_signer_key_paths,
        trusted_key_root,
    ):
        try:
            marker, name, version, architecture, signer = (
                package_path.read_text(encoding="ascii").rstrip("\n").split("|")
            )
        except (OSError, UnicodeError, ValueError) as error:
            raise GateError(f"fixture APK signature failed: {error}") from None
        if marker != "signed-apk" or signer not in allowed_signer_key_paths:
            raise GateError("fixture APK signature failed")
        if not trusted_key_root.joinpath(*Path(signer).parts).is_file():
            raise GateError("fixture APK key is absent")
        self.package_calls.append((name, version, architecture, signer))
        return VerifiedPackage(PackageIdentity(name, version, architecture), signer)


class OfflineCacheTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.acquisition = self.root / "acquisition"
        self.acquisition.mkdir(mode=0o700)
        for directory in (
            "cache_apk_aarch64",
            "cache_apk_x86_64",
            "cache_http",
            "cache_distfiles",
        ):
            (self.acquisition / directory).mkdir(mode=0o700)
        (self.acquisition / "version").write_bytes(b"8\n")
        (self.acquisition / "version").chmod(0o600)

        self.pmbootstrap = self.root / "pmbootstrap"
        key_dir = self.pmbootstrap / "pmb/data/keys"
        key_dir.mkdir(parents=True, mode=0o700)
        self.key_payloads = {
            "alpine-test.rsa.pub": b"synthetic alpine public key\n",
            "pmos-test.rsa.pub": b"synthetic postmarketOS public key\n",
        }
        for name, payload in self.key_payloads.items():
            path = key_dir / name
            path.write_bytes(payload)
            path.chmod(0o600)

        repositories = []
        self.index_packages = {}
        for architecture in ("aarch64", "x86_64"):
            for url in sorted(PRODUCTION_REPOSITORY_URLS):
                key_name = (
                    "pmos-test.rsa.pub" if "postmarketos.org" in url else "alpine-test.rsa.pub"
                )
                signer_path = f"work/cache_apk_{architecture}/{key_name}"
                payload = f"signed-index:{architecture}:{url}:{signer_path}\n".encode(
                    "ascii"
                )
                relative = f"work/cache_apk_{architecture}/{index_name(url)}"
                source = self.acquisition.joinpath(*Path(relative).parts[1:])
                source.write_bytes(payload)
                source.chmod(0o600)
                repositories.append(
                    {
                        "architecture": architecture,
                        "url": url,
                        "index_path": relative,
                        "index_size": len(payload),
                        "index_sha256": sha256(payload),
                        "signer_key_path": signer_path,
                        "signer_key_sha256": sha256(self.key_payloads[key_name]),
                    }
                )

        alpine_main = "http://dl-cdn.alpinelinux.org/alpine/edge/main"
        x86_identity = PackageIdentity("fixture-x86", "1.2.3-r4", "x86_64")
        arm_identity = PackageIdentity("fixture-noarch", "5.6-r0", "noarch")
        x86_indexed = self._write_apk(
            "cache_apk_x86_64/opaque-cache-name.apk",
            x86_identity,
            "pmos@local-fixture-x86.rsa.pub",
        )
        arm_indexed = self._write_apk(
            "cache_apk_aarch64/another-opaque-name.apk",
            arm_identity,
            "pmos@local-fixture-arm.rsa.pub",
        )
        self.index_packages[("x86_64", alpine_main)] = (x86_indexed,)
        self.index_packages[("aarch64", alpine_main)] = (arm_indexed,)

        http_name = "apk-tools-static-3.0.6-r0.apk_fixture"
        http_relative = f"work/cache_http/{http_name}"
        http_identity = PackageIdentity("apk-tools-static", "3.0.6-r0", "x86_64")
        http_signer = "work/cache_apk_x86_64/alpine-test.rsa.pub"
        http_payload = (
            f"signed-apk|{http_identity.name}|{http_identity.version}|"
            f"{http_identity.architecture}|{http_signer}\n"
        ).encode("ascii")
        http_path = self.acquisition / "cache_http" / http_name
        http_path.write_bytes(http_payload)
        http_path.chmod(0o600)

        dist_name = "linux-xiaomi-lmi-fixture.tar.gz"
        dist_payload = b"synthetic pinned kernel distfile\x00\n"
        dist_path = self.acquisition / "cache_distfiles" / dist_name
        dist_path.write_bytes(dist_payload)
        dist_path.chmod(0o600)

        self.profile_mapping = {
            "schema": PROMOTION_PROFILE_SCHEMA,
            "pins": {
                "pmbootstrap": {
                    "commit": "1" * 40,
                    "version": "3.11.1",
                    "work_version": 8,
                },
                "pmaports": {
                    "commit": "2" * 40,
                    "tree": "3" * 40,
                    "channel": "edge",
                },
            },
            "repositories": sorted(
                repositories, key=lambda item: (item["architecture"], item["url"])
            ),
            "http_artifacts": [
                {
                    "kind": "apk-tools-static",
                    "name": "apk-tools-static",
                    "version": "3.0.6-r0",
                    "url": f"https://dl.example.invalid/{http_name}",
                    "path": http_relative,
                    "size": len(http_payload),
                    "sha256": sha256(http_payload),
                    "signer_key_path": http_signer,
                    "signer_key_sha256": sha256(
                        self.key_payloads["alpine-test.rsa.pub"]
                    ),
                }
            ],
            "distfiles": [
                {
                    "url": f"https://github.com/example/kernel/archive/{dist_name}",
                    "path": f"work/cache_distfiles/{dist_name}",
                    "size": len(dist_payload),
                    "sha256": sha256(dist_payload),
                    "apkbuild_sha512": "a" * 128,
                }
            ],
        }
        self.profile = validate_promotion_profile(self.profile_mapping)
        self.verifier = FixtureVerifier(self.index_packages)
        self.quarantine = self.root / ".cache.quarantine"
        self.published = self.root / "offline-cache"

    @staticmethod
    def _apk_payload(identity: PackageIdentity, signer: str) -> bytes:
        return v2_apk_payload(identity, signer)[0]

    def _write_apk(self, relative: str, identity: PackageIdentity, signer: str):
        path = self.acquisition / relative
        payload, checksum = v2_apk_payload(identity, signer)
        path.write_bytes(payload)
        path.chmod(0o600)
        return IndexedPackage(identity, len(payload), checksum)

    def promote(self):
        return promote_offline_cache(
            self.acquisition,
            self.quarantine,
            self.published,
            self.profile,
            trusted_key_root=self.pmbootstrap,
            verifier=self.verifier,
        )

    def test_promotes_only_after_signature_binding_and_emits_exact_manifest(self):
        result = self.promote()

        self.assertEqual(result.root, self.published)
        self.assertFalse(self.quarantine.exists())
        self.assertEqual(oct(self.published.stat().st_mode & 0o777), "0o700")
        manifest_path = self.published / MANIFEST_NAME
        manifest = json.loads(manifest_path.read_bytes())
        self.assertEqual(manifest_path.read_bytes(), canonical_json_bytes(manifest))
        self.assertEqual(manifest["schema"], MANIFEST_SCHEMA)
        self.assertEqual(set(manifest), {
            "schema", "pins", "repositories", "external_apks",
            "http_artifacts", "distfiles", "members", "aggregate_sha256",
        })
        self.assertEqual(manifest["aggregate_sha256"], aggregate_sha256(manifest))
        self.assertEqual(result.manifest_sha256, sha256(manifest_path.read_bytes()))
        self.assertEqual(len(self.verifier.index_calls), 8)
        # Only the independently pinned HTTP bootstrap APK uses standalone
        # package-signature verification. Repository APKs bind to verified
        # APKINDEX identity records.
        self.assertEqual(len(self.verifier.package_calls), 1)
        by_name = {item["name"]: item for item in manifest["external_apks"]}
        self.assertEqual(by_name["fixture-noarch"]["architecture"], "aarch64")
        self.assertEqual(
            by_name["fixture-noarch"]["builder_signer"],
            "pmos@local-fixture-arm.rsa.pub",
        )
        self.assertEqual(
            by_name["fixture-noarch"]["index_signer_key_path"],
            "work/cache_apk_aarch64/alpine-test.rsa.pub",
        )
        self.assertEqual(
            by_name["fixture-x86"]["repository_url"],
            "http://dl-cdn.alpinelinux.org/alpine/edge/main",
        )
        member_paths = {item["path"] for item in manifest["members"]}
        self.assertIn("work/cache_apk_aarch64/alpine-test.rsa.pub", member_paths)
        self.assertIn("work/cache_apk_x86_64/pmos-test.rsa.pub", member_paths)
        self.assertFalse((self.acquisition / "config_apk_keys").exists())
        self.assertEqual(
            (self.published / "work/cache_apk_x86_64/alpine-test.rsa.pub").read_bytes(),
            self.key_payloads["alpine-test.rsa.pub"],
        )
        self.assertEqual(read_offline_cache_manifest(self.published).manifest, manifest)

        # Keep the producer and the independently owned seal consumer on the
        # same exact v1 schema without importing seal code from the producer.
        from scripts.lmi_p1.seal import _validate_offline_cache_manifest

        seal_result = _validate_offline_cache_manifest(
            manifest,
            {item["path"]: item for item in manifest["members"]},
            repository_urls=PRODUCTION_REPOSITORY_URLS,
            expected_pmbootstrap_commit="1" * 40,
            expected_pmbootstrap_version="3.11.1",
            expected_pmaports_commit="2" * 40,
            expected_pmaports_tree="3" * 40,
        )
        self.assertEqual(seal_result, manifest)

    def test_publish_rejects_source_path_inode_substitution_hook(self):
        raw_rename = offline_cache_module._renameat2_noreplace
        validated_elsewhere = self.root / ".validated-quarantine-moved"
        calls = 0

        def substitute_then_rename(
            source_dir_fd, source_name, destination_dir_fd, destination_name
        ):
            nonlocal calls
            calls += 1
            if calls == 1:
                os.rename(self.quarantine, validated_elsewhere)
                self.quarantine.mkdir(mode=0o700)
                hostile = self.quarantine / "unverified"
                hostile.write_bytes(b"unverified substitution\n")
                hostile.chmod(0o600)
            return raw_rename(
                source_dir_fd, source_name, destination_dir_fd, destination_name
            )

        with (
            mock.patch.object(
                offline_cache_module,
                "_renameat2_noreplace",
                side_effect=substitute_then_rename,
            ),
            self.assertRaisesRegex(GateError, "source inode substitution"),
        ):
            self.promote()

        self.assertEqual(calls, 2)
        self.assertFalse(self.published.exists())
        self.assertEqual(
            (self.quarantine / "unverified").read_bytes(),
            b"unverified substitution\n",
        )
        self.assertTrue((validated_elsewhere / MANIFEST_NAME).is_file())

    def test_profile_reader_requires_canonical_exact_json(self):
        profile_path = self.root / "profile.json"
        profile_path.write_bytes(canonical_json_bytes(self.profile_mapping))
        self.assertEqual(load_promotion_profile(profile_path), self.profile)

        profile_path.write_text(json.dumps(self.profile_mapping, indent=2) + "\n")
        with self.assertRaisesRegex(GateError, "not canonical"):
            load_promotion_profile(profile_path)

    def test_same_noarch_package_may_be_bound_once_per_cache_architecture(self):
        repository_url = "http://dl-cdn.alpinelinux.org/alpine/edge/main"
        identity = PackageIdentity("fixture-noarch", "5.6-r0", "noarch")
        indexed = self._write_apk(
            "cache_apk_x86_64/opaque-noarch-copy.apk",
            identity,
            "untrusted-builder-copy.rsa.pub",
        )
        self.index_packages[("x86_64", repository_url)] += (indexed,)

        manifest = self.promote().manifest

        copies = [
            item
            for item in manifest["external_apks"]
            if item["name"] == "fixture-noarch"
        ]
        self.assertEqual(
            [item["architecture"] for item in copies], ["aarch64", "x86_64"]
        )

    def test_profile_rejects_non_apk_tools_http_artifact(self):
        changed = copy.deepcopy(self.profile_mapping)
        changed["http_artifacts"][0]["kind"] = "opaque-download"
        with self.assertRaisesRegex(GateError, "pinned apk-tools-static artifact"):
            validate_promotion_profile(changed)

    def test_missing_verifier_blocks_before_creating_quarantine(self):
        with self.assertRaisesRegex(GateError, "reviewed promotion attestation"):
            promote_offline_cache(
                self.acquisition,
                self.quarantine,
                self.published,
                self.profile,
                trusted_key_root=self.pmbootstrap,
            )
        self.assertFalse(self.quarantine.exists())
        self.assertFalse(self.published.exists())

    def test_attested_output_mismatch_never_publishes(self):
        source_paths = offline_cache_module._inventory_acquisition(
            self.acquisition, self.profile
        )
        acquisition_count, acquisition_digest = offline_cache_module._acquisition_identity(
            self.acquisition, source_paths
        )
        bootstrap_signer = self.profile.http_artifacts[0]["signer_key_path"]
        basename = PurePosixPath(str(bootstrap_signer)).name
        authorization = PromotionAuthorization(
            project_root=self.root,
            profile=self.profile,
            profile_sha256="a" * 64,
            trusted_pmbootstrap_commit=str(
                self.profile.pins["pmbootstrap"]["commit"]
            ),
            trusted_pmbootstrap_tree="b" * 40,
            signer_key_path=f"pmb/data/keys/{basename}",
            signer_key_sha256=str(
                self.profile.http_artifacts[0]["signer_key_sha256"]
            ),
            acquisition_inventory_sha256=acquisition_digest,
            acquisition_member_count=acquisition_count,
            producer_code={},
            runtime_trust={},
            bootstrap_pins=mock.sentinel.bootstrap_pins,
            expected_output={
                "schema": MANIFEST_SCHEMA,
                "manifest_sha256": "0" * 64,
                "aggregate_sha256": "0" * 64,
                "member_count": 0,
            },
            replay_report={},
        )
        verifier = FixtureVerifier(self.index_packages)
        verifier.close = mock.Mock()  # type: ignore[attr-defined]
        with (
            mock.patch.object(
                offline_cache_module,
                "_trusted_pmbootstrap_identity",
                return_value=(
                    authorization.trusted_pmbootstrap_commit,
                    authorization.trusted_pmbootstrap_tree,
                ),
            ),
            mock.patch.object(
                offline_cache_module,
                "bootstrap_apk_static_verifier",
                return_value=verifier,
            ),
            self.assertRaisesRegex(
                GateError, "output differs from reviewed attestation"
            ),
        ):
            promote_offline_cache(
                self.acquisition,
                self.quarantine,
                self.published,
                self.profile,
                trusted_key_root=self.pmbootstrap,
                authorization=authorization,
            )
        self.assertTrue(self.quarantine.exists())
        self.assertFalse(self.published.exists())

    def test_rejects_extra_top_level_mutable_cache(self):
        (self.acquisition / "cache_ccache_x86_64").mkdir(mode=0o700)
        with self.assertRaisesRegex(GateError, "top-level mismatch"):
            self.promote()
        self.assertFalse(self.published.exists())

    def test_rejects_stale_duplicate_apkindex(self):
        stale = self.acquisition / "cache_apk_x86_64/APKINDEX.deadbeef.tar.gz"
        stale.write_bytes(b"stale")
        stale.chmod(0o600)
        with self.assertRaisesRegex(GateError, "stale_or_duplicate"):
            self.promote()
        self.assertFalse(self.published.exists())

    def test_rejects_http_apkindex_download_copy(self):
        stale = self.acquisition / "cache_http/APKINDEX_deadbeef"
        stale.write_bytes(b"stale")
        stale.chmod(0o600)
        with self.assertRaisesRegex(GateError, "HTTP cache set mismatch"):
            self.promote()

    def test_rejects_symlink_hardlink_fifo_and_group_writable_input(self):
        cases = ("symlink", "hardlink", "fifo", "writable")
        for case in cases:
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory(dir=self.root) as temporary:
                    # Rebuild through setUp-like byte copying without preserving links.
                    clone = Path(temporary) / "acquisition"
                    clone.mkdir(mode=0o700)
                    for directory in _tree_directories(self.acquisition):
                        (clone / directory).mkdir(mode=0o700)
                    for relative in _tree_files(self.acquisition):
                        target = clone / relative
                        target.write_bytes((self.acquisition / relative).read_bytes())
                        target.chmod(0o600)
                    target = clone / self.profile.repositories[0]["index_path"].removeprefix("work/")
                    if case == "symlink":
                        target.unlink()
                        target.symlink_to(clone / "version")
                    elif case == "hardlink":
                        duplicate = clone / "cache_apk_aarch64/duplicate.apk"
                        os.link(clone / "cache_apk_aarch64/another-opaque-name.apk", duplicate)
                    elif case == "fifo":
                        target.unlink()
                        os.mkfifo(target, 0o600)
                    else:
                        target.chmod(0o622)
                    quarantine = Path(temporary) / ".q"
                    published = Path(temporary) / "cache"
                    with self.assertRaises(GateError):
                        promote_offline_cache(
                            clone,
                            quarantine,
                            published,
                            self.profile,
                            trusted_key_root=self.pmbootstrap,
                            verifier=FixtureVerifier(self.index_packages),
                        )
                    self.assertFalse(published.exists())

    def test_rejects_pinned_index_byte_mismatch_before_verification(self):
        path = self.acquisition / self.profile.repositories[0]["index_path"].removeprefix("work/")
        path.write_bytes(path.read_bytes() + b"changed")
        path.chmod(0o600)
        with self.assertRaisesRegex(GateError, "pinned repository index bytes mismatch"):
            self.promote()
        self.assertEqual(self.verifier.index_calls, [])

    def test_rejects_cryptographically_unverified_index_before_package_inspection(self):
        changed = copy.deepcopy(self.profile_mapping)
        repository = changed["repositories"][0]
        path = self.acquisition / str(repository["index_path"]).removeprefix("work/")
        tampered = path.read_bytes().replace(b"signed-index", b"unsigned-idx", 1)
        path.write_bytes(tampered)
        path.chmod(0o600)
        repository["index_size"] = len(tampered)
        repository["index_sha256"] = sha256(tampered)
        self.profile = validate_promotion_profile(changed)

        with self.assertRaisesRegex(GateError, "fixture index signature failed"):
            self.promote()

        self.assertEqual(self.verifier.package_calls, [])
        self.assertFalse(self.published.exists())

    def test_rejects_signer_source_digest_mismatch(self):
        key = self.pmbootstrap / "pmb/data/keys/alpine-test.rsa.pub"
        key.write_bytes(b"replacement key\n")
        key.chmod(0o600)
        with self.assertRaisesRegex(GateError, "signer key digest mismatch"):
            self.promote()
        self.assertFalse(self.quarantine.exists())

    def test_rejects_package_not_present_in_exact_signed_index(self):
        self.verifier.index_packages = {}
        with self.assertRaisesRegex(GateError, "does not bind uniquely"):
            self.promote()
        self.assertFalse(self.published.exists())

    def test_rejects_apkindex_checksum_size_and_duplicate_binding(self):
        repository_url = "http://dl-cdn.alpinelinux.org/alpine/edge/main"
        key = ("x86_64", repository_url)
        original = self.index_packages[key][0]
        cases = {
            "checksum": IndexedPackage(
                original.identity,
                original.size,
                "Q1" + base64.b64encode(b"\0" * 20).decode("ascii"),
            ),
            "size": IndexedPackage(
                original.identity,
                original.size + 1,
                original.apkindex_checksum,
            ),
        }
        for case, changed in cases.items():
            with self.subTest(case=case):
                self.index_packages[key] = (changed,)
                quarantine = self.root / f".{case}.q"
                published = self.root / f"{case}.cache"
                with self.assertRaisesRegex(GateError, "C:Q1|APKINDEX S"):
                    promote_offline_cache(
                        self.acquisition,
                        quarantine,
                        published,
                        self.profile,
                        trusted_key_root=self.pmbootstrap,
                        verifier=FixtureVerifier(self.index_packages),
                    )
                self.assertFalse(published.exists())
                self.index_packages[key] = (original,)

        duplicate_url = "http://dl-cdn.alpinelinux.org/alpine/edge/testing"
        self.index_packages[("x86_64", duplicate_url)] = (original,)
        with self.assertRaisesRegex(GateError, "does not bind uniquely"):
            self.promote()
        self.assertFalse(self.published.exists())

    def test_rejects_missing_or_malformed_builder_signer(self):
        path = self.acquisition / "cache_apk_x86_64/opaque-cache-name.apk"
        _signature, control_and_data = _split_first_gzip_member(path.read_bytes())
        cases = {
            "missing": gzip.compress(
                tar_bytes([(".NOT-A-SIGNATURE", b"fixture")]), mtime=0
            ),
            "malformed": gzip.compress(
                tar_bytes([(".SIGN.RSA.nested/builder.rsa.pub", b"fixture")]),
                mtime=0,
            ),
        }
        original = path.read_bytes()
        for case, signature in cases.items():
            with self.subTest(case=case):
                path.write_bytes(signature + control_and_data)
                path.chmod(0o600)
                quarantine = self.root / f".{case}.builder.q"
                published = self.root / f"{case}.builder.cache"
                with self.assertRaisesRegex(GateError, "ambiguous signature member"):
                    promote_offline_cache(
                        self.acquisition,
                        quarantine,
                        published,
                        self.profile,
                        trusted_key_root=self.pmbootstrap,
                        verifier=FixtureVerifier(self.index_packages),
                    )
                self.assertFalse(published.exists())
                path.write_bytes(original)
                path.chmod(0o600)

    def test_accepts_arbitrary_builder_signer_as_non_authorizing_provenance(self):
        path = self.acquisition / "cache_apk_x86_64/opaque-cache-name.apk"
        identity = PackageIdentity("fixture-x86", "1.2.3-r4", "x86_64")
        payload, checksum = v2_apk_payload(identity, "arbitrary-builder.rsa.pub")
        path.write_bytes(payload)
        path.chmod(0o600)
        repository_url = "http://dl-cdn.alpinelinux.org/alpine/edge/main"
        self.index_packages[("x86_64", repository_url)] = (
            IndexedPackage(identity, len(payload), checksum),
        )

        manifest = self.promote().manifest

        record = next(
            item for item in manifest["external_apks"] if item["name"] == identity.name
        )
        self.assertEqual(record["builder_signer"], "arbitrary-builder.rsa.pub")
        self.assertEqual(
            record["index_signer_key_path"],
            "work/cache_apk_x86_64/alpine-test.rsa.pub",
        )

    def test_reader_rejects_bit_flip_extra_member_and_noncanonical_manifest(self):
        self.promote()
        original = (self.published / "work/version").read_bytes()
        (self.published / "work/version").write_bytes(b"9\n")
        (self.published / "work/version").chmod(0o600)
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            read_offline_cache_manifest(self.published)
        (self.published / "work/version").write_bytes(original)
        (self.published / "work/version").chmod(0o600)

        extra = self.published / "work/cache_http/extra"
        extra.write_bytes(b"extra")
        extra.chmod(0o600)
        with self.assertRaisesRegex(GateError, "inventory mismatch"):
            read_offline_cache_manifest(self.published)
        extra.unlink()

        manifest_path = self.published / MANIFEST_NAME
        value = json.loads(manifest_path.read_bytes())
        manifest_path.write_text(json.dumps(value, indent=2) + "\n")
        manifest_path.chmod(0o600)
        with self.assertRaisesRegex(GateError, "not canonical"):
            read_offline_cache_manifest(self.published)

    def test_reader_rejects_aggregate_tamper_even_with_canonical_bytes(self):
        self.promote()
        manifest_path = self.published / MANIFEST_NAME
        value = json.loads(manifest_path.read_bytes())
        value["aggregate_sha256"] = "0" * 64
        manifest_path.write_bytes(canonical_json_bytes(value))
        manifest_path.chmod(0o600)
        with self.assertRaisesRegex(GateError, "aggregate_sha256 mismatch"):
            read_offline_cache_manifest(self.published)

    def test_reader_binds_manifest_to_exact_profile_and_external_keys(self):
        self.promote()
        read_offline_cache_manifest(
            self.published,
            expected_profile=self.profile,
            trusted_key_root=self.pmbootstrap,
        )
        changed = copy.deepcopy(self.profile_mapping)
        changed["distfiles"][0]["apkbuild_sha512"] = "b" * 128
        with self.assertRaisesRegex(GateError, "differs from promotion profile"):
            read_offline_cache_manifest(
                self.published,
                expected_profile=changed,
                trusted_key_root=self.pmbootstrap,
            )


class ConcreteApkStaticVerifierTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)
        self.trust_root = self.root / "cache"
        key_dir = self.trust_root / "work/cache_apk_x86_64"
        key_dir.mkdir(parents=True, mode=0o700)
        (self.trust_root / "work").chmod(0o700)
        self.key_name = "fixture-signing-key.rsa.pub"
        self.key_payload = b"fixture RSA public key\n"
        self.key_path = key_dir / self.key_name
        self.key_path.write_bytes(self.key_payload)
        self.key_path.chmod(0o600)
        self.signer_relative = f"work/cache_apk_x86_64/{self.key_name}"

        runtime_sources = self.root / "runtime-sources"
        runtime_sources.mkdir(mode=0o700)
        destinations = {
            "openssl": "openssl",
            "loader": "ld-linux-x86-64.so.2",
            "libssl": "libssl.so.3",
            "libcrypto": "libcrypto.so.3",
            "libc": "libc.so.6",
            "libz": "libz.so.1",
            "libzstd": "libzstd.so.1",
        }
        runtime_members = []
        for role, destination in destinations.items():
            source = runtime_sources / f"{role}.source"
            payload = f"fixture pinned {role}\n".encode()
            source.write_bytes(payload)
            source.chmod(0o700 if role in {"openssl", "loader"} else 0o600)
            runtime_members.append(
                RuntimeClosureMember(
                    role=role,
                    source_path=source,
                    destination_basename=destination,
                    size=len(payload),
                    sha256=sha256(payload),
                )
            )
        self.runtime = OpenSslRuntimePins(
            version="3.5.5",
            members=tuple(runtime_members),
            review_distribution="Ubuntu",
            review_packages=({"name": "openssl", "version": "3.5.5-fixture"},),
        )
        self.apk_static_payload = b"fixture authenticated apk.static executable\n"
        self.embedded_signature = b"fixture embedded signature"
        self.package = self.root / "apk-tools-static.apk"
        package_payload, _checksum = v2_apk_payload(
            PackageIdentity("apk-tools-static", "3.0.6-r0", "x86_64"),
            self.key_name,
            data_members=[
                ("sbin/apk.static", self.apk_static_payload),
                (
                    f"sbin/apk.static.SIGN.RSA.sha256.{self.key_name}",
                    self.embedded_signature,
                ),
            ],
        )
        self.package.write_bytes(package_payload)
        self.package.chmod(0o600)
        self.package_record = {
            "kind": "apk-tools-static",
            "name": "apk-tools-static",
            "version": "3.0.6-r0",
            "url": "https://dl.example.invalid/apk-tools-static.apk",
            "path": "work/cache_http/apk-tools-static.apk_fixture",
            "size": self.package.stat().st_size,
            "sha256": sha256(self.package.read_bytes()),
            "signer_key_path": self.signer_relative,
            "signer_key_sha256": sha256(self.key_payload),
        }
        self.pins = ApkStaticBootstrapPins(
            openssl_runtime=self.runtime,
            apk_static_size=len(self.apk_static_payload),
            apk_static_sha256=sha256(self.apk_static_payload),
            apk_static_version="3.0.6-r0",
        )
        self.bootstrap_root = self.root / ".verifier-bootstrap"
        self.commands = []

    def fake_run(self, argv, *, cwd, environment):
        self.commands.append((tuple(argv), cwd, dict(environment)))
        executable = Path(argv[0])
        arguments = tuple(argv[1:])
        if executable.name == "ld-linux-x86-64.so.2":
            self.assertEqual(arguments[:2], ("--inhibit-cache", "--library-path"))
            runtime_root = Path(arguments[2])
            self.assertEqual(runtime_root, Path(cwd) / "openssl-runtime")
            self.assertEqual(environment["OPENSSL_CONF"], "/dev/null")
            self.assertEqual(
                Path(environment["OPENSSL_MODULES"]), runtime_root / "modules"
            )
            if arguments[3] == "--list":
                self.assertEqual(Path(arguments[4]), runtime_root / "openssl")
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    "".join(
                        f"{item.destination_basename} => "
                        f"{runtime_root / item.destination_basename} (0x1)\n"
                        for item in self.runtime.members
                        if item.role != "openssl"
                    ),
                    "",
                )
            self.assertEqual(Path(arguments[3]), runtime_root / "openssl")
            openssl_arguments = arguments[4:]
        else:
            openssl_arguments = ()
        if executable.name == "ld-linux-x86-64.so.2" and openssl_arguments == ("version",):
            return subprocess.CompletedProcess(argv, 0, "OpenSSL 3.5.5 fixture\n", "")
        if executable.name == "ld-linux-x86-64.so.2" and openssl_arguments[:2] == ("dgst", "-sha256"):
            self.assertEqual(openssl_arguments[2], "-verify")
            self.assertEqual(Path(openssl_arguments[3]).read_bytes(), self.key_payload)
            self.assertEqual(openssl_arguments[4], "-signature")
            self.assertEqual(Path(openssl_arguments[5]).read_bytes(), self.embedded_signature)
            self.assertEqual(Path(openssl_arguments[6]).read_bytes(), self.apk_static_payload)
            return subprocess.CompletedProcess(argv, 0, "Verified OK\n", "")
        if executable.name == "apk.static" and arguments == ("--version",):
            return subprocess.CompletedProcess(
                argv, 0, "apk-tools 3.0.6-r0, compiled for x86_64.\n", ""
            )
        if executable.name == "apk.static" and "verify" in argv:
            root = Path(argv[argv.index("--root") + 1])
            keys_dir = Path(argv[argv.index("--keys-dir") + 1])
            self.assertTrue(keys_dir.is_absolute())
            self.assertEqual(keys_dir, root / "keys")
            keys = list(keys_dir.iterdir())
            self.assertEqual(len(keys), 1)
            target = Path(argv[-1])
            with tarfile.open(target, "r:*") as archive:
                accepted = f".SIGN.RSA.{keys[0].name}" in archive.getnames()
            return subprocess.CompletedProcess(
                argv,
                0 if accepted else 1,
                f"{target}: {'OK' if accepted else 'UNTRUSTED'}\n",
                "",
            )
        self.fail(f"unexpected verifier command: {argv!r}")

    def bootstrap(self):
        patcher = mock.patch(
            "scripts.lmi_p1.offline_cache._run_command", side_effect=self.fake_run
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return bootstrap_apk_static_verifier(
            self.package,
            package_record=self.package_record,
            trusted_key_root=self.trust_root,
            bootstrap_root=self.bootstrap_root,
            pins=self.pins,
        )

    def test_bootstrap_and_concrete_v2_index_package_verification(self):
        verifier = self.bootstrap()
        self.assertIsInstance(verifier, PinnedApkStaticVerifier)
        self.assertEqual(
            (self.bootstrap_root / "apk.static").read_bytes(),
            self.apk_static_payload,
        )

        package = self.root / "opaque.apk"
        identity = PackageIdentity("fixture-package", "9.8-r1", "x86_64")
        package_payload, package_checksum = v2_apk_payload(identity, self.key_name)
        package.write_bytes(package_payload)
        package.chmod(0o600)
        index = self.root / "APKINDEX.fixture.tar.gz"
        write_tar(
            index,
            [
                (f".SIGN.RSA.{self.key_name}", b"index signature"),
                (
                    "APKINDEX",
                    (
                        f"C:{package_checksum}\nP:fixture-package\nV:9.8-r1\n"
                        f"A:x86_64\nS:{len(package_payload)}\n\n"
                    ).encode("ascii"),
                ),
            ],
        )
        verified_index = verifier.verify_index(
            index,
            repository_url="https://repo.example.invalid/main",
            architecture="x86_64",
            signer_key_path=self.signer_relative,
            trusted_key_root=self.trust_root,
        )
        verified_package = verifier.verify_package(
            package,
            expected_cache_architecture="x86_64",
            allowed_signer_key_paths=(self.signer_relative,),
            trusted_key_root=self.trust_root,
        )

        self.assertEqual(
            verified_index.packages,
            (IndexedPackage(identity, len(package_payload), package_checksum),),
        )
        self.assertEqual(verified_package, VerifiedPackage(identity, self.signer_relative))
        verify_commands = [argv for argv, _cwd, _env in self.commands if "verify" in argv]
        self.assertEqual(len(verify_commands), 2)
        for command in verify_commands:
            self.assertIn("--no-network", command)
            self.assertNotIn("--allow-untrusted", command)
        verifier.close()
        self.assertFalse(self.bootstrap_root.exists())

    def test_bootstrap_fails_closed_on_openssl_pin_or_embedded_signature(self):
        bad_pins = ApkStaticBootstrapPins(
            openssl_runtime=OpenSslRuntimePins(
                version=self.runtime.version,
                members=tuple(
                    RuntimeClosureMember(
                        item.role,
                        item.source_path,
                        item.destination_basename,
                        item.size,
                        "0" * 64 if item.role == "openssl" else item.sha256,
                    )
                    for item in self.runtime.members
                ),
                review_distribution=self.runtime.review_distribution,
                review_packages=self.runtime.review_packages,
            ),
            apk_static_size=len(self.apk_static_payload),
            apk_static_sha256=sha256(self.apk_static_payload),
            apk_static_version="3.0.6-r0",
        )
        with mock.patch(
            "scripts.lmi_p1.offline_cache._run_command"
        ) as run_command, self.assertRaisesRegex(GateError, "openssl source size or SHA-256"):
            bootstrap_apk_static_verifier(
                self.package,
                package_record=self.package_record,
                trusted_key_root=self.trust_root,
                bootstrap_root=self.bootstrap_root,
                pins=bad_pins,
            )
        run_command.assert_not_called()

        # Use a fresh root because failed bootstrap deliberately quarantines its
        # extracted evidence instead of deleting it.
        second_root = self.root / ".second-bootstrap"

        def reject_signature(argv, *, cwd, environment):
            if Path(argv[0]).name == "ld-linux-x86-64.so.2" and (
                "--list" in argv or tuple(argv[5:]) == ("version",)
            ):
                return self.fake_run(argv, cwd=cwd, environment=environment)
            return subprocess.CompletedProcess(argv, 1, "", "bad signature")

        with mock.patch(
            "scripts.lmi_p1.offline_cache._run_command", side_effect=reject_signature
        ), self.assertRaisesRegex(GateError, "signature verification.*status 1"):
            bootstrap_apk_static_verifier(
                self.package,
                package_record=self.package_record,
                trusted_key_root=self.trust_root,
                bootstrap_root=second_root,
                pins=self.pins,
            )
        self.assertTrue(second_root.exists())

    def test_bootstrap_rejects_private_runtime_tamper_swap_and_extra_member(self):
        for case in ("tamper", "swap", "extra"):
            with self.subTest(case=case):
                bootstrap_root = self.root / f".{case}-bootstrap"

                def mutate_after_version(argv, *, cwd, environment):
                    result = self.fake_run(argv, cwd=cwd, environment=environment)
                    if Path(argv[0]).name == "ld-linux-x86-64.so.2" and tuple(argv[5:]) == ("version",):
                        runtime_root = bootstrap_root / "openssl-runtime"
                        if case == "tamper":
                            target = runtime_root / "libssl.so.3"
                            target.write_bytes(b"tampered runtime\n")
                            target.chmod(0o600)
                        elif case == "swap":
                            first = runtime_root / "libssl.so.3"
                            second = runtime_root / "libcrypto.so.3"
                            first_payload, second_payload = first.read_bytes(), second.read_bytes()
                            first.write_bytes(second_payload)
                            first.chmod(0o600)
                            second.write_bytes(first_payload)
                            second.chmod(0o600)
                        else:
                            extra = runtime_root / "libprovider-injection.so"
                            extra.write_bytes(b"hostile provider\n")
                            extra.chmod(0o600)
                    return result

                with mock.patch(
                    "scripts.lmi_p1.offline_cache._run_command",
                    side_effect=mutate_after_version,
                ), self.assertRaisesRegex(GateError, "runtime|private libssl"):
                    bootstrap_apk_static_verifier(
                        self.package,
                        package_record=self.package_record,
                        trusted_key_root=self.trust_root,
                        bootstrap_root=bootstrap_root,
                        pins=self.pins,
                    )
                self.assertTrue(bootstrap_root.exists())

    def test_bootstrap_ignores_host_openssl_configuration_and_provider_injection(self):
        with mock.patch.dict(
            os.environ,
            {
                "OPENSSL_CONF": "/hostile/openssl.cnf",
                "OPENSSL_MODULES": "/hostile/modules",
                "LD_LIBRARY_PATH": "/hostile/libraries",
                "LD_PRELOAD": "/hostile/preload.so",
            },
            clear=False,
        ):
            verifier = self.bootstrap()
        openssl_commands = [
            environment
            for argv, _cwd, environment in self.commands
            if Path(argv[0]).name == "ld-linux-x86-64.so.2"
        ]
        self.assertEqual(len(openssl_commands), 3)
        for environment in openssl_commands:
            self.assertEqual(environment["OPENSSL_CONF"], "/dev/null")
            self.assertEqual(
                Path(environment["OPENSSL_MODULES"]),
                self.bootstrap_root / "openssl-runtime/modules",
            )
            self.assertNotIn("LD_LIBRARY_PATH", environment)
            self.assertNotIn("LD_PRELOAD", environment)
        verifier.close()

    def test_concrete_verifier_rejects_wrong_signature_basename_and_ambiguity(self):
        verifier = self.bootstrap()
        package = self.root / "wrong.apk"
        identity = PackageIdentity("fixture-package", "1-r0", "x86_64")
        valid, _checksum = v2_apk_payload(identity, self.key_name)
        _signature, control_and_data = _split_first_gzip_member(valid)
        ambiguous_signature = gzip.compress(
            tar_bytes(
                [
                    (f".SIGN.RSA.{self.key_name}", b"package signature"),
                    (f".SIGN.RSA.sha256.{self.key_name}", b"second signature"),
                ]
            ),
            mtime=0,
        )
        package.write_bytes(ambiguous_signature + control_and_data)
        package.chmod(0o600)
        with self.assertRaisesRegex(GateError, "ambiguous signature"):
            verifier.verify_package(
                package,
                expected_cache_architecture="x86_64",
                allowed_signer_key_paths=(self.signer_relative,),
                trusted_key_root=self.trust_root,
            )
        verifier.close()

    def test_concrete_verifier_selects_expected_arch_copy_of_shared_key(self):
        verifier = self.bootstrap()
        arm_signer = f"work/cache_apk_aarch64/{self.key_name}"
        arm_key = self.trust_root.joinpath(*Path(arm_signer).parts)
        arm_key.parent.mkdir(mode=0o700)
        arm_key.write_bytes(self.key_payload)
        arm_key.chmod(0o600)
        command_count = len(self.commands)

        result = verifier.verify_package(
            self.package,
            expected_cache_architecture="x86_64",
            allowed_signer_key_paths=(arm_signer, self.signer_relative),
            trusted_key_root=self.trust_root,
        )

        self.assertEqual(result.signer_key_path, self.signer_relative)
        verify_commands = [
            argv
            for argv, _cwd, _env in self.commands[command_count:]
            if "verify" in argv
        ]
        self.assertEqual(len(verify_commands), 1)
        verifier.close()

    def test_concrete_verifier_rejects_shared_basename_with_different_bytes(self):
        verifier = self.bootstrap()
        arm_signer = f"work/cache_apk_aarch64/{self.key_name}"
        arm_key = self.trust_root.joinpath(*Path(arm_signer).parts)
        arm_key.parent.mkdir(mode=0o700)
        arm_key.write_bytes(b"different RSA public key\n")
        arm_key.chmod(0o600)

        with self.assertRaisesRegex(GateError, "basename with different key material"):
            verifier.verify_package(
                self.package,
                expected_cache_architecture="x86_64",
                allowed_signer_key_paths=(arm_signer, self.signer_relative),
                trusted_key_root=self.trust_root,
            )
        verifier.close()


def _tree_directories(root: Path):
    return sorted(
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_dir() and not path.is_symlink()
    )


def _tree_files(root: Path):
    return sorted(
        path.relative_to(root)
        for path in root.rglob("*")
        if path.is_file() and not path.is_symlink()
    )


if __name__ == "__main__":
    unittest.main()
