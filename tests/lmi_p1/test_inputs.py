import hashlib
import io
import json
import re
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest

from scripts.lmi_p1.common import GateError
import scripts.lmi_p1.build as build_module
from scripts.lmi_p1.inputs import prepare_inputs, safe_extract


REQUIRED_NAMES = (
    "device-xiaomi-lmi-1-r139.apk",
    "linux-xiaomi-lmi-4.19.325-r9.apk",
    "weston-14.0.2-r10.apk",
    "weston-backend-drm-14.0.2-r10.apk",
    "weston-clients-14.0.2-r10.apk",
    "weston-shell-desktop-14.0.2-r10.apk",
    "weston-terminal-14.0.2-r10.apk",
)

PRODUCTION_REQUIRED_MEMBERS = {
    "device-xiaomi-lmi-1-r139.apk": (
        "ac00f22751607ae736cc26fbe72c1ede9c7d4d26f3af887ab0af800d5d9a3934"
    ),
    "linux-xiaomi-lmi-4.19.325-r9.apk": (
        "678a94cb0d309c69e56e697533ad7f6fe9e9cbfc7dea5a5109ca55b36ee72f50"
    ),
    "weston-14.0.2-r10.apk": (
        "d62a5b63fb1d4a35cec06dedf62c86d7da67b4d796ea7c973ea92035622bf2e7"
    ),
    "weston-backend-drm-14.0.2-r10.apk": (
        "53e95028082b3ddecb5460aa100557971b368451f1f51f0b92b9484a6b76bc1b"
    ),
    "weston-clients-14.0.2-r10.apk": (
        "1301346e110d7363a5fbe611f3ee282a3074ec2c52d884485ca961bb63835476"
    ),
    "weston-shell-desktop-14.0.2-r10.apk": (
        "b7bd061487f7ede3ebd102a3552d5596c87091146cf1d60a1a93c6ada847083e"
    ),
    "weston-terminal-14.0.2-r10.apk": (
        "868eadb0171214945a34cec73da00a6b78d4a4e3e115611545f56bdb25a3d877"
    ),
}


class InputTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.cache = self.root / "cache"
        self.out = self.root / "out"
        self._sequence = 0

    def fixture_payloads(self):
        values = (b"device", b"kernel", b"weston", b"drm", b"clients", b"shell", b"terminal")
        return dict(zip(REQUIRED_NAMES, values, strict=True))

    @staticmethod
    def checksums_for(payloads):
        return "".join(
            f"{hashlib.sha256(payload).hexdigest()}  {name}\n"
            for name, payload in payloads.items()
        ).encode("utf-8")

    def make_tar(self, members):
        self._sequence += 1
        path = self.root / f"archive-{self._sequence}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            for name, payload in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o600
                archive.addfile(info, io.BytesIO(payload))
        return path

    def make_special_tar(self, name, member_type, linkname=""):
        self._sequence += 1
        path = self.root / f"special-{self._sequence}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            info = tarfile.TarInfo(name)
            info.type = member_type
            info.linkname = linkname
            archive.addfile(info)
        return path

    def make_wrapped_tar(self, wrapper, members):
        self._sequence += 1
        path = self.root / f"wrapped-{self._sequence}.tar.gz"
        with tarfile.open(path, "w:gz") as archive:
            directory = tarfile.TarInfo(f"{wrapper}/")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o777
            archive.addfile(directory)
            for name, payload in members.items():
                info = tarfile.TarInfo(f"{wrapper}/{name}")
                info.size = len(payload)
                info.mode = 0o777
                archive.addfile(info, io.BytesIO(payload))
        return path

    def lock_for(
        self,
        archive,
        *,
        sha=None,
        size=None,
        inner_sha=None,
        required_members=None,
        url=None,
    ):
        with tarfile.open(archive, "r:*") as source:
            checksum_candidates = [
                member
                for member in source.getmembers()
                if member.isreg() and member.name.rsplit("/", 1)[-1] == "SHA256SUMS"
            ]
            self.assertEqual(len(checksum_candidates), 1)
            checksum_member = source.extractfile(checksum_candidates[0])
            checksum_payload = checksum_member.read() if checksum_member else b""
        value = {
            "schema": 1,
            "d80": {
                "url": archive.as_uri() if url is None else url,
                "size": archive.stat().st_size if size is None else size,
                "sha256": self.file_sha256(archive) if sha is None else sha,
                "inner_sha256sums_sha256": (
                    hashlib.sha256(checksum_payload).hexdigest()
                    if inner_sha is None
                    else inner_sha
                ),
                "required_members": (
                    {
                        name: hashlib.sha256(payload).hexdigest()
                        for name, payload in self.fixture_payloads().items()
                    }
                    if required_members is None
                    else required_members
                ),
            },
        }
        self._sequence += 1
        lock = self.root / f"lock-{self._sequence}.json"
        lock.write_text(json.dumps(value), encoding="utf-8")
        return lock

    @staticmethod
    def file_sha256(path):
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
        return digest.hexdigest()

    def valid_archive(self):
        payloads = self.fixture_payloads()
        checksums = self.checksums_for(payloads)
        return self.make_tar({"SHA256SUMS": checksums, **payloads})

    def valid_lock(self):
        return self.lock_for(self.valid_archive())

    def test_rejects_parent_traversal(self):
        with self.assertRaisesRegex(GateError, "unsafe archive member"):
            safe_extract(self.make_tar({"../escape": b"x"}), self.out)

    def test_rejects_absolute_tar_member(self):
        with self.assertRaisesRegex(GateError, "unsafe archive member"):
            safe_extract(self.make_tar({"/absolute": b"x"}), self.out)

    def test_rejects_links(self):
        archive = self.make_special_tar("link", tarfile.SYMTYPE, "target")
        with self.assertRaisesRegex(GateError, "non-regular archive member"):
            safe_extract(archive, self.out)

    def test_rejects_device_or_other_non_regular_members(self):
        archive = self.make_special_tar("pipe", tarfile.FIFOTYPE)
        with self.assertRaisesRegex(GateError, "non-regular archive member"):
            safe_extract(archive, self.out)

    def test_rejects_contiguous_tar_members(self):
        archive = self.make_special_tar("contiguous", tarfile.CONTTYPE)
        with self.assertRaisesRegex(GateError, "non-regular archive member"):
            safe_extract(archive, self.out)

    def test_rejects_gnu_sparse_tar_members(self):
        archive = self.make_special_tar("sparse", tarfile.GNUTYPE_SPARSE)
        with self.assertRaisesRegex(GateError, "non-regular archive member"):
            safe_extract(archive, self.out)

    def test_outer_hash_is_checked_before_extract(self):
        archive = self.make_tar({"SHA256SUMS": b""})
        lock = self.lock_for(archive, sha="0" * 64)

        with self.assertRaisesRegex(GateError, "outer sha256 mismatch"):
            prepare_inputs(lock, self.cache)

        self.assertFalse(self.cache.exists() and any(self.cache.iterdir()))

    def test_outer_size_is_pinned(self):
        archive = self.valid_archive()
        lock = self.lock_for(archive, size=archive.stat().st_size + 1)

        with self.assertRaisesRegex(GateError, "outer size mismatch"):
            prepare_inputs(lock, self.cache)

    def test_inner_sha256sums_hash_is_pinned(self):
        archive = self.valid_archive()
        lock = self.lock_for(archive, inner_sha="0" * 64)

        with self.assertRaisesRegex(
            GateError, "inner SHA256SUMS sha256 mismatch"
        ):
            prepare_inputs(lock, self.cache)

    def test_inner_member_hash_mismatch_is_rejected(self):
        payloads = self.fixture_payloads()
        checksums = self.checksums_for(payloads)
        expected = hashlib.sha256(payloads[REQUIRED_NAMES[0]]).hexdigest()
        checksums = checksums.replace(expected.encode("ascii"), b"0" * 64, 1)
        archive = self.make_tar({"SHA256SUMS": checksums, **payloads})
        lock = self.lock_for(archive)

        with self.assertRaisesRegex(GateError, "member sha256 mismatch"):
            prepare_inputs(lock, self.cache)

    def test_complete_checksum_member_set_is_required(self):
        payloads = self.fixture_payloads()
        archive = self.make_tar(
            {"SHA256SUMS": self.checksums_for(payloads), **payloads, "extra": b"x"}
        )
        lock = self.lock_for(archive)

        with self.assertRaisesRegex(GateError, "checksum member set mismatch"):
            prepare_inputs(lock, self.cache)

    def test_checksum_file_cannot_supply_an_unsafe_path(self):
        payloads = self.fixture_payloads()
        checksums = self.checksums_for(payloads)
        checksums += f"{hashlib.sha256(b'x').hexdigest()}  ../escape\n".encode(
            "ascii"
        )
        archive = self.make_tar({"SHA256SUMS": checksums, **payloads})
        lock = self.lock_for(archive)

        with self.assertRaisesRegex(GateError, "unsafe SHA256SUMS member"):
            prepare_inputs(lock, self.cache)

    def test_missing_required_apk_is_rejected(self):
        payloads = self.fixture_payloads()
        incomplete = dict(payloads)
        del incomplete[REQUIRED_NAMES[-1]]
        archive = self.make_tar(
            {"SHA256SUMS": self.checksums_for(incomplete), **incomplete}
        )
        required = {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in payloads.items()
        }
        lock = self.lock_for(archive, required_members=required)

        with self.assertRaisesRegex(GateError, "missing required APK"):
            prepare_inputs(lock, self.cache)

    def test_plain_http_source_is_rejected(self):
        archive = self.valid_archive()
        lock = self.lock_for(archive, url="http://example.invalid/d80.tar.gz")

        with self.assertRaisesRegex(GateError, "unsupported D80 URL"):
            prepare_inputs(lock, self.cache)

    def test_valid_local_file_archive_is_verified(self):
        extracted = prepare_inputs(self.valid_lock(), self.cache)

        self.assertEqual(
            (extracted / "device-xiaomi-lmi-1-r139.apk").read_bytes(), b"device"
        )
        self.assertEqual(
            set(path.name for path in extracted.iterdir()),
            {"SHA256SUMS", *REQUIRED_NAMES},
        )

    def test_valid_single_wrapper_archive_returns_direct_content_directory(self):
        payloads = self.fixture_payloads()
        archive = self.make_wrapped_tar(
            "d80-minimal-gui-osk-20260712",
            {"SHA256SUMS": self.checksums_for(payloads), **payloads},
        )
        extracted = prepare_inputs(self.lock_for(archive), self.cache)

        self.assertTrue((extracted / "SHA256SUMS").is_file())
        self.assertFalse((extracted / "d80-minimal-gui-osk-20260712").exists())
        self.assertEqual(
            (extracted / "device-xiaomi-lmi-1-r139.apk").read_bytes(), b"device"
        )
        self.assertEqual(
            stat.S_IMODE(
                (extracted / "device-xiaomi-lmi-1-r139.apk").stat().st_mode
            ),
            0o600,
        )

    def test_production_source_lock_is_exact(self):
        repository = Path(__file__).resolve().parents[2]
        actual = json.loads(
            (repository / "config/lmi-p1/source-lock.json").read_text(
                encoding="utf-8"
            )
        )

        sha1_re = re.compile(r"^[0-9a-f]{40}$")
        sha256_re = re.compile(r"^[0-9a-f]{64}$")
        sha512_re = re.compile(r"^[0-9a-f]{128}$")
        self.assertEqual(len(actual["pmbootstrap"]["entrypoint_sha256"]), 64)
        self.assertRegex(actual["pmbootstrap"]["entrypoint_sha256"], sha256_re)
        self.assertEqual(len(actual["pmbootstrap"]["tree"]), 40)
        self.assertEqual(len(actual["pmaports"]["tree"]), 40)
        self.assertEqual(len(actual["kernel"]["commit"]), 40)
        self.assertEqual(len(actual["kernel"]["sha512"]), 128)
        self.assertEqual(len(actual["pmaports"]["commit"]), 40)
        self.assertEqual(len(actual["pmbootstrap"]["commit"]), 40)
        self.assertRegex(actual["pmbootstrap"]["commit"], sha1_re)
        self.assertRegex(actual["pmaports"]["commit"], sha1_re)
        self.assertRegex(actual["kernel"]["commit"], sha1_re)
        self.assertRegex(actual["kernel"]["sha512"], sha512_re)
        self.assertRegex(actual["offline_cache"]["aggregate_sha256"], sha256_re)
        self.assertRegex(actual["offline_cache"]["manifest_sha256"], sha256_re)
        known_good_kernel = actual.pop("known_good_kernel_package")
        self.assertEqual(
            known_good_kernel,
            build_module._EXPECTED_KNOWN_GOOD_KERNEL_PIN,
        )

        expected = {
            "schema": "lmi-source-lock/v3",
            "pmbootstrap": {
                "entrypoint_sha256": "475f14ae696ef66a88f3d48c04fdfe391d0714b044522a2423b6872b99cd03bd",
                "remote": "https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git",
                "commit": "ce76febabd983db6445fa9a8b75d601970b2f436",
                "tree": "6ea77f76fe5914d44ed8c85ae51b81f1081e73b7",
                "version": "3.11.1",
            },
            "pmaports": {
                "remote": "https://gitlab.postmarketos.org/postmarketOS/pmaports.git",
                "commit": "6fb3a1e5eb21c809891645a2ba5ae11fa788e032",
                "tree": "749f154b6f154f86133e7c7616074aa9eb876f2e",
            },
            "offline_cache": {
                "aggregate_sha256": "261d675016c298c0d924fa856c834e355ac13c7b5f536459e3236ee698351018",
                "manifest_sha256": "4192aa5636fb6a740dc47fb7370e32547359bc8c3ea1464fb891b347a84b60a3",
                "schema": "lmi-p1-offline-cache/v2",
            },
            "kernel": {
                "commit": "a5b3099017ae581aae8bf597b2f9c8c765026af1",
                "package": "linux-xiaomi-lmi",
                "remote": "https://github.com/LineageOS/android_kernel_xiaomi_sm8250",
                "sha512": "b9d00e0efcb88d613bd65b1f2cd6b75e2b5f0d79b23def0b9c14eb397265e582a580e93cb365d81e7aa167b027920845ff8db798bbf781bbd9e7845e796bd923",
                "version": "4.19.325-r8",
            },
            "public_credential_policy": {
                "boot_state": "never_booted",
                "credential_state": "unprovisioned",
                "owner_test_artifact": "never-publish",
                "personalization_required": True,
                "ssh_ready": False,
            },
            "release": {
                "source_repo": "jian45154/redmi-k30-pro-postmarketos",
                "public_allowed": True,
                "visibility": "public",
            },
        }

        self.assertEqual(actual, expected)

    def test_production_source_lock_excludes_private_inputs(self):
        repository = Path(__file__).resolve().parents[2]
        source_lock = repository / "config/lmi-p1/source-lock.json"
        source_lock_text = source_lock.read_text(encoding="utf-8")
        source_lock_json = json.loads(source_lock_text)

        self.assertEqual(source_lock_json["schema"], "lmi-source-lock/v3")
        self.assertNotIn("artifact_repo", source_lock_json["release"])
        self.assertNotIn("ssh", source_lock_json)
        self.assertIn("public_allowed", source_lock_json["release"])
        self.assertTrue(source_lock_json["release"]["public_allowed"])
        self.assertNotIn("d80", source_lock_json)
        self.assertNotRegex(source_lock_text, r"[A-Za-z]:[\\/]+Users[\\/]")
        self.assertNotIn("SHA256:", source_lock_text)
        self.assertNotIn("serial_sha256", source_lock_text)
        self.assertNotIn("d82_evidence_member_sha256", source_lock_text)

    def test_p2_d80_source_lock_is_exact(self):
        repository = Path(__file__).resolve().parents[2]
        actual = json.loads(
            (repository / "config/lmi-p2/d80-source-lock.json").read_text(
                encoding="utf-8"
            )
        )
        expected = {
            "schema": "lmi-source-lock/v2",
            "d80": {
                "url": "https://github.com/jian45154/redmi-k30-pro-postmarketos/releases/download/d80-minimal-gui-osk-20260712/d80-minimal-gui-osk-20260712.tar.gz",
                "size": 19451357,
                "sha256": "f380eb275ef4ba8854dd3bc389f7113a701a29ab3fd302684b729e6ad64286ca",
                "inner_sha256sums_sha256": "561efa3a0e311e4bb5118f661f897da1c54838e2746f18e94665e711e0f85c33",
                "required_members": PRODUCTION_REQUIRED_MEMBERS,
            },
        }
        self.assertEqual(actual, expected)

    def test_private_userdata_disposition_is_not_committed(self):
        repository = Path(__file__).resolve().parents[2]
        public_path = repository / "config/lmi-p1/userdata-disposition.json"

        self.assertFalse(public_path.exists())
        self.assertIn("/private/", (repository / ".gitignore").read_text())



if __name__ == "__main__":
    unittest.main()
