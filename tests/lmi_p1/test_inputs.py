import hashlib
import io
import json
from pathlib import Path
import stat
import tarfile
import tempfile
import unittest

from scripts.lmi_p1.common import GateError
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
        expected = {
            "schema": 1,
            "pmbootstrap": {
                "commit": "ce76febabd983db6445fa9a8b75d601970b2f436",
                "version": "3.11.1",
            },
            "pmaports": {
                "commit": "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
            },
            "d80": {
                "url": "https://github.com/jian45154/redmi-k30-pro-postmarketos/releases/download/d80-minimal-gui-osk-20260712/d80-minimal-gui-osk-20260712.tar.gz",
                "size": 19451357,
                "sha256": "f380eb275ef4ba8854dd3bc389f7113a701a29ab3fd302684b729e6ad64286ca",
                "inner_sha256sums_sha256": "561efa3a0e311e4bb5118f661f897da1c54838e2746f18e94665e711e0f85c33",
                "required_members": PRODUCTION_REQUIRED_MEMBERS,
            },
            "ssh": {
                "public_key_path": "/mnt/c/Users/microstar/.ssh/id_ed25519.pub",
                "fingerprint": "SHA256:MaX0FIvahR2a2THIjIYYfpbmTGVDk/8fwJ1a+ov3n9o",
            },
            "release": {
                "source_repo": "jian45154/redmi-k30-pro-postmarketos",
                "artifact_repo": "jian45154/redmi-k30-pro-postmarketos-artifacts",
                "visibility": "private",
                "public_allowed": False,
            },
        }

        self.assertEqual(actual, expected)

    def test_userdata_disposition_records_the_exact_authorization_basis(self):
        repository = Path(__file__).resolve().parents[2]
        actual = json.loads(
            (repository / "config/lmi-p1/userdata-disposition.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            actual,
            {
                "schema": "lmi-userdata-disposition/v1",
                "product": "lmi",
                "serial_sha256": "0d71649b94add9a513413c424925341348208dd8a900ed8474c623cd47c2dfeb",
                "classification": "disposable-pmos-test-data",
                "prior_d80_userdata_sha256": "c005e29f2f924154152ff58b228d14e6c3a716cfbbbabf9995be198792b40d90",
                "d82_evidence_member_sha256": "4ac88bcfbfab1b12c9158f1bd2636626b019712ea2d41ade6c856a56c589f2d1",
                "basis": "D81 deliberately replaced userdata with that D80 postmarketOS image; D82 successfully booted it and bound the same root UUID; the repository is an installation/porting workspace and the user has authorized replacement of this test image.",
                "warning": "This is not an Android personal-data backup and would be insufficient if the serial hash, prior image identity, or project history differed.",
            },
        )


if __name__ == "__main__":
    unittest.main()
