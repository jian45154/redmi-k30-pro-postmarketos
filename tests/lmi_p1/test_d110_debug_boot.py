from __future__ import annotations

import base64
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from unittest import mock

import scripts.lmi_p1.d110_debug_boot as debug_boot


class D110DebugBootTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.root.chmod(0o700)

        self.cmdline = b"console=ttyMSM0 androidboot.hardware=qcom quiet"
        self.kernel = b"synthetic-kernel\0payload"
        self.ramdisk = b"synthetic-initramfs\0payload"
        self.dtb = b"synthetic-dtb\0payload"
        self.source_image, self.profile = self._boot_fixture()

        self.source = self.root / "source-d110.img"
        self.key = self.root / "recovery-key.pub"
        self._write_private(self.source, self.source_image)
        self._write_private(self.key, self._ed25519_key())

    @staticmethod
    def _wire_string(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    @classmethod
    def _ed25519_key(cls) -> bytes:
        blob = cls._wire_string(b"ssh-ed25519") + cls._wire_string(bytes(range(32)))
        return b"ssh-ed25519 " + base64.b64encode(blob) + b" fixture-comment\n"

    @staticmethod
    def _write_private(path: Path, value: bytes) -> None:
        path.write_bytes(value)
        path.chmod(0o600)

    @staticmethod
    def _pad(value: bytes) -> bytes:
        padding = debug_boot._align(len(value), debug_boot.PAGE_SIZE) - len(value)
        return value + b"\0" * padding

    def _boot_fixture(self) -> tuple[bytes, debug_boot.Profile]:
        header = bytearray(debug_boot.BOOT_HEADER_SIZE)
        header[:8] = debug_boot.BOOT_MAGIC
        struct.pack_into("<I", header, 8, len(self.kernel))
        struct.pack_into("<I", header, 12, 0x00008000)
        struct.pack_into("<I", header, 16, len(self.ramdisk))
        struct.pack_into("<I", header, 20, 0x01000000)
        struct.pack_into("<I", header, 24, 0)
        struct.pack_into("<I", header, 28, 0)
        struct.pack_into("<I", header, 32, 0x00000100)
        struct.pack_into("<I", header, 36, debug_boot.PAGE_SIZE)
        struct.pack_into("<I", header, 40, 2)
        struct.pack_into("<I", header, 44, 0)
        struct.pack_into("<I", header, 1632, 0)
        struct.pack_into("<Q", header, 1636, 0)
        struct.pack_into("<I", header, 1644, debug_boot.BOOT_HEADER_SIZE)
        struct.pack_into("<I", header, 1648, len(self.dtb))
        struct.pack_into("<Q", header, 1652, 0x01F00000)
        debug_boot._encode_cmdline(header, self.cmdline)
        header[debug_boot.BOOT_ID] = debug_boot._boot_id(
            self.kernel, self.ramdisk, self.dtb
        )

        image = (
            bytes(header)
            + b"\0" * (debug_boot.PAGE_SIZE - len(header))
            + self._pad(self.kernel)
            + self._pad(self.ramdisk)
            + self._pad(self.dtb)
        )
        recovery_cmdline = self.cmdline + b" " + debug_boot.DEBUG_TOKEN
        profile = debug_boot.Profile(
            source_size=len(image),
            source_sha256=debug_boot._sha256(image),
            source_cmdline_sha256=debug_boot._sha256(self.cmdline),
            recovery_cmdline_sha256=debug_boot._sha256(recovery_cmdline),
            kernel_sha256=debug_boot._sha256(self.kernel),
            ramdisk_sha256=debug_boot._sha256(self.ramdisk),
            dtb_sha256=debug_boot._sha256(self.dtb),
        )
        return image, profile

    def _canonical_manifest(self, candidate_path: Path, candidate: bytes) -> bytes:
        key, _canonical = debug_boot._key_binding(self.key)
        return debug_boot._manifest(
            self.source.name, candidate_path.name, candidate, self.profile, key
        )

    def test_transform_is_exactly_the_pinned_cmdline_only_change(self) -> None:
        candidate = debug_boot._transform(self.source_image, self.profile)

        expected_header = bytearray(self.source_image[: debug_boot.BOOT_HEADER_SIZE])
        debug_boot._encode_cmdline(
            expected_header, self.cmdline + b" " + debug_boot.DEBUG_TOKEN
        )
        expected = (
            bytes(expected_header)
            + self.source_image[debug_boot.BOOT_HEADER_SIZE :]
        )

        self.assertEqual(candidate, expected)
        self.assertEqual(
            debug_boot._decode_cmdline(candidate[: debug_boot.BOOT_HEADER_SIZE]),
            self.cmdline + b" " + debug_boot.DEBUG_TOKEN,
        )
        allowed = set(
            range(debug_boot.CMDLINE_FIRST.start, debug_boot.CMDLINE_FIRST.stop)
        )
        allowed.update(
            range(debug_boot.CMDLINE_EXTRA.start, debug_boot.CMDLINE_EXTRA.stop)
        )
        changed = {
            offset
            for offset, (source_byte, candidate_byte) in enumerate(
                zip(self.source_image, candidate, strict=True)
            )
            if source_byte != candidate_byte
        }
        self.assertTrue(changed)
        self.assertLessEqual(changed, allowed)

    def test_transform_preserves_payload_boot_id_and_total_size(self) -> None:
        candidate = debug_boot._transform(self.source_image, self.profile)

        self.assertEqual(len(candidate), len(self.source_image))
        self.assertEqual(
            candidate[debug_boot.PAGE_SIZE :],
            self.source_image[debug_boot.PAGE_SIZE :],
        )
        self.assertEqual(
            candidate[debug_boot.BOOT_ID], self.source_image[debug_boot.BOOT_ID]
        )

    def test_pinned_noncanonical_source_spacing_is_preserved_verbatim(self) -> None:
        self.cmdline = b"console=ttyMSM0  androidboot.hardware=qcom quiet"
        source_image, profile = self._boot_fixture()

        with self.assertRaisesRegex(
            debug_boot.RecoveryError, "spacing is not canonical"
        ):
            debug_boot._decode_cmdline(source_image[: debug_boot.BOOT_HEADER_SIZE])

        candidate = debug_boot._transform(source_image, profile)
        recovered = debug_boot._decode_cmdline(
            candidate[: debug_boot.BOOT_HEADER_SIZE],
            require_canonical_spacing=False,
        )
        self.assertEqual(
            recovered,
            self.cmdline + b" " + debug_boot.DEBUG_TOKEN,
        )

    def test_source_tampering_is_rejected(self) -> None:
        tampered = bytearray(self.source_image)
        tampered[debug_boot.PAGE_SIZE + 1] ^= 1

        with self.assertRaisesRegex(
            debug_boot.RecoveryError, "source D110 image identity mismatch"
        ):
            debug_boot._transform(bytes(tampered), self.profile)

    def test_candidate_tampering_is_rejected_by_verify(self) -> None:
        expected = debug_boot._transform(self.source_image, self.profile)
        candidate_path = self.root / "candidate.img"
        manifest_path = self.root / "candidate.manifest.json"
        tampered = bytearray(expected)
        tampered[debug_boot.PAGE_SIZE + 1] ^= 1
        self._write_private(candidate_path, bytes(tampered))
        self._write_private(
            manifest_path, self._canonical_manifest(candidate_path, expected)
        )

        with mock.patch.object(debug_boot, "PRODUCTION", self.profile):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "differs from the exact transformation"
            ):
                debug_boot.verify(
                    self.source, self.key, candidate_path, manifest_path
                )

    def test_non_ed25519_authorized_key_is_rejected(self) -> None:
        rsa_blob = self._wire_string(b"ssh-rsa") + self._wire_string(b"fixture-rsa")
        rsa_key = self.root / "rsa.pub"
        self._write_private(
            rsa_key, b"ssh-rsa " + base64.b64encode(rsa_blob) + b" fixture\n"
        )

        with self.assertRaisesRegex(
            debug_boot.RecoveryError, "public key is not Ed25519"
        ):
            debug_boot._key_binding(rsa_key)

    def test_publication_is_complete_and_mode_0600(self) -> None:
        output = self.root / "candidate.img"
        manifest_path = self.root / "candidate.manifest.json"
        candidate = b"candidate bytes"
        manifest = b'{"fixture":true}\n'

        debug_boot._publish_pair(output, candidate, manifest_path, manifest)

        for path, expected in ((output, candidate), (manifest_path, manifest)):
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
            self.assertEqual(metadata.st_nlink, 1)
            self.assertEqual(path.read_bytes(), expected)
        self.assertEqual(list(self.root.glob(".d111-*-*")), [])

    def test_publication_rolls_back_both_targets_if_second_link_fails(self) -> None:
        output = self.root / "candidate.img"
        manifest_path = self.root / "candidate.manifest.json"
        real_link = os.link
        link_count = 0

        def fail_second_link(
            source: os.PathLike[str] | str,
            destination: os.PathLike[str] | str,
            *,
            src_dir_fd: int | None = None,
            dst_dir_fd: int | None = None,
            follow_symlinks: bool = True,
        ) -> None:
            nonlocal link_count
            link_count += 1
            if link_count == 2:
                raise OSError("synthetic second publication failure")
            real_link(
                source,
                destination,
                src_dir_fd=src_dir_fd,
                dst_dir_fd=dst_dir_fd,
                follow_symlinks=follow_symlinks,
            )

        with mock.patch.object(debug_boot.os, "link", side_effect=fail_second_link):
            with self.assertRaisesRegex(
                OSError, "synthetic second publication failure"
            ):
                debug_boot._publish_pair(
                    output, b"candidate", manifest_path, b"manifest"
                )

        self.assertFalse(output.exists())
        self.assertFalse(manifest_path.exists())
        self.assertEqual(list(self.root.glob(".d111-*-*")), [])

    def test_existing_target_is_refused_without_overwrite(self) -> None:
        output = self.root / "candidate.img"
        manifest_path = self.root / "candidate.manifest.json"

        for existing in (output, manifest_path):
            with self.subTest(existing=existing.name):
                for target in (output, manifest_path):
                    if target.exists() or target.is_symlink():
                        target.unlink()
                self._write_private(existing, b"preserve me")

                with self.assertRaisesRegex(
                    debug_boot.RecoveryError, "output target already exists"
                ):
                    debug_boot._publish_pair(
                        output, b"candidate", manifest_path, b"manifest"
                    )

                self.assertEqual(existing.read_bytes(), b"preserve me")
                other = manifest_path if existing == output else output
                self.assertFalse(other.exists())

    def test_symlinked_source_key_and_candidate_are_rejected(self) -> None:
        source_link = self.root / "source-link.img"
        key_link = self.root / "key-link.pub"
        source_link.symlink_to(self.source)
        key_link.symlink_to(self.key)

        with self.subTest(kind="source"):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "single-link regular file"
            ):
                debug_boot._derive(source_link, self.key, self.profile)
        with self.subTest(kind="key"):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "single-link regular file"
            ):
                debug_boot._derive(self.source, key_link, self.profile)

        candidate = debug_boot._transform(self.source_image, self.profile)
        real_candidate = self.root / "real-candidate.img"
        linked_candidate = self.root / "candidate-link.img"
        manifest_path = self.root / "candidate-link.manifest.json"
        self._write_private(real_candidate, candidate)
        linked_candidate.symlink_to(real_candidate)
        self._write_private(
            manifest_path, self._canonical_manifest(linked_candidate, candidate)
        )
        with mock.patch.object(debug_boot, "PRODUCTION", self.profile):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "single-link regular file"
            ):
                debug_boot.verify(
                    self.source, self.key, linked_candidate, manifest_path
                )

    def test_hardlinked_source_key_and_candidate_are_rejected(self) -> None:
        source_alias = self.root / "source-hardlink"
        os.link(self.source, source_alias)
        with self.subTest(kind="source"):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "single-link regular file"
            ):
                debug_boot._derive(source_alias, self.key, self.profile)
        source_alias.unlink()

        key_alias = self.root / "key-hardlink"
        os.link(self.key, key_alias)
        with self.subTest(kind="key"):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "single-link regular file"
            ):
                debug_boot._derive(self.source, key_alias, self.profile)
        key_alias.unlink()

        candidate = debug_boot._transform(self.source_image, self.profile)
        real_candidate = self.root / "real-candidate.img"
        hardlinked_candidate = self.root / "candidate-hardlink.img"
        manifest_path = self.root / "candidate-hardlink.manifest.json"
        self._write_private(real_candidate, candidate)
        os.link(real_candidate, hardlinked_candidate)
        self._write_private(
            manifest_path,
            self._canonical_manifest(hardlinked_candidate, candidate),
        )
        with mock.patch.object(debug_boot, "PRODUCTION", self.profile):
            with self.assertRaisesRegex(
                debug_boot.RecoveryError, "single-link regular file"
            ):
                debug_boot.verify(
                    self.source, self.key, hardlinked_candidate, manifest_path
                )

    def test_existing_symlink_or_hardlink_output_is_refused(self) -> None:
        backing = self.root / "backing"
        self._write_private(backing, b"preserve me")

        for kind in ("symlink", "hardlink"):
            with self.subTest(kind=kind):
                output = self.root / f"candidate-{kind}.img"
                manifest_path = self.root / f"candidate-{kind}.manifest.json"
                if kind == "symlink":
                    output.symlink_to(backing)
                else:
                    os.link(backing, output)

                with self.assertRaisesRegex(
                    debug_boot.RecoveryError, "output target already exists"
                ):
                    debug_boot._publish_pair(
                        output, b"candidate", manifest_path, b"manifest"
                    )

                self.assertEqual(backing.read_bytes(), b"preserve me")
                self.assertFalse(manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
