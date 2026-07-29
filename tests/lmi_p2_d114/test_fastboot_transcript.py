from __future__ import annotations

import unittest

from scripts.lmi_p2_d114 import fastboot_transcript as transcript


# Reconstructed from the captured on-device evidence in
# docs/release/lmi-r6-rootfs-write-result-20260624.md (five sparse chunks,
# every Sending/Writing pair OKAY, footer "Finished. Total time: 45.269s").
# The doc elides the chunk sizes and per-line timings with "..."; the values
# here restore the platform-tools line shape around the captured tokens.
R6_SPARSE_LINES = (
    "Sending sparse 'userdata' 1/5 (262140 KB)          OKAY [  8.520s]",
    "Writing 'userdata'                                 OKAY [  1.284s]",
    "Sending sparse 'userdata' 2/5 (262140 KB)          OKAY [  8.113s]",
    "Writing 'userdata'                                 OKAY [  1.191s]",
    "Sending sparse 'userdata' 3/5 (262140 KB)          OKAY [  8.077s]",
    "Writing 'userdata'                                 OKAY [  1.205s]",
    "Sending sparse 'userdata' 4/5 (262140 KB)          OKAY [  8.302s]",
    "Writing 'userdata'                                 OKAY [  1.187s]",
    "Sending sparse 'userdata' 5/5 (110488 KB)          OKAY [  3.981s]",
    "Writing 'userdata'                                 OKAY [  0.899s]",
    "Finished. Total time: 45.269s",
)
R6_SPARSE = ("\n".join(R6_SPARSE_LINES) + "\n").encode("ascii")

# The confirmed on-device false-negative shape: when the payload fits under
# max-download-size, real fastboot sends the image in one non-sparse
# transfer and prints "Sending 'userdata'" without the "sparse" token.
NONSPARSE_SUCCESS = (
    b"Sending 'userdata' (2109484 KB)                    OKAY [ 47.585s]\n"
    b"Writing 'userdata'                                 OKAY [  0.986s]\n"
    b"Finished. Total time: 48.571s\n"
)


def classify(stderr: bytes, stdout: bytes = b"") -> transcript.Classification:
    return transcript.classify(stdout, stderr)


class ClassifyCompletedTests(unittest.TestCase):
    def test_r6_captured_sparse_ladder_is_completed(self) -> None:
        result = classify(R6_SPARSE)
        self.assertIs(result.outcome, transcript.Outcome.COMPLETED)
        self.assertEqual(result.reason, "SPARSE_TRANSPORT_LADDER_COMPLETE")

    def test_nonsparse_single_transfer_success_is_completed(self) -> None:
        result = classify(NONSPARSE_SUCCESS)
        self.assertIs(result.outcome, transcript.Outcome.COMPLETED)
        self.assertEqual(result.reason, "RAW_TRANSPORT_LADDER_COMPLETE")

    def test_crlf_line_endings_are_tolerated(self) -> None:
        for payload in (R6_SPARSE, NONSPARSE_SUCCESS):
            with self.subTest(payload=payload[:40]):
                crlf = payload.replace(b"\n", b"\r\n")
                self.assertIs(
                    classify(crlf).outcome, transcript.Outcome.COMPLETED
                )

    def test_trailing_whitespace_and_trailing_blank_line_are_tolerated(self) -> None:
        padded = b"".join(
            line + b"  \n" for line in R6_SPARSE.splitlines()
        ) + b"\n"
        self.assertIs(classify(padded).outcome, transcript.Outcome.COMPLETED)
        self.assertIs(
            classify(NONSPARSE_SUCCESS + b"\r\n").outcome,
            transcript.Outcome.COMPLETED,
        )

    def test_missing_final_newline_is_tolerated(self) -> None:
        self.assertIs(
            classify(R6_SPARSE.rstrip(b"\n")).outcome,
            transcript.Outcome.COMPLETED,
        )

    def test_benign_bootloader_info_lines_are_tolerated(self) -> None:
        interleaved = (
            b"(bootloader) Device state: unlocked\n" + NONSPARSE_SUCCESS
        )
        self.assertIs(
            classify(interleaved).outcome, transcript.Outcome.COMPLETED
        )

    def test_single_unnumbered_sparse_pair_remains_completed(self) -> None:
        payload = (
            b"Sending sparse 'userdata' (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  2.000s]\n"
            b"Finished. Total time: 3.000s\n"
        )
        self.assertIs(classify(payload).outcome, transcript.Outcome.COMPLETED)


class ClassifyNotCompletedTests(unittest.TestCase):
    def assertUnknown(self, payload: bytes, reason: str | None = None) -> None:
        result = classify(payload)
        self.assertIs(result.outcome, transcript.Outcome.UNKNOWN, payload)
        if reason is not None:
            self.assertEqual(result.reason, reason, payload)

    def test_partial_sparse_fraction_is_not_completed(self) -> None:
        partial = (
            b"Sending sparse 'userdata' 1/3 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  2.000s]\n"
            b"Finished. Total time: 3.000s\n"
        )
        self.assertUnknown(partial, "SPARSE_FRACTION_INCOMPLETE")

    def test_truncated_ladder_missing_final_write_is_not_completed(self) -> None:
        truncated_lines = R6_SPARSE_LINES[:-2] + (R6_SPARSE_LINES[-1],)
        self.assertUnknown(
            ("\n".join(truncated_lines) + "\n").encode("ascii"),
        )

    def test_out_of_order_or_total_mismatch_fractions_are_not_completed(self) -> None:
        swapped = (
            b"Sending sparse 'userdata' 2/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Sending sparse 'userdata' 1/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Finished. Total time: 4.000s\n"
        )
        self.assertUnknown(swapped, "SPARSE_FRACTION_INCOMPLETE")
        mismatch = (
            b"Sending sparse 'userdata' 1/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Sending sparse 'userdata' 2/3 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Finished. Total time: 4.000s\n"
        )
        self.assertUnknown(mismatch, "SPARSE_FRACTION_INCOMPLETE")

    def test_repeated_unnumbered_transfers_are_not_completed(self) -> None:
        repeated = (
            b"Sending 'userdata' (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Sending 'userdata' (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Finished. Total time: 4.000s\n"
        )
        self.assertUnknown(repeated, "UNNUMBERED_SENDING_REPEATED")

    def test_numbered_raw_transfers_are_not_completed(self) -> None:
        for body in (
            (
                b"Sending 'userdata' 1/1 (123 KB) OKAY [  1.000s]\n"
                b"Writing 'userdata' OKAY [  1.000s]\n"
            ),
            (
                b"Sending 'userdata' 1/2 (123 KB) OKAY [  1.000s]\n"
                b"Writing 'userdata' OKAY [  1.000s]\n"
                b"Sending 'userdata' 2/2 (123 KB) OKAY [  1.000s]\n"
                b"Writing 'userdata' OKAY [  1.000s]\n"
            ),
        ):
            with self.subTest(body=body):
                self.assertUnknown(
                    body + b"Finished. Total time: 4.000s\n",
                    "RAW_SENDING_MUST_BE_SINGLE_UNNUMBERED",
                )

    def test_mixed_sparse_and_raw_sending_is_not_completed(self) -> None:
        mixed = (
            b"Sending sparse 'userdata' 1/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Sending 'userdata' 2/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Finished. Total time: 4.000s\n"
        )
        self.assertUnknown(mixed, "MIXED_SPARSE_AND_RAW_SENDING")

    def test_failed_write_after_transfer_is_not_completed(self) -> None:
        failed = (
            b"Sending sparse 'userdata' 1/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' FAILED (remote: 'flash write failure')\n"
            b"fastboot: error: Command failed\n"
        )
        self.assertUnknown(failed, "TRANSPORT_FAILED_AFTER_TRANSFER_STARTED")

    def test_footer_only_or_empty_transcript_is_not_completed(self) -> None:
        self.assertUnknown(b"Finished. Total time: 1.000s\n")
        self.assertUnknown(b"", "TRANSCRIPT_EMPTY")

    def test_missing_or_repeated_footer_is_not_completed(self) -> None:
        no_footer = b"".join(
            line + b"\n" for line in R6_SPARSE.splitlines()[:-1]
        )
        self.assertUnknown(no_footer, "FINISHED_FOOTER_MISSING")
        self.assertUnknown(
            R6_SPARSE + b"Finished. Total time: 45.269s\n",
            "FINISHED_FOOTER_REPEATED",
        )

    def test_unrecognized_interleaved_line_is_conservatively_unknown(self) -> None:
        noisy = (
            b"Resizing 'userdata'                          OKAY [  0.004s]\n"
            + NONSPARSE_SUCCESS
        )
        self.assertUnknown(noisy, "UNRECOGNIZED_TRANSCRIPT_LINE")

    def test_wrong_partition_is_not_completed(self) -> None:
        wrong = NONSPARSE_SUCCESS.replace(b"'userdata'", b"'system'")
        self.assertUnknown(wrong, "UNRECOGNIZED_TRANSCRIPT_LINE")

    def test_nonempty_stdout_is_not_completed(self) -> None:
        result = transcript.classify(b"noise", NONSPARSE_SUCCESS)
        self.assertIs(result.outcome, transcript.Outcome.UNKNOWN)
        self.assertEqual(result.reason, "STDOUT_NOT_EMPTY")

    def test_non_ascii_transcript_is_not_completed(self) -> None:
        self.assertUnknown(R6_SPARSE + b"\xff", "TRANSCRIPT_NOT_ASCII")

    def test_footer_before_body_is_not_completed(self) -> None:
        reordered = (
            b"Finished. Total time: 3.000s\n"
            b"Sending 'userdata' (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  2.000s]\n"
        )
        self.assertUnknown(reordered)


class ClassifyRefusedTests(unittest.TestCase):
    def test_failed_first_transfer_before_any_write_is_refused(self) -> None:
        refused = (
            b"Sending 'userdata' (2109484 KB) FAILED (remote: 'data too large')\n"
            b"fastboot: error: Command failed\n"
        )
        result = classify(refused)
        self.assertIs(result.outcome, transcript.Outcome.REFUSED)
        self.assertEqual(result.reason, "DEVICE_REFUSED_BEFORE_FIRST_WRITE")

    def test_refusal_shape_with_footer_is_still_refused(self) -> None:
        refused = (
            b"Sending sparse 'userdata' 1/5 (262140 KB) FAILED (remote: 'unknown command')\n"
            b"fastboot: error: Command failed\n"
            b"Finished. Total time: 0.004s\n"
        )
        self.assertIs(classify(refused).outcome, transcript.Outcome.REFUSED)

    def test_failed_later_chunk_is_unknown_not_refused(self) -> None:
        later = (
            b"Sending sparse 'userdata' 1/2 (123 KB) OKAY [  1.000s]\n"
            b"Writing 'userdata' OKAY [  1.000s]\n"
            b"Sending sparse 'userdata' 2/2 (123 KB) FAILED (remote: 'transfer error')\n"
            b"fastboot: error: Command failed\n"
        )
        self.assertIs(classify(later).outcome, transcript.Outcome.UNKNOWN)


class SharedHelperPatternTests(unittest.TestCase):
    SERIAL = "SYNTHETIC-LMI-0001"

    def test_finished_footer_pattern_matches_historical_shapes(self) -> None:
        import re

        pattern = transcript.finished_footer_pattern()
        for text in (
            "Finished. Total time: 45.269s",
            "Finished. Total time: 0.007s\n",
            "Finished. Total time: 3s\r\n",
        ):
            with self.subTest(text=text):
                self.assertIsNotNone(re.fullmatch(pattern, text))
        for text in (
            "finished. total time: 1.0s\n",
            "Finished. Total time: s\n",
            "Finished. Total time: 1.0s extra\n",
        ):
            with self.subTest(text=text):
                self.assertIsNone(re.fullmatch(pattern, text))

    def test_devices_parser_accepts_only_the_observed_exact_shapes(self) -> None:
        accepted = (
            f"{self.SERIAL}\tfastboot\n",
            f"{self.SERIAL}\tfastboot\r\n",
            f"{self.SERIAL}\t fastboot\n\n",
            f"{self.SERIAL}\t fastboot\r\n\r\n",
        )
        for text in accepted:
            with self.subTest(text=text):
                self.assertEqual(transcript.parse_devices(text), self.SERIAL)
        rejected = (
            "",
            f"{self.SERIAL}\tfastboot",
            f"{self.SERIAL}\tfastboot\nSECOND\tfastboot\n",
            f" {self.SERIAL}\tfastboot\n",
            f"{self.SERIAL}\tfastboot\n\n",
            f"{self.SERIAL}\tfastbootd\n",
            f"{self.SERIAL}  fastboot\n",
            f"{self.SERIAL}\t fastboot\r\n\n",
        )
        for text in rejected:
            with self.subTest(text=text):
                self.assertIsNone(transcript.parse_devices(text))

    def test_getvar_parser_accepts_only_exact_shapes(self) -> None:
        self.assertEqual(
            transcript.parse_getvar(
                "product", "(bootloader) product: lmi\nFinished. Total time: 1.25s\n"
            ),
            ("lmi", False),
        )
        self.assertEqual(
            transcript.parse_getvar(
                "product", "product: lmi\nFinished. Total time: 1.25s\n"
            ),
            ("lmi", False),
        )
        self.assertEqual(
            transcript.parse_getvar(
                "is-logical:userdata",
                "getvar:is-logical:userdata   FAILED (remote: 'GetVar Variable Not found')\n"
                "Finished. Total time: 0.001s\n",
                allow_unsupported=True,
            ),
            (None, True),
        )
        for text in (
            "product: lmi\n",
            "product: lmi\nFinished. Total time: 0.1s\nEXTRA\n",
            "getvar:is-logical:userdata FAILED (remote: 'GetVar Variable Not found')\n"
            "Finished. Total time: 0.1s\n",
        ):
            with self.subTest(text=text):
                self.assertIsNone(transcript.parse_getvar("product", text))
        self.assertIsNone(
            transcript.parse_getvar(
                "is-logical:userdata",
                "getvar:is-logical:userdata   FAILED (remote: 'unknown variable')\n"
                "Finished. Total time: 0.1s\n",
                allow_unsupported=True,
            )
        )

    def test_partition_names_are_validated(self) -> None:
        with self.assertRaises(ValueError):
            transcript.classify(b"", b"", partition="User Data")
        with self.assertRaises(ValueError):
            transcript.classify(b"", b"", partition="")


if __name__ == "__main__":
    unittest.main()
