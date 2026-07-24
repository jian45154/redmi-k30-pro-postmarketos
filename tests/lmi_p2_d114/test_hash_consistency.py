from __future__ import annotations

import unittest

from scripts.lmi_p2_d114 import hash_consistency


class HashConsistencyTests(unittest.TestCase):
    def test_pipeline_hashes_are_cross_file_consistent(self) -> None:
        report = hash_consistency.verify()
        self.assertTrue(
            report.ok(),
            "SHA-256 drift between a value and its single source of truth:\n"
            + "\n".join(report.failures),
        )
        # The registry must actually be checking a meaningful number of pins;
        # a silently-empty registry would pass vacuously.
        self.assertGreaterEqual(report.checked, 40)

    def test_checker_catches_the_keyboard_sha_black_screen_drift(self) -> None:
        # Regression guard for the 2026-07-23 black screen: the session script
        # pinned a stale keyboard SHA that no test cross-checked. Prove the
        # governance checker fails closed when a mirror drifts from its source.
        derived, _ = hash_consistency.registry()
        session_entry = next(e for e in derived if e.label == "session script")
        report = hash_consistency.Report()

        original = hash_consistency._occurs

        def _blind(path, value, _entry=session_entry):
            # Simulate the session mirror no longer pinning the true digest.
            if path == _entry.mirrors[0]:
                return False
            return original(path, value)

        hash_consistency._occurs = _blind
        try:
            hash_consistency.verify_derived(session_entry, report)
        finally:
            hash_consistency._occurs = original
        self.assertFalse(report.ok())
        self.assertTrue(any("session script" in f for f in report.failures))


if __name__ == "__main__":
    unittest.main()
