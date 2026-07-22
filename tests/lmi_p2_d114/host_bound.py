"""Support for tests that need maintainer-host resources.

Several P2-D114 tests validate contracts against resources that only exist
on the maintainer host: the gitignored `private/` build outputs, the pinned
host toolchains (sparse tools, fastboot, bwrap, getfattr), and their exact
ELF runtime closures. On other hosts those tests skip with a reason instead
of erroring, so the portable remainder of the suite still runs in public CI.

Set LMI_REQUIRE_HOST_BOUND_FIXTURES=1 (maintainer environments) to turn a
missing resource back into a hard failure.
"""

from __future__ import annotations

import os
from pathlib import Path
import unittest

REPO = Path(__file__).resolve().parents[2]


def _strict() -> bool:
    return os.environ.get("LMI_REQUIRE_HOST_BOUND_FIXTURES") == "1"


def require(condition: bool, reason: str) -> None:
    if condition:
        return
    if _strict():
        raise AssertionError(f"host-bound requirement missing: {reason}")
    raise unittest.SkipTest(
        f"{reason}; set LMI_REQUIRE_HOST_BOUND_FIXTURES=1 to fail instead"
    )


def require_path(path: Path | str) -> None:
    require(Path(path).exists(), f"host-bound input not present: {path}")
