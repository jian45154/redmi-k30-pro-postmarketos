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
import re
import subprocess
import tempfile
import unittest

REPO = Path(__file__).resolve().parents[2]

_TREE_TOOLS_CACHE: bool | None = None


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


def _probe_tree_snapshot_tools() -> bool:
    """Check the exact host-tool behaviors snapshot_tree() depends on."""
    if not Path("/usr/bin/getfattr").exists():
        return False
    with tempfile.TemporaryDirectory() as temporary:
        lsattr = subprocess.run(
            ["/usr/bin/lsattr", "-d", temporary],
            capture_output=True,
            text=True,
            check=False,
        )
        field = lsattr.stdout.split(None, 1)[0] if lsattr.stdout.strip() else ""
        if lsattr.returncode != 0 or re.fullmatch(r"[A-Za-z-]{22}", field) is None:
            return False
        stat = subprocess.run(
            ["stat", "-c", "%a:%u:%g:%h:%s:%t:%T:%r", temporary],
            capture_output=True,
            text=True,
            check=False,
        )
        rendered = stat.stdout.strip()
        if stat.returncode != 0 or rendered.count(":") != 7 or "%" in rendered:
            return False
    return True


def require_tree_snapshot_tools() -> None:
    global _TREE_TOOLS_CACHE
    if _TREE_TOOLS_CACHE is None:
        _TREE_TOOLS_CACHE = _probe_tree_snapshot_tools()
    require(
        _TREE_TOOLS_CACHE,
        "host stat/lsattr/getfattr behavior differs from the injector's "
        "pinned snapshot_tree expectations",
    )
