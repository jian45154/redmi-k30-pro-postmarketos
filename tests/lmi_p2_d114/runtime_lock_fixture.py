"""Synthetic host view of the tracked WSL fastboot runtime lock.

``deploy._validate_runtime`` verifies the maintainer host against the frozen
``config/lmi-p2-d114/fastboot-wsl-runtime-lock.json``: exact symlink chains,
file identities, and locked subprocess transcripts.  That check can only pass
on the host where the lock was captured, so the portable suite must not touch
the real filesystem or execute the real loader.

``synthetic_runtime_host`` derives, from the lock itself, the filesystem view
a host that exactly matches the lock would present, and serves it at the
validator's three host access points (``Path.lstat``, ``os.readlink``,
``deploy._open_regular``).  Paths outside the lock's runtime closure fall
through to the real filesystem, so repo-root contract files keep their real
open/hash semantics.  The accept path and its command discipline stay
testable on any host; the binding of the lock to the *real* host is covered
separately by ``tests/lmi_p2_d114_hostbound``, which public CI does not run.
"""

from __future__ import annotations

import contextlib
import os
from pathlib import Path, PurePosixPath
import stat
import tempfile
from typing import Any, Iterator
from unittest import mock

from scripts.lmi_p2_d114 import deploy_userdata_wsl as deploy

_DEVICE = 0x51
_EPOCH = 1_750_000_000


def _stat_result(mode: int, inode: int, size: int) -> os.stat_result:
    return os.stat_result(
        (mode, inode, _DEVICE, 1, 0, 0, size, _EPOCH, _EPOCH, _EPOCH)
    )


class _SyntheticHost:
    """Immutable lstat/readlink/open tables derived from one runtime lock."""

    def __init__(self, runtime: dict[str, Any]) -> None:
        links: dict[str, tuple[str, int]] = {}
        regulars: dict[str, tuple[str, int, int]] = {}

        symlink = runtime["symlink"]
        links[symlink["path"]] = (symlink["target"], symlink["lstat_size"])

        interpreter = runtime["interpreter"]
        for entry in interpreter["usrmerge_chain"]:
            links[entry["path"]] = (entry["target"], entry["lstat_size"])
        regulars[interpreter["resolved_path"]] = (
            interpreter["sha256"],
            interpreter["size"],
            int(interpreter["mode"], 8),
        )

        executable = runtime["executable"]
        regulars[executable["path"]] = (
            executable["sha256"],
            executable["size"],
            int(executable["mode"], 8),
        )

        for library in runtime["libraries"]:
            if library["link_target"] is not None:
                links[library["lookup_path"]] = (
                    library["link_target"],
                    len(library["link_target"]),
                )
            regulars[library["resolved_path"]] = (
                library["sha256"],
                library["size"],
                int(library["mode"], 8),
            )

        directories: set[str] = set()
        for path in (*links, *regulars):
            for parent in PurePosixPath(path).parents:
                if str(parent) != "/":
                    directories.add(str(parent))
        directories -= set(links)
        directories -= set(regulars)

        self.stats: dict[str, os.stat_result] = {}
        self.targets: dict[str, str] = {}
        inode = 1000
        for path in sorted(directories):
            inode += 1
            self.stats[path] = _stat_result(stat.S_IFDIR | 0o755, inode, 4096)
        for path, (target, lstat_size) in sorted(links.items()):
            inode += 1
            self.stats[path] = _stat_result(stat.S_IFLNK | 0o777, inode, lstat_size)
            self.targets[path] = target
        self.regulars: dict[str, tuple[str, int, int]] = dict(regulars)
        for path, (_sha256, size, mode) in sorted(regulars.items()):
            inode += 1
            self.stats[path] = _stat_result(stat.S_IFREG | mode, inode, size)


class _SyntheticHeld(deploy.HeldFile):
    """A held runtime file whose fd stat registration dies with it."""

    def __init__(self, *args: Any, registry: dict[int, os.stat_result]) -> None:
        super().__init__(*args)
        self._registry = registry

    def close(self) -> None:
        self._registry.pop(self.descriptor, None)
        super().close()


@contextlib.contextmanager
def synthetic_runtime_host(runtime: dict[str, Any]) -> Iterator[None]:
    """Serve the lock-derived host view beneath ``deploy._validate_runtime``."""

    host = _SyntheticHost(runtime)
    fd_stats: dict[int, os.stat_result] = {}
    real_lstat = Path.lstat
    real_readlink = os.readlink
    real_fstat = os.fstat
    real_open_regular = deploy._open_regular

    def synthetic_lstat(path: Path) -> os.stat_result:
        found = host.stats.get(str(path))
        if found is not None:
            return found
        return real_lstat(path)

    def synthetic_readlink(path, *args, **kwargs):
        found = host.targets.get(str(path))
        if found is not None:
            return found
        return real_readlink(path, *args, **kwargs)

    def synthetic_fstat(descriptor: int) -> os.stat_result:
        found = fd_stats.get(descriptor)
        if found is not None:
            return found
        return real_fstat(descriptor)

    def synthetic_open_regular(
        path: Path,
        root: Path | None,
        label: str,
        *,
        maximum: int | None = None,
    ) -> deploy.HeldFile:
        found = host.stats.get(str(path))
        spec = host.regulars.get(str(path))
        if spec is None:
            return real_open_regular(path, root, label, maximum=maximum)
        sha256, size, _mode = spec
        descriptor, backing = tempfile.mkstemp(prefix="synthetic-runtime-")
        os.unlink(backing)
        fd_stats[descriptor] = found
        return _SyntheticHeld(
            Path(path), descriptor, deploy._identity(found), size, sha256,
            registry=fd_stats,
        )

    with (
        mock.patch.object(Path, "lstat", synthetic_lstat),
        mock.patch.object(os, "readlink", synthetic_readlink),
        mock.patch.object(os, "fstat", synthetic_fstat),
        mock.patch.object(deploy, "_open_regular", synthetic_open_regular),
    ):
        yield


def locked_process_runner(runtime: dict[str, Any]) -> deploy.ProcessRunner:
    """Answer the two locked metadata commands from the lock, run nothing."""

    version_argv = tuple(runtime["execution"]["argv_prefix"]) + ("--version",)
    version_output = ("\n".join(runtime["version_output"]) + "\n").encode("ascii")
    package = runtime["package"]
    dpkg_argv = (
        "/usr/bin/dpkg-query", "-W",
        "-f=${Package}\\t${Version}\\t${Architecture}\\n", "fastboot",
    )
    dpkg_output = (
        f"{package['name']}\t{package['version']}\t{package['architecture']}\n"
    ).encode("ascii")

    def runner(
        argv,
        timeout: int,
        pass_fds: tuple[int, ...],
        environment,
    ) -> deploy.CommandResult:
        if (
            timeout != deploy.QUERY_TIMEOUT_SECONDS
            or pass_fds
            or dict(environment) != deploy.SAFE_ENV
        ):
            raise AssertionError("unexpected runtime metadata invocation contract")
        if tuple(argv) == version_argv:
            return deploy.CommandResult(0, version_output, b"")
        if tuple(argv) == dpkg_argv:
            return deploy.CommandResult(0, dpkg_output, b"")
        raise AssertionError(f"unapproved runtime metadata command: {argv!r}")

    return runner
