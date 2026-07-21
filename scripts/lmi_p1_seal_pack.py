#!/usr/bin/python3
"""Unprivileged, fail-closed producer for lmi P1 seal and request files."""

from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import hashlib
import io
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
from typing import BinaryIO, Callable, Iterator, Sequence, TypeVar
from urllib.parse import urlsplit

if __package__:
    from .lmi_p1 import seal
    from .lmi_p1.common import GateError
    from .lmi_p1.pmaports import (
        _expected_directories,
        _git_index_from_output,
        _git_tree_from_output,
        _physical_tree,
        validate_staged_pmaports,
    )
    from . import lmi_p1_root_launcher as launcher
else:
    # Isolated mode removes the script directory. Restore only this reviewed
    # script's real directory, never a caller-controlled PYTHONPATH.
    sys.path.insert(0, str(Path(__file__).resolve(strict=True).parent))
    from lmi_p1 import seal
    from lmi_p1.common import GateError
    from lmi_p1.pmaports import (
        _expected_directories,
        _git_index_from_output,
        _git_tree_from_output,
        _physical_tree,
        validate_staged_pmaports,
    )
    import lmi_p1_root_launcher as launcher


_GIT = Path("/usr/bin/git")
_GIT_TIMEOUT = 120
_MAX_PMBOOTSTRAP_METADATA = 16 * 1024 * 1024
_RENAME_NOREPLACE = 1
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
_AUTHORITATIVE_REMOTES = {
    "project": "https://github.com/jian45154/redmi-k30-pro-postmarketos.git",
    "pmbootstrap": "https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git",
    "pmaports": "https://gitlab.postmarketos.org/postmarketOS/pmaports.git",
}
_GIT_ADMIN_TOP = frozenset({"HEAD", "config", "index", "objects", "refs"})
_T = TypeVar("_T")


@dataclass(frozen=True)
class _GitBinding:
    fd: int
    metadata: os.stat_result


@dataclass(frozen=True)
class _GitAdminProfile:
    commit: str
    remote: str
    root_identity: tuple[int, ...]
    git_identity: tuple[int, ...]
    head_identity: tuple[int, ...]
    config_identity: tuple[int, ...]
    index_identity: tuple[int, ...]
    objects_identity: tuple[int, ...]
    refs_identity: tuple[int, ...]


class _PublicationInterrupted(BaseException):
    """A catchable termination signal received inside the publication boundary."""


class _PublicationSignalBoundary:
    """Keep catchable termination signals inside the cleanup/revalidation scope."""

    def __init__(self) -> None:
        self.signals = frozenset(
            value
            for name in ("SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT")
            if isinstance((value := getattr(signal, name, None)), int)
        )
        self.previous_mask: set[signal.Signals] | None = None
        self.previous_handlers: dict[int, object] = {}

    @staticmethod
    def _interrupt(_number: int, _frame: object) -> None:
        raise _PublicationInterrupted()

    def __enter__(self) -> "_PublicationSignalBoundary":
        if (
            not self.signals
            or not hasattr(signal, "pthread_sigmask")
            or not hasattr(signal, "SIG_BLOCK")
            or not hasattr(signal, "SIG_SETMASK")
        ):
            raise GateError("catchable publication signal control is unavailable")
        try:
            self.previous_mask = signal.pthread_sigmask(
                signal.SIG_BLOCK, self.signals
            )
            for number in self.signals:
                self.previous_handlers[number] = signal.getsignal(number)
                signal.signal(number, self._interrupt)
        except (OSError, RuntimeError, ValueError):
            self._restore()
            raise GateError("could not establish the publication signal boundary") from None
        return self

    def activate(self) -> None:
        if self.previous_mask is None:
            raise GateError("publication signal boundary is not initialized")
        signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)

    def block(self) -> None:
        signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)

    def _restore(self) -> None:
        try:
            signal.pthread_sigmask(signal.SIG_BLOCK, self.signals)
        except (AttributeError, OSError, RuntimeError, ValueError):
            pass
        for number, handler in self.previous_handlers.items():
            try:
                signal.signal(number, handler)
            except (OSError, RuntimeError, ValueError):
                pass
        if self.previous_mask is not None:
            try:
                signal.pthread_sigmask(signal.SIG_SETMASK, self.previous_mask)
            except (OSError, RuntimeError, ValueError):
                pass

    def __exit__(self, _kind: object, _value: object, _traceback: object) -> None:
        self.block()
        self._restore()


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return seal._metadata_identity(metadata)  # type: ignore[attr-defined]


def _directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
    )


def _output_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
    )


def _inode_identity(metadata: os.stat_result) -> tuple[int, int]:
    return metadata.st_dev, metadata.st_ino


def _absolute(path: Path, label: str) -> Path:
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise GateError(f"{label} must be an absolute normalized path")
    try:
        before = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve {label}: errno {error.errno or 'unknown'}") from None
    if stat.S_ISLNK(before.st_mode) or resolved != path:
        raise GateError(f"{label} must not traverse or name a symlink")
    return path


def _preflight_sources(sources: seal.SealSources) -> seal.SealSources:
    directories = {"project", "pmbootstrap", "pmaports", "offline_cache"}
    values: dict[str, Path] = {}
    for label in (
        "project",
        "pmbootstrap",
        "pmaports",
        "offline_cache",
        "authorized_key",
        "source_lock",
    ):
        path = _absolute(Path(getattr(sources, label)), label.replace("_", " "))
        metadata = path.lstat()
        if label in directories:
            valid = stat.S_ISDIR(metadata.st_mode)
        else:
            valid = stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1
        if not valid:
            raise GateError(f"{label.replace('_', ' ')} has an unsafe type or link count")
        seal._check_owner_and_mode(  # type: ignore[attr-defined]
            path,
            metadata,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
        values[label] = path
    directory_values = [values[label] for label in directories]
    for index, left in enumerate(directory_values):
        for right in directory_values[index + 1 :]:
            if left == right or left in right.parents or right in left.parents:
                raise GateError("seal directory inputs overlap")
    for label in ("authorized_key", "source_lock"):
        if any(root in values[label].parents for root in directory_values):
            raise GateError(f"{label.replace('_', ' ')} overlaps a directory input")
    checked = seal.SealSources(**values)
    # Reuse the packer's complete metadata inventory before invoking Git. This
    # rejects special files, hardlinks, xattrs and writable/foreign metadata;
    # pack_seal_stream repeats it authoritatively immediately before writing.
    seal._source_records(  # type: ignore[attr-defined]
        checked,
        expected_uid=os.geteuid(),
        expected_gid=os.getegid(),
    )
    return checked


def _git_environment() -> dict[str, str]:
    return {
        "HOME": "/nonexistent",
        "USER": "lmi-p1-seal-producer",
        "LOGNAME": "lmi-p1-seal-producer",
        "SHELL": "/bin/sh",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/nonexistent",
        "XDG_CONFIG_HOME": "/nonexistent",
        "XDG_DATA_HOME": "/nonexistent",
        "PATH": "/usr/bin:/bin",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_OPTIONAL_LOCKS": "0",
    }


@contextmanager
def _bound_git() -> Iterator[_GitBinding]:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        before = _GIT.lstat()
        descriptor = os.open(_GIT, flags)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise GateError(f"could not bind /usr/bin/git: errno {error.errno or 'unknown'}") from None
    try:
        if (
            _GIT != Path("/usr/bin/git")
            or not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or not opened.st_mode & stat.S_IXUSR
            or stat.S_IMODE(opened.st_mode) & 0o022
            or opened.st_uid == os.geteuid()
            or _identity(before) != _identity(opened)
            or not Path(f"/proc/self/fd/{descriptor}").exists()
        ):
            raise GateError("/usr/bin/git has unsafe metadata or cannot be fd-bound")
        yield _GitBinding(descriptor, opened)
        if _identity(_GIT.lstat()) != _identity(opened):
            raise GateError("/usr/bin/git changed during inspection")
    finally:
        os.close(descriptor)


def _git_run(
    binding: _GitBinding,
    repository: Path,
    arguments: Sequence[str],
    operation: str,
    *,
    statuses: frozenset[int] = frozenset({0}),
    discard: bool = False,
) -> bytes:
    command = [
        str(_GIT),
        "-c",
        f"safe.directory={repository}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.preloadIndex=false",
        "-c",
        "protocol.allow=never",
        "-c",
        "core.attributesFile=/dev/null",
        "-c",
        "core.excludesFile=/dev/null",
        "-c",
        "diff.external=/usr/bin/false",
        "-c",
        "status.renames=false",
        "-C",
        str(repository),
        *arguments,
    ]
    try:
        completed = subprocess.run(
            command,
            executable=f"/proc/self/fd/{binding.fd}",
            pass_fds=(binding.fd,),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if discard else subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=_git_environment(),
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise GateError(f"Git {operation} timed out") from None
    except OSError as error:
        raise GateError(f"Git {operation} could not start: errno {error.errno or 'unknown'}") from None
    if completed.returncode not in statuses:
        # Never echo untrusted Git output: config or paths could contain secrets.
        raise GateError(f"Git {operation} failed with status {completed.returncode}")
    return b"" if discard else completed.stdout


def _git_ascii(binding: _GitBinding, root: Path, args: Sequence[str], label: str) -> str:
    try:
        return _git_run(binding, root, args, label).decode("ascii", errors="strict").strip()
    except UnicodeError:
        raise GateError(f"Git {label} returned non-ASCII data") from None


def _split_nul(payload: bytes, label: str) -> list[bytes]:
    if not payload:
        return []
    if not payload.endswith(b"\0"):
        raise GateError(f"Git {label} was not NUL terminated")
    return payload[:-1].split(b"\0")


def _authoritative_remote(value: object, label: str) -> str:
    expected = _AUTHORITATIVE_REMOTES.get(label)
    if expected is None:
        raise GateError("unknown authoritative Git repository")
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
        or "%" in value
        or "\\" in value
    ):
        raise GateError(f"{label} origin is not the authoritative canonical URL")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        raise GateError(f"{label} origin is not the authoritative canonical URL") from None
    if (
        value != expected
        or parsed.scheme != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.netloc != urlsplit(expected).netloc
        or parsed.path != urlsplit(expected).path
    ):
        raise GateError(f"{label} origin is not the authoritative canonical URL")
    return value


def _canonical_git_config(label: str) -> bytes:
    remote = _authoritative_remote(_AUTHORITATIVE_REMOTES.get(label), label)
    return (
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "\tfilemode = true\n"
        "\tbare = false\n"
        "\tlogallrefupdates = false\n"
        '[remote "origin"]\n'
        f"\turl = {remote}\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
    ).encode("ascii")


def _read_admin_file(path: Path, maximum: int, label: str) -> tuple[bytes, os.stat_result]:
    try:
        before = path.lstat()
    except OSError as error:
        raise GateError(
            f"{label} Git administrative file is unavailable: errno "
            f"{error.errno or 'unknown'}"
        ) from None
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_uid != os.geteuid()
        or before.st_gid != os.getegid()
        or stat.S_IMODE(before.st_mode) not in {0o600, 0o640, 0o644}
        or seal._xattrs(path)  # type: ignore[attr-defined]
    ):
        raise GateError(f"{label} Git administrative file has unsafe metadata")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(maximum + 1)
            finished = os.fstat(stream.fileno())
        after = path.lstat()
    except OSError as error:
        raise GateError(
            f"could not read {label} Git administrative file: errno "
            f"{error.errno or 'unknown'}"
        ) from None
    if len(payload) > maximum:
        raise GateError(f"{label} Git administrative file exceeds its size limit")
    if not (
        _identity(before)
        == _identity(opened)
        == _identity(finished)
        == _identity(after)
    ):
        raise GateError(f"{label} Git administrative file changed while reading")
    return payload, after


def _real_admin_directory(path: Path, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise GateError(
            f"{label} Git administrative directory is unavailable: errno "
            f"{error.errno or 'unknown'}"
        ) from None
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) not in {0o700, 0o750, 0o755}
        or seal._xattrs(path)  # type: ignore[attr-defined]
    ):
        raise GateError(f"{label} Git administrative directory has unsafe metadata")
    return metadata


def _directory_names(path: Path, label: str) -> tuple[set[str], os.stat_result]:
    before = _real_admin_directory(path, label)
    try:
        names = {entry.name for entry in os.scandir(path)}
        after = path.lstat()
    except OSError as error:
        raise GateError(
            f"could not enumerate {label} Git administration: errno "
            f"{error.errno or 'unknown'}"
        ) from None
    if _identity(before) != _identity(after):
        raise GateError(f"{label} Git administration changed while enumerating")
    return names, after


def _validate_git_admin_profile(root: Path, label: str) -> _GitAdminProfile:
    """Validate a detached, privacy-minimal Git directory without running Git."""

    root_metadata = _real_admin_directory(root, label)
    git_dir = root / ".git"
    try:
        resolved_git_dir = git_dir.resolve(strict=True)
    except OSError as error:
        raise GateError(
            f"{label} Git directory is unavailable: errno {error.errno or 'unknown'}"
        ) from None
    if resolved_git_dir != git_dir:
        raise GateError(f"{label} must use one real in-tree .git directory")
    top_names, git_metadata = _directory_names(git_dir, label)
    if top_names != _GIT_ADMIN_TOP:
        raise GateError(f"{label} Git administration is not privacy-minimal")

    head_payload, head_metadata = _read_admin_file(git_dir / "HEAD", 64, label)
    try:
        commit = head_payload.decode("ascii", errors="strict").removesuffix("\n")
    except UnicodeError:
        raise GateError(f"{label} Git HEAD is malformed") from None
    if head_payload != f"{commit}\n".encode("ascii") or re.fullmatch(
        r"[0-9a-f]{40}", commit
    ) is None:
        raise GateError(f"{label} Git HEAD must be one detached sha1 commit")

    config_payload, config_metadata = _read_admin_file(
        git_dir / "config", 16 * 1024, label
    )
    if config_payload != _canonical_git_config(label):
        raise GateError(f"{label} Git config is not the canonical safe profile")

    _index_payload, index_metadata = _read_admin_file(
        git_dir / "index", 128 * 1024 * 1024, label
    )
    objects_metadata = _real_admin_directory(git_dir / "objects", label)
    refs_names, refs_metadata = _directory_names(git_dir / "refs", label)
    if refs_names != {"heads", "tags"}:
        raise GateError(f"{label} Git refs are not the canonical detached profile")
    for name in ("heads", "tags"):
        names, _metadata = _directory_names(git_dir / "refs" / name, label)
        if names:
            raise GateError(f"{label} Git refs are not the canonical detached profile")
    for relative in ("objects/info/alternates", "objects/info/http-alternates"):
        if os.path.lexists(git_dir / relative):
            raise GateError(f"{label} Git repository uses unsafe object indirection")

    return _GitAdminProfile(
        commit=commit,
        remote=_AUTHORITATIVE_REMOTES[label],
        root_identity=_identity(root_metadata),
        git_identity=_identity(git_metadata),
        head_identity=_identity(head_metadata),
        config_identity=_identity(config_metadata),
        index_identity=_identity(index_metadata),
        objects_identity=_identity(objects_metadata),
        refs_identity=_identity(refs_metadata),
    )


def _git_utf8(
    binding: _GitBinding, root: Path, args: Sequence[str], label: str
) -> str:
    try:
        return _git_run(binding, root, args, label).decode("utf-8", errors="strict")
    except UnicodeError:
        raise GateError(f"Git {label} returned non-UTF-8 data") from None


def _exact_physical_checkout(
    root: Path,
    label: str,
    expected: dict[str, tuple[str, str]],
) -> None:
    actual, directories = _physical_tree(root, label)
    if set(actual) != set(expected):
        raise GateError(f"{label} physical path inventory differs from HEAD")
    if directories != _expected_directories(set(expected)):
        raise GateError(f"{label} physical directory inventory differs from HEAD")
    for relative, (expected_mode, expected_object) in expected.items():
        actual_mode, actual_object, _digest = actual[relative]
        if (actual_mode, actual_object) != (expected_mode, expected_object):
            raise GateError(f"{label} physical bytes or mode differ from HEAD")


def _repository(
    binding: _GitBinding,
    root: Path,
    label: str,
    *,
    staged_commit: str | None = None,
) -> seal.GitProvenance:
    root = _absolute(root, f"{label} Git root")
    profile = _validate_git_admin_profile(root, label)
    git_dir = root / ".git"
    if _git_utf8(binding, root, ["rev-parse", "--show-toplevel"], f"{label} root").strip() != str(root):
        raise GateError(f"{label} path is not its Git worktree root")
    if _git_utf8(binding, root, ["rev-parse", "--absolute-git-dir"], f"{label} git-dir").strip() != str(git_dir):
        raise GateError(f"{label} does not use its in-tree .git directory")
    if _git_ascii(binding, root, ["rev-parse", "--show-object-format"], f"{label} format") != "sha1":
        raise GateError(f"{label} Git object format is not sha1")
    commit = _git_ascii(binding, root, ["rev-parse", "--verify", "HEAD^{commit}"], f"{label} commit")
    tree = _git_ascii(binding, root, ["rev-parse", "--verify", "HEAD^{tree}"], f"{label} tree")
    if (
        commit != profile.commit
        or not re.fullmatch(r"[0-9a-f]{40}", commit)
        or not re.fullmatch(r"[0-9a-f]{40}", tree)
    ):
        raise GateError(f"{label} Git provenance is malformed")
    flags = _split_nul(
        _git_run(binding, root, ["ls-files", "-v", "-z"], f"{label} index flags"),
        f"{label} index flags",
    )
    if any(not record.startswith(b"H ") for record in flags):
        raise GateError(f"{label} Git index contains special flags")
    expected = _git_tree_from_output(
        _git_utf8(
            binding,
            root,
            ["ls-tree", "-r", "--full-tree", "-z", commit],
            f"{label} tree inventory",
        ),
        label,
    )
    index = _git_index_from_output(
        _git_utf8(
            binding,
            root,
            ["ls-files", "--stage", "-z"],
            f"{label} index inventory",
        ),
        label,
    )
    if index != expected:
        raise GateError(f"{label} Git index differs from HEAD")
    if staged_commit is None:
        _exact_physical_checkout(root, label, expected)
    else:
        if staged_commit != commit:
            raise GateError("pmaports source-lock commit differs from HEAD")

        def bound_output(repository: Path, *arguments: str, check: bool = True) -> str:
            if Path(repository) != root or not check:
                raise GateError("pmaports stage requested an unsafe Git operation")
            return _git_utf8(
                binding,
                root,
                list(arguments),
                "pmaports shared stage validation",
            )

        validate_staged_pmaports(
            root,
            staged_commit,
            git_output=bound_output,
        )
    _git_run(
        binding,
        root,
        ["rev-list", "--objects", "--missing=error", commit],
        f"{label} local object closure",
        discard=True,
    )
    if _validate_git_admin_profile(root, label) != profile:
        raise GateError(f"{label} Git administration changed during inspection")
    return seal.GitProvenance(remote=profile.remote, commit=commit, tree=tree)


def _tracked_payload(
    binding: _GitBinding,
    root: Path,
    relative: str,
    mode: str,
    label: str,
) -> bytes:
    records = _split_nul(
        _git_run(
            binding,
            root,
            ["ls-files", "--stage", "-z", "--", relative],
            f"{label} {relative} index binding",
        ),
        f"{label} {relative} index binding",
    )
    if len(records) != 1:
        raise GateError(f"{label} {relative} is not one tracked file")
    try:
        header, path = records[0].split(b"\t", 1)
        index_mode, index_object, stage = header.decode("ascii").split(" ")
    except (UnicodeError, ValueError):
        raise GateError(f"{label} {relative} index binding is malformed") from None
    head_object = _git_ascii(
        binding,
        root,
        ["rev-parse", f"HEAD:{relative}"],
        f"{label} {relative} HEAD binding",
    )
    if (
        path != relative.encode("ascii")
        or index_mode != mode
        or stage != "0"
        or index_object != head_object
    ):
        raise GateError(f"{label} {relative} does not match HEAD")
    payload = seal._read_source_payload(  # type: ignore[attr-defined]
        root / relative, _MAX_PMBOOTSTRAP_METADATA
    )
    digest = hashlib.sha1(usedforsecurity=False)
    digest.update(b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload)
    if digest.hexdigest() != head_object:
        raise GateError(f"{label} {relative} worktree bytes do not match HEAD")
    return payload


def _version(payload: bytes) -> str:
    try:
        module = ast.parse(payload.decode("utf-8", errors="strict"), filename="pmb/__init__.py")
    except (UnicodeError, SyntaxError):
        raise GateError("pmbootstrap version source is not valid UTF-8 Python") from None
    values = [
        statement.value.value
        for statement in module.body
        if isinstance(statement, ast.Assign)
        and len(statement.targets) == 1
        and isinstance(statement.targets[0], ast.Name)
        and statement.targets[0].id == "__version__"
        and isinstance(statement.value, ast.Constant)
        and isinstance(statement.value.value, str)
    ]
    if len(values) != 1 or not _VERSION.fullmatch(values[0]):
        raise GateError("pmbootstrap version source lacks one safe literal __version__")
    return values[0]


def derive_seal_provenance(sources: seal.SealSources, generation: int) -> seal.SealProvenance:
    if type(generation) is not int or generation <= 0:
        raise GateError("seal generation must be a positive integer")
    lock_payload = seal._read_source_payload(  # type: ignore[attr-defined]
        sources.source_lock, 1024 * 1024
    )
    lock = seal._parse_source_lock(lock_payload)  # type: ignore[attr-defined]
    locked_pmbootstrap = lock.get("pmbootstrap")
    locked_pmaports = lock.get("pmaports")
    if (
        lock.get("schema") != "lmi-source-lock/v3"
        or not isinstance(locked_pmbootstrap, dict)
        or not isinstance(locked_pmaports, dict)
    ):
        raise GateError("source lock lacks V3 pmbootstrap or pmaports provenance")
    with _bound_git() as binding:
        project = _repository(binding, sources.project, "project")
        tracked_lock = _tracked_payload(
            binding,
            sources.project,
            "config/lmi-p1/source-lock.json",
            "100644",
            "project",
        )
        if tracked_lock != lock_payload:
            raise GateError("external source-lock bytes differ from tracked project lock")
        pmbootstrap_git = _repository(binding, sources.pmbootstrap, "pmbootstrap")
        locked_pmaports_commit = locked_pmaports.get("commit")
        if (
            not isinstance(locked_pmaports_commit, str)
            or re.fullmatch(r"[0-9a-f]{40}", locked_pmaports_commit) is None
        ):
            raise GateError("source lock pmaports commit is malformed")
        pmaports = _repository(
            binding,
            sources.pmaports,
            "pmaports",
            staged_commit=locked_pmaports_commit,
        )
        entrypoint = _tracked_payload(
            binding,
            sources.pmbootstrap,
            "pmbootstrap.py",
            "100755",
            "pmbootstrap",
        )
        version_source = _tracked_payload(
            binding,
            sources.pmbootstrap,
            "pmb/__init__.py",
            "100644",
            "pmbootstrap",
        )
    pmbootstrap_base = {
        "remote": pmbootstrap_git.remote,
        "commit": pmbootstrap_git.commit,
        "tree": pmbootstrap_git.tree,
    }
    pmaports_value = {
        "remote": pmaports.remote,
        "commit": pmaports.commit,
        "tree": pmaports.tree,
    }
    if any(locked_pmbootstrap.get(key) != value for key, value in pmbootstrap_base.items()):
        raise GateError("pmbootstrap Git provenance does not match source lock")
    if any(locked_pmaports.get(key) != value for key, value in pmaports_value.items()):
        raise GateError("pmaports Git provenance does not match source lock")
    entrypoint_sha256 = hashlib.sha256(entrypoint).hexdigest()
    version = _version(version_source)
    if locked_pmbootstrap.get("entrypoint_sha256") != entrypoint_sha256:
        raise GateError("pmbootstrap entrypoint digest does not match source lock")
    if locked_pmbootstrap.get("version") != version:
        raise GateError("pmbootstrap version does not match source lock")
    return seal.SealProvenance(
        generation=generation,
        project=project,
        pmbootstrap=seal.PmbootstrapProvenance(
            **pmbootstrap_base,
            version=version,
            entrypoint_sha256=entrypoint_sha256,
        ),
        pmaports=pmaports,
    )


def _open_parent(output: Path) -> tuple[Path, str, int, os.stat_result]:
    output = Path(output)
    if not output.is_absolute() or ".." in output.parts or not output.name:
        raise GateError("output must be an absolute normalized file path")
    parent = output.parent
    current = Path("/")
    for part in parent.parts[1:]:
        current /= part
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise GateError("output parent ancestry contains a symlink or non-directory")
        if stat.S_IMODE(metadata.st_mode) & 0o022 and not metadata.st_mode & stat.S_ISVTX:
            raise GateError("output parent ancestry is writable by another account")
    metadata = parent.lstat()
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_gid != os.getegid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or seal._xattrs(parent)  # type: ignore[attr-defined]
    ):
        raise GateError("output parent must be user-owned, mode 0700, and xattr-free")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(parent, flags)
        opened = os.fstat(descriptor)
    except OSError as error:
        raise GateError(f"could not open output parent: errno {error.errno or 'unknown'}") from None
    if _directory_identity(metadata) != _directory_identity(opened):
        os.close(descriptor)
        raise GateError("output parent changed while opening")
    return parent, output.name, descriptor, opened


def _stable_parent(parent: Path, descriptor: int, expected: os.stat_result) -> None:
    try:
        path_metadata = parent.lstat()
        fd_metadata = os.fstat(descriptor)
    except OSError as error:
        raise GateError(f"output parent changed: errno {error.errno or 'unknown'}") from None
    if (
        stat.S_ISLNK(path_metadata.st_mode)
        or _directory_identity(path_metadata) != _directory_identity(expected)
        or _directory_identity(fd_metadata) != _directory_identity(expected)
    ):
        raise GateError("output parent was replaced during publication")


def _absent(parent_fd: int, name: str) -> None:
    try:
        os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError as error:
        raise GateError(f"could not inspect output name: errno {error.errno or 'unknown'}") from None
    raise GateError("output already exists")


def _rename_noreplace(parent_fd: int, source: str, destination: str) -> None:
    try:
        function = ctypes.CDLL(None, use_errno=True).renameat2
    except AttributeError:
        raise GateError("atomic no-replace publication is unavailable") from None
    function.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    function.restype = ctypes.c_int
    if function(
        parent_fd,
        os.fsencode(source),
        parent_fd,
        os.fsencode(destination),
        _RENAME_NOREPLACE,
    ):
        value = ctypes.get_errno()
        if value == errno.EEXIST:
            raise GateError("output appeared concurrently; existing output was preserved")
        raise GateError(f"atomic no-replace publication failed: errno {value or 'unknown'}")


def _unlink_if_ours(
    parent_fd: int, name: str, identity: tuple[int, int]
) -> None:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if _inode_identity(current) == identity:
            os.unlink(name, dir_fd=parent_fd)
    except OSError:
        pass


def _preflight_output(output: Path) -> None:
    _parent, name, descriptor, _metadata = _open_parent(output)
    try:
        _absent(descriptor, name)
    finally:
        os.close(descriptor)


def _publish_new(output: Path, writer: Callable[[BinaryIO], _T]) -> _T:
    with _PublicationSignalBoundary() as signal_boundary:
        parent, output_name, parent_fd, parent_metadata = _open_parent(output)
        temporary: str | None = None
        temporary_fd: int | None = None
        temporary_inode: tuple[int, int] | None = None
        published: tuple[int, ...] | None = None
        published_inode: tuple[int, int] | None = None
        try:
            _absent(parent_fd, output_name)
            for _attempt in range(128):
                temporary = f".{output_name}.tmp-{secrets.token_hex(16)}"
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0)
                )
                try:
                    temporary_fd = os.open(
                        temporary, flags, 0o600, dir_fd=parent_fd
                    )
                    break
                except FileExistsError:
                    continue
            else:
                raise GateError("could not allocate a unique temporary output")
            created = os.fstat(temporary_fd)
            if (
                not stat.S_ISREG(created.st_mode)
                or created.st_nlink != 1
                or created.st_uid != os.geteuid()
                or created.st_gid != os.getegid()
            ):
                raise GateError("temporary output has unsafe initial metadata")
            temporary_inode = _inode_identity(created)
            os.fchmod(temporary_fd, 0o600)
            created = os.fstat(temporary_fd)
            if (
                _inode_identity(created) != temporary_inode
                or not stat.S_ISREG(created.st_mode)
                or created.st_nlink != 1
                or created.st_uid != os.geteuid()
                or created.st_gid != os.getegid()
                or stat.S_IMODE(created.st_mode) != 0o600
                or os.listxattr(temporary_fd)
            ):
                raise GateError("temporary output has unsafe initial metadata")
            signal_boundary.activate()
            stream = os.fdopen(temporary_fd, "wb")
            temporary_fd = None
            with stream:
                os.fchmod(stream.fileno(), 0o600)
                result = writer(stream)
                stream.flush()
                os.fsync(stream.fileno())
                complete = os.fstat(stream.fileno())
                xattrs = list(os.listxattr(stream.fileno()))
            if (
                not stat.S_ISREG(complete.st_mode)
                or complete.st_nlink != 1
                or complete.st_uid != os.geteuid()
                or complete.st_gid != os.getegid()
                or stat.S_IMODE(complete.st_mode) != 0o600
                or xattrs
                or _inode_identity(complete) != temporary_inode
            ):
                raise GateError("temporary output has unsafe metadata")
            published = _output_identity(complete)
            published_inode = _inode_identity(complete)
            _stable_parent(parent, parent_fd, parent_metadata)
            _absent(parent_fd, output_name)
            _rename_noreplace(parent_fd, temporary, output_name)
            temporary = None
            final = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
            if _output_identity(final) != published:
                raise GateError("published output was concurrently replaced")
            _stable_parent(parent, parent_fd, parent_metadata)
            os.fsync(parent_fd)
            final = os.stat(output_name, dir_fd=parent_fd, follow_symlinks=False)
            if _output_identity(final) != published:
                raise GateError("published output changed during parent fsync")
            _stable_parent(parent, parent_fd, parent_metadata)
            # This is the commit point. Signals after it can only leave the
            # already-fsynced, revalidated output, never an uncertain file.
            signal_boundary.block()
            return result
        except BaseException as error:
            # Do not permit a second catchable termination signal to interrupt
            # cleanup after the first failure or after rename.
            signal_boundary.block()
            if temporary is not None and temporary_inode is not None:
                _unlink_if_ours(parent_fd, temporary, temporary_inode)
            if published_inode is not None:
                _unlink_if_ours(parent_fd, output_name, published_inode)
            try:
                os.fsync(parent_fd)
            except OSError:
                pass
            if isinstance(error, _PublicationInterrupted):
                raise GateError("publication interrupted by a termination signal") from None
            raise
        finally:
            if temporary_fd is not None:
                try:
                    os.close(temporary_fd)
                except OSError:
                    pass
            os.close(parent_fd)


def pack_seal(output: Path, sources: seal.SealSources, generation: int) -> str:
    if os.geteuid() == 0:
        raise GateError("seal production must run as an unprivileged account")
    sources = _preflight_sources(sources)
    _preflight_output(output)
    output_path = Path(output)
    for label in ("project", "pmbootstrap", "pmaports", "offline_cache"):
        root = Path(getattr(sources, label))
        if root in output_path.parents:
            raise GateError(f"output must not be placed inside the {label} input")
    provenance = derive_seal_provenance(sources, generation)

    def write(stream: BinaryIO) -> str:
        policy_id = seal.pack_seal_stream(
            stream,
            sources,
            provenance,
            expected_uid=os.geteuid(),
            expected_gid=os.getegid(),
        )
        if derive_seal_provenance(sources, generation) != provenance:
            raise GateError("Git or source-lock provenance changed while packing")
        return policy_id

    return _publish_new(output, write)


def create_request(output: Path, policy_id: str, tag: str) -> None:
    if os.geteuid() == 0:
        raise GateError("request production must run as an unprivileged account")
    request = {
        "policy_id": policy_id,
        "schema": launcher.REQUEST_SCHEMA,
        "tag": tag,
    }
    try:
        framed = launcher.encode_request(request)
        if launcher.parse_request(io.BytesIO(framed)) != request:
            raise GateError("request did not round-trip through the launcher parser")
    except launcher.LauncherError as error:
        raise GateError(f"build request is invalid: {error}") from None

    def write(stream: BinaryIO) -> None:
        view = memoryview(framed)
        while view:
            written = stream.write(view)
            if not isinstance(written, int) or written <= 0:
                raise GateError("request writer made no progress")
            view = view[written:]

    _publish_new(output, write)


def _require_cli_runtime() -> None:
    flags = sys.flags
    if (
        sys.executable != "/usr/bin/python3"
        or flags.isolated != 1
        or flags.no_site != 1
        or flags.dont_write_bytecode != 1
        or flags.ignore_environment != 1
        or getattr(flags, "safe_path", False) is not True
        or flags.optimize != 0
    ):
        raise GateError(
            "seal producer CLI requires /usr/bin/python3 -I -S -B without optimization"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create a private lmi P1 V3 seal stream or reviewed build request"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    pack = commands.add_parser("pack", help="pack one V3 seal stream")
    for option in (
        "project",
        "pmbootstrap",
        "pmaports",
        "offline-cache",
        "authorized-key",
        "source-lock",
    ):
        pack.add_argument(f"--{option}", type=Path, required=True)
    pack.add_argument("--generation", type=int, required=True)
    pack.add_argument("--output", type=Path, required=True)
    request = commands.add_parser(
        "request", help="frame one separately reviewed policy id and candidate tag"
    )
    request.add_argument("--policy-id", required=True)
    request.add_argument("--tag", required=True)
    request.add_argument("--output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        _require_cli_runtime()
        arguments = _parser().parse_args(argv)
        if arguments.command == "pack":
            sources = seal.SealSources(
                project=arguments.project,
                pmbootstrap=arguments.pmbootstrap,
                pmaports=arguments.pmaports,
                offline_cache=arguments.offline_cache,
                authorized_key=arguments.authorized_key,
                source_lock=arguments.source_lock,
            )
            sys.stdout.write(pack_seal(arguments.output, sources, arguments.generation) + "\n")
        else:
            create_request(arguments.output, arguments.policy_id, arguments.tag)
            sys.stdout.write("request-created\n")
    except (GateError, OSError) as error:
        if isinstance(error, OSError):
            message = f"filesystem operation failed: errno {error.errno or 'unknown'}"
        else:
            message = str(error)
        sys.stderr.write(f"lmi-p1 seal producer rejected input: {message}\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
