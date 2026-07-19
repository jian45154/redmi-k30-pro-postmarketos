"""Fail-closed staging of the pinned pmaports tree for the lmi P1 build."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat

from .common import GateError, run, sha256_file, write_json


_COMMAND_TIMEOUT = 120
_GIT = "/usr/bin/git"
_SYSTEM_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"
_OVERLAY_PACKAGES = ("device-xiaomi-lmi", "linux-xiaomi-lmi")
_PATCHED_FILES = (
    "main/postmarketos-initramfs/APKBUILD",
    "main/postmarketos-initramfs/init_2nd.sh",
    "main/postmarketos-initramfs/init_functions.sh",
)


def _git_environment() -> dict[str, str]:
    return {
        "HOME": "/root",
        "USER": "root",
        "LOGNAME": "root",
        "SHELL": "/bin/sh",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "TMPDIR": "/tmp",
        "TERM": "dumb",
        "PATH": _SYSTEM_PATH,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }


def _git_prefix(repository: Path) -> tuple[Path, list[str]]:
    try:
        resolved = repository.resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve Git repository: {error}") from None
    if not resolved.is_dir():
        raise GateError(f"Git repository is not a directory: {resolved}")
    return resolved, [
        _GIT,
        "-c",
        f"safe.directory={resolved}",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
    ]


def _git_output(repository: Path, *arguments: str, check: bool = True) -> str:
    resolved, prefix = _git_prefix(repository)
    completed = run(
        [*prefix, "-C", str(resolved), *arguments],
        timeout=_COMMAND_TIMEOUT,
        env=_git_environment(),
        check=check,
    )
    return completed.stdout


def _git(repository: Path, *arguments: str) -> str:
    return _git_output(repository, *arguments).strip()


def _nul_records(value: str, label: str) -> list[str]:
    if not value:
        return []
    if not value.endswith("\0"):
        raise GateError(f"{label} was not NUL terminated")
    return value[:-1].split("\0")


def _reject_replace_refs(repository: Path, label: str) -> None:
    refs = _git_output(
        repository,
        "for-each-ref",
        "--format=%(refname)",
        "refs/replace",
    ).splitlines()
    if refs:
        raise GateError(f"{label} contains replace refs")


def _reject_special_index_flags(repository: Path, label: str) -> None:
    records = _nul_records(
        _git_output(repository, "ls-files", "-v", "-z"),
        f"{label} index flag inventory",
    )
    special = [record for record in records if not record.startswith("H ")]
    if special:
        raise GateError(f"{label} contains special index flags")


def _require_sha1_repository(repository: Path, label: str) -> None:
    object_format = _git(repository, "rev-parse", "--show-object-format")
    if object_format != "sha1":
        raise GateError(f"{label} Git object format must be sha1, got {object_format!r}")


def _safe_git_path(relative: str, label: str) -> None:
    if (
        not relative
        or relative.startswith("/")
        or "\0" in relative
        or any(part in {"", ".", ".."} for part in relative.split("/"))
    ):
        raise GateError(f"{label} contains an unsafe Git path")


def _git_tree(repository: Path, commit: str, label: str) -> dict[str, tuple[str, str]]:
    records = _nul_records(
        _git_output(repository, "ls-tree", "-r", "--full-tree", "-z", commit),
        f"{label} tree inventory",
    )
    result: dict[str, tuple[str, str]] = {}
    for record in records:
        try:
            header, relative = record.split("\t", 1)
            mode, kind, object_id = header.split(" ")
        except ValueError:
            raise GateError(f"{label} tree inventory is malformed") from None
        _safe_git_path(relative, label)
        if kind != "blob" or mode not in {"100644", "100755", "120000"}:
            raise GateError(
                f"{label} tree contains an unsupported entry: {relative} {mode} {kind}"
            )
        if object_id == "0" * 40 or len(object_id) != 40:
            raise GateError(f"{label} tree contains an invalid object ID")
        if relative in result:
            raise GateError(f"{label} tree contains a duplicate path: {relative}")
        result[relative] = (mode, object_id)
    if not result:
        raise GateError(f"{label} pinned tree is empty")
    return result


def _expected_directories(paths: set[str]) -> set[str]:
    directories: set[str] = set()
    for relative in paths:
        parts = relative.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    return directories


def _blob_ids(payload: bytes) -> tuple[str, str]:
    framed = b"blob " + str(len(payload)).encode("ascii") + b"\0" + payload
    return hashlib.sha1(framed, usedforsecurity=False).hexdigest(), hashlib.sha256(
        payload
    ).hexdigest()


def _stat_identity(value: os.stat_result) -> tuple[int, int, int, int, int, int]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _stream_blob_ids(path: Path, initial: os.stat_result, label: str) -> tuple[str, str]:
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha1.update(b"blob " + str(initial.st_size).encode("ascii") + b"\0")
    sha256 = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            if _stat_identity(opened) != _stat_identity(initial):
                raise GateError(f"{label} changed before hashing")
            while True:
                block = stream.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                sha1.update(block)
                sha256.update(block)
            finished = os.fstat(stream.fileno())
    except OSError as error:
        raise GateError(f"cannot stream {label}: {error}") from None
    try:
        final = path.lstat()
    except OSError as error:
        raise GateError(f"cannot restat {label}: {error}") from None
    expected = _stat_identity(initial)
    if (
        total != initial.st_size
        or _stat_identity(finished) != expected
        or _stat_identity(final) != expected
    ):
        raise GateError(f"{label} changed while hashing")
    return sha1.hexdigest(), sha256.hexdigest()


def _physical_tree(
    root: Path, label: str
) -> tuple[dict[str, tuple[str, str, str]], set[str]]:
    if root.is_symlink() or not root.is_dir():
        raise GateError(f"{label} must be a real directory")
    files: dict[str, tuple[str, str, str]] = {}
    directories: set[str] = set()
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise GateError(f"cannot inspect {label}: {error}") from None
        for entry in entries:
            path = Path(entry.path)
            relative = path.relative_to(root).as_posix()
            if directory == root and entry.name == ".git":
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    raise GateError(f"{label} .git must be a real directory")
                continue
            _safe_git_path(relative, label)
            try:
                initial = path.lstat()
                mode = initial.st_mode
                if stat.S_ISDIR(mode):
                    directories.add(relative)
                    pending.append(path)
                    continue
                if stat.S_ISLNK(mode):
                    payload = os.readlink(path).encode(
                        "utf-8", errors="surrogateescape"
                    )
                    git_mode = "120000"
                elif stat.S_ISREG(mode):
                    git_mode = "100755" if mode & 0o111 else "100644"
                    object_id, digest = _stream_blob_ids(
                        path, initial, f"{label} entry {relative}"
                    )
                else:
                    raise GateError(f"{label} contains a special entry: {relative}")
            except (OSError, UnicodeError) as error:
                raise GateError(f"cannot inspect {label} entry {relative}: {error}") from None
            if stat.S_ISLNK(mode):
                object_id, digest = _blob_ids(payload)
            files[relative] = (git_mode, object_id, digest)
    return files, directories


def _verify_physical_checkout(repository: Path, commit: str, label: str) -> None:
    _reject_replace_refs(repository, label)
    _reject_special_index_flags(repository, label)
    _require_sha1_repository(repository, label)
    head = _git(repository, "rev-parse", "--verify", "HEAD")
    if head != commit:
        raise GateError(f"{label} HEAD mismatch: expected {commit}, got {head}")
    expected = _git_tree(repository, commit, label)
    actual, directories = _physical_tree(repository, label)
    if set(actual) != set(expected):
        raise GateError(
            f"{label} physical path inventory mismatch: "
            f"missing {sorted(set(expected) - set(actual))!r}, "
            f"extra {sorted(set(actual) - set(expected))!r}"
        )
    if directories != _expected_directories(set(expected)):
        raise GateError(f"{label} physical directory inventory mismatch")
    for relative, (expected_mode, expected_object) in expected.items():
        actual_mode, actual_object, _digest = actual[relative]
        if (actual_mode, actual_object) != (expected_mode, expected_object):
            raise GateError(f"{label} physical bytes or Git mode mismatch: {relative}")


def _reject_checkout_filters(repository: Path, commit: str, label: str) -> None:
    attributes = sorted(
        relative
        for relative in _git_tree(repository, commit, label)
        if relative == ".gitattributes" or relative.endswith("/.gitattributes")
    )
    for relative in attributes:
        content = _git_output(repository, "show", f"{commit}:{relative}")
        for line_number, line in enumerate(content.splitlines(), start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for attribute in stripped.split()[1:]:
                name = attribute.lstrip("-!").split("=", 1)[0]
                if name == "filter":
                    raise GateError(
                        f"{label} pinned tree uses checkout filter attributes: "
                        f"{relative}:{line_number}"
                    )


def _secure_checkout(
    source: Path,
    destination: Path,
    commit: str,
    label: str,
    *,
    require_clean_source: bool,
    reject_source_index_flags: bool,
) -> None:
    _reject_replace_refs(source, label + " source")
    if reject_source_index_flags:
        _reject_special_index_flags(source, label + " source")
    _require_sha1_repository(source, label + " source")
    head = _git(source, "rev-parse", "--verify", "HEAD")
    if head != commit:
        raise GateError(
            f"{label} source HEAD mismatch: expected {commit}, got {head}"
        )
    if _git(source, "cat-file", "-t", commit) != "commit":
        raise GateError(f"{label} source commit is not a commit object")
    if require_clean_source:
        changes = _git(source, "status", "--porcelain", "--untracked-files=no")
        if changes:
            raise GateError(f"source has tracked modifications: {changes}")
    _reject_checkout_filters(source, commit, label + " source")

    destination.parent.mkdir(parents=True, exist_ok=True)
    _resolved, prefix = _git_prefix(source)
    run(
        [
            *prefix,
            "clone",
            "--local",
            "--no-hardlinks",
            "--no-checkout",
            "--no-tags",
            str(source.resolve(strict=True)),
            str(destination),
        ],
        timeout=_COMMAND_TIMEOUT,
        env=_git_environment(),
    )
    alternates = destination / ".git/objects/info/alternates"
    if alternates.exists() or alternates.is_symlink():
        raise GateError(f"{label} isolated checkout uses object alternates")
    _reject_replace_refs(destination, label)
    _require_sha1_repository(destination, label)
    _reject_checkout_filters(destination, commit, label)
    _git(destination, "checkout", "--detach", "--force", commit)
    _verify_physical_checkout(destination, commit, label)


def _compare_physical_trees(left: Path, right: Path, label: str) -> None:
    left_files, left_directories = _physical_tree(left, label + " input")
    right_files, right_directories = _physical_tree(right, label + " expected")
    if left_directories != right_directories or left_files != right_files:
        raise GateError(f"{label} physical tree mismatch")


def _tree_entries(root: Path, *, skip_git_directory: bool = False):
    pending = [root]
    while pending:
        directory = pending.pop()
        try:
            entries = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise GateError(f"cannot inspect tree {directory}: {error}") from None
        for entry in entries:
            path = Path(entry.path)
            if skip_git_directory and directory == root and entry.name == ".git":
                continue
            yield path
            if entry.is_dir(follow_symlinks=False):
                pending.append(path)


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _paths_overlap(left: Path, right: Path) -> bool:
    return left == right or _is_within(left, right) or _is_within(right, left)


def _reject_path_overlaps(
    source: Path,
    destination: Path,
    overlay: Path,
    overlay_sources: dict[str, Path],
) -> None:
    resolved = {
        "source": source.resolve(strict=True),
        "destination": destination.resolve(strict=False),
        "overlay": overlay.resolve(strict=True),
        **{
            f"overlay package {name}": path.resolve(strict=True)
            for name, path in overlay_sources.items()
        },
    }
    labels = tuple(resolved)
    for index, left_label in enumerate(labels):
        for right_label in labels[index + 1 :]:
            left = resolved[left_label]
            right = resolved[right_label]
            expected_overlay_child = (
                left_label == "overlay"
                and right_label.startswith("overlay package ")
                and left != right
                and _is_within(right, left)
            )
            if expected_overlay_child:
                continue
            if _paths_overlap(left, right):
                raise GateError(
                    f"path overlap: {left_label}={left} and "
                    f"{right_label}={right}"
                )


def _validate_tree(root: Path, *, skip_git_directory: bool = False) -> None:
    try:
        resolved_root = root.resolve(strict=True)
    except OSError as error:
        raise GateError(f"tree does not resolve: {root}: {error}") from None
    if root.is_symlink() or not root.is_dir():
        raise GateError(f"tree must be a real directory: {root}")

    for path in _tree_entries(root, skip_git_directory=skip_git_directory):
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise GateError(f"cannot inspect tree entry {path}: {error}") from None
        if stat.S_ISLNK(mode):
            target = (path.parent / os.readlink(path)).resolve(strict=False)
            if not _is_within(target, resolved_root):
                raise GateError(f"symlink escapes tree: {path}")
        elif not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise GateError(f"unsupported tree entry: {path}")


def _output_path_must_be_empty(destination: Path) -> None:
    if os.path.lexists(destination) and destination.is_symlink():
        raise GateError(f"output path must not be a symlink: {destination}")
    if destination.exists():
        if not destination.is_dir():
            raise GateError(f"output path is not a directory: {destination}")
        try:
            populated = next(destination.iterdir(), None) is not None
        except OSError as error:
            raise GateError(f"cannot inspect output path {destination}: {error}") from None
        if populated:
            raise GateError(f"output path is not empty: {destination}")


def _overlay_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in _tree_entries(root):
        if not stat.S_ISDIR(path.lstat().st_mode):
            files.append(path)
    return sorted(files)


def _sha256_entry(path: Path) -> str:
    if path.is_symlink():
        target = os.readlink(path).encode("utf-8", errors="surrogateescape")
        return hashlib.sha256(target).hexdigest()
    return sha256_file(path)


def _verify_expected_changes(destination: Path, overlay_files: set[str]) -> set[str]:
    staged = _git(destination, "diff", "--cached", "--name-only")
    if staged:
        raise GateError(f"unexpected staged modification in destination: {staged}")

    tracked_lines = _git(destination, "diff", "--name-status").splitlines()
    expected_tracked = {f"M\t{path}" for path in _PATCHED_FILES}
    if set(tracked_lines) != expected_tracked:
        raise GateError(
            "unexpected tracked modification in destination: "
            f"expected {sorted(expected_tracked)!r}, got {sorted(tracked_lines)!r}"
        )

    ordinary_untracked = set(
        filter(
            None,
            _git(
                destination,
                "ls-files",
                "--others",
                "--exclude-standard",
            ).splitlines(),
        )
    )
    ignored_untracked = set(
        filter(
            None,
            _git(
                destination,
                "ls-files",
                "--others",
                "--ignored",
                "--exclude-standard",
            ).splitlines(),
        )
    )
    untracked = ordinary_untracked | ignored_untracked
    if untracked != overlay_files:
        raise GateError(
            "unexpected untracked file in destination: "
            f"expected {sorted(overlay_files)!r}, got {sorted(untracked)!r}"
        )
    _git(destination, "diff", "--check")
    return set(_PATCHED_FILES) | untracked


def _verify_overlay_content(
    destination: Path, expected: dict[str, tuple[int, str]]
) -> None:
    for relative, (expected_type, expected_digest) in expected.items():
        path = destination / relative
        if not os.path.lexists(path):
            raise GateError(f"overlay file disappeared after copy: {relative}")
        actual_type = stat.S_IFMT(path.lstat().st_mode)
        actual_digest = _sha256_entry(path)
        if (actual_type, actual_digest) != (expected_type, expected_digest):
            raise GateError(f"overlay file changed after copy: {relative}")


def prepare_pmaports(
    source: Path,
    destination: Path,
    commit: str,
    overlay: Path,
    patch: Path,
) -> dict[str, str]:
    """Clone, pin, overlay, patch, verify, and describe an lmi pmaports stage."""

    source = Path(source)
    destination = Path(destination)
    overlay = Path(overlay)
    patch = Path(patch)

    if source.is_symlink():
        raise GateError(f"source root must not be a symlink: {source}")
    if not source.is_dir():
        raise GateError(f"pmaports source is not a directory: {source}")
    if overlay.is_symlink() or not overlay.is_dir():
        raise GateError(f"overlay must be a real directory: {overlay}")

    overlay_sources: dict[str, Path] = {}
    for package_name in _OVERLAY_PACKAGES:
        package = overlay / package_name
        if not package.is_dir() or package.is_symlink():
            raise GateError(f"missing real overlay package directory: {package}")
        _validate_tree(package)
        overlay_sources[package_name] = package

    _reject_path_overlaps(source, destination, overlay, overlay_sources)
    _output_path_must_be_empty(destination)
    if patch.is_symlink() or not patch.is_file():
        raise GateError(f"patch must be a real file: {patch}")

    _secure_checkout(
        source,
        destination,
        commit,
        "pmaports stage",
        require_clean_source=True,
        reject_source_index_flags=True,
    )
    _validate_tree(destination, skip_git_directory=True)

    manifest: dict[str, str] = {"commit": commit}
    expected_overlay_files: set[str] = set()
    expected_overlay_content: dict[str, tuple[int, str]] = {}
    for package_name, package_source in overlay_sources.items():
        package_destination = destination / "device/downstream" / package_name
        if os.path.lexists(package_destination):
            raise GateError(f"overlay destination exists: {package_destination}")
        downstream = package_destination.parent.resolve(strict=True)
        if not _is_within(downstream, destination.resolve(strict=True)):
            raise GateError(f"overlay destination escapes staged tree: {package_destination}")
        shutil.copytree(package_source, package_destination, symlinks=True)
        _validate_tree(package_destination)
        for source_file in _overlay_files(package_source):
            relative_in_package = source_file.relative_to(package_source)
            staged_file = package_destination / relative_in_package
            relative = staged_file.relative_to(destination).as_posix()
            expected_overlay_files.add(relative)
            digest = _sha256_entry(staged_file)
            manifest[relative] = digest
            expected_overlay_content[relative] = (
                stat.S_IFMT(staged_file.lstat().st_mode),
                digest,
            )

    _git_output(destination, "apply", "--check", str(patch.resolve()))
    _git_output(destination, "apply", str(patch.resolve()))
    inventory = _verify_expected_changes(destination, expected_overlay_files)
    _verify_overlay_content(destination, expected_overlay_content)

    for relative in _PATCHED_FILES:
        staged_file = destination / relative
        if staged_file.is_symlink() or not staged_file.is_file():
            raise GateError(f"patched file is not a real file: {relative}")
        manifest[relative] = sha256_file(staged_file)

    manifest_files = set(manifest) - {"commit"}
    if manifest_files != inventory:
        raise GateError(
            "stage inventory is not fully hashed: "
            f"inventory {sorted(inventory)!r}, manifest {sorted(manifest_files)!r}"
        )

    manifest = dict(sorted(manifest.items()))
    write_json(destination / ".lmi-p1-stage.json", manifest)
    return manifest
