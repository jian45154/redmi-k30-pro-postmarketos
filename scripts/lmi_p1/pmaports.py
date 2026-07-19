"""Fail-closed staging of the pinned pmaports tree for the lmi P1 build."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import stat

from .common import GateError, run, sha256_file, write_json


_COMMAND_TIMEOUT = 120
_OVERLAY_PACKAGES = ("device-xiaomi-lmi", "linux-xiaomi-lmi")
_PATCHED_FILES = (
    "main/postmarketos-initramfs/APKBUILD",
    "main/postmarketos-initramfs/init_2nd.sh",
    "main/postmarketos-initramfs/init_functions.sh",
)


def _git(repository: Path, *arguments: str) -> str:
    completed = run(
        ["git", "-C", str(repository), *arguments],
        timeout=_COMMAND_TIMEOUT,
    )
    return completed.stdout.strip()


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

    source_head = _git(source, "rev-parse", "--verify", "HEAD")
    if source_head != commit:
        raise GateError(f"source HEAD mismatch: expected {commit}, got {source_head}")
    source_changes = _git(source, "status", "--porcelain", "--untracked-files=no")
    if source_changes:
        raise GateError(f"source has tracked modifications: {source_changes}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    run(
        ["git", "clone", "--shared", str(source.resolve()), str(destination)],
        timeout=_COMMAND_TIMEOUT,
    )
    _git(destination, "checkout", "--detach", commit)
    staged_head = _git(destination, "rev-parse", "--verify", "HEAD")
    if staged_head != commit:
        raise GateError(f"staged commit mismatch: expected {commit}, got {staged_head}")
    if _git(destination, "status", "--porcelain"):
        raise GateError("newly cloned destination is dirty")
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

    run(
        ["git", "apply", "--check", str(patch.resolve())],
        timeout=_COMMAND_TIMEOUT,
        cwd=destination,
    )
    run(
        ["git", "apply", str(patch.resolve())],
        timeout=_COMMAND_TIMEOUT,
        cwd=destination,
    )
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
