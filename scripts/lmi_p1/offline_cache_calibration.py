"""One-shot, host-only calibration for a new P1 offline-cache attestation.

This module deliberately lives outside the production promotion runtime.  It
does not alter the canonical promotion attestation or replay report.  A
``prepare`` run emits a private draft for manual review; ``execute`` accepts
only the separately installed canonical calibration authorization and leaves
private candidate production records in a new, one-shot execution bundle.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import hashlib
import inspect
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
from typing import Mapping, Sequence

from .common import GateError
from . import offline_cache


CALIBRATION_AUTHORIZATION_SCHEMA = (
    "lmi-p1-offline-cache-calibration-authorization/v1"
)
_BASE_ATTESTATION_RELATIVE = (
    "config/lmi-p1/offline-cache-promotion-attestation.json"
)
_PROFILE_RELATIVE = "config/lmi-p1/offline-cache-promotion.json"
_CANONICAL_AUTHORIZATION_RELATIVE = (
    "config/lmi-p1/offline-cache-calibration-authorization.json"
)
_CANONICAL_REPLAY_RELATIVE = (
    "config/lmi-p1/offline-cache-promotion-replay.json"
)
_PRIVATE_CALIBRATION_RELATIVE = PurePosixPath("private/lmi-p1/calibration")
_BASE_PUBLISHED_MEMBER_COUNT = 588
_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_MAX_JSON_BYTES = 16 * 1024 * 1024

_PRODUCTION_RUNTIME_PATHS = (
    "scripts/lmi_p1/__init__.py",
    "scripts/lmi_p1/common.py",
    "scripts/lmi_p1/offline_cache.py",
    "scripts/lmi_p1_cli.py",
)
_CALIBRATION_RUNTIME_PATHS = (
    "scripts/lmi_p1/__init__.py",
    "scripts/lmi_p1/common.py",
    "scripts/lmi_p1/offline_cache.py",
    "scripts/lmi_p1/offline_cache_calibration.py",
)

_FIRST_QUARANTINE = "promotion-first.quarantine"
_FIRST_PUBLISHED = "promotion-first.published"
_REPLAY_QUARANTINE = "promotion-replay.quarantine"
_REPLAY_PUBLISHED = "promotion-replay.published"
_FIRST_BOOTSTRAP = ".verifier-first"
_REPLAY_BOOTSTRAP = ".verifier-replay"
_CANDIDATE_REPLAY = "offline-cache-promotion-replay.candidate.json"
_CANDIDATE_ATTESTATION = (
    "offline-cache-promotion-attestation.candidate.json"
)
_SNAPSHOT_DIRECTORY = "authorized-acquisition.snapshot"
_EXECUTION_RECEIPT = "offline-cache-calibration-execution-receipt.json"
CALIBRATION_EXECUTION_RECEIPT_SCHEMA = (
    "lmi-p1-offline-cache-calibration-execution-receipt/v1"
)
_RECEIPT_ASSURANCE = {
    "accepted_output_binding": (
        "accepted outputs are byte-equivalent to the descriptor-held "
        "authorized acquisition snapshot under SHA-256"
    ),
    "promoter_input_semantics": (
        "the unchanged promote_offline_cache implementation reopens an "
        "ordinary pathname; this receipt does not claim that it consumed "
        "the held snapshot inode"
    ),
    "trust_boundary": [
        (
            "same-UID pathname A-B-A substitution for authorization, base "
            "cache, or trusted pmbootstrap is not claimed to be prevented; "
            "those inputs rely on exact byte/hash validation and the "
            "administrative same-UID trust assumption"
        ),
        (
            "same-UID ptrace or process-memory modification and post-exit "
            "evidence rewrite are outside this receipt's assurance"
        ),
        "privileged or kernel compromise is outside this receipt's assurance",
    ],
}

_AUTHORIZATION_FIELDS = frozenset(
    {
        "schema",
        "base_attestation",
        "profile",
        "trusted_pmbootstrap",
        "base_cache",
        "acquisition",
        "execution_bundle",
        "calibration_runtime",
        "runtime_trust",
        "apk_static",
        "openssl_runtime",
    }
)


@dataclass(frozen=True)
class _BaseTrust:
    value: Mapping[str, object]
    payload: bytes
    authorization: offline_cache.PromotionAuthorization


@dataclass(frozen=True)
class _ExecutionState:
    root: Path
    authorization_path: Path
    authorization_payload_sha256: str
    authorization_file: "_HeldAuthorization"
    base: _BaseTrust
    trusted_pmbootstrap: Path
    base_cache: Path
    acquisition: Path
    acquisition_member_count: int
    acquisition_inventory_sha256: str
    bundle: Path
    calibration_runtime: tuple[Mapping[str, str], ...]


@dataclass
class _HeldDirectory:
    path: Path
    descriptor: int
    binding: tuple[int, int, int, int, int]

    def validate(self, *, label: str) -> None:
        try:
            pathname = self.path.lstat()
            opened = os.fstat(self.descriptor)
        except OSError as error:
            raise GateError(f"could not revalidate {label}: {error}") from None
        if (
            offline_cache._directory_binding(pathname) != self.binding
            or offline_cache._directory_binding(opened) != self.binding
        ):
            raise GateError(f"{label} path no longer names its held directory")

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _HeldAuthorization:
    path: Path
    descriptor: int
    metadata_identity: tuple[int, ...]
    size: int
    sha256: str

    def validate(self) -> None:
        metadata, digest = _hash_held_file(
            self.descriptor,
            label="held canonical calibration authorization",
            maximum=_MAX_JSON_BYTES,
        )
        try:
            pathname = self.path.lstat()
        except OSError as error:
            raise GateError(
                f"could not revalidate canonical calibration authorization: {error}"
            ) from None
        if (
            offline_cache._metadata_identity(metadata)
            != self.metadata_identity
            or offline_cache._metadata_identity(pathname)
            != self.metadata_identity
            or metadata.st_size != self.size
            or digest != self.sha256
        ):
            raise GateError(
                "canonical calibration authorization changed or was rebound"
            )

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _HeldSnapshotFile:
    path: str
    descriptor: int
    metadata_identity: tuple[int, ...]
    size: int
    sha256: str

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _AcquisitionSnapshot:
    source: _HeldDirectory
    directory: _HeldDirectory
    files: tuple[_HeldSnapshotFile, ...]
    member_count: int
    inventory_sha256: str

    def close(self) -> None:
        for member in self.files:
            member.close()
        self.directory.close()
        self.source.close()


@dataclass(frozen=True)
class _OfflineBindings:
    verifier_factory: object
    promoter: object
    cache_reader: object


@dataclass(frozen=True)
class _TransactionCallables:
    load_state: object
    create_bundle: object
    create_snapshot: object
    validate_snapshot: object
    promote: object
    revalidate_published: object
    bind_output: object
    revalidate_inputs: object
    candidate_values: object
    write_bundle: object
    receipt: object


@dataclass(frozen=True)
class _CallableGuard:
    name: str
    function: object
    code: object

    def validate(self) -> None:
        if (
            not inspect.isfunction(self.function)
            or self.function.__code__ is not self.code
        ):
            raise GateError(f"captured callable code was rebound: {self.name}")


def _project_root() -> Path:
    try:
        module = Path(__file__).resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve calibration module: {error}") from None
    if len(module.parents) < 3:
        raise GateError("calibration module path has an invalid layout")
    root = module.parents[2]
    expected = root / "scripts/lmi_p1/offline_cache_calibration.py"
    if module != expected:
        raise GateError("calibration module is not executing from its project root")
    return offline_cache._absolute_real_directory(
        root, label="calibration project root"
    )


def _canonical_function(module: object, name: str, source: Path) -> object:
    """Resolve one function only when it is the definition in canonical source."""

    function = getattr(module, name, None)
    if not inspect.isfunction(function):
        raise GateError(f"canonical callable was rebound: {name}")
    try:
        function_source = Path(function.__code__.co_filename).resolve(strict=True)
    except OSError as error:
        raise GateError(f"could not resolve canonical callable {name}: {error}") from None
    if (
        function_source != source
        or function.__name__ != name
        or function.__qualname__ != name
    ):
        raise GateError(f"canonical callable identity mismatch: {name}")
    payload = offline_cache._read_stable_regular_bytes(
        source, label=f"canonical callable source {source}", maximum=_MAX_JSON_BYTES
    )
    try:
        tree = ast.parse(payload.decode("utf-8", errors="strict"))
    except (UnicodeError, SyntaxError) as error:
        raise GateError(f"could not parse canonical callable source: {error}") from None
    definitions = [
        node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == name
    ]
    if (
        len(definitions) != 1
        or function.__code__.co_firstlineno != definitions[0].lineno
    ):
        raise GateError(f"canonical callable definition mismatch: {name}")
    return function


def _resolve_offline_bindings(root: Path) -> _OfflineBindings:
    source = _canonical_path(root, "scripts/lmi_p1/offline_cache.py")
    try:
        module_source = Path(offline_cache.__file__).resolve(strict=True)
    except (OSError, TypeError) as error:
        raise GateError(f"could not resolve offline-cache module: {error}") from None
    if module_source != source:
        raise GateError("offline-cache module is not the canonical project module")
    return _OfflineBindings(
        verifier_factory=_canonical_function(
            offline_cache, "bootstrap_apk_static_verifier", source
        ),
        promoter=_canonical_function(
            offline_cache, "promote_offline_cache", source
        ),
        cache_reader=_canonical_function(
            offline_cache, "read_offline_cache_manifest", source
        ),
    )


def _resolve_local_function(name: str) -> object:
    source = Path(__file__).resolve(strict=True)
    return _canonical_function(sys.modules[__name__], name, source)


def _callable_guard(name: str, function: object) -> _CallableGuard:
    if not inspect.isfunction(function):
        raise GateError(f"captured callable is not a function: {name}")
    return _CallableGuard(
        name,
        function,
        function.__code__,
    )


def _canonical_path(root: Path, relative: str) -> Path:
    return root.joinpath(*PurePosixPath(relative).parts)


def _hash_record(root: Path, relative: str, *, label: str) -> dict[str, str]:
    path = offline_cache._project_regular_file(root, relative, label=label)
    _metadata, digest = offline_cache._hash_stable_regular(
        path, label=label, maximum=_MAX_JSON_BYTES
    )
    return {"path": relative, "sha256": digest}


def _load_base_trust(root: Path) -> _BaseTrust:
    """Validate the current v3 attestation with its exact attested runtime map."""

    attestation_path = _canonical_path(root, _BASE_ATTESTATION_RELATIVE)
    value, payload = offline_cache._read_canonical_json(
        attestation_path, _MAX_JSON_BYTES, "base production attestation"
    )
    attestation = offline_cache._require_exact_fields(
        value,
        offline_cache._ATTESTATION_FIELDS,
        label="base production attestation",
    )
    if attestation["schema"] != offline_cache.PROMOTION_ATTESTATION_SCHEMA:
        raise GateError("base production attestation is not canonical v3")
    producers = offline_cache._require_exact_fields(
        attestation["producer_code"],
        frozenset({"curation", "promotion_runtime"}),
        label="base production producer_code",
    )
    runtime_value = producers["promotion_runtime"]
    if not isinstance(runtime_value, list):
        raise GateError("base production runtime inventory must be a list")
    runtime_paths: list[str] = []
    for index, item in enumerate(runtime_value):
        record = offline_cache._require_exact_fields(
            item,
            frozenset({"path", "sha256"}),
            label=f"base production runtime[{index}]",
        )
        runtime_paths.append(
            offline_cache._safe_relative_path(
                record["path"], label=f"base production runtime[{index}].path"
            )
        )
    if tuple(runtime_paths) != _PRODUCTION_RUNTIME_PATHS:
        raise GateError("base production runtime map is not the exact reviewed map")
    runtime_files = {
        relative: _canonical_path(root, relative)
        for relative in runtime_paths
    }
    authorization = offline_cache._load_promotion_authorization_from_context(
        project_root=root,
        attestation_path=attestation_path,
        runtime_files=runtime_files,
    )
    return _BaseTrust(
        value=dict(attestation),
        payload=payload,
        authorization=authorization,
    )


def _private_relative_directory(root: Path, path: Path, *, label: str) -> tuple[Path, str]:
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise GateError(f"{label} must be an explicit normalized absolute path")
    directory = offline_cache._absolute_real_directory(path, label=label)
    try:
        relative = directory.relative_to(root)
    except ValueError:
        raise GateError(f"{label} must be inside the calibration project") from None
    posix = PurePosixPath(*relative.parts)
    if posix.parts[: len(_PRIVATE_CALIBRATION_RELATIVE.parts)] != (
        _PRIVATE_CALIBRATION_RELATIVE.parts
    ):
        raise GateError(f"{label} must be below private/lmi-p1/calibration")
    return directory, posix.as_posix()


def _path_from_private_record(root: Path, value: object, *, label: str) -> Path:
    relative = offline_cache._safe_relative_path(value, label=f"{label}.path")
    parts = PurePosixPath(relative).parts
    if parts[: len(_PRIVATE_CALIBRATION_RELATIVE.parts)] != (
        _PRIVATE_CALIBRATION_RELATIVE.parts
    ):
        raise GateError(f"{label}.path must be below private/lmi-p1/calibration")
    path = _canonical_path(root, relative)
    directory, actual_relative = _private_relative_directory(root, path, label=label)
    if actual_relative != relative:
        raise GateError(f"{label}.path is not canonical")
    return directory


def _new_private_file(root: Path, path: Path, *, label: str) -> tuple[Path, str]:
    path = Path(path)
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise GateError(f"{label} must be an explicit normalized absolute path")
    try:
        relative_path = path.relative_to(root)
    except ValueError:
        raise GateError(f"{label} must be inside the calibration project") from None
    relative = PurePosixPath(*relative_path.parts)
    if relative.parts[: len(_PRIVATE_CALIBRATION_RELATIVE.parts)] != (
        _PRIVATE_CALIBRATION_RELATIVE.parts
    ):
        raise GateError(f"{label} must be below private/lmi-p1/calibration")
    parent = offline_cache._absolute_real_directory(path.parent, label=f"{label} parent")
    try:
        parent.relative_to(root)
    except ValueError:
        raise GateError(f"{label} parent must remain inside the project") from None
    if os.path.lexists(path):
        raise GateError(f"{label} must be a new absent path")
    return path, relative.as_posix()


def _output_identity(
    verified: offline_cache.VerifiedOfflineCache,
) -> dict[str, object]:
    members = verified.manifest.get("members")
    if not isinstance(members, list):
        raise GateError("validated offline cache has an invalid members inventory")
    return {
        "schema": verified.manifest["schema"],
        "manifest_sha256": verified.manifest_sha256,
        "aggregate_sha256": verified.aggregate_sha256,
        "member_count": len(members),
    }


def _validate_trusted_pmbootstrap(
    base: _BaseTrust, trusted_pmbootstrap: Path
) -> None:
    offline_cache._validate_authorized_pmbootstrap(
        base.authorization, trusted_pmbootstrap
    )
    offline_cache._verify_signer_keys(
        base.authorization.profile, trusted_pmbootstrap
    )


def _validate_base_cache(
    base: _BaseTrust,
    base_cache: Path,
    trusted_pmbootstrap: Path,
    *,
    cache_reader: object,
) -> tuple[offline_cache.VerifiedOfflineCache, dict[str, object]]:
    if not callable(cache_reader):
        raise GateError("offline-cache reader binding is not callable")
    verified = cache_reader(
        base_cache,
        expected_profile=base.authorization.profile,
        trusted_key_root=trusted_pmbootstrap,
    )
    output = _output_identity(verified)
    if output != dict(base.authorization.expected_output):
        raise GateError("base cache differs from the reviewed production output")
    if output["member_count"] != _BASE_PUBLISHED_MEMBER_COUNT:
        raise GateError("base cache is not the reviewed 588-member bootstrap cache")
    return verified, output


def _acquisition_identity(
    base: _BaseTrust, acquisition: Path
) -> tuple[int, str]:
    source_paths = offline_cache._inventory_acquisition(
        acquisition, base.authorization.profile
    )
    count, digest = offline_cache._acquisition_identity(
        acquisition, source_paths
    )
    if (
        count <= base.authorization.acquisition_member_count
        or digest == base.authorization.acquisition_inventory_sha256
    ):
        raise GateError("new acquisition is not a strict successor to the base acquisition")
    return count, digest


def _calibration_runtime(root: Path) -> list[dict[str, str]]:
    return [
        _hash_record(
            root,
            relative,
            label=f"calibration runtime {relative}",
        )
        for relative in _CALIBRATION_RUNTIME_PATHS
    ]


def _execution_bundle_relative(tag: str) -> str:
    if not isinstance(tag, str) or _TAG_RE.fullmatch(tag) is None:
        raise GateError("calibration tag is invalid")
    return (_PRIVATE_CALIBRATION_RELATIVE / tag).as_posix()


def _write_exclusive_payload(path: Path, payload: bytes, *, label: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(0o600)
        metadata = path.lstat()
    except OSError as error:
        raise GateError(f"could not write {label}: {error}") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise GateError(f"{label} is not a private single-link regular file")
    offline_cache._fsync_directory(path.parent)


def _write_exclusive_canonical(path: Path, value: object, *, label: str) -> bytes:
    payload = offline_cache.canonical_json_bytes(value)
    if len(payload) > _MAX_JSON_BYTES:
        raise GateError(f"{label} exceeds its size limit")
    if os.path.lexists(path):
        raise GateError(f"{label} must be a new absent path")
    staged = path.parent / f".{path.name}.stage"
    _write_exclusive_payload(staged, payload, label=f"staged {label}")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = path.parent.lstat()
        descriptor = os.open(path.parent, directory_flags)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(before.st_mode)
            or offline_cache._directory_binding(before)
            != offline_cache._directory_binding(opened)
        ):
            raise GateError(f"{label} parent changed before publication")
        offline_cache._renameat2_noreplace(
            descriptor, staged.name, descriptor, path.name
        )
        os.fsync(descriptor)
        after = path.parent.lstat()
        if (
            offline_cache._directory_binding(before)
            != offline_cache._directory_binding(after)
        ):
            raise GateError(f"{label} parent changed during publication")
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not atomically publish {label}: {error}") from None
    finally:
        if "descriptor" in locals():
            os.close(descriptor)
    parsed, reread = offline_cache._read_canonical_json(
        path, _MAX_JSON_BYTES, label
    )
    if parsed != value or reread != payload:
        raise GateError(f"{label} changed after its exclusive write")
    return payload


def _write_bundle_canonical(
    bundle: _HeldDirectory, name: str, value: object, *, label: str
) -> bytes:
    if PurePosixPath(name).name != name or "\x00" in name:
        raise GateError(f"{label} name is unsafe")
    payload = offline_cache.canonical_json_bytes(value)
    if len(payload) > _MAX_JSON_BYTES:
        raise GateError(f"{label} exceeds its size limit")
    bundle.validate(label="calibration bundle")
    stage_name = f".{name}.stage"
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(stage_name, flags, 0o600, dir_fd=bundle.descriptor)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        offline_cache._renameat2_noreplace(
            bundle.descriptor,
            stage_name,
            bundle.descriptor,
            name,
        )
        os.fsync(bundle.descriptor)
        final_fd = os.open(
            name,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            dir_fd=bundle.descriptor,
        )
        with os.fdopen(final_fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            reread = stream.read(_MAX_JSON_BYTES + 1)
    except OSError as error:
        raise GateError(f"could not atomically write {label}: {error}") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or reread != payload
    ):
        raise GateError(f"{label} changed during its anchored write")
    bundle.validate(label="calibration bundle")
    return payload


def _prepare_calibration(
    root: Path,
    *,
    bindings: _OfflineBindings,
    new_acquisition: Path,
    base_cache: Path,
    trusted_pmbootstrap: Path,
    tag: str,
    output: Path,
) -> Mapping[str, object]:
    root = offline_cache._absolute_real_directory(
        Path(root), label="calibration project root"
    )
    base = _load_base_trust(root)
    trusted_pmbootstrap, trusted_relative = _private_relative_directory(
        root, trusted_pmbootstrap, label="trusted pmbootstrap"
    )
    base_cache, base_cache_relative = _private_relative_directory(
        root, base_cache, label="base offline cache"
    )
    new_acquisition, acquisition_relative = _private_relative_directory(
        root, new_acquisition, label="new curated acquisition"
    )
    output, _output_relative = _new_private_file(
        root, output, label="calibration authorization draft"
    )
    for bound_input, label in (
        (trusted_pmbootstrap, "trusted pmbootstrap"),
        (base_cache, "base cache"),
        (new_acquisition, "new acquisition"),
    ):
        try:
            output.relative_to(bound_input)
        except ValueError:
            continue
        raise GateError(
            f"calibration authorization draft must not be inside the {label}"
        )
    bundle_relative = _execution_bundle_relative(tag)
    bundle = _canonical_path(root, bundle_relative)
    if os.path.lexists(bundle):
        raise GateError("calibration execution bundle must be absent")

    _validate_trusted_pmbootstrap(base, trusted_pmbootstrap)
    _base_verified, base_output = _validate_base_cache(
        base,
        base_cache,
        trusted_pmbootstrap,
        cache_reader=bindings.cache_reader,
    )
    acquisition_count, acquisition_digest = _acquisition_identity(
        base, new_acquisition
    )
    profile_value, profile_payload = offline_cache._read_canonical_json(
        _canonical_path(root, _PROFILE_RELATIVE),
        _MAX_JSON_BYTES,
        "current calibration profile",
    )
    if profile_value != base.authorization.profile.as_mapping():
        raise GateError("current profile value differs from the base attestation")
    profile_sha256 = hashlib.sha256(profile_payload).hexdigest()
    if profile_sha256 != base.authorization.profile_sha256:
        raise GateError("current profile bytes differ from the base attestation")

    draft: dict[str, object] = {
        "schema": CALIBRATION_AUTHORIZATION_SCHEMA,
        "base_attestation": {
            "path": _BASE_ATTESTATION_RELATIVE,
            "sha256": hashlib.sha256(base.payload).hexdigest(),
        },
        "profile": {
            "path": _PROFILE_RELATIVE,
            "sha256": profile_sha256,
        },
        "trusted_pmbootstrap": {
            "path": trusted_relative,
            "commit": base.authorization.trusted_pmbootstrap_commit,
            "tree": base.authorization.trusted_pmbootstrap_tree,
            "signer_key_path": base.authorization.signer_key_path,
            "signer_key_sha256": base.authorization.signer_key_sha256,
        },
        "base_cache": {
            "path": base_cache_relative,
            "expected_output": base_output,
        },
        "acquisition": {
            "schema": "lmi-p1-curated-offline-acquisition/v1",
            "path": acquisition_relative,
            "member_count": acquisition_count,
            "inventory_sha256": acquisition_digest,
        },
        "execution_bundle": {"path": bundle_relative},
        "calibration_runtime": _calibration_runtime(root),
        "runtime_trust": dict(base.authorization.runtime_trust),
        "apk_static": dict(base.value["apk_static"]),  # type: ignore[arg-type]
        "openssl_runtime": json.loads(
            json.dumps(base.value["openssl_runtime"], ensure_ascii=True)
        ),
    }
    _write_exclusive_canonical(
        output, draft, label="calibration authorization draft"
    )
    return {
        "schema": CALIBRATION_AUTHORIZATION_SCHEMA,
        "draft": output,
        "execution_bundle": bundle,
        "acquisition_member_count": acquisition_count,
        "acquisition_inventory_sha256": acquisition_digest,
    }


def prepare_calibration(
    *,
    new_acquisition: Path,
    base_cache: Path,
    trusted_pmbootstrap: Path,
    tag: str,
    output: Path,
) -> Mapping[str, object]:
    """Validate current trust inputs and emit one non-authorizing private draft."""

    root = _project_root()
    return _prepare_calibration(
        root,
        bindings=_resolve_offline_bindings(root),
        new_acquisition=new_acquisition,
        base_cache=base_cache,
        trusted_pmbootstrap=trusted_pmbootstrap,
        tag=tag,
        output=output,
    )


def _validate_runtime_record(
    root: Path, value: object, expected: Sequence[str]
) -> None:
    if not isinstance(value, list) or len(value) != len(expected):
        raise GateError("calibration runtime inventory is incomplete")
    normalized: list[dict[str, str]] = []
    for index, item in enumerate(value):
        record = offline_cache._require_exact_fields(
            item,
            frozenset({"path", "sha256"}),
            label=f"calibration runtime[{index}]",
        )
        relative = offline_cache._safe_relative_path(
            record["path"], label=f"calibration runtime[{index}].path"
        )
        digest = offline_cache._require_hash(
            record["sha256"],
            offline_cache._SHA256_RE,
            label=f"calibration runtime[{index}].sha256",
        )
        actual = _hash_record(
            root, relative, label=f"authorized calibration runtime {relative}"
        )
        if actual["sha256"] != digest:
            raise GateError(f"calibration runtime hash drift: {relative}")
        normalized.append({"path": relative, "sha256": digest})
    if tuple(item["path"] for item in normalized) != tuple(expected):
        raise GateError("calibration runtime paths are not exact and sorted")


def _validate_fixed_record(
    value: object,
    *,
    label: str,
    expected_path: str,
    expected_sha256: str,
) -> None:
    record = offline_cache._require_exact_fields(
        value, frozenset({"path", "sha256"}), label=label
    )
    if dict(record) != {"path": expected_path, "sha256": expected_sha256}:
        raise GateError(f"{label} differs from the current reviewed input")


def _hold_authorization(
    path: Path, payload: bytes
) -> _HeldAuthorization:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags)
        metadata, digest = _hash_held_file(
            descriptor,
            label="canonical calibration authorization",
            maximum=_MAX_JSON_BYTES,
        )
        pathname = path.lstat()
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    expected = hashlib.sha256(payload).hexdigest()
    if (
        offline_cache._metadata_identity(pathname)
        != offline_cache._metadata_identity(metadata)
        or metadata.st_size != len(payload)
        or digest != expected
    ):
        os.close(descriptor)
        raise GateError(
            "canonical calibration authorization changed while being held"
        )
    return _HeldAuthorization(
        path,
        descriptor,
        offline_cache._metadata_identity(metadata),
        metadata.st_size,
        digest,
    )


def _load_execution_state(
    root: Path, bindings: _OfflineBindings
) -> _ExecutionState:
    authorization_path = _canonical_path(
        root, _CANONICAL_AUTHORIZATION_RELATIVE
    )
    value, payload = offline_cache._read_canonical_json(
        authorization_path,
        _MAX_JSON_BYTES,
        "canonical calibration authorization",
    )
    authorization = offline_cache._require_exact_fields(
        value, _AUTHORIZATION_FIELDS, label="canonical calibration authorization"
    )
    if authorization["schema"] != CALIBRATION_AUTHORIZATION_SCHEMA:
        raise GateError("canonical calibration authorization schema is unsupported")

    base = _load_base_trust(root)
    _validate_fixed_record(
        authorization["base_attestation"],
        label="calibration base_attestation",
        expected_path=_BASE_ATTESTATION_RELATIVE,
        expected_sha256=hashlib.sha256(base.payload).hexdigest(),
    )
    _validate_fixed_record(
        authorization["profile"],
        label="calibration profile",
        expected_path=_PROFILE_RELATIVE,
        expected_sha256=base.authorization.profile_sha256,
    )
    if authorization["runtime_trust"] != dict(base.authorization.runtime_trust):
        raise GateError("calibration runtime trust assumption differs from the base")
    if authorization["apk_static"] != base.value["apk_static"]:
        raise GateError("calibration apk.static pins differ from the base")
    if authorization["openssl_runtime"] != base.value["openssl_runtime"]:
        raise GateError("calibration OpenSSL pins differ from the base")
    _validate_runtime_record(
        root, authorization["calibration_runtime"], _CALIBRATION_RUNTIME_PATHS
    )

    trusted_record = offline_cache._require_exact_fields(
        authorization["trusted_pmbootstrap"],
        frozenset(
            {
                "path",
                "commit",
                "tree",
                "signer_key_path",
                "signer_key_sha256",
            }
        ),
        label="calibration trusted_pmbootstrap",
    )
    trusted_pmbootstrap = _path_from_private_record(
        root, trusted_record["path"], label="authorized trusted pmbootstrap"
    )
    expected_trusted = {
        "path": trusted_record["path"],
        "commit": base.authorization.trusted_pmbootstrap_commit,
        "tree": base.authorization.trusted_pmbootstrap_tree,
        "signer_key_path": base.authorization.signer_key_path,
        "signer_key_sha256": base.authorization.signer_key_sha256,
    }
    if dict(trusted_record) != expected_trusted:
        raise GateError("trusted pmbootstrap facts differ from the base attestation")
    _validate_trusted_pmbootstrap(base, trusted_pmbootstrap)

    base_cache_record = offline_cache._require_exact_fields(
        authorization["base_cache"],
        frozenset({"path", "expected_output"}),
        label="calibration base_cache",
    )
    base_cache = _path_from_private_record(
        root, base_cache_record["path"], label="authorized base cache"
    )
    _base_verified, base_output = _validate_base_cache(
        base,
        base_cache,
        trusted_pmbootstrap,
        cache_reader=bindings.cache_reader,
    )
    authorized_base_output = offline_cache._validate_expected_output(
        base_cache_record["expected_output"],
        label="calibration base_cache.expected_output",
    )
    if authorized_base_output != base_output:
        raise GateError("authorized base cache output differs from current bytes")

    acquisition_record = offline_cache._require_exact_fields(
        authorization["acquisition"],
        frozenset(
            {"schema", "path", "member_count", "inventory_sha256"}
        ),
        label="calibration acquisition",
    )
    if (
        acquisition_record["schema"]
        != "lmi-p1-curated-offline-acquisition/v1"
    ):
        raise GateError("calibration acquisition schema is unsupported")
    acquisition = _path_from_private_record(
        root, acquisition_record["path"], label="authorized acquisition"
    )
    acquisition_count, acquisition_digest = _acquisition_identity(
        base, acquisition
    )
    if (
        offline_cache._require_size(
            acquisition_record["member_count"],
            label="calibration acquisition.member_count",
        )
        != acquisition_count
        or offline_cache._require_hash(
            acquisition_record["inventory_sha256"],
            offline_cache._SHA256_RE,
            label="calibration acquisition.inventory_sha256",
        )
        != acquisition_digest
    ):
        raise GateError("authorized acquisition identity differs from current bytes")

    bundle_record = offline_cache._require_exact_fields(
        authorization["execution_bundle"],
        frozenset({"path"}),
        label="calibration execution_bundle",
    )
    bundle_relative = offline_cache._safe_relative_path(
        bundle_record["path"], label="calibration execution_bundle.path"
    )
    bundle_parts = PurePosixPath(bundle_relative).parts
    if (
        bundle_parts[: len(_PRIVATE_CALIBRATION_RELATIVE.parts)]
        != _PRIVATE_CALIBRATION_RELATIVE.parts
        or len(bundle_parts) != len(_PRIVATE_CALIBRATION_RELATIVE.parts) + 1
        or _TAG_RE.fullmatch(bundle_parts[-1]) is None
    ):
        raise GateError("calibration execution bundle path is not fixed")
    bundle = _canonical_path(root, bundle_relative)
    if os.path.lexists(bundle):
        raise GateError("calibration execution bundle must be absent")

    held_authorization = _hold_authorization(authorization_path, payload)
    held_authorization.validate()
    return _ExecutionState(
        root=root,
        authorization_path=authorization_path,
        authorization_payload_sha256=hashlib.sha256(payload).hexdigest(),
        authorization_file=held_authorization,
        base=base,
        trusted_pmbootstrap=trusted_pmbootstrap,
        base_cache=base_cache,
        acquisition=acquisition,
        acquisition_member_count=acquisition_count,
        acquisition_inventory_sha256=acquisition_digest,
        bundle=bundle,
        calibration_runtime=tuple(
            dict(item)  # type: ignore[arg-type]
            for item in authorization["calibration_runtime"]  # type: ignore[union-attr]
        ),
    )


def _hold_directory(
    path: Path, *, label: str, exact_mode: int | None = None
) -> _HeldDirectory:
    directory = offline_cache._absolute_real_directory(
        path, label=label, exact_mode=exact_mode
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = directory.lstat()
        descriptor = os.open(directory, flags)
        opened = os.fstat(descriptor)
        after = directory.lstat()
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise GateError(f"could not hold {label}: {error}") from None
    binding = offline_cache._directory_binding(before)
    if (
        offline_cache._directory_binding(opened) != binding
        or offline_cache._directory_binding(after) != binding
    ):
        os.close(descriptor)
        raise GateError(f"{label} changed while its directory was held")
    return _HeldDirectory(directory, descriptor, binding)


def _create_bundle(bundle: Path) -> _HeldDirectory:
    parent = offline_cache._absolute_real_directory(
        bundle.parent, label="calibration bundle parent"
    )
    if bundle.parent != parent or os.path.lexists(bundle):
        raise GateError("calibration bundle must be a new direct child")
    try:
        bundle.mkdir(mode=0o700)
        bundle.chmod(0o700)
    except OSError as error:
        raise GateError(f"could not create calibration bundle: {error}") from None
    offline_cache._absolute_real_directory(
        bundle, label="calibration bundle", exact_mode=0o700
    )
    if bundle.lstat().st_uid != os.geteuid():
        raise GateError("calibration bundle must be owned by the effective user")
    offline_cache._fsync_directory(parent)
    return _hold_directory(
        bundle, label="calibration bundle", exact_mode=0o700
    )


def _open_relative_parent_at(
    root_fd: int, relative: PurePosixPath, *, label: str
) -> tuple[int, str]:
    if relative.is_absolute() or not relative.parts:
        raise GateError(f"{label} has an invalid relative path")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    current = os.dup(root_fd)
    try:
        for part in relative.parts[:-1]:
            child = os.open(part, flags, dir_fd=current)
            os.close(current)
            current = child
            metadata = os.fstat(current)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o022
            ):
                raise GateError(f"{label} has an unsafe directory component")
        return current, relative.parts[-1]
    except GateError:
        os.close(current)
        raise
    except OSError as error:
        os.close(current)
        raise GateError(f"could not traverse {label}: {error}") from None


def _hash_held_file(
    descriptor: int, *, label: str, maximum: int = offline_cache._MAX_FILE_BYTES
) -> tuple[os.stat_result, str]:
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > maximum
        ):
            raise GateError(f"{label} is not one bounded private regular file")
        os.lseek(descriptor, 0, os.SEEK_SET)
        digest = hashlib.sha256()
        for block in iter(
            lambda: os.read(descriptor, offline_cache._COPY_BLOCK_SIZE), b""
        ):
            digest.update(block)
        after = os.fstat(descriptor)
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not hash {label}: {error}") from None
    if offline_cache._metadata_identity(before) != offline_cache._metadata_identity(
        after
    ):
        raise GateError(f"{label} changed while held")
    return before, digest.hexdigest()


def _copy_snapshot_member(
    *,
    source_fd: int,
    snapshot_fd: int,
    relative: PurePosixPath,
    cache_path: str,
    seen_source_inodes: set[tuple[int, int]],
) -> dict[str, object]:
    source_parent, source_name = _open_relative_parent_at(
        source_fd, relative, label=f"source acquisition member {relative}"
    )
    destination_parent, destination_name = _open_relative_parent_at(
        snapshot_fd, relative, label=f"snapshot member {relative}"
    )
    source_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    destination_flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        before = os.stat(
            source_name, dir_fd=source_parent, follow_symlinks=False
        )
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_size > offline_cache._MAX_FILE_BYTES
        ):
            raise GateError(
                f"source acquisition member is not one mode-0600 regular file: {relative}"
            )
        inode = (before.st_dev, before.st_ino)
        if inode in seen_source_inodes:
            raise GateError(f"source acquisition member is hardlinked: {relative}")
        seen_source_inodes.add(inode)
        input_fd = os.open(source_name, source_flags, dir_fd=source_parent)
        try:
            output_fd = os.open(
                destination_name,
                destination_flags,
                0o600,
                dir_fd=destination_parent,
            )
        except Exception:
            os.close(input_fd)
            raise
        digest = hashlib.sha256()
        with os.fdopen(input_fd, "rb") as source, os.fdopen(
            output_fd, "wb"
        ) as destination:
            os.fchmod(destination.fileno(), 0o600)
            opened = os.fstat(source.fileno())
            if offline_cache._metadata_identity(
                opened
            ) != offline_cache._metadata_identity(before):
                raise GateError(
                    f"source acquisition member changed while opening: {relative}"
                )
            for block in iter(
                lambda: source.read(offline_cache._COPY_BLOCK_SIZE), b""
            ):
                digest.update(block)
                destination.write(block)
            destination.flush()
            os.fsync(destination.fileno())
            finished = os.fstat(source.fileno())
        after = os.stat(
            source_name, dir_fd=source_parent, follow_symlinks=False
        )
        if not (
            offline_cache._metadata_identity(before)
            == offline_cache._metadata_identity(finished)
            == offline_cache._metadata_identity(after)
        ):
            raise GateError(
                f"source acquisition member changed during snapshot: {relative}"
            )
        os.fsync(destination_parent)
    except GateError:
        raise
    except OSError as error:
        raise GateError(f"could not snapshot acquisition member {relative}: {error}") from None
    finally:
        os.close(source_parent)
        os.close(destination_parent)
    return {
        "path": cache_path,
        "size": before.st_size,
        "sha256": digest.hexdigest(),
    }


def _held_child_directory(
    parent: _HeldDirectory, name: str, path: Path, *, label: str
) -> _HeldDirectory:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
        opened = os.fstat(descriptor)
        pathname = path.lstat()
    except OSError as error:
        if "descriptor" in locals():
            os.close(descriptor)
        raise GateError(f"could not hold {label}: {error}") from None
    binding = offline_cache._directory_binding(opened)
    if (
        not stat.S_ISDIR(opened.st_mode)
        or stat.S_IMODE(opened.st_mode) != 0o700
        or offline_cache._directory_binding(pathname) != binding
    ):
        os.close(descriptor)
        raise GateError(f"{label} path binding is invalid")
    return _HeldDirectory(path, descriptor, binding)


def _inventory_acquisition_at(
    source: _HeldDirectory, profile: offline_cache.PromotionProfile
) -> list[str]:
    try:
        top = set(os.listdir(source.descriptor))
    except OSError as error:
        raise GateError(f"could not enumerate held acquisition: {error}") from None
    if top != offline_cache._ALLOWED_ACQUISITION_TOP_LEVEL:
        raise GateError("held acquisition top-level layout is not exact")
    expected_indexes: dict[str, set[str]] = {
        architecture: set() for architecture in offline_cache.ARCHITECTURES
    }
    for record in profile.repositories:
        expected_indexes[str(record["architecture"])].add(
            PurePosixPath(str(record["index_path"])).name
        )
    paths = ["work/version"]
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    for architecture in sorted(offline_cache.ARCHITECTURES):
        dirname = f"cache_apk_{architecture}"
        descriptor = -1
        try:
            descriptor = os.open(
                dirname, directory_flags, dir_fd=source.descriptor
            )
            metadata = os.fstat(descriptor)
            names = sorted(os.listdir(descriptor))
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise GateError(
                f"could not enumerate held {architecture} acquisition cache: {error}"
            ) from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            os.close(descriptor)
            raise GateError(f"held {architecture} cache directory is unsafe")
        os.close(descriptor)
        actual_indexes = {name for name in names if name.startswith("APKINDEX")}
        if actual_indexes != expected_indexes[architecture]:
            raise GateError(f"held {architecture} APKINDEX set is not exact")
        if any(
            not (name.startswith("APKINDEX") or name.endswith(".apk"))
            for name in names
        ):
            raise GateError(f"held {architecture} cache contains extra content")
        paths.extend(f"work/{dirname}/{name}" for name in names)
    for records, dirname in (
        (profile.http_artifacts, "cache_http"),
        (profile.distfiles, "cache_distfiles"),
    ):
        expected = {
            PurePosixPath(str(item["path"])).name for item in records
        }
        descriptor = -1
        try:
            descriptor = os.open(
                dirname, directory_flags, dir_fd=source.descriptor
            )
            metadata = os.fstat(descriptor)
            actual = set(os.listdir(descriptor))
        except OSError as error:
            if descriptor >= 0:
                os.close(descriptor)
            raise GateError(
                f"could not enumerate held acquisition {dirname}: {error}"
            ) from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            os.close(descriptor)
            raise GateError(f"held acquisition {dirname} is unsafe")
        os.close(descriptor)
        if actual != expected:
            raise GateError(f"held acquisition {dirname} set is not exact")
        paths.extend(f"work/{dirname}/{name}" for name in sorted(actual))
    return sorted(paths)


def _open_held_snapshot_file(
    snapshot: _HeldDirectory, record: Mapping[str, object]
) -> _HeldSnapshotFile:
    cache_path = str(record["path"])
    relative = PurePosixPath(cache_path.removeprefix("work/"))
    parent, name = _open_relative_parent_at(
        snapshot.descriptor, relative, label=f"held snapshot member {relative}"
    )
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent)
        pathname = os.stat(name, dir_fd=parent, follow_symlinks=False)
        metadata, digest = _hash_held_file(
            descriptor, label=f"held snapshot member {relative}"
        )
    except Exception:
        if "descriptor" in locals():
            os.close(descriptor)
        raise
    finally:
        os.close(parent)
    if (
        offline_cache._metadata_identity(pathname)
        != offline_cache._metadata_identity(metadata)
        or metadata.st_size != record["size"]
        or digest != record["sha256"]
    ):
        os.close(descriptor)
        raise GateError(f"held snapshot member differs from its record: {relative}")
    return _HeldSnapshotFile(
        cache_path,
        descriptor,
        offline_cache._metadata_identity(metadata),
        metadata.st_size,
        digest,
    )


def _create_acquisition_snapshot(
    state: _ExecutionState, bundle: _HeldDirectory
) -> _AcquisitionSnapshot:
    source = _hold_directory(
        state.acquisition, label="authorized source acquisition", exact_mode=0o700
    )
    snapshot_path = state.bundle / _SNAPSHOT_DIRECTORY
    try:
        bundle.validate(label="calibration bundle")
        os.mkdir(_SNAPSHOT_DIRECTORY, 0o700, dir_fd=bundle.descriptor)
        os.fsync(bundle.descriptor)
        snapshot = _held_child_directory(
            bundle,
            _SNAPSHOT_DIRECTORY,
            snapshot_path,
            label="execution acquisition snapshot",
        )
        os.fchmod(snapshot.descriptor, 0o700)
    except Exception:
        source.close()
        raise

    held_files: list[_HeldSnapshotFile] = []
    try:
        for directory in (
            "cache_apk_aarch64",
            "cache_apk_x86_64",
            "cache_http",
            "cache_distfiles",
        ):
            os.mkdir(directory, 0o700, dir_fd=snapshot.descriptor)
            child = os.open(
                directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=snapshot.descriptor,
            )
            try:
                os.fchmod(child, 0o700)
            finally:
                os.close(child)
        source_paths = _inventory_acquisition_at(
            source, state.base.authorization.profile
        )
        records: list[dict[str, object]] = []
        seen_source_inodes: set[tuple[int, int]] = set()
        for cache_path in source_paths:
            relative = PurePosixPath(cache_path.removeprefix("work/"))
            records.append(
                _copy_snapshot_member(
                    source_fd=source.descriptor,
                    snapshot_fd=snapshot.descriptor,
                    relative=relative,
                    cache_path=cache_path,
                    seen_source_inodes=seen_source_inodes,
                )
            )
        records.sort(key=lambda item: str(item["path"]))
        inventory = [
            {
                "path": str(item["path"]).removeprefix("work/"),
                "size": item["size"],
                "sha256": item["sha256"],
            }
            for item in records
        ]
        count = len(inventory)
        digest = hashlib.sha256(
            offline_cache.canonical_json_bytes(inventory)
        ).hexdigest()
        if (
            count != state.acquisition_member_count
            or digest != state.acquisition_inventory_sha256
        ):
            raise GateError(
                "descriptor-copied acquisition snapshot differs from authorization"
            )
        for directory in (
            "cache_apk_aarch64",
            "cache_apk_x86_64",
            "cache_http",
            "cache_distfiles",
        ):
            child = os.open(
                directory,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=snapshot.descriptor,
            )
            try:
                os.fsync(child)
            finally:
                os.close(child)
        os.fsync(snapshot.descriptor)
        for record in records:
            held_files.append(_open_held_snapshot_file(snapshot, record))
        result = _AcquisitionSnapshot(
            source,
            snapshot,
            tuple(held_files),
            count,
            digest,
        )
        _validate_snapshot(result, label="new acquisition snapshot")
        return result
    except Exception:
        for member in held_files:
            member.close()
        snapshot.close()
        source.close()
        raise


def _validate_snapshot(snapshot: _AcquisitionSnapshot, *, label: str) -> None:
    snapshot.source.validate(label=f"{label} source directory")
    snapshot.directory.validate(label=f"{label} directory")
    records: list[dict[str, object]] = []
    for member in snapshot.files:
        metadata, digest = _hash_held_file(
            member.descriptor, label=f"{label} member {member.path}"
        )
        if (
            offline_cache._metadata_identity(metadata)
            != member.metadata_identity
            or metadata.st_size != member.size
            or digest != member.sha256
        ):
            raise GateError(f"{label} held member changed: {member.path}")
        relative = PurePosixPath(member.path.removeprefix("work/"))
        parent, name = _open_relative_parent_at(
            snapshot.directory.descriptor,
            relative,
            label=f"{label} pathname {member.path}",
        )
        try:
            pathname = os.stat(name, dir_fd=parent, follow_symlinks=False)
        except OSError as error:
            raise GateError(
                f"could not revalidate {label} pathname {member.path}: {error}"
            ) from None
        finally:
            os.close(parent)
        if offline_cache._metadata_identity(pathname) != member.metadata_identity:
            raise GateError(f"{label} member pathname was rebound: {member.path}")
        records.append(
            {
                "path": member.path.removeprefix("work/"),
                "size": member.size,
                "sha256": member.sha256,
            }
        )
    records.sort(key=lambda item: str(item["path"]))
    digest = hashlib.sha256(
        offline_cache.canonical_json_bytes(records)
    ).hexdigest()
    if (
        len(records) != snapshot.member_count
        or digest != snapshot.inventory_sha256
    ):
        raise GateError(f"{label} inventory identity changed")


def _bind_output_to_snapshot(
    state: _ExecutionState,
    snapshot: _AcquisitionSnapshot,
    verified: offline_cache.VerifiedOfflineCache,
) -> None:
    members_value = verified.manifest.get("members")
    if not isinstance(members_value, list):
        raise GateError("promoted output has an invalid member inventory")
    members = {
        str(item["path"]): item
        for item in members_value
        if isinstance(item, Mapping)
    }
    if len(members) != len(members_value):
        raise GateError("promoted output member inventory is ambiguous")
    expected_snapshot = {
        member.path: {"size": member.size, "sha256": member.sha256}
        for member in snapshot.files
    }
    expected_signers: dict[str, str] = {}
    for record in (
        *state.base.authorization.profile.repositories,
        *state.base.authorization.profile.http_artifacts,
    ):
        path = str(record["signer_key_path"])
        digest = str(record["signer_key_sha256"])
        previous = expected_signers.setdefault(path, digest)
        if previous != digest:
            raise GateError("promotion profile signer bindings conflict")
    if set(members) != set(expected_snapshot) | set(expected_signers):
        raise GateError("promoted output members do not exactly match the snapshot")
    for path, expected in expected_snapshot.items():
        if (
            members[path]["size"] != expected["size"]
            or members[path]["sha256"] != expected["sha256"]
        ):
            raise GateError(
                f"promoted output is not byte-bound to snapshot member: {path}"
            )
    for path, digest in expected_signers.items():
        if members[path]["sha256"] != digest:
            raise GateError(f"promoted output signer differs from profile: {path}")


def _bootstrap_and_promote(
    *,
    state: _ExecutionState,
    acquisition: Path,
    quarantine: Path,
    published: Path,
    bootstrap: Path,
    bindings: _OfflineBindings,
) -> None:
    http_record = state.base.authorization.profile.http_artifacts[0]
    package = state.base_cache.joinpath(
        *PurePosixPath(str(http_record["path"])).parts
    )
    if (
        not callable(bindings.verifier_factory)
        or not callable(bindings.promoter)
    ):
        raise GateError("offline-cache promotion bindings are not callable")
    verifier = bindings.verifier_factory(
        package,
        package_record=http_record,
        trusted_key_root=state.base_cache,
        bootstrap_root=bootstrap,
        pins=state.base.authorization.bootstrap_pins,
    )
    try:
        bindings.promoter(
            acquisition,
            quarantine,
            published,
            state.base.authorization.profile,
            trusted_key_root=state.trusted_pmbootstrap,
            verifier=verifier,
        )
    finally:
        verifier.close()


def _revalidate_published(
    state: _ExecutionState,
    published: Path,
    bindings: _OfflineBindings,
) -> tuple[offline_cache.VerifiedOfflineCache, bytes, dict[str, object]]:
    if not callable(bindings.cache_reader):
        raise GateError("offline-cache reader binding is not callable")
    verified = bindings.cache_reader(
        published,
        expected_profile=state.base.authorization.profile,
        trusted_key_root=state.trusted_pmbootstrap,
    )
    _parsed, payload = offline_cache._read_canonical_json(
        published / offline_cache.MANIFEST_NAME,
        _MAX_JSON_BYTES,
        "calibration published manifest",
    )
    return verified, payload, _output_identity(verified)


def _revalidate_execution_inputs(
    state: _ExecutionState, bindings: _OfflineBindings
) -> None:
    state.authorization_file.validate()
    if state.authorization_file.sha256 != state.authorization_payload_sha256:
        raise GateError("canonical calibration authorization changed during execution")
    current_base = _load_base_trust(state.root)
    if current_base.payload != state.base.payload:
        raise GateError("base production attestation changed during calibration")
    _validate_runtime_record(
        state.root,
        list(state.calibration_runtime),
        _CALIBRATION_RUNTIME_PATHS,
    )
    _validate_trusted_pmbootstrap(current_base, state.trusted_pmbootstrap)
    _validate_base_cache(
        current_base,
        state.base_cache,
        state.trusted_pmbootstrap,
        cache_reader=bindings.cache_reader,
    )
    count, digest = _acquisition_identity(current_base, state.acquisition)
    if (
        count != state.acquisition_member_count
        or digest != state.acquisition_inventory_sha256
    ):
        raise GateError("calibration acquisition changed during execution")


def _candidate_values(
    state: _ExecutionState, output: Mapping[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    normalized_output = offline_cache._validate_expected_output(
        output, label="calibrated production output"
    )
    base_overhead = (
        int(state.base.authorization.expected_output["member_count"])
        - state.base.authorization.acquisition_member_count
    )
    if (
        base_overhead < 0
        or normalized_output["member_count"]
        != state.acquisition_member_count + base_overhead
    ):
        raise GateError(
            "calibrated output member count differs from the validated cache overhead"
        )
    acquisition = {
        "inventory_sha256": state.acquisition_inventory_sha256,
        "member_count": state.acquisition_member_count,
    }
    replay = {
        "schema": offline_cache.PROMOTION_REPLAY_SCHEMA,
        "scope": "same-curated-acquisition-reproducibility-replay",
        "acquisition": acquisition,
        "first_promotion": normalized_output,
        "replay_promotion": normalized_output,
        "comparison": {"byte_identical": True},
    }
    offline_cache._validate_replay_report(
        replay,
        acquisition=acquisition,
        expected_output=normalized_output,
    )
    replay_payload = offline_cache.canonical_json_bytes(replay)
    candidate = json.loads(
        json.dumps(state.base.value, ensure_ascii=True)
    )
    candidate["acquisition"] = {
        "schema": "lmi-p1-curated-offline-acquisition/v1",
        **acquisition,
    }
    candidate["published"] = normalized_output
    candidate["replay_report"] = {
        "path": _CANONICAL_REPLAY_RELATIVE,
        "sha256": hashlib.sha256(replay_payload).hexdigest(),
    }
    if candidate["schema"] != offline_cache.PROMOTION_ATTESTATION_SCHEMA:
        raise GateError("candidate attestation did not preserve production v3")
    return replay, candidate


def _manifest_receipt(
    path: Path, payload: bytes, output: Mapping[str, object]
) -> dict[str, object]:
    return {
        "path": path.as_posix(),
        "output": dict(output),
        "manifest_bytes": {
            "size": len(payload),
            "sha256": hashlib.sha256(payload).hexdigest(),
        },
    }


def _execution_receipt(
    *,
    state: _ExecutionState,
    snapshot: _AcquisitionSnapshot,
    first_path: Path,
    first_payload: bytes,
    first_output: Mapping[str, object],
    replay_path: Path,
    replay_payload: bytes,
    replay_output: Mapping[str, object],
    candidate_replay_payload: bytes,
    candidate_attestation_payload: bytes,
) -> dict[str, object]:
    def relative(path: Path) -> str:
        try:
            return path.relative_to(state.root).as_posix()
        except ValueError:
            raise GateError("receipt path escaped the calibration project") from None

    base_record = state.base.value
    producer_code = base_record["producer_code"]
    if not isinstance(producer_code, Mapping):
        raise GateError("base producer_code is invalid for receipt")
    return {
        "schema": CALIBRATION_EXECUTION_RECEIPT_SCHEMA,
        "assurance": json.loads(json.dumps(_RECEIPT_ASSURANCE)),
        "authorization": {
            "path": _CANONICAL_AUTHORIZATION_RELATIVE,
            "sha256": state.authorization_payload_sha256,
        },
        "base": {
            "attestation": {
                "path": _BASE_ATTESTATION_RELATIVE,
                "sha256": hashlib.sha256(state.base.payload).hexdigest(),
            },
            "profile": {
                "path": _PROFILE_RELATIVE,
                "sha256": state.base.authorization.profile_sha256,
            },
            "production_runtime": json.loads(
                json.dumps(producer_code["promotion_runtime"])
            ),
            "calibration_runtime": [
                dict(item) for item in state.calibration_runtime
            ],
            "runtime_trust": dict(state.base.authorization.runtime_trust),
        },
        "acquisition": {
            "source": {
                "path": relative(state.acquisition),
                "member_count": state.acquisition_member_count,
                "inventory_sha256": state.acquisition_inventory_sha256,
            },
            "snapshot": {
                "path": relative(snapshot.directory.path),
                "member_count": snapshot.member_count,
                "inventory_sha256": snapshot.inventory_sha256,
            },
        },
        "promotions": {
            "first": _manifest_receipt(
                Path(relative(first_path)),
                first_payload,
                first_output,
            ),
            "replay": _manifest_receipt(
                Path(relative(replay_path)),
                replay_payload,
                replay_output,
            ),
        },
        "comparison": {
            "manifest_bytes_identical": first_payload == replay_payload,
            "outputs_identical": dict(first_output) == dict(replay_output),
        },
        "candidates": {
            "replay": {
                "path": relative(state.bundle / _CANDIDATE_REPLAY),
                "sha256": hashlib.sha256(candidate_replay_payload).hexdigest(),
            },
            "attestation": {
                "path": relative(state.bundle / _CANDIDATE_ATTESTATION),
                "sha256": hashlib.sha256(
                    candidate_attestation_payload
                ).hexdigest(),
            },
        },
    }


def _execute_canonical_transaction(
    root: Path,
    bindings: _OfflineBindings,
    callables: _TransactionCallables,
) -> Mapping[str, object]:
    root = offline_cache._absolute_real_directory(
        Path(root), label="calibration project root"
    )
    for name, function in vars(callables).items():
        if not callable(function):
            raise GateError(f"calibration transaction binding is not callable: {name}")
    state = callables.load_state(root, bindings)
    bundle: _HeldDirectory | None = None
    snapshot: _AcquisitionSnapshot | None = None
    try:
        bundle = callables.create_bundle(state.bundle)
        snapshot = callables.create_snapshot(state, bundle)

        first_quarantine = state.bundle / _FIRST_QUARANTINE
        first_published = state.bundle / _FIRST_PUBLISHED
        replay_quarantine = state.bundle / _REPLAY_QUARANTINE
        replay_published = state.bundle / _REPLAY_PUBLISHED
        callables.validate_snapshot(
            snapshot, label="pre-first-promotion snapshot"
        )
        bundle.validate(label="pre-first-promotion bundle")
        callables.promote(
            state=state,
            acquisition=snapshot.directory.path,
            quarantine=first_quarantine,
            published=first_published,
            bootstrap=state.bundle / _FIRST_BOOTSTRAP,
            bindings=bindings,
        )
        callables.validate_snapshot(
            snapshot, label="post-first-promotion snapshot"
        )
        bundle.validate(label="post-first-promotion bundle")
        first, first_payload, first_output = callables.revalidate_published(
            state, first_published, bindings
        )
        callables.bind_output(state, snapshot, first)

        callables.validate_snapshot(
            snapshot, label="pre-replay-promotion snapshot"
        )
        bundle.validate(label="pre-replay-promotion bundle")
        callables.promote(
            state=state,
            acquisition=snapshot.directory.path,
            quarantine=replay_quarantine,
            published=replay_published,
            bootstrap=state.bundle / _REPLAY_BOOTSTRAP,
            bindings=bindings,
        )
        callables.validate_snapshot(
            snapshot, label="post-replay-promotion snapshot"
        )
        bundle.validate(label="post-replay-promotion bundle")
        replay, replay_payload, replay_output = callables.revalidate_published(
            state, replay_published, bindings
        )
        callables.bind_output(state, snapshot, replay)
        if (
            first_output != replay_output
            or first_payload != replay_payload
            or first.manifest != replay.manifest
        ):
            raise GateError("calibration promotions are not byte-identical")

        callables.revalidate_inputs(state, bindings)
        callables.validate_snapshot(
            snapshot, label="final authorized snapshot"
        )
        bundle.validate(label="final calibration bundle")

        # Final revalidation is intentionally after every other input gate.
        first, first_payload, first_output = callables.revalidate_published(
            state, first_published, bindings
        )
        callables.bind_output(state, snapshot, first)
        replay, replay_payload, replay_output = callables.revalidate_published(
            state, replay_published, bindings
        )
        callables.bind_output(state, snapshot, replay)
        if (
            first_output != replay_output
            or first_payload != replay_payload
            or first.manifest != replay.manifest
        ):
            raise GateError("final calibration outputs are not byte-identical")

        replay_value, attestation_value = callables.candidate_values(
            state, first_output
        )
        replay_candidate = state.bundle / _CANDIDATE_REPLAY
        attestation_candidate = state.bundle / _CANDIDATE_ATTESTATION
        candidate_replay_payload = callables.write_bundle(
            bundle,
            _CANDIDATE_REPLAY,
            replay_value,
            label="candidate production replay",
        )
        candidate_attestation_payload = callables.write_bundle(
            bundle,
            _CANDIDATE_ATTESTATION,
            attestation_value,
            label="candidate production attestation",
        )
        receipt_value = callables.receipt(
            state=state,
            snapshot=snapshot,
            first_path=first_published,
            first_payload=first_payload,
            first_output=first_output,
            replay_path=replay_published,
            replay_payload=replay_payload,
            replay_output=replay_output,
            candidate_replay_payload=candidate_replay_payload,
            candidate_attestation_payload=candidate_attestation_payload,
        )
        receipt_path = state.bundle / _EXECUTION_RECEIPT
        callables.write_bundle(
            bundle,
            _EXECUTION_RECEIPT,
            receipt_value,
            label="calibration execution receipt",
        )
        bundle.validate(label="completed calibration bundle")
        return {
            "schema": CALIBRATION_AUTHORIZATION_SCHEMA,
            "execution_bundle": state.bundle,
            "first_published": first_published,
            "replay_published": replay_published,
            "candidate_replay": replay_candidate,
            "candidate_attestation": attestation_candidate,
            "execution_receipt": receipt_path,
            "published": first_output,
        }
    finally:
        if snapshot is not None:
            snapshot.close()
        if bundle is not None:
            bundle.close()
        state.authorization_file.close()


def _make_supported_executor(
    *,
    root: Path,
    transaction: object,
    bindings: _OfflineBindings,
    callables: _TransactionCallables,
    guards: tuple[_CallableGuard, ...],
) -> object:
    """Close the supported execute path over import-time canonical objects."""

    def supported_execute_calibration() -> Mapping[str, object]:
        for guard in guards:
            guard.validate()
        if not callable(transaction):
            raise GateError("captured calibration transaction is not callable")
        return transaction(root, bindings, callables)

    supported_execute_calibration.__name__ = "execute_calibration"
    supported_execute_calibration.__qualname__ = "execute_calibration"
    supported_execute_calibration.__doc__ = (
        "Execute the sole canonical authorization once and emit private candidates."
    )
    return supported_execute_calibration


def _install_supported_executor() -> object:
    """Validate and capture every supported execute dependency at import time."""

    root = _project_root()
    runtime_names = (
        "_load_execution_state",
        "_create_bundle",
        "_create_acquisition_snapshot",
        "_validate_snapshot",
        "_bootstrap_and_promote",
        "_revalidate_published",
        "_bind_output_to_snapshot",
        "_revalidate_execution_inputs",
        "_candidate_values",
        "_write_bundle_canonical",
        "_execution_receipt",
        "_execute_canonical_transaction",
    )
    names = (*runtime_names, "_make_supported_executor")
    local = {
        name: _resolve_local_function(name)
        for name in names
    }
    bindings = _resolve_offline_bindings(root)
    offline_expected = (
        ("bootstrap_apk_static_verifier", bindings.verifier_factory),
        ("promote_offline_cache", bindings.promoter),
        ("read_offline_cache_manifest", bindings.cache_reader),
    )
    callables = _TransactionCallables(
        load_state=local["_load_execution_state"],
        create_bundle=local["_create_bundle"],
        create_snapshot=local["_create_acquisition_snapshot"],
        validate_snapshot=local["_validate_snapshot"],
        promote=local["_bootstrap_and_promote"],
        revalidate_published=local["_revalidate_published"],
        bind_output=local["_bind_output_to_snapshot"],
        revalidate_inputs=local["_revalidate_execution_inputs"],
        candidate_values=local["_candidate_values"],
        write_bundle=local["_write_bundle_canonical"],
        receipt=local["_execution_receipt"],
    )
    guarded = tuple(
        _callable_guard(name, function)
        for name, function in (
            *((name, local[name]) for name in runtime_names),
            *offline_expected,
        )
    )
    factory = local["_make_supported_executor"]
    if not callable(factory):
        raise GateError("supported executor factory is not callable")
    return factory(
        root=root,
        transaction=local["_execute_canonical_transaction"],
        bindings=bindings,
        callables=callables,
        guards=guarded,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare or execute one host-only offline-cache calibration"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    prepare = subparsers.add_parser(
        "prepare", help="emit a private draft calibration authorization"
    )
    prepare.add_argument("--new-acquisition", type=Path, required=True)
    prepare.add_argument("--base-cache", type=Path, required=True)
    prepare.add_argument("--trusted-pmbootstrap", type=Path, required=True)
    prepare.add_argument("--tag", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    subparsers.add_parser(
        "execute", help="execute only the canonical manually installed authorization"
    )
    return parser


def _json_result(value: Mapping[str, object]) -> dict[str, object]:
    return {
        key: str(item) if isinstance(item, Path) else item
        for key, item in value.items()
    }


def _make_supported_main(executor: object) -> object:
    if not callable(executor):
        raise GateError("supported calibration executor is not callable")

    def supported_main(argv: Sequence[str] | None = None) -> int:
        parser = build_parser()
        arguments = parser.parse_args(argv)
        try:
            if arguments.command == "prepare":
                result = prepare_calibration(
                    new_acquisition=arguments.new_acquisition,
                    base_cache=arguments.base_cache,
                    trusted_pmbootstrap=arguments.trusted_pmbootstrap,
                    tag=arguments.tag,
                    output=arguments.output,
                )
            else:
                result = executor()
        except GateError as error:
            parser.exit(1, f"offline-cache calibration gate failed: {error}\n")
        print(json.dumps(_json_result(result), indent=2, sort_keys=True))
        return 0

    supported_main.__name__ = "main"
    supported_main.__qualname__ = "main"
    return supported_main


execute_calibration = _install_supported_executor()
_main_factory = _resolve_local_function("_make_supported_main")
if not callable(_main_factory):
    raise GateError("supported main factory is not callable")
main = _main_factory(execute_calibration)


if __name__ == "__main__":
    raise SystemExit(main())
