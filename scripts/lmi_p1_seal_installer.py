#!/usr/bin/python3
"""Standalone, root-owned installer for inactive lmi P1 seal generations.

Production invocation is deliberately argument-free and can only write below
``/opt/lmi-p1/seals``.  This file imports no workspace module so the installed
copy can run with ``/usr/bin/python3 -I -S -B``.
"""

from __future__ import annotations

import base64
import errno
import fcntl
import hashlib
import json
import os
from pathlib import PurePosixPath
import re
import secrets
import stat
import sys
from typing import BinaryIO, Mapping


STREAM_MAGIC = b"LMI-P1-SEAL\x00V3\n"
STREAM_LENGTH_BYTES = 8
MANIFEST_SCHEMA = 3
# Installation is intentionally not a legacy read boundary.
READ_MANIFEST_SCHEMAS = frozenset({MANIFEST_SCHEMA})
SEAL_POLICY_ABI_FINGERPRINT = (
    "96aea3fd68aeeba23cd9955cf5996cdc3e6ae14518e2dccdb4c902316696c729"
)
MANIFEST_NAME = "seal.manifest.json"
OFFLINE_CACHE_SCHEMA = "lmi-p1-offline-cache/v2"
OFFLINE_CACHE_MANIFEST_NAME = "offline-cache.manifest.json"
OFFLINE_WORK_VERSION = b"8\n"
SEALS_ROOT = "/opt/lmi-p1/seals"
INSTALLER_PATH = "/usr/local/sbin/lmi-p1-seal-installer"
EMPTY_SHA256 = hashlib.sha256(b"").hexdigest()
LAYOUT = {
    "authorized_key": "authorized_key.pub",
    "offline_cache": "offline-cache",
    "pmaports": "pmaports",
    "pmbootstrap": "pmbootstrap",
    "project": "project",
    "source_lock": "source-lock.json",
}
DIRECTORY_INPUTS = frozenset({"offline_cache", "project", "pmbootstrap", "pmaports"})
POLICY_RE = re.compile(r"^[0-9a-f]{64}$")
GIT_OBJECT_RE = re.compile(r"^[0-9a-f]{40}$")
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$")
BUILDER_SIGNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+@:-]{0,255}$")
MAX_MANIFEST_BYTES = 64 * 1024 * 1024
MAX_MEMBERS = 200_000
MAX_PATH_BYTES = 1024
MAX_DEPTH = 32
MAX_SYMLINK_TARGET_BYTES = 1024
MAX_SYMLINK_TARGET_DEPTH = 32
MAX_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_FILE_BYTES = 16 * 1024 * 1024 * 1024
MAX_SOURCE_LOCK_BYTES = 1024 * 1024
MAX_OFFLINE_CACHE_MANIFEST_BYTES = 16 * 1024 * 1024
OFFLINE_WORK_DIRECTORIES = frozenset(
    {
        "work/cache_apk_aarch64",
        "work/cache_apk_x86_64",
        "work/cache_distfiles",
        "work/cache_http",
    }
)
OFFLINE_ARCHITECTURES = frozenset({"aarch64", "x86_64"})
PRODUCTION_REPOSITORY_URLS = frozenset(
    {
        "http://dl-cdn.alpinelinux.org/alpine/edge/community",
        "http://dl-cdn.alpinelinux.org/alpine/edge/main",
        "http://dl-cdn.alpinelinux.org/alpine/edge/testing",
        "http://mirror.postmarketos.org/postmarketos/main",
    }
)
EXPECTED_PMBOOTSTRAP_COMMIT = "ce76febabd983db6445fa9a8b75d601970b2f436"
EXPECTED_PMBOOTSTRAP_VERSION = "3.11.1"
EXPECTED_PMAPORTS_COMMIT = "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"
EXPECTED_PMAPORTS_TREE = "749f154b6f154f86133e7c7616074aa9eb876f2e"
BLOCK_SIZE = 1024 * 1024
SYMLINK_COMPONENTS = frozenset({"project", "pmbootstrap", "pmaports"})


class InstallerError(RuntimeError):
    """The standalone installer rejected the stream or trust boundary."""


def _duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise InstallerError(f"duplicate JSON key: {key!r}")
        result[key] = value
    return result


def _canonical(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError) as error:
        raise InstallerError(f"manifest is not canonical JSON data: {error}") from None
    return (rendered + "\n").encode("ascii")


def _safe_relative(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value or "\0" in value:
        raise InstallerError("manifest contains an unsafe member path")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InstallerError("manifest member path contains a control character")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise InstallerError("manifest member path is not UTF-8") from None
    relative = PurePosixPath(value)
    if (
        relative.is_absolute()
        or any(part in {"", ".", ".."} for part in relative.parts)
        or relative.as_posix() != value
        or len(encoded) > MAX_PATH_BYTES
        or len(relative.parts) > MAX_DEPTH
    ):
        raise InstallerError("manifest contains an unsafe or overlong member path")
    return value


def _safe_symlink_target(relative: str, value: object) -> tuple[str, bytes, str]:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or "\0" in value
        or value.startswith("/")
    ):
        raise InstallerError(f"manifest symlink target is unsafe: {relative}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InstallerError(
            f"manifest symlink target contains a control character: {relative}"
        )
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeError:
        raise InstallerError(
            f"manifest symlink target is not valid UTF-8: {relative}"
        ) from None
    raw_parts = value.split("/")
    if (
        len(encoded) > MAX_SYMLINK_TARGET_BYTES
        or len(raw_parts) > MAX_SYMLINK_TARGET_DEPTH
        or any(part == "" for part in raw_parts)
    ):
        raise InstallerError(f"manifest symlink target exceeds its limits: {relative}")
    member = PurePosixPath(relative)
    component = member.parts[0]
    if component not in SYMLINK_COMPONENTS:
        raise InstallerError(
            f"manifest symlink is outside a repository component: {relative}"
        )
    resolved = list(member.parent.parts)
    for part in raw_parts:
        if part == ".":
            continue
        if part == "..":
            if len(resolved) <= 1:
                raise InstallerError(
                    f"manifest symlink target escapes its component: {relative}"
                )
            resolved.pop()
        else:
            resolved.append(part)
        if len(resolved) > MAX_DEPTH:
            raise InstallerError(
                f"manifest symlink target resolves too deeply: {relative}"
            )
    if not resolved or resolved[0] != component:
        raise InstallerError(
            f"manifest symlink target escapes its component: {relative}"
        )
    return value, encoded, PurePosixPath(*resolved).as_posix()


def _symlink_walk_paths(relative: str, target: str) -> list[str]:
    current = list(PurePosixPath(relative).parent.parts)
    walked: list[str] = []
    for part in target.split("/"):
        if part == "..":
            current.pop()
        elif part != ".":
            current.append(part)
        walked.append(PurePosixPath(*current).as_posix())
    return walked


def _validate_symlink_graph(members: list[dict[str, object]]) -> None:
    by_path = {str(member["path"]): member for member in members}
    for member in members:
        relative = str(member["path"])
        parent = PurePosixPath(relative).parent.as_posix()
        if parent != ".":
            parent_member = by_path.get(parent)
            if parent_member is None or parent_member["type"] != "directory":
                raise InstallerError(
                    "manifest member parent is absent or not a directory: "
                    f"{relative}"
                )
        if member["type"] != "symlink":
            continue
        target, _encoded, resolved = _safe_symlink_target(
            relative, member["target"]
        )
        for traversed in _symlink_walk_paths(relative, target)[:-1]:
            traversed_member = by_path.get(traversed)
            if traversed_member is None or traversed_member["type"] != "directory":
                raise InstallerError(
                    "manifest symlink traverses a missing or non-directory member: "
                    f"{relative}"
                )
        target_member = by_path.get(resolved)
        if target_member is None:
            raise InstallerError(f"manifest symlink target is absent: {relative}")
        if target_member["type"] != "file":
            raise InstallerError(
                f"manifest symlink target is not one regular file: {relative}"
            )


def _valid_remote(value: object, label: str) -> None:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 2048
        or any(
            character.isspace()
            or ord(character) < 32
            or ord(character) == 127
            for character in value
        )
    ):
        raise InstallerError(f"seal provenance {label} remote is invalid")


def _valid_git(value: object, label: str) -> None:
    if not isinstance(value, dict) or set(value) != {"commit", "remote", "tree"}:
        raise InstallerError(f"seal provenance {label} has an invalid shape")
    _valid_remote(value["remote"], label)
    for field in ("commit", "tree"):
        if (
            not isinstance(value[field], str)
            or GIT_OBJECT_RE.fullmatch(value[field]) is None
        ):
            raise InstallerError(f"seal provenance {label}.{field} is invalid")


def _valid_provenance(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "generation",
        "offline_cache",
        "pmaports",
        "pmbootstrap",
        "project",
    }:
        raise InstallerError("seal provenance has an invalid shape")
    if type(value["generation"]) is not int or value["generation"] <= 0:
        raise InstallerError("seal provenance generation must be positive")
    _valid_git(value["project"], "project")
    _valid_git(value["pmaports"], "pmaports")
    offline_cache = value["offline_cache"]
    if not isinstance(offline_cache, dict) or set(offline_cache) != {
        "aggregate_sha256",
        "manifest_sha256",
        "schema",
    }:
        raise InstallerError("seal provenance offline_cache has an invalid shape")
    if offline_cache["schema"] != OFFLINE_CACHE_SCHEMA:
        raise InstallerError("seal provenance offline_cache schema is invalid")
    for field in ("aggregate_sha256", "manifest_sha256"):
        if (
            not isinstance(offline_cache[field], str)
            or POLICY_RE.fullmatch(offline_cache[field]) is None
        ):
            raise InstallerError(f"seal provenance offline_cache.{field} is invalid")
    pmbootstrap = value["pmbootstrap"]
    if not isinstance(pmbootstrap, dict) or set(pmbootstrap) != {
        "commit",
        "entrypoint_sha256",
        "remote",
        "tree",
        "version",
    }:
        raise InstallerError("seal provenance pmbootstrap has an invalid shape")
    _valid_remote(pmbootstrap["remote"], "pmbootstrap")
    for field in ("commit", "tree"):
        if (
            not isinstance(pmbootstrap[field], str)
            or GIT_OBJECT_RE.fullmatch(pmbootstrap[field]) is None
        ):
            raise InstallerError(f"seal provenance pmbootstrap.{field} is invalid")
    if (
        not isinstance(pmbootstrap["entrypoint_sha256"], str)
        or POLICY_RE.fullmatch(pmbootstrap["entrypoint_sha256"]) is None
    ):
        raise InstallerError("seal provenance pmbootstrap entrypoint digest is invalid")
    if (
        not isinstance(pmbootstrap["version"], str)
        or VERSION_RE.fullmatch(pmbootstrap["version"]) is None
    ):
        raise InstallerError("seal provenance pmbootstrap version is invalid")
    return value


def _validated_manifest(
    payload: bytes,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    try:
        manifest = json.loads(payload.decode("ascii"), object_pairs_hook=_duplicates)
    except InstallerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InstallerError(f"manifest is not valid canonical JSON: {error}") from None
    if not isinstance(manifest, dict) or set(manifest) != {
        "inputs",
        "layout",
        "members",
        "provenance",
        "schema",
    }:
        raise InstallerError("manifest has unexpected or missing fields")
    if _canonical(manifest) != payload:
        raise InstallerError("manifest bytes are not canonical")
    if (
        type(manifest["schema"]) is not int
        or manifest["schema"] not in READ_MANIFEST_SCHEMAS
    ):
        raise InstallerError("unsupported manifest schema")
    if manifest["layout"] != LAYOUT:
        raise InstallerError("manifest layout mismatch")
    provenance = _valid_provenance(manifest["provenance"])
    inputs = manifest["inputs"]
    if not isinstance(inputs, dict) or set(inputs) != {
        "authorized_key_sha256",
        "source_lock_sha256",
    }:
        raise InstallerError("manifest inputs have an invalid shape")
    for digest in inputs.values():
        if not isinstance(digest, str) or POLICY_RE.fullmatch(digest) is None:
            raise InstallerError("manifest input digest is invalid")
    members = manifest["members"]
    if (
        not isinstance(members, list)
        or not members
        or len(members) > MAX_MEMBERS
    ):
        raise InstallerError("manifest member count is invalid")
    result: list[dict[str, object]] = []
    seen: set[str] = set()
    directories: set[str] = set()
    total = 0
    for item in members:
        if not isinstance(item, dict):
            raise InstallerError("manifest member has an invalid shape")
        member_type = item.get("type")
        expected_fields = {"mode", "path", "sha256", "size", "type"}
        if member_type == "symlink":
            expected_fields.add("target")
        if set(item) != expected_fields:
            raise InstallerError("manifest member has an invalid shape")
        relative = _safe_relative(item["path"])
        if relative in seen:
            raise InstallerError(f"manifest contains duplicate member: {relative}")
        seen.add(relative)
        mode = item["mode"]
        size = item["size"]
        digest = item["sha256"]
        if not isinstance(member_type, str) or member_type not in {
            "directory",
            "file",
            "symlink",
        }:
            raise InstallerError(f"manifest member type is invalid: {relative}")
        if (
            type(mode) is not int
            or not 0 <= mode <= 0o777
            or (member_type != "symlink" and mode & 0o022)
        ):
            raise InstallerError(f"manifest member mode is unsafe: {relative}")
        if type(size) is not int or size < 0 or size > MAX_FILE_BYTES:
            raise InstallerError(f"manifest member size is invalid: {relative}")
        if relative == LAYOUT["source_lock"] and size > MAX_SOURCE_LOCK_BYTES:
            raise InstallerError("source lock exceeds its size limit")
        if (
            relative
            == f'{LAYOUT["offline_cache"]}/{OFFLINE_CACHE_MANIFEST_NAME}'
            and size > MAX_OFFLINE_CACHE_MANIFEST_BYTES
        ):
            raise InstallerError("offline-cache manifest exceeds its size limit")
        if not isinstance(digest, str) or POLICY_RE.fullmatch(digest) is None:
            raise InstallerError(f"manifest member digest is invalid: {relative}")
        parent = PurePosixPath(relative).parent.as_posix()
        if parent != "." and parent not in directories:
            raise InstallerError(f"manifest member parent is absent or unordered: {relative}")
        if member_type == "directory":
            if size != 0 or digest != EMPTY_SHA256:
                raise InstallerError(f"directory record is not canonical: {relative}")
            directories.add(relative)
        elif member_type == "file":
            total += size
            if total > MAX_TOTAL_FILE_BYTES:
                raise InstallerError("manifest total file size exceeds its limit")
        else:
            target, encoded, _resolved = _safe_symlink_target(
                relative, item["target"]
            )
            if (
                mode != 0o777
                or size != len(encoded)
                or digest != hashlib.sha256(encoded).hexdigest()
                or target != item["target"]
            ):
                raise InstallerError(
                    f"symlink record is not canonical: {relative}"
                )
        result.append(dict(item))
    paths = [str(item["path"]) for item in result]
    if paths != sorted(paths):
        raise InstallerError("manifest members are not path-sorted")
    _validate_symlink_graph(result)
    by_path = {str(item["path"]): item for item in result}
    expected_top = set(LAYOUT.values())
    actual_top = {path for path in paths if "/" not in path}
    if actual_top != expected_top:
        raise InstallerError("manifest fixed top-level layout is incomplete")
    for label, relative in LAYOUT.items():
        expected_type = "directory" if label in DIRECTORY_INPUTS else "file"
        if by_path[relative]["type"] != expected_type:
            raise InstallerError(f"manifest {label} has the wrong type")
    for field, relative in {
        "authorized_key_sha256": LAYOUT["authorized_key"],
        "source_lock_sha256": LAYOUT["source_lock"],
    }.items():
        if inputs[field] != by_path[relative]["sha256"]:
            raise InstallerError(f"manifest input digest mismatch: {field}")
    entrypoint = by_path.get("pmbootstrap/pmbootstrap.py")
    if (
        entrypoint is None
        or entrypoint["type"] != "file"
        or provenance["pmbootstrap"]["entrypoint_sha256"]
        != entrypoint["sha256"]
    ):
        raise InstallerError("pmbootstrap entrypoint provenance does not match member")
    return manifest, result


def _source_lock_binding(payload: bytes, provenance: Mapping[str, object]) -> None:
    if len(payload) > MAX_SOURCE_LOCK_BYTES:
        raise InstallerError("source lock exceeds its size limit")
    try:
        value = json.loads(
            payload.decode("utf-8", errors="strict"), object_pairs_hook=_duplicates
        )
    except InstallerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InstallerError(f"source lock is not valid JSON: {error}") from None
    if not isinstance(value, dict):
        raise InstallerError("source lock must be an object")
    if value.get("schema") != "lmi-source-lock/v3":
        raise InstallerError("source lock schema must be lmi-source-lock/v3")
    for label, fields in {
        "pmbootstrap": ("remote", "commit", "tree", "version", "entrypoint_sha256"),
        "pmaports": ("remote", "commit", "tree"),
        "offline_cache": ("schema", "manifest_sha256", "aggregate_sha256"),
    }.items():
        locked = value.get(label)
        sealed = provenance.get(label)
        if not isinstance(locked, dict) or not isinstance(sealed, dict):
            raise InstallerError(f"source lock is missing {label} provenance")
        for field in fields:
            if locked.get(field) != sealed.get(field):
                raise InstallerError(f"source lock provenance mismatch: {label}.{field}")


def _validate_offline_contract(
    payload: bytes,
    outer_members: list[dict[str, object]],
    provenance: Mapping[str, object],
) -> None:
    """Validate the inner v1 cache manifest without importing workspace code."""

    if len(payload) > MAX_OFFLINE_CACHE_MANIFEST_BYTES:
        raise InstallerError("offline-cache manifest exceeds its size limit")
    try:
        value = json.loads(payload.decode("ascii"), object_pairs_hook=_duplicates)
    except InstallerError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise InstallerError(f"offline-cache manifest is invalid JSON: {error}") from None
    if _canonical(value) != payload:
        raise InstallerError("offline-cache manifest bytes are not canonical")
    top = {
        "aggregate_sha256",
        "distfiles",
        "external_apks",
        "http_artifacts",
        "members",
        "pins",
        "repositories",
        "schema",
    }
    if not isinstance(value, dict) or set(value) != top:
        raise InstallerError("offline-cache manifest has an invalid top-level shape")
    if value["schema"] != OFFLINE_CACHE_SCHEMA:
        raise InstallerError("offline-cache manifest schema mismatch")
    aggregate = value["aggregate_sha256"]
    preimage = dict(value)
    del preimage["aggregate_sha256"]
    if (
        not isinstance(aggregate, str)
        or POLICY_RE.fullmatch(aggregate) is None
        or hashlib.sha256(_canonical(preimage)).hexdigest() != aggregate
    ):
        raise InstallerError("offline-cache aggregate digest mismatch")
    offline_provenance = provenance.get("offline_cache")
    if offline_provenance != {
        "aggregate_sha256": aggregate,
        "manifest_sha256": hashlib.sha256(payload).hexdigest(),
        "schema": OFFLINE_CACHE_SCHEMA,
    }:
        raise InstallerError("seal provenance offline_cache binding mismatch")

    pins = value["pins"]
    if not isinstance(pins, dict) or pins != {
        "pmbootstrap": {
            "commit": EXPECTED_PMBOOTSTRAP_COMMIT,
            "version": EXPECTED_PMBOOTSTRAP_VERSION,
            "work_version": 8,
        },
        "pmaports": {
            "channel": "edge",
            "commit": EXPECTED_PMAPORTS_COMMIT,
            "tree": EXPECTED_PMAPORTS_TREE,
        },
    }:
        raise InstallerError("offline-cache exact source pins mismatch")

    cache_prefix = LAYOUT["offline_cache"] + "/"
    directories = {
        str(item["path"])[len(cache_prefix):]
        for item in outer_members
        if item["type"] == "directory"
        and str(item["path"]).startswith(cache_prefix)
    }
    if directories != {"work", *OFFLINE_WORK_DIRECTORIES}:
        raise InstallerError("offline-cache contains forbidden mutable directories")
    actual = {
        str(item["path"])[len(cache_prefix):]: {
            "path": str(item["path"])[len(cache_prefix):],
            "sha256": item["sha256"],
            "size": item["size"],
        }
        for item in outer_members
        if item["type"] == "file"
        and str(item["path"]).startswith(cache_prefix + "work/")
    }

    def records(
        name: str,
        fields: set[str],
        key_fields: tuple[str, ...],
    ) -> list[dict[str, object]]:
        items = value[name]
        if not isinstance(items, list):
            raise InstallerError(f"offline-cache {name} must be a list")
        keys: list[tuple[str, ...]] = []
        result: list[dict[str, object]] = []
        for item in items:
            if not isinstance(item, dict) or set(item) != fields:
                raise InstallerError(f"offline-cache {name} record has an invalid shape")
            key = tuple(item[field] for field in key_fields)
            if not all(isinstance(part, str) for part in key):
                raise InstallerError(f"offline-cache {name} record has an invalid sort key")
            result.append(dict(item))
            keys.append(key)
        if keys != sorted(keys) or len(keys) != len(set(keys)):
            raise InstallerError(f"offline-cache {name} is not sorted and unique")
        return result

    declared = records("members", {"path", "sha256", "size"}, ("path",))
    declared_map: dict[str, dict[str, object]] = {}
    for item in declared:
        path = _safe_relative(item["path"])
        if not path.startswith("work/") or path == "work":
            raise InstallerError("offline-cache member path must be below work/")
        if (
            type(item["size"]) is not int
            or item["size"] < 0
            or item["size"] > MAX_FILE_BYTES
            or not isinstance(item["sha256"], str)
            or POLICY_RE.fullmatch(item["sha256"]) is None
            or path in declared_map
        ):
            raise InstallerError(f"offline-cache member metadata is invalid: {path}")
        declared_map[path] = item
    if [str(item["path"]) for item in declared] != sorted(declared_map):
        raise InstallerError("offline-cache members are not path-sorted")
    if declared_map != actual:
        raise InstallerError("offline-cache work inventory does not match its manifest")
    version = actual.get("work/version")
    if version != {
        "path": "work/version",
        "sha256": hashlib.sha256(OFFLINE_WORK_VERSION).hexdigest(),
        "size": len(OFFLINE_WORK_VERSION),
    }:
        raise InstallerError("offline-cache work/version binding mismatch")

    classifications: dict[str, int] = {}
    signer_paths: set[str] = set()

    def bind(
        item: Mapping[str, object],
        path_field: str,
        size_field: str | None,
        digest_field: str,
        prefix: str | None,
        classify: bool,
    ) -> str:
        path = _safe_relative(item[path_field])
        if not path.startswith("work/") or (
            prefix is not None and not path.startswith(prefix + "/")
        ):
            raise InstallerError(f"offline-cache path is outside its cache: {path}")
        member = actual.get(path)
        if member is None:
            raise InstallerError(f"offline-cache binding references a missing member: {path}")
        if (size_field is not None and item[size_field] != member["size"]) or item[
            digest_field
        ] != member["sha256"]:
            raise InstallerError(f"offline-cache member binding mismatch: {path}")
        if classify:
            classifications[path] = classifications.get(path, 0) + 1
        return path

    repositories = records(
        "repositories",
        {
            "architecture",
            "index_path",
            "index_sha256",
            "index_size",
            "signer_key_path",
            "signer_key_sha256",
            "url",
        },
        ("architecture", "url"),
    )
    repo_map: dict[tuple[str, str], dict[str, object]] = {}
    repository_signers: dict[str, str] = {}
    for item in repositories:
        architecture = item["architecture"]
        url = item["url"]
        if architecture not in OFFLINE_ARCHITECTURES:
            raise InstallerError("offline-cache repository architecture is invalid")
        _valid_remote(url, "offline-cache repository")
        pair = (str(url), str(architecture))
        if pair in repo_map:
            raise InstallerError("offline-cache repository binding is duplicated")
        prefix = f"work/cache_apk_{architecture}"
        expected_index = (
            f"{prefix}/APKINDEX."
            f"{hashlib.sha1(str(url).encode('utf-8'), usedforsecurity=False).hexdigest()[:8]}"
            ".tar.gz"
        )
        if item["index_path"] != expected_index:
            raise InstallerError(
                "offline-cache repository index path does not match its URL"
            )
        bind(item, "index_path", "index_size", "index_sha256", prefix, True)
        signer_path = bind(
            item, "signer_key_path", None, "signer_key_sha256", prefix, False
        )
        signer_parts = PurePosixPath(signer_path).parts
        if (
            len(signer_parts) != 3
            or signer_parts[1] != f"cache_apk_{architecture}"
            or not signer_parts[2].endswith(".rsa.pub")
        ):
            raise InstallerError("offline-cache repository signer path is invalid")
        signer_paths.add(signer_path)
        previous_signer = repository_signers.setdefault(
            signer_path, str(item["signer_key_sha256"])
        )
        if previous_signer != item["signer_key_sha256"]:
            raise InstallerError(
                "offline-cache repository signer path has conflicting bytes"
            )
        repo_map[pair] = item
    expected_pairs = {
        (url, arch) for url in PRODUCTION_REPOSITORY_URLS for arch in OFFLINE_ARCHITECTURES
    }
    if set(repo_map) != expected_pairs:
        raise InstallerError("offline-cache repository URL/architecture set mismatch")

    for item in records(
        "external_apks",
        {
            "architecture", "apkindex_checksum", "builder_signer", "index_sha256",
            "index_signer_key_path", "index_signer_key_sha256", "name", "path",
            "repository_url", "sha256", "size", "version",
        },
        ("architecture", "name", "version", "path"),
    ):
        architecture = item["architecture"]
        for field in ("name", "version"):
            if not isinstance(item[field], str) or VERSION_RE.fullmatch(item[field]) is None:
                raise InstallerError(f"offline-cache external APK {field} is invalid")
        if (
            not isinstance(item["builder_signer"], str)
            or BUILDER_SIGNER_RE.fullmatch(item["builder_signer"]) is None
        ):
            raise InstallerError("offline-cache external APK builder provenance is invalid")
        checksum = item["apkindex_checksum"]
        try:
            checksum_bytes = base64.b64decode(str(checksum)[2:], validate=True)
        except (ValueError, base64.binascii.Error):
            checksum_bytes = b""
        if (
            not isinstance(checksum, str)
            or not checksum.startswith("Q1")
            or len(checksum_bytes) != hashlib.sha1().digest_size
            or checksum != "Q1" + base64.b64encode(checksum_bytes).decode("ascii")
        ):
            raise InstallerError("offline-cache external APK index checksum is invalid")
        _valid_remote(item["repository_url"], "offline-cache external APK")
        repository = repo_map.get((str(item["repository_url"]), str(architecture)))
        if repository is None or (
            item["index_sha256"] != repository["index_sha256"]
            or item["index_signer_key_path"] != repository["signer_key_path"]
            or item["index_signer_key_sha256"] != repository["signer_key_sha256"]
        ):
            raise InstallerError("offline-cache external APK index trust binding mismatch")
        apk_path = bind(
            item, "path", "size", "sha256", f"work/cache_apk_{architecture}", True
        )
        apk_parts = PurePosixPath(apk_path).parts
        if (
            len(apk_parts) != 3
            or apk_parts[1] != f"cache_apk_{architecture}"
            or not apk_parts[2].endswith(".apk")
        ):
            raise InstallerError(
                "offline-cache external APK path is not a flat APK cache path"
            )

    http_artifacts = records(
        "http_artifacts",
        {"kind", "name", "path", "sha256", "signer_key_path", "signer_key_sha256", "size", "url", "version"},
        ("kind", "name", "version", "url", "path"),
    )
    if len(http_artifacts) != 1:
        raise InstallerError(
            "offline-cache manifest must contain exactly one apk-tools-static artifact"
        )
    for item in http_artifacts:
        for field in ("kind", "name", "version"):
            if not isinstance(item[field], str) or VERSION_RE.fullmatch(item[field]) is None:
                raise InstallerError(f"offline-cache HTTP artifact {field} is invalid")
        if item["kind"] != "apk-tools-static" or item["name"] != "apk-tools-static":
            raise InstallerError("offline-cache HTTP artifact is not apk-tools-static")
        _valid_remote(item["url"], "offline-cache HTTP artifact")
        http_path = bind(item, "path", "size", "sha256", "work/cache_http", True)
        http_parts = PurePosixPath(http_path).parts
        if (
            len(http_parts) != 3
            or http_parts[1] != "cache_http"
            or http_parts[2].startswith("APKINDEX_")
        ):
            raise InstallerError("offline-cache HTTP artifact path is invalid")
        http_signer = bind(
            item, "signer_key_path", None, "signer_key_sha256", None, False
        )
        if repository_signers.get(http_signer) != item["signer_key_sha256"]:
            raise InstallerError(
                "offline-cache HTTP signer is not an existing repository signer"
            )
        signer_paths.add(http_signer)

    distfiles = records(
        "distfiles", {"apkbuild_sha512", "path", "sha256", "size", "url"},
        ("url", "path"),
    )
    if len(distfiles) != 1:
        raise InstallerError(
            "offline-cache manifest must contain exactly one kernel distfile"
        )
    for item in distfiles:
        _valid_remote(item["url"], "offline-cache distfile")
        if not isinstance(item["apkbuild_sha512"], str) or re.fullmatch(
            r"[0-9a-f]{128}", item["apkbuild_sha512"]
        ) is None:
            raise InstallerError("offline-cache distfile APKBUILD SHA512 is invalid")
        distfile_path = bind(
            item, "path", "size", "sha256", "work/cache_distfiles", True
        )
        distfile_parts = PurePosixPath(distfile_path).parts
        if len(distfile_parts) != 3 or distfile_parts[1] != "cache_distfiles":
            raise InstallerError("offline-cache distfile path is not flat")
    if set(classifications) & signer_paths:
        raise InstallerError("offline-cache member has conflicting classifications")
    if set(classifications) | signer_paths != set(actual) - {"work/version"} or any(
        count != 1 for count in classifications.values()
    ):
        raise InstallerError("offline-cache members are not classified exactly once")

    outer_by_path = {str(item["path"]): item for item in outer_members}
    key_fingerprints: dict[str, tuple[object, object]] = {}
    for signer_path in sorted(signer_paths):
        basename = PurePosixPath(signer_path).name
        if not basename.endswith(".rsa.pub") or len(basename.encode("utf-8")) > 255:
            raise InstallerError("offline-cache signer key has an invalid basename")
        cache_member = outer_by_path.get(cache_prefix + signer_path)
        trust_member = outer_by_path.get(
            LAYOUT["pmbootstrap"] + "/pmb/data/keys/" + basename
        )
        if (
            cache_member is None
            or trust_member is None
            or cache_member.get("type") != "file"
            or trust_member.get("type") != "file"
        ):
            raise InstallerError(
                "offline-cache signer key is absent from the pinned pmbootstrap trust root"
            )
        fingerprint = (cache_member.get("size"), cache_member.get("sha256"))
        if fingerprint != (trust_member.get("size"), trust_member.get("sha256")):
            raise InstallerError(
                "offline-cache signer key differs from the pinned pmbootstrap trust root"
            )
        previous = key_fingerprints.setdefault(basename, fingerprint)
        if previous != fingerprint:
            raise InstallerError(
                "offline-cache signer basename has conflicting key material"
            )


def _read_exact(stream: BinaryIO, length: int, label: str) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        try:
            block = stream.read(min(BLOCK_SIZE, remaining))
        except OSError as error:
            raise InstallerError(f"could not read {label}: {error}") from None
        if not isinstance(block, bytes):
            raise InstallerError("installer input must be a binary stream")
        if not block:
            raise InstallerError(f"seal stream is truncated in {label}")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        try:
            written = os.write(fd, view)
        except OSError as error:
            raise InstallerError(f"could not write installed member: {error}") from None
        if written <= 0:
            raise InstallerError("installed member write made no progress")
        view = view[written:]


def _identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _secure_symlink_at(
    parent_fd: int,
    name: str,
    member: Mapping[str, object],
    *,
    uid: int,
    gid: int,
) -> None:
    try:
        before = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        first_target = os.readlink(name, dir_fd=parent_fd)
        second_target = os.readlink(name, dir_fd=parent_fd)
        after = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        xattrs = os.listxattr(
            f"/proc/self/fd/{parent_fd}/{name}", follow_symlinks=False
        )
    except (AttributeError, NotImplementedError):
        raise InstallerError("filesystem symlink inspection is unavailable") from None
    except OSError as error:
        raise InstallerError(f"could not inspect created symlink: {error}") from None
    try:
        encoded = first_target.encode("utf-8", errors="strict")
    except UnicodeError:
        raise InstallerError("created symlink target is not valid UTF-8") from None
    if (
        not stat.S_ISLNK(before.st_mode)
        or _identity(before) != _identity(after)
        or before.st_nlink != 1
        or before.st_uid != uid
        or before.st_gid != gid
        or stat.S_IMODE(before.st_mode) != 0o777
        or before.st_size != member["size"]
        or first_target != second_target
        or first_target != member["target"]
        or len(encoded) != member["size"]
        or hashlib.sha256(encoded).hexdigest() != member["sha256"]
        or xattrs
    ):
        raise InstallerError(
            f"created symlink metadata does not match its manifest: {member['path']}"
        )


def _secure_fd(fd: int, *, directory: bool, mode: int, uid: int, gid: int) -> None:
    metadata = os.fstat(fd)
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if (
        not expected_type(metadata.st_mode)
        or (not directory and metadata.st_nlink != 1)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise InstallerError("created member metadata does not match its manifest")
    try:
        if os.listxattr(fd):
            raise InstallerError("created member unexpectedly has xattrs")
    except (AttributeError, NotImplementedError):
        raise InstallerError("filesystem xattr inspection is unavailable") from None
    except OSError as error:
        raise InstallerError(f"could not inspect created member xattrs: {error}") from None


def _open_directory_at(parent_fd: int, name: str) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return os.open(name, flags, dir_fd=parent_fd)


def _open_parent(root_fd: int, relative: str) -> int:
    current = os.dup(root_fd)
    try:
        for part in PurePosixPath(relative).parts[:-1]:
            following = _open_directory_at(current, part)
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def _verify_installed_generation(
    generation_fd: int,
    members: list[dict[str, object]],
    manifest_payload: bytes,
    *,
    uid: int,
    gid: int,
) -> None:
    expected_children: dict[str, set[str]] = {".": {MANIFEST_NAME}}
    for member in members:
        path = PurePosixPath(str(member["path"]))
        parent = path.parent.as_posix()
        expected_children.setdefault(parent, set()).add(path.name)
        if member["type"] == "directory":
            expected_children.setdefault(path.as_posix(), set())
    if set(os.listdir(generation_fd)) != expected_children["."]:
        raise InstallerError("installed generation has an unexpected top-level layout")

    for member in members:
        relative = str(member["path"])
        parent_fd = _open_parent(generation_fd, relative)
        try:
            name = PurePosixPath(relative).name
            if member["type"] == "directory":
                descriptor = _open_directory_at(parent_fd, name)
                try:
                    _secure_fd(
                        descriptor,
                        directory=True,
                        mode=int(member["mode"]),
                        uid=uid,
                        gid=gid,
                    )
                    if set(os.listdir(descriptor)) != expected_children[relative]:
                        raise InstallerError(
                            f"installed directory inventory mismatch: {relative}"
                        )
                finally:
                    os.close(descriptor)
            elif member["type"] == "file":
                descriptor = os.open(
                    name,
                    os.O_RDONLY
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    dir_fd=parent_fd,
                )
                digest = hashlib.sha256()
                try:
                    _secure_fd(
                        descriptor,
                        directory=False,
                        mode=int(member["mode"]),
                        uid=uid,
                        gid=gid,
                    )
                    metadata = os.fstat(descriptor)
                    if metadata.st_size != member["size"]:
                        raise InstallerError(
                            f"installed member size mismatch: {relative}"
                        )
                    while True:
                        block = os.read(descriptor, BLOCK_SIZE)
                        if not block:
                            break
                        digest.update(block)
                    if digest.hexdigest() != member["sha256"]:
                        raise InstallerError(
                            f"installed member digest mismatch: {relative}"
                        )
                finally:
                    os.close(descriptor)
            else:
                _secure_symlink_at(
                    parent_fd,
                    name,
                    member,
                    uid=uid,
                    gid=gid,
                )
        finally:
            os.close(parent_fd)

    manifest_fd = os.open(
        MANIFEST_NAME,
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=generation_fd,
    )
    try:
        _secure_fd(manifest_fd, directory=False, mode=0o600, uid=uid, gid=gid)
        if os.fstat(manifest_fd).st_size != len(manifest_payload):
            raise InstallerError("installed manifest size mismatch")
        digest = hashlib.sha256()
        while True:
            block = os.read(manifest_fd, BLOCK_SIZE)
            if not block:
                break
            digest.update(block)
        if digest.digest() != hashlib.sha256(manifest_payload).digest():
            raise InstallerError("installed manifest digest mismatch")
    finally:
        os.close(manifest_fd)


def _remove_tree_at(parent_fd: int, name: str) -> None:
    try:
        root_fd = _open_directory_at(parent_fd, name)
    except FileNotFoundError:
        return
    try:
        for entry in list(os.scandir(root_fd)):
            metadata = os.stat(entry.name, dir_fd=root_fd, follow_symlinks=False)
            if stat.S_ISDIR(metadata.st_mode):
                _remove_tree_at(root_fd, entry.name)
            else:
                os.unlink(entry.name, dir_fd=root_fd)
    finally:
        os.close(root_fd)
    os.rmdir(name, dir_fd=parent_fd)


def _secure_ancestry(path: str, *, uid: int, gid: int) -> None:
    if not os.path.isabs(path) or ".." in PurePosixPath(path).parts:
        raise InstallerError("trusted path is not absolute and normalized")
    current = "/"
    candidates = [current]
    for part in PurePosixPath(path).parts[1:]:
        current = os.path.join(current, part)
        candidates.append(current)
    for current in candidates:
        try:
            metadata = os.lstat(current)
        except OSError as error:
            raise InstallerError(f"could not inspect trusted ancestry: {error}") from None
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise InstallerError(f"trusted ancestry is unsafe: {current}")
        try:
            if os.listxattr(current, follow_symlinks=False):
                raise InstallerError(f"trusted ancestry has xattrs: {current}")
        except (AttributeError, NotImplementedError):
            raise InstallerError("filesystem xattr inspection is unavailable") from None
        except OSError as error:
            raise InstallerError(f"could not inspect trusted ancestry: {error}") from None


def _install_stream(
    stream: BinaryIO,
    *,
    seals_root: str = SEALS_ROOT,
    expected_uid: int = 0,
    expected_gid: int = 0,
    verify_ancestry: bool = True,
    expected_input_identity: tuple[int, ...] | None = None,
) -> str:
    """Install exactly one inactive generation; path injection is test-only."""

    if verify_ancestry:
        _secure_ancestry(seals_root, uid=expected_uid, gid=expected_gid)
    root_flags = (
        os.O_RDONLY
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        seals_fd = os.open(seals_root, root_flags)
    except OSError as error:
        raise InstallerError(f"could not open fixed seals root: {error}") from None
    temporary_name: str | None = None
    installed = False
    try:
        _secure_fd(
            seals_fd,
            directory=True,
            mode=0o700,
            uid=expected_uid,
            gid=expected_gid,
        )
        try:
            fcntl.flock(seals_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno in {errno.EACCES, errno.EAGAIN}:
                raise InstallerError("another seal installation is in progress") from None
            raise InstallerError(f"could not lock seals root: {error}") from None

        if _read_exact(stream, len(STREAM_MAGIC), "stream magic") != STREAM_MAGIC:
            raise InstallerError("seal stream magic/version is invalid")
        manifest_length = int.from_bytes(
            _read_exact(stream, STREAM_LENGTH_BYTES, "manifest length"), "big"
        )
        if manifest_length <= 0 or manifest_length > MAX_MANIFEST_BYTES:
            raise InstallerError("seal manifest length exceeds its limit")
        manifest_payload = _read_exact(stream, manifest_length, "manifest")
        manifest, members = _validated_manifest(manifest_payload)
        policy_id = hashlib.sha256(manifest_payload).hexdigest()
        try:
            os.stat(policy_id, dir_fd=seals_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise InstallerError("policy generation is already installed")

        for _attempt in range(32):
            candidate = f".incoming-{secrets.token_hex(16)}"
            try:
                os.mkdir(candidate, 0o700, dir_fd=seals_fd)
            except FileExistsError:
                continue
            temporary_name = candidate
            break
        if temporary_name is None:
            raise InstallerError("could not allocate an inactive generation")
        generation_fd = _open_directory_at(seals_fd, temporary_name)
        try:
            _secure_fd(
                generation_fd,
                directory=True,
                mode=0o700,
                uid=expected_uid,
                gid=expected_gid,
            )
            source_lock_payload: bytes | None = None
            offline_manifest_payload: bytes | None = None
            for member in members:
                relative = str(member["path"])
                parent_fd = _open_parent(generation_fd, relative)
                try:
                    name = PurePosixPath(relative).name
                    if member["type"] == "directory":
                        os.mkdir(name, 0o700, dir_fd=parent_fd)
                        child_fd = _open_directory_at(parent_fd, name)
                        try:
                            os.fchmod(child_fd, int(member["mode"]))
                            os.fsync(child_fd)
                            _secure_fd(
                                child_fd,
                                directory=True,
                                mode=int(member["mode"]),
                                uid=expected_uid,
                                gid=expected_gid,
                            )
                        finally:
                            os.close(child_fd)
                    elif member["type"] == "file":
                        flags = (
                            os.O_WRONLY
                            | os.O_CREAT
                            | os.O_EXCL
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0)
                        )
                        output_fd = os.open(name, flags, 0o600, dir_fd=parent_fd)
                        digest = hashlib.sha256()
                        capture_limit: int | None = None
                        capture_error = ""
                        if relative == LAYOUT["source_lock"]:
                            capture_limit = MAX_SOURCE_LOCK_BYTES
                            capture_error = "source lock exceeds its size limit"
                        elif relative == (
                            f'{LAYOUT["offline_cache"]}/'
                            f"{OFFLINE_CACHE_MANIFEST_NAME}"
                        ):
                            capture_limit = MAX_OFFLINE_CACHE_MANIFEST_BYTES
                            capture_error = (
                                "offline-cache manifest exceeds its size limit"
                            )
                        captured = (
                            bytearray() if capture_limit is not None else None
                        )
                        try:
                            remaining = int(member["size"])
                            while remaining:
                                block = _read_exact(
                                    stream,
                                    min(BLOCK_SIZE, remaining),
                                    f"member {relative}",
                                )
                                remaining -= len(block)
                                digest.update(block)
                                if captured is not None and capture_limit is not None:
                                    if len(block) > capture_limit - len(captured):
                                        raise InstallerError(capture_error)
                                    captured.extend(block)
                                _write_all(output_fd, block)
                            if digest.hexdigest() != member["sha256"]:
                                raise InstallerError(
                                    f"member digest does not match manifest: {relative}"
                                )
                            os.fchmod(output_fd, int(member["mode"]))
                            os.fsync(output_fd)
                            _secure_fd(
                                output_fd,
                                directory=False,
                                mode=int(member["mode"]),
                                uid=expected_uid,
                                gid=expected_gid,
                            )
                            metadata = os.fstat(output_fd)
                            if metadata.st_size != member["size"]:
                                raise InstallerError(
                                    f"installed member size mismatch: {relative}"
                                )
                        finally:
                            os.close(output_fd)
                        if captured is not None:
                            if relative == LAYOUT["source_lock"]:
                                source_lock_payload = bytes(captured)
                            else:
                                offline_manifest_payload = bytes(captured)
                    else:
                        os.symlink(
                            str(member["target"]),
                            name,
                            dir_fd=parent_fd,
                        )
                        os.chown(
                            name,
                            expected_uid,
                            expected_gid,
                            dir_fd=parent_fd,
                            follow_symlinks=False,
                        )
                        _secure_symlink_at(
                            parent_fd,
                            name,
                            member,
                            uid=expected_uid,
                            gid=expected_gid,
                        )
                    os.fsync(parent_fd)
                finally:
                    os.close(parent_fd)
            try:
                trailing = stream.read(1)
            except OSError as error:
                raise InstallerError(f"could not check stream terminator: {error}") from None
            if trailing:
                raise InstallerError("seal stream has trailing bytes")
            if source_lock_payload is None:
                raise InstallerError("seal stream omitted source-lock.json")
            if offline_manifest_payload is None:
                raise InstallerError("seal stream omitted offline-cache manifest")
            _source_lock_binding(source_lock_payload, manifest["provenance"])
            _validate_offline_contract(
                offline_manifest_payload, members, manifest["provenance"]
            )

            flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            manifest_fd = os.open(MANIFEST_NAME, flags, 0o600, dir_fd=generation_fd)
            try:
                _write_all(manifest_fd, manifest_payload)
                os.fchmod(manifest_fd, 0o600)
                os.fsync(manifest_fd)
                _secure_fd(
                    manifest_fd,
                    directory=False,
                    mode=0o600,
                    uid=expected_uid,
                    gid=expected_gid,
                )
            finally:
                os.close(manifest_fd)
            _verify_installed_generation(
                generation_fd,
                members,
                manifest_payload,
                uid=expected_uid,
                gid=expected_gid,
            )
            os.fsync(generation_fd)
        finally:
            os.close(generation_fd)
        if expected_input_identity is not None:
            final_input_identity = _verify_regular_input(stream)
            if final_input_identity != expected_input_identity:
                raise InstallerError("installer input file changed while reading")
        os.rename(
            temporary_name,
            policy_id,
            src_dir_fd=seals_fd,
            dst_dir_fd=seals_fd,
        )
        temporary_name = policy_id
        os.fsync(seals_fd)
        installed = True
        return policy_id
    except InstallerError:
        raise
    except OSError as error:
        raise InstallerError(f"could not install seal: {error}") from None
    finally:
        if temporary_name is not None and not installed:
            try:
                _remove_tree_at(seals_fd, temporary_name)
                os.fsync(seals_fd)
            except OSError:
                pass
        os.close(seals_fd)


def _verify_installed_self() -> None:
    configured = os.path.abspath(INSTALLER_PATH)
    executing = os.path.abspath(__file__)
    if executing != configured:
        raise InstallerError("installer is not running from its fixed installed path")
    _secure_ancestry(os.path.dirname(configured), uid=0, gid=0)
    try:
        metadata = os.lstat(configured)
    except OSError as error:
        raise InstallerError(f"could not inspect installed installer: {error}") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != 0
        or metadata.st_gid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o755
    ):
        raise InstallerError("installed installer metadata is not root:root 0755")
    if os.listxattr(configured, follow_symlinks=False):
        raise InstallerError("installed installer has xattrs")


def _verify_root_process() -> None:
    getresuid = getattr(os, "getresuid", None)
    getresgid = getattr(os, "getresgid", None)
    if getresuid is None or getresgid is None:
        raise InstallerError("platform cannot verify real/effective/saved IDs")
    if tuple(getresuid()) != (0, 0, 0) or tuple(getresgid()) != (0, 0, 0):
        raise InstallerError("installer requires root real/effective/saved IDs")
    try:
        os.setgroups([])
    except OSError as error:
        raise InstallerError(f"could not clear supplementary groups: {error}") from None
    if os.getgroups():
        raise InstallerError("supplementary groups were not cleared")
    os.umask(0o077)


def _verify_regular_input(stream: BinaryIO) -> tuple[int, ...]:
    try:
        fd = stream.fileno()
        metadata = os.fstat(fd)
    except (AttributeError, OSError) as error:
        raise InstallerError(f"installer stdin is not inspectable: {error}") from None
    maximum = (
        len(STREAM_MAGIC)
        + STREAM_LENGTH_BYTES
        + MAX_MANIFEST_BYTES
        + MAX_TOTAL_FILE_BYTES
    )
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size > maximum
    ):
        raise InstallerError("installer stdin must be one bounded regular stream file")
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    try:
        if len(argv) != 1:
            raise InstallerError("installer accepts no command-line arguments")
        if not (
            sys.flags.isolated
            and sys.flags.no_site
            and sys.flags.dont_write_bytecode
            and sys.flags.ignore_environment
        ):
            raise InstallerError("installer requires Python flags -I -S -B")
        _verify_root_process()
        _verify_installed_self()
        before = _verify_regular_input(sys.stdin.buffer)
        policy_id = _install_stream(
            sys.stdin.buffer,
            expected_input_identity=before,
        )
    except InstallerError as error:
        sys.stderr.write(f"lmi-p1 seal installer rejected input: {error}\n")
        return 1
    sys.stdout.write(policy_id + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
