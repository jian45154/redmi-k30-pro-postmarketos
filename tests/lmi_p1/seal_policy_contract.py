"""Canonical ABI evidence and differential cases for the standalone seal TCB."""

from __future__ import annotations

import copy
from dataclasses import dataclass
import hashlib
import json
from typing import Mapping


POLICY_ABI: dict[str, object] = {
    "abi": "lmi-p1-seal-policy/v3",
    "directory_inputs": ["offline_cache", "pmaports", "pmbootstrap", "project"],
    "layout": {
        "authorized_key": "authorized_key.pub",
        "offline_cache": "offline-cache",
        "pmaports": "pmaports",
        "pmbootstrap": "pmbootstrap",
        "project": "project",
        "source_lock": "source-lock.json",
    },
    "limits": {
        "file_bytes": 4 * 1024 * 1024 * 1024,
        "manifest_bytes": 64 * 1024 * 1024,
        "members": 200_000,
        "offline_cache_manifest_bytes": 16 * 1024 * 1024,
        "path_bytes": 1024,
        "path_depth": 32,
        "symlink_target_bytes": 1024,
        "symlink_target_depth": 32,
        "total_file_bytes": 16 * 1024 * 1024 * 1024,
    },
    "manifest": {
        "fields": ["inputs", "layout", "members", "provenance", "schema"],
        "input_fields": ["authorized_key_sha256", "source_lock_sha256"],
        "member_fields": {
            "directory": ["mode", "path", "sha256", "size", "type"],
            "file": ["mode", "path", "sha256", "size", "type"],
            "symlink": ["mode", "path", "sha256", "size", "target", "type"],
        },
        "member_types_by_schema": {
            "2": ["directory", "file"],
            "3": ["directory", "file", "symlink"],
        },
    },
    "provenance_fields": {
        "git": ["commit", "remote", "tree"],
        "offline_cache": ["aggregate_sha256", "manifest_sha256", "schema"],
        "pmbootstrap": [
            "commit",
            "entrypoint_sha256",
            "remote",
            "tree",
            "version",
        ],
        "top": [
            "generation",
            "offline_cache",
            "pmaports",
            "pmbootstrap",
            "project",
        ],
    },
    "schemas": {
        "current": 3,
        "installer_read": [3],
        "legacy": 2,
        "producer_write": 3,
        "verifier_read": [2, 3],
    },
    "stream": {
        "length_bytes": 8,
        "magic_hex": b"LMI-P1-SEAL\x00V3\n".hex(),
        "payload_member_types": ["file"],
    },
    "symlink": {
        "allow_ancestor": False,
        "allow_chain": False,
        "components": ["pmaports", "pmbootstrap", "project"],
        "mode": 0o777,
        "target_encoding": "UTF-8",
        "target_member_type": "file",
        "target_scope": "relative-lexical-same-component",
    },
}


def canonical_abi_bytes() -> bytes:
    return (
        json.dumps(POLICY_ABI, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


POLICY_ABI_FINGERPRINT = hashlib.sha256(canonical_abi_bytes()).hexdigest()


@dataclass(frozen=True)
class ManifestCase:
    name: str
    manifest: dict[str, object]
    producer_accepts: bool
    installer_accepts: bool
    launcher_accepts: bool


def _bind_target(record: dict[str, object], target: str) -> None:
    try:
        encoded = target.encode("utf-8", errors="strict")
    except UnicodeError:
        encoded = b"invalid-utf8-placeholder"
    record["target"] = target
    record["size"] = len(encoded)
    record["sha256"] = hashlib.sha256(encoded).hexdigest()


def manifest_cases(base: Mapping[str, object]) -> tuple[ManifestCase, ...]:
    """Return one shared accept/reject corpus for all three frozen validators."""

    def clone() -> dict[str, object]:
        return copy.deepcopy(dict(base))

    def symlink(value: dict[str, object]) -> dict[str, object]:
        return next(
            item
            for item in value["members"]
            if item["type"] == "symlink"
        )

    def member(value: dict[str, object], path: str) -> dict[str, object]:
        return next(item for item in value["members"] if item["path"] == path)

    cases: list[ManifestCase] = [
        ManifestCase("valid-v3", clone(), True, True, True),
    ]

    legacy = clone()
    legacy["schema"] = 2
    legacy["members"] = [
        item for item in legacy["members"] if item["type"] != "symlink"
    ]
    cases.append(ManifestCase("valid-v2-reader-only", legacy, True, False, True))

    legacy_link = clone()
    legacy_link["schema"] = 2
    cases.append(ManifestCase("v2-forbids-symlink", legacy_link, False, False, False))

    internal = clone()
    transit = {
        "mode": 0o755,
        "path": "pmaports/transit",
        "sha256": hashlib.sha256(b"").hexdigest(),
        "size": 0,
        "type": "directory",
    }
    internal["members"].append(transit)
    _bind_target(symlink(internal), "transit/../pmaports.cfg")
    internal["members"].sort(key=lambda item: item["path"])
    cases.append(ManifestCase("internal-dotdot", internal, True, True, True))

    offline_limit = POLICY_ABI["limits"]["offline_cache_manifest_bytes"]
    offline_path = "offline-cache/offline-cache.manifest.json"
    offline_boundary = clone()
    member(offline_boundary, offline_path)["size"] = offline_limit
    cases.append(
        ManifestCase(
            "offline-manifest-size-boundary",
            offline_boundary,
            True,
            True,
            True,
        )
    )

    path_scoped = clone()
    ordinary_file = next(
        item
        for item in path_scoped["members"]
        if item["type"] == "file" and item["path"] != offline_path
    )
    ordinary_file["size"] = offline_limit + 1
    cases.append(
        ManifestCase(
            "offline-limit-is-exact-path-scoped",
            path_scoped,
            True,
            True,
            True,
        )
    )

    mutations: list[tuple[str, object]] = []

    offline_oversized = clone()
    member(offline_oversized, offline_path)["size"] = offline_limit + 1
    mutations.append(("offline-manifest-oversized", offline_oversized))

    invalid_schema = clone()
    invalid_schema["schema"] = 4
    mutations.append(("unsupported-schema", invalid_schema))

    invalid_layout = clone()
    invalid_layout["layout"]["pmaports"] = "elsewhere"
    mutations.append(("layout-drift", invalid_layout))

    invalid_provenance = clone()
    invalid_provenance["provenance"]["project"]["tree"] = "z" * 40
    mutations.append(("provenance-drift", invalid_provenance))

    invalid_utf8 = clone()
    _bind_target(symlink(invalid_utf8), "\udcff")
    mutations.append(("target-invalid-utf8", invalid_utf8))

    noncanonical_target_digest = clone()
    symlink(noncanonical_target_digest)["sha256"] = "0" * 64
    mutations.append(("target-digest-drift", noncanonical_target_digest))

    escaped = clone()
    _bind_target(symlink(escaped), "../pmbootstrap/pmbootstrap.py")
    mutations.append(("target-escape", escaped))

    dangling = clone()
    _bind_target(symlink(dangling), "missing")
    mutations.append(("target-dangling", dangling))

    directory_target = clone()
    _bind_target(symlink(directory_target), ".")
    mutations.append(("target-directory", directory_target))

    missing_transit = clone()
    _bind_target(symlink(missing_transit), "missing/../pmaports.cfg")
    mutations.append(("target-missing-transit", missing_transit))

    chained = clone()
    first = symlink(chained)
    second = copy.deepcopy(first)
    second["path"] = "pmaports/second.alias"
    _bind_target(second, "pmaports.cfg")
    _bind_target(first, "second.alias")
    chained["members"].append(second)
    chained["members"].sort(key=lambda item: item["path"])
    mutations.append(("target-chain", chained))

    ancestor = clone()
    link = symlink(ancestor)
    ancestor["members"].append(
        {
            "mode": 0o644,
            "path": str(link["path"]) + "/child",
            "sha256": hashlib.sha256(b"child").hexdigest(),
            "size": len(b"child"),
            "type": "file",
        }
    )
    ancestor["members"].sort(key=lambda item: item["path"])
    mutations.append(("symlink-as-ancestor", ancestor))

    overlong = clone()
    _bind_target(symlink(overlong), "a" * 1025)
    mutations.append(("target-overlong", overlong))

    target_deep = clone()
    _bind_target(symlink(target_deep), "./" * 33 + "pmaports.cfg")
    mutations.append(("target-too-deep", target_deep))

    path_overlong = clone()
    symlink(path_overlong)["path"] = "pmaports/" + "a" * 1016
    path_overlong["members"].sort(key=lambda item: item["path"])
    mutations.append(("member-path-overlong", path_overlong))

    path_deep = clone()
    symlink(path_deep)["path"] = "pmaports/" + "/".join("a" for _ in range(32))
    path_deep["members"].sort(key=lambda item: item["path"])
    mutations.append(("member-path-too-deep", path_deep))

    path_normalization = clone()
    symlink(path_normalization)["path"] = "pmaports//pmaports.alias"
    mutations.append(("member-path-normalization", path_normalization))

    unordered = clone()
    unordered["members"] = list(reversed(unordered["members"]))
    mutations.append(("member-order", unordered))

    unsupported_type = clone()
    symlink(unsupported_type).pop("target")
    symlink(unsupported_type)["type"] = "fifo"
    mutations.append(("special-member-type", unsupported_type))

    for name, value in mutations:
        cases.append(ManifestCase(name, value, False, False, False))
    return tuple(cases)
