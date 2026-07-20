#!/usr/bin/env python3
"""Command-line entry point for the lmi P1 pipeline."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, fields, is_dataclass
import importlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Sequence

if __package__:
    from .lmi_p1.common import GateError
else:
    from lmi_p1.common import GateError


_REQUEST_SCHEMA = "lmi-p1-build-request/v1"
_POLICY_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_RUN_RE = re.compile(r"^run-[0-9a-f]{32}$")
_MAX_REQUEST_BYTES = 4096


def _import_lmi_p1_module(name: str) -> object:
    """Import one command's implementation without widening other commands' TCB."""

    prefix = f"{__package__}.lmi_p1" if __package__ else "lmi_p1"
    return importlib.import_module(f"{prefix}.{name}")


def curate_offline_cache_acquisition(*args: object, **kwargs: object) -> object:
    module = _import_lmi_p1_module("acquisition")
    return module.curate_offline_cache_acquisition(*args, **kwargs)  # type: ignore[attr-defined]


def load_promotion_authorization() -> object:
    module = _import_lmi_p1_module("offline_cache")
    return module.load_promotion_authorization()  # type: ignore[attr-defined]


def promote_offline_cache(*args: object, **kwargs: object) -> object:
    module = _import_lmi_p1_module("offline_cache")
    return module.promote_offline_cache(*args, **kwargs)  # type: ignore[attr-defined]


def build_candidate(*args: object, **kwargs: object) -> object:
    module = _import_lmi_p1_module("build")
    return module.build_candidate(*args, **kwargs)  # type: ignore[attr-defined]


def revalidate_sealed_build_result(*args: object, **kwargs: object) -> object:
    module = _import_lmi_p1_module("build")
    return module.revalidate_sealed_build_result(  # type: ignore[attr-defined]
        *args, **kwargs
    )


@dataclass(frozen=True)
class SealedCliPaths:
    active: Path = Path("/opt/lmi-p1/active-policy")
    seals: Path = Path("/opt/lmi-p1/seals")
    runs: Path = Path("/var/lib/lmi-p1/runs")
    trusted_root: Path = Path("/")


DEFAULT_SEALED_PATHS = SealedCliPaths()


def _duplicate_request_field(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise GateError(f"build request contains duplicate field: {name!r}")
        result[name] = value
    return result


def _canonical_request_bytes(value: object) -> bytes:
    try:
        rendered = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    except (TypeError, ValueError) as error:
        raise GateError(f"build request is not canonical JSON data: {error}") from None
    return (rendered + "\n").encode("ascii")


def _read_sealed_request(
    request_path: Path,
    *,
    paths: SealedCliPaths,
    expected_uid: int,
    expected_gid: int,
) -> tuple[dict[str, str], Path]:
    seal_module = _import_lmi_p1_module("seal")
    _check_owner_and_mode = seal_module._check_owner_and_mode  # type: ignore[attr-defined]
    _check_secure_ancestry = seal_module._check_secure_ancestry  # type: ignore[attr-defined]
    _metadata_identity = seal_module._metadata_identity  # type: ignore[attr-defined]
    request_path = Path(request_path).absolute()
    runs_root = Path(paths.runs).absolute()
    run_root = request_path.parent
    if (
        request_path.name != "request.json"
        or run_root.parent != runs_root
        or _RUN_RE.fullmatch(run_root.name) is None
    ):
        raise GateError("sealed request path is not launcher-derived")
    _check_secure_ancestry(
        run_root,
        trusted_root=Path(paths.trusted_root),
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    for directory, label in ((runs_root, "runs root"), (run_root, "run root")):
        if stat.S_IMODE(directory.lstat().st_mode) != 0o700:
            raise GateError(f"sealed {label} must have mode 0700")
    try:
        metadata = request_path.lstat()
    except OSError as error:
        raise GateError(f"could not inspect sealed request: {error}") from None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise GateError("sealed request must be one real, unlinked regular file")
    _check_owner_and_mode(
        request_path,
        metadata,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if stat.S_IMODE(metadata.st_mode) != 0o600:
        raise GateError("sealed request must have mode 0600")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(request_path, flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            payload = stream.read(_MAX_REQUEST_BYTES + 1)
            trailing = stream.read(1)
            finished = os.fstat(stream.fileno())
        after = request_path.lstat()
    except OSError as error:
        raise GateError(f"could not read sealed request: {error}") from None
    if len(payload) > _MAX_REQUEST_BYTES or trailing:
        raise GateError("sealed request exceeds 4 KiB")
    if (
        _metadata_identity(metadata) != _metadata_identity(opened)
        or _metadata_identity(finished) != _metadata_identity(opened)
        or _metadata_identity(after) != _metadata_identity(opened)
    ):
        raise GateError("sealed request changed while reading")
    try:
        value = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_duplicate_request_field,
        )
    except GateError:
        raise
    except (UnicodeError, json.JSONDecodeError) as error:
        raise GateError(f"sealed request is not valid JSON: {error}") from None
    if not isinstance(value, dict) or set(value) != {"policy_id", "schema", "tag"}:
        raise GateError("sealed request has unexpected or missing fields")
    if _canonical_request_bytes(value) != payload:
        raise GateError("sealed request bytes are not canonical")
    if value["schema"] != _REQUEST_SCHEMA:
        raise GateError("sealed request schema mismatch")
    policy_id = value["policy_id"]
    tag = value["tag"]
    if not isinstance(policy_id, str) or _POLICY_ID_RE.fullmatch(policy_id) is None:
        raise GateError("sealed request policy_id is invalid")
    if not isinstance(tag, str) or _TAG_RE.fullmatch(tag) is None:
        raise GateError("sealed request tag is invalid")
    return {"policy_id": policy_id, "schema": _REQUEST_SCHEMA, "tag": tag}, run_root


def build_sealed_from_request(
    request_path: Path,
    *,
    executing_cli: Path | None = None,
    paths: SealedCliPaths = DEFAULT_SEALED_PATHS,
    expected_uid: int = 0,
    expected_gid: int = 0,
    geteuid: object = os.geteuid,
) -> object:
    """Verify launcher state and derive every production build input."""

    build_module = _import_lmi_p1_module("build")
    seal_module = _import_lmi_p1_module("seal")
    read_active_policy = seal_module.read_active_policy  # type: ignore[attr-defined]
    verify_seal = seal_module.verify_seal  # type: ignore[attr-defined]
    _prepare_sealed_build_context = (  # type: ignore[attr-defined]
        build_module._prepare_sealed_build_context
    )
    if not callable(geteuid) or geteuid() != expected_uid:
        raise GateError("sealed CLI requires the trusted effective UID")
    request, run_root = _read_sealed_request(
        request_path,
        paths=paths,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    active_policy = read_active_policy(
        paths.active,
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if active_policy != request["policy_id"]:
        raise GateError("sealed request policy is not the active policy")

    cli = Path(__file__ if executing_cli is None else executing_cli).absolute()
    if len(cli.parents) < 3:
        raise GateError("sealed CLI path has an invalid layout")
    seal_root = cli.parents[2]
    expected_cli = seal_root / "project/scripts/lmi_p1_cli.py"
    expected_seal = Path(paths.seals).absolute() / request["policy_id"]
    if cli != expected_cli or seal_root != expected_seal:
        raise GateError("sealed CLI is not executing from the active seal path")
    try:
        cli_metadata = cli.lstat()
    except OSError as error:
        raise GateError(f"could not inspect sealed CLI path: {error}") from None
    if not stat.S_ISREG(cli_metadata.st_mode) or cli_metadata.st_nlink != 1:
        raise GateError("sealed CLI path is not one real regular file")

    verified = verify_seal(
        seal_root,
        request["policy_id"],
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    if verified.project / "scripts/lmi_p1_cli.py" != cli:
        raise GateError("verified seal did not return the executing CLI")
    context, authorization = _prepare_sealed_build_context(
        verified,
        tag=request["tag"],
        run_root=run_root,
    )
    result = build_candidate(context, _sealed_authorization=authorization)
    revalidate_sealed_build_result(
        result,
        expected_policy_id=request["policy_id"],
        active_path=paths.active,
        trusted_root=paths.trusted_root,
        expected_uid=expected_uid,
        expected_gid=expected_gid,
    )
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run fail-closed lmi P1 stages")
    commands = parser.add_subparsers(dest="command", required=True)
    stage = commands.add_parser(
        "stage-pmaports", help="stage the pinned pmaports source tree"
    )
    stage.add_argument("--source", type=Path, required=True)
    stage.add_argument("--destination", type=Path, required=True)
    stage.add_argument("--commit", required=True)
    stage.add_argument("--overlay", type=Path, required=True)
    stage.add_argument("--patch", type=Path, required=True)
    build = commands.add_parser(
        "build",
        help="build one unsealed-development lmi P1 SSH candidate",
    )
    build.add_argument("--repo", type=Path, required=True)
    build.add_argument("--tag", required=True)
    build.add_argument("--source-commit", required=True)
    build.add_argument("--work", type=Path, required=True)
    build.add_argument("--pmaports", type=Path, required=True)
    build.add_argument("--pmbootstrap", type=Path, required=True)
    build.add_argument("--public-key", type=Path, required=True)
    build.add_argument("--public-key-fingerprint", required=True)
    sealed = commands.add_parser(
        "build-sealed",
        help="internal root-launcher entry point for a verified production seal",
    )
    sealed.add_argument("--request", type=Path, required=True)
    curate = commands.add_parser(
        "curate-offline-cache",
        help="curate downloaded material into a promotion-only acquisition",
    )
    curate.add_argument("--profile", type=Path, required=True)
    curate.add_argument("--acquisition-root", type=Path, required=True)
    curate.add_argument("--output", type=Path, required=True)
    promote = commands.add_parser(
        "promote-offline-cache",
        help="authenticate and atomically promote one exact offline acquisition",
    )
    promote.add_argument("--acquisition", type=Path, required=True)
    promote.add_argument("--quarantine", type=Path, required=True)
    promote.add_argument("--published", type=Path, required=True)
    promote.add_argument("--trusted-pmbootstrap", type=Path, required=True)
    return parser


def _json_result(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: str(getattr(value, field.name))
            if isinstance(getattr(value, field.name), Path)
            else getattr(value, field.name)
            for field in fields(value)
        }
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "stage-pmaports":
            pmaports_module = _import_lmi_p1_module("pmaports")
            result = pmaports_module.prepare_pmaports(
                source=arguments.source,
                destination=arguments.destination,
                commit=arguments.commit,
                overlay=arguments.overlay,
                patch=arguments.patch,
            )
        elif arguments.command == "build":
            build_module = _import_lmi_p1_module("build")
            result = build_candidate(
                build_module.BuildContext(
                    repo=arguments.repo,
                    tag=arguments.tag,
                    privilege_model=build_module._PRIVILEGE_UNSEALED,
                    policy_id=build_module._UNSEALED_POLICY_ID,
                    source_commit=arguments.source_commit,
                    work=arguments.work,
                    pmaports=arguments.pmaports,
                    pmbootstrap=arguments.pmbootstrap,
                    public_key=arguments.public_key,
                    public_key_fingerprint=arguments.public_key_fingerprint,
                )
            )
        elif arguments.command == "build-sealed":
            result = build_sealed_from_request(arguments.request)
        elif arguments.command == "curate-offline-cache":
            result = curate_offline_cache_acquisition(
                arguments.acquisition_root,
                arguments.output,
                arguments.profile,
            )
        elif arguments.command == "promote-offline-cache":
            authorization = load_promotion_authorization()
            result = promote_offline_cache(
                arguments.acquisition,
                arguments.quarantine,
                arguments.published,
                authorization.profile,
                trusted_key_root=arguments.trusted_pmbootstrap,
                authorization=authorization,
            )
        else:  # pragma: no cover - argparse rejects unknown commands
            parser.error(f"unsupported command: {arguments.command}")
    except GateError as error:
        parser.exit(1, f"lmi-p1 gate failed: {error}\n")
    print(json.dumps(_json_result(result), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
