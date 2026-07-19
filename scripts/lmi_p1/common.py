"""Common fail-closed primitives for the lmi P1 pipeline."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Mapping, Sequence


_HASH_BLOCK_SIZE = 1024 * 1024
_DEVICE_SERIAL = "8336ded7"
_GITHUB_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:github_pat_[A-Za-z0-9_]{20,255}|gh[pousr]_[A-Za-z0-9]{20,255})(?![A-Za-z0-9_])"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?"
    r"-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----",
    re.DOTALL,
)


class GateError(RuntimeError):
    """A safety or verification gate failed closed."""


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of *path*, streamed in 1 MiB blocks."""

    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(_HASH_BLOCK_SIZE), b""):
            digest.update(block)
    return digest.hexdigest()


def _as_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _redact(value: str | bytes | None) -> str:
    redacted = _as_text(value)
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY]", redacted)
    redacted = _GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", redacted)
    return redacted.replace(_DEVICE_SERIAL, "[REDACTED_DEVICE_SERIAL]")


def _command_for_error(argv: Sequence[str]) -> str:
    return _redact(repr(list(argv)))


def run(
    argv: Sequence[str],
    timeout: int,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run an argv-only subprocess and convert failures into redacted GateError."""

    command = list(argv)
    try:
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            cwd=cwd,
            env=env,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise GateError(
            f"command timed out after {timeout} seconds: {_command_for_error(command)}\n"
            f"stdout:\n{_redact(error.stdout)}\n"
            f"stderr:\n{_redact(error.stderr)}"
        ) from None
    except OSError as error:
        raise GateError(
            f"command could not start: {_command_for_error(command)}: "
            f"{_redact(str(error))}"
        ) from None

    if check and completed.returncode != 0:
        raise GateError(
            f"command failed with exit status {completed.returncode}: "
            f"{_command_for_error(command)}\n"
            f"stdout:\n{_redact(completed.stdout)}\n"
            f"stderr:\n{_redact(completed.stderr)}"
        )
    return completed


def write_json(path: Path, value: object) -> None:
    """Atomically write stable, sorted JSON after syncing a sibling temporary file."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_name = stream.name
            json.dump(value, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    except Exception:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
        raise
