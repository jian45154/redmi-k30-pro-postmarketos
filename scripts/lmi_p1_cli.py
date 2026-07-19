#!/usr/bin/env python3
"""Command-line entry point for the lmi P1 pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

if __package__:
    from .lmi_p1.common import GateError
    from .lmi_p1.pmaports import prepare_pmaports
else:
    from lmi_p1.common import GateError
    from lmi_p1.pmaports import prepare_pmaports


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
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "stage-pmaports":
            result = prepare_pmaports(
                source=arguments.source,
                destination=arguments.destination,
                commit=arguments.commit,
                overlay=arguments.overlay,
                patch=arguments.patch,
            )
        else:  # pragma: no cover - argparse rejects unknown commands
            parser.error(f"unsupported command: {arguments.command}")
    except GateError as error:
        parser.exit(1, f"lmi-p1 gate failed: {error}\n")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
