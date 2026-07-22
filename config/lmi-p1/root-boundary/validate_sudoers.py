#!/usr/bin/python3
"""Offline exact-byte validator for the lmi P1 builder sudoers policy."""

from __future__ import annotations

from pathlib import Path
import stat
import sys


POLICY_NAME = "90-lmi-p1-root-launcher"
EXPECTED_POLICY = (
    b"# lmi P1 sealed builder: the only delegated root command.\n"
    b"Cmnd_Alias LMI_P1_ROOT_LAUNCHER = /usr/bin/python3 -I -S -B "
    b"/usr/local/sbin/lmi-p1-root-launcher\n"
    b"Defaults!LMI_P1_ROOT_LAUNCHER !use_pty\n"
    b"%lmi-p1-builders ALL=(root:root) NOPASSWD: NOSETENV: "
    b"LMI_P1_ROOT_LAUNCHER\n"
)


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv
    if len(argv) > 2:
        sys.stderr.write(f"usage: {argv[0]} [SUDOERS_POLICY]\n")
        return 2
    path = Path(argv[1]) if len(argv) == 2 else Path(__file__).with_name(POLICY_NAME)
    try:
        metadata = path.lstat()
        payload = path.read_bytes()
    except OSError as error:
        sys.stderr.write(f"could not read sudoers policy {path}: {error}\n")
        return 1
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        sys.stderr.write("sudoers policy must be one real, single-link regular file\n")
        return 1
    if payload != EXPECTED_POLICY:
        sys.stderr.write(
            "sudoers policy is not the reviewed launcher-only exact policy\n"
        )
        return 1
    sys.stdout.write(f"validated launcher-only sudoers policy: {path}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
