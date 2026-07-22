#!/usr/bin/env python3
"""Dump every base-image fact the D114 P2 lock rewrites need, without mounting.

Reads a D114 base/candidate rootfs ext4 through debugfs (no root, no loop
device) and emits one JSON document with the values that get pinned across
source-lock.json, candidate-rebuild-lock.json, the injector's inline
constants, and injection-policy-lock.json:

- world / installed-db / scripts-db / triggers-db hashes,
- sanitation targets' metadata (machine-id, shadow pair, resolv.conf,
  apk.log, authorized_keys, /var/cache/apk APKINDEX inventory, sshd
  configuration),
- runtime component hashes for the source-lock runtime section,
- package versions parsed from the installed database (for the source-lock
  dependency pin list), and the kernel release from /lib/modules.

Validated against the r1 base (p2-d114-build-20260720/lmi-d114-rootfs-base
.ext4): every emitted hash matches the corresponding r1 pin.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

DEBUGFS = "/usr/sbin/debugfs"

HASH_FILES = {
    "world": "/etc/apk/world",
    "installed_db": "/usr/lib/apk/db/installed",
    "scripts_db": "/usr/lib/apk/db/scripts.tar.gz",
    "triggers_db": "/usr/lib/apk/db/triggers",
    "shadow": "/etc/shadow",
    "shadow_backup": "/etc/shadow-",
    "machine_id": "/etc/machine-id",
    "resolv_conf": "/etc/resolv.conf",
    "apk_log": "/var/log/apk.log",
    "authorized_keys": "/home/lmi/.ssh/authorized_keys",
    "sshd_config": "/etc/ssh/sshd_config",
    "sshd_ui_policy": "/etc/ssh/sshd_config.d/50-postmarketos-ui-policy.conf",
    "greetd_confd": "/etc/conf.d/greetd",
}

RUNTIME_COMPONENTS = (
    "/usr/bin/seatd",
    "/usr/bin/weston",
    "/usr/lib/libweston-14.so.0.0.2",
    "/usr/lib/libweston-14/drm-backend.so",
    "/usr/lib/weston/desktop-shell.so",
    "/usr/sbin/greetd",
)

DEPENDENCY_PACKAGES = (
    "device-xiaomi-lmi",
    "linux-xiaomi-lmi",
    "greetd",
    "greetd-openrc",
    "greetd-phrog",
    "libseat",
    "libweston",
    "openrc",
    "seatd",
    "seatd-openrc",
    "weston",
    "weston-backend-drm",
    "weston-shell-desktop",
    "weston-terminal",
    "pd-mapper",
    "pd-mapper-openrc",
    "dbus",
    "elogind",
)


def debugfs(image: Path, request: str) -> str:
    result = subprocess.run(
        [DEBUGFS, "-R", request, str(image)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise SystemExit(f"debugfs {request!r} failed: {result.stderr.strip()}")
    return result.stdout


def dump_file(image: Path, path: str, destination: Path) -> None:
    result = subprocess.run(
        [DEBUGFS, "-R", f'dump -p "{path}" {destination}', str(image)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not destination.exists():
        raise SystemExit(f"debugfs dump of {path} failed: {result.stderr.strip()}")


def file_facts(image: Path, path: str, scratch: Path) -> dict | None:
    stat_output = debugfs(image, f'stat "{path}"')
    if "File not found" in stat_output:
        return None
    mode_match = re.search(r"Mode:\s+(0[0-7]+)", stat_output)
    links_match = re.search(r"Links:\s+(\d+)", stat_output)
    size_match = re.search(r"Size:\s+(\d+)", stat_output)
    user_match = re.search(r"User:\s+(\d+)", stat_output)
    group_match = re.search(r"Group:\s+(\d+)", stat_output)
    if not (mode_match and size_match and links_match):
        raise SystemExit(f"unparseable debugfs stat for {path}")
    target = scratch / "payload"
    if target.exists():
        target.unlink()
    dump_file(image, path, target)
    payload = target.read_bytes()
    if len(payload) != int(size_match.group(1)):
        raise SystemExit(f"dump size mismatch for {path}")
    return {
        "path": path,
        "mode": mode_match.group(1)[-3:],
        "uid": int(user_match.group(1)) if user_match else None,
        "gid": int(group_match.group(1)) if group_match else None,
        "links": int(links_match.group(1)),
        "size": len(payload),
        "sha256": hashlib.sha256(payload).hexdigest(),
    }


def list_directory(image: Path, path: str) -> list[str]:
    output = debugfs(image, f'ls -p "{path}"')
    names = []
    for line in output.splitlines():
        parts = line.split("/")
        if len(parts) > 5 and parts[5] not in (".", "..", ""):
            names.append(parts[5])
    return sorted(names)


def parse_installed_versions(installed_text: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    name = None
    for line in installed_text.splitlines():
        if line.startswith("P:"):
            name = line[2:]
        elif line.startswith("V:") and name is not None:
            versions[name] = line[2:]
        elif not line:
            name = None
    return versions


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=Path, help="base/candidate rootfs ext4")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    if not args.image.is_file():
        raise SystemExit(f"missing image: {args.image}")

    facts: dict = {"schema": "lmi-p2-d114-base-facts/v1", "image": str(args.image)}
    with tempfile.TemporaryDirectory(prefix="lmi-base-facts.") as scratch_name:
        scratch = Path(scratch_name)
        files = {}
        for key, path in HASH_FILES.items():
            files[key] = file_facts(args.image, path, scratch)
        facts["files"] = files

        components = {}
        for path in RUNTIME_COMPONENTS:
            entry = file_facts(args.image, path, scratch)
            if entry is not None:
                components[path] = entry["sha256"]
        facts["runtime_component_sha256"] = components

        cache_members = {}
        for name in list_directory(args.image, "/var/cache/apk"):
            cache_members[name] = file_facts(
                args.image, f"/var/cache/apk/{name}", scratch
            )
        facts["apk_cache"] = cache_members

        facts["sshd_config_d"] = list_directory(args.image, "/etc/ssh/sshd_config.d")
        facts["modules"] = list_directory(args.image, "/lib/modules")

        target = scratch / "payload"
        if target.exists():
            target.unlink()
        dump_file(args.image, "/usr/lib/apk/db/installed", target)
        versions = parse_installed_versions(target.read_text(encoding="utf-8"))
        facts["package_versions"] = {
            name: versions.get(name) for name in DEPENDENCY_PACKAGES
        }
        facts["package_count"] = len(versions)

    payload = json.dumps(facts, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(payload)
        args.output.chmod(0o600)
        print(f"wrote {args.output}")
    else:
        print(payload)


if __name__ == "__main__":
    main()
