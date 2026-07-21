#!/usr/bin/env python3
"""Verify the hash-locked lmi six-row Weston client sources and recipe."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-weston-sixrow"
LOCK_PATH = REPO / "config/lmi-weston-sixrow/source-lock.json"
BUILD_ATTESTATION_PATH = REPO / "config/lmi-weston-sixrow/build-attestation.json"
APKBUILD = FILES / "APKBUILD"
EXPECTED_ROWS = (
    (("Esc", 2), ("Tab", 2), ("Ctrl", 2), ("Shift", 2), ("Backspace", 4)),
    tuple((key, 1) for key in "1 2 3 4 5 6 7 8 9 0 - =".split()),
    tuple((key, 1) for key in "q w e r t y u i o p [ ]".split()),
    tuple((key, 1) for key in ["a", "s", "d", "f", "g", "h", "j", "k", "l", ";", "'", "Enter"]),
    tuple((key, 1) for key in ["z", "x", "c", "v", "b", "n", "m", ",", ".", "/", "\\", "Shift"]),
    (("Space", 8), ("←", 1), ("↑", 1), ("↓", 1), ("→", 1)),
)
EXPECTED_SHIFTED = {
    "1": "!", "2": "@", "3": "#", "4": "$", "5": "%", "6": "^",
    "7": "&", "8": "*", "9": "(", "0": ")", "-": "_", "=": "+",
    "[": "{", "]": "}", ";": ":", "'": '"', ",": "<", ".": ">",
    "/": "?", "\\": "|",
}
class VerificationError(RuntimeError):
    """Raised when the locked recipe or patched source violates its contract."""


def digest(path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def load_lock() -> dict:
    return json.loads(LOCK_PATH.read_text(encoding="utf-8"))


def _decode_c_string(value: str) -> str:
    return ast.literal_eval('"' + value + '"')


def parse_normal_layout(keyboard_source: str) -> tuple[tuple[tuple[str, str, int], ...], ...]:
    match = re.search(
        r"static const struct key normal_keys\[\] = \{\n(?P<body>.*?)\n\};",
        keyboard_source,
        re.DOTALL,
    )
    if not match:
        raise VerificationError("normal_keys array is missing")

    rows = []
    entry_pattern = re.compile(
        r'\{\s*keytype_\w+,\s*"((?:\\.|[^"\\])*)",\s*'
        r'"((?:\\.|[^"\\])*)",\s*"(?:\\.|[^"\\])*",\s*(\d+)\s*\}'
    )
    for chunk in re.split(r"\n\s*\n", match.group("body")):
        entries = tuple(
            (_decode_c_string(label), _decode_c_string(shifted), int(width))
            for label, shifted, width in entry_pattern.findall(chunk)
        )
        if entries:
            rows.append(entries)
    return tuple(rows)


def verify_layout(keyboard_source: str) -> None:
    rows = parse_normal_layout(keyboard_source)
    visible = tuple(tuple((label, width) for label, _shifted, width in row) for row in rows)
    if visible != EXPECTED_ROWS:
        raise VerificationError(f"six-row layout mismatch: {visible!r}")
    if any(sum(width for _label, width in row) != 12 for row in visible):
        raise VerificationError("each keyboard row must total exactly 12 columns")

    shifted = {label: upper for row in rows for label, upper, _width in row}
    for key in "qwertyuiopasdfghjklzxcvbnm":
        if shifted.get(key) != key.upper():
            raise VerificationError(f"missing uppercase mapping for {key}")
    for key, expected in EXPECTED_SHIFTED.items():
        if shifted.get(key) != expected:
            raise VerificationError(f"shifted mapping for {key!r} is not {expected!r}")

    required_dimensions = (
        "static const double key_width = 60;",
        "static const double key_height = 60;",
        "static const double keyboard_scale_x = 0.75;",
        "static const double keyboard_scale_y = 1.0;",
        "\t12,\n\t6,\n\t\"en\"",
    )
    for declaration in required_dimensions:
        if declaration not in keyboard_source:
            raise VerificationError(f"missing dimension contract: {declaration!r}")
    if abs(12 * 60 * 0.75 - 540) > 0.001:
        raise VerificationError("logical keyboard width is not 540")


def verify_keyboard_behavior(keyboard_source: str) -> None:
    for keysym in ("Escape", "Tab", "BackSpace", "Return", "Left", "Up", "Down", "Right"):
        if f"XKB_KEY_{keysym}" not in keyboard_source:
            raise VerificationError(f"real keysym missing for {keysym}")
    required = (
        "bool control_latched;",
        "keyboard->control_latched = !keyboard->control_latched;",
        "keyboard->control_latched = false;",
        "bool consume_control = keyboard->control_latched &&",
        "key->key_type != keytype_control &&",
        "key->key_type != keytype_switch &&",
        "key->key_type != keytype_symbols &&",
        "key->key_type != keytype_style;",
        "mod_mask |= keyboard->keyboard->keysym.control_mask;",
        "WL_KEYBOARD_KEY_STATE_PRESSED, mod_mask",
        "WL_KEYBOARD_KEY_STATE_RELEASED, mod_mask",
        "time, XKB_KEY_space,",
        "state == WL_POINTER_BUTTON_STATE_RELEASED &&",
        "key->key_type == keytype_control && keyboard->control_latched",
    )
    for token in required:
        if token not in keyboard_source:
            raise VerificationError(f"Ctrl latch behavior missing: {token}")


def verify_terminal_control(terminal_source: str) -> None:
    if "terminal_text_input_modifiers_map" not in terminal_source:
        raise VerificationError("terminal modifiers-map callback is missing")
    for name, field, flag in (
        ("Shift", "text_input_shift_mask", "MOD_SHIFT_MASK"),
        ("Mod1", "text_input_alt_mask", "MOD_ALT_MASK"),
        ("Control", "text_input_control_mask", "MOD_CONTROL_MASK"),
    ):
        if f'keysym_modifiers_get_mask(map, "{name}")' not in terminal_source:
            raise VerificationError(f"{name} modifier is not mapped by name")
        if f"modifiers & terminal->{field}" not in terminal_source:
            raise VerificationError(f"incoming {name} modifier is ignored")
        if f"terminal_modifiers |= {flag};" not in terminal_source:
            raise VerificationError(f"incoming {name} modifier is not normalized")

    if terminal_source.count("terminal_encode_key(") != 3:
        raise VerificationError("physical and text-input paths do not share one key encoder")
    required_encoder = (
        "len = apply_key_map(terminal->key_mode, sym, modifiers, response);",
        "if (sym >= '3' && sym <= '7')",
        "sym = (sym & 0x1f) + 8;",
        "sym &= 0x1f;",
        "else if (sym == '2')",
        "sym = 0x00;",
        "else if (sym == '/')",
        "sym = 0x1f;",
        "else if (sym == '8' || sym == '?')",
        "sym = 0x7f;",
        "case XKB_KEY_BackSpace:",
        "response[len++] = 0x7f;",
        "case XKB_KEY_Return:",
        "case XKB_KEY_Escape:",
    )
    for token in required_encoder:
        if token not in terminal_source:
            raise VerificationError(f"shared terminal key encoder is missing {token!r}")
    if ("static struct key_map KM_NORMAL[]" in terminal_source and
            "static struct key_map KM_APPLICATION[]" not in terminal_source):
        raise VerificationError("application-cursor key map is missing")
    if "state != WL_KEYBOARD_KEY_STATE_RELEASED" not in terminal_source:
        raise VerificationError("text-input keysym event is not consumed exactly once")

    if "static struct key_map KM_NORMAL[]" in terminal_source:
        handler_match = re.search(
            r"terminal_text_input_keysym\(.*?\n\}\n\nstatic void\n"
            r"terminal_text_input_enter",
            terminal_source,
            re.DOTALL,
        )
        if not handler_match:
            raise VerificationError("terminal text-input keysym handler is missing")
        for fixed_sequence in ('"\\033[A"', '"\\033[B"', '"\\033[C"', '"\\033[D"'):
            if fixed_sequence in handler_match.group(0):
                raise VerificationError("text-input arrow path bypasses terminal key mode")
    for token in ("terminal_text_input_commit_string", "terminal_text_input_preedit_string"):
        if token not in terminal_source:
            raise VerificationError(f"ordinary text-input path was lost: {token}")


def verify_recipe() -> None:
    lock = load_lock()
    if lock["architecture"] != "aarch64":
        raise VerificationError("recipe lock is not aarch64-only")
    for item in lock["patches"]:
        path = REPO / item["path"]
        if digest(path) != item["sha256"]:
            raise VerificationError(f"patch hash mismatch: {path}")

    apkbuild = APKBUILD.read_text(encoding="utf-8")
    if 'arch="aarch64"' not in apkbuild:
        raise VerificationError("APKBUILD is not aarch64-only")
    if "/mnt/c" in apkbuild:
        raise VerificationError("APKBUILD depends on a Windows mount")
    if "meson compile -C build weston-keyboard weston-terminal" not in apkbuild:
        raise VerificationError("APKBUILD does not limit compilation to the two clients")
    if "\tpango-dev\n" not in apkbuild:
        raise VerificationError("Pango development support is required by the terminal toolkit path")
    if "meson install" in apkbuild.replace("does not run meson install", ""):
        raise VerificationError("APKBUILD must not install the full Weston project")

    package_match = re.search(r"package\(\) \{(?P<body>.*?)\n\}", apkbuild, re.DOTALL)
    if not package_match:
        raise VerificationError("APKBUILD package() is missing")
    install_paths = set(re.findall(r'\$pkgdir([^"\n]+)', package_match.group("body")))
    expected = set(lock["install_paths"])
    if install_paths != expected:
        raise VerificationError(f"package install paths are not the exact whitelist: {install_paths}")
    for forbidden in lock["forbidden_install_paths"]:
        if forbidden in install_paths:
            raise VerificationError(f"forbidden stock path would be overwritten: {forbidden}")

    tar_sha512 = lock["weston"]["sha512"]
    if f"{tar_sha512}  weston-14.0.2.tar.xz" not in apkbuild:
        raise VerificationError("official tar SHA-512 is not locked in APKBUILD")
    for item in lock["patches"]:
        patch_path = REPO / item["path"]
        line = f"{digest(patch_path, 'sha512')}  {patch_path.name}"
        if line not in apkbuild:
            raise VerificationError(f"APKBUILD SHA-512 missing for {patch_path.name}")


def verify_build_attestation(*, require_artifact: bool = False) -> bool:
    attestation = json.loads(BUILD_ATTESTATION_PATH.read_text(encoding="utf-8"))
    source = attestation["source"]
    artifact = attestation["artifact"]
    if source["source_lock_sha256"] != digest(LOCK_PATH):
        raise VerificationError("build attestation source-lock hash is stale")
    if source["apkbuild_sha256"] != digest(APKBUILD):
        raise VerificationError("build attestation APKBUILD hash is stale")
    for item in source["verification_sources"]:
        path = REPO / item["path"]
        if digest(path) != item["sha256"]:
            raise VerificationError(f"build attestation verification hash is stale: {path}")

    artifact_path = REPO / artifact["path"]
    if not artifact_path.exists():
        if require_artifact:
            raise VerificationError(f"attested APK is missing: {artifact_path}")
        return False
    if digest(artifact_path) != artifact["sha256"]:
        raise VerificationError("built APK hash does not match its attestation")
    if artifact_path.stat().st_size != artifact["compressed_size"]:
        raise VerificationError("built APK size does not match its attestation")

    expected_payload = {
        path.lstrip("/"): expected_hash
        for path, expected_hash in artifact["payload"].items()
    }
    with tarfile.open(artifact_path, mode="r:gz") as archive:
        regular_payload = {}
        pkginfo = None
        for member in archive.getmembers():
            if member.name == ".PKGINFO":
                stream = archive.extractfile(member)
                if stream is None:
                    raise VerificationError("APK .PKGINFO is unreadable")
                pkginfo = stream.read().decode("utf-8")
            elif member.isfile() and not member.name.startswith(".SIGN."):
                stream = archive.extractfile(member)
                if stream is None:
                    raise VerificationError(f"APK member is unreadable: {member.name}")
                regular_payload[member.name] = hashlib.sha256(stream.read()).hexdigest()
            elif not (member.isdir() or member.isfile()):
                raise VerificationError(f"unexpected non-regular APK member: {member.name}")

    if regular_payload != expected_payload:
        raise VerificationError(f"APK payload is not the exact whitelist: {regular_payload}")
    if pkginfo is None:
        raise VerificationError("APK .PKGINFO is missing")
    if f"pkgver = {artifact['package_version']}" not in pkginfo:
        raise VerificationError("APK package version does not match its attestation")
    if "arch = aarch64" not in pkginfo:
        raise VerificationError("APK package architecture is not aarch64")

    supersedes = attestation["supersedes"]
    if supersedes["status"] != "NO_GO_CTRL_LATCH_AND_CURSOR_MODE_DEFECTS":
        raise VerificationError("superseded r0 artifact is not explicitly NO-GO")
    old_artifact = REPO / supersedes["artifact"]
    if old_artifact == artifact_path:
        raise VerificationError("current and superseded APK paths must be distinct")
    if old_artifact.exists() and digest(old_artifact) != supersedes["sha256"]:
        raise VerificationError("superseded r0 APK hash does not match its record")
    return True


def _retained_patch_text(path: Path) -> str:
    """Return context and additions, omitting removed lines and diff headers."""
    retained = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith(" "):
            retained.append(line[1:])
        elif line.startswith("+") and not line.startswith("+++"):
            retained.append(line[1:])
    return "\n".join(retained)


def verify_patch_contract() -> None:
    combined = "\n".join(
        _retained_patch_text(FILES / name)
        for name in (
            "0001-phone-input-terminal-text-input.patch",
            "0002-sixrow-control.patch",
        )
    )
    verify_layout(combined)
    verify_terminal_control(combined)
    for token in (
        "bool control_latched;",
        "keyboard->control_latched = !keyboard->control_latched;",
        "keyboard->control_latched = false;",
        "bool consume_control = keyboard->control_latched &&",
        "key->key_type != keytype_switch &&",
        "mod_mask |= keyboard->keyboard->keysym.control_mask;",
        "key->key_type == keytype_control && keyboard->control_latched",
        "XKB_KEY_Escape",
        "XKB_KEY_BackSpace",
        "XKB_KEY_space",
        "state == WL_POINTER_BUTTON_STATE_RELEASED &&",
    ):
        if token not in combined:
            raise VerificationError(f"six-row patch contract is missing {token}")


def verify_meson_targets(meson_source: str) -> None:
    keyboard_target = re.search(
        r"exe_keyboard\s*=\s*executable\(\s*'weston-keyboard'",
        meson_source,
        re.DOTALL,
    )
    terminal_tool = re.search(
        r"'name':\s*'terminal'.*?'sources':\s*\[.*?'terminal\.c'",
        meson_source,
        re.DOTALL,
    )
    generated_tool_target = "executable(\n\t\t\t'weston-@0@'.format(t.get('name'))"
    if not keyboard_target:
        raise VerificationError("Meson target weston-keyboard is missing")
    if not terminal_tool or generated_tool_target not in meson_source:
        raise VerificationError("Meson target weston-terminal cannot be derived from tools_list")


def _safe_extract(archive: tarfile.TarFile, destination: Path) -> None:
    destination = destination.resolve()
    for member in archive.getmembers():
        target = (destination / member.name).resolve()
        if target != destination and destination not in target.parents:
            raise VerificationError(f"unsafe tar member: {member.name}")
    archive.extractall(destination, filter="data")


def verify_tarball(tarball: Path) -> None:
    lock = load_lock()
    if digest(tarball) != lock["weston"]["sha256"]:
        raise VerificationError("Weston tarball SHA-256 does not match source lock")
    if digest(tarball, "sha512") != lock["weston"]["sha512"]:
        raise VerificationError("Weston tarball SHA-512 does not match source lock")
    if shutil.which("patch") is None:
        raise VerificationError("patch executable is required for dry-run verification")

    with tempfile.TemporaryDirectory(prefix="lmi-weston-sixrow-") as temp:
        root = Path(temp)
        with tarfile.open(tarball, mode="r:xz") as archive:
            _safe_extract(archive, root)
        children = [path for path in root.iterdir() if path.is_dir()]
        if len(children) != 1:
            raise VerificationError("Weston tarball must contain one source root")
        source = children[0]

        for item in lock["patches"]:
            patch_path = REPO / item["path"]
            common = ["patch", "--batch", "--fuzz=0", "-d", str(source), "-p1", "-i", str(patch_path)]
            subprocess.run([*common, "--dry-run"], check=True, capture_output=True, text=True)
            subprocess.run(common, check=True, capture_output=True, text=True)

        keyboard_source = (source / "clients/keyboard.c").read_text(encoding="utf-8")
        terminal_source = (source / "clients/terminal.c").read_text(encoding="utf-8")
        meson_source = (source / "clients/meson.build").read_text(encoding="utf-8")
        verify_layout(keyboard_source)
        verify_keyboard_behavior(keyboard_source)
        verify_terminal_control(terminal_source)
        verify_meson_targets(meson_source)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tarball", required=True, type=Path)
    args = parser.parse_args()
    verify_recipe()
    verify_build_attestation()
    verify_patch_contract()
    verify_tarball(args.tarball)
    print("lmi Weston six-row source, patches, layout, Ctrl mapping, and install paths: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
