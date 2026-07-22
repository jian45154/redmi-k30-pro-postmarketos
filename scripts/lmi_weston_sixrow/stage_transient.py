#!/usr/bin/env python3
"""Build a hash-pinned, local-only D114 six-row trial stage.

The generated stage is intended for a later, separately approved `/tmp` test.
This tool never opens SSH, invokes fastboot, installs an APK, or changes a
phone or image.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))

from scripts.lmi_weston_sixrow import verify


FILES = REPO / "files/lmi-weston-sixrow"
FROZEN_STOCK_SESSION = FILES / "frozen-d114-r1-stock-session"
FROZEN_STOCK_CONFIG = FILES / "frozen-d114-r1-stock-weston.ini"
TRANSIENT_LOCK_PATH = REPO / "config/lmi-weston-sixrow/transient-stage-lock.json"
FROZEN_STOCK_SESSION_SHA256 = "57c77281f23b57ab297fe77d434f89762200cf554405be84ec375b44ae4fc77a"
FROZEN_STOCK_CONFIG_SHA256 = "19a872670debc8c81bcb64b16f5e49b8958709d8150fcf3634c63cab25ac67f4"
ACTIVE_STOCK_SESSION_SHA256 = "57c77281f23b57ab297fe77d434f89762200cf554405be84ec375b44ae4fc77a"
STOCK_WESTON_SHA256 = "191703aa8da1d965fe7a2e7b4ec7ad7316c484cdc26ac77f31c015d6ee4bd45e"
STOCK_TERMINAL_SHA256 = "1bdeb6070eab5bb05eb2bece2803812e9824fb1a9c76a820352abb880bd1e118"
STOCK_KEYBOARD_SHA256 = "4649049a9793172cc592bc8c1a07eef6eb387fb42f5ee4039aab09a4808d99d3"
BUSYBOX_SHA256 = "a8d8e2b9898537c8b9fb4fcb3d9c95c2e09fecc76c9adfb19ac75965e1a4f19b"
SETSID_SHA256 = "53c7e6e86b00235ccd9c2c1c15667d5c5a02500ddc6a587d3702dcb482763903"
REMOTE_ROOT = "/tmp/lmi-weston-sixrow-r1-ff8dbb022089"
ACTIVE_STOCK_SESSION = "/tmp/lmi-p2-d114-r1-57c77281/session"
EXPECTED_APK_SHA256 = "ff8dbb02208959db4af9f1da735cb7b4f8765138388b6f7daebabce161fe208b"
TRANSIENT_LOCK_STATUS = "NO_GO_EXECUTION_DISABLED_PID_SIGNAL_RACE"
TRANSIENT_NO_GO_REASON_CODE = "LEGACY_STOCK_PID_SIGNAL_RACE"
PAYLOAD = {
    "usr/libexec/lmi-p2-d114/weston-keyboard-sixrow": (
        "weston-keyboard-sixrow",
        "88d06d99f7c2d3eb1da64e7f89a0f5e37b87bc4c93f8b6778b1ca6491bf1dba6",
    ),
    "usr/libexec/lmi-p2-d114/weston-terminal-sixrow": (
        "weston-terminal-sixrow",
        "6602f7ac8e0c11892eec1d9db0411397e95f704a1655b94e0885a1220962a8cf",
    ),
}
SESSION_DIRECTORIES = (
    "home",
    "state",
    "cache",
    "config",
    "tmp",
    "stock-home",
    "stock-state",
    "stock-cache",
    "stock-config",
    "stock-tmp",
)


class StageError(RuntimeError):
    """Raised when an input or generated trial stage violates its contract."""


def digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            hasher.update(block)
    return hasher.hexdigest()


def replace_exact(text: str, old: str, new: str, *, count: int = 1) -> str:
    actual = text.count(old)
    if actual != count:
        raise StageError(f"expected {count} occurrences, found {actual}: {old!r}")
    return text.replace(old, new)


def replace_shell_function(text: str, name: str, replacement: str) -> str:
    pattern = rf"(?ms)^{re.escape(name)}\(\) \{{\n.*?^\}}\n"
    rendered, count = re.subn(pattern, replacement.rstrip("\n") + "\n", text)
    if count != 1:
        raise StageError(f"expected one shell function named {name}, found {count}")
    return rendered


def verify_transient_source_lock() -> dict:
    lock = json.loads(TRANSIENT_LOCK_PATH.read_text(encoding="utf-8"))
    if lock.get("schema") != "lmi-weston-sixrow-transient-source-lock/v1":
        raise StageError("transient source lock schema changed")
    if lock.get("status") != TRANSIENT_LOCK_STATUS:
        raise StageError("transient source lock status is not fail-closed")
    if lock.get("execution_enabled") is not False:
        raise StageError("transient source lock does not disable execution")
    decision = lock.get("review_decision", {})
    if decision.get("outcome") != "NO-GO":
        raise StageError("transient source lock review outcome is not NO-GO")
    if decision.get("reason_code") != TRANSIENT_NO_GO_REASON_CODE:
        raise StageError("transient source lock NO-GO reason changed")
    if lock.get("remote_root") != REMOTE_ROOT:
        raise StageError("transient source lock remote root changed")
    for item in lock.get("sources", []):
        path = REPO / item["path"]
        if path.is_symlink() or not path.is_file():
            raise StageError(f"locked transient source is unavailable: {path}")
        if digest(path) != item["sha256"]:
            raise StageError(f"locked transient source hash changed: {path}")
    runtime = lock.get("runtime_pins", {})
    expected_runtime = {
        "active_stock_session": {
            "path": ACTIVE_STOCK_SESSION,
            "sha256": ACTIVE_STOCK_SESSION_SHA256,
            "required_ppid": 1,
        },
        "busybox_sha256": BUSYBOX_SHA256,
        "setsid_sha256": SETSID_SHA256,
        "candidate_apk_sha256": EXPECTED_APK_SHA256,
    }
    if runtime != expected_runtime:
        raise StageError("transient runtime pins changed")
    return lock


def _component_line(path: str, sha256: str) -> str:
    return f"check_sha256 {path} \\\n\t{sha256}"


def render_session(role: str = "candidate") -> str:
    if role not in {"candidate", "fallback"}:
        raise StageError(f"unsupported session role: {role}")
    if digest(FROZEN_STOCK_SESSION) != FROZEN_STOCK_SESSION_SHA256:
        raise StageError("frozen D114 stock session source changed")

    candidate = role == "candidate"
    directory_prefix = "" if candidate else "stock-"
    wayland_display = "wayland-lmi-sixrow-r1" if candidate else "wayland-lmi-p2-d114"
    session_lock_name = (
        "lmi-weston-sixrow-r1-session.lock"
        if candidate
        else "lmi-p2-d114-session.lock"
    )
    ready_name = "candidate-ready" if candidate else "stock-ready"
    keyboard_path = (
        f"{REMOTE_ROOT}/weston-keyboard-sixrow"
        if candidate
        else "/usr/libexec/weston-keyboard"
    )
    keyboard_sha256 = (
        PAYLOAD["usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"][1]
        if candidate
        else STOCK_KEYBOARD_SHA256
    )
    terminal_path = (
        f"{REMOTE_ROOT}/weston-terminal-sixrow"
        if candidate
        else "/usr/bin/weston-terminal"
    )
    terminal_sha256 = (
        PAYLOAD["usr/libexec/lmi-p2-d114/weston-terminal-sixrow"][1]
        if candidate
        else STOCK_TERMINAL_SHA256
    )
    config_path = (
        f"{REMOTE_ROOT}/weston.ini" if candidate else "/etc/lmi-p2-d114/weston.ini"
    )
    config_sha256 = (
        "@CONFIG_SHA256@" if candidate else FROZEN_STOCK_CONFIG_SHA256
    )

    text = FROZEN_STOCK_SESSION.read_text(encoding="utf-8")
    text = replace_exact(
        text,
        "weston_pid=\nterminal_pid=\nkeyboard_pid=",
        "session_starttime=\n"
        "weston_pid=\nweston_starttime=\n"
        "terminal_pid=\nterminal_starttime=\n"
        "keyboard_pid=\nkeyboard_starttime=\n"
        "ready_path=\nready_owned=0",
    )
    if candidate:
        text = replace_exact(
            text,
            '[ "$keyboard_exe" = /usr/libexec/weston-keyboard ]',
            f'[ "$keyboard_exe" = {keyboard_path} ]',
        )
    text = replace_exact(
        text,
        "session_lock=$XDG_RUNTIME_DIR/lmi-p2-d114-session.lock",
        f"session_lock=$XDG_RUNTIME_DIR/{session_lock_name}",
    )

    old_environment = """export PATH=/usr/bin:/bin
export HOME=/home/lmi
export USER=lmi
export LOGNAME=lmi
export XDG_SESSION_TYPE=wayland
export XDG_RUNTIME_DIR=/run/user/10000
export WAYLAND_DISPLAY=wayland-lmi-p2-d114
export LIBSEAT_BACKEND=seatd
umask 077"""
    new_environment = f"""stage={REMOTE_ROOT}
ready_path=$stage/{ready_name}
export PATH=/usr/bin:/bin
export HOME=$stage/{directory_prefix}home
export USER=lmi
export LOGNAME=lmi
export SHELL=/bin/ash
export XDG_SESSION_TYPE=wayland
export XDG_RUNTIME_DIR=/run/user/10000
export XDG_STATE_HOME=$stage/{directory_prefix}state
export XDG_CACHE_HOME=$stage/{directory_prefix}cache
export XDG_CONFIG_HOME=$stage/{directory_prefix}config
export TMPDIR=$stage/{directory_prefix}tmp
export HISTFILE=/dev/null
export WAYLAND_DISPLAY={wayland_display}
export LIBSEAT_BACKEND=seatd
unset LD_PRELOAD LD_LIBRARY_PATH ENV BASH_ENV CDPATH GCONV_PATH LOCPATH
umask 077
ulimit -c 0
""" + 'cd "$HOME"'
    text = replace_exact(text, old_environment, new_environment)

    account_check = (
        '[ "$(getent passwd lmi)" = '
        '"lmi:x:10000:10000::/home/lmi:/bin/ash" ] ||\n'
        '\tfail "the frozen lmi passwd record changed"'
    )
    temporary_tree_check = account_check + (
        '\n\nfor temporary_dir in "$stage" "$HOME" "$XDG_STATE_HOME" \\\n'
        '\t\t"$XDG_CACHE_HOME" "$XDG_CONFIG_HOME" "$TMPDIR"; do\n'
        '\t[ -d "$temporary_dir" ] && [ ! -L "$temporary_dir" ] ||\n'
        '\t\tfail "temporary directory is unavailable: $temporary_dir"\n'
        '\t[ "$(stat -c %u "$temporary_dir")" = 10000 ] &&\n'
        '\t\t[ "$(stat -c %g "$temporary_dir")" = 10000 ] &&\n'
        '\t\t[ "$(stat -c %a "$temporary_dir")" = 700 ] ||\n'
        '\t\tfail "temporary directory metadata changed: $temporary_dir"\n'
        "done"
    )
    text = replace_exact(text, account_check, temporary_tree_check)
    text = replace_exact(
        text,
        'done\n\n[ -d "$XDG_RUNTIME_DIR" ]',
        'done\n\nsession_starttime=$(process_starttime $$) || '
        'fail "session start time is unavailable"\n\n'
        '[ -d "$XDG_RUNTIME_DIR" ]',
    )

    process_helpers = """process_starttime() {
\tstart_pid=$1
\t[ -r "/proc/$start_pid/stat" ] || return 1
\tstart_line=$(cat "/proc/$start_pid/stat") || return 1
\tstart_rest=${start_line##*) }
\t[ "$start_rest" != "$start_line" ] || return 1
\tset -- $start_rest
\t[ "$#" -ge 20 ] || return 1
\tshift 19
\tstart_value=$1
\tcase "$start_value" in
\t\t''|*[!0-9]*) return 1 ;;
\tesac
\tprintf '%s\\n' "$start_value"
}

core_child_valid() {
\tcore_pid=$1
\tcore_exe_expected=$2
\tcore_starttime_expected=$3
\tchild_alive "$core_pid" || return 1
\tcore_status_path=/proc/$core_pid/status
\t[ -r "$core_status_path" ] || return 1
\tcore_uid=$(awk '$1 == "Uid:" { print $2; exit }' "$core_status_path" 2>/dev/null) ||
\t\treturn 1
\tcore_parent=$(awk '$1 == "PPid:" { print $2; exit }' "$core_status_path" 2>/dev/null) ||
\t\treturn 1
\t[ "$core_uid" = 10000 ] || return 1
\t[ "$core_parent" = "$$" ] || return 1
\tcore_exe=$(readlink "/proc/$core_pid/exe" 2>/dev/null) || return 1
\t[ "$core_exe" = "$core_exe_expected" ] || return 1
\tcore_starttime=$(process_starttime "$core_pid") || return 1
\tif [ "$core_starttime_expected" != - ]; then
\t\t[ "$core_starttime" = "$core_starttime_expected" ] || return 1
\tfi
}

process_sha256_valid() {
\tprocess_pid=$1
\tprocess_expected_sha256=$2
\tchild_alive "$process_pid" || return 1
\tprocess_sha_line=$(sha256sum "/proc/$process_pid/exe" 2>/dev/null) || return 1
\tprocess_sha_value=${process_sha_line%% *}
\t[ "$process_sha_value" = "$process_expected_sha256" ]
}

process_identity_full() {
\tprocess_pid=$1
\tprocess_exe=$2
\tprocess_expected_sha256=$3
\tprocess_expected_starttime=$4
\tcore_child_valid "$process_pid" "$process_exe" "$process_expected_starttime" ||
\t\treturn 1
\tprocess_sha256_valid "$process_pid" "$process_expected_sha256"
}

wait_for_core_child() {
\tcore_wait_pid=$1
\tcore_wait_exe=$2
\tcore_wait_sha256=$3
\tcore_wait_name=$4
\tcore_wait_attempt=0
\twhile [ "$core_wait_attempt" -lt 50 ]; do
\t\tchild_alive "$core_wait_pid" ||
\t\t\tfail "$core_wait_name exited before identity verification"
\t\tif core_child_valid "$core_wait_pid" "$core_wait_exe" - &&
\t\t   process_sha256_valid "$core_wait_pid" "$core_wait_sha256"; then
\t\t\treturn 0
\t\tfi
\t\tsleep 0.1
\t\tcore_wait_attempt=$((core_wait_attempt + 1))
\tdone
\tfail "$core_wait_name process identity did not stabilize"
}

publish_ready() {
\tready_tmp=$stage/.ready.$$.tmp
\t[ ! -e "$ready_tmp" ] && [ ! -L "$ready_tmp" ] || return 1
\t(
\t\tset -C
\t\tumask 077
\t\tprintf 'session_pid=%s\\nsession_starttime=%s\\nweston_pid=%s\\nweston_starttime=%s\\nterminal_pid=%s\\nterminal_starttime=%s\\nkeyboard_pid=%s\\nkeyboard_starttime=%s\\n' \\
\t\t\t"$$" "$session_starttime" "$weston_pid" "$weston_starttime" \\
\t\t\t"$terminal_pid" "$terminal_starttime" "$keyboard_pid" \\
\t\t\t"$keyboard_starttime" > "$ready_tmp"
\t) || return 1
\t[ -f "$ready_tmp" ] && [ ! -L "$ready_tmp" ] || return 1
\t[ "$(stat -c %u "$ready_tmp")" = 10000 ] || return 1
\t[ "$(stat -c %g "$ready_tmp")" = 10000 ] || return 1
\t[ "$(stat -c %a "$ready_tmp")" = 600 ] || return 1
\tmv "$ready_tmp" "$ready_path" || return 1
\tready_owned=1
}

release_ready() {
\t[ "$ready_owned" -eq 1 ] || return 0
\t[ -f "$ready_path" ] && [ ! -L "$ready_path" ] || return 1
\t[ "$(stat -c %u "$ready_path")" = 10000 ] || return 1
\t[ "$(stat -c %g "$ready_path")" = 10000 ] || return 1
\t[ "$(stat -c %a "$ready_path")" = 600 ] || return 1
\t[ "$(awk -F= '$1 == "session_pid" { print $2; exit }' "$ready_path")" = "$$" ] ||
\t\treturn 1
\trm -f "$ready_path" || return 1
\tready_owned=0
}
"""
    text = replace_exact(
        text,
        "\nkeyboard_child_valid() {",
        "\n" + process_helpers + "\nkeyboard_child_valid() {",
    )

    check_core_children = f"""check_core_children() {{
\tcheck_context=$1
\tif ! child_alive "$weston_pid"; then
\t\tweston_status=0
\t\twait "$weston_pid" || weston_status=$?
\t\tweston_pid=
\t\tfail "Weston exited $check_context (status $weston_status)"
\tfi
\tcore_child_valid "$weston_pid" /usr/bin/weston "$weston_starttime" ||
\t\tfail "Weston process identity changed $check_context"
\tif [ -n "$terminal_pid" ]; then
\t\tif ! child_alive "$terminal_pid"; then
\t\t\tterminal_status=0
\t\t\twait "$terminal_pid" || terminal_status=$?
\t\t\tterminal_pid=
\t\t\tfail "weston-terminal exited $check_context (status $terminal_status)"
\t\tfi
\t\tcore_child_valid "$terminal_pid" {terminal_path} "$terminal_starttime" ||
\t\t\tfail "weston-terminal process identity changed $check_context"
\tfi
}}
"""
    text = replace_shell_function(text, "check_core_children", check_core_children)

    stop_child = """stop_child() {
\tstop_pid=$1
\tstop_exe=$2
\tstop_sha256=$3
\tstop_starttime=$4
\tcase "$stop_pid" in
\t\t''|*[!0-9]*) return 0 ;;
\tesac
\tif child_alive "$stop_pid"; then
\t\tprocess_identity_full \\
\t\t\t"$stop_pid" "$stop_exe" "$stop_sha256" "$stop_starttime" ||
\t\t\treturn 1
\t\tkill -TERM "$stop_pid" 2>/dev/null || return 1
\tfi
\tstop_attempt=0
\twhile child_alive "$stop_pid" && [ "$stop_attempt" -lt 30 ]; do
\t\tcore_child_valid "$stop_pid" "$stop_exe" "$stop_starttime" || return 1
\t\tsleep 0.1
\t\tstop_attempt=$((stop_attempt + 1))
\tdone
\tif child_alive "$stop_pid"; then
\t\tprocess_identity_full \\
\t\t\t"$stop_pid" "$stop_exe" "$stop_sha256" "$stop_starttime" ||
\t\t\treturn 1
\t\tkill -KILL "$stop_pid" 2>/dev/null || return 1
\tfi
\twait "$stop_pid" 2>/dev/null || true
}
"""
    text = replace_shell_function(text, "stop_child", stop_child)

    cleanup = f"""cleanup() {{
\tcleanup_status=$?
\tcleanup_identity_failure=0
\ttrap - EXIT HUP INT TERM
\trelease_ready || cleanup_identity_failure=1
\tstop_child "$terminal_pid" {terminal_path} {terminal_sha256} \\
\t\t"$terminal_starttime" || cleanup_identity_failure=1
\tstop_child "$weston_pid" /usr/bin/weston {STOCK_WESTON_SHA256} \\
\t\t"$weston_starttime" || cleanup_identity_failure=1
\trelease_session_lock
\tif [ "$backoff_required" -eq 1 ] || {{
\t\t[ "$cleanup_status" -ne 0 ] && [ "$signal_exit" -eq 0 ]
\t}}; then
\t\tsleep 5
\tfi
\t[ "$cleanup_identity_failure" -eq 0 ] || exit 1
\texit "$cleanup_status"
}}
"""
    text = replace_shell_function(text, "cleanup", cleanup)

    keyboard_stable = (
        '\t\t\tif [ "$keyboard_stable_polls" -ge 5 ]; then\n'
        '\t\t\t\tprocess_sha256_valid "$keyboard_pid" \\\n'
        f"\t\t\t\t\t{keyboard_sha256} ||\n"
        '\t\t\t\t\tfail "weston-keyboard process digest changed"\n'
        '\t\t\t\tkeyboard_starttime=$(process_starttime "$keyboard_pid") ||\n'
        '\t\t\t\t\tfail "weston-keyboard start time is unavailable"\n'
        "\t\t\t\treturn 0\n"
        "\t\t\tfi"
    )
    text = replace_exact(
        text,
        '\t\t\t[ "$keyboard_stable_polls" -lt 5 ] || return 0',
        keyboard_stable,
    )

    text = replace_exact(
        text,
        _component_line("/usr/bin/weston-terminal", STOCK_TERMINAL_SHA256),
        _component_line(terminal_path, terminal_sha256),
    )
    text = replace_exact(
        text,
        _component_line("/usr/libexec/weston-keyboard", STOCK_KEYBOARD_SHA256),
        _component_line(keyboard_path, keyboard_sha256),
    )
    text = replace_exact(
        text,
        _component_line(
            "/etc/lmi-p2-d114/weston.ini", FROZEN_STOCK_CONFIG_SHA256
        ),
        _component_line(config_path, config_sha256),
    )
    text = replace_exact(
        text,
        "state_dir=$HOME/.local/state/lmi-p2-d114",
        "state_dir=$XDG_STATE_HOME",
    )
    text = replace_exact(
        text,
        "--config=/etc/lmi-p2-d114/weston.ini",
        f"--config={config_path}",
    )
    text = replace_exact(
        text,
        "/usr/bin/weston-terminal --maximized --font-size=18 &",
        f"{terminal_path} --maximized --font-size=18 &",
    )
    text = replace_exact(
        text,
        "weston_pid=$!\n\nsocket_ready=0",
        'weston_pid=$!\nweston_starttime=$(process_starttime "$weston_pid") || '
        'fail "Weston start time is unavailable"\n\nsocket_ready=0',
    )
    text = replace_exact(
        text,
        '[ "$socket_ready" -eq 1 ] || fail "Weston socket readiness timed out"\n\n'
        'wait_for_keyboard 150 "before keyboard readiness"',
        '[ "$socket_ready" -eq 1 ] || fail "Weston socket readiness timed out"\n\n'
        f'wait_for_core_child "$weston_pid" /usr/bin/weston {STOCK_WESTON_SHA256} Weston\n'
        'wait_for_keyboard 150 "before keyboard readiness"',
    )
    text = replace_exact(
        text,
        f"{terminal_path} --maximized --font-size=18 &\nterminal_pid=$!",
        f"{terminal_path} --maximized --font-size=18 &\nterminal_pid=$!\n"
        'terminal_starttime=$(process_starttime "$terminal_pid") || '
        'fail "weston-terminal start time is unavailable"\n'
        f'wait_for_core_child "$terminal_pid" {terminal_path} '
        f"{terminal_sha256} weston-terminal\n"
        'publish_ready || fail "could not publish full session readiness"',
    )
    text = replace_exact(
        text,
        'wait_for_keyboard 50 "while recovering after exit"\n'
        "\t\tkeyboard_stable_ticks=0",
        'wait_for_keyboard 50 "while recovering after exit"\n'
        '\t\tpublish_ready || fail "could not refresh full session readiness"\n'
        "\t\tkeyboard_stable_ticks=0",
    )
    return text


def render_config() -> str:
    if digest(FROZEN_STOCK_CONFIG) != FROZEN_STOCK_CONFIG_SHA256:
        raise StageError("frozen D114 stock Weston config changed")
    template = (FILES / "transient-weston.ini.in").read_text(encoding="utf-8")
    return replace_exact(template, "@REMOTE_ROOT@", REMOTE_ROOT, count=2)


def extract_payload(apk: Path) -> dict[str, bytes]:
    if digest(apk) != EXPECTED_APK_SHA256:
        raise StageError("refusing APK whose exact r1 SHA-256 is not approved")
    extracted: dict[str, bytes] = {}
    with tarfile.open(apk, mode="r:gz") as archive:
        for member in archive.getmembers():
            if member.name not in PAYLOAD:
                continue
            if member.name in extracted:
                raise StageError(f"duplicate payload member: {member.name}")
            if not member.isfile() or member.issym() or member.islnk():
                raise StageError(f"payload is not a regular file: {member.name}")
            stream = archive.extractfile(member)
            if stream is None:
                raise StageError(f"payload is unreadable: {member.name}")
            data = stream.read()
            if digest_bytes(data) != PAYLOAD[member.name][1]:
                raise StageError(f"payload hash mismatch: {member.name}")
            extracted[member.name] = data
    if set(extracted) != set(PAYLOAD):
        raise StageError("APK does not contain the exact two expected payload files")
    return extracted


def write_file(path: Path, data: bytes | str, mode: int) -> None:
    if isinstance(data, str):
        data = data.encode("utf-8")
    path.write_bytes(data)
    path.chmod(mode)


def _render_supervisor(
    *,
    candidate_session_sha256: str,
    fallback_session_sha256: str,
    config_sha256: str,
) -> str:
    template_path = FILES / "transient-supervisor.in"
    supervisor = template_path.read_text(encoding="utf-8")
    substitutions = {
        "@REMOTE_ROOT@": REMOTE_ROOT,
        "@ACTIVE_STOCK_SESSION@": ACTIVE_STOCK_SESSION,
        "@ACTIVE_STOCK_SESSION_SHA256@": ACTIVE_STOCK_SESSION_SHA256,
        "@CANDIDATE_SESSION_SHA256@": candidate_session_sha256,
        "@FALLBACK_SESSION_SHA256@": fallback_session_sha256,
        "@CONFIG_SHA256@": config_sha256,
        "@KEYBOARD_SHA256@": PAYLOAD[
            "usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"
        ][1],
        "@TERMINAL_SHA256@": PAYLOAD[
            "usr/libexec/lmi-p2-d114/weston-terminal-sixrow"
        ][1],
        "@BUSYBOX_SHA256@": BUSYBOX_SHA256,
        "@SETSID_SHA256@": SETSID_SHA256,
        "@STOCK_WESTON_SHA256@": STOCK_WESTON_SHA256,
        "@STOCK_TERMINAL_SHA256@": STOCK_TERMINAL_SHA256,
        "@STOCK_KEYBOARD_SHA256@": STOCK_KEYBOARD_SHA256,
    }
    for placeholder, value in substitutions.items():
        supervisor = replace_exact(supervisor, placeholder, value)
    if re.search(r"@[A-Z0-9_]+@", supervisor):
        raise StageError("supervisor contains unresolved placeholders")
    return supervisor


def _build_stage_tree(apk: Path, root: Path, artifact_path: str) -> dict:
    config = render_config()
    config_sha256 = digest_bytes(config.encode("utf-8"))
    candidate_session = replace_exact(
        render_session("candidate"), "@CONFIG_SHA256@", config_sha256
    )
    fallback_session = render_session("fallback")
    for name, script in (
        ("candidate", candidate_session),
        ("fallback", fallback_session),
    ):
        if re.search(r"@[A-Z0-9_]+@", script):
            raise StageError(f"{name} session contains an unresolved placeholder")
    candidate_session_sha256 = digest_bytes(candidate_session.encode("utf-8"))
    fallback_session_sha256 = digest_bytes(fallback_session.encode("utf-8"))
    supervisor = _render_supervisor(
        candidate_session_sha256=candidate_session_sha256,
        fallback_session_sha256=fallback_session_sha256,
        config_sha256=config_sha256,
    )
    payload = extract_payload(apk)

    for directory in SESSION_DIRECTORIES:
        (root / directory).mkdir(mode=0o700)
    for archive_name, (target_name, _expected_hash) in PAYLOAD.items():
        write_file(root / target_name, payload[archive_name], 0o700)
    write_file(root / "weston.ini", config, 0o600)
    write_file(root / "candidate-session", candidate_session, 0o700)
    write_file(root / "stock-session", fallback_session, 0o700)
    write_file(root / "supervisor", supervisor, 0o700)
    write_file(
        root / "status",
        "NO-GO: execution disabled after PID-signal-race review\n",
        0o600,
    )

    for script in (
        root / "candidate-session",
        root / "stock-session",
        root / "supervisor",
    ):
        subprocess.run(["sh", "-n", str(script)], check=True)

    staged_files = {}
    for path in sorted(root.iterdir()):
        if path.is_file() and not path.is_symlink():
            staged_files[path.name] = {
                "sha256": digest(path),
                "mode": f"{path.stat().st_mode & 0o777:03o}",
            }
    manifest = {
        "schema": "lmi-weston-sixrow-transient-stage/v2",
        "status": TRANSIENT_LOCK_STATUS,
        "execution_enabled": False,
        "purpose": "local read-only source and artifact inspection",
        "remote_root": REMOTE_ROOT,
        "trial_seconds": 120,
        "candidate_stability_seconds": 12,
        "restore_stability_seconds": 12,
        "apk": {"path": artifact_path, "sha256": EXPECTED_APK_SHA256},
        "active_stock_session": {
            "path": ACTIVE_STOCK_SESSION,
            "sha256": ACTIVE_STOCK_SESSION_SHA256,
            "required_ppid": 1,
        },
        "runtime_pins": {
            "/usr/bin/busybox": BUSYBOX_SHA256,
            "/usr/bin/setsid": SETSID_SHA256,
        },
        "writes_allowed": [REMOTE_ROOT, "/run/user/10000"],
        "files": staged_files,
        "known_residual_risks": [
            (
                "SIGKILL, kernel failure, or power loss can bypass in-process "
                "restoration; a live pinned SSH monitor and manual recovery remain required."
            ),
            (
                "The already-running legacy stock session validates its shell but not each "
                "child identity immediately before its own cleanup signals. The supervisor "
                "therefore exits before handoff; execution is disabled and operator acceptance "
                "does not waive the NO-GO decision."
            ),
        ],
        "no_go_reason": (
            "Independent review found a narrow PID-reuse signal race in the "
            "already-running legacy stock session cleanup path. The generated "
            "supervisor exits before preflight or signalling and is retained only "
            "for local inspection."
        ),
        "forbidden_operations": [
            "apk add/fix",
            "fastboot or partition writes",
            "reboot",
            "rc-service or rc-update",
            "writes to /home, /etc, /usr, or /var",
        ],
    }
    write_file(
        root / "manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    return manifest


def stage(apk: Path, output: Path) -> dict:
    transient_lock = verify_transient_source_lock()
    attestation = json.loads(verify.BUILD_ATTESTATION_PATH.read_text(encoding="utf-8"))
    artifact_path = attestation["artifact"]["path"]
    expected_apk = Path(os.path.abspath(REPO / artifact_path))
    supplied_apk = Path(os.path.abspath(apk))
    if apk.is_symlink() or supplied_apk != expected_apk:
        raise StageError("APK must be the exact non-symlink attested r1 path")
    verify.verify_build_attestation(require_artifact=True)

    output = Path(os.path.abspath(output))
    if output.exists() or output.is_symlink():
        raise StageError("output path already exists; refusing overwrite")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        raise StageError("output parent must be an existing non-symlink directory")

    temporary = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.partial-", dir=str(parent))
    )
    try:
        temporary.chmod(0o700)
        manifest = _build_stage_tree(apk, temporary, artifact_path)
        manifest["source_lock"] = {
            "path": str(TRANSIENT_LOCK_PATH.relative_to(REPO)),
            "sha256": digest(TRANSIENT_LOCK_PATH),
            "status": transient_lock["status"],
        }
        write_file(
            temporary / "manifest.json",
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            0o600,
        )
        os.rename(temporary, output)
        temporary = Path()
        return manifest
    finally:
        if temporary != Path() and temporary.exists():
            shutil.rmtree(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    manifest = stage(args.apk, args.output)
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
