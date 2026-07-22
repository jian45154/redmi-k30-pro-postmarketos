"""Strict parser and policy checks for the lmi P2 source-only profile."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
from urllib.parse import urlsplit


SCHEMA = "lmi-p2-source-profile/v1"
UNVERIFIED = "UNVERIFIED"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_PACKAGE_RE = re.compile(r"^[a-z0-9][a-z0-9+_.-]*$")
_VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*-r[0-9]+$")

_TOP_KEYS = {
    "baseline",
    "build_dependencies",
    "display",
    "keyboard",
    "kernel_delta",
    "package",
    "package_pins",
    "primary_sources",
    "release",
    "repository_index_sha256",
    "schema",
    "source_files",
    "weston",
}
_SOURCE_FILES = {
    "device-xiaomi-lmi-gui.post-install",
    "device-xiaomi-lmi-gui.post-upgrade",
    "device-xiaomi-lmi-gui.pre-deinstall",
    "lmi-account-lifecycle",
    "lmi-child-supervisor.c",
    "lmi-child-supervisor.h",
    "lmi-input-state.c",
    "lmi-input-state.h",
    "lmi-layer-state.c",
    "lmi-layer-state.h",
    "lmi-display-handoff.c",
    "lmi-display.initd",
    "lmi-editor",
    "lmi-session-launcher.c",
    "lmi-terminal",
    "lmi-terminal-bridge.c",
    "lmi-weston-osk.c",
    "lmi-weston-user-session",
    "weston.ini",
}
_REQUIRED_PACKAGES = {
    "device-xiaomi-lmi",
    "font-dejavu",
    "kbd",
    "libdrm-tests",
    "libseat",
    "libweston",
    "linux-xiaomi-lmi",
    "openrc",
    "seatd",
    "seatd-openrc",
    "weston",
    "weston-backend-drm",
    "weston-clients",
    "weston-shell-desktop",
    "weston-terminal",
}
_EXPECTED_PIN_FACTS = {
    "device-xiaomi-lmi": ("1-r107", "local-p1", "6fb3a1e5eb21c809891645a2ba5ae11fa788e032"),
    "font-dejavu": ("2.37-r6", "alpine-edge-main", "59420f440b2e664f7be1a6e135a3175aab56cd51"),
    "kbd": ("2.8.0-r0", "alpine-edge-main", "8b9313df10ed04f8840a6437d3187341a1cbdaa5"),
    "libdrm-tests": ("2.4.134-r0", "alpine-edge-main", "2015800769b781bef45917b668d10bffe2ac538f"),
    "libseat": ("0.9.3-r0", "alpine-edge-community", "493aed10300970781e9df821a418b91cf3aa6af2"),
    "libweston": ("14.0.2-r5", "alpine-edge-community", "d17cb894a1d4eb6c810dd6b6dc9e678eb48a1901"),
    "linux-xiaomi-lmi": ("4.19.325-r8", "local-p1", "a5b3099017ae581aae8bf597b2f9c8c765026af1"),
    "openrc": ("0.63.2-r0", "alpine-edge-main", "ec72b2b622241418671d1805bf004d00f953d51a"),
    "seatd": ("0.9.3-r0", "alpine-edge-community", "493aed10300970781e9df821a418b91cf3aa6af2"),
    "seatd-openrc": ("0.9.3-r0", "alpine-edge-community", "493aed10300970781e9df821a418b91cf3aa6af2"),
    "weston": ("14.0.2-r5", "alpine-edge-community", "d17cb894a1d4eb6c810dd6b6dc9e678eb48a1901"),
    "weston-backend-drm": ("14.0.2-r5", "alpine-edge-community", "d17cb894a1d4eb6c810dd6b6dc9e678eb48a1901"),
    "weston-clients": ("14.0.2-r5", "alpine-edge-community", "d17cb894a1d4eb6c810dd6b6dc9e678eb48a1901"),
    "weston-shell-desktop": ("14.0.2-r5", "alpine-edge-community", "d17cb894a1d4eb6c810dd6b6dc9e678eb48a1901"),
    "weston-terminal": ("14.0.2-r5", "alpine-edge-community", "d17cb894a1d4eb6c810dd6b6dc9e678eb48a1901"),
}
_WESTON_PACKAGES = {
    "libweston",
    "weston",
    "weston-backend-drm",
    "weston-clients",
    "weston-shell-desktop",
    "weston-terminal",
}
_BUILD_DEPENDENCIES = {
    "build-base",
    "cairo-dev",
    "linux-headers",
    "pango-dev",
    "pkgconf",
    "wayland-dev",
    "wayland-protocols",
    "xkbcommon-dev",
}
_LAYER_NAMES = {"lower", "upper", "symbols", "nav"}
_ACTIONS = {"text", "keysym", "layer", "modifier"}
_KEY_FIELDS = {"action", "label", "value", "weight"}
_REQUIRED_KEYSYMS = {
    "BackSpace",
    "Return",
    "Escape",
    "Tab",
    "Left",
    "Right",
    "Up",
    "Down",
    "Home",
    "End",
    "Prior",
    "Next",
    "Delete",
}
_REQUIRED_MODIFIERS = {"shift", "control", "alt"}
_REQUIRED_SHELL_CHARACTERS = set(
    "0123456789-_/\\|<>=+*?.,:;'\"()[]{}$#@!%&~^` "
)
_SOURCE_BLOCKERS = [
    "alpine-edge-libseat-runtime-requires-libelogind",
    "hardware-display-and-touch-validation-not-run",
    "linux-xiaomi-lmi-r8-vt-delta-unverified",
    "native-osk-not-built-in-pinned-aarch64-chroot",
    "repository-index-and-apk-digests-unverified",
    "stock-weston-terminal-native-focus-integration-unavailable",
]


class ProfileError(ValueError):
    """A fail-closed P2 profile validation error."""


@dataclass(frozen=True)
class SourceProfile:
    """Validated profile with the original JSON object."""

    path: Path
    value: dict[str, Any]
    raw: bytes
    sha256: str

    @property
    def package_pins(self) -> dict[str, dict[str, Any]]:
        return {record["name"]: record for record in self.value["package_pins"]}

    @property
    def release_eligible(self) -> bool:
        return bool(self.value["release"]["eligible"])

    def require_release_ready(self) -> None:
        if not self.release_eligible:
            raise ProfileError("P2 profile is explicitly not release eligible")
        unresolved = [
            record["name"]
            for record in self.value["package_pins"]
            if record["artifact_sha256"] == UNVERIFIED
        ]
        if self.value["repository_index_sha256"] == UNVERIFIED or unresolved:
            raise ProfileError("P2 release pins are unresolved")
        if self.value["baseline"]["kernel_config_blocker"]:
            raise ProfileError("P2 kernel configuration blocker is unresolved")
        if self.value["kernel_delta"]["delta_commit"] == UNVERIFIED or self.value[
            "kernel_delta"
        ]["patch_sha256"] == UNVERIFIED:
            raise ProfileError("P2 kernel delta pin is unresolved")


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _read_stable_profile(path: Path) -> bytes:
    """Read one regular immutable snapshot and retain those exact bytes."""

    descriptor = -1
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
        )
        initial = os.fstat(descriptor)
        if (
            not stat.S_ISREG(initial.st_mode)
            or initial.st_nlink != 1
            or initial.st_mode & 0o022
        ):
            raise ProfileError("unsafe P2 profile file")
        chunks: list[bytes] = []
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
        final_descriptor = os.fstat(descriptor)
        final_path = path.lstat()
    except OSError as error:
        raise ProfileError(f"could not read P2 profile: {error}") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    raw = b"".join(chunks)
    stable_fields = (
        "st_dev",
        "st_ino",
        "st_mode",
        "st_nlink",
        "st_uid",
        "st_gid",
        "st_size",
        "st_mtime_ns",
        "st_ctime_ns",
    )
    if (
        any(
            getattr(initial, field) != getattr(final_descriptor, field)
            for field in stable_fields
        )
        or any(
            getattr(initial, field) != getattr(final_path, field)
            for field in stable_fields
        )
        or len(raw) != initial.st_size
    ):
        raise ProfileError("unsafe or unstable P2 profile file")
    return raw


def _object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        actual = set(value) if isinstance(value, dict) else type(value).__name__
        raise ProfileError(f"{label} fields mismatch: {actual!r}")
    return value


def _string(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not value and not allow_empty) or "\x00" in value:
        raise ProfileError(f"{label} must be a safe string")
    return value


def _integer(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ProfileError(f"{label} must be an integer in [{minimum}, {maximum}]")
    return value


def _sha_or_placeholder(value: Any, label: str) -> str:
    if value == UNVERIFIED:
        return value
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise ProfileError(f"{label} must be sha256 or {UNVERIFIED}")
    return value


def _validate_packages(value: Any, weston: dict[str, Any], baseline: dict[str, Any]) -> None:
    if not isinstance(value, list) or not value:
        raise ProfileError("package_pins must be a non-empty list")
    names: list[str] = []
    records: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(value):
        record = _object(
            item,
            {"artifact_sha256", "name", "repository", "source_commit", "version"},
            f"package_pins[{index}]",
        )
        name = _string(record["name"], f"package_pins[{index}].name")
        if _PACKAGE_RE.fullmatch(name) is None or "elogind" in name:
            raise ProfileError(f"forbidden or malformed package name: {name}")
        version = _string(record["version"], f"package_pins[{index}].version")
        if _VERSION_RE.fullmatch(version) is None:
            raise ProfileError(f"malformed package version: {name}={version}")
        repository = _string(record["repository"], f"package_pins[{index}].repository")
        if repository not in {"local-p1", "alpine-edge-main", "alpine-edge-community"}:
            raise ProfileError(f"unapproved package repository: {repository}")
        if not isinstance(record["source_commit"], str) or _COMMIT_RE.fullmatch(
            record["source_commit"]
        ) is None:
            raise ProfileError(f"invalid source commit for {name}")
        _sha_or_placeholder(record["artifact_sha256"], f"{name}.artifact_sha256")
        if name in records:
            raise ProfileError(f"duplicate package pin: {name}")
        names.append(name)
        records[name] = record
    if names != sorted(names) or set(names) != _REQUIRED_PACKAGES:
        raise ProfileError("package_pins must be the exact sorted P2 package set")
    for name, expected in _EXPECTED_PIN_FACTS.items():
        record = records[name]
        actual = (record["version"], record["repository"], record["source_commit"])
        if actual != expected:
            raise ProfileError(f"reviewed package source fact changed: {name}")
    expected_device = baseline["device_dependency"].split("=", 1)
    if expected_device != ["device-xiaomi-lmi", records["device-xiaomi-lmi"]["version"]]:
        raise ProfileError("GUI package does not bind the exact P1 device package")
    weston_version = weston["version"]
    if any(records[name]["version"] != weston_version for name in _WESTON_PACKAGES):
        raise ProfileError("Weston and libweston split versions must match exactly")
    if weston["abi"] != 14 or not weston_version.startswith("14."):
        raise ProfileError("Weston package set does not provide the required libweston-14 ABI")


def _validate_keyboard(value: Any, display: dict[str, Any]) -> None:
    keyboard = _object(
        value,
        {"gap", "layers", "margin", "minimum_touch_height", "minimum_touch_width"},
        "keyboard",
    )
    gap = _integer(keyboard["gap"], "keyboard.gap", 0, 20)
    margin = _integer(keyboard["margin"], "keyboard.margin", 0, 40)
    min_width = _integer(
        keyboard["minimum_touch_width"], "keyboard.minimum_touch_width", 32, 100
    )
    min_height = _integer(
        keyboard["minimum_touch_height"], "keyboard.minimum_touch_height", 32, 100
    )
    layers = keyboard["layers"]
    if not isinstance(layers, list) or len(layers) != len(_LAYER_NAMES):
        raise ProfileError("keyboard must contain exactly four layers")

    found_layers: dict[str, dict[str, Any]] = {}
    text_values: set[str] = set()
    keysym_values: set[str] = set()
    modifier_values: set[str] = set()
    edges: dict[str, set[str]] = {}
    for layer_index, item in enumerate(layers):
        layer = _object(item, {"name", "rows"}, f"keyboard.layers[{layer_index}]")
        name = _string(layer["name"], f"keyboard.layers[{layer_index}].name")
        if name not in _LAYER_NAMES or name in found_layers:
            raise ProfileError(f"invalid or duplicate keyboard layer: {name}")
        rows = layer["rows"]
        if not isinstance(rows, list) or not 3 <= len(rows) <= 6:
            raise ProfileError(f"layer {name} must contain 3-6 rows")
        row_height = (
            display["logical_height"] - 2 * margin - gap * (len(rows) - 1)
        ) / len(rows)
        if row_height < min_height:
            raise ProfileError(f"layer {name} touch rows are clipped or too short")
        edges[name] = set()
        for row_index, row in enumerate(rows):
            if not isinstance(row, list) or not 2 <= len(row) <= 12:
                raise ProfileError(f"layer {name} row {row_index} has invalid key count")
            weights = 0
            for key_index, item_key in enumerate(row):
                key = _object(
                    item_key,
                    _KEY_FIELDS,
                    f"keyboard.{name}.rows[{row_index}][{key_index}]",
                )
                action = _string(key["action"], "key.action")
                label = _string(key["label"], "key.label")
                key_value = _string(key["value"], "key.value")
                weight = _integer(key["weight"], "key.weight", 5, 50)
                if action not in _ACTIONS or len(label) > 12:
                    raise ProfileError(f"invalid key in layer {name}: {label}")
                if action == "text":
                    if len(key_value) != 1 or ord(key_value) > 0x7F:
                        raise ProfileError("P2 text keys must be single ASCII characters")
                    text_values.add(key_value)
                elif action == "keysym":
                    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*", key_value):
                        raise ProfileError(f"invalid keysym: {key_value}")
                    keysym_values.add(key_value)
                elif action == "layer":
                    if key_value not in _LAYER_NAMES:
                        raise ProfileError(f"invalid layer target: {key_value}")
                    edges[name].add(key_value)
                elif action == "modifier":
                    if key_value not in _REQUIRED_MODIFIERS:
                        raise ProfileError(f"invalid modifier: {key_value}")
                    modifier_values.add(key_value)
                weights += weight
            drawable = display["logical_width"] - 2 * margin - gap * (len(row) - 1)
            if min(drawable * key["weight"] / weights for key in row) < min_width:
                raise ProfileError(f"layer {name} row {row_index} has a clipped touch target")
        found_layers[name] = layer

    if set(found_layers) != _LAYER_NAMES:
        raise ProfileError("keyboard layer set is incomplete")
    reachable = {"lower"}
    pending = ["lower"]
    while pending:
        current = pending.pop()
        for target in edges[current] - reachable:
            reachable.add(target)
            pending.append(target)
    if reachable != _LAYER_NAMES:
        raise ProfileError("not every keyboard layer is reachable from lower")
    if not set("abcdefghijklmnopqrstuvwxyz") <= text_values:
        raise ProfileError("lowercase alphabet is incomplete")
    if not set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") <= text_values:
        raise ProfileError("uppercase alphabet is incomplete")
    if not _REQUIRED_SHELL_CHARACTERS <= text_values:
        raise ProfileError("digit, punctuation or shell-symbol coverage is incomplete")
    if not _REQUIRED_KEYSYMS <= keysym_values:
        raise ProfileError("navigation/editing keysym coverage is incomplete")
    if not _REQUIRED_MODIFIERS <= modifier_values:
        raise ProfileError("modifier coverage is incomplete")


def load_profile(path: Path) -> SourceProfile:
    """Load a profile with exact-field, type, dependency and layout validation."""

    try:
        raw = _read_stable_profile(path)
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_fields
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ProfileError(f"could not read P2 profile: {error}") from None
    root = _object(value, _TOP_KEYS, "profile")
    if root["schema"] != SCHEMA:
        raise ProfileError("unsupported P2 profile schema")

    baseline = _object(
        root["baseline"],
        {"device_dependency", "kernel_config_blocker", "kernel_dependency", "pmaports_commit"},
        "baseline",
    )
    if baseline["device_dependency"] != "device-xiaomi-lmi=1-r107":
        raise ProfileError("P2 must layer on the exact locked P1 device package")
    if baseline["kernel_dependency"] != "linux-xiaomi-lmi=4.19.325-r8":
        raise ProfileError("P2 baseline kernel identity changed")
    if baseline["kernel_config_blocker"] != "CONFIG_VT is not set":
        raise ProfileError("P2 must retain the explicit r8 VT blocker")
    if baseline["pmaports_commit"] != "6fb3a1e5eb21c809891645a2ba5ae11fa788e032":
        raise ProfileError("pmaports commit changed from locked P1")

    build_dependencies = root["build_dependencies"]
    if (
        not isinstance(build_dependencies, list)
        or build_dependencies != sorted(build_dependencies)
        or set(build_dependencies) != _BUILD_DEPENDENCIES
    ):
        raise ProfileError("build dependency set must be exact and sorted")

    display = _object(
        root["display"],
        {"connector", "height", "logical_height", "logical_width", "renderer", "scale", "tty", "width"},
        "display",
    )
    expected_display = {
        "connector": "DSI-1",
        "height": 2400,
        "logical_height": 420,
        "logical_width": 540,
        "renderer": "pixman",
        "scale": 2,
        "tty": 7,
        "width": 1080,
    }
    if display != expected_display:
        raise ProfileError("display profile must be the reviewed 1080x2400 scale-2 contract")
    if display["logical_width"] * display["scale"] != display["width"]:
        raise ProfileError("logical keyboard width would clip the physical output")
    if display["logical_height"] * display["scale"] > display["height"]:
        raise ProfileError("logical keyboard height would clip the physical output")

    package = _object(root["package"], {"arch", "name", "pkgrel", "pkgver"}, "package")
    if package != {"arch": "aarch64", "name": "device-xiaomi-lmi-gui", "pkgrel": 0, "pkgver": "1"}:
        raise ProfileError("unexpected GUI package identity")
    weston = _object(root["weston"], {"abi", "version"}, "weston")
    _integer(weston["abi"], "weston.abi", 1, 99)
    if not isinstance(weston["version"], str) or _VERSION_RE.fullmatch(weston["version"]) is None:
        raise ProfileError("invalid Weston version")
    _validate_packages(root["package_pins"], weston, baseline)
    _validate_keyboard(root["keyboard"], display)

    kernel_delta = _object(
        root["kernel_delta"],
        {"base_commit", "base_package", "delta_commit", "patch_sha256", "required_symbols"},
        "kernel_delta",
    )
    if kernel_delta["base_commit"] != "a5b3099017ae581aae8bf597b2f9c8c765026af1":
        raise ProfileError("kernel delta changed the locked downstream base commit")
    if kernel_delta["base_package"] != baseline["kernel_dependency"]:
        raise ProfileError("kernel delta changed the locked P1 kernel package")
    if kernel_delta["delta_commit"] != UNVERIFIED or kernel_delta["patch_sha256"] != UNVERIFIED:
        raise ProfileError("kernel delta pins require a separately reviewed profile revision")
    required_symbols = kernel_delta["required_symbols"]
    expected_symbols = [
        "CONFIG_DRM=y",
        "CONFIG_DRM_KMS_HELPER=y",
        "CONFIG_INPUT_EVDEV=y",
        "CONFIG_UNIX98_PTYS=y",
        "CONFIG_VT=y",
        "CONFIG_VT_CONSOLE=y",
        "CONFIG_VT_HW_CONSOLE_BINDING=y",
    ]
    if required_symbols != expected_symbols:
        raise ProfileError("kernel delta feature contract is incomplete")

    release = _object(
        root["release"], {"blockers", "eligible", "reason"}, "release"
    )
    if not isinstance(release["eligible"], bool) or release["eligible"]:
        raise ProfileError("this source profile must remain explicitly non-release-eligible")
    _string(release["reason"], "release.reason")
    if release["blockers"] != _SOURCE_BLOCKERS:
        raise ProfileError("source-only release blocker set changed")
    _sha_or_placeholder(root["repository_index_sha256"], "repository_index_sha256")
    if root["repository_index_sha256"] != UNVERIFIED:
        raise ProfileError("repository index pin requires a separately reviewed profile revision")

    source_files = root["source_files"]
    if not isinstance(source_files, dict) or set(source_files) != _SOURCE_FILES:
        raise ProfileError("source file digest set mismatch")
    for name, digest in source_files.items():
        if _SHA256_RE.fullmatch(digest) is None:
            raise ProfileError(f"invalid source file digest: {name}")

    primary_sources = root["primary_sources"]
    if not isinstance(primary_sources, list) or len(primary_sources) < 8:
        raise ProfileError("primary source references are incomplete")
    if len(set(primary_sources)) != len(primary_sources):
        raise ProfileError("duplicate primary source reference")
    for url in primary_sources:
        if not isinstance(url, str) or not url.startswith("https://") or any(
            character in url for character in ("\x00", "\n", "\r")
        ):
            raise ProfileError("invalid primary source URL")
        if urlsplit(url).hostname not in {
            "gitlab.postmarketos.org",
            "wiki.alpinelinux.org",
            "pkgs.alpinelinux.org",
            "gitlab.freedesktop.org",
        }:
            raise ProfileError("primary source URL is not on an approved upstream host")

    return SourceProfile(
        path=path,
        value=root,
        raw=raw,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
