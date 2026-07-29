#!/usr/bin/env python3
"""Cross-check hand-copied release pins across the repository.

The repository pins release artifacts (APKs, payload binaries, lock
files) by SHA-256 digests that are hand-copied into JSON locks, shell
variables, Python constants, the on-device session gate, and docs.  A
stale copy passes CI but bricks the device session: the on-device gate
refuses mismatched digests.  This module is the single registry of
every such pin site and a verify-only cross-checker.

Guarantees:

- read-only: never writes, never regenerates a pin, never touches the
  network or any device;
- deterministic: sites are declared and reported in a fixed order;
- explicit: every mismatched or unreadable site is listed with a
  stable label, so ``verify`` output doubles as the re-pin checklist
  from notes/lmi-d114-p2-next-version-handoff-2026-07-22.md.

Usage:
    python3 scripts/lmi_release_pins.py verify [--root DIR]
    python3 scripts/lmi_release_pins.py list [--root DIR]

Exit status: 0 when every site agrees, 1 when any site is mismatched
or unreadable, 2 on usage errors.
"""

import argparse
import ast
import dataclasses
import hashlib
import json
import pathlib
import re
import sys

_SHA256_HEX = r"([0-9a-f]{64})"


class SiteUnreadable(Exception):
    """A pin site could not be read or its pin could not be located."""


@dataclasses.dataclass(frozen=True)
class Site:
    """One location where a pin value is declared.

    ``label`` is stable and human-oriented: the verify report keyed by
    these labels is the executable form of the prose re-pin checklist.
    """

    label: str
    path: str
    kind: str  # json | shell_var | python_const | regex | file_sha256
    pointer: tuple = ()  # json: key path into the document
    var: str = ""  # shell_var: variable name
    const: str = ""  # python_const: module-level constant name
    selector: tuple = ()  # python_const: keys/indices into the value
    pattern: str = ""  # regex: context-anchored, one capture group
    min_count: int = 1  # regex: minimum required occurrences
    exact_count: int = 0  # regex: nonzero means exactly this many occurrences
    value_pattern: str = ""  # post-filter applied to extracted values
    expected_transform: str = ""  # "" | "prefix:N" | "int"
    best_effort: bool = False  # prose site: unreadable warns, not fails


@dataclasses.dataclass(frozen=True)
class Artifact:
    """A logical pinned artifact: one truth plus every copy site."""

    name: str
    truth: Site
    sites: tuple


@dataclasses.dataclass(frozen=True)
class Finding:
    status: str  # OK | MISMATCH | UNREADABLE | WARN
    artifact: str
    site_label: str
    path: str
    detail: str

    @property
    def fatal(self):
        return self.status in ("MISMATCH", "UNREADABLE")


def _site_file(root, site):
    relative = pathlib.PurePosixPath(site.path)
    if relative.is_absolute() or ".." in relative.parts:
        raise SiteUnreadable(
            "unsafe site path (must be repo-relative): %s" % site.path
        )
    path = pathlib.Path(root) / site.path
    if not path.is_file():
        raise SiteUnreadable("file does not exist: %s" % site.path)
    return path


def _read_text(root, site):
    try:
        return _site_file(root, site).read_text(encoding="utf-8")
    except SiteUnreadable:
        raise
    except (OSError, UnicodeDecodeError) as error:
        raise SiteUnreadable(
            "cannot read %s: %s" % (site.path, error)
        ) from error


def _walk(value, steps, describe):
    for step in steps:
        if isinstance(step, int) and isinstance(value, (list, tuple)):
            if not 0 <= step < len(value):
                raise SiteUnreadable(
                    "index %r out of range in %s" % (step, describe)
                )
            value = value[step]
        elif isinstance(value, dict):
            if step not in value:
                raise SiteUnreadable(
                    "key %r missing in %s" % (step, describe)
                )
            value = value[step]
        else:
            raise SiteUnreadable(
                "cannot select %r from %s value in %s"
                % (step, type(value).__name__, describe)
            )
    return value


def _extract_json(root, site):
    text = _read_text(root, site)
    try:
        document = json.loads(text)
    except ValueError as error:
        raise SiteUnreadable(
            "invalid JSON in %s: %s" % (site.path, error)
        ) from error
    value = _walk(document, site.pointer, site.path)
    if not isinstance(value, (str, int)):
        raise SiteUnreadable(
            "JSON value at %r in %s is not a string or integer"
            % ("/".join(str(p) for p in site.pointer), site.path)
        )
    return [str(value)]


def _extract_shell_var(root, site):
    text = _read_text(root, site)
    pattern = re.compile(
        r"^[ \t]*(?:readonly[ \t]+)?"
        + re.escape(site.var)
        + r"=([\"']?)([^\"'\s#]+)\1[ \t]*$",
        re.MULTILINE,
    )
    matches = pattern.findall(text)
    if not matches:
        raise SiteUnreadable(
            "shell variable %s not found in %s" % (site.var, site.path)
        )
    if len(matches) > 1:
        raise SiteUnreadable(
            "shell variable %s assigned %d times in %s (need exactly 1)"
            % (site.var, len(matches), site.path)
        )
    return [matches[0][1]]


def _extract_python_const(root, site):
    text = _read_text(root, site)
    try:
        module = ast.parse(text, filename=site.path)
    except SyntaxError as error:
        raise SiteUnreadable(
            "cannot parse %s: %s" % (site.path, error)
        ) from error
    assignments = []
    for node in module.body:
        if isinstance(node, ast.Assign):
            names = [
                target.id
                for target in node.targets
                if isinstance(target, ast.Name)
            ]
            if site.const in names:
                assignments.append(node.value)
        elif isinstance(node, ast.AnnAssign):
            if (
                isinstance(node.target, ast.Name)
                and node.target.id == site.const
                and node.value is not None
            ):
                assignments.append(node.value)
    if not assignments:
        raise SiteUnreadable(
            "constant %s not found in %s" % (site.const, site.path)
        )
    if len(assignments) > 1:
        raise SiteUnreadable(
            "constant %s assigned %d times in %s (need exactly 1)"
            % (site.const, len(assignments), site.path)
        )
    try:
        value = ast.literal_eval(assignments[0])
    except (ValueError, SyntaxError) as error:
        raise SiteUnreadable(
            "constant %s in %s is not a literal: %s"
            % (site.const, site.path, error)
        ) from error
    value = _walk(
        value, site.selector, "%s in %s" % (site.const, site.path)
    )
    if not isinstance(value, (str, int)):
        raise SiteUnreadable(
            "constant %s in %s is not a string or integer"
            % (site.const, site.path)
        )
    return [str(value)]


def _extract_regex(root, site):
    text = _read_text(root, site)
    try:
        pattern = re.compile(site.pattern, re.MULTILINE | re.DOTALL)
    except re.error as error:
        raise SiteUnreadable(
            "invalid site pattern for %s: %s" % (site.label, error)
        ) from error
    values = [match.group(1) for match in pattern.finditer(text)]
    if site.exact_count and len(values) != site.exact_count:
        raise SiteUnreadable(
            "pattern for %s matched %d time(s) in %s (need exactly %d)"
            % (site.label, len(values), site.path, site.exact_count)
        )
    if len(values) < site.min_count:
        raise SiteUnreadable(
            "pattern for %s matched %d time(s) in %s (need >= %d)"
            % (site.label, len(values), site.path, site.min_count)
        )
    return values


def _extract_file_sha256(root, site):
    path = _site_file(root, site)
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
    except OSError as error:
        raise SiteUnreadable(
            "cannot hash %s: %s" % (site.path, error)
        ) from error
    return [digest.hexdigest()]


_EXTRACTORS = {
    "json": _extract_json,
    "shell_var": _extract_shell_var,
    "python_const": _extract_python_const,
    "regex": _extract_regex,
    "file_sha256": _extract_file_sha256,
}


def extract_site(root, site):
    """Return every pin value declared at ``site`` (raises SiteUnreadable)."""
    extractor = _EXTRACTORS.get(site.kind)
    if extractor is None:
        raise SiteUnreadable(
            "unknown site kind %r for %s" % (site.kind, site.label)
        )
    values = extractor(root, site)
    if site.value_pattern:
        try:
            refine = re.compile(site.value_pattern)
        except re.error as error:
            raise SiteUnreadable(
                "invalid value pattern for %s: %s" % (site.label, error)
            ) from error
        refined = []
        for value in values:
            match = refine.search(value)
            if match is None:
                raise SiteUnreadable(
                    "value %r at %s does not match expected shape"
                    % (value, site.label)
                )
            refined.append(match.group(1))
        values = refined
    return values


def _expected_for(site, truth_value):
    transform = site.expected_transform
    if not transform:
        return truth_value
    if transform.startswith("prefix:"):
        length = int(transform.split(":", 1)[1])
        return truth_value[:length]
    if transform == "int":
        return truth_value
    raise SiteUnreadable(
        "unknown expected_transform %r for %s" % (transform, site.label)
    )


def _values_equal(site, expected, actual):
    if site.expected_transform == "int":
        try:
            return int(str(expected).replace(",", "").replace("_", "")) == int(
                str(actual).replace(",", "").replace("_", "")
            )
        except ValueError:
            return False
    return expected == actual


def verify_registry(root, registry):
    """Cross-check every artifact; return findings in declaration order."""
    root = pathlib.Path(root)
    findings = []
    for artifact in registry:
        try:
            truth_values = extract_site(root, artifact.truth)
        except SiteUnreadable as error:
            findings.append(
                Finding(
                    status="UNREADABLE",
                    artifact=artifact.name,
                    site_label=artifact.truth.label,
                    path=artifact.truth.path,
                    detail="declared truth is unreadable: %s" % error,
                )
            )
            for site in artifact.sites:
                findings.append(
                    Finding(
                        status="UNREADABLE",
                        artifact=artifact.name,
                        site_label=site.label,
                        path=site.path,
                        detail="skipped: truth for %s is unreadable"
                        % artifact.name,
                    )
                )
            continue
        if len(truth_values) != 1:
            findings.append(
                Finding(
                    status="UNREADABLE",
                    artifact=artifact.name,
                    site_label=artifact.truth.label,
                    path=artifact.truth.path,
                    detail="declared truth must yield exactly one value, "
                    "got %d" % len(truth_values),
                )
            )
            continue
        truth_value = truth_values[0]
        findings.append(
            Finding(
                status="OK",
                artifact=artifact.name,
                site_label=artifact.truth.label,
                path=artifact.truth.path,
                detail="truth = %s" % truth_value,
            )
        )
        for site in artifact.sites:
            try:
                expected = _expected_for(site, truth_value)
                values = extract_site(root, site)
            except SiteUnreadable as error:
                findings.append(
                    Finding(
                        status="WARN" if site.best_effort else "UNREADABLE",
                        artifact=artifact.name,
                        site_label=site.label,
                        path=site.path,
                        detail=str(error),
                    )
                )
                continue
            stale = [
                value
                for value in values
                if not _values_equal(site, expected, value)
            ]
            if stale:
                findings.append(
                    Finding(
                        status="MISMATCH",
                        artifact=artifact.name,
                        site_label=site.label,
                        path=site.path,
                        detail="expected %s, found %s"
                        % (expected, ", ".join(sorted(set(stale)))),
                    )
                )
            else:
                findings.append(
                    Finding(
                        status="OK",
                        artifact=artifact.name,
                        site_label=site.label,
                        path=site.path,
                        detail="%d occurrence(s) agree" % len(values),
                    )
                )
    return findings


def _session_path_digest(component):
    """Digest continued after an escaped-newline component path."""
    return re.escape(component) + r" \\\s*" + _SHA256_HEX


# ---------------------------------------------------------------------------
# The registry: one entry per logical artifact, one Site per hand copy.
# Labels are stable; `verify` output keyed by them is the re-pin
# checklist (notes/lmi-d114-p2-next-version-handoff-2026-07-22.md).
# Pin values themselves live only in the checked files, never here.
# ---------------------------------------------------------------------------

_BUILD_ATTESTATION = "config/lmi-weston-sixrow/build-attestation.json"
_BUILD_ATTESTATION_R2 = "config/lmi-weston-sixrow/build-attestation-r2.json"
_TRANSIENT_STAGE_LOCK = "config/lmi-weston-sixrow/transient-stage-lock.json"
_INJECTION_POLICY_LOCK = "config/lmi-p2-d114/injection-policy-lock.json"
_CANDIDATE_REBUILD_LOCK = "config/lmi-p2-d114/candidate-rebuild-lock.json"
_P2_SOURCE_LOCK = "config/lmi-p2-d114/source-lock.json"
_P1_SOURCE_LOCK = "config/lmi-p1/source-lock.json"
_INJECT_SH = "scripts/lmi_p2_d114/inject_rootfs_candidate.sh"
_LAUNCH_SH = "scripts/lmi_p2_d114/launch_inject_rootfs_candidate.sh"
_STAGE_TRANSIENT = "scripts/lmi_weston_sixrow/stage_transient.py"
_SOURCE_LOCK_PY = "scripts/lmi_p2_d114/source_lock.py"
_ASSEMBLE_PY = "scripts/lmi_p2_d114/assemble_userdata_image.py"
_DEPLOY_PY = "scripts/lmi_p2_d114/deploy_userdata.py"
_HELPER_PS1 = "scripts/lmi_p2_d114/deploy_userdata_helper.ps1"
_SESSION = "files/lmi-p2-d114/lmi-p2-d114-session"
_READINESS_DOC = "docs/release/lmi-d114-r1-sixrow-readiness-20260722.md"
_KERNEL_DOC = "docs/lmi-p1-known-good-kernel-package.md"
_STATIC_CI = "scripts/59_release_static_ci.sh"
_BUILD_PY = "scripts/lmi_p1/build.py"
_KERNEL_TEST = "tests/lmi_p1/test_known_good_kernel.py"

_KBD = "/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"
_TERM = "/usr/libexec/lmi-p2-d114/weston-terminal-sixrow"
_WESTON = "/usr/bin/weston"


def _payload_artifact(name, component, add_file_meta, session_sites,
                      attestation=_BUILD_ATTESTATION,
                      attestation_tag="build-attestation"):
    """Injected D114 keyboard/terminal payload sites share one layout."""
    return Artifact(
        name=name,
        truth=Site(
            label="%s.artifact.payload[%s]" % (attestation_tag, component),
            path=attestation,
            kind="json",
            pointer=("artifact", "payload", component),
        ),
        sites=(
            Site(
                label="source-lock.runtime.component_sha256[%s]" % component,
                path=_P2_SOURCE_LOCK,
                kind="json",
                pointer=("runtime", "component_sha256", component),
            ),
            Site(
                label="source_lock.EXPECTED_RUNTIME.component_sha256[%s]"
                % component,
                path=_SOURCE_LOCK_PY,
                kind="python_const",
                const="EXPECTED_RUNTIME",
                selector=("component_sha256", component),
            ),
            Site(
                label="inject_rootfs_candidate.add_file[%s]" % component,
                path=_INJECT_SH,
                kind="regex",
                pattern=(
                    r'add_file\["'
                    + re.escape(component)
                    + r'"\]="'
                    + add_file_meta
                    + r"\|"
                    + _SHA256_HEX
                    + r'"'
                ),
            ),
            Site(
                label="inject_rootfs_candidate.verify_image_file[%s]"
                % component,
                path=_INJECT_SH,
                kind="regex",
                pattern=(
                    r"verify_image_file "
                    + re.escape(component)
                    + r" 755 "
                    + _SHA256_HEX
                ),
            ),
        )
        + session_sites,
    )


def _transient_payload_artifact(name, component):
    """One r2 transient payload, intentionally separate from frozen D114 r1."""
    return Artifact(
        name=name,
        truth=Site(
            label="build-attestation-r2.artifact.payload[%s]" % component,
            path=_BUILD_ATTESTATION_R2,
            kind="json",
            pointer=("artifact", "payload", component),
        ),
        sites=(
            Site(
                label="stage_transient.PAYLOAD[%s]" % component.lstrip("/"),
                path=_STAGE_TRANSIENT,
                kind="python_const",
                const="PAYLOAD",
                selector=(component.lstrip("/"), 1),
            ),
        ),
    )


REGISTRY = (
    Artifact(
        name="sixrow-clients-apk-frozen-d114-r1",
        truth=Site(
            label="build-attestation.artifact.sha256",
            path=_BUILD_ATTESTATION,
            kind="json",
            pointer=("artifact", "sha256"),
        ),
        sites=(
            Site(
                label="readiness-doc frozen r1 APK digest (prose)",
                path=_READINESS_DOC,
                kind="regex",
                pattern=(
                    r"`lmi-weston-sixrow-clients-14\.0\.2-r1\.apk`[^`]*"
                    r"SHA-256 `" + _SHA256_HEX + r"`"
                ),
                best_effort=True,
            ),
        ),
    ),
    # The r2-most-complete injection chain injects the canonically re-signed
    # r2 APK, whose identity is the r2 attestation's artifact.sha256; the
    # earlier NO-GO transient trial below keeps the pre-resign hash, which
    # the same attestation retains as source.resigned_from_sha256.
    Artifact(
        name="sixrow-clients-apk-injected-r2-resigned",
        truth=Site(
            label="build-attestation-r2.artifact.sha256",
            path=_BUILD_ATTESTATION_R2,
            kind="json",
            pointer=("artifact", "sha256"),
        ),
        sites=(
            Site(
                label="injection-policy-lock.input.apks.sixrow.sha256",
                path=_INJECTION_POLICY_LOCK,
                kind="json",
                pointer=("input", "apks", "sixrow", "sha256"),
            ),
            Site(
                label="inject_rootfs_candidate.SIXROW_APK_SHA256",
                path=_INJECT_SH,
                kind="shell_var",
                var="SIXROW_APK_SHA256",
            ),
        ),
    ),
    Artifact(
        name="sixrow-clients-apk-transient-r2",
        truth=Site(
            label="build-attestation-r2.source.resigned_from_sha256",
            path=_BUILD_ATTESTATION_R2,
            kind="json",
            pointer=("source", "resigned_from_sha256"),
        ),
        sites=(
            Site(
                label="transient-stage-lock.runtime_pins.candidate_apk_sha256",
                path=_TRANSIENT_STAGE_LOCK,
                kind="json",
                pointer=("runtime_pins", "candidate_apk_sha256"),
            ),
            Site(
                label="transient-stage-lock.remote_root (12-char prefix)",
                path=_TRANSIENT_STAGE_LOCK,
                kind="json",
                pointer=("remote_root",),
                value_pattern=r"-r2-([0-9a-f]{12})$",
                expected_transform="prefix:12",
            ),
            Site(
                label=(
                    "transient-stage-lock.trial_contract."
                    "allowed_write_roots[0] (12-char prefix)"
                ),
                path=_TRANSIENT_STAGE_LOCK,
                kind="json",
                pointer=("trial_contract", "allowed_write_roots", 0),
                value_pattern=r"-r2-([0-9a-f]{12})$",
                expected_transform="prefix:12",
            ),
            Site(
                label="stage_transient.EXPECTED_APK_SHA256",
                path=_STAGE_TRANSIENT,
                kind="python_const",
                const="EXPECTED_APK_SHA256",
            ),
            Site(
                label="stage_transient.REMOTE_ROOT (12-char prefix)",
                path=_STAGE_TRANSIENT,
                kind="python_const",
                const="REMOTE_ROOT",
                value_pattern=r"-r2-([0-9a-f]{12})$",
                expected_transform="prefix:12",
            ),
        ),
    ),
    # The injected keyboard binary follows the r2 attestation payload (the
    # r1 keyboard was superseded); the terminal binary is byte-identical in
    # r1 and r2, so its entry keeps the r1 attestation as truth.
    _payload_artifact(
        name="weston-keyboard-sixrow-binary-injected-r2",
        component=_KBD,
        add_file_meta=r"755\|134456",
        attestation=_BUILD_ATTESTATION_R2,
        attestation_tag="build-attestation-r2",
        session_sites=(
            Site(
                label="session-gate check_sha256/stop/wait[%s]" % _KBD,
                path=_SESSION,
                kind="regex",
                pattern=_session_path_digest(_KBD),
                min_count=1,
                exact_count=1,
            ),
            Site(
                label="session-gate process_sha256_valid[keyboard pid]",
                path=_SESSION,
                kind="regex",
                pattern=(
                    r'process_sha256_valid "\$keyboard(?:_identity)?_pid"'
                    r" \\\s*" + _SHA256_HEX
                ),
                min_count=2,
                exact_count=2,
            ),
        ),
    ),
    _transient_payload_artifact(
        name="weston-keyboard-sixrow-binary-transient-r2",
        component=_KBD,
    ),
    _payload_artifact(
        name="weston-terminal-sixrow-binary-frozen-d114-r1",
        component=_TERM,
        add_file_meta=r"755\|200960",
        session_sites=(
            Site(
                label="session-gate check_sha256/stop/wait[%s]" % _TERM,
                path=_SESSION,
                kind="regex",
                pattern=_session_path_digest(_TERM),
                min_count=3,
                exact_count=3,
            ),
        ),
    ),
    _transient_payload_artifact(
        name="weston-terminal-sixrow-binary-transient-r2",
        component=_TERM,
    ),
    Artifact(
        name="stock-weston-binary",
        truth=Site(
            label="source-lock.runtime.component_sha256[%s]" % _WESTON,
            path=_P2_SOURCE_LOCK,
            kind="json",
            pointer=("runtime", "component_sha256", _WESTON),
        ),
        sites=(
            Site(
                label="source_lock.EXPECTED_RUNTIME.component_sha256[%s]"
                % _WESTON,
                path=_SOURCE_LOCK_PY,
                kind="python_const",
                const="EXPECTED_RUNTIME",
                selector=("component_sha256", _WESTON),
            ),
            Site(
                label="stage_transient.STOCK_WESTON_SHA256",
                path=_STAGE_TRANSIENT,
                kind="python_const",
                const="STOCK_WESTON_SHA256",
            ),
            Site(
                label="session-gate check_sha256/stop/wait[%s]" % _WESTON,
                path=_SESSION,
                kind="regex",
                pattern=_session_path_digest(_WESTON),
                min_count=3,
                exact_count=3,
            ),
        ),
    ),
    Artifact(
        name="build-attestation-file-hash",
        truth=Site(
            label="sha256(%s)" % _BUILD_ATTESTATION_R2,
            path=_BUILD_ATTESTATION_R2,
            kind="file_sha256",
        ),
        sites=(
            Site(
                label="inject_rootfs_candidate.SIXROW_BUILD_ATTESTATION_SHA256",
                path=_INJECT_SH,
                kind="shell_var",
                var="SIXROW_BUILD_ATTESTATION_SHA256",
            ),
            Site(
                label=(
                    "injection-policy-lock.input.apks.sixrow."
                    "build_attestation_sha256"
                ),
                path=_INJECTION_POLICY_LOCK,
                kind="json",
                pointer=(
                    "input",
                    "apks",
                    "sixrow",
                    "build_attestation_sha256",
                ),
            ),
        ),
    ),
    Artifact(
        name="candidate-rebuild-lock-file-hash",
        truth=Site(
            label="sha256(%s)" % _CANDIDATE_REBUILD_LOCK,
            path=_CANDIDATE_REBUILD_LOCK,
            kind="file_sha256",
        ),
        sites=(
            Site(
                label="inject_rootfs_candidate.REBUILD_LOCK_SHA256",
                path=_INJECT_SH,
                kind="shell_var",
                var="REBUILD_LOCK_SHA256",
            ),
            Site(
                label="injection-policy-lock.candidate_rebuild_lock_sha256",
                path=_INJECTION_POLICY_LOCK,
                kind="regex",
                pattern=(
                    r'"candidate_rebuild_lock_sha256": "'
                    + _SHA256_HEX
                    + r'"'
                ),
            ),
        ),
    ),
    Artifact(
        name="p2-source-lock-file-hash",
        truth=Site(
            label="sha256(%s)" % _P2_SOURCE_LOCK,
            path=_P2_SOURCE_LOCK,
            kind="file_sha256",
        ),
        sites=(
            Site(
                label="assemble_userdata_image.SOURCE_LOCK_SHA256",
                path=_ASSEMBLE_PY,
                kind="python_const",
                const="SOURCE_LOCK_SHA256",
            ),
            Site(
                label="deploy_userdata.SOURCE_LOCK_SHA256",
                path=_DEPLOY_PY,
                kind="python_const",
                const="SOURCE_LOCK_SHA256",
            ),
        ),
    ),
    Artifact(
        name="injection-policy-lock-file-hash",
        truth=Site(
            label="sha256(%s)" % _INJECTION_POLICY_LOCK,
            path=_INJECTION_POLICY_LOCK,
            kind="file_sha256",
        ),
        sites=(
            Site(
                label="assemble_userdata_image.INJECTION_POLICY_LOCK_SHA256",
                path=_ASSEMBLE_PY,
                kind="python_const",
                const="INJECTION_POLICY_LOCK_SHA256",
            ),
        ),
    ),
    Artifact(
        name="deploy-userdata-helper-file-hash",
        truth=Site(
            label="sha256(%s)" % _HELPER_PS1,
            path=_HELPER_PS1,
            kind="file_sha256",
        ),
        sites=(
            Site(
                label="deploy_userdata.HELPER_SHA256",
                path=_DEPLOY_PY,
                kind="python_const",
                const="HELPER_SHA256",
            ),
        ),
    ),
    Artifact(
        name="rootfs-injector-file-hash",
        truth=Site(
            label="sha256(%s)" % _INJECT_SH,
            path=_INJECT_SH,
            kind="file_sha256",
        ),
        sites=(
            Site(
                label="launch_inject_rootfs_candidate.INJECTOR_SHA256",
                path=_LAUNCH_SH,
                kind="shell_var",
                var="INJECTOR_SHA256",
            ),
        ),
    ),
    Artifact(
        name="known-good-kernel-apk-sha256",
        truth=Site(
            label="p1-source-lock.known_good_kernel_package.artifact.sha256",
            path=_P1_SOURCE_LOCK,
            kind="json",
            pointer=("known_good_kernel_package", "artifact", "sha256"),
        ),
        sites=(
            Site(
                label="59_release_static_ci.known_good_kernel_apk_sha256",
                path=_STATIC_CI,
                kind="shell_var",
                var="known_good_kernel_apk_sha256",
            ),
            Site(
                label="lmi_p1.build._KNOWN_GOOD_APK_SHA256",
                path=_BUILD_PY,
                kind="python_const",
                const="_KNOWN_GOOD_APK_SHA256",
            ),
            Site(
                label="test_known_good_kernel packaged-apk digest assert",
                path=_KERNEL_TEST,
                kind="regex",
                pattern=(
                    r"sha256_file\(package\),\s*\"" + _SHA256_HEX + r"\""
                ),
            ),
            Site(
                label="kernel-package-doc digest table row (prose)",
                path=_KERNEL_DOC,
                kind="regex",
                pattern=(
                    r"\| `linux-xiaomi-lmi-4\.19\.325-r8-p1-known-good"
                    r"\.apk` \| [0-9,]+ \| `" + _SHA256_HEX + r"`"
                ),
                best_effort=True,
            ),
        ),
    ),
    Artifact(
        name="known-good-kernel-apk-size",
        truth=Site(
            label="p1-source-lock.known_good_kernel_package.artifact.size",
            path=_P1_SOURCE_LOCK,
            kind="json",
            pointer=("known_good_kernel_package", "artifact", "size"),
        ),
        sites=(
            Site(
                label="59_release_static_ci.known_good_kernel_apk_size",
                path=_STATIC_CI,
                kind="shell_var",
                var="known_good_kernel_apk_size",
                expected_transform="int",
            ),
            Site(
                label="lmi_p1.build._KNOWN_GOOD_APK_SIZE",
                path=_BUILD_PY,
                kind="python_const",
                const="_KNOWN_GOOD_APK_SIZE",
                expected_transform="int",
            ),
            Site(
                label="kernel-package-doc size table cell (prose)",
                path=_KERNEL_DOC,
                kind="regex",
                pattern=(
                    r"\| `linux-xiaomi-lmi-4\.19\.325-r8-p1-known-good"
                    r"\.apk` \| ([0-9,]+) \|"
                ),
                expected_transform="int",
                best_effort=True,
            ),
        ),
    ),
)


def _print_report(findings, stream):
    counts = {"OK": 0, "MISMATCH": 0, "UNREADABLE": 0, "WARN": 0}
    for finding in findings:
        counts[finding.status] = counts.get(finding.status, 0) + 1
        stream.write(
            "%-10s %s :: %s (%s)\n      %s\n"
            % (
                finding.status,
                finding.artifact,
                finding.site_label,
                finding.path,
                finding.detail,
            )
        )
    stream.write(
        "pin registry: %d ok, %d mismatched, %d unreadable, %d warned\n"
        % (
            counts["OK"],
            counts["MISMATCH"],
            counts["UNREADABLE"],
            counts["WARN"],
        )
    )


def cmd_verify(root, stream=None):
    stream = stream if stream is not None else sys.stdout
    findings = verify_registry(root, REGISTRY)
    failures = [finding for finding in findings if finding.fatal]
    if failures:
        stream.write(
            "release pin cross-check FAILED; every listed site must carry "
            "the same pin as its declared truth (this list is the re-pin "
            "checklist):\n"
        )
        _print_report(failures, stream)
        return 1
    _print_report(findings, stream)
    return 0


def cmd_list(root, stream=None):
    stream = stream if stream is not None else sys.stdout
    for artifact in REGISTRY:
        stream.write(
            "%s\n  truth: %s (%s)\n"
            % (artifact.name, artifact.truth.label, artifact.truth.path)
        )
        for site in artifact.sites:
            stream.write("  site:  %s (%s)\n" % (site.label, site.path))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="lmi_release_pins.py",
        description="Cross-check hand-copied release pins (read-only).",
    )
    parser.add_argument(
        "command",
        choices=("verify", "list"),
        help="verify: cross-check all pin sites; list: print the registry",
    )
    parser.add_argument(
        "--root",
        default=str(pathlib.Path(__file__).resolve().parents[1]),
        help="repository root (default: parent of scripts/)",
    )
    arguments = parser.parse_args(argv)
    root = pathlib.Path(arguments.root)
    if not root.is_dir():
        print(
            "lmi_release_pins: root is not a directory: %s" % root,
            file=sys.stderr,
        )
        return 2
    if arguments.command == "list":
        return cmd_list(root)
    return cmd_verify(root)


if __name__ == "__main__":
    sys.exit(main())
