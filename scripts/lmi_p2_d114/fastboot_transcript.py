#!/usr/bin/env python3
"""One shared, fail-closed grammar for fastboot transcripts on the lmi route.

Every host-side judgement about what fastboot printed — the flash transport
ladder, ``devices`` enumeration, and ``getvar`` responses — lives here so the
WSL and Windows deployment gates cannot drift apart line-shape by line-shape
(the r3 trailing blank line, the r4 partition-size leading space, and the r5
non-sparse ``Sending 'userdata'`` false negative were all such drifts).

``classify`` maps a captured flash transcript to exactly one of three
outcomes with a machine-readable reason:

* ``COMPLETED`` — the transcript is a full Sending/Writing ladder in which
  every transfer and every write reported ``OKAY`` and exactly one
  ``Finished. Total time:`` footer closes the output.  Both the sparse
  chunked form (``Sending sparse 'userdata' N/M (K KB)``) and the single
  non-sparse transfer (``Sending 'userdata' (K KB)``) that real fastboot
  emits when the payload fits under max-download-size are accepted.
* ``REFUSED`` — the device rejected the very first transfer before any
  ``Writing`` line, so no partition byte can have changed.
* ``UNKNOWN`` — anything else.  This grammar decides whether a persistent
  flash of a physical phone completed; when the evidence is ambiguous the
  only safe answer is "unknown", never "completed" and never "refused".

Tolerated formatting variance is limited to what real platform-tools emit:
``\\r\\n`` line endings, trailing whitespace, trailing blank lines, and
interleaved ``(bootloader)`` INFO lines.  Any other unrecognized line makes
the whole transcript ``UNKNOWN``.

This module is stdlib-only, imports nothing from the deployment gates, and
never talks to a device.
"""

from __future__ import annotations

from dataclasses import dataclass
import enum
import re


FINISHED_LINE_PATTERN = r"Finished\. Total time: [0-9]+(?:\.[0-9]+)?s"
DEVICES_PATTERN = (
    r"([A-Za-z0-9._:-]{1,128})"
    r"(?:\tfastboot(?:\n|\r\n)|\t fastboot(?:\n\n|\r\n\r\n))"
)

_PARTITION_RE = re.compile(r"[a-z][a-z0-9_-]{0,35}")
_FINISHED_RE = re.compile(FINISHED_LINE_PATTERN)
_DEVICES_RE = re.compile(DEVICES_PATTERN)
_BOOTLOADER_INFO_RE = re.compile(r"\(bootloader\)(?: [^\r\n]*)?")
_CLIENT_ERROR_RE = re.compile(r"fastboot: error: [^\r\n]+")
_OKAY_STATUS = r"OKAY \[[ ]*[0-9]+(?:\.[0-9]+)?s\]"
_FAILED_STATUS = r"FAILED \(remote: '[^'\r\n]*'\)"
_STATUS = rf"(?:(?P<okay>{_OKAY_STATUS})|(?P<failed>{_FAILED_STATUS}))"


class Outcome(enum.Enum):
    COMPLETED = "COMPLETED"
    REFUSED = "REFUSED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class Classification:
    outcome: Outcome
    reason: str


def _unknown(reason: str) -> Classification:
    return Classification(Outcome.UNKNOWN, reason)


def _partition_pattern(partition: str) -> str:
    if _PARTITION_RE.fullmatch(partition) is None:
        raise ValueError("partition name is not a strict lowercase identifier")
    return re.escape(partition)


def finished_footer_pattern() -> str:
    """The footer subpattern used inside larger ``fullmatch`` grammars."""

    return FINISHED_LINE_PATTERN + r"\r?\n?"


def sending_pattern(partition: str) -> re.Pattern[str]:
    """One transfer line: sparse chunk N/M or a single non-sparse payload."""

    name = _partition_pattern(partition)
    return re.compile(
        rf"Sending (?P<sparse>sparse )?'{name}'"
        rf"(?: (?P<index>[0-9]+)/(?P<total>[0-9]+))? \([0-9]+ KB\)"
        rf"[ .]*{_STATUS}"
    )


def writing_pattern(partition: str) -> re.Pattern[str]:
    name = _partition_pattern(partition)
    return re.compile(rf"Writing '{name}'[ .]*{_STATUS}")


def parse_devices(text: str) -> str | None:
    """Return the serial of exactly one bootloader-mode device, else None."""

    match = _DEVICES_RE.fullmatch(text)
    return None if match is None else match.group(1)


def getvar_success_pattern(name: str) -> str:
    return (
        rf"(?:\(bootloader\) )?{re.escape(name)}: ([^\r\n]+)\r?\n"
        + finished_footer_pattern()
    )


def getvar_unsupported_pattern(name: str) -> str:
    return (
        rf"getvar:{re.escape(name)}[ \t]+FAILED"
        rf" \(remote: 'GetVar Variable Not found'\)\r?\n"
        + finished_footer_pattern()
    )


def parse_getvar(
    name: str, text: str, *, allow_unsupported: bool = False
) -> tuple[str | None, bool] | None:
    """Parse one exact getvar response; None when the shape does not match."""

    success = re.fullmatch(getvar_success_pattern(name), text)
    if success is not None:
        return success.group(1), False
    if allow_unsupported and re.fullmatch(getvar_unsupported_pattern(name), text) is not None:
        return None, True
    return None


def _significant_lines(text: str) -> list[str]:
    lines = []
    for raw in text.split("\n"):
        line = raw.rstrip(" \t\r")
        if line:
            lines.append(line)
    return lines


def classify(stdout: bytes, stderr: bytes, *, partition: str = "userdata") -> Classification:
    """Classify one captured flash transcript, conservatively.

    ``stdout``/``stderr`` are the raw captured bytes of the fastboot flash
    process.  Real fastboot keeps stdout empty and prints the transport
    ladder on stderr; any deviation is ``UNKNOWN``.
    """

    sending = sending_pattern(partition)
    writing = writing_pattern(partition)
    if stdout != b"":
        return _unknown("STDOUT_NOT_EMPTY")
    try:
        text = stderr.decode("ascii")
    except UnicodeDecodeError:
        return _unknown("TRANSCRIPT_NOT_ASCII")
    lines = _significant_lines(text)
    if not lines:
        return _unknown("TRANSCRIPT_EMPTY")
    sendings: list[re.Match[str]] = []
    ladder: list[str] = []
    failed = False
    client_errors = 0
    footers = 0
    for line in lines:
        if _FINISHED_RE.fullmatch(line) is not None:
            footers += 1
            continue
        if footers:
            # Nothing but trailing whitespace may follow the footer.
            return _unknown("FINISHED_FOOTER_NOT_FINAL")
        if _BOOTLOADER_INFO_RE.fullmatch(line) is not None:
            continue
        match = sending.fullmatch(line)
        if match is not None:
            sendings.append(match)
            ladder.append("S")
            failed = failed or match.group("failed") is not None
            continue
        match = writing.fullmatch(line)
        if match is not None:
            ladder.append("W")
            failed = failed or match.group("failed") is not None
            continue
        if _CLIENT_ERROR_RE.fullmatch(line) is not None:
            client_errors += 1
            continue
        return _unknown("UNRECOGNIZED_TRANSCRIPT_LINE")
    if failed or client_errors:
        # A definite refusal is exactly one FAILED transfer with no Writing
        # line (so no partition byte can have changed) and at most the
        # client's own error echo.  Everything else stays UNKNOWN.
        if (
            ladder == ["S"]
            and len(sendings) == 1
            and sendings[0].group("failed") is not None
            and client_errors <= 1
        ):
            return Classification(Outcome.REFUSED, "DEVICE_REFUSED_BEFORE_FIRST_WRITE")
        return _unknown("TRANSPORT_FAILED_AFTER_TRANSFER_STARTED")
    if footers == 0:
        return _unknown("FINISHED_FOOTER_MISSING")
    if footers > 1:
        return _unknown("FINISHED_FOOTER_REPEATED")
    if (
        len(ladder) < 2
        or len(ladder) % 2
        or any(ladder[index] != ("S" if index % 2 == 0 else "W") for index in range(len(ladder)))
    ):
        return _unknown("TRANSPORT_LADDER_SHAPE_MISMATCH")
    sparse_flags = {match.group("sparse") is not None for match in sendings}
    if len(sparse_flags) != 1:
        return _unknown("MIXED_SPARSE_AND_RAW_SENDING")
    fractions = [(match.group("index"), match.group("total")) for match in sendings]
    reason = (
        "SPARSE_TRANSPORT_LADDER_COMPLETE"
        if sparse_flags.pop()
        else "RAW_TRANSPORT_LADDER_COMPLETE"
    )
    if all(index is None and total is None for index, total in fractions):
        if len(sendings) != 1:
            return _unknown("UNNUMBERED_SENDING_REPEATED")
        return Classification(Outcome.COMPLETED, reason)
    if any(index is None or total is None for index, total in fractions):
        return _unknown("SPARSE_FRACTION_INCOMPLETE")
    totals = {int(total) for _index, total in fractions if total is not None}
    if len(totals) != 1:
        return _unknown("SPARSE_FRACTION_INCOMPLETE")
    total = totals.pop()
    if total != len(sendings) or [
        int(index) for index, _total in fractions if index is not None
    ] != list(range(1, total + 1)):
        return _unknown("SPARSE_FRACTION_INCOMPLETE")
    return Classification(Outcome.COMPLETED, reason)
