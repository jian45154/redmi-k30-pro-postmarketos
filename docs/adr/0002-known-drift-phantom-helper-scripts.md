# ADR 0002 — Known drift: five cited helper scripts have never existed

Status: **Proposed** (decision belongs to the owner, ian)
Date: 2026-07-29
Related: ADR 0001 (documentation/reality drift is the shared failure mode)

## Context

Current documentation cites five `scripts/` helpers that are absent from the
working tree **and from the entire git history** (no commit has ever added
them; the numbered scripts end at `74`):

| Cited script | Cited at |
| --- | --- |
| `scripts/87_redact_downstream_hardware_log.sh` | `AGENTS.md:71`, `README.md:200`, `docs/open-source-release-audit-2026-07-22.md:45` |
| `scripts/86_generate_downstream_hardware_window_runbook.sh` | `README.md:198` |
| `scripts/85_audit_downstream_priority_status.sh` | `README.md:197` |
| `scripts/84_audit_downstream_p2_audio_bt_readiness.sh` | `README.md:207` |
| `scripts/77_probe_downstream_p2_audio_bt.sh` | `README.md:208` |

The most serious is `87`: `AGENTS.md`'s data-hygiene section names it as
**the** procedure that produces the only committable form of hardware logs
(`logs/*.redacted.txt`), and the open-source release audit relies on it as
the mitigation for serials, CPU IDs, bootloader tokens, and MACs in raw
logs. A contributor following the documented procedure hits a missing tool
at exactly the moment they are holding sensitive data; the failure mode is
improvising redaction by hand or committing a raw log.

## Decision (proposed)

Treat `87` as a real gap, not a doc typo: either write the redaction script
to match its documented contract, or replace the three citations with the
actual manual redaction checklist (what fields to strip, verified how).
Until one of those happens, `AGENTS.md` should say the redaction is manual.
For `77`/`84`/`85`/`86`, `README.md`'s "Current hardware focus" section
should either drop the phantom names or mark them as planned-but-unwritten;
they read today as runnable procedure.

## Consequences

- The data-hygiene procedure becomes executable as written, closing a
  real leak path for device-identifying data.
- `README.md` stops directing readers at tooling that cannot be run,
  which also keeps automated agents from "helpfully" inventing these
  scripts to make the documentation true.
