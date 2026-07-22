# AGENTS.md — Xiaomi `lmi` postmarketOS port

Guidance for any coding agent working in this repository, regardless of vendor
or harness. This file supersedes the former vendor-specific governance files
(`PROJECT_LANGGRAPH.md`, `.codex/AGENTS.md`); the original LangGraph workflow
contract is archived at
[`notes/archive-project-langgraph-2026-05-28.md`](notes/archive-project-langgraph-2026-05-28.md).

## Project snapshot

- Goal: run postmarketOS natively on the Redmi K30 Pro / POCO F2 Pro
  (`lmi`, Qualcomm SM8250), built from WSL2 with `pmbootstrap`.
- Two version tracks: downstream `D-vNN` (LineageOS 4.19 kernel, the working
  baseline) and mainline/copydown `M-rNN` (not boot-verified).
- Start with [`README.md`](README.md), then
  [`docs/tracks/README.md`](docs/tracks/README.md) for version-label rules and
  file placement.

## Hardware-test governance (v4)

The bringup governance engine (`scripts/bringup_loop.py`) is the authority
for device-affecting actions; this section states intent and does not restate
the engine's rules.

- At most one active experiment: `notes/bringup-active.json`; absence of that
  file is the safe idle state. `python3 scripts/bringup_loop.py validate`
  rules on record and policy validity.
- Actions are tiered by the irreversibility of their **consequences**, not by
  whether the command itself writes:
  - `read_only` — probes and log capture; no approval, no receipt.
  - `volatile` — bare `fastboot reboot`; standing scope in
    `config/governance/policy.json`, one-shot receipt + claim + executor
    device gate.
  - `ram_rw` — RAM-only `fastboot boot` and runtime handoff. The command
    writes no partition, but on lmi the rootfs lives inside `userdata` and
    the booted OS mounts it read-write, so a claim additionally requires a
    persistent-media acknowledgment naming how userdata would be rebuilt.
  - `persistent` — partition writes (`boot`, `userdata`, `dtbo`, `vbmeta`).
    Never standing: every write requires a hash-bound `authorized_profiles`
    entry approved by the owner (ian) for that specific profile, plus a
    distinct-hash rollback artifact, a repeat guard on re-writes, and
    post-write verification.
- `erase`, `format`, repartition, `set_active`, `--force`, and
  verity-disable flags are permanently refused; the forbidden set is
  hardcoded in the engine and no data file can widen it. Bootloader relock
  stays manual-only with no executor; never relock while non-stock images or
  partitions are present.
- One state change per experiment. After a claim consumes its receipt, no
  outcome permits an automatic retry; running again means a new experiment
  and a new receipt. The claims ledger `notes/bringup-claims/` is
  append-only and is never cleaned.
- Prefer, in order: read-only probes → host-side rebuilds verified without
  the device → the smallest reversible device step.
- Stop and report when device identity, partition target, image provenance,
  battery state, or rollback path is uncertain.
- Historical checklists (e.g. the mainline r6 documents) are evidence, not
  runnable procedures. Any future device write requires a fresh reviewed plan.
- Transition note: pre-v4 guarded flows keep their own gates until wired to
  the engine — the D110 RAM-boot session flow
  (`scripts/72_stage_downstream_ssh_wifi_test.sh`,
  `docs/lmi-d110-session-approval.md`) and the D114 userdata deploy gates
  (`scripts/lmi_p2_d114/`). No fastboot state change may happen outside
  those executors or an engine-claimed `exact_command`;
  `scripts/65_lmi_release_safety_lint.sh` enforces the invoker set.

## Data hygiene

- Raw device logs contain serial numbers, CPU IDs, bootloader tokens, and MAC
  addresses. They are gitignored; commit only redacted logs
  (`logs/*.redacted.txt`), produced with
  `scripts/87_redact_downstream_hardware_log.sh`.
- Never commit boot/rootfs images, stock/recovery binaries, or rejected flash
  candidates; `artifacts/images/` holds manifests and hashes only.
- `private/` and `.work/` are local-only and must stay out of git.

## Workflow gates

Every device-affecting change moves through these gates in order:

1. **Evidence inventory** — collect current repo/device facts; separate
   observed facts from inference.
2. **Host-side build and static verification** — package builds, image
   inspection, and the host test suites under `tests/`;
   `scripts/59_release_static_ci.sh` runs the static release checks.
3. **Authorization gate** — resolved by tier: volatile/ram_rw actions claim
   against the standing scopes the owner established in
   `config/governance/policy.json`; persistent writes additionally need a
   hash-bound per-profile authorization from the owner. The standing
   authorization itself (its creation and revocation) is always a human act.
4. **Smallest reversible device step** — RAM-only boot before any persistent
   write; one claim per state change; verify before the next step.
5. **Record results** — evidence bound via
   `python3 scripts/bringup_loop.py result`, then archived; exact commands,
   hashes, package revisions, redacted logs, and rollback status as dated
   notes under `notes/`.

## Multi-agent rules

When work is split across parallel agents or lanes (lane definitions:
[`docs/hardware-enablement-subagents.md`](docs/hardware-enablement-subagents.md)):

- one bounded task per agent at a time; an agent never reverts another lane's
  work;
- read-only lanes stay read-only; write access is granted per file, per task;
- never claim hardware works from device-node presence alone; success requires
  observed behavior (panel output, scan results, real ALSA cards, …);
- the coordinator (main thread) reviews agent output before packages or
  scripts change, and keeps commits small and tied to one hypothesis;
- change one hardware hypothesis at a time.

## Task routing

Route by task risk, not by vendor model names:

| Task type | Reasoning effort |
| --- | --- |
| Routine scripts, tests, documentation | standard |
| Mechanical formatting or test updates | low |
| Boot-chain, partition, or flash-safety review | highest available |
| Kernel crash, display, or QDSP6 deep debugging | highest available |
| Parallelizable research or static review | high, fanned out across agents |

## Conventions

- Version labels: downstream `D-vNN`, mainline `M-rNN`; rules in
  [`docs/tracks/README.md`](docs/tracks/README.md).
- Dated evidence notes live under `notes/` as `<topic>-YYYY-MM-DD.md`.
- Reusable skills use the generic Agent Skills format
  (`.agents/skills/<name>/SKILL.md` plus `references/`), with no
  vendor-specific adapters.
- Chinese and English documentation are both welcome; keep root-level
  governance files in English.
