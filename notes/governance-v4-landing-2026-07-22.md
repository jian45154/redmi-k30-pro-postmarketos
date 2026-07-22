# Bringup governance v4 — landing record (2026-07-22)

Owner (ian) directed landing of the governance baseline on 2026-07-22 after
the same-day evaluation of the "Bringup Governance v4" design draft. This
note records what landed, how the design was adapted to this repository's
real state, and what is deliberately deferred.

## What landed

- `config/governance/constants.json` — single source for battery floor,
  receipt TTL, partition targets, operation tiers, forbidden command words.
  The engine keeps a hardcoded copy of the forbidden set and refuses to run
  if the data file diverges (the only permitted double-write).
- `config/governance/policy.json` — schema-validated policy (no byte-exact
  code binding). Standing scopes: volatile (`device_reboot`) and ram_rw
  (`ram_boot`, `runtime_handoff`). `authorized_profiles` is empty: no
  persistent write is authorized by this landing.
- `scripts/bringup_loop.py` — L3 engine: `new` (auto-computes all hashes) /
  `validate` / `approve` (dry-run) / `claim` (atomic issue-and-claim under
  the ledger lock) / `result` / `observe` / `archive`. Single receipt,
  single `action_digest`, append-only ledger `notes/bringup-claims/claims.log`,
  frozen archive `notes/bringup-completed/`. One structural validator shared
  by every subcommand (the `_open_spec` split-validator failure mode from
  `notes/lmi-d114-wsl-deploy-refusal-2026-07-22.md` is structurally excluded).
- `tests/governance/test_bringup_loop.py` — 27 host tests; wired into
  `scripts/59_release_static_ci.sh`.
- `scripts/65_lmi_release_safety_lint.sh` — rewritten: literal-line pinning
  replaced by an enumerated fastboot invoker set plus the existing forbidden
  pattern scans, plus governance data validation.
- `AGENTS.md` — hardware governance and workflow-gate sections rewritten to
  the v4 tier model; data hygiene, multi-agent, routing, conventions kept.

## Adaptations from the design draft (per the 2026-07-22 evaluation)

1. **Tier model corrected for lmi.** The draft classed `ram_boot` and
   `runtime_handoff` as volatile ("nothing persists"). On lmi the rootfs
   lives inside `userdata` and a RAM-booted OS mounts it read-write, so these
   operations form a distinct `ram_rw` tier whose claims require a
   persistent-media acknowledgment (`--acknowledge-persistent-media` +
   `--rebuild-reference`). Bare `fastboot reboot` remains the only volatile
   operation.
2. **Persistent tier is never standing.** The draft put `partition_write`
   into standing scopes; given this project's history (M-r6/r7 non-booting
   writes, the D114 dirty-kernel baseline) every partition write requires a
   hash-bound `authorized_profiles` entry: owner authorizes a specific
   profile file (by SHA-256) for specific targets. The engine also rejects
   any policy file that lists a persistent operation as a standing scope.
3. **Migration re-baselined to the real repository.** The draft's "v3"
   (bringup engine, 8 deploy.ps1 copies, 22 retired stubs, 60+ SSH probe
   preambles) does not exist here. What actually exists and remains to be
   converged is listed under "Deferred" below.

## Coexistence / transition

Pre-v4 guarded flows keep their own gates until wired to the engine:

- D110 RAM-boot session flow: `scripts/72_stage_downstream_ssh_wifi_test.sh`
  (`docs/lmi-d110-session-approval.md`), still enforced by 59 CI contracts.
- D114 userdata deploy gates: `scripts/lmi_p2_d114/deploy_userdata_wsl.py`
  and the Windows variant, still bound by their policy locks.

The engine governs newly defined actions from day one; no fastboot state
change may happen outside the allowlisted executors or an engine-claimed
`exact_command` (lint check 1).

## Deferred (in order)

- **M2′ deployer convergence**: merge `deploy_userdata.py` (3118 lines) and
  `deploy_userdata_wsl.py` (2014 lines) into one shared validation core with
  platform shims, driven by `profiles/*.json`; wire its execute path to
  engine claims; then delete the retired r6 stage scripts (53/55/60/61 and
  the generators that reference them) and shrink the lint invoker set.
- **M3′ probe boilerplate**: extract the `section()`/`run()`/`grep_dmesg()`
  helpers duplicated across 9 on-device probe scripts (the draft's "SSH
  preamble" premise was wrong — probes run on-device).
- **Constant convergence**: point the 8 hardcoded battery-floor sites and
  10+ identity sites at `config/governance/constants.json` as their owning
  modules are next touched (not retrofitted into hash-locked deployers now,
  since editing them would invalidate their policy-lock bindings).
- **M4 SSH `reboot-bootloader` executor**: prerequisites unchanged from the
  draft; would remove the last routine physical touchpoint.

## Acceptance evidence

- `python3 -m unittest discover -s tests/governance` — 27 tests, all pass.
- `bash scripts/65_lmi_release_safety_lint.sh` — OK (invoker set, forbidden
  patterns, governance validation).
- `python3 scripts/bringup_loop.py validate` — "safe idle state" with no
  active record.
- Volatile record top-level field count: 16 (draft acceptance: ≤ 16).
