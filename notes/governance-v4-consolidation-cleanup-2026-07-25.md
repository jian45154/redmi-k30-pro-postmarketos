# Governance v4 consolidation cleanup (2026-07-25)

Status: **host-side cleanup only; no experiment, claim, executor, or device
action ran.**

## Sole authority

The active project-governance path is:

```text
AGENTS.md
  -> scripts/bringup_loop.py
  -> config/governance/{constants,policy}.json
  -> one-shot claim and external executor
  -> result and immutable evidence
```

`authorize-profile` is the only owner-facing persistent-profile authorization
entry point. The ambiguous v4 dry-run name `approve` was removed; its
non-mutating function is now named `preflight`.

## Removed retired routes

The complete M-r6/M-r7 fastbootd execution and command-generation chain was
deleted:

- scripts 48 through 58 in that historical route;
- retired state-change stages 60 and 61;
- release refresh/status/readiness helpers 62 through 64;
- fastbootd wait/audit and post-boot summary helpers 66 and 67.

The exact deleted filenames remain visible in Git history and in archived
result documents, which are explicitly marked non-runnable. The safety lint
now rejects any reappearance of all 18 retired helper paths. Its shell
allowlist contains only:

- `scripts/72_stage_downstream_ssh_wifi_test.sh`, the still-live guarded D110
  executor;
- `scripts/59_release_static_ci.sh` and
  `scripts/65_lmi_release_safety_lint.sh`, which only inspect command text.

The lint separately enumerates the four retained D114 Python/PowerShell files
that contain the frozen `flash userdata` contract and verifies the two exact
executor boundaries. Their hash-lock graph and host tests remain authoritative
until the transition executors consume v4 claims.

The duplicate `docs/release/edge-release-checks.workflow.yml` template was
also deleted. `.github/workflows/edge-release-checks.yml` is the single
installed CI workflow.

## Historical evidence retained

Historical result documents were not deleted because they record real writes,
failures, outcomes, and rollback facts. Notes that still contain literal old
commands now begin with an archived-evidence warning. The imported mainline
device README no longer contains its upstream flash recipe.

The old LangGraph contract remains only as a clearly superseded historical
record under `notes/`; it is not read by tooling and is not an active
governance entry point.

## Deliberately retained transition executors

Two guarded implementations remain temporarily:

- D110 RAM boot: `scripts/72_stage_downstream_ssh_wifi_test.sh`;
- D114 userdata: `scripts/lmi_p2_d114/` plus its hash-bound config graph.

They are not alternative project authorities. They remain because they are
currently the only live device-gated executors. Removing their gates before
their execute paths consume governance-v4 claims would create either an
unguarded command path or an authorization engine with no controlled
executor.

The final convergence order is:

1. wire the D114 shared execute core to an engine-claimed `exact_command`;
2. wire the D110 device gate to the same claim contract;
3. only then remove the transition-specific session/policy-lock graphs.

All deletions in this cleanup are recoverable from Git history.
