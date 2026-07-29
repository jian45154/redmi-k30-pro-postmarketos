# bringup-claims — append-only claims ledger

`claims.log` is written only by `scripts/bringup_loop.py claim`, one
`key=value` line per consumed receipt, under an exclusive file lock. It is
the permanent audit trail of every governed device action.

Each claim also creates
`notes/bringup-claims/<experiment_id>.claim-guard.json` before the ledger or
active record is changed. The guard is a durable per-experiment replay barrier:
if a host failure splits the multi-file update, the same experiment must stop
for manual audit and can never print or issue its command again.

Rules:

- Append-only. Never rewrite, reorder, or clean existing lines.
- Claim guards are append-only evidence too. Never remove or replace them.
- The repeat guard reads this ledger to detect that a physical action
  (operation, target, artifact_sha256) has already been executed.
- `.lock` is the advisory lock file used by the engine; it carries no data.
