# bringup-claims — append-only claims ledger

`claims.log` is written only by `scripts/bringup_loop.py claim`, one
`key=value` line per consumed receipt, under an exclusive file lock. It is
the permanent audit trail of every governed device action.

Rules:

- Append-only. Never rewrite, reorder, or clean existing lines.
- The repeat guard reads this ledger to detect that a physical action
  (operation, target, artifact_sha256) has already been executed.
- `.lock` is the advisory lock file used by the engine; it carries no data.
