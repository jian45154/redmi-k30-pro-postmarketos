# bringup-completed — frozen experiment archive

`scripts/bringup_loop.py archive` moves each completed experiment record
here as `<experiment_id>.json`. Archived records are frozen evidence:

- The schema validation performed at archive time is final; the current
  validator is never re-run against archived records (frozen history).
- An archive destination must not already exist; records are never
  overwritten or deleted.
- The repeat guard requires the prior experiment referenced by a re-write
  to be present in this directory.
