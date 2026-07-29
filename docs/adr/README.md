# Architecture Decision Records

An ADR records one architectural decision: the context that forced a choice,
the options that were genuinely on the table, the decision, and its expected
consequences — so a future reader does not have to reconstruct "why is it this
way" from git archaeology. Files are numbered sequentially
(`0001-slug.md`, `0002-slug.md`, …); to add one, take the highest existing
number plus one and never renumber old records. Each record carries a
`Status` line with the lifecycle `Proposed → Accepted` (or `Rejected`), and
later `Deprecated` or `Superseded by ADR-NNNN` when a newer record replaces
it; a `Proposed` record is a decision *offered to the owner*, not yet policy,
and only the repository owner moves a record to `Accepted`. Accepted records
are immutable history — if the decision changes, write a new ADR that
supersedes the old one instead of editing it.
