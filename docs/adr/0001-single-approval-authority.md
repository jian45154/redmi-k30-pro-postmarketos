# ADR 0001 — One approval authority for device-affecting actions

Status: **Proposed** (decision belongs to the owner, ian)
Date: 2026-07-29
Deciders: owner
Related: `notes/governance-v4-landing-2026-07-22.md`, `AGENTS.md`,
`docs/lmi-d110-session-approval.md`, ADR 0002 (documentation drift)

## Context

`AGENTS.md` (lines 21–23) and `README.md` (lines 93–100) name the bringup
governance engine `scripts/bringup_loop.py` as "the authority for
device-affecting actions". As of the commit this ADR is written against
(`2cb20cf`), the observable state is:

- **The engine is wired in name only.** It is 946 lines (schema v4) with
  verbs `validate` / `new` / `approve` / `claim` / `result` / `observe` /
  `archive`, backed by a 533-line test suite
  (`tests/governance/test_bringup_loop.py`, 27 tests). The only production
  caller of any verb is `scripts/65_lmi_release_safety_lint.sh` line 100,
  which runs `validate`. No executor calls `new`, `claim`, or `result`.
  The claims ledger `notes/bringup-claims/` contains only its `README.md`;
  `config/governance/policy.json` has `authorized_profiles: []`; no profile
  file or `profiles/` directory exists.

- **Three parallel approval machines coexist:**

  1. **The engine** — tiers `read_only` / `volatile` / `ram_rw` /
     `persistent`, standing scopes in `config/governance/policy.json`,
     one-shot receipts (TTL 900 s from
     `config/governance/constants.json`), an append-only claims ledger, a
     hardcoded forbidden-command set, and hash-bound per-profile owner
     authorization for partition writes.
  2. **The D110 session-grant machine**, inlined in the 1,454-line
     `scripts/72_stage_downstream_ssh_wifi_test.sh`: a `CODEX_THREAD_ID`-bound
     session grant (ceiling 43,200 s / 12 h per
     `docs/lmi-d110-session-approval.md`), grant storage under `private/`, a
     non-blocking exclusive execute lock, and an internal 30-second one-shot
     attempt receipt per execution.
  3. **The D114 deploy gates**, inlined in `scripts/lmi_p2_d114/`
     (`deploy_userdata.py` 3,118 lines, `deploy_userdata_wsl.py` 2,014
     lines): hash-pinned policy locks
     (`lmi-p2-d114-userdata-deploy-policy-lock/v4`), a 120-second one-use
     approval (`APPROVAL_TTL_SECONDS`), no automatic or same-claim retry
     (`RETRY_SCOPE`), and an `UNKNOWN_FOLLOWUP` constant requiring review
     plus a new exact human approval and a new claim after any
     indeterminate outcome.

- **The coexistence is deliberate but open-ended.** `AGENTS.md` lines 58–64
  and the landing note `notes/governance-v4-landing-2026-07-22.md` record it
  as a transition: "pre-v4 guarded flows keep their own gates until wired to
  the engine", with the convergence work named (migration M2′) but not
  scheduled. Meanwhile the three machines have three receipt lifetimes
  (900 s / 30 s / 120 s), three approval vocabularies, and three evidence
  formats for what is conceptually one thing: owner consent to one device
  state change.

- **An in-flight engine revision exists but is uncommitted.** At the time
  of writing, the maintainer's working tree (not this branch) grows the
  engine to 2,040 lines: roughly 480 lines of hardened filesystem helpers
  (`O_NOFOLLOW` `*at()` opens rooted at the repo directory, descriptor-held
  atomic JSON writes, a verified `flock` ledger lock), a host-only
  `authorize-profile` verb for recording per-profile persistent
  authorizations, and a `scripts/README.md` rule reading
  "`scripts/bringup_loop.py` is the only current governance authority. …
  Do not add a parallel approval workflow." That rule states the intended
  end state; it is not yet true of the code, and at `2cb20cf` the rule text
  itself is not yet in the tree.

The fork to resolve: either the transition finishes, or the authority claim
should stop being made.

## Option A — Finish the transition (wire D114 and D110 to the engine)

Both executors keep their device gates (the engine's layer contract is
explicit: it "never touches the device"; identity, battery, and fastboot
argument gates belong to the executor). What moves to the engine is the
*consent* layer: experiment records, receipts, claims, and the ledger.

**D114 userdata deploy (tier `persistent`, operation `partition_write`,
target `userdata`)** — the higher-value wiring, because persistent writes
are where duplicated approval logic is most dangerous:

1. Owner records a profile file (e.g.
   `config/governance/profiles/d114-p2-userdata-<rev>.json`) pinning the
   candidate sparse image SHA-256/size and the rollback artifact, and adds
   the hash-bound `authorized_profiles` entry to `policy.json` (via the
   `authorize-profile` verb once that revision lands; by reviewed manual
   edit before then).
2. The deployer's `approve` step additionally runs
   `bringup_loop.py new --operation partition_write` (artifact = the sparse
   image, rollback = the distinct-hash rollback artifact) and
   `bringup_loop.py approve` (dry-run of every gate, changes nothing).
3. The deployer's `execute` step calls `bringup_loop.py claim` immediately
   before invoking the platform helper, and refuses to proceed unless its
   own fixed flash command equals the engine's returned `exact_command`.
   The engine's one-claim-per-state-change rule subsumes the deployer's
   "no automatic or same-claim retry" rule — the semantics already agree.
4. After the attempt, the deployer binds the outcome with
   `bringup_loop.py result` (`unknown` maps onto the existing
   `UNKNOWN_FOLLOWUP` discipline: no retry without a new experiment, a new
   owner approval, and a new claim) and `archive` freezes the record.

**D110 RAM-boot session flow (tier `ram_rw`, operation `ram_boot`, target
`ram`)** — the standing scope already exists in `policy.json`:

1. Each `--execute` becomes one engine experiment: script 72 calls `new`
   (with the persistent-media acknowledgment and rebuild reference the
   `ram_rw` tier already requires, since the booted OS mounts `userdata`
   read-write) and `claim`; the engine receipt replaces the internal
   30-second attempt ticket.
2. The thread-bound session grant can be kept as an outer convenience layer
   (it answers "may this session ask at all") or retired; either way the
   per-execution consent and its evidence live in the ledger.

Then the lint invoker allowlist in `scripts/65_lmi_release_safety_lint.sh`
shrinks toward "engine-claimed executors only", and the "only current
governance authority" sentence becomes literally true.

**Cost:** touching two hash-locked, fail-closed executors is expensive by
design — the D114 policy locks pin the deployers' own bytes, so wiring them
re-pins every dependent hash (see the re-pinning chain in
`notes/lmi-d114-p2-next-version-handoff-2026-07-22.md` §3, and the
MEMORY note on SHA duplication fragility). The work must ride an already
planned re-pin cycle (the next candidate rebuild), not happen as a
standalone edit.

## Option B — Retire the engine to a validate-only schema linter

Accept that the executors' bespoke gates are the real authorities, keep
`bringup_loop.py` only as the schema/policy validator that
`65_lmi_release_safety_lint.sh` already uses, and stop claiming otherwise.
Documentation changes required:

- `AGENTS.md` lines 21–23: replace "is the authority for device-affecting
  actions" with "validates the governance data files; device-affecting
  actions are gated by their executors" — and rewrite the tier/claim bullets
  (lines 24–56) plus workflow-gate steps 3 and 5 (lines 85–95), which
  describe claims, receipts, and `result` binding that would never run.
- `README.md` lines 93–100: rewrite the "Hardware-affecting actions are
  governed by the bringup governance engine" paragraph the same way.
- The in-flight `scripts/README.md` "only current governance authority /
  do not add a parallel approval workflow" wording must not land as-is.
- `notes/governance-v4-landing-2026-07-22.md` stays untouched (dated
  evidence), but a superseding note records the retirement.

**Cost:** discards a tested consent-and-evidence design (27 passing tests,
append-only ledger, uniform tier model) and makes the bespoke gates
permanent. Every future executor re-invents approval, and cross-cutting
questions ("what device writes ever happened?") have no single ledger to
ask.

## Option C — Status quo

Keep all three machines and the transition note. This is the only option
that requires no work now, and its cost is already visible: three approval
machines with three receipt formats; an "authority" that has never issued a
claim (empty ledger, empty `authorized_profiles`); the intended
"no parallel approval workflow" rule violated by the two largest executors
in the repository; and documentation that describes the end state as if it
were the current state — the same class of doc/reality drift that produced
the phantom helper scripts recorded in ADR 0002.

## Recommendation

**Option A, staged, D114 first.** Reasoning grounded in what is in the
tree: the engine already models exactly the two operations the executors
perform (`partition_write`/`userdata` for D114; `ram_boot` standing scope
for D110 is already in `policy.json`); the executors' retry/unknown
semantics already match the engine's one-claim rule, so wiring is
claim-plumbing, not a redesign of gates; and the repository is already
moving this way (the landing note's M2′ plan, and the uncommitted engine
revision adding `authorize-profile` and the authority wording). Option B
would reverse a direction the owner set on 2026-07-22 and re-affirmed since,
for a saving that is mostly the cost Option A already confines to the next
re-pin cycle. Sequence: (1) land the hardened engine revision, (2) wire
D114 during its next candidate rebuild (hashes re-pin anyway), (3) wire
D110's execute path, (4) shrink the lint allowlist. Until step 2 lands,
soften the two authority sentences to "the engine is the target authority;
D110/D114 gates remain interim" so the docs describe reality.

## Follow-up regardless of A/B/C: extract the hardened-filesystem layer

The uncommitted engine revision embeds ~480 lines of reusable,
governance-independent filesystem hardening (repo-rooted `*at()` opens with
`O_NOFOLLOW`, symlink/ownership/mode validation, descriptor-held reads with
same-file-state re-verification, fsynced atomic JSON replace, verified
advisory locking). The D114 deployers independently reimplement the same
patterns. This layer should land as its own module (e.g.
`scripts/lib/hardened_fs.py`) with its own tests, imported by the engine —
and by the deployers whenever they are next re-pinned — rather than living
inside `bringup_loop.py`. This is worth doing even under Option B: the
linter and the deployers both keep needing it. (Related cleanup for that
revision: of the `Paths` class's 17 attributes, the 8 absolute-`Path`
duplicates of the `*_rel` strings are unused by the hardened code paths and
can be dropped.)

## Consequences

- If accepted as Option A: one consent vocabulary and one append-only
  evidence ledger for every device state change; the lint allowlist stops
  being the only thing standing between "documented authority" and
  practice; cost is borne inside already-planned re-pin cycles.
- If accepted as Option B: documentation becomes honest at low cost; the
  engine's ledger/receipt design is abandoned; per-executor gates are
  permanent.
- Until either lands: `AGENTS.md`/`README.md` overstate the engine, and
  every new reader (human or agent) must rediscover that the authority has
  no callers.
