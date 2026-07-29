# Governance v4 persistent-profile authorization CLI (2026-07-25)

Status: **host-side implementation only; no profile was authorized and no
device action was performed by this change.**

## Purpose

Persistent writes already require a hash-bound `authorized_profiles` entry in
`config/governance/policy.json`, but v4 originally required the owner to edit
that JSON by hand. The canonical one-invocation owner entry point is now:

```sh
python3 scripts/bringup_loop.py authorize-profile \
  --profile profiles/<reviewed-profile>.json \
  --target <boot|userdata|dtbo|vbmeta> \
  --note "<what the owner reviewed>"
```

The command derives the declared owner from policy, computes all hashes itself,
requires the engine, policy, constants, and selected profile to be
byte-identical to one clean Git `HEAD`, shows the complete immutable preview,
and requires this exact TTY ceremony:

```text
AUTHORIZE-PERSISTENT <authorization_digest>
```

There is no `--yes`, environment-variable bypass, piped confirmation, or
combined authorize-and-claim mode.

## What the command proves

- safe idle: no `notes/bringup-active.json`;
- one canonical, tracked `profiles/*.json` profile and one target;
- Git `HEAD`, index, and worktree equality for the engine, constants, policy,
  and profile, checked with a fixed Git binary and sanitized environment;
- duplicate-key-free JSON;
- candidate and rollback paths remain inside owner/root-owned, non-writable
  repository ancestry and contain no symlink component, hardlink, FIFO, or
  other special file;
- candidate and rollback sizes and SHA-256 values match their actual bytes;
- large candidate and rollback files are hashed through fixed 1 MiB chunks and
  stable file descriptors rather than loaded into memory;
- rollback targets the same partition and has a different SHA-256;
- the confirmation digest binds Git `HEAD`, all four TCB hashes, the base
  policy hash, next revision, declared owner, profile path/hash, target,
  candidate pin, rollback pin, and note;
- policy, constants, profile, candidate, and rollback are revalidated under the
  same lock used by `claim` before the atomic policy replacement;
- `claim` now loads policy while holding that lock, closing the previous
  authorize/claim policy-read race.

The policy write preserves existing Unix mode and ownership, fsyncs the
temporary file, atomically replaces the JSON, fsyncs the parent directory, and
validates the result before reporting success. ACLs and extended attributes
are intentionally outside this v4 implementation.

## What the command never does

- create or change an active experiment;
- issue or consume a receipt;
- append the claims ledger;
- build or print an `exact_command`;
- import or call an executor;
- invoke fastboot, adb, pmbootstrap, telnet, SSH, or any network operation;
- contact the handset.

Authorization, `new`, dry-run `preflight`, `claim`, external execution, `result`,
and `archive` remain distinct state transitions.

`claim` also creates a durable per-experiment replay guard before appending the
ledger and replacing the active record. If a host failure splits those writes,
the guard remains and the same experiment cannot issue or print its command
again; recovery is a stop-and-audit event, never an automatic retry.

## Trust boundary

`authorized_by: "ian"` and an interactive TTY are an owner declaration and
audit ceremony, not cryptographic identity authentication. A process with the
same repository write permissions can still rewrite policy directly. Strong
operator authentication would require an external trust root unavailable to
the agent, such as an offline signing key or a separately owned authorization
broker.

An `authorized_profiles` entry remains profile/target-scoped until separately
reviewed and removed. It is not itself a one-shot token. Each actual state
change still needs a fresh experiment and consumes a fresh receipt; reusing the
same physical write additionally requires the existing repeat guard. A future
schema can add expiring, consumable authorization IDs if the owner wants a new
human signature before every persistent claim.

Because the authorization entry point itself must equal the reviewed commit,
the command correctly refuses in the current uncommitted implementation
worktree. The owner should review and commit this change and the selected
profile before invoking it.

## Host acceptance

`tests/governance/test_bringup_loop.py` has 52 passing tests. They cover the
successful host-only path, subsequent claim compatibility, bounded streaming,
non-TTY and wrong-phrase refusal, unsafe human text, hostile Git environment,
safe-idle enforcement, path escape/symlink/hardlink/FIFO/owner-mode refusal,
dirty/staged/untracked TCB and profile states, duplicate JSON keys, disabled
policy, post-confirmation artifact/TCB/HEAD drift, claim partial-commit replay
protection, idempotence, and conflicting profile replacement. Every
authorization refusal keeps policy byte-identical.
