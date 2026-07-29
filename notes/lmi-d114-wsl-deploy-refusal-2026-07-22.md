# LMI D114 WSL deploy host-gate refusal — 2026-07-22

Status: **host gate aborted; no device query, transport attempt, or device state
change. A new exact approval is required before any later invocation.**

The owner approved the complete `deploy-once` command recorded in
[lmi-d114-wsl-userdata-preflight-2026-07-22.md](lmi-d114-wsl-userdata-preflight-2026-07-22.md),
bound to sparse userdata SHA-256
`64d5121c3dfc3e143626386417e1f56cd6dcfcd2cf647d51182516415195b217`.
The approved command was invoked once from WSL. It exited with status `2` after
approximately 8.9 seconds and emitted exactly:

```text
refused: candidate fields mismatch
```

## Failure boundary

The invoked deployer was SHA-256
`dcb259fa39ed3348ed2da41d73cc169ab4323f3bf686066cc2beb517978cd9f9`.
Its `local_audit()` first validated the complete sparse candidate schema, then
called `_open_spec()` without its sparse-schema mode. `_open_spec()` therefore
incorrectly required only `path`, `sha256`, and `size` while the valid
candidate also contained `logical_size`, `representation`, and
`roundtrip_raw_sha256`. The generic exact-field check raised the recorded
error.

This happened before `_open_spec()` resolved or opened the candidate. The
process opened and read only the 4,246-byte private profile. It did not open,
read, or hash the candidate sparse, expanded userdata, rootfs, or rollback
image. It did not reach runtime validation, a fastboot query, preflight,
approval-claim publication, claim consumption, candidate-attempt publication,
intent publication, or the flash runner.

Observed local evidence immediately after refusal:

- deploy run directory: mode `0700`, zero entries including hidden entries;
- claim-consumption ledger: mode `0700`, zero entries;
- candidate-attempt ledger: mode `0700`, zero entries;
- candidate sparse: still mode `0600`, 2,160,111,768 bytes, with its prior
  modification time;
- preflight/approval/intent/execute outputs: absent.

Accordingly:

```text
device_query=false
approval_claim_created=false
approval_claim_consumed=false
candidate_attempt_created=false
intent_created=false
transport_attempt=false
device_state_change=false
```

No entry is added to either deterministic ledger or to the completed-actions
lock for this host-only refusal.

## Corrective action and authorization boundary

The minimal correction makes `_open_spec(..., sparse=True)` reuse the existing
exact six-field artifact validator only for `candidate` and `rollback`.
Ordinary artifacts remain exact three-field objects; missing or extra sparse
fields still fail closed. The corrected deployer has SHA-256
`a756d0c3dd4b4969ba792be0a26bb9a7c162016189b67d315886b339af104ecf`.

The original approval was used to start the refused invocation. It is not a
retry authorization and must not be converted into a claim or attempt ledger
entry. After the corrected code and tests receive independent review, the
owner must receive the complete command again and give a new immediate exact
approval before another invocation. No automatic retry is permitted.

## Second host-gate refusal (`r2`)

After the sparse-schema correction received independent review, the owner
approved a second command using a new empty `wsl-deploy-run-20260722-r2`
directory. That command ran the corrected deployer SHA-256
`a756d0c3dd4b4969ba792be0a26bb9a7c162016189b67d315886b339af104ecf`
once. It exited with status `2` after approximately 13.2 seconds and emitted:

```text
refused: ELF interpreter has a symlink or non-directory ancestor
```

Unlike the first refusal, this invocation opened and audited the large
candidate/rootfs/rollback closure before reaching runtime validation. The
failure then occurred while validating the host fastboot ELF interpreter,
before running even `fastboot --version`. It did not reach a device query,
preflight, claim, attempt, intent, or flash.

The cause was a second host-only false positive. Fastboot records the normal
ELF `PT_INTERP` path `/lib64/ld-linux-x86-64.so.2`; this WSL installation uses
the standard usr-merge chain `/lib64 -> usr/lib64`, followed by the leaf link
to the real loader under `/usr/lib/x86_64-linux-gnu`. The generic ancestor
policy correctly rejects symlink ancestors for ordinary executable, library,
and artifact paths, but it had not modeled this one legitimate, fixed
interpreter alias.

Immediately after refusal, the `r2` run directory and both deterministic
ledgers remained mode `0700` and empty. No deploy or fastboot process remained.
The `r2` approval is spent; it is not reused. The correction must retain the
global ancestor policy and instead model only the exact usr-merge interpreter
chain while continuing to execute the resolved, hash-locked loader. A later
invocation requires independent review, a new empty run directory, and a new
immediate exact owner approval.

## Runtime-v2 corrective closure

The corrected runtime schema explicitly locks the two-link evidence chain:

```text
/lib64 -> usr/lib64
/usr/lib64/ld-linux-x86-64.so.2 \
  -> ../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
```

Only the ELF interpreter uses that dedicated verifier. Both links are checked
for exact type, target, lstat size, and identity before and after opening the
resolved loader. Fastboot execution continues to use the resolved, hashed
loader directly; all ordinary libraries, the fastboot symlink, repository
artifacts, and their ancestors retain the original no-symlink policy. Runtime
validation now precedes opening or hashing any multi-gigabyte artifact.

The frozen corrective closure is:

| Item | SHA-256 | Size (bytes) |
| --- | --- | ---: |
| WSL deployer | `858ee65f9ed8df2092cb8e2ac0ba851f1d7cb82cbd91b6adb3383a75ae7710d2` | 87,553 |
| runtime lock v2 | `a2db2d343aeeead7400da9b0487de536ba0842d20a3861fdde23ca647d71c65d` | 8,066 |
| deploy policy | `75c5ab47566fa81aa296f7a9cf7581467d013f45c282afefeb4e4fa382d61a84` | 4,284 |
| private profile | `31a9674e0fa07999d226d7805364b2b2fc556c243bf9224a80b095a968542219` | 4,246 |
| WSL postwrite gate | `7aae3b78286c8c71375fe07c73c78c4d9bd9a0a581a321ea823578b99400bbb4` | 42,533 |

The real-WSL runtime integration invokes only the exact resolved-loader
`fastboot --version` command and `dpkg-query`; it rejects `devices`, `getvar`,
`flash`, and all other commands. The combined deploy/postwrite suite passes
41 tests, including the actual runtime lock with the postwrite static metadata
runner. Local-audit code paths were exercised only with small synthetic
fixtures or early-stop probes; no deploy command, device query, or
large-artifact read was performed.

## Third host-gate refusal (`r3`)

After runtime-v2 received independent review, the owner approved a third
command using a new empty `wsl-deploy-run-20260722-r3` directory. The command
ran deployer SHA-256
`858ee65f9ed8df2092cb8e2ac0ba851f1d7cb82cbd91b6adb3383a75ae7710d2`
once. Runtime and the complete large-artifact audit passed. The first fresh,
read-only `fastboot devices` query then caused exit status `2` with:

```text
refused: exactly one bootloader-mode fastboot device is required
```

No preflight, approval, intent, or execute output was published. The `r3` run
directory and both deterministic ledgers remained mode `0700` and empty, so no
claim or candidate attempt existed and no flash argv could be reached.

A subsequent read-only check showed one matching fastboot device on WSL USB
path `1-1`. Replaying the exact locked-loader query exposed the parser mismatch:

```text
actual Debian fastboot bytes:  <serial>\t fastboot\n\n
previous accepted bytes:      <serial>\tfastboot\n
```

The serial itself is private and is not recorded here. The single space after
the tab and the second newline are deterministic formatting from the locked
Debian fastboot invocation, not evidence of a second device. The current
strict parser rejected this legitimate one-device shape before publishing a
preflight. The query was read-only and did not change device state.

The corrective parser may accept only the existing canonical single-device
shape and this exact observed Debian shape (with their CRLF equivalents). It
must continue to reject zero or multiple devices, extra lines/text, arbitrary
whitespace, and any mode other than `fastboot`. The `r3` approval is spent;
after implementation and independent review, any later command requires a new
empty run directory and a new immediate exact approval.

The corrected deployer is SHA-256
`b19b669e08b01a2b0b34f7eb5cd9df665934f39c15e206dfd0613372bc6f9b52`
(87,614 bytes). It accepts only the canonical one-line shape or the observed
single-space, double-line-ending Debian shape. The combined deploy/postwrite
suite passes 44 tests; an independent probe accepted all four LF/CRLF forms in
that two-shape allowlist and rejected 23 zero/multiple/noise/space/EOL/mode and
process-status adversarial forms. Independent review marked the parser and its
postwrite reuse GO. No device command or large-artifact read was performed for
that corrective review.

## Fourth host-gate refusal (`r4`)

After the strict devices parser received independent review, the owner
approved a fourth command using a new empty `wsl-deploy-run-20260722-r4`
directory. Deployer SHA-256
`b19b669e08b01a2b0b34f7eb5cd9df665934f39c15e206dfd0613372bc6f9b52`
passed runtime, the complete large-artifact audit, one-device enumeration, and
the fixed read-only getvar collection. Integer conversion then refused with:

```text
refused: partition size is not a strict integer
```

The refusal was still inside preflight construction and occurred before
preflight publication. The `r4` directory and both mode-`0700` ledgers remained
empty, so approval, attempt, intent, execute report, and flash were unreachable.
The completed getvars were read-only and did not change device state.

The code already accepted hexadecimal integers. A single diagnostic replay of
only the locked `partition-size:userdata` getvar showed the exact cause:

```text
partition-size:userdata:  0x1AC07FB000
Finished. Total time: 0.004s
```

Fastboot's field delimiter accounts for the first space; the device value
therefore reaches the integer parser with exactly one additional leading ASCII
space. The correction may accept zero or one leading space only for the
partition-size value, while battery voltage and maximum-download-size remain
unchanged. Tabs, two spaces, trailing space, signs, and non-integer text remain
invalid. The `r4` approval is spent and cannot authorize a corrected command.

The corrected deployer is SHA-256
`92bea6669cc07782bd5aff5ee948f31bada655b61bd5fcaa92c92cc21a69d913`
(87,845 bytes). Its combined deploy/postwrite suite passes 46 tests. Independent
integer/parser probes accepted all intended canonical and observed values and
rejected leading tabs, two spaces, trailing spaces, signs, empty values, and
garbage; query probes confirmed the relaxation is used only for partition
size, not battery or maximum download size. Independent review marked this
correction GO. No device command, deploy, local audit, or large-artifact read
was performed for the corrective implementation or review.
