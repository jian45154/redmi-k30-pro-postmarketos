# D110 current-thread RAM-boot approval

The D110 recovery helper supports a scoped approval for the current Codex
thread. This replaces the former workflow in which a human had to copy a
30-second receipt challenge through chat.

The approval is deliberately narrower than a general fastboot approval. It is
valid only for:

- stage `ramboot` and operation `fastboot boot`;
- the policy-pinned lmi identity and bootloader state;
- the exact D110 boot image, component hashes, manifests, UUIDs, and known D114
  userdata pairing;
- the pinned official fastboot binary and acquisition record;
- the exact helper contents, current `CODEX_THREAD_ID`, and current host boot;
- at most 43,200 seconds (12 hours), unless revoked earlier.

The raw Codex thread ID and host boot ID are never written to the grant or
printed. Only domain-separated SHA-256 bindings are persisted in the private
grant directory. `CODEX_THREAD_ID` is a scope discriminator supplied by the
Codex runtime, not a cryptographic user identity: the user's authority still
comes from the Codex conversation and tool-approval boundary. The helper fails
closed when that variable is absent.

## Workflow

Keep the handset on the bootloader **FASTBOOT** screen and connected over USB.
Create the session grant once:

```sh
scripts/72_stage_downstream_ssh_wifi_test.sh \
  --stage ramboot --authorize-session
```

Authorization performs the full read-only handset, artifact, helper, and tool
preflight. It does not boot the phone. After it succeeds, request a temporary
boot without another copied token:

```sh
scripts/72_stage_downstream_ssh_wifi_test.sh \
  --stage ramboot --execute
```

Every execute invocation:

1. takes a non-blocking exclusive execution lock;
2. verifies the exact current-thread grant;
3. repeats the complete read-only preflight;
4. creates and immediately consumes a private 30-second one-shot attempt
   receipt inside the same process;
5. repeats the checks within that short action deadline; and
6. attempts exactly one pinned `fastboot boot` command, with no automatic
   retry.

The 30-second receipt now limits only the atomic device-action window; it is no
longer a chat approval timeout. A second explicit execute request in the same
valid session may create a new one-shot attempt receipt.

Revoke the current thread's grant locally with:

```sh
scripts/72_stage_downstream_ssh_wifi_test.sh \
  --stage ramboot --revoke-session
```

Changing the thread, host boot, policy, helper, image, device identity, or
pinned tool invalidates the grant. The 12-hour ceiling is a fail-safe for a
missing session-end notification. The retired `--receipt`, `--confirm`, and
caller-supplied `--session-id` interfaces are rejected rather than silently
downgraded.

## Safety boundary

This workflow never issues `fastboot flash`, `erase`, `format`, relock, or any
partition-writing command. The boot image itself runs code on the handset, so
the booted operating system may still modify persisted userdata.

The gate protects the reviewed helper path; it cannot prevent the same host
user from bypassing the helper and invoking Windows fastboot directly. It also
cannot undo a boot command already accepted by the bootloader. Persistent
partition writes remain outside this approval and require their own fresh,
separately scoped authorization and rollback evidence.
