# LMI D114 WSL userdata preflight and rollback — 2026-07-22

Status: **runtime-v2, postwrite, devices-output, and partition-size gates are
independently reviewed GO; no current device-write authorization. Four earlier
approved invocations were refused before any state-changing command. A new
immediate approval is required for the exact `r5` command below.**

This note covers exactly one persistent write to the physical, unslotted
`userdata` partition of the identity-matched Xiaomi `lmi`. It does not approve
or authorize `boot`, `vendor_boot`, `init_boot`, `dtbo`, `vbmeta`, `super`,
`persist`, modem/EFS, erase, format, reboot, relock, or a fastbootd fallback.

## Destructive scope

`fastboot flash userdata` replaces the partition contents and destroys the
currently installed userdata filesystem and its data. The observed partition
is physical (not proven logical or slotted), reports type `f2fs`, and has size
`0x1ac07fb000` (114,898,743,296 bytes). The final command must independently
re-observe `product=lmi`, an unlocked bootloader, bootloader fastboot rather
than fastbootd, the expected partition type and capacity, and acceptable
battery state. A stale observation in this note is not sufficient.

The selected hardware-test candidate is:

| Item | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| Android sparse userdata | 2,160,111,768 | `64d5121c3dfc3e143626386417e1f56cd6dcfcd2cf647d51182516415195b217` |
| Expanded userdata | 3,339,714,560 | `eedf2e762869bdbfb4a0b660b6837ed69faf3fbc1afed35c4ed185657d1891f7` |
| Injected rootfs | 2,826,960,896 | `ff49900bd302cbcaaa5bddc8f7a76d221cce4af9313c3b45bf6e02dc85c624da` |

The sparse image passed assembly geometry, GPT, prefix/suffix, P2-range,
round-trip expansion, and expanded-byte identity checks. Its injection
attestation still says `hardware_test_only=true`, `production=false`, and
`release_eligible=false`; this write is a hardware qualification step, not a
production release claim.

The WSL one-shot deployer is SHA-256
`92bea6669cc07782bd5aff5ee948f31bada655b61bd5fcaa92c92cc21a69d913`
(87,845 bytes). The combined deploy/postwrite suite passes 46 tests, and the
partition-size parser passed independent accept/reject and query probes.
It opens and verifies the candidate, expanded image, rootfs, rollback image,
and governance inputs once, retains the opened descriptors, performs a fresh
device gate, consumes approval/candidate ledgers, and permits only:

```text
<locked loader and fastboot argv> -s <identity-matched-private-serial> \
  flash userdata /proc/self/fd/<held-candidate-fd>
```

Do not run standalone `local-audit` first. `deploy-once` performs that complete
audit before any device query or write; running it separately would reread the
same large artifacts without producing reusable authorization.

## Exact one-shot deployment command

The following command is the only proposed write. The run directory must be a
new empty mode-`0700` directory, all four output paths must not exist, and the
private profile must remain mode `0600` with SHA-256
`31a9674e0fa07999d226d7805364b2b2fc556c243bf9224a80b095a968542219`.

```bash
./scripts/lmi_p2_d114/deploy_userdata_wsl.py deploy-once \
  --profile private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/lmi-d114-userdata-p2-r1-sixrow-wsl-deploy-profile-20260722.json \
  --preflight private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/wsl-deploy-run-20260722-r5/preflight.json \
  --approval private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/wsl-deploy-run-20260722-r5/approval.json \
  --intent private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/wsl-deploy-run-20260722-r5/intent.json \
  --report private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722/wsl-deploy-run-20260722-r5/execute.json \
  --approved-operation flash-userdata \
  --approved-sparse-sha256 64d5121c3dfc3e143626386417e1f56cd6dcfcd2cf647d51182516415195b217
```

The owner must approve this complete command immediately before execution.
Earlier approval for sparse SHA-256 `39d45c6d...` does not authorize this
different image. The command may be attempted exactly once. A timeout,
exception, partial transcript, nonzero result, or `UNKNOWN` outcome after
candidate-attempt publication consumes the attempt and forbids a retry until
evidence is preserved and reviewed. A refusal before attempt publication does
not fabricate a ledger entry, but it spends that immediate approval and still
requires evidence review plus a new approval before another invocation.

The first approval for this new hash started an earlier deployer whose
sparse-profile schema mismatch refused before opening the candidate. The
second approved `r2` invocation completed the large host audit but refused on
the legitimate WSL `/lib64 -> usr/lib64` alias before any fastboot process or
device query. The third approved `r3` invocation passed runtime v2 and the
large audit, then rejected the exact Debian one-device output because its
space/newline shape was not yet in the strict allowlist. It ran only the
read-only `fastboot devices` query. None produced a claim, attempt, intent,
transport, or device change. The fourth approved `r4` invocation passed the
host audit and complete read-only query collection, then refused because the
partition-size value carried one exact additional leading space. It also
stopped before preflight publication. All four approvals are spent.
The evidence and corrections are recorded in
[lmi-d114-wsl-deploy-refusal-2026-07-22.md](lmi-d114-wsl-deploy-refusal-2026-07-22.md).

Only the route
`USERDATA_TRANSPORT_COMPLETED_DEVICE_REVALIDATION_PENDING` permits moving to
the postwrite stage. It does not establish successful boot or terminal
functionality.

## Postwrite host revalidation

The WSL postwrite tool is SHA-256
`7aae3b78286c8c71375fe07c73c78c4d9bd9a0a581a321ea823578b99400bbb4`.
After a completed write, preserve the execute report, physically disconnect
the phone, and run `arm-replug` only while WSL observes zero fastboot devices.
It emits an atomic mode-`0600`, one-use, 300-second token under a mode-`0700`
private run directory. Reconnect the same phone and run `revalidate` with the
exact profile hash, execute-report path/hash/size, and token path/hash.

Both stages also require the exact path, SHA-256, and size of the deterministic
consumed-claim ledger entry, candidate-attempt ledger entry, and preattempt
intent produced by this deployment. The gate opens these small mode-`0600`
files, holds their descriptors, verifies their canonical schemas and expected
mode-`0700` parent ledgers, and cross-binds candidate, approval, profile,
runtime, mapping, device identity, argv, route, and chronology. A caller cannot
replace that lineage with arbitrary digest strings or omit the underlying
files.

The report field is
`host_observed_zero_then_one_fastboot_device`; the host can prove only that it
observed zero devices followed by one
nonce-bound, identity-matching `lmi` that passes the full read-only fastboot
gate. It cannot prove the physical mechanism of removal. It issues no write,
reboot, or boot command. A consumed, expired, failed, noisy, zero-device, or
multi-device token is not retried.

Only
`POSTWRITE_REVALIDATED_PRIOR_COMPLETED_NO_STATE_CHANGE` permits considering a
separately approved D110 RAM boot. `fastboot boot` is not authorized by the
userdata approval and may still allow the booted OS to modify userdata.

## Rollback boundary and trigger

The reviewed rollback artifact is the previously hardware-tested D114 sparse
userdata image:

| Item | Size (bytes) | SHA-256 |
| --- | ---: | --- |
| D114 rollback sparse | 2,192,400,084 | `e8a30dc37cb4b75508d89725a9603bc15a985f4e51af77384e8d43c2928f8d68` |
| Its expanded image | 3,339,714,560 | `61ca69e6c241a92ad86539ffeebc0d4ef296572709445604ce26a78648f27bf6` |

Historical D198 evidence records all three sparse write segments as `OKAY`;
D199 revalidated the reattached device; D200–D202 then demonstrated D110 RAM
boot, rootfs mount, RNDIS, and SSH against that D114 userdata. The imported
history review records the same hashes and limitations in
[lmi-windows-history-evidence-review-20260720.md](../docs/lmi-windows-history-evidence-review-20260720.md).

This is a verified **postmarketOS userdata rollback point**, not an Android or
factory recovery. No complete, source-verified LOS/MIUI fastboot ROM and no
complete Android userdata restoration manifest are present. The A12 TWRP RAM
boot path is also not storage-read-only because it automatically mounted
userdata read/write; see
[repair-phase5-recovery-test-2026-06-22.md](repair-phase5-recovery-test-2026-06-22.md).

Rollback is considered only after preserving the new command's preflight,
approval, intent, execute report, deterministic ledgers, and postwrite
evidence. Triggers include a completed write followed by failure to revalidate
the same device, failure to reach the expected D110 rootfs/terminal milestone,
or a regression that prevents continued qualification. An `UNKNOWN` flash
outcome is first investigated and is never treated as permission to overwrite
again.

Rollback is not automatic. Before it is used, re-check its bytes and sparse
round-trip, recreate a fresh device preflight, prepare a separate one-shot
command whose only write is
`fastboot -s <identity-matched-private-serial> flash userdata <held-D114-rollback-sparse>`,
and obtain a new explicit owner approval for that fully instantiated command.
No boot/erase/format/reboot action is implied by rollback approval.

## Stop conditions

Stop without writing when any artifact, script, runtime, policy, mapping,
profile, device identity, partition property, battery threshold, ledger state,
approval TTL, or output-path check differs. Stop after any non-successful or
ambiguous transport result. Do not relock the bootloader. Preserve evidence
before proposing any new device action.
