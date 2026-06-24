# Xiaomi lmi r6 current handoff - 2026-06-24

This is the short handoff for the current `edge` mainline/copydown route. It
is not an approval to execute hardware commands.

## Repository

- Branch: `edge`
- Remote: `https://github.com/jian45154/redmi-k30-pro-postmarketos.git`

This tracked handoff intentionally does not record a commit hash because the
file is generated before the commit that archives it. Use `git rev-parse HEAD`
or the GitHub `edge` branch tip for the authoritative revision.

## Route Decision

RAM-only boot is no longer a prerequisite for this route. The current path is a
guarded recovery-fastbootd persistent test: enter fastbootd, verify
`is-userspace=yes`, flash only `userdata` rootfs and `boot`, then reboot and
collect evidence.

## Device Gate

- Product: `lmi`
- Unlocked: `yes`
- is-userspace: `yes`
- Route status: `READY_FOR_FASTBOOTD_PREFLIGHT`

Current blocker: fastbootd preflight is ready. The next step is a separately approved rootfs write to userdata.

## Exact Next Command Requiring Approval

```sh
LMI_FLASH_CONFIRM=flash-xiaomi-lmi-rootfs-45bc097634b5-d778d4ea659e scripts/53_stage_lmi_fastbootd_flash.sh --stage rootfs --execute
```

After that, rerun the readiness audit and only then request separate boot-stage approval.

```sh
scripts/66_wait_and_audit_lmi_fastbootd.sh
```

This combined read-only gate waits for `is-userspace=yes`, runs fastbootd
preflight, and reruns the persistent readiness audit. Do not flash unless it
finishes with `fastbootd audit gate: OK`.

## Artifact Hashes

- Boot: `45bc097634b521037a9a7b1298046e9ca56bae21c54e612876b8ad3be9610254`
- Rootfs: `d778d4ea659e6fa09ea9038f3626d837d0ec2cea5d09aeb9d0653ce5ea38c4af`
- Rollback boot candidate: `0c06ad2aca2ab0d510e9d9c97ba31d35a514b9a3d15850b1c4a2121e55fa5cbf`

## Canonical Local Reports

- Release manifest: `docs/release/lmi-r6-bootmem-release-manifest-20260624.md`
- Execution checklist: `docs/release/lmi-r6-bootmem-execution-checklist-20260624.md`
- Plan report: `/tmp/lmi-release-r6-bootmem-20260624/PERSISTENT_FLASH_PLAN.txt`
- Refresh summary: `/tmp/lmi-release-r6-bootmem-20260624/RELEASE_REFRESH_SUMMARY.txt`

## Refresh Command

```sh
scripts/62_refresh_lmi_release_docs.sh --quick
```

## Hard Safety Boundary

Do not run any `fastboot flash`, `fastboot reboot`, `fastboot reboot
fastboot`, `pmbootstrap flasher flash_rootfs`, erase, format, sideload, or
bootloader-lock command without fresh exact approval for that command.

Do not touch `super`, `dtbo`, `vbmeta`, `persist`,
modem/EFS/calibration partitions, `vendor_boot`, `init_boot`, or bootloader
lock state as part of this route.
