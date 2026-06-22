# Repair Phase 6: Ext4 Compatibility

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## V6 Hardware Evidence

```text
artifact=artifacts/images/pmos-lmi-http-diagnostic-20260622-v6.img
artifact_sha256=544E15067029E230FFF3CB55C62337D88BAB32709ADDD249819497234B4FB897
report_size=34071
report_sha256=9E29F65A1C493E9EC2963371DC3E96247FA6BBEECF08FF711A10EA6C9E2FB00F
reports_identical=yes
```

Sanitized report:

```text
logs/repair-http-debug-v6-postwrite-2026-06-22.redacted.txt
sha256=C9648EE76F889B20B77DF22DDF80A6D55555034C940519D05E766E44B03C5E38
redaction_audit=pass
```

V6 confirmed:

- valid GPT at 4096-byte sectors;
- `pmOS_boot` UUID `2c2600b1-700f-4bdd-a22c-bb12cc589baa`;
- `pmOS_root` UUID `8646c5cd-6298-46b4-8465-47c4a0fbb370`;
- both UUIDs match the RAM boot cmdline;
- kernel partition scan reports `loop0: p1 p2`.

Mounting `pmOS_root` still failed. The kernel config has `CONFIG_EXT4_FS=y`,
`CONFIG_JBD2=y` and `CONFIG_FS_MBCACHE=y`, so the failure is not a missing
driver.

## Root Cause

The original rootfs enabled:

```text
orphan_file
```

Ubuntu e2fsck 1.46.5 reported this as unsupported `FEATURE_C12`. The lmi kernel
is 4.19 and predates ext4 orphan-file support. This is the remaining rootfs
mount blocker.

## Compatible Candidate

A local copy of the expanded, target-sized sparse candidate was modified only
in its `pmOS_root` filesystem:

1. `tune2fs 1.47.4 -O ^orphan_file`;
2. `e2fsck 1.47.4 -f -y`;
3. `e2fsck 1.47.4 -f -n`;
4. conversion to Android sparse format;
5. full sparse round-trip and 700 MiB split round-trip validation.

Final candidate:

```text
file=artifacts/images/xiaomi-lmi-userdata-4096-k419-20260622-sparse.img
sparse_size=934211144
expanded_size=114898743296
sha256=B8B12435FAA70F3AB2EC380D6F82475349E5B68B40E4A517A60D5EB7AF57FE30
```

Validation results:

- target-sized 4096-sector GPT: no problems found;
- disk GUID and partition boundaries unchanged;
- filesystem labels and UUIDs unchanged;
- `orphan_file` absent;
- both filesystems pass e2fsck 1.46.5;
- 700 MiB split chunks are `680987212` and `253223984` bytes;
- split round trip retains valid GPT and both UUIDs.

## Authorization Gate

The previous userdata authorization applied to the previous candidate and has
already been consumed. Rewriting userdata with this new 4.19-compatible image
is a new destructive action and requires separate explicit approval.
