# Fastboot Check
签名：codex_ian | 2026-05-28 13:01:00 +10:00 Australia/Sydney

## Result

The phone is now connected in fastboot mode.

ADB mode is not active in this state.

## Fastboot Summary

- Product: `lmi`
- Bootloader unlocked: `yes`
- Secure: `yes`
- Kernel/boot firmware type: `uefi`
- Fastboot userspace mode: `is-userspace:no`
- Storage variant: `SM8 UFS`
- Anti-rollback value: `1`
- Battery voltage observed: `4132`
- Parallel download flash: `yes`
- Max download size: `805306368`

Private identifiers are present in `logs/phone-fastboot.txt`, including token,
serial number, and CPU ID. Do not share the raw log without redaction.

## Important Partition Sizes From Fastboot

```text
boot      raw   0x8000000
recovery  raw   0x8000000
dtbo      raw   0x2000000
vbmeta    raw   0x20000
super     raw   0x220000000
userdata  f2fs  0x1AC07FB000
cache     ext4  0x18000000
metadata  ext4  0x1000000
persist   raw   0x4000000
```

No `vendor_boot` or `init_boot` partition appeared in the fastboot partition
list.

## Porting Implications

- The local pmaports `deviceinfo` using Android boot image header version `2`
  remains plausible for this device generation.
- `deviceinfo_flash_pagesize="4096"` matches the fastboot logical block size
  observed as `0x1000`.
- `boot` and `recovery` are both 128 MiB, matching the copied image sizes.
- Since userspace fastboot is not active, dynamic partition work involving
  `super` should be handled cautiously and not attempted before a recovery plan
  is confirmed.

## Next Safe Step

Before any flash or boot test:

1. Identify whether `artifacts/images/boot.img` is a postmarketOS image or an
   Android/recovery image.
2. Inspect Android boot image metadata locally.
3. Locate the kernel source and config matching
   `4.19.325-cip128-st12-perf-ga5b3099017ae`.
4. Prefer a temporary `fastboot boot` test only if lmi bootloader accepts it;
   do not flash `boot`, `dtbo`, `vbmeta`, or `super` yet.
