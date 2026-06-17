# Image Inspection
签名：codex_ian | 2026-05-28 13:12:00 +10:00 Australia/Sydney

## Result

Image metadata was inspected locally with
`scripts/04_inspect_images.bat`.

Raw output was written to `logs/image-inspection.txt`, which is ignored by Git.

## Summary

### `artifacts/images/boot.img`

- Type: Android boot image
- Header version: `2`
- File size: `134217728`
- Page size: `4096`
- OS version field: `16.0.0 patch=2026-04`
- Kernel size: `47454232`
- Ramdisk size: `1494405`
- Kernel address: `0x00008000`
- Ramdisk address: `0x01000000`
- Tags address: `0x00000100`
- DTB size: `1424944`
- DTB address: `0x0000000001f00000`
- Recovery DTBO size: `0`

The cmdline matches the local `device-xiaomi-lmi/deviceinfo` kernel cmdline
closely. This image is likely the LineageOS Android 16 boot image copied from
WSL, not a complete postmarketOS Linux server image.

### `artifacts/images/[REC_BOOT]3.7.1_12-RedmiK30Pro-POCOF2Pro_v9.0_A15-lmi-skkk.img`

- Type: Android boot image
- Header version: `2`
- File size: `134217728`
- Page size: `4096`
- OS version field: `15.0.0 patch=2099-12`
- Kernel size: `50634768`
- Ramdisk size: `48965358`
- Recovery DTBO size: `12330818`
- DTB size: `1613676`

This appears to be a recovery boot image, consistent with its filename and the
large ramdisk/recovery DTBO payload. It should be treated as recovery material,
not a postmarketOS boot artifact.

### `artifacts/images/[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk_ef1ce3b4.zip`

- Type: ZIP
- Contains one Android boot image:
  `[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk.img`
- Contained image size: `134217728`

## Porting Implications

- The pmaports boot image settings in `deviceinfo` are aligned with observed
  Android boot image header version `2` and page size `4096`.
- `boot.img` is useful as a reference for cmdline, offsets, DTB size, and
  Android 16 kernel context.
- None of the inspected images should be treated as a ready Linux server image.
- Do not flash or boot any image until the kernel source, config, and generated
  postmarketOS boot image are known.
