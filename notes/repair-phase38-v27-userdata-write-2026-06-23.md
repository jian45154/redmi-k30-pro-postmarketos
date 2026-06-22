# Repair Phase 38: v27 Userdata Write

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Explicit approval

The operator confirmed:

```text
确认用 fastboot -S 256M flash userdata 写入 v27 userdata
```

## Written partition

```text
partition=userdata
command=fastboot -S 256M flash userdata artifacts\images\xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img
```

No `boot`, `dtbo`, `vbmeta`, `super`, modem/EFS, persist, or calibration
partition was written.

## Image

```text
file=artifacts/images/xiaomi-lmi-v27-rndis-usbid-userdata-20260623.img
sha256=9035ae1e1ba035134553dafed1b1900288b4d082c408018a1ebd31fe89cd7fb4
size=1754267648
layout=4096-byte-sector GPT with pmOS_boot and pmOS_root
```

## Fastboot result

```text
Invalid sparse file format at header magic
Sending sparse 'userdata' 1/4 (261826 KB) OKAY
Writing 'userdata' OKAY
Sending sparse 'userdata' 2/4 (262131 KB) OKAY
Writing 'userdata' OKAY
Sending sparse 'userdata' 3/4 (247918 KB) OKAY
Writing 'userdata' OKAY
Sending sparse 'userdata' 4/4 (136365 KB) OKAY
Writing 'userdata' OKAY
Finished. Total time: 44.134s
```

The "Invalid sparse file format at header magic" line is fastboot falling back
from sparse parsing for a raw image; the four chunked transfers and writes all
completed with `OKAY`.

## Post-write state

```text
fastboot devices: device present
product: lmi
partition-size:userdata: 0x1AC07FB000
```

The device remained reachable in fastboot after the write.

## Next validation

The next reversible validation is RAM-only boot of:

```text
artifacts/images/pmos-lmi-normalboot-v27-rndis-usbid-loopdevfix-20260623.img
```

This boot image uses the v27 userdata UUID pair:

```text
pmos_boot_uuid=3c14f75f-450e-4457-b109-6fc5d9f7c54c
pmos_root_uuid=b50c1119-2cd9-4675-a9be-3201c98d54ec
```

This validation still does not require writing the boot partition.
