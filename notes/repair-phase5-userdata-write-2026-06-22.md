# Repair Phase 5: Userdata Write

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Authorization And Scope

Ian explicitly authorized: `确认擦除并刷写 userdata`.

Only `userdata` was written. No command wrote `boot`, `super`, `recovery`,
`dtbo`, `vbmeta`, `persist`, modem/EFS or any other partition.

## Final Preflight

```text
product=lmi
unlocked=yes
battery_voltage_mv=4386
is_userspace=no
max_download_size=805306368
partition_size_userdata=0x1AC07FB000
candidate=artifacts/images/xiaomi-lmi-userdata-4096-20260622-sparse.img
candidate_size=934207076
candidate_sha256=E1D3A3D2B5BE2A85FB9909D01045A9D0B3929748BEEC35564EDD8CBF43EA5414
```

## Command

```powershell
fastboot -S 700M flash userdata artifacts/images/xiaomi-lmi-userdata-4096-20260622-sparse.img
```

## Result

```text
Sending sparse 'userdata' 1/2 (665022 KB)  OKAY [14.742s]
Writing 'userdata'                          OKAY [ 0.002s]
Sending sparse 'userdata' 2/2 (247289 KB)  OKAY [33.429s]
Writing 'userdata'                          OKAY [ 0.001s]
Finished. Total time: 48.659s
```

Fastboot printed `skip copying userdata image avb footer due to sparse image`.
The candidate is a validated nested-GPT userdata image and does not rely on a
userdata AVB footer.

The older fastboot client used for the write did not enumerate the device after
completion. Windows reported the bootloader driver healthy, and the installed
fastboot 37.0.0 immediately enumerated the same device. Post-write read-only
checks with that client confirmed:

```text
product=lmi
unlocked=yes
battery_voltage_mv=4382
partition_size_userdata=0x1AC07FB000
```

The next action is a separately approved v5 RAM boot for read-only GPT,
filesystem and rootfs discovery verification.
