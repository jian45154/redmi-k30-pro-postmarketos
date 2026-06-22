# Repair Phase 6: K4.19 Userdata Rewrite

Operator: Lucien Auregin (ian)
Date: 2026-06-22 Australia/Sydney

## Authorization And Scope

Ian explicitly authorized: `确认重写 userdata 为 4.19 兼容镜像`.

Only `userdata` was rewritten. No command wrote any other partition.

## Final Preflight

```text
product=lmi
unlocked=yes
battery_voltage_mv=4382
is_userspace=no
max_download_size=805306368
partition_size_userdata=0x1AC07FB000
candidate=artifacts/images/xiaomi-lmi-userdata-4096-k419-20260622-sparse.img
candidate_size=934211144
candidate_sha256=B8B12435FAA70F3AB2EC380D6F82475349E5B68B40E4A517A60D5EB7AF57FE30
```

## Command And Result

```powershell
fastboot -S 700M flash userdata artifacts/images/xiaomi-lmi-userdata-4096-k419-20260622-sparse.img
```

```text
Sending sparse 'userdata' 1/2 (665026 KB)  OKAY [14.554s]
Writing 'userdata'                          OKAY [ 0.002s]
Sending sparse 'userdata' 2/2 (247289 KB)  OKAY [34.828s]
Writing 'userdata'                          OKAY [ 0.001s]
Finished. Total time: 49.908s
```

After the successful write, Windows continued to enumerate the bootloader and
reported a healthy driver. `fastboot devices` could list the device after a
stale process was terminated, but subsequent `getvar` returned `no link`.
Re-entering fastboot or reconnecting USB is required before the next RAM boot.

The next action is a separately approved v6 RAM boot to confirm that the 4.19
kernel can now mount `pmOS_root`.
