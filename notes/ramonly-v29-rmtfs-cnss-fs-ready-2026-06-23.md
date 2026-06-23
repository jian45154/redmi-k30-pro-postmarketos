# RAM-only v29 RMTFS/CNSS fs_ready result

Date: 2026-06-23

Artifact booted with `fastboot boot`:

- `artifacts/images/pmos-lmi-v29-rmtfs-currentroot-20260623.img`
- boot sha256: `771cce74e14cac225c3b2a5512f0170dd0317751876e3fbb27e861bb4cd73653`
- rootfs: existing v27 userdata/rootfs, no partition writes

## Result

The RAM-only boot succeeded and reached SSH over USB/RNDIS after a slow service
start. The v29 DTB RMTFS change works:

```text
/proc/device-tree/reserved-memory/pil_wlan_fw_region@86700000/compatible:
qcom,rmtfs-mem

/proc/device-tree/reserved-memory/pil_wlan_fw_region@86700000/qcom,client-id:
00000000  00 00 00 01

/dev/qcom_rmtfs_mem1:
crw------- root root 237,1
```

The platform driver is bound:

```text
/sys/bus/platform/drivers/qcom_rmtfs_mem/86700000.pil_wlan_fw_region
```

Foreground `rmtfs -P -r` no longer reports the v28 failure path and remains
running until killed manually. This confirms the missing
`/dev/qcom_rmtfs_mem1` blocker is fixed.

## Firmware and CNSS live test

The stock `modem` partition was mounted read-only:

```text
/dev/disk/by-partlabel/modem on /mnt/vendor/firmware_mnt type vfat (ro,...)
```

`/lib/firmware/qca6390` was bind-mounted to
`/mnt/vendor/firmware_mnt/image/qca6390`. The requested downstream WLAN
firmware was present:

```text
/lib/firmware/qca6390/amss20.bin
/lib/firmware/qca6390/m3.bin
/lib/firmware/qca6390/regdb.bin
/lib/firmware/qca6390/bdwlan.elf
```

After starting `pd-mapper`, `tqftpserv`, and `rmtfs`, writing `1` to
`/sys/kernel/cnss/fs_ready` triggered the CNSS QCA6390 path:

```text
cnss: File system is ready, fs_ready is 1
cnss: Posting event: COLD_BOOT_CAL_START(5)
cnss: Assert WLAN_EN GPIO successfully
cnss: Resuming PCI link
cnss: Setting MHI state: INIT(0)
cnss: Setting MHI state: POWER_ON(2)
cnss: MHI status cb is called with reason MISSION_MODE(6)
cnss: Notify MHI to use already allocated images
```

This proves the firmware path plus `fs_ready` notification moves CNSS beyond
the earlier boot-time suspend.

## Remaining blocker

No wireless netdev is created yet:

```text
ip link: lo, bond0, dummy0, tunnels, usb0 only
iw dev: no output
/sys/class/wlan/wlan exists as a character device, not a netdev
/sys/kernel/cnss/subsys9/state: ONLINE
```

`rmtfs` and `pd-mapper` do not remain running under OpenRC in the current v27
rootfs, while `tqftpserv` and `wpa_supplicant` do. Follow-up testing on the
older `#7` kernel/rootfs showed another required userspace step: Android's Wi-Fi
HAL writes `ON` to `/dev/wlan`, which calls `hdd_driver_load()` in qcacld. pmOS
was not doing this.

On the old `#7` kernel, the sequence below proved that `/dev/wlan` reaches the
qcacld driver-load path:

```sh
mount -o ro /dev/disk/by-partlabel/modem /mnt/vendor/firmware_mnt
mount --bind /mnt/vendor/firmware_mnt/image/qca6390 /usr/lib/firmware/qca6390
rc-service tqftpserv start
rc-service pd-mapper start
rc-service rmtfs start
printf 1 > /sys/kernel/cnss/fs_ready
printf ON > /dev/wlan
```

That old kernel still has
`pil_wlan_fw_region@86700000 compatible = "removed-dma-pool"` and no
`/dev/qcom_rmtfs_mem1`, so its calibration timeout is not valid evidence against
the rmtfs DT fix:

```text
cnss: Start to wait for calibration to complete
cnss: Timeout (80000ms) waiting for calibration to complete
cnss: Calibration timed out, force shutdown
cnss: fatal: Timeout waiting for FW ready indication
```

The next investigation should retest the complete sequence on the v29 or later
RAM-only kernel where `/dev/qcom_rmtfs_mem1` exists:

- whether `lmi-wlan-on` creates `wlan0` after `lmi-cnss-fs-ready`;
- whether the driver needs a different board data/NV file selection after
  `amss20.bin` boots;
- whether moving to the mainline `ath11k_pci` path is lower risk than completing
  downstream CLD userspace bring-up.

## Staged package follow-up

`device-xiaomi-lmi` `pkgrel=9` adds:

- robust `/lib/firmware/qca6390` handling in `lmi-firmware-mount`, including
  bind-mounting when an empty directory already exists;
- `lmi-cnss-fs-ready`, an OpenRC service that writes `1` to
  `/sys/kernel/cnss/fs_ready` after firmware and Qualcomm services are started.

`device-xiaomi-lmi` `pkgrel=10` adds:

- `lmi-wlan-on`, an OpenRC service that writes `ON` to `/dev/wlan` after
  `lmi-cnss-fs-ready`;
- a default runlevel symlink for `lmi-wlan-on`.

The `device-xiaomi-lmi-1-r9.apk` build was verified to contain:

```text
etc/init.d/lmi-cnss-fs-ready
etc/init.d/lmi-firmware-mount
etc/runlevels/boot/lmi-firmware-mount
etc/runlevels/default/lmi-cnss-fs-ready
etc/runlevels/default/pd-mapper
etc/runlevels/default/rmtfs
etc/runlevels/default/tqftpserv
```

The `device-xiaomi-lmi-1-r10.apk` build was verified to contain:

```text
etc/init.d/lmi-cnss-fs-ready
etc/init.d/lmi-firmware-mount
etc/init.d/lmi-wlan-on
etc/runlevels/boot/lmi-firmware-mount
etc/runlevels/default/lmi-cnss-fs-ready
etc/runlevels/default/lmi-wlan-on
etc/runlevels/default/pd-mapper
etc/runlevels/default/rmtfs
etc/runlevels/default/tqftpserv
```
