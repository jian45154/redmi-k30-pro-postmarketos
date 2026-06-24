# RAM-only v28 RMTFS/CNSS result

Date: 2026-06-23

Artifact booted with `fastboot boot`:

- `artifacts/images/pmos-lmi-v28-kernel-currentroot-20260623.img`
- boot sha256: `a4f7875969fcdb7a4e51297852cfa4d852293d2cf2d55dda6c72c1991a24abbf`
- rootfs: existing v27 userdata/rootfs, no partition writes

## Result

The RAM-only boot succeeded and reached SSH over USB/RNDIS.

Kernel:

- `Linux xiaomi-lmi 4.19.325-cip128-st12-perf #8-postmarketOS`
- `CONFIG_QCOM_RMTFS_MEM=y`
- `CONFIG_QRTR=y`
- `CONFIG_CNSS2=y`
- `CONFIG_QCA_CLD_WLAN=y`
- `CONFIG_QCA_CLD_WLAN_PROFILE="qca6390"`

Missing device nodes:

- `/dev/qcom_rmtfs_mem*`
- `/dev/qcom_rmtfs_uio*`
- `/dev/rmtfs*`
- `/dev/qrtr*`
- `/dev/mem`

Foreground `rmtfs -P -r` still fails:

```text
failed to open /dev/qcom_rmtfs_mem1: No such file or directory
falling back to uio access
failed to open /dev/qcom_rmtfs_uio1: No such file or directory
falling back to /dev/mem access
failed to open /dev/mem
```

## Root cause

`qcom_rmtfs_mem` is present in the kernel, but there is no platform device bound
to `/sys/bus/platform/drivers/qcom_rmtfs_mem`.

Both the stock backup DTB from
`/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img`
and the current pmos v28 DTB lack a `compatible = "qcom,rmtfs-mem"` reserved
memory node. They do contain:

```dts
pil_wlan_fw_region@86700000 {
	compatible = "removed-dma-pool";
	no-map;
	reg = <0x00 0x86700000 0x00 0x100000>;
};
```

The downstream binding for `drivers/soc/qcom/rmtfs_mem.c` requires a
reserved-memory node with `compatible = "qcom,rmtfs-mem"` and
`qcom,client-id = <1>` to create `/dev/qcom_rmtfs_mem1`.

## Follow-up staged

`linux-xiaomi-lmi` `pkgrel=8` stages `lmi-rmtfs-mem-node.patch`, changing the
0x86700000 no-map region to:

```dts
compatible = "qcom,rmtfs-mem";
qcom,client-id = <1>;
```

This is intended for another RAM-only boot validation before any partition
write.

Generated follow-up artifacts:

- `artifacts/images/pmos-lmi-v29-rmtfs-currentroot-20260623.img`
  - sha256: `771cce74e14cac225c3b2a5512f0170dd0317751876e3fbb27e861bb4cd73653`
  - purpose: RAM-only boot against the existing v27 rootfs
- `artifacts/images/xiaomi-lmi-v29-rmtfs-userdata-20260623.img`
  - sha256: `60944cb4d33c80f06dfda26bb55b03cf3c943291204d3a6c5900abbc4be6c68c`
  - purpose: full v29/rmtfs rootfs artifact, not used by the RAM-only test

Static DTB verification confirms the currentroot boot image contains:

```dts
pil_wlan_fw_region@86700000 {
	compatible = "qcom,rmtfs-mem";
	no-map;
	reg = <0x00 0x86700000 0x00 0x100000>;
	qcom,client-id = <0x01>;
};
```

## Remaining Wi-Fi blocker

CNSS probes the QCA6390 PCI device, then disables it. The current rootfs has
only regulatory database firmware:

```text
/lib/firmware/regulatory.db
/lib/firmware/regulatory.db.p7s
```

The kernel logs request `qca6390/amss20.bin` with fallback `amss20.bin`, so the
next network bring-up stage also needs a vetted firmware package source for lmi.

## Firmware source found

The device's existing stock `modem` partition is vfat and can be mounted
read-only. It contains the QCA6390 firmware requested by the downstream kernel:

```text
/tmp/fw-modem/image/qca6390/amss20.bin
/tmp/fw-modem/image/qca6390/m3.bin
/tmp/fw-modem/image/qca6390/regdb.bin
/tmp/fw-modem/image/qca6390/regdb_j11.bin
/tmp/fw-modem/image/qca6390/bdwlan.elf
/tmp/fw-modem/image/qca6390/bdwlan.e01 ... bdwlan.e18, bdwlan.e25
```

Key hashes from the mounted stock partition:

```text
3c4c0c04df036db96a33fe322fb7f5b1294aa606c040ee506c7e904ddd5e9459  amss20.bin
b2f804de850865a23905afe1b9b614f42f3af2951c927b8a144aed8e3b9c78ce  m3.bin
8a96951dea7a5fef2846a8330e859c471b8a688a358cb2c379853ecec2578419  regdb.bin
536859e4ebd5073ff32f56dd3dd06fae8177a564bd0492b079d7bc8b6fc5072f  regdb_j11.bin
a3ee9de2c77edd268c023eaae55a79177df5619ba2f0be252232919dae549f4f  bdwlan.elf
```

The stock `bluetooth` partition also contains QCA Bluetooth payloads:

```text
c6ac59eaa877786f0c883ce087816d8882e06f4850afd36ec1fcc5c2e0b72c5c  htbtfw10.tlv
008e83a926ccf9ddb18d788552cbbf0c107faf9c99d206baa39860fc619d1ea0  htbtfw20.tlv
```

`device-xiaomi-lmi` `pkgrel=8` adds `lmi-firmware-mount`, an OpenRC boot service
that mounts `/dev/disk/by-partlabel/modem` read-only at
`/mnt/vendor/firmware_mnt` and links `/lib/firmware/qca6390` to
`/mnt/vendor/firmware_mnt/image/qca6390`. This avoids committing proprietary
firmware blobs while satisfying the downstream firmware path
`qca6390/amss20.bin`.
