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
