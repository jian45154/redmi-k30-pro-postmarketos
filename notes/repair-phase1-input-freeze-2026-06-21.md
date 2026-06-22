# Repair Phase 1: Input Freeze

Operator: Lucien Auregin (ian)
Date: 2026-06-21 Australia/Sydney

## Scope

Local artifact hashing and pmaports source reconciliation only. No phone boot,
flash, erase, format, repartition or partition write was performed.

## Current postmarketOS Artifacts

```text
SHA256 934A7E018C8119D3C7101C55C161DFE7F8F2EAC921C5A47DA8B6E1047C3F2030
size   53264384
path   artifacts/images/pmos-lmi-boot.img

SHA256 BA0CD8EE2B25638C04310E8DC85BE6D5F87BE57514FBF7617CA38D7B98F9CFD2
size   53424128
path   artifacts/images/pmos-lmi-debug-boot.img
```

Active WSL build outputs:

```text
SHA256 57B07144EBB8CC69E0C334AC8BE3BE9A1543DF80262B006DB167FAEE00B80664
size   53424128
path   /home/microstar/.local/var/pmbootstrap/chroot_rootfs_xiaomi-lmi/boot/boot.img

SHA256 9263D2FD82BF73B11900454AC5B849A5EE8D40D4310E2FAB5E1F73688509D760
size   9308669
path   /home/microstar/.local/var/pmbootstrap/chroot_rootfs_xiaomi-lmi/boot/initramfs

SHA256 D4365A1D0B6B6804C4AF80BA46ACE7040B066383BDE865687CFC09BC8091B9E3
size   43231256
path   /home/microstar/.local/var/pmbootstrap/chroot_rootfs_xiaomi-lmi/boot/vmlinuz

SHA256 212D80826CEEF522AFF2D967082B5708D20DDCCC13AE322EDCE72412F1A06B51
size   874418
path   /home/microstar/.local/var/pmbootstrap/chroot_rootfs_xiaomi-lmi/boot/kona-v2.1-lmi.dtb

SHA256 320FC99EDA26C71B2D560675D54DE7343768271AC82521A7ADF84CA7A8E226B6
size   1760559104
path   /home/microstar/.local/var/pmbootstrap/chroot_native/home/pmos/rootfs/xiaomi-lmi.img
```

The Windows debug boot and active WSL boot have the same file size but different
SHA-256 values. The Windows file is an older copy and must not be treated as the
current diagnostic source. A new diagnostic artifact needs a new name and
manifest.

## Recovery Evidence

```text
SHA256 0C06AD2ACA2AB0D510E9D9C97BA31D35A514B9A3D15850B1C4A2121E55FA5CBF
size   134217728
path   C:/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-current-boot.img

SHA256 3514241DC1E72C1D52FCFC55DA6A463E36D19330645184BAAA67A1C7E4CC8168
size   9728
path   C:/Users/microstar/Latest ADB Fastboot Tool/lmi/device-backup/lmi-gpt.bin
```

`lmi-current-boot.img` is a boot rollback candidate pending provenance
confirmation. `lmi-gpt.bin` has incomplete GPT validation and is evidence only;
it is not approved as a restore image.

## Supplied Diagnostic And Mainline Artifacts

```text
SHA256 0D2F82E9FC958EDA17F151C0E38C04C1A0C3CB1C2D40516E6672DF01624F61C6
size   54071296
file   boot-pmos-http-rootfs-diagnostic.img

SHA256 0503CB164B306AF9674151EF0EDA544D51C9A5CCC249D4AA00282777B5CD7EBB
size   27402240
file   boot-linux-copydown-lmi.img

SHA256 5AC7D05C7BCED54833A028BED504BEF89E9787A5679F60AFB99A82E3790B0337
size   2114878
file   initramfs-sm8250-xiaomi-lmi.cpio.gz

SHA256 E88E92DBE3E4B3F6B33105AE53B14B7E2C878EBDB432496A5597DE6E8A8E5E2E
size   1153422364
file   ubuntu-24.04-arm64-console.ext4.sparse
```

The supplied initramfs archive does not match its adjacent manifest. The
supplied HTTP diagnostic image also omits the 4096-sector metadata and assumes
`/dev/sda34`; it will not be RAM-booted unchanged.

## Authoritative pmaports Sources

The repository mirrors were synchronized line-by-line with the active WSL
packages and verified byte-identical.

```text
SHA256 8508BF4FC427A4FBBCCD49ED37C1B276F58C01C8074E977DA96CFD83151EC840
path   artifacts/wsl-pmaports/device-xiaomi-lmi/deviceinfo

SHA256 5DB7C6730EB76B84E94C04EB3C83A47B5E8382EAB9B5CDC3CE10595094BD54FC
path   artifacts/wsl-pmaports/device-xiaomi-lmi/APKBUILD

SHA256 8303D4AEE0447B4DC3F10630C496DBA32E9171C83516BCB73A98EB5EF64BCD0C
path   artifacts/wsl-pmaports/linux-xiaomi-lmi/APKBUILD
```

The authoritative device package now records:

```text
deviceinfo_dtb="qcom/kona-v2.1-lmi"
deviceinfo_rootfs_image_sector_size="4096"
deviceinfo_flash_fastboot_partition_rootfs="userdata"
```

The authoritative kernel package builds the premerged lmi DTB with
`fdtoverlay`. The device package includes `pd-mapper`, `rmtfs` and `tqftpserv`.

## Phase 1 Result

- Artifact identities: recorded.
- Active package source: reconciled with the repository mirror.
- Current debug image source: active WSL output, not the older Windows copy.
- Complete GPT rollback artifact: still missing.
- Known-good stock ROM/recovery provenance: still needs confirmation before any
  partition write.
- Next non-destructive task: construct and locally audit a corrected HTTP
  diagnostic initramfs and boot image.
