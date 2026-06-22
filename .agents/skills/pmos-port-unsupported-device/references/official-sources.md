# Official sources and freshness

## Source priority

Use official sources in this order:

1. Current postmarketOS documentation linked below.
2. Current `pmbootstrap` and `pmaports` source code.
3. Device package examples for similar SoC, storage, boot-image, and partition layouts.
4. Project observations and logs.

Do not treat forum posts, vendor blogs, generic Android flashing guides, or another device's package as authoritative. Use them only to form hypotheses that are verified against official code and the target device.

## Canonical official entry points

- Porting: https://postmarketos.org/porting/
- Partition layout: https://postmarketos.org/partitions
- Recovery ZIP: https://postmarketos.org/recoveryzip
- Device information: https://postmarketos.org/deviceinfo
- Device packages: https://postmarketos.org/devicepkg
- pmbootstrap repository: https://gitlab.postmarketos.org/postmarketOS/pmbootstrap
- pmaports repository: https://gitlab.postmarketos.org/postmarketOS/pmaports

Before acting on hardware, open the current official pages and compare their commands with `pmbootstrap <command> --help`. Documentation and CLI behavior can change.

## Verified local official snapshots

The skill was authored on 2026-06-18 from official local Git checkouts because direct web access was blocked by the environment's network policy.

- `pmbootstrap` origin: `https://gitlab.postmarketos.org/postmarketOS/pmbootstrap.git`
- `pmbootstrap` commit: `eead21aac30bb5482c91e8bb1c63a1cdf8247b3e`
- `pmbootstrap` version: `3.10.1`
- `pmaports` origin: `https://gitlab.postmarketos.org/postmarketOS/pmaports.git`
- `pmaports` commit: `a325d6d06d5b2dedf5f17a96d2a68acd3cc75cd0`

The local source directly confirmed:

- `pmbootstrap init` directs new unsupported devices to the official porting guide.
- `pmbootstrap install` exposes `--sector-size {512,2048,4096}` and image-layout options.
- `pmbootstrap flasher` separates temporary `boot` from `flash_kernel`, `flash_rootfs`, `flash_dtbo`, and `flash_vbmeta`.
- `pmaports/deviceinfo_schema.toml` defines boot-image, partition, DTB, rootfs-sector, module, and kernel-cmdline fields independently.
- `postmarketos-initramfs/init_functions.sh` implements `pmos.debug-shell`, `/pmOS_init.log`, telnet on port 23, and `pmos_continue_boot`.

When a current checkout differs, follow the current official code and update this reference rather than preserving stale commands.

