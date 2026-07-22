# D114 downstream pmaports (P2 most-complete-image track)

Source packages for the D114 P2 rootfs rebuilds. This directory is the
version-controlled home of the downstream device/kernel recipes that the
D114 track builds with `pmbootstrap`; sync it into the pmbootstrap cache
before building (see `scripts/74_build_pmos_d114_r2_rootfs.sh`).

Do NOT confuse this tree with `artifacts/wsl-pmaports/`:

- `artifacts/wsl-pmaports/` is the **P1 installer's frozen input**
  (device r107, kernel r8). The P1 sealed builder pins that tree member
  by member (`scripts/lmi_p1/build.py`, `config/lmi-p1/source-lock.json`)
  and its seal signatures bind the exact bytes. It must not change.
- `artifacts/d114-pmaports/` (this tree) carries the D114 track:
  - `device-xiaomi-lmi` **r144**: imported from the most complete r143
    (Windows-side `lmi_linx` project copy) plus the two missing default
    runlevel links for `lmi-cnss-fs-ready` and `lmi-wlan-on` — the exact
    root cause of wlan0 never appearing (firmware/driver/CNSS were all
    ready but nothing wrote ON to /dev/wlan). Includes lmi-rootctl (+
    sudoers), pd-mapper/seatd runlevels, splash/power-panel/weston
    service foundation.
  - `linux-xiaomi-lmi` **r15**: the kernel recipe that built the
    hardware-validated D110 normalboot (2b264d64, `v110-bpf-fs-context-
    enoparam-r15`); checksummed with exact sha512 entries (no SKIP).

History note: device r108–r142 sources were lost because only the
pmbootstrap cache was updated build-to-build and the cache kept being
overwritten from the (stale) workspace copy. This tracked directory
exists so D114 recipes can never be lost that way again.
