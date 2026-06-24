# Project Tracks

This project now uses two explicit development tracks. Keep their version
numbers separate in new notes, manifests, and handoff text.

## Version labels

| Track | Canonical label | Legacy filenames | Meaning |
| --- | --- | --- | --- |
| Downstream | `D-vNN` | `vNN`, `downstream-vNN` | LineageOS 4.19 downstream kernel path. |
| Mainline | `M-rNN` | `rNN`, `mainline-rNN` | Mainline/copydown SM8250 path. |

Examples:

- `D-v43` means downstream `v43-downstream-wlan-mac-persist`.
- `D-v46` means downstream `v46-daemon-status-idempotent`.
- `M-r6` means mainline/copydown `r6-bootmem`.
- `M-r7` means mainline/copydown `r7-earlydebug`.

Existing filenames are not renamed. Use the canonical labels in new prose so
the two sequences do not appear to be one combined version line.

## Track indexes

- [Downstream track](downstream.md)
- [Mainline track](mainline.md)

## File placement

- Track-independent safety, release, and workflow documents stay in `docs/`.
- Mainline release records stay in `docs/release/`.
- Downstream live hardware notes stay in `notes/` unless promoted into `docs/`.
- Image manifests stay in `artifacts/images/`; see
  [artifacts/images/README.md](../../artifacts/images/README.md).
- Scripts stay in `scripts/`; see [scripts/README.md](../../scripts/README.md).
