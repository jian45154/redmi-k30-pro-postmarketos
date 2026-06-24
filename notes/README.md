# Notes

Notes are historical evidence and working logs. Use
`docs/tracks/README.md` as the current navigation entry point.

## Current high-signal notes

- `wifi-bringup-live-2026-06-24.md` — downstream Wi-Fi bring-up from `D-v40`
  through verified `D-v43`.
- `archive-summary-2026-06-23.md` — stable downstream `D-v27` baseline summary.
- `hardware-enablement-queue-2026-06-23.md` — hardware work queue that led into
  the later downstream Wi-Fi sequence.
- `audio-bringup-analysis-2026-06-23.md` — audio/ADSP analysis.
- `power-sensors-status-2026-06-23.md` — battery, power, and sensor state.

## Historical repair sequence

`repair-phase*.md` files are chronological repair notes. They should not be
read as the current state unless a track index cites them.

Key downstream milestones:

- `repair-phase35` through `repair-phase39`: `D-v27` reproducible build,
  current-userdata boot, userdata write, and full RAM boot.
- `repair-phase40` through `repair-phase42`: persistent boot preflight, boot
  write, and display observation.
- `repair-phase43` through `repair-phase46`: full hardware check, enablement
  plan, reboot gate, and post-reboot stability for the `D-v27` baseline.

## Mainline records

Mainline/copydown progress is documented under `docs/release/` and
`docs/tracks/mainline.md`, not primarily in this directory.
