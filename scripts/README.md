# Scripts

Scripts are grouped by historical sequence and by project track. Existing file
names are preserved because many notes cite them directly.

## Downstream sequence (`D-vNN`)

| Range | Purpose |
| --- | --- |
| `00`-`09` | Host, WSL, USB, source, and initial pmaports setup. |
| `10`-`24` | Early HTTP/initramfs/rootfs diagnostics through `D-v24`. |
| `25`-`31` | `D-v27` persistent boot, display checks, hardware checks, and `D-v28` hardware tools. |
| `32`-`39` | Firmware service, inventory, display/audio/power/network probes. |
| `70`-`72` | Downstream SSH/Wi-Fi build, sidecar monitor, and staged downstream Wi-Fi test helpers. |

## Mainline/copydown sequence (`M-rNN`)

| Range | Purpose |
| --- | --- |
| `40` | Prepare the external mainline overlay in a temporary pmbootstrap cache. |
| `45`-`47` | Build, verify, and bundle copydown boot images. |
| `48`-`58` | Fastbootd preflight, approval sheets, rollback scan, staged write, monitor, and release docs. |
| `59`-`69` | Static CI, guarded fastbootd/reboot helpers, release refresh, readiness audit, and mainline progress/resource loops. |

## Naming rule for new scripts

Prefer explicit track names in new scripts:

- `downstream_vNN_<action>.sh` for downstream work.
- `mainline_rNN_<action>.sh` for mainline/copydown work.

Keep destructive or hardware-state-changing commands behind an explicit,
exact-scope approval gate. Persistent partition writes retain their fresh
per-action confirmation. The D110 RAM-boot helper instead uses one approval
bound to the current Codex thread, helper, policy, image, tool, host boot, and
device; every execute invocation still performs a fresh read-only preflight
and an internal single-use attempt ticket.

The complete D110 authorization and revocation contract is documented in
[`docs/lmi-d110-session-approval.md`](../docs/lmi-d110-session-approval.md).
