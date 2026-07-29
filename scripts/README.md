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
| `74` | SSH protocol acceptance with no explicit remote mutation; mocked tests cover logic only, and hardware claims require captured real-device evidence. |

## Mainline/copydown sequence (`M-rNN`)

| Range | Purpose |
| --- | --- |
| `40` | Prepare the external mainline overlay in a temporary pmbootstrap cache. |
| `45`-`47` | Build, verify, and bundle copydown boot images. |
| `48`-`58` | Fastbootd preflight, approval sheets, rollback scan, staged write, monitor, and release docs. |
| `59`-`69` | Static CI, guarded fastbootd/reboot helpers, release refresh, readiness audit, and mainline progress/resource loops. |

## Release pin registry

`lmi_release_pins.py` is the read-only registry of every hand-copied release
pin site (`verify` cross-checks all of them and exits nonzero listing each
mismatched or unreadable site; `list` prints the re-pin checklist).

## P1 sealed-build helpers

The Python modules under `scripts/lmi_p1/` implement the source-locked P1
builder and its host-side artifact gates. Offline-cache calibration is a
separate two-step workflow:

- `python3 -B -m scripts.lmi_p1.offline_cache_calibration prepare ...` writes
  only a private review draft;
- `python3 -B -m scripts.lmi_p1.offline_cache_calibration execute` accepts only
  the manually installed canonical authorization and writes only private
  candidate replay/attestation records plus a hash-bound execution receipt.

Neither command changes device state. Prepare never installs its own
authorization, and execute has no alternate authorization, verifier, or trust
pin options. The receipt binds accepted output bytes to a descriptor-held
snapshot, but does not claim that the unchanged pathname-based production
promoter consumed the held inode. Same-UID process-memory and post-exit
evidence modification require a stronger external trust boundary.

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
