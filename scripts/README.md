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
| `70`-`72` | Downstream SSH/Wi-Fi build, sidecar monitor, and staged downstream Wi-Fi test helpers. The `72` gate's Python bodies live in `lmi_d110_session.py`, pinned by SHA-256 inside `72` (see "Re-pinning the D110 session module" below). |
| `74` | SSH protocol acceptance with no explicit remote mutation; mocked tests cover logic only, and hardware claims require captured real-device evidence. |

## Mainline/copydown sequence (`M-rNN`)

| Range | Purpose |
| --- | --- |
| `40` | Prepare the external mainline overlay in a temporary pmbootstrap cache. |
| `45`-`47` | Build, verify, and bundle copydown boot images. |
| `48`-`58`, `60`-`64`, `66`-`67` | Retired M-r6/M-r7 execution, generation, readiness, and monitoring chain; removed after governance v4 consolidation. |
| `59`, `65` | Static release CI and the governance safety lint. |
| `68`-`69` | Read-only mainline host progress and resource-audit loops. |

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

`scripts/bringup_loop.py` is the only current governance authority. The owner
records a persistent profile with its host-only `authorize-profile` command;
every device state change then uses a separate experiment and one-shot claim.
Do not add a parallel approval workflow.

Keep destructive or hardware-state-changing commands behind that exact-scope
gate. The D110 RAM-boot helper temporarily uses one transition approval
bound to the current Codex thread, helper, policy, image, tool, host boot, and
device; every execute invocation still performs a fresh read-only preflight
and an internal single-use attempt ticket.

The complete D110 authorization and revocation contract is documented in
[`docs/lmi-d110-session-approval.md`](../docs/lmi-d110-session-approval.md).

## Re-pinning the D110 session module

`scripts/72_stage_downstream_ssh_wifi_test.sh` no longer embeds its Python
verifier/grant/receipt code as heredocs; the code lives in
`scripts/lmi_d110_session.py` and the gate refuses to run unless that file
matches the literal `TRUSTED_SESSION_MODULE_SHA256` pin inside `72`. After any
reviewed change to `scripts/lmi_d110_session.py`:

1. Recompute the hash: `sha256sum scripts/lmi_d110_session.py`.
2. Replace the value of `TRUSTED_SESSION_MODULE_SHA256` in
   `scripts/72_stage_downstream_ssh_wifi_test.sh` with the new digest.
3. Run `python3 -m unittest tests.lmi_p1.test_d110_session_module` — it
   asserts the pin equals the real file hash — and
   `python3 -m unittest tests.lmi_p1.test_hardware_helper_safety`.

Never update the pin without reviewing the module diff; the pin is what makes
the on-disk module as tamper-evident as the former in-script heredocs.
