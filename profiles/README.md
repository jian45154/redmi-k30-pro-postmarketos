# Persistent-write profiles

This directory contains the small, reviewable JSON profiles used by the sole
governance-v4 persistent-authorization path. A profile must be committed and
byte-identical to `HEAD` before the owner can run `authorize-profile`.

Images themselves must **not** be committed. Their repository-relative paths
normally point into an ignored local directory such as `private/`; the profile
records their exact SHA-256 and byte size.

Minimal shape for one target:

```json
{
  "schema_version": 1,
  "release": "D-vNN",
  "boot": {
    "path": "private/reviewed/candidate-boot.img",
    "sha256": "<64 lowercase hex characters>",
    "size": 123
  },
  "rollback": {
    "target": "boot",
    "path": "private/reviewed/distinct-rollback-boot.img",
    "sha256": "<different 64 lowercase hex characters>",
    "size": 123
  }
}
```

Replace `boot` with `userdata`, `dtbo`, or `vbmeta` as appropriate. The
rollback target must match, its hash must differ from the candidate, and both
local files must match the recorded hash and size.

After review and commit, the owner records the authorization with:

```sh
python3 scripts/bringup_loop.py authorize-profile \
  --profile profiles/<reviewed-profile>.json \
  --target <boot|userdata|dtbo|vbmeta> \
  --note "<what was reviewed>"
```

This command is host-only. It never creates a claim or contacts the device.
