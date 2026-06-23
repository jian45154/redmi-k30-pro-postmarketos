# Firmware Inventory: Initial Requirements

Date: 2026-06-23 Australia/Sydney

This note records the firmware requirements inferred from the v27 runtime logs
and the first local attempt to inspect a LineageOS vendor image. It does not
publish proprietary firmware binaries.

## Runtime Evidence

Probe:

```sh
ssh -o BatchMode=yes -o ConnectTimeout=5 lmi@172.16.42.1 'sh -s' < scripts/32_firmware_service_probe.sh
```

Redacted log:

```text
logs/firmware-service-probe-v27-20260623.redacted.txt
```

Observed on v27:

- `/lib/firmware` contains only `regulatory.db` and `regulatory.db.p7s`.
- `/dev/subsys_adsp`, `/dev/subsys_cdsp`, `/dev/subsys_slpi`,
  `/dev/subsys_venus`, and `/dev/subsys_wlan` exist.
- `/dev/rmtfs0`, `/dev/rmtfs1`, `/dev/qrtr`, and `/dev/qrtr*` do not exist.
- `pd-mapper`, `rmtfs`, and `tqftpserv` services are installed but stopped.
- `qrtr-ns` and `bluetooth` OpenRC services do not exist.
- WLAN PCI endpoint `0000:01:00.0` has `enable=0`.
- Bluetooth only exposes `bt_power` rfkill and is soft-blocked.
- `/proc/asound/cards` reports no soundcards; `/dev/snd` only has `timer`.

## Required Firmware Candidates

| subsystem | expected file or group | evidence | publishable |
| :--- | :--- | :--- | :--- |
| Venus | `venus.mdt`, `venus.b*` | dmesg reports missing `venus.mdt` and failed Venus firmware download | no |
| Wi-Fi | `qca6390/amss20.bin`, `amss20.bin` fallback | CNSS logs name `qca6390/amss20.bin` and fallback `amss20.bin` | no |
| ADSP/audio | `adsp.mdt`, `adsp.b*`, audio DSP files | ADSP/subsys and audio PDR paths are present, but no ALSA card | no |
| CDSP | `cdsp.mdt`, `cdsp.b*` | CDSP reserved memory and subsys node are present | no |
| SLPI/SSC | `slpi.mdt` or `ssc.mdt`, matching segments | SLPI reserved memory and subsys node are present | no |
| IPA | `ipa_fws.*`, `ipa_uc.*` | IPA subsystem nodes are present in earlier hardware logs | no |
| GPU zap | `a650_zap.*` | `subsys_a650_zap` exists in earlier hardware logs | no |
| Bluetooth | QCA6390 BT `*.tlv`, `*.bin`, `*.hcd`, `bt_*` | `vendor:bt_qca6390` rfkill exists, no HCI adapter yet | no |

## Local Vendor Image Source

Known local source:

```text
/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.new.dat.br
/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.transfer.list
```

Conversion command:

```sh
scripts/34_extract_android_dat_partition.sh \
  "/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.new.dat.br" \
  "/mnt/c/Users/microstar/Latest ADB Fastboot Tool/lineage-23.2-20260422-nightly-lmi-signed/vendor.transfer.list" \
  /tmp/lmi-lineage-vendor
```

Result:

- `vendor.new.dat.br` decompressed successfully.
- `vendor.transfer.list` converted successfully.
- raw image written to `/tmp/lmi-lineage-vendor/vendor.raw.img`.
- the raw image is EROFS.
- old p7zip mis-detected the raw image and could not extract it.
- read-only kernel mount failed in this environment with `Permission denied`.

Next requirement:

- inspect `/tmp/lmi-lineage-vendor/vendor.raw.img` with `dump.erofs`,
  `erofsfuse`, a host with EROFS mount support, or another read-only EROFS
  extractor;
- then run `scripts/33_firmware_inventory.sh` against the extracted file tree
  and replace this initial requirement table with file-level hashes.

## Packaging Direction

Do not commit firmware binaries. Add a local-only firmware package or staging
directory later with:

- a manifest of expected files;
- sha256 hashes;
- source image or partition provenance;
- install targets under `/lib/firmware`;
- explicit notes that binaries are proprietary and local-only.
