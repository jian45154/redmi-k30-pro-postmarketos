# Firmware Inventory: LineageOS Dynamic Partitions

Date: 2026-06-23 Australia/Sydney

This note records the publishable inventory from local LineageOS images. It
does not publish proprietary firmware binaries.

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

## Search Result

Local LineageOS dynamic partitions inspected:

- `vendor.new.dat.br`
- `odm.new.dat.br`
- `product.new.dat.br`
- `system_ext.new.dat.br`

Useful firmware found:

- IPA firmware: `ipa_fws.*`, `ipa_uc.*`
- Adreno GPU zap firmware: `a650_zap.*`

Not found in these dynamic partitions:

- Wi-Fi firmware named `qca6390/amss20.bin`, `amss20.bin`, `bdwlan*`,
  `qwlan*`, or similar.
- QCA6390 Bluetooth payloads named `*.tlv`, `*.hcd`, `bt_*`, or similar.
- Full ADSP/CDSP/SLPI/Venus modem-style firmware groups.

Conclusion: the current LineageOS OTA dynamic partitions are not sufficient for
Wi-Fi bring-up. The next source to inspect is an lmi-specific firmware package
or read-only dumps of firmware-bearing partitions such as modem/bluetooth from a
known-good stock image. Do not use the unrelated local `capricorn` NON-HLOS
image.

## Required Firmware Candidates

| subsystem | expected file or group | current status | publishable |
| :--- | :--- | :--- | :--- |
| Venus | `venus.mdt`, `venus.b*` | not found in inspected dynamic partitions | no |
| Wi-Fi | `qca6390/amss20.bin`, `amss20.bin` fallback | not found in inspected dynamic partitions | no |
| ADSP/audio | `adsp.mdt`, `adsp.b*`, audio DSP files | not found in inspected dynamic partitions | no |
| CDSP | `cdsp.mdt`, `cdsp.b*` | not found in inspected dynamic partitions | no |
| SLPI/SSC | `slpi.mdt` or `ssc.mdt`, matching segments | not found in inspected dynamic partitions | no |
| IPA | `ipa_fws.*`, `ipa_uc.*` | found in LineageOS `vendor` | no |
| GPU zap | `a650_zap.*` | found in LineageOS `vendor` | no |
| Bluetooth | QCA6390 BT `*.tlv`, `*.bin`, `*.hcd`, `bt_*` | not found in inspected dynamic partitions | no |

## LineageOS Vendor File Inventory

| subsystem | source path | target path | size | sha256 | publishable |
| :--- | :--- | :--- | ---: | :--- | :--- |
| ipa | `etc/init/ipa_fws.rc` | `/lib/firmware/ipa_fws.rc` | 173 | `20eff0d45b053323d7e53888dd188b0a2f7c6ea9080bda85b79e4d88d04cedd0` | local-only |
| gpu-zap | `firmware/a650_zap.b00` | `/lib/firmware/a650_zap.b00` | 148 | `ec9b9d5a67456384809624b14a00d15d36297e5f2e75728504cd872bc95e0947` | local-only |
| gpu-zap | `firmware/a650_zap.b01` | `/lib/firmware/a650_zap.b01` | 6712 | `e40e95a8a036591e2ed4eb1c0058bfa04a20f63e5de9ceec452a1278953e9e41` | local-only |
| gpu-zap | `firmware/a650_zap.b02` | `/lib/firmware/a650_zap.b02` | 1676 | `a415e5452fa8f597670a6e51010e97bfabca7d20fbce8044caed64d9d5873113` | local-only |
| gpu-zap | `firmware/a650_zap.elf` | `/lib/firmware/a650_zap.elf` | 13964 | `d6cc281beb3b94d16a99b002ae26a7cab9d60481975d40dd60e5a2c24fe21a09` | local-only |
| gpu-zap | `firmware/a650_zap.mdt` | `/lib/firmware/a650_zap.mdt` | 6860 | `2458df52f746782f179d01e727be01d107a75ff1096c143168952203d4b5ee7a` | local-only |
| ipa | `firmware/ipa_fws.b00` | `/lib/firmware/ipa_fws.b00` | 212 | `7c13550da75df1080e4db8546281c0077f4a749ac239c611ec0bfadf33581177` | local-only |
| ipa | `firmware/ipa_fws.b01` | `/lib/firmware/ipa_fws.b01` | 6808 | `e9c7fafa57905a7d2d4cc973a80978f5b3901cedfe8849acf0aab05d40dd62a7` | local-only |
| ipa | `firmware/ipa_fws.b02` | `/lib/firmware/ipa_fws.b02` | 19200 | `0d2bc176d166448bf601d3ad04f51f22214ebe4652d48b1d83b93e38a1bed255` | local-only |
| ipa | `firmware/ipa_fws.b03` | `/lib/firmware/ipa_fws.b03` | 128 | `14024088f436ebd24b097cb113b2177e12c939efdac0211d560c7cc498611507` | local-only |
| ipa | `firmware/ipa_fws.b04` | `/lib/firmware/ipa_fws.b04` | 560 | `08a996d4efe3ac0d4e4d8948d2a6bcc24fda5138c2e196f9568245fbafee62a3` | local-only |
| ipa | `firmware/ipa_fws.elf` | `/lib/firmware/ipa_fws.elf` | 37552 | `a3be3fc649944d05c28f9bcd8acebb5faebce0db9497c1f71b3456e4a77d181d` | local-only |
| ipa | `firmware/ipa_fws.mdt` | `/lib/firmware/ipa_fws.mdt` | 7020 | `97295b5e6a9f5d9225e15f918c0ed5ec5e2eb857644598184ab30e31d8b3f66c` | local-only |
| ipa | `firmware/ipa_uc.b00` | `/lib/firmware/ipa_uc.b00` | 148 | `e5e337f396e3d27e4ecf6306c1edd5268a9f58f4c89476f5c39d15b39bb52214` | local-only |
| ipa | `firmware/ipa_uc.b01` | `/lib/firmware/ipa_uc.b01` | 6712 | `e6daac6148ed1b061d002027527ad6734c15eba76d9aa1ea34a32429ef4e8860` | local-only |
| ipa | `firmware/ipa_uc.b02` | `/lib/firmware/ipa_uc.b02` | 35572 | `8a6deb4744d98bdef05878a968b2e300e22423b0a68be8f2d0ead0c0ed0d0261` | local-only |
| ipa | `firmware/ipa_uc.elf` | `/lib/firmware/ipa_uc.elf` | 47860 | `483c63b7ebbf48f8f9beb06087597f3648989693c68f74f5fce653c8cfa3359b` | local-only |
| ipa | `firmware/ipa_uc.mdt` | `/lib/firmware/ipa_uc.mdt` | 6860 | `7b5893cff1f23d60e4a225979ef036e54de4e22c9d50adc0e1d9adfd71cc70e4` | local-only |
