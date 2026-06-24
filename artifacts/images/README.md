# Image Artifacts

This directory contains local image artifacts and manifests from both project
tracks. Large binary images may be local-only or gitignored; manifests are the
stable evidence to cite.

## Version labels

- Downstream artifacts use canonical labels `D-vNN`.
- Mainline/copydown artifacts use canonical labels `M-rNN`.
- Existing filenames keep their historical names. New notes should include the
  canonical label alongside the filename.

## Downstream manifests

| Canonical | Manifest pattern | Meaning |
| --- | --- | --- |
| `D-v27` | `pmos-lmi-v27-rndis-usbid-full-20260623.manifest` | Verified downstream boot/rootfs/RNDIS/SSH baseline. |
| `D-v28` | `pmos-lmi-v28-hwtools-full-20260623.manifest` | Hardware tools rootfs. |
| `D-v29`-`D-v32` | `pmos-lmi-v29*` through `pmos-lmi-v32*` | RMTFS/CNSS/initfs firmware experiments. |
| `D-v33`-`D-v39` | `pmos-lmi-v33*` through `pmos-lmi-v39*` | SSH-first and early downstream Wi-Fi bring-up experiments. |
| `D-v40`-`D-v42` | `pmos-lmi-v40*` through `pmos-lmi-v42*` | CNSS property shim, QRTR nameservice, WLAN config path. |
| `D-v43` | `pmos-lmi-v43-downstream-wlan-mac-persist-full-20260624.manifest` | First verified Wi-Fi success with persisted MAC path. |
| `D-v44`-`D-v46` | `pmos-lmi-v44*` through `pmos-lmi-v46*` | Cleanup builds after Wi-Fi success. |

## Mainline artifacts

Mainline release bundles are primarily tracked under `docs/release/` and
`/tmp/lmi-release-*` paths rather than committed large image files here.

| Canonical | Evidence | Meaning |
| --- | --- | --- |
| `M-r6` | `docs/release/lmi-r6-bootmem-release-manifest-20260624.md` | Bootmem copydown release bundle. |
| `M-r7` | `docs/release/lmi-r7-earlydebug-build-result-20260624.md` | Early-debug boot-only bundle. |

## Caution

Do not infer that a binary image is safe to flash from its presence in this
directory. Use the matching manifest, track index, and approval-required command
sheet before any hardware action.
