# device-xiaomi-lmi — Xiaomi POCO F2 Pro / Redmi K30 Pro

Mainline port (kernel `linux-postmarketos-qcom-sm8250-lmi`, SoC Qualcomm SM8250 / Snapdragon 865).

## Estado del hardware

Fuente: [wiki postmarketOS](https://wiki.postmarketos.org/wiki/Xiaomi_POCO_F2_Pro_/_Redmi_K30_Pro_(xiaomi-lmi))

### Funciona
- Pantalla (60 Hz, brillo), táctil
- Aceleración 3D (Adreno 650, requiere firmware a650 + a650-zap)
- WiFi (qca6391, requiere ath11k), Bluetooth (requiere qca)
- Audio (codec wcd9380 + altavoces tfa9874)
- Batería y carga, almacenamiento interno UFS
- USB OTG, NFC, flash LED, IR TX
- Sensores: acelerómetro, magnetómetro, luz ambiental (vía hexagonrpcd/SDSP)
- Cámara: **parcial**

### En progreso / experimental
- **Modem (SDX55 5G): habilitación en curso** — ver sección "Modem" más abajo.

### NO funciona
- **GPS: roto.**
- **Proximidad: roto.**
- **Haptics (vibración): roto.**

## Modem (SDX55 — EN PRUEBAS)

El POCO F2 Pro usa un módem externo **Qualcomm SDX55** conectado por **PCIe bus 1**
(no integrado en el SoC). A diferencia de lo que indicaba el wiki, mainline **sí
soporta** este módem:

- El driver `mhi_pci_generic` autodetecta el SDX55 por su PCI ID `17cb:0306`.
- Todos los drivers necesarios ya están en el kernel: `MHI_BUS`,
  `MHI_BUS_PCI_GENERIC`, `MHI_NET`, `QCOM_IPA`, `QRTR_MHI`, `WWAN`.
- El firmware operativo (`mpss`) reside en la flash interna del propio SDX55,
  por lo que **no** hace falta empaquetar blobs de modem en el host.

**Lo que faltaba:** el devicetree del lmi no habilitaba el bus PCIe del módem.
El patch `0001-sm8250-xiaomi-lmi-enable-sdx55-modem.patch` (en el paquete del
kernel) habilita `&pcie1` + `&pcie1_phy`.

### Cómo probar tras flashear

```sh
# 1. ¿Aparece el dispositivo PCIe del modem? (vendor 17cb, device 0306)
lspci | grep -i 17cb
dmesg | grep -iE "mhi|pci.*17cb|qcom-sdx55"

# 2. ¿Lo ve ModemManager?
mmcli -L
mmcli -m 0          # detalles del modem

# 3. Datos móviles (ajustar APN del operador):
mmcli -m 0 --enable
nmcli c add type gsm ifname '*' con-name internet apn TU_APN
```

> **Estado esperado:** detección del modem y datos móviles son lo más probable.
> **Llamadas/SMS (voz)** requieren VoLTE y aún son experimentales en Linux móvil
> incluso con el módem detectado — no garantizadas.
> El SDX55 además requiere [FCC unlock](https://modemmanager.org/docs/modemmanager/fcc-unlock/)
> en algunos operadores.

## Firmware

- Blobs QCOM (adsp, cdsp, slpi, venus, a650_zap, ipa_fws) + sensores: paquete `firmware-xiaomi-lmi`.
- Cirrus Logic (audio) y Focaltech (táctil): extraídos de `firmware-xiaomi-lmi-Tag.zip` (incluido en el árbol).

## Flasheo

```bash
pmbootstrap install
pmbootstrap export
fastboot flash boot boot.img
fastboot flash system xiaomi-lmi.img
fastboot reboot
```

## Debug primer boot

USB networking funciona desde el initramfs. Tras conectar por USB:
- initramfs: `telnet 172.16.42.1`
- sistema arrancado: `ssh user@172.16.42.1`

Revisar `dmesg` por el panel Samsung ams667 y el GPU Adreno 650 (a650-zap es el punto típico de fallo gráfico).

## Riesgo de mantenimiento

El kernel se obtiene de un fork personal (`yuweiyuan8/linux` tag `v6.19`/`lmi`).
El tarball fuente está cacheado, pero si el fork desaparece, recompilar requerirá
re-localizar los parches. Base upstream de referencia: proyecto `sm8250-mainline`.
