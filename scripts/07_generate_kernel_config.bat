@echo off
setlocal
cd /d "%~dp0\.."

set DISTRO=Ubuntu-22.04
set COMMIT=a5b3099017ae581aae8bf597b2f9c8c765026af1
set SRC=/home/microstar/lmi_linx_kernel/android_kernel_xiaomi_sm8250
set OUT=/home/microstar/lmi_linx_kernel/out-xiaomi-lmi
set DEST=/mnt/c/Users/microstar/Documents/lmi_linx/artifacts/wsl-pmaports/linux-xiaomi-lmi/config-xiaomi-lmi.aarch64

echo This fetches the pinned LineageOS kernel source and generates a merged config.
echo It does not build the kernel and does not touch the phone.
echo.

wsl -d %DISTRO% -- bash -lc "set -e; mkdir -p /home/microstar/lmi_linx_kernel; if [ ! -d %SRC%/.git ]; then git clone https://github.com/LineageOS/android_kernel_xiaomi_sm8250.git %SRC%; fi; cd %SRC%; git fetch --depth 1 origin %COMMIT%; git checkout --detach %COMMIT%; rm -rf %OUT%; mkdir -p %OUT%; ./scripts/kconfig/merge_config.sh -m -O %OUT% arch/arm64/configs/vendor/kona-perf_defconfig arch/arm64/configs/vendor/debugfs.config arch/arm64/configs/vendor/xiaomi/sm8250-common.config arch/arm64/configs/vendor/xiaomi/lmi.config; make O=%OUT% ARCH=arm64 olddefconfig; cp %OUT%/.config %DEST%"
if errorlevel 1 (
  echo.
  echo Failed to generate final kernel config.
  echo Install missing WSL dependencies with scripts\06_prepare_wsl_tools.bat, then retry.
  exit /b 1
)

echo.
echo Generated artifacts\wsl-pmaports\linux-xiaomi-lmi\config-xiaomi-lmi.aarch64
endlocal
