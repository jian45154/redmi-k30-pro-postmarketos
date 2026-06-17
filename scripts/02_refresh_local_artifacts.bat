@echo off
setlocal
cd /d "%~dp0\.."

set DISTRO=Ubuntu-22.04
set PMB_SRC=/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream
set PMB_DST=/mnt/c/Users/microstar/Documents/lmi_linx/artifacts/wsl-pmaports

if not exist artifacts mkdir artifacts
if not exist artifacts\images mkdir artifacts\images
if not exist artifacts\wsl-pmaports mkdir artifacts\wsl-pmaports
if not exist artifacts\wsl-pmaports\device-xiaomi-lmi mkdir artifacts\wsl-pmaports\device-xiaomi-lmi
if not exist artifacts\wsl-pmaports\linux-xiaomi-lmi mkdir artifacts\wsl-pmaports\linux-xiaomi-lmi

echo Refreshing WSL pmaports files...
wsl -d %DISTRO% -- bash -lc "cp -a %PMB_SRC%/device-xiaomi-lmi/. %PMB_DST%/device-xiaomi-lmi/ && cp -aL %PMB_SRC%/linux-xiaomi-lmi/. %PMB_DST%/linux-xiaomi-lmi/ && cp -f /home/microstar/.config/pmbootstrap_v3.cfg %PMB_DST%/pmbootstrap_v3.cfg && cp -f /home/microstar/.local/var/pmbootstrap/workdir.cfg %PMB_DST%/workdir.cfg"

echo Refreshing known image files...
if exist "\\wsl.localhost\Ubuntu-22.04\home\microstar\boot.img" copy /y "\\wsl.localhost\Ubuntu-22.04\home\microstar\boot.img" "artifacts\images\boot.img"
if exist "C:\Users\microstar\Downloads\[REC_BOOT]3.7.1_12-RedmiK30Pro-POCOF2Pro_v9.0_A15-lmi-skkk.img" copy /y "C:\Users\microstar\Downloads\[REC_BOOT]3.7.1_12-RedmiK30Pro-POCOF2Pro_v9.0_A15-lmi-skkk.img" "artifacts\images\"
if exist "C:\Users\microstar\Downloads\[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk_ef1ce3b4.zip" copy /y "C:\Users\microstar\Downloads\[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk_ef1ce3b4.zip" "artifacts\images\"

echo Done.
endlocal
