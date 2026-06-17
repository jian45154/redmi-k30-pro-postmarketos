@echo off
setlocal
cd /d "%~dp0\.."
if not exist logs mkdir logs

set DISTRO=Ubuntu-22.04

echo Inspecting local boot/recovery images...
wsl -d %DISTRO% -- bash -lc "python3 /mnt/c/Users/microstar/Documents/lmi_linx/scripts/inspect_android_boot_images.py /mnt/c/Users/microstar/Documents/lmi_linx/artifacts/images" > logs\image-inspection.txt 2>&1

type logs\image-inspection.txt
echo.
echo Wrote logs\image-inspection.txt
endlocal
