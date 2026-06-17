@echo off
setlocal
cd /d "%~dp0\.."
if not exist logs mkdir logs

set DISTRO=Ubuntu-22.04
set PMB_PATH=export PATH=/home/microstar/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin;

echo Building lmi pmaports packages in WSL.
echo This does not flash, boot, erase, or format the phone.
echo.
echo If sudo requires a password, this .bat may hang because it is non-interactive.
echo Prefer running scripts/09_build_pmaports_lmi.sh inside WSL.
echo.

wsl -d %DISTRO% -- bash -lc "%PMB_PATH% set -e; pmbootstrap checksum linux-xiaomi-lmi; pmbootstrap checksum device-xiaomi-lmi; pmbootstrap build linux-xiaomi-lmi; pmbootstrap build device-xiaomi-lmi" > logs\pmaports-build.txt 2>&1
if errorlevel 1 (
  type logs\pmaports-build.txt
  echo.
  echo Build failed. See logs\pmaports-build.txt
  exit /b 1
)

type logs\pmaports-build.txt
echo.
echo Build completed. See logs\pmaports-build.txt
endlocal
