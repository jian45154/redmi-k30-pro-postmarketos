@echo off
setlocal
cd /d "%~dp0\.."

set DISTRO=Ubuntu-22.04
set SRC=/mnt/c/Users/microstar/Documents/lmi_linx/artifacts/wsl-pmaports
set DST=/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream

echo Syncing local pmaports edits back into WSL pmbootstrap pmaports...
wsl -d %DISTRO% -- bash -lc "set -e; cp -a %SRC%/device-xiaomi-lmi/. %DST%/device-xiaomi-lmi/; cp -a %SRC%/linux-xiaomi-lmi/. %DST%/linux-xiaomi-lmi/"
if errorlevel 1 exit /b 1

echo Done.
endlocal
