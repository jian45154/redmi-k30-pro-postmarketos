@echo off
setlocal
cd /d "%~dp0\.."
if not exist logs mkdir logs

set DISTRO=Ubuntu-22.04
set WSL_PATH_EXPORT=export PATH=/home/microstar/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin;

echo Checking WSL distro %DISTRO%...
(
  echo === OS ===
  wsl -d %DISTRO% -- uname -a
  wsl -d %DISTRO% -- cat /etc/os-release
  echo.
  echo === DISK ===
  wsl -d %DISTRO% -- df -h / /home
  echo.
  echo === MEMORY ===
  wsl -d %DISTRO% -- free -h
  echo.
  echo === CORE TOOL VERSIONS ===
  wsl -d %DISTRO% -- git --version
  wsl -d %DISTRO% -- python3 --version
  wsl -d %DISTRO% -- bash -lc "%WSL_PATH_EXPORT% pmbootstrap --version"
  echo.
  echo === FOUND TOOL PATHS ===
  wsl -d %DISTRO% -- bash -lc "%WSL_PATH_EXPORT% which git python3 pip3 gcc clang make dtc mkbootimg fastboot adb pmbootstrap repo unzip || true"
  echo.
  echo === EXPECTED MISSING TOOL NOTES ===
  echo If a tool is absent from the list above, install it before build/flash work in WSL.
  echo For this project, clang, dtc, mkbootimg, fastboot, adb, repo, and unzip are important.
  echo.
  echo === PMBOOTSTRAP STATUS ===
  wsl -d %DISTRO% -- bash -lc "%WSL_PATH_EXPORT% pmbootstrap status"
  echo.
  echo === PMBOOTSTRAP CONFIG ===
  wsl -d %DISTRO% -- cat /home/microstar/.config/pmbootstrap_v3.cfg
) > logs\wsl-env.txt 2>&1

type logs\wsl-env.txt
echo.
echo Wrote logs\wsl-env.txt
endlocal
