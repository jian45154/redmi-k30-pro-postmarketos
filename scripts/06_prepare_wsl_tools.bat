@echo off
setlocal
set DISTRO=Ubuntu-22.04

echo This installs WSL build and inspection dependencies.
echo It may ask for the Ubuntu sudo password.
echo.

wsl -d %DISTRO% -- bash -lc "sudo apt update && sudo apt install -y git python3 python3-pip build-essential clang llvm lld flex bison bc libssl-dev device-tree-compiler android-sdk-libsparse-utils android-sdk-platform-tools-common repo unzip file cpio gzip xz-utils"

echo.
echo Re-run scripts\01_check_wsl_env.bat after this completes.
endlocal
