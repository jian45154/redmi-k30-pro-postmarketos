@echo off
setlocal
cd /d "%~dp0\.."
if not exist logs mkdir logs

echo Collecting Windows host environment...
(
  echo === DATE ===
  date /t
  time /t
  echo.
  echo === WINDOWS ===
  ver
  echo.
  echo === ADB PATH ===
  where adb
  echo.
  echo === FASTBOOT PATH ===
  where fastboot
  echo.
  echo === ADB VERSION ===
  adb version
  echo.
  echo === FASTBOOT VERSION ===
  fastboot --version
  echo.
  echo === WSL STATUS ===
  wsl --status
  echo.
  echo === WSL DISTROS ===
  wsl -l -v
) > logs\windows-env.txt 2>&1

type logs\windows-env.txt
echo.
echo Wrote logs\windows-env.txt
endlocal
