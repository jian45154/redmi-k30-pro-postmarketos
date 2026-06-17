@echo off
setlocal
cd /d "%~dp0\.."
if not exist logs mkdir logs

echo This script is read-only. It does not flash, boot, erase, or unlock anything.
echo Connect the phone over USB in either Android/LineageOS mode or fastboot mode.
echo.

(
  echo === DATE ===
  date /t
  time /t
  echo.
  echo === ADB DEVICES ===
  adb devices -l
  echo.
  echo === ADB BASIC PROPS ===
  adb shell getprop ro.product.device
  adb shell getprop ro.product.model
  adb shell getprop ro.build.version.release
  adb shell getprop ro.lineage.version
  adb shell getprop ro.boot.slot_suffix
  adb shell uname -a
  echo.
  echo === ADB CMDLINE ===
  adb shell cat /proc/cmdline
  echo.
  echo === ADB BLOCK BY-NAME ===
  adb shell ls -l /dev/block/by-name
) > logs\phone-adb.txt 2>&1

fastboot devices > logs\fastboot-devices.tmp 2>&1
(
  echo === FASTBOOT DEVICES ===
  type logs\fastboot-devices.tmp
  echo.
  echo === FASTBOOT GETVAR ALL ===
  echo Review this file before sharing. It may contain serial identifiers.
  findstr /r /c:".*[	 ]fastboot" logs\fastboot-devices.tmp >nul
  if errorlevel 1 (
    echo No fastboot device detected. Skipping fastboot getvar all.
  ) else (
    fastboot getvar all
  )
) > logs\phone-fastboot.txt 2>&1
del logs\fastboot-devices.tmp >nul 2>&1

type logs\phone-adb.txt
echo.
type logs\phone-fastboot.txt
echo.
echo Wrote logs\phone-adb.txt and logs\phone-fastboot.txt
echo Remove serial numbers or other private identifiers before sharing logs.
endlocal
