@echo off
setlocal
cd /d "%~dp0\.."

if not exist artifacts\kernel-source mkdir artifacts\kernel-source
if not exist artifacts\kernel-source\configs mkdir artifacts\kernel-source\configs
if not exist artifacts\kernel-source\device-tree-evidence mkdir artifacts\kernel-source\device-tree-evidence

set COMMIT=a5b3099017ae581aae8bf597b2f9c8c765026af1
set KERNEL_BASE=https://raw.githubusercontent.com/LineageOS/android_kernel_xiaomi_sm8250/%COMMIT%
set COMMON_BASE=https://raw.githubusercontent.com/LineageOS/android_device_xiaomi_sm8250-common/lineage-23.2
set LMI_BASE=https://raw.githubusercontent.com/LineageOS/android_device_xiaomi_lmi/lineage-23.2

echo Fetching pinned kernel config fragments and device-tree evidence...

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "Invoke-WebRequest '%KERNEL_BASE%/arch/arm64/configs/vendor/kona-perf_defconfig' -OutFile 'artifacts/kernel-source/configs/kona-perf_defconfig';" ^
  "Invoke-WebRequest '%KERNEL_BASE%/arch/arm64/configs/vendor/debugfs.config' -OutFile 'artifacts/kernel-source/configs/debugfs.config';" ^
  "Invoke-WebRequest '%KERNEL_BASE%/arch/arm64/configs/vendor/xiaomi/sm8250-common.config' -OutFile 'artifacts/kernel-source/configs/sm8250-common.config';" ^
  "Invoke-WebRequest '%KERNEL_BASE%/arch/arm64/configs/vendor/xiaomi/lmi.config' -OutFile 'artifacts/kernel-source/configs/lmi.config';" ^
  "Invoke-WebRequest '%COMMON_BASE%/BoardConfigCommon.mk' -OutFile 'artifacts/kernel-source/device-tree-evidence/BoardConfigCommon.mk';" ^
  "Invoke-WebRequest '%LMI_BASE%/BoardConfig.mk' -OutFile 'artifacts/kernel-source/device-tree-evidence/BoardConfig-lmi.mk'"

echo Done.
endlocal
