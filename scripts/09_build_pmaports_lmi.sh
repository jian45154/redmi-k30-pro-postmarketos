#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

cd /mnt/c/Users/microstar/Documents/lmi_linx
mkdir -p logs

echo "Building lmi pmaports packages."
echo "This does not flash, boot, erase, or format the phone."
echo "If sudo asks for a password, enter the Ubuntu password."
echo

{
  pmbootstrap checksum linux-xiaomi-lmi
  pmbootstrap checksum device-xiaomi-lmi
  pmbootstrap build linux-xiaomi-lmi
  pmbootstrap build device-xiaomi-lmi
} 2>&1 | tee logs/pmaports-build.txt
