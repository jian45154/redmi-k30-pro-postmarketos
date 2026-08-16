#!/usr/bin/env bash
# Rebuild the embedded lmi-weston-sixrow-clients 14.0.2-r2 from source,
# unprivileged, and verify the payload bytes against the pinned session
# components.
#
# Validated 2026-08-15: reproduced both embedded sixrow binaries
# BYTE-IDENTICALLY — see
# docs/release/d114-p2-sixrow-r2-source-reproduction-2026-08-15.md.
#
# The r2 aport (APKBUILD pkgrel=2 + three patches) is taken from published
# git history at commit 1fbbc708eede2a67e68235185f4f77d1336c20cb — the
# tracked files/lmi-weston-sixrow/ tree has since moved to pkgrel=3, so the
# embedded revision is built from its exact recorded source, not from the
# current working tree. The build root is materialized from the recorded
# 199-package closure (config/lmi-weston-sixrow/build-root-closure-r2.manifest);
# point CACHE_DIR at a directory holding exactly those packages.
#
# The signing key affects only the .SIGN member of the produced .apk, never
# the payload bytes verified here.
#
# Requires (override via env): PROOT, PROOT_LIBS, QEMU_AARCH64, APK_STATIC,
# ABUILD_KEY, ABUILD_KEY_PUB, CACHE_DIR, DISTFILE (weston-14.0.2.tar.xz).
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
work=${WORK:-$repo/.work/sixrow-r2-build}
root=$work/root

APORT_COMMIT=1fbbc708eede2a67e68235185f4f77d1336c20cb
APORT_FILES="APKBUILD 0001-phone-input-terminal-text-input.patch
  0002-sixrow-control.patch 0003-sixrow-paged-touch.patch"
APKBUILD_SHA256=a42ab2a6d90dbab6972e002a2d4574e4178ca10a5d90154dedd17dde39cf490d

private_tools=$repo/private/lmi-p1/calibration/acquisition-root
APK_STATIC=${APK_STATIC:-$private_tools/work-proot-chroot2/apk.static}
PROOT=${PROOT:-$private_tools/proot-root/usr/bin/proot}
PROOT_LIBS=${PROOT_LIBS:-$private_tools/proot-root/usr/lib/x86_64-linux-gnu}
QEMU_AARCH64=${QEMU_AARCH64:-$private_tools/work-proot-chroot2/chroot_native-pre-rootfs-calibration/usr/bin/qemu-aarch64}
ABUILD_KEY=${ABUILD_KEY:-$private_tools/work-proot-chroot2/config_abuild/pmos@local-6a5d38f2.rsa}
ABUILD_KEY_PUB=${ABUILD_KEY_PUB:-$ABUILD_KEY.pub}
CACHE_DIR=${CACHE_DIR:-$repo/.work/pmbootstrap-sixrow/cache_apk_aarch64}
DISTFILE=${DISTFILE:-$repo/.work/pmbootstrap-sixrow/cache_distfiles/weston-14.0.2.tar.xz}

declare -A EXPECT=(
	[usr/libexec/lmi-p2-d114/weston-keyboard-sixrow]=d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a
	[usr/libexec/lmi-p2-d114/weston-terminal-sixrow]=6602f7ac8e0c11892eec1d9db0411397e95f704a1655b94e0885a1220962a8cf
)

for tool in "$APK_STATIC" "$PROOT" "$QEMU_AARCH64" "$ABUILD_KEY" "$ABUILD_KEY_PUB" "$DISTFILE"; do
	[ -e "$tool" ] || { echo "missing prerequisite: $tool (set the matching env var)" >&2; exit 1; }
done
[ -d "$CACHE_DIR" ] || { echo "missing CACHE_DIR: $CACHE_DIR" >&2; exit 1; }

rm -rf "$work"
mkdir -p "$work/aport" "$root"

echo "extracting the r2 aport from git $APORT_COMMIT"
for f in $APORT_FILES; do
	git -C "$repo" show "$APORT_COMMIT:files/lmi-weston-sixrow/$f" > "$work/aport/$f"
done
echo "$APKBUILD_SHA256  $work/aport/APKBUILD" | sha256sum -c --quiet \
	|| { echo "extracted APKBUILD does not match the attested sha256" >&2; exit 1; }

echo "materializing the aarch64 build root from $CACHE_DIR"
unshare -r sh -c "'$APK_STATIC' add --root '$root' \
	--initdb --arch aarch64 --allow-untrusted '$CACHE_DIR'/*.apk" \
	> "$work/apk-add.log" 2>&1 || true

cp "$QEMU_AARCH64" "$root/usr/bin/qemu-aarch64-static"
mkdir -p "$root/home/pmos/.abuild" "$root/var/cache/distfiles" \
         "$root/home/pmos/build/lmi-weston-sixrow" "$root/home/pmos/packages" \
         "$root/etc/apk/keys"
cp "$ABUILD_KEY" "$ABUILD_KEY_PUB" "$root/home/pmos/.abuild/"
printf 'PACKAGER_PRIVKEY="/home/pmos/.abuild/%s"\n' "$(basename "$ABUILD_KEY")" \
	> "$root/etc/abuild.conf"
cp "$ABUILD_KEY_PUB" "$root/etc/apk/keys/"
cp "$DISTFILE" "$root/var/cache/distfiles/"
cp "$work/aport"/* "$root/home/pmos/build/lmi-weston-sixrow/"

echo "building lmi-weston-sixrow-clients 14.0.2-r2 under proot/qemu (log: $work/abuild.log)"
# PROOT_NO_SECCOMP=1: proot's seccomp accelerator kills the qemu loader on
# WSL2 kernels; plain ptrace translation works.
env "LD_LIBRARY_PATH=$PROOT_LIBS" PROOT_NO_SECCOMP=1 \
	"$PROOT" -0 -r "$root" -q "$QEMU_AARCH64" \
	-b /proc -b /dev -w /home/pmos/build/lmi-weston-sixrow /bin/sh -c '
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export SOURCE_DATE_EPOCH=1785283200
export ABUILD_LAST_COMMIT=sixrow-r2-reproduction
export SRCDEST=/var/cache/distfiles
export REPODEST=/home/pmos/packages
/bin/busybox --install -s
grep -q "^abuild:" /etc/group || addgroup -S abuild
abuild -F -d
' > "$work/abuild.log" 2>&1

out=$(find "$root/home/pmos/packages" -name 'lmi-weston-sixrow-clients-14.0.2-r2.apk' | head -1)
[ -n "$out" ] || { echo "build produced no r2 apk; see $work/abuild.log" >&2; exit 1; }
echo "built: $out"
sha256sum "$out"

echo "verifying payload bytes against the pinned session components:"
status=0
for member in "${!EXPECT[@]}"; do
	want=${EXPECT[$member]}
	got=$(tar -xzOf "$out" "$member" 2>/dev/null | sha256sum | cut -d' ' -f1)
	if [ "$got" = "$want" ]; then
		echo "  REPRODUCED  $member ($got)"
	else
		echo "  DIFFERS     $member (built $got, pinned $want)" >&2
		status=1
	fi
done
exit $status
