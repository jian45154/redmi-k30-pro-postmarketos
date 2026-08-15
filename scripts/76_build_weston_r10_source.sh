#!/usr/bin/env bash
# Rebuild the D114 weston 14.0.2-r10 aport from source, unprivileged, and
# verify the payload bytes against the pinned session components.
#
# Validated 2026-08-15: this procedure reproduced all four pinned weston
# components of the D114 P2 image BYTE-IDENTICALLY from the public aport
# (notes/d80-weston-r10-aport/) — see
# docs/release/d114-p2-weston-r10-source-reproduction-2026-08-15.md.
#
# Method (same as the recorded six-row r4 build): a network-capable
# apk.static resolves and downloads the full aarch64 dependency closure from
# Alpine edge, materializes the build root under `unshare -r` (aarch64
# install scripts cannot run on the x86_64 host; their failures are
# tolerated and the essential ones are replayed), then proot -0 with
# qemu-aarch64 user-mode emulation runs `abuild -F -d`.
#
# The signing key affects only the .SIGN member of the produced .apk files,
# never the payload bytes verified here — downloaders may use any abuild
# key of their own.
#
# Requires (override via env):
#   APK_STATIC  network-capable apk-tools-static binary (>= 3.0)
#   PROOT       proot binary            PROOT_LIBS  its libtalloc dir
#   QEMU_AARCH64  qemu-aarch64 user-mode binary
#   ABUILD_KEY  abuild RSA private key   ABUILD_KEY_PUB  its .pub
#   DISTFILE    weston-14.0.2.tar.xz (sha512-pinned in the APKBUILD;
#               downloaded into the build root if absent)
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=${REPO:-$(dirname "$script_dir")}
aport=$repo/notes/d80-weston-r10-aport
work=${WORK:-$repo/.work/weston-r10-build}
root=$work/root
pkgs=$work/pkgs

private_tools=$repo/private/lmi-p1/calibration/acquisition-root
APK_STATIC=${APK_STATIC:-$work/tools/sbin/apk.static}
PROOT=${PROOT:-$private_tools/proot-root/usr/bin/proot}
PROOT_LIBS=${PROOT_LIBS:-$private_tools/proot-root/usr/lib/x86_64-linux-gnu}
QEMU_AARCH64=${QEMU_AARCH64:-$private_tools/work-proot-chroot2/chroot_native-pre-rootfs-calibration/usr/bin/qemu-aarch64}
ABUILD_KEY=${ABUILD_KEY:-$private_tools/work-proot-chroot2/config_abuild/pmos@local-6a5d38f2.rsa}
ABUILD_KEY_PUB=${ABUILD_KEY_PUB:-$ABUILD_KEY.pub}
DISTFILE=${DISTFILE:-}
MIRROR=${MIRROR:-https://dl-cdn.alpinelinux.org/alpine/edge}

# Constants of the validated reproduction (affect .apk metadata only, not
# the payload bytes):
SOURCE_DATE_EPOCH_PIN=1785283200
ABUILD_LAST_COMMIT_PIN=d80-weston-r10-aport

# The four pinned session components and their expected payload sha256
# (config/lmi-p2-d114/source-lock.json runtime.component_sha256):
declare -A EXPECT=(
	[weston-14.0.2-r10.apk!usr/bin/weston]=191703aa8da1d965fe7a2e7b4ec7ad7316c484cdc26ac77f31c015d6ee4bd45e
	[libweston-14.0.2-r10.apk!usr/lib/libweston-14.so.0.0.2]=2c7565771a3e4097cdaf3e240d5e1dece2cdff78227967153df6088164bde9cd
	[weston-backend-drm-14.0.2-r10.apk!usr/lib/libweston-14/drm-backend.so]=3d74572726b4c7cbbdf1abad75dbeeee6d76f08af766a8bba06f30aeaf617a2f
	[weston-shell-desktop-14.0.2-r10.apk!usr/lib/weston/desktop-shell.so]=e4996ef148957fbeaafd1c374611a4831a7afe74b6014e47869e445c88b6cf67
)

for tool in "$PROOT" "$QEMU_AARCH64" "$ABUILD_KEY" "$ABUILD_KEY_PUB"; do
	[ -e "$tool" ] || { echo "missing prerequisite: $tool (set the matching env var)" >&2; exit 1; }
done
[ -f "$aport/APKBUILD" ] || { echo "missing aport: $aport" >&2; exit 1; }

mkdir -p "$work"

if [ ! -x "$APK_STATIC" ]; then
	echo "fetching official apk-tools-static (APK_STATIC not provided)"
	mkdir -p "$work/tools" && (
		cd "$work/tools"
		curl -fsS "$MIRROR/main/x86_64/APKINDEX.tar.gz" -o idx.tar.gz
		tar -xzf idx.tar.gz APKINDEX
		v=$(grep -A1 '^P:apk-tools-static$' APKINDEX | sed -n 's/^V://p' | head -1)
		curl -fsS "$MIRROR/main/x86_64/apk-tools-static-$v.apk" -o apk-tools-static.apk
		tar -xzf apk-tools-static.apk sbin/apk.static
	)
fi

BASESET="busybox busybox-binsh alpine-baselayout alpine-keys apk-tools musl-utils abuild build-base git tar xz"
MAKEDEPENDS=$(sed -n '/^makedepends="/,/"/p' "$aport/APKBUILD" | sed 's/makedepends="//;s/"//' | tr -s '[:space:]' ' ')

if [ ! -f "$pkgs/.complete" ]; then
	echo "resolving and fetching the aarch64 dependency closure from $MIRROR"
	rm -rf "$pkgs" "$work/apkroot"
	mkdir -p "$pkgs" "$work/apkroot/etc/apk/keys"
	printf '%s/main\n%s/community\n' "$MIRROR" "$MIRROR" > "$work/apkroot/etc/apk/repositories"
	echo aarch64 > "$work/apkroot/etc/apk/arch"
	cp /usr/share/apk/keys/aarch64/*.pub "$work/apkroot/etc/apk/keys/" 2>/dev/null || true
	cp "$repo"/.claude/worktrees/d114-p2-r2/.work/pmbootstrap-sixrow/config_apk_keys/alpine-devel*.pub \
	   "$work/apkroot/etc/apk/keys/" 2>/dev/null || true
	ls "$work/apkroot/etc/apk/keys/" | grep -q alpine-devel || {
		echo "no Alpine signing keys available for index verification" >&2; exit 1; }
	unshare -r sh -c "
		set -e
		'$APK_STATIC' --root '$work/apkroot' --arch aarch64 add --initdb
		'$APK_STATIC' --root '$work/apkroot' update
		'$APK_STATIC' --root '$work/apkroot' fetch -R -o '$pkgs' $BASESET $MAKEDEPENDS
	" > "$work/fetch.log" 2>&1
	curl -fsS "$MIRROR/main/aarch64/APKINDEX.tar.gz" -o "$work/APKINDEX-main-aarch64.tar.gz"
	curl -fsS "$MIRROR/community/aarch64/APKINDEX.tar.gz" -o "$work/APKINDEX-community-aarch64.tar.gz"
	( cd "$work" && sha256sum APKINDEX-*.tar.gz > snapshot-indexes.sha256 )
	( cd "$pkgs" && sha256sum ./*.apk > ../pkgs.sha256 )
	date -u +%Y-%m-%dT%H:%M:%SZ > "$work/snapshot-fetched-at.txt"
	touch "$pkgs/.complete"
fi

echo "materializing the aarch64 build root"
rm -rf "$root"
mkdir -p "$root"
unshare -r sh -c "'$APK_STATIC' add --root '$root' \
	--initdb --arch aarch64 --allow-untrusted '$pkgs'/*.apk" \
	> "$work/apk-add.log" 2>&1 || true

cp "$QEMU_AARCH64" "$root/usr/bin/qemu-aarch64-static"
mkdir -p "$root/home/pmos/.abuild" "$root/var/cache/distfiles" \
         "$root/home/pmos/build/weston" "$root/home/pmos/packages" \
         "$root/etc/apk/keys"
cp "$ABUILD_KEY" "$ABUILD_KEY_PUB" "$root/home/pmos/.abuild/"
printf 'PACKAGER_PRIVKEY="/home/pmos/.abuild/%s"\n' "$(basename "$ABUILD_KEY")" \
	> "$root/etc/abuild.conf"
cp "$ABUILD_KEY_PUB" "$root/etc/apk/keys/"
[ -z "$DISTFILE" ] || cp "$DISTFILE" "$root/var/cache/distfiles/"
cp "$aport/APKBUILD" "$aport"/*.patch "$aport/weston.pre-install" \
	"$root/home/pmos/build/weston/"

echo "building weston 14.0.2-r10 under proot/qemu (log: $work/abuild.log)"
# PROOT_NO_SECCOMP=1: proot's seccomp accelerator kills the qemu loader on
# WSL2 kernels; plain ptrace translation works.
env "LD_LIBRARY_PATH=$PROOT_LIBS" PROOT_NO_SECCOMP=1 \
	"$PROOT" -0 -r "$root" -q "$QEMU_AARCH64" \
	-b /proc -b /dev -w /home/pmos/build/weston /bin/sh -c "
set -e
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export HOME=/root
export SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH_PIN
export ABUILD_LAST_COMMIT=$ABUILD_LAST_COMMIT_PIN
export SRCDEST=/var/cache/distfiles
export REPODEST=/home/pmos/packages
/bin/busybox --install -s
grep -q '^abuild:' /etc/group || addgroup -S abuild
abuild -F -d
" > "$work/abuild.log" 2>&1

out=$root/home/pmos/packages/build/aarch64
echo "built packages:"
( cd "$out" && sha256sum ./*.apk )

echo "verifying payload bytes against the pinned session components:"
status=0
for key in "${!EXPECT[@]}"; do
	apk=${key%%!*}; member=${key##*!}; want=${EXPECT[$key]}
	got=$(tar -xzOf "$out/$apk" "$member" 2>/dev/null | sha256sum | cut -d' ' -f1)
	if [ "$got" = "$want" ]; then
		echo "  REPRODUCED  $member ($got)"
	else
		echo "  DIFFERS     $member (built $got, pinned $want)" >&2
		status=1
	fi
done
exit $status
