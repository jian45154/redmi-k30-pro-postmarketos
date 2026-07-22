#!/usr/bin/env bash
# Fail-closed, offline transformation of one reviewed D114 P2 ext4 input.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C LC_ALL=C TZ=UTC
unset BASH_ENV CDPATH ENV LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD

derive_repo_root() {
	local source_path canonical suffix=/scripts/lmi_p2_d114/inject_rootfs_candidate.sh
	if [[ "${BASH_SOURCE[0]}" == /run/lmi-p2-d114-inject/inject_rootfs_candidate.*.sh ]]; then
		[[ "$#" == 19 && "${18}" == --canonical-source ]] || return 1
		source_path=${19}
	else
		source_path=${BASH_SOURCE[0]}
	fi
	[[ "$source_path" == /* && -f "$source_path" && ! -L "$source_path" ]] || return 1
	canonical="$(realpath -e -- "$source_path")" || return 1
	[[ "$canonical" == "$source_path" && "$canonical" == *"$suffix" ]] || return 1
	canonical=${canonical%"$suffix"}
	[[ -n "$canonical" && "$canonical" == /* && -d "$canonical" && ! -L "$canonical" ]] || return 1
	printf '%s\n' "$canonical"
}

REPO="$(derive_repo_root "$@")" || {
	printf 'D114 candidate injection refused: could not derive canonical repository root\n' >&2
	exit 1
}
readonly REPO
readonly CANONICAL_INJECTOR_SOURCE="$REPO/scripts/lmi_p2_d114/inject_rootfs_candidate.sh"
readonly INPUT_BUILD_DIR="$REPO/private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-build-20260723"
readonly BUILD_DIR="$REPO/private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-injected-20260723"
readonly RAW="$INPUT_BUILD_DIR/xiaomi-lmi-d114-r2-most-complete-userdata-20260723.normalized.img"
readonly RAW_SHA256=b108f581426c644319396fe5d5cdafd2f490151f2ac2b63bd2ef5275567d0721
readonly RAW_SIZE=3436183552
readonly SPARSE="$INPUT_BUILD_DIR/xiaomi-lmi-d114-r2-most-complete-userdata-20260723.android-sparse.img"
readonly SPARSE_SHA256=79276015be7d79ed77494b4bd3aec9e8a0f09325c53c4802eef54fede1022cbc
readonly SPARSE_SIZE=2269399372
readonly GPT_SECTOR_SIZE=4096
readonly ROOT_START_SECTOR=124928
readonly ROOT_SECTOR_COUNT=713728
readonly BASE="$INPUT_BUILD_DIR/lmi-d114-rootfs-base.ext4"
readonly BASE_SHA256=7738604558ad38f95316e2f65f99dcd4d6cc222c3ff3469a590b4892da81448d
readonly INPUT="$INPUT_BUILD_DIR/lmi-d114-rootfs-p2-candidate-20260723.ext4"
readonly INPUT_SHA256=a5b368da152e52c732d558a9fb4158beec6a079ff9aafb6de073f83f108b435b
readonly IMAGE_SIZE=2923429888
readonly IMAGE_UUID=f8eb7c4b-a7bc-4c44-972f-ee4a7c2e075f
readonly REPAIR_EPOCH=1784734606
readonly REPAIR_VERIFY_LOG="$INPUT_BUILD_DIR/candidate-preinstall-e2fsck-verify.log"
readonly REPAIR_VERIFY_LOG_SHA256=96a42f54078536e361b57a80d73a8199ae62dff4537db4b459eecdc6b16119c4
readonly REPAIR_LOG="$INPUT_BUILD_DIR/candidate-preinstall-e2fsck-repair.log"
readonly REPAIR_LOG_SHA256=96a42f54078536e361b57a80d73a8199ae62dff4537db4b459eecdc6b16119c4
readonly REBUILD_LOCK="$REPO/config/lmi-p2-d114/candidate-rebuild-lock.json"
readonly REBUILD_LOCK_SHA256=a45ba8072a5ed8667edc7ac84146c4daba5a595f22af05f396fce7a670357ce1
readonly REBUILD_LOCK_SCHEMA=lmi-p2-d114-candidate-rebuild-lock/v1
readonly OUTPUT_BUNDLE="$BUILD_DIR/lmi-d114-rootfs-p2-r2-most-complete-injected-20260723.bundle"
readonly OUTPUT="$OUTPUT_BUNDLE/rootfs.ext4"
readonly ATTESTATION="$OUTPUT_BUNDLE/attestation.json"
readonly P2_APK="$INPUT_BUILD_DIR/run2-device-xiaomi-lmi-terminal-0.1.0-r2.apk"
readonly P2_APK_SHA256=70d45810b14bb14274a23d935bb390271c8544db554ac70fb484f6eb2a4b93bc
readonly P2_APK_SIZE=8775
readonly P2_APK_CHECKSUM=Q1gHoYAku3NLLc7jWlEYfOGUhQcYs=
readonly SIXROW_APK="$INPUT_BUILD_DIR/lmi-weston-sixrow-clients-14.0.2-r2.resigned.apk"
readonly SIXROW_APK_SHA256=8d2f23522eb737432577b33ee7dd012b76d06012f1d6918eac289853f6f015e7
readonly SIXROW_APK_SIZE=121842
readonly SIXROW_APK_CHECKSUM=Q1dyp8uNSMxPIjVUwuCP4wyyBBCs4=
readonly P2_KEY="$REPO/config/lmi-p2-d114/pmos@local-6a5d38f2.rsa.pub"
readonly P2_KEY_SHA256=c42ba833751ab9ca164c506cd72c2c3b9a6079db09ebe2cf52838ae79e936736
readonly SIXROW_KEY="$REPO/config/lmi-p2-d114/pmos@local-6a5d38f2.rsa.pub"
readonly SIXROW_KEY_SHA256=c42ba833751ab9ca164c506cd72c2c3b9a6079db09ebe2cf52838ae79e936736
readonly P2_BUILD_ATTESTATION="$REPO/config/lmi-p2-d114/apk-build-attestation.json"
readonly P2_BUILD_ATTESTATION_SHA256=519c9e9cd9a0087567fe5980f2a04906051b13c465cfac636793ed54aeae687b
readonly SIXROW_BUILD_ATTESTATION="$REPO/config/lmi-weston-sixrow/build-attestation-r2.json"
readonly SIXROW_BUILD_ATTESTATION_SHA256=5bb55928ae0b4109ad028d1a24e29de0dc74d2078f31d33628fd683cfbbaa0a2
readonly APK_STATIC="$REPO/private/lmi-p1/calibration/acquisition-root/work-proot-chroot2/apk.static"
readonly APK_STATIC_SHA256=a6542dc1fdb6214be1ef462668241bfe91f301e9249c99c0c6c327269d5e5ce4
readonly PROOT="$REPO/private/lmi-p1/calibration/acquisition-root/proot-root/usr/bin/proot"
readonly PROOT_SHA256=e95e0da51b8948c38743704a0e751276faf95b176e11dc4f1f99bca7157fb2ab
readonly PROOT_TALLOC="$REPO/private/lmi-p1/calibration/acquisition-root/proot-root/usr/lib/x86_64-linux-gnu/libtalloc.so.2.4.3"
readonly PROOT_TALLOC_SHA256=261d4fd32e2341567eeafba6d4d75684c8eeaedb9bcda04f1fd69792e6197634
readonly QEMU="$REPO/private/lmi-p1/calibration/acquisition-root/work-proot-chroot2/chroot_native-pre-rootfs-calibration/usr/bin/qemu-aarch64"
readonly QEMU_SHA256=4a2fd0e1fb9c1ba3f63f81113ead9e96e0cdb513c64c83bb2ecfc94e1df05e4c
readonly RUNTIME_LOCK="$REPO/config/lmi-p2-d114/injector-runtime-lock.json"
readonly RUNTIME_LOCK_SHA256=11d2cc4e8c327193f2acb23869376cb93838f7d9e775ead24f4755704263ed73
readonly RUNTIME_LOCK_SCHEMA=lmi-p2-d114-injector-runtime-lock/v1
readonly HOST_LIBC=/usr/lib/x86_64-linux-gnu/libc.so.6
readonly HOST_LIBC_SHA256=d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0
readonly HOST_LOADER=/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
readonly HOST_LOADER_SHA256=223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb
readonly HOST_INTERPRETER=/lib64/ld-linux-x86-64.so.2
readonly BWRAP=/usr/bin/bwrap
readonly BWRAP_SHA256=0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0
readonly BWRAP_LIBSELINUX=/usr/lib/x86_64-linux-gnu/libselinux.so.1
readonly BWRAP_LIBSELINUX_SHA256=7538ee77765a27966563c0d22437a3080dcdb346ff76cc16d71a3ce3379a716a
readonly BWRAP_LIBCAP=/usr/lib/x86_64-linux-gnu/libcap.so.2.75
readonly BWRAP_LIBCAP_SHA256=c5b463a8136dabb152bad8b04e89bf67bd2049ef49777ed0b96bdbc6cb5b9565
readonly BWRAP_LIBPCRE=/usr/lib/x86_64-linux-gnu/libpcre2-8.so.0.14.0
readonly BWRAP_LIBPCRE_SHA256=4a6b6b2078685b074869d75cb068664d7da6b3036df7bca0442b1bbbd4ac7e65
readonly SIMG2IMG=/usr/bin/simg2img
readonly SIMG2IMG_SHA256=449872690de38e40848c4d781f9e9829d3e65610ceea448cb24a9f70cd738fac
readonly E2FSCK=/usr/sbin/e2fsck
readonly E2FSCK_SHA256=2e51f521c676729920eaba694933d9d4048645f1a5789556fd0027e62d11ecc8
readonly DUMPE2FS=/usr/sbin/dumpe2fs
readonly DUMPE2FS_SHA256=a3761403c5075e6af52f3c2ad7d8c35591751ba997fd2377895fc2fe88b5a774
readonly E2IMAGE=/usr/sbin/e2image
readonly E2IMAGE_SHA256=08377ede318c65ef308246cfd2cd8bb7047c829d9997fb2b85c9e922d5205759
readonly DEBUGFS=/usr/sbin/debugfs
readonly DEBUGFS_SHA256=864e1d7b445e7b5bfc831da78330dbcafc590fa82b89ea9de60b7527f989954f
readonly GETFATTR=/usr/bin/getfattr
readonly GETFATTR_SHA256=19b08ed0130464b5565205cf8b02cb39a5c656a7e55b0a4130080025f8bf4e14
readonly LSATTR=/usr/bin/lsattr
readonly LSATTR_SHA256=a302ce5655825f7eec323b106d91b582cc1c231936acb927dbfd360f815b5b99
readonly LSATTR_LIBE2P=/usr/lib/x86_64-linux-gnu/libe2p.so.2.3
readonly LSATTR_LIBE2P_SHA256=78b962737fc0df9fdd6b77ed284958065ff4c3ee0776251967f434b764204377
readonly LSATTR_LIBCOM_ERR=/usr/lib/x86_64-linux-gnu/libcom_err.so.2.1
readonly LSATTR_LIBCOM_ERR_SHA256=6fb3115b11fe7e14c26f3e086c4dc1fb41061130869a66c976e0ea69fdb912d6
readonly BASH=/usr/bin/bash
readonly BASH_SHA256=3efccc187bafa75ff1e37d246270ab3e7aa559f242c7a52bf3ec2a1b5450bdbd
readonly DASH=/usr/bin/dash
readonly DASH_SHA256=c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917
readonly WORLD_SHA256=d2db0f373a095db97676afe6c088ba98cc9ebdf78c3576cae6a3d17b053d02eb
readonly INSTALLED_DB_PRE_SHA256=bfd4503236d82deb0fafdd6c483ba19d1a2217d977b6a9b05536888053f3a1b7
readonly SCRIPTS_DB_PRE_SHA256=ce9b0a667edcc434a718db4a17a78d39a9e24af847a3b219e01ea437fe2ecbc7
readonly TRIGGERS_DB_SHA256=8847b2f186ea9b5a8705a2aa020fd0c00595531f1b25550ced1bc7f803952286
readonly SHADOW_SHA256=ccf1c9cb866c6eedc1d624340b8bb7e69d7f5ba058b8f40bfe70b779092bd9c0
readonly SHADOW_BACKUP_SHA256=7cc7f7bbc72feae8c9e6ac350e9b2f9d2cba159a039400c1fa5d64c1ab87766f
readonly EXT4_BLOCK_SIZE=4096
readonly JOURNAL_FIRST_BLOCK=327680
readonly JOURNAL_BLOCK_COUNT=16384
readonly JOURNAL_INACTIVE_FIRST_BLOCK=327681
readonly JOURNAL_INACTIVE_BLOCK_COUNT=16383
readonly JOURNAL_INACTIVE_ZERO_SHA256=40b4947fd669bcb849e47705c797e2484a4d406a596017fa889987d2614008b3
readonly ZERO_BLOCK_SHA256=ad7facb2586fc6e966c004d7d1d16b024f5805ff7cb47c7a85dabd8b48892ca7
# The r2 candidate's e2fsck repair freed no blocks; the reviewed list is empty.
readonly -a REVIEWED_FREED_BLOCKS=()

MOUNTPOINT=
LOOP_DEVICE=
LOOP_DEVICE_ID=
LOOP_BACKING_ID=
SCRATCH_DIR=
SCRATCH_ID=
SCRATCH_IMAGE=
ATTESTATION_TMP=
ROOT_MOUNTED=0
SOURCE_BRIDGE_DIR=
SOURCE_BRIDGE_DIR_ID=
SOURCE_BRIDGE_PARENT=
SOURCE_BRIDGE_PARENT_ID=
SOURCE_BRIDGE_IMAGE=
SOURCE_BRIDGE_IMAGE_SOURCE_ID=
SOURCE_BRIDGE_IMAGE_TARGET_ID=
SOURCE_BRIDGE_IMAGE_MOUNT_ID=
SOURCE_BRIDGE_TOOLS=
SOURCE_BRIDGE_TOOLS_SOURCE_ID=
SOURCE_BRIDGE_TOOLS_TARGET_ID=
SOURCE_BRIDGE_TOOLS_MOUNT_ID=
SOURCE_BRIDGE_KEYS=
SOURCE_BRIDGE_KEYS_SOURCE_ID=
SOURCE_BRIDGE_KEYS_TARGET_ID=
SOURCE_BRIDGE_KEYS_MOUNT_ID=
SOURCE_BRIDGE_RUNTIME=
SOURCE_BRIDGE_RUNTIME_SOURCE_ID=
SOURCE_BRIDGE_RUNTIME_TARGET_ID=
SOURCE_BRIDGE_RUNTIME_MOUNT_ID=
PUBLISHED_BUNDLE=0
COMMITTED=0
PUBLISHED_BUNDLE_PATH=
PUBLISHED_BUNDLE_ID=
PUBLISHED_IMAGE_ID=
PUBLISHED_ATTESTATION_ID=
PUBLISHED_IMAGE_SHA256=
PUBLISHED_ATTESTATION_SHA256=
PUBLISHED_OWNER=
SEALED_SCRIPT_PATH=
SEALED_SCRIPT_ID=
CALLER_UID=
CALLER_GID=

fail() {
	printf 'D114 candidate injection refused: %s\n' "$*" >&2
	exit 1
}

sha256_of() {
	local line
	line="$(sha256sum -- "$1")" || return 1
	printf '%s\n' "${line%% *}"
}

metadata_of() {
	stat -Lc '%d:%i:%f:%h:%u:%g:%s:%Y:%Z' -- "$1"
}

directory_identity_of() {
	stat -Lc '%d:%i:%f:%u:%g' -- "$1"
}

# Open once for reading and return both the descriptor and its immutable identity.
open_trusted_file() {
	local path=$1 descriptor_name=$2 identity_name=$3
	local descriptor before opened
	[[ -e "$path" && ! -L "$path" && -f "$path" ]] || return 1
	[[ "$(realpath -e -- "$path")" == "$path" ]] || return 1
	before="$(metadata_of "$path")" || return 1
	exec {descriptor}<"$path" || return 1
	opened="$(metadata_of "/proc/self/fd/$descriptor")" || return 1
	if [[ "$before" != "$opened" ]]; then
		exec {descriptor}<&-
		return 1
	fi
	printf -v "$descriptor_name" '%s' "$descriptor"
	printf -v "$identity_name" '%s' "$before"
}

verify_open_path_unchanged() {
	local path=$1 descriptor=$2 identity=$3
	[[ -e "$path" && ! -L "$path" && -f "$path" ]] || return 1
	[[ "$(metadata_of "$path")" == "$identity" ]] || return 1
	[[ "$(metadata_of "/proc/self/fd/$descriptor")" == "$identity" ]] || return 1
}

open_trusted_directory() {
	local path=$1 descriptor_name=$2 identity_name=$3
	local descriptor before opened
	[[ -d "$path" && ! -L "$path" && "$(realpath -e -- "$path")" == "$path" ]] || return 1
	before="$(directory_identity_of "$path")" || return 1
	exec {descriptor}<"$path" || return 1
	opened="$(directory_identity_of "/proc/self/fd/$descriptor")" || return 1
	[[ "$before" == "$opened" ]] || return 1
	printf -v "$descriptor_name" '%s' "$descriptor"
	printf -v "$identity_name" '%s' "$before"
}

verify_open_directory_unchanged() {
	local path=$1 descriptor=$2 identity=$3
	[[ -d "$path" && ! -L "$path" ]] || return 1
	[[ "$(directory_identity_of "$path")" == "$identity" ]] || return 1
	[[ "$(directory_identity_of "/proc/self/fd/$descriptor")" == "$identity" ]] || return 1
}

require_repo_ancestors() {
	local path=$1 current mode owner
	current="$(dirname -- "$path")"
	while :; do
		[[ -d "$current" && ! -L "$current" ]] || fail "unsafe ancestor: $current"
		[[ "$(realpath -e -- "$current")" == "$current" ]] || fail "noncanonical ancestor: $current"
		mode="$(stat -Lc %a -- "$current")"
		(( (8#$mode & 8#022) == 0 )) || fail "writable ancestor: $current"
		owner="$(stat -Lc %u:%g -- "$current")"
		[[ "$owner" == "$REPO_OWNER" ]] || fail "unexpected ancestor owner: $current"
		[[ "$current" == "$REPO" ]] && break
		[[ "$current" == "$REPO/"* ]] || fail "ancestor escaped repository"
		current="$(dirname -- "$current")"
	done
}

require_repo_file() {
	local path=$1 mode=$2 label=$3
	require_repo_ancestors "$path"
	[[ "$(stat -Lc %u:%g -- "$path")" == "$REPO_OWNER" ]] || fail "$label owner mismatch"
	[[ "$(stat -Lc %a -- "$path")" == "$mode" ]] || fail "$label mode mismatch"
	[[ "$(stat -Lc %h -- "$path")" == 1 ]] || fail "$label has hard links"
}

require_system_file() {
	local path=$1 mode=$2 label=$3 current directory_mode
	[[ -f "$path" && ! -L "$path" && "$(realpath -e -- "$path")" == "$path" ]] ||
		fail "$label system path is unsafe"
	[[ "$(stat -Lc %a:%u:%g:%h -- "$path")" == "$mode:0:0:1" ]] ||
		fail "$label system metadata mismatch"
	current="$(dirname -- "$path")"
	while :; do
		[[ -d "$current" && ! -L "$current" && "$(stat -Lc %u:%g -- "$current")" == 0:0 ]] ||
			fail "$label system ancestor is unsafe: $current"
		directory_mode="$(stat -Lc %a -- "$current")"
		(( (8#$directory_mode & 8#022) == 0 )) || fail "$label system ancestor is writable: $current"
		[[ "$current" == / ]] && break
		current="$(dirname -- "$current")"
	done
}

require_private_input() {
	local path=$1 label=$2
	case "$path" in
		"$RAW"|"$SPARSE"|"$BASE"|"$INPUT") ;;
		*) fail "$label is not an exact allowlisted read-only input" ;;
	esac
	[[ "$(dirname -- "$path")" == "$INPUT_BUILD_DIR" ]] ||
		fail "$label is outside the read-only input directory"
	require_repo_ancestors "$path"
	[[ "$(stat -Lc %u:%g -- "$path")" == "$REPO_OWNER" ]] || fail "$label owner mismatch"
	[[ "$(stat -Lc %a -- "$path")" == 600 ]] || fail "$label mode mismatch"
	[[ "$(stat -Lc %h -- "$path")" == 1 ]] || fail "$label has hard links"
}

copy_fd_to_scratch() {
	local descriptor=$1 destination=$2
	cp --reflink=never --sparse=always -- \
		"/proc/self/fd/$descriptor" "$destination" || return 1
	chmod 0600 -- "$destination"
}

remove_if_identity() {
	local path=$1 identity=$2
	[[ -n "$path" && -n "$identity" ]] || return 0
	if [[ -f "$path" && ! -L "$path" && "$(stat -Lc %d:%i -- "$path")" == "$identity" ]]; then
		rm -f -- "$path"
	fi
}

# A directory rename is the publication unit.  The image is therefore never
# reachable at its final name without the attestation in the same bundle.
publish_bundle() {
	local bundle_tmp=$1 bundle_output=$2 expected_image_sha=$3 expected_attestation_sha=$4 owner=$5
	local before_bundle before_image before_attestation after_bundle after_image after_attestation
	local before_image_inode before_attestation_inode
	[[ -d "$bundle_tmp" && ! -L "$bundle_tmp" ]] || return 1
	[[ ! -e "$bundle_output" && ! -L "$bundle_output" ]] || return 1
	[[ "$owner" =~ ^[0-9]+:[0-9]+$ ]] || return 1
	[[ "$(stat -Lc %a:%u:%g:%h -- "$bundle_tmp")" == "750:$owner:2" ]] || return 1
	[[ "$(find "$bundle_tmp" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == $'attestation.json\nrootfs.ext4' ]] || return 1
	before_bundle="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$bundle_tmp")" || return 1
	before_image="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$bundle_tmp/rootfs.ext4")" || return 1
	before_attestation="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$bundle_tmp/attestation.json")" || return 1
	before_image_inode="$(stat -Lc %d:%i -- "$bundle_tmp/rootfs.ext4")" || return 1
	before_attestation_inode="$(stat -Lc %d:%i -- "$bundle_tmp/attestation.json")" || return 1
	[[ "$before_image" == *":640:$owner:1" ]] || return 1
	[[ "$before_attestation" == *":640:$owner:1" ]] || return 1
	[[ "$before_image_inode" != "$before_attestation_inode" ]] || return 1
	[[ "$(sha256_of "$bundle_tmp/rootfs.ext4")" == "$expected_image_sha" ]] || return 1
	[[ "$(sha256_of "$bundle_tmp/attestation.json")" == "$expected_attestation_sha" ]] || return 1
	mv -T --no-clobber -- "$bundle_tmp" "$bundle_output" || return 1
	[[ ! -e "$bundle_tmp" && ! -L "$bundle_tmp" ]] || return 1
	after_bundle="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$bundle_output")" || return 1
	after_image="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$bundle_output/rootfs.ext4")" || return 1
	after_attestation="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$bundle_output/attestation.json")" || return 1
	[[ "$after_bundle" == "$before_bundle" && "$after_image" == "$before_image" &&
		"$after_attestation" == "$before_attestation" ]] || return 1
	[[ "$(sha256_of "$bundle_output/rootfs.ext4")" == "$expected_image_sha" ]] || return 1
	[[ "$(sha256_of "$bundle_output/attestation.json")" == "$expected_attestation_sha" ]] || return 1
	PUBLISHED_BUNDLE_PATH=$bundle_output
	PUBLISHED_BUNDLE_ID=$before_bundle
	PUBLISHED_IMAGE_ID=$before_image
	PUBLISHED_ATTESTATION_ID=$before_attestation
	PUBLISHED_IMAGE_SHA256=$expected_image_sha
	PUBLISHED_ATTESTATION_SHA256=$expected_attestation_sha
	PUBLISHED_OWNER=$owner
	PUBLISHED_BUNDLE=1
}

remove_published_bundle_if_identity() {
	[[ "$PUBLISHED_BUNDLE" == 1 && -n "$PUBLISHED_BUNDLE_PATH" ]] || return 0
	[[ -d "$PUBLISHED_BUNDLE_PATH" && ! -L "$PUBLISHED_BUNDLE_PATH" ]] || return 1
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$PUBLISHED_BUNDLE_PATH")" == "$PUBLISHED_BUNDLE_ID" ]] || return 1
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$PUBLISHED_BUNDLE_PATH/rootfs.ext4")" == "$PUBLISHED_IMAGE_ID" ]] || return 1
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$PUBLISHED_BUNDLE_PATH/attestation.json")" == "$PUBLISHED_ATTESTATION_ID" ]] || return 1
	[[ "$(find "$PUBLISHED_BUNDLE_PATH" -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == $'attestation.json\nrootfs.ext4' ]] || return 1
	[[ "$(sha256_of "$PUBLISHED_BUNDLE_PATH/rootfs.ext4")" == "$PUBLISHED_IMAGE_SHA256" ]] || return 1
	[[ "$(sha256_of "$PUBLISHED_BUNDLE_PATH/attestation.json")" == "$PUBLISHED_ATTESTATION_SHA256" ]] || return 1
	rm -f -- "$PUBLISHED_BUNDLE_PATH/rootfs.ext4" "$PUBLISHED_BUNDLE_PATH/attestation.json" || return 1
	rmdir -- "$PUBLISHED_BUNDLE_PATH" || return 1
	PUBLISHED_BUNDLE=0
}

loop_backing_path_of() {
	local loop=$1 lines
	lines="$(losetup --list --noheadings --raw --output BACK-FILE -- "$loop")" || return 1
	[[ -n "$lines" && "$lines" != *$'\n'* ]] || return 1
	printf '%s\n' "$lines"
}

loop_backing_path_or_empty() {
	local loop=$1 lines
	lines="$(losetup --list --noheadings --raw --output BACK-FILE -- "$loop")" || return 1
	[[ "$lines" != *$'\n'* ]] || return 1
	printf '%s\n' "$lines"
}

verify_loop_device_identity() {
	[[ -n "$LOOP_DEVICE" && -n "$LOOP_DEVICE_ID" ]] || return 1
	[[ -b "$LOOP_DEVICE" && "$(stat -Lc %t:%T:%r -- "$LOOP_DEVICE")" == "$LOOP_DEVICE_ID" ]]
}

verify_loop_backing_identity() {
	local backing
	[[ -n "$LOOP_DEVICE" && -n "$LOOP_DEVICE_ID" && -n "$LOOP_BACKING_ID" ]] || return 1
	[[ -b "$LOOP_DEVICE" && "$(stat -Lc %t:%T:%r -- "$LOOP_DEVICE")" == "$LOOP_DEVICE_ID" ]] || return 1
	backing="$(loop_backing_path_of "$LOOP_DEVICE")" || return 1
	[[ -f "$backing" && ! -L "$backing" ]] || return 1
	[[ "$(stat -Lc %d:%i -- "$backing")" == "$LOOP_BACKING_ID" ]] || return 1
	[[ -f "$SCRATCH_IMAGE" && ! -L "$SCRATCH_IMAGE" ]] || return 1
	[[ "$(stat -Lc %d:%i -- "$SCRATCH_IMAGE")" == "$LOOP_BACKING_ID" ]] || return 1
}

detach_loop_checked() {
	local backing
	[[ -n "$LOOP_DEVICE" ]] || return 0
	[[ -n "$LOOP_DEVICE_ID" && -n "$LOOP_BACKING_ID" ]] || return 1
	verify_loop_device_identity || return 1
	backing="$(loop_backing_path_or_empty "$LOOP_DEVICE")" || return 1
	if [[ -z "$backing" ]]; then
		LOOP_DEVICE=
		LOOP_DEVICE_ID=
		LOOP_BACKING_ID=
		return 0
	fi
	verify_loop_backing_identity || return 1
	losetup --detach "$LOOP_DEVICE" || return 1
	LOOP_DEVICE=
	LOOP_DEVICE_ID=
	LOOP_BACKING_ID=
}

attach_loop_checked() {
	[[ -f "$SCRATCH_IMAGE" && ! -L "$SCRATCH_IMAGE" ]] || return 1
	LOOP_BACKING_ID="$(stat -Lc %d:%i -- "$SCRATCH_IMAGE")" || return 1
	LOOP_DEVICE="$(losetup --find)" || return 1
	[[ -n "$LOOP_DEVICE" && -b "$LOOP_DEVICE" ]] || return 1
	LOOP_DEVICE_ID="$(stat -Lc %t:%T:%r -- "$LOOP_DEVICE")" || return 1
	[[ -z "$(loop_backing_path_or_empty "$LOOP_DEVICE")" ]] || return 1
	# All cleanup identity is recorded before attach.  If a signal arrives after
	# this command attaches but before it returns, the EXIT trap can still prove
	# the backing inode before detaching it.
	losetup "$LOOP_DEVICE" "$SCRATCH_IMAGE" || return 1
	verify_loop_backing_identity
}

remove_sealed_script_if_identity() {
	[[ -n "$SEALED_SCRIPT_PATH" && -n "$SEALED_SCRIPT_ID" ]] || return 0
	[[ -f "$SEALED_SCRIPT_PATH" && ! -L "$SEALED_SCRIPT_PATH" ]] || return 1
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$SEALED_SCRIPT_PATH")" == "$SEALED_SCRIPT_ID" ]] || return 1
	[[ "$(sha256_of "$SEALED_SCRIPT_PATH")" == "$SEALED_SCRIPT_SHA256" ]] || return 1
	rm -f -- "$SEALED_SCRIPT_PATH" || return 1
	[[ ! -e "$SEALED_SCRIPT_PATH" && ! -L "$SEALED_SCRIPT_PATH" ]] || return 1
	SEALED_SCRIPT_PATH=
	SEALED_SCRIPT_ID=
}

verify_private_namespaces() {
	local namespace self_namespace init_namespace parent_name parent_value
	[[ "$BASHPID" == 1 && "$(awk '/^NSpid:/ { print $NF }' /proc/1/status)" == 1 ]] ||
		fail "sealed injector must be PID 1 in its disposable PID namespace"
	for namespace in mnt net pid ipc uts; do
		self_namespace="$(readlink -- "/proc/self/ns/$namespace")"
		init_namespace="$(readlink -- "/proc/1/ns/$namespace")"
		[[ -n "$self_namespace" && "$self_namespace" == "$init_namespace" ]] ||
			fail "private $namespace namespace is not self-contained"
		parent_name="PARENT_${namespace^^}NS"
		parent_value=${!parent_name}
		[[ "$parent_value" =~ ^${namespace}:\[[0-9]+\]$ ]] || fail "invalid launcher parent $namespace namespace identity"
		[[ "$self_namespace" != "$parent_value" ]] || fail "$namespace namespace was not unshared by the launcher"
	done
	hostname lmi-d114-offline
	[[ "$(hostname)" == lmi-d114-offline ]] || fail "private UTS hostname mismatch"
	awk -F: 'NR > 2 { gsub(/[ \t]/, "", $1); seen=1; if ($1 != "lo") exit 1 } END { if (!seen) exit 2 }' \
		/proc/net/dev || fail "private network namespace must contain only loopback"
}

source_bridge_mount_id_of() {
	local target=$1 lines
	mountpoint -q -- "$target" || return 1
	lines="$(findmnt -nro ID -M "$target")" || return 1
	[[ "$lines" =~ ^[1-9][0-9]*$ ]] || return 1
	printf '%s\n' "$lines"
}

verify_source_bridge_mount() {
	local source=$1 target=$2 expected_source_id=$3 expected_mount_id=$4 current_mount_id
	[[ -n "$SOURCE_BRIDGE_DIR" && "$(dirname -- "$target")" == "$SOURCE_BRIDGE_DIR" ]] || return 1
	[[ -d "$source" && ! -L "$source" && "$(realpath -e -- "$source")" == "$source" ]] || return 1
	[[ "$(directory_identity_of "$source")" == "$expected_source_id" ]] || return 1
	[[ -d "$target" && ! -L "$target" ]] || return 1
	mountpoint -q -- "$target" || return 1
	[[ "$(directory_identity_of "$target")" == "$expected_source_id" ]] || return 1
	current_mount_id="$(source_bridge_mount_id_of "$target")" || return 1
	[[ -n "$expected_mount_id" && "$current_mount_id" == "$expected_mount_id" ]]
}

bind_source_bridge_mount() {
	local source=$1 target=$2 source_id_name=$3 target_id_name=$4 mount_id_name=$5
	local source_id target_id mount_id
	[[ -d "$source" && ! -L "$source" && "$(realpath -e -- "$source")" == "$source" ]] || return 1
	[[ -d "$target" && ! -L "$target" && "$(dirname -- "$target")" == "$SOURCE_BRIDGE_DIR" ]] || return 1
	[[ ! -z "$SOURCE_BRIDGE_DIR_ID" && "$(directory_identity_of "$SOURCE_BRIDGE_DIR")" == "$SOURCE_BRIDGE_DIR_ID" ]] || return 1
	[[ ! -z "$SOURCE_BRIDGE_PARENT_ID" && "$(directory_identity_of "$SOURCE_BRIDGE_PARENT")" == "$SOURCE_BRIDGE_PARENT_ID" ]] || return 1
	mountpoint -q -- "$target" && return 1
	source_id="$(directory_identity_of "$source")" || return 1
	target_id="$(directory_identity_of "$target")" || return 1
	[[ "$target_id" == *:41c0:0:0 ]] || return 1
	printf -v "$source_id_name" '%s' "$source_id"
	printf -v "$target_id_name" '%s' "$target_id"
	printf -v "$mount_id_name" '%s' ''
	# The cleanup identity is complete before mount(2).  A signal immediately
	# after a successful bind can therefore still prove and remove this mount.
	mount --bind "$source" "$target" || return 1
	mount_id="$(source_bridge_mount_id_of "$target")" || return 1
	printf -v "$mount_id_name" '%s' "$mount_id"
	verify_source_bridge_mount "$source" "$target" "$source_id" "$mount_id"
}

cleanup_source_bridge_mount() {
	local source=$1 target=$2 expected_source_id=$3 expected_target_id=$4 expected_mount_id=$5
	local current_mount_id failed=0
	[[ -n "$target" ]] || return 0
	[[ -n "$SOURCE_BRIDGE_DIR" && "$(dirname -- "$target")" == "$SOURCE_BRIDGE_DIR" ]] || return 1
	[[ -d "$target" && ! -L "$target" ]] || return 1
	if mountpoint -q -- "$target"; then
		[[ -n "$expected_source_id" && -d "$source" && ! -L "$source" ]] || return 1
		[[ "$(directory_identity_of "$source")" == "$expected_source_id" ]] || return 1
		[[ "$(directory_identity_of "$target")" == "$expected_source_id" ]] || return 1
		current_mount_id="$(source_bridge_mount_id_of "$target")" || return 1
		[[ -z "$expected_mount_id" || "$current_mount_id" == "$expected_mount_id" ]] || return 1
		umount -- "$target" || return 1
	elif [[ -n "$expected_mount_id" ]]; then
		# A completed mount disappeared without our checked normal unmount.
		failed=1
	fi
	[[ -d "$target" && ! -L "$target" ]] || return 1
	if [[ -n "$expected_target_id" ]]; then
		[[ "$(directory_identity_of "$target")" == "$expected_target_id" ]] || return 1
	else
		# Covers a signal after mkdir and before its inode was recorded.  The
		# unpredictable root-owned parent makes this exact empty placeholder ours.
		[[ "$(stat -Lc %a:%u:%g:%h -- "$target")" == 700:0:0:2 ]] || return 1
	fi
	rmdir -- "$target" || return 1
	return "$failed"
}

clear_source_bridge_state() {
	SOURCE_BRIDGE_DIR=
	SOURCE_BRIDGE_DIR_ID=
	SOURCE_BRIDGE_PARENT=
	SOURCE_BRIDGE_PARENT_ID=
	SOURCE_BRIDGE_IMAGE=
	SOURCE_BRIDGE_IMAGE_SOURCE_ID=
	SOURCE_BRIDGE_IMAGE_TARGET_ID=
	SOURCE_BRIDGE_IMAGE_MOUNT_ID=
	SOURCE_BRIDGE_TOOLS=
	SOURCE_BRIDGE_TOOLS_SOURCE_ID=
	SOURCE_BRIDGE_TOOLS_TARGET_ID=
	SOURCE_BRIDGE_TOOLS_MOUNT_ID=
	SOURCE_BRIDGE_KEYS=
	SOURCE_BRIDGE_KEYS_SOURCE_ID=
	SOURCE_BRIDGE_KEYS_TARGET_ID=
	SOURCE_BRIDGE_KEYS_MOUNT_ID=
	SOURCE_BRIDGE_RUNTIME=
	SOURCE_BRIDGE_RUNTIME_SOURCE_ID=
	SOURCE_BRIDGE_RUNTIME_TARGET_ID=
	SOURCE_BRIDGE_RUNTIME_MOUNT_ID=
}

cleanup_source_bridge() {
	local failed=0
	[[ -n "$SOURCE_BRIDGE_DIR" ]] || return 0
	[[ -n "$SOURCE_BRIDGE_PARENT" && -d "$SOURCE_BRIDGE_PARENT" && ! -L "$SOURCE_BRIDGE_PARENT" ]] || return 1
	[[ "$(directory_identity_of "$SOURCE_BRIDGE_PARENT")" == "$SOURCE_BRIDGE_PARENT_ID" ]] || return 1
	[[ -d "$SOURCE_BRIDGE_DIR" && ! -L "$SOURCE_BRIDGE_DIR" ]] || return 1
	if [[ -n "$SOURCE_BRIDGE_DIR_ID" ]]; then
		[[ "$(directory_identity_of "$SOURCE_BRIDGE_DIR")" == "$SOURCE_BRIDGE_DIR_ID" ]] || return 1
	else
		# Covers a signal after mktemp created its unpredictable root-owned path
		# but before the shell recorded its inode.
		[[ "$(dirname -- "$SOURCE_BRIDGE_DIR")" == "$SOURCE_BRIDGE_PARENT" ]] || return 1
		[[ "${SOURCE_BRIDGE_DIR##*/}" =~ ^source-bridge\.[A-Za-z0-9]{8}$ ]] || return 1
		[[ "$(stat -Lc %a:%u:%g -- "$SOURCE_BRIDGE_DIR")" == 700:0:0 ]] || return 1
	fi
	# Reverse bind order; never use lazy detach for a security boundary.
	cleanup_source_bridge_mount "$RUNTIME_CLOSURE" "$SOURCE_BRIDGE_RUNTIME" \
		"$SOURCE_BRIDGE_RUNTIME_SOURCE_ID" "$SOURCE_BRIDGE_RUNTIME_TARGET_ID" \
		"$SOURCE_BRIDGE_RUNTIME_MOUNT_ID" || failed=1
	cleanup_source_bridge_mount "$KEY_CLOSURE" "$SOURCE_BRIDGE_KEYS" \
		"$SOURCE_BRIDGE_KEYS_SOURCE_ID" "$SOURCE_BRIDGE_KEYS_TARGET_ID" \
		"$SOURCE_BRIDGE_KEYS_MOUNT_ID" || failed=1
	cleanup_source_bridge_mount "$TOOL_CLOSURE" "$SOURCE_BRIDGE_TOOLS" \
		"$SOURCE_BRIDGE_TOOLS_SOURCE_ID" "$SOURCE_BRIDGE_TOOLS_TARGET_ID" \
		"$SOURCE_BRIDGE_TOOLS_MOUNT_ID" || failed=1
	cleanup_source_bridge_mount "$MOUNTPOINT" "$SOURCE_BRIDGE_IMAGE" \
		"$SOURCE_BRIDGE_IMAGE_SOURCE_ID" "$SOURCE_BRIDGE_IMAGE_TARGET_ID" \
		"$SOURCE_BRIDGE_IMAGE_MOUNT_ID" || failed=1
	if [[ -z "$(find "$SOURCE_BRIDGE_DIR" -mindepth 1 -maxdepth 1 -print -quit)" ]]; then
		rmdir -- "$SOURCE_BRIDGE_DIR" || return 1
		clear_source_bridge_state
	else
		failed=1
	fi
	return "$failed"
}

create_source_bridge() {
	local parent=$1 image=$2 tools=$3 keys=$4 runtime=$5 name target
	[[ -z "$SOURCE_BRIDGE_DIR" ]] || return 1
	[[ -d "$parent" && ! -L "$parent" && "$(realpath -e -- "$parent")" == "$parent" ]] || return 1
	[[ "$(stat -Lc %a:%u:%g -- "$parent")" == 700:0:0 ]] || return 1
	SOURCE_BRIDGE_PARENT=$parent
	SOURCE_BRIDGE_PARENT_ID="$(directory_identity_of "$parent")" || return 1
	SOURCE_BRIDGE_DIR="$(mktemp -d "$parent/source-bridge.XXXXXXXX")" || return 1
	[[ "$(stat -Lc %a:%u:%g -- "$SOURCE_BRIDGE_DIR")" == 700:0:0 ]] || return 1
	SOURCE_BRIDGE_DIR_ID="$(directory_identity_of "$SOURCE_BRIDGE_DIR")" || return 1
	for name in image tools keys runtime; do
		target="$SOURCE_BRIDGE_DIR/$name"
		printf -v "SOURCE_BRIDGE_${name^^}" '%s' "$target"
		mkdir -m 0700 -- "$target" || return 1
	done
	bind_source_bridge_mount "$image" "$SOURCE_BRIDGE_IMAGE" \
		SOURCE_BRIDGE_IMAGE_SOURCE_ID SOURCE_BRIDGE_IMAGE_TARGET_ID SOURCE_BRIDGE_IMAGE_MOUNT_ID || return 1
	bind_source_bridge_mount "$tools" "$SOURCE_BRIDGE_TOOLS" \
		SOURCE_BRIDGE_TOOLS_SOURCE_ID SOURCE_BRIDGE_TOOLS_TARGET_ID SOURCE_BRIDGE_TOOLS_MOUNT_ID || return 1
	bind_source_bridge_mount "$keys" "$SOURCE_BRIDGE_KEYS" \
		SOURCE_BRIDGE_KEYS_SOURCE_ID SOURCE_BRIDGE_KEYS_TARGET_ID SOURCE_BRIDGE_KEYS_MOUNT_ID || return 1
	bind_source_bridge_mount "$runtime" "$SOURCE_BRIDGE_RUNTIME" \
		SOURCE_BRIDGE_RUNTIME_SOURCE_ID SOURCE_BRIDGE_RUNTIME_TARGET_ID SOURCE_BRIDGE_RUNTIME_MOUNT_ID || return 1
}

cleanup_partials() {
	local failed=0
	if [[ -n "$SCRATCH_DIR" && -d "$SCRATCH_DIR" ]]; then
		[[ ! -L "$SCRATCH_DIR" ]] || return 1
		if [[ -n "$SCRATCH_ID" && "$(directory_identity_of "$SCRATCH_DIR")" != "$SCRATCH_ID" ]]; then
			return 1
		fi
		find "$SCRATCH_DIR" -xdev -depth -mindepth 1 -delete || failed=1
		rmdir -- "$SCRATCH_DIR" || failed=1
	fi
	return "$failed"
}

cleanup() {
	local status=$? cleanup_failed=0
	trap - EXIT INT TERM HUP
	set +e
	if [[ -n "$SOURCE_BRIDGE_DIR" ]]; then
		cleanup_source_bridge || cleanup_failed=1
	fi
	if [[ "$ROOT_MOUNTED" == 1 ]]; then
		umount -- "$MOUNTPOINT" || cleanup_failed=1
		ROOT_MOUNTED=0
	fi
	if [[ -n "$LOOP_DEVICE" ]]; then
		detach_loop_checked || cleanup_failed=1
	fi
	if [[ "$PUBLISHED_BUNDLE" == 1 && "$COMMITTED" == 0 ]]; then
		remove_published_bundle_if_identity || cleanup_failed=1
	fi
	if (( cleanup_failed == 0 )); then
		cleanup_partials || cleanup_failed=1
	elif [[ -n "$SCRATCH_DIR" && -d "$SCRATCH_DIR" ]]; then
		chmod 0700 -- "$SCRATCH_DIR"
		printf 'D114 candidate injection: isolated partial retained at %s\n' "$SCRATCH_DIR" >&2
	fi
	if ! remove_sealed_script_if_identity; then
		cleanup_failed=1
		printf 'D114 candidate injection: sealed root entry cleanup failed: %s\n' "$SEALED_SCRIPT_PATH" >&2
	fi
	if (( cleanup_failed != 0 && status == 0 )); then status=1; fi
	exit "$status"
}

verify_runtime_closure() {
	local runtime=$1 path mode expected
	[[ -d "$runtime" && ! -L "$runtime" && "$(stat -Lc %a:%u:%g -- "$runtime")" == 700:0:0 ]] || return 1
	[[ "$(find "$runtime" -xdev -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == $'bwrap\ndash\nld-linux-x86-64.so.2\nlibc.so.6\nlibcap.so.2\nlibpcre2-8.so.0\nlibselinux.so.1\nlibtalloc.so.2\nproot' ]] || return 1
	for spec in \
		bwrap:700:$BWRAP_SHA256 dash:700:$DASH_SHA256 proot:700:$PROOT_SHA256 \
		ld-linux-x86-64.so.2:700:$HOST_LOADER_SHA256 libc.so.6:644:$HOST_LIBC_SHA256 \
		libselinux.so.1:644:$BWRAP_LIBSELINUX_SHA256 libcap.so.2:644:$BWRAP_LIBCAP_SHA256 \
		libpcre2-8.so.0:644:$BWRAP_LIBPCRE_SHA256 libtalloc.so.2:644:$PROOT_TALLOC_SHA256; do
		IFS=: read -r path mode expected <<<"$spec"
		[[ -f "$runtime/$path" && ! -L "$runtime/$path" ]] || return 1
		[[ "$(stat -Lc %a:%u:%g:%h -- "$runtime/$path")" == "$mode:0:0:1" ]] || return 1
		[[ "$(sha256_of "$runtime/$path")" == "$expected" ]] || return 1
	done
}

filesystem_geometry() {
	dumpe2fs -h "$1" 2>/dev/null |
		awk -F: '/^(Filesystem features|Inode count|Block count|Reserved block count|First block|Block size|Fragment size|Blocks per group|Fragments per group|Inodes per group|Inode blocks per group|Flex block group size|Inode size):/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $1 ":" $2}'
}

verify_image_file() {
	local relative=$1 mode=$2 expected_sha=$3 path="$MOUNTPOINT$1"
	[[ -f "$path" && ! -L "$path" && "$(stat -Lc %h -- "$path")" == 1 ]] ||
		fail "unsafe image payload: $relative"
	[[ "$(stat -Lc %a -- "$path")" == "$mode" ]] || fail "payload mode mismatch: $relative"
	[[ "$(stat -Lc %u:%g -- "$path")" == 0:0 ]] || fail "payload owner mismatch: $relative"
	[[ "$(sha256_of "$path")" == "$expected_sha" ]] || fail "payload hash mismatch: $relative"
}

shadow_records_safe() {
	local path=$1 root_policy=$2
	awk -F: -v root_policy="$root_policy" '
		NF != 9 { bad=1 }
		$1 == "" || seen[$1]++ { bad=1 }
		$1 == "root" {
			root++
			if (root_policy == "empty" && $2 != "") bad=1
			if (root_policy == "locked" && $2 !~ /^[!*]/) bad=1
		}
		$1 == "lmi" { lmi++; if ($2 == "") bad=1 }
		END { exit !(bad == 0 && root == 1 && lmi == 1) }
	' "$path"
}

write_ssh_public_image_policy() {
	local destination=$1
	printf '%s\n' \
		'# D114 public-image SSH policy: local passwords remain available only on the console.' \
		'PasswordAuthentication no' \
		'KbdInteractiveAuthentication no' \
		'PermitEmptyPasswords no' \
		'AuthenticationMethods publickey' >"$destination"
}

# Public-image sanitation is intentionally independent of APK lifecycle state:
# uninstalling either D114 package must never restore any removed state.
sanitize_public_image() {
	local ssh_dir=$MOUNTPOINT/home/lmi/.ssh
	local authorized_keys=$ssh_dir/authorized_keys
	local machine_id=$MOUNTPOINT/etc/machine-id
	local shadow=$MOUNTPOINT/etc/shadow
	local shadow_backup=$MOUNTPOINT/etc/shadow-
	local resolv_conf=$MOUNTPOINT/etc/resolv.conf
	local apk_log=$MOUNTPOINT/var/log/apk.log
	local apk_cache=$MOUNTPOINT/var/cache/apk
	local ssh_config_dir=$MOUNTPOINT/etc/ssh
	local ssh_dropin_dir=$ssh_config_dir/sshd_config.d
	local ssh_policy=$ssh_dropin_dir/99-lmi-public-image.conf
	local cache_name clear_path clear_metadata clear_label
	# The r2 base is installed without any host SSH public key, so the lmi
	# account must have no ~/.ssh at all; fail closed if anything occupies
	# either path (a populated authorized_keys must never ship).
	[[ ! -e "$ssh_dir" && ! -L "$ssh_dir" ]] ||
		fail "image lmi SSH directory unexpectedly present"
	[[ ! -e "$authorized_keys" && ! -L "$authorized_keys" ]] ||
		fail "image authorized_keys unexpectedly present"

	# Remove (not truncate) the machine-id: an empty /etc/machine-id makes dbus
	# refuse to start on first boot (which cascades into elogind and the session
	# gate), while an absent file is rebuilt by dbus-uuidgen --ensure.
	[[ -f "$machine_id" && ! -L "$machine_id" ]] || fail "image machine-id is unsafe"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$machine_id")" == 644:0:0:1:33 ]] ||
		fail "image machine-id metadata mismatch"
	rm -- "$machine_id" || fail "could not remove image machine-id"
	[[ ! -e "$machine_id" && ! -L "$machine_id" ]] ||
		fail "image machine-id remains after sanitation"

	[[ -f "$shadow" && ! -L "$shadow" && -f "$shadow_backup" && ! -L "$shadow_backup" ]] ||
		fail "image shadow database or backup is unsafe"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$shadow")" == 640:0:42:1:731 ]] ||
		fail "image shadow database metadata mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$shadow_backup")" == 640:0:42:1:730 ]] ||
		fail "image shadow backup metadata mismatch"
	[[ "$(sha256_of "$shadow")" == "$SHADOW_SHA256" ]] || fail "image shadow database digest mismatch"
	[[ "$(sha256_of "$shadow_backup")" == "$SHADOW_BACKUP_SHA256" ]] || fail "image shadow backup digest mismatch"
	shadow_records_safe "$shadow" locked || fail "image shadow database policy mismatch"
	shadow_records_safe "$shadow_backup" empty || fail "image shadow backup baseline policy mismatch"
	cp --reflink=never -- "$shadow" "$shadow_backup" || fail "could not rebuild image shadow backup"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$shadow_backup")" == 640:0:42:1:731 ]] ||
		fail "rebuilt image shadow backup metadata mismatch"
	shadow_records_safe "$shadow_backup" locked || fail "rebuilt image shadow backup policy mismatch"
	cmp -s -- "$shadow" "$shadow_backup" || fail "rebuilt image shadow backup differs from active shadow"
	[[ "$(sha256_of "$shadow")" == "$SHADOW_SHA256" && "$(sha256_of "$shadow_backup")" == "$SHADOW_SHA256" ]] ||
		fail "rebuilt image shadow databases differ from the locked active credentials"

	for cache_name in \
		APKINDEX.066df28d.tar.gz \
		APKINDEX.30e6f5af.tar.gz \
		APKINDEX.b53994b4.tar.gz \
		APKINDEX.bc99f2f3.tar.gz; do
		[[ -f "$apk_cache/$cache_name" && ! -L "$apk_cache/$cache_name" ]] ||
			fail "image APK cache member is unsafe: $cache_name"
	done
	[[ -d "$apk_cache" && ! -L "$apk_cache" && "$(stat -Lc %a:%u:%g -- "$apk_cache")" == 755:0:0 ]] ||
		fail "image APK cache directory metadata mismatch"
	[[ "$(find "$apk_cache" -xdev -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == $'APKINDEX.066df28d.tar.gz\nAPKINDEX.30e6f5af.tar.gz\nAPKINDEX.b53994b4.tar.gz\nAPKINDEX.bc99f2f3.tar.gz' ]] ||
		fail "image APK cache inventory mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$apk_cache/APKINDEX.066df28d.tar.gz")" == 644:0:0:1:527944 ]] || fail "APK cache member metadata mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$apk_cache/APKINDEX.30e6f5af.tar.gz")" == 644:0:0:1:748453 ]] || fail "APK cache member metadata mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$apk_cache/APKINDEX.b53994b4.tar.gz")" == 644:0:0:1:2507751 ]] || fail "APK cache member metadata mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$apk_cache/APKINDEX.bc99f2f3.tar.gz")" == 644:0:0:1:110467 ]] || fail "APK cache member metadata mismatch"
	rm -- "$apk_cache"/APKINDEX.066df28d.tar.gz "$apk_cache"/APKINDEX.30e6f5af.tar.gz \
		"$apk_cache"/APKINDEX.b53994b4.tar.gz "$apk_cache"/APKINDEX.bc99f2f3.tar.gz ||
		fail "could not clear image APK cache"
	[[ -z "$(find "$apk_cache" -xdev -mindepth 1 -maxdepth 1 -print -quit)" ]] ||
		fail "image APK cache is not empty after sanitation"

	for cache_name in "$resolv_conf|644:0:0:1:215|resolv.conf" "$apk_log|644:0:0:1:68657|apk.log"; do
		IFS='|' read -r clear_path clear_metadata clear_label <<<"$cache_name"
		[[ -f "$clear_path" && ! -L "$clear_path" ]] || fail "image $clear_label is unsafe"
		[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$clear_path")" == "$clear_metadata" ]] ||
			fail "image $clear_label metadata mismatch"
		: >"$clear_path" || fail "could not clear image $clear_label"
		[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$clear_path")" == 644:0:0:1:0 ]] ||
			fail "sanitized image $clear_label metadata mismatch"
		[[ "$(sha256_of "$clear_path")" == e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 ]] ||
			fail "sanitized image $clear_label is not empty"
	done

	[[ -d "$ssh_config_dir" && ! -L "$ssh_config_dir" && "$(stat -Lc %a:%u:%g -- "$ssh_config_dir")" == 755:0:0 ]] ||
		fail "image SSH configuration directory metadata mismatch"
	[[ -d "$ssh_dropin_dir" && ! -L "$ssh_dropin_dir" && "$(stat -Lc %a:%u:%g -- "$ssh_dropin_dir")" == 755:0:0 ]] ||
		fail "image SSH drop-in directory metadata mismatch"
	verify_image_file /etc/ssh/sshd_config 644 6f64d4e84459b3da36fe3fc8e133efde88cce9def6d093c198207136ad7ff54b
	[[ -f "$ssh_dropin_dir/50-postmarketos-ui-policy.conf" && ! -L "$ssh_dropin_dir/50-postmarketos-ui-policy.conf" &&
		"$(stat -Lc %a:%u:%g:%h:%s -- "$ssh_dropin_dir/50-postmarketos-ui-policy.conf")" == 600:0:0:1:176 &&
		"$(sha256_of "$ssh_dropin_dir/50-postmarketos-ui-policy.conf")" == a0ef667efae484b210282c62068419500c505acbf5237f517699d3f5aa76a835 ]] ||
		fail "image postmarketOS SSH policy mismatch"
	[[ ! -e "$ssh_policy" && ! -L "$ssh_policy" ]] || fail "image SSH publication policy path is occupied"
	[[ -z "$(find "$ssh_config_dir" -xdev -mindepth 1 -maxdepth 1 -type f -name 'ssh_host_*_key' -print -quit)" ]] ||
		fail "image contains an SSH host private key"
	write_ssh_public_image_policy "$ssh_policy" || fail "could not write image SSH publication policy"
	chown 0:0 -- "$ssh_policy"
	chmod 0644 -- "$ssh_policy"
	verify_image_file /etc/ssh/sshd_config.d/99-lmi-public-image.conf 644 a77a68392af734fe7f110041db319673cddae05ac38a6720734a37b1bbc7967b
	[[ "$(find "$ssh_dropin_dir" -xdev -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == $'50-postmarketos-ui-policy.conf\n99-lmi-public-image.conf' ]] ||
		fail "sanitized image SSH drop-in inventory mismatch"
}

read_ext4_u32() {
	local image=$1 offset=$2 value
	value="$(od -An -tu4 -N4 -j "$((1024 + offset))" -- "$image")" || return 1
	value=${value//[[:space:]]/}
	[[ "$value" =~ ^[0-9]+$ ]] || return 1
	printf '%s\n' "$value"
}

verify_repair_epoch() {
	local image=$1
	[[ "$(read_ext4_u32 "$image" 48)" == "$REPAIR_EPOCH" ]] || fail "ext4 s_wtime is not normalized"
	[[ "$(read_ext4_u32 "$image" 64)" == "$REPAIR_EPOCH" ]] || fail "ext4 s_lastcheck is not normalized"
}

normalize_repair_epoch() {
	local image=$1
	printf '\216\343\140\152' | dd of="$image" bs=1 seek=1072 count=4 conv=notrunc status=none || return 1
	printf '\216\343\140\152' | dd of="$image" bs=1 seek=1088 count=4 conv=notrunc status=none || return 1
	verify_repair_epoch "$image"
}

read_u16_at() {
	local image=$1 offset=$2 value
	value="$(od -An -tu2 -N2 -j "$offset" -- "$image")" || return 1
	value=${value//[[:space:]]/}
	[[ "$value" =~ ^[0-9]+$ ]] || return 1
	printf '%s\n' "$value"
}

read_u32_at() {
	local image=$1 offset=$2 value
	value="$(od -An -tu4 -N4 -j "$offset" -- "$image")" || return 1
	value=${value//[[:space:]]/}
	[[ "$value" =~ ^[0-9]+$ ]] || return 1
	printf '%s\n' "$value"
}

verify_journal_extent() {
	local image=$1 inode_extent_offset=$((382 * EXT4_BLOCK_SIZE + 7 * 256 + 40)) report
	report="$("$DUMPE2FS" -h "$image" 2>/dev/null)" || return 1
	grep -Fx 'Block size:               4096' <<<"$report" >/dev/null || return 1
	grep -Fx 'Inodes per group:         16224' <<<"$report" >/dev/null || return 1
	grep -Fx 'Inode size:               256' <<<"$report" >/dev/null || return 1
	grep -Fx 'Journal inode:            8' <<<"$report" >/dev/null || return 1
	grep -Fx 'Total journal blocks:     16384' <<<"$report" >/dev/null || return 1
	grep -Fx 'Journal start:            0' <<<"$report" >/dev/null || return 1
	[[ "$(read_u16_at "$image" "$inode_extent_offset")" == 62218 ]] || return 1
	[[ "$(read_u16_at "$image" "$((inode_extent_offset + 2))")" == 1 ]] || return 1
	[[ "$(read_u16_at "$image" "$((inode_extent_offset + 4))")" == 4 ]] || return 1
	[[ "$(read_u16_at "$image" "$((inode_extent_offset + 6))")" == 0 ]] || return 1
	[[ "$(read_u32_at "$image" "$((inode_extent_offset + 12))")" == 0 ]] || return 1
	[[ "$(read_u16_at "$image" "$((inode_extent_offset + 16))")" == "$JOURNAL_BLOCK_COUNT" ]] || return 1
	[[ "$(read_u16_at "$image" "$((inode_extent_offset + 18))")" == 0 ]] || return 1
	[[ "$(read_u32_at "$image" "$((inode_extent_offset + 20))")" == "$JOURNAL_FIRST_BLOCK" ]] || return 1
}

block_range_sha256() {
	local image=$1 first=$2 count=$3 line
	line="$(dd if="$image" bs="$EXT4_BLOCK_SIZE" skip="$first" count="$count" status=none | sha256sum)" || return 1
	printf '%s\n' "${line%% *}"
}

verify_reviewed_blocks_unallocated() {
	local image=$1 block report
	for block in ${REVIEWED_FREED_BLOCKS[@]+"${REVIEWED_FREED_BLOCKS[@]}"}; do
		report="$("$DEBUGFS" -R "testb $block" "$image" 2>&1)" || return 1
		[[ "$report" == $'debugfs 1.47.2 (1-Jan-2025)\n'"Block $block not in use" ]] || return 1
	done
}

normalize_allocated_ext4() {
	local image=$1 normalized=$2 proof=$3
	[[ -f "$image" && ! -L "$image" && ! -e "$normalized" && ! -L "$normalized" &&
		! -e "$proof" && ! -L "$proof" ]] || return 1
	verify_journal_extent "$image" || return 1
	dd if=/dev/zero of="$image" bs="$EXT4_BLOCK_SIZE" seek="$JOURNAL_INACTIVE_FIRST_BLOCK" \
		count="$JOURNAL_INACTIVE_BLOCK_COUNT" conv=notrunc status=none || return 1
	sync -f "$image" || return 1
	[[ "$(block_range_sha256 "$image" "$JOURNAL_INACTIVE_FIRST_BLOCK" "$JOURNAL_INACTIVE_BLOCK_COUNT")" == \
		"$JOURNAL_INACTIVE_ZERO_SHA256" ]] || return 1
	PRE_NORMALIZATION_SHA256="$(sha256_of "$image")" || return 1
	"$E2IMAGE" -r -a -p "$image" "$normalized" || return 1
	chmod 0600 -- "$normalized" || return 1
	[[ -f "$normalized" && ! -L "$normalized" && "$(stat -Lc %a:%u:%g:%h:%s -- "$normalized")" == \
		"600:0:0:1:$IMAGE_SIZE" ]] || return 1
	"$E2IMAGE" -r -a -p "$normalized" "$proof" || return 1
	chmod 0600 -- "$proof" || return 1
	[[ -f "$proof" && ! -L "$proof" && "$(stat -Lc %a:%u:%g:%h:%s -- "$proof")" == \
		"600:0:0:1:$IMAGE_SIZE" ]] || return 1
	cmp -s -- "$normalized" "$proof" || return 1
	NORMALIZATION_PROOF_SHA256="$(sha256_of "$proof")" || return 1
	[[ "$(block_range_sha256 "$normalized" "$JOURNAL_INACTIVE_FIRST_BLOCK" "$JOURNAL_INACTIVE_BLOCK_COUNT")" == \
		"$JOURNAL_INACTIVE_ZERO_SHA256" ]] || return 1
	for reviewed_block in ${REVIEWED_FREED_BLOCKS[@]+"${REVIEWED_FREED_BLOCKS[@]}"}; do
		[[ "$(block_range_sha256 "$normalized" "$reviewed_block" 1)" == "$ZERO_BLOCK_SHA256" ]] || return 1
	done
	verify_reviewed_blocks_unallocated "$normalized" || return 1
	verify_journal_extent "$normalized" || return 1
	NORMALIZED_ST_BLOCKS="$(stat -Lc %b -- "$normalized")" || return 1
	[[ "$NORMALIZED_ST_BLOCKS" =~ ^[0-9]+$ && "$NORMALIZED_ST_BLOCKS" -gt 0 &&
		$((NORMALIZED_ST_BLOCKS * 512)) -lt "$IMAGE_SIZE" ]] || return 1
	rm -- "$proof" "$image" || return 1
	mv -T -- "$normalized" "$image" || return 1
	[[ "$(sha256_of "$image")" == "$NORMALIZATION_PROOF_SHA256" ]] || return 1
}

verify_gpt_geometry() {
	local raw=$1 report
	report="$(fdisk -l -b "$GPT_SECTOR_SIZE" -- "$raw" 2>&1)" || return 1
	grep -Fx "Units: sectors of 1 * 4096 = 4096 bytes" <<<"$report" >/dev/null || return 1
	grep -Fx "Sector size (logical/physical): 4096 bytes / 4096 bytes" <<<"$report" >/dev/null || return 1
	grep -Fx "Disklabel type: gpt" <<<"$report" >/dev/null || return 1
	awk '$2 == 2048 && $3 == 124927 && $4 == 122880 && $5 == "480M" && $6 == "EFI" { boot++ }
		$2 == 124928 && $3 == 838655 && $4 == 713728 && $5 == "2.7G" && $6 == "Linux" && $7 == "root" && $8 == "(ARM-64)" { root++ }
		END { exit !(boot == 1 && root == 1) }' <<<"$report"
}

snapshot_tree() {
	local root=$1 output=$2 path relative target kind payload xattr_sha xattr_field inode_flags line flag_path
	local flag_expected=0 flag_seen=0
	local -a xattr_batch=() flag_batch=()
	local -A flags_by_path=()
	local path_list=${output}.paths.partial inventory=${output}.inventory.partial
	local xattrs=${output}.xattrs.partial flags=${output}.flags.partial metadata_error=${output}.metadata-error.partial
	[[ -d "$root" && ! -L "$root" ]] || return 1
	[[ ! -e "$output" && ! -L "$output" &&
		! -e "$path_list" && ! -L "$path_list" &&
		! -e "$inventory" && ! -L "$inventory" &&
		! -e "$xattrs" && ! -L "$xattrs" &&
		! -e "$flags" && ! -L "$flags" &&
		! -e "$metadata_error" && ! -L "$metadata_error" ]] || return 1
	: >"$path_list" || return 1
	: >"$inventory" || return 1
	: >"$xattrs" || return 1
	: >"$flags" || return 1
	: >"$metadata_error" || return 1
	chmod 0600 -- "$path_list" "$inventory" "$xattrs" "$flags" "$metadata_error" || return 1
	# A process-substitution producer can fail without changing the while-loop
	# status.  Materialize this pipe so pipefail authenticates both traversal
	# and sorting before any inventory is eligible for publication.
	find "$root" -xdev -print0 | sort -z >"$path_list" || return 1
	# Batch the standard metadata tools.  Per-inode process creation made a
	# complete fixed-rootfs inventory impractically slow, while ordered batches
	# preserve the same fail-closed coverage.
	while IFS= read -r -d '' path; do
		if [[ "$path" == "$root" ]]; then
			relative=/
			target=.
		else
			relative=/${path#"$root"/}
			target=.${relative}
		fi
		[[ "$relative" != *$'\n'* && "$relative" != *'|'* ]] || return 1
		if [[ -L "$path" ]]; then
			kind="symbolic link"
		elif [[ -f "$path" ]]; then
			kind="regular file"
		elif [[ -d "$path" ]]; then
			kind=directory
		else
			return 1
		fi
		xattr_batch+=("$target")
		if [[ "$kind" != "symbolic link" ]]; then
			flag_batch+=("$path")
			flag_expected=$((flag_expected + 1))
		fi
		if (( ${#xattr_batch[@]} == 128 )); then
			(
				cd -- "$root"
				"$GETFATTR" --no-dereference --dump --encoding=hex --match=- -- "${xattr_batch[@]}"
			) >>"$xattrs" 2>>"$metadata_error" || return 1
			xattr_batch=()
		fi
		if (( ${#flag_batch[@]} == 128 )); then
			"$LSATTR" -d "${flag_batch[@]}" >>"$flags" 2>>"$metadata_error" || return 1
			flag_batch=()
		fi
	done <"$path_list"
	if (( ${#xattr_batch[@]} != 0 )); then
		(
			cd -- "$root"
			"$GETFATTR" --no-dereference --dump --encoding=hex --match=- -- "${xattr_batch[@]}"
		) >>"$xattrs" 2>>"$metadata_error" || return 1
	fi
	if (( ${#flag_batch[@]} != 0 )); then
		"$LSATTR" -d "${flag_batch[@]}" >>"$flags" 2>>"$metadata_error" || return 1
	fi
	xattr_sha="$(sha256_of "$xattrs")" || return 1
	while IFS= read -r line; do
		(( ${#line} >= 24 )) || return 1
		[[ "${line:22:1}" == " " ]] || return 1
		inode_flags=${line:0:22}
		[[ "$inode_flags" =~ ^[A-Za-z-]{22}$ ]] || return 1
		flag_path=${line:23}
		if [[ "$flag_path" == "$root" ]]; then
			relative=/
		elif [[ "$flag_path" == "$root/"* ]]; then
			relative=/${flag_path#"$root"/}
		else
			return 1
		fi
		[[ "$relative" != *$'\n'* && "$relative" != *'|'* ]] || return 1
		flags_by_path["$relative"]=$inode_flags
		flag_seen=$((flag_seen + 1))
	done <"$flags"
	(( flag_seen == flag_expected )) || return 1
	while IFS= read -r -d '' path; do
		if [[ "$path" == "$root" ]]; then
			relative=/
		else
			relative=/${path#"$root"/}
		fi
		if [[ -L "$path" ]]; then
			kind="symbolic link"
			payload="$(readlink -- "$path")" || return 1
			[[ "$payload" != *$'\n'* && "$payload" != *'|'* ]] || return 1
			inode_flags=not-applicable
		elif [[ -f "$path" ]]; then
			kind="regular file"
			payload="$(sha256_of "$path")" || return 1
			inode_flags=${flags_by_path["$relative"]-}
		elif [[ -d "$path" ]]; then
			kind=directory
			payload=-
			inode_flags=${flags_by_path["$relative"]-}
		else
			return 1
		fi
		if [[ "$kind" != "symbolic link" ]]; then
			[[ "$inode_flags" =~ ^[A-Za-z-]{22}$ ]] || return 1
		fi
		if [[ "$relative" == / ]]; then
			xattr_field=$xattr_sha
		else
			xattr_field=covered-by-root-xattr-manifest
		fi
		printf '%s|%s|%s|%s|%s|%s\n' "$relative" "$kind" \
			"$(stat -c '%a:%u:%g:%h:%s:%t:%T:%r' -- "$path")" "$payload" "$xattr_field" "$inode_flags" >>"$inventory"
	done <"$path_list"
	chmod 0600 -- "$inventory" || return 1
	mv -T -- "$inventory" "$output" || return 1
	[[ -f "$output" && ! -L "$output" ]] || return 1
}

compute_tree_delta() {
	local before=$1 after=$2 output=$3
	awk -F'|' 'NR == FNR { old[$1]=$0; next }
		{ seen[$1]=1; if (!($1 in old)) print "A|" $0; else if (old[$1] != $0) print "M|" $0 }
		END { for (path in old) if (!(path in seen)) print "D|" old[path] }' "$before" "$after" |
		sort >"$output"
	chmod 0600 -- "$output"
}

emit_full_delta_diagnostic() {
	local parse_status=$1 actual_count=$2 actual_bytes=$3 evidence=$4 disposition=$5 evidence_scope=$6
	local evidence_sha256 evidence_bytes evidence_lines encoded
	evidence_sha256="$(sha256_of "$evidence")" || return 1
	evidence_bytes="$(stat -Lc %s -- "$evidence")" || return 1
	evidence_lines="$(awk 'END { print NR + 0 }' "$evidence")" || return 1
	if [[ "$disposition" == over-bound ]]; then
		printf 'D114 filesystem delta diagnostic: schema=lmi-p2-d114-filesystem-delta-diagnostic/v1 parse=%s expected_count=29 actual_count=%s actual_bytes=%s evidence_scope=%s evidence_sha256=%s evidence_bytes=%s evidence_lines=%s omitted=over-bound\n' \
			"$parse_status" "$actual_count" "$actual_bytes" "$evidence_scope" "$evidence_sha256" \
			"$evidence_bytes" "$evidence_lines" >&2
	else
		[[ "$evidence_scope" == normalized-op-path ]] || return 1
		encoded="$(base64 -w 0 -- "$evidence")" || return 1
		[[ "$encoded" =~ ^[A-Za-z0-9+/]*={0,2}$ ]] || return 1
		printf 'D114 filesystem delta diagnostic: schema=lmi-p2-d114-filesystem-delta-diagnostic/v1 parse=%s expected_count=29 actual_count=%s actual_bytes=%s evidence_scope=%s evidence_sha256=%s evidence_bytes=%s evidence_lines=%s omitted=no op_path_b64=%s\n' \
			"$parse_status" "$actual_count" "$actual_bytes" "$evidence_scope" "$evidence_sha256" \
			"$evidence_bytes" "$evidence_lines" "$encoded" >&2
	fi
}

verify_full_delta_fields() {
	local before=$1 after=$2
	[[ -f "$before" && ! -L "$before" && -f "$after" && ! -L "$after" ]] || return 1
	awk -F'|' -v before_file="$before" -v after_file="$after" '
		BEGIN {
			plain_flags="----------------------"
			extent_flags="--------------e-------"

			add_dir["/etc/lmi-p2-d114"]="755"
			add_dir["/usr/libexec/lmi-p2-d114"]="755"
			add_dir["/usr/share/lmi-p2-d114"]="755"
			add_dir["/var/lib/lmi-p2-d114"]="700"
			add_parent["/etc/lmi-p2-d114"]="/etc"
			add_parent["/usr/libexec/lmi-p2-d114"]="/usr/libexec"
			add_parent["/usr/share/lmi-p2-d114"]="/usr/share"
			add_parent["/var/lib/lmi-p2-d114"]="/var/lib"

			add_file["/etc/lmi-p2-d114/greetd.toml"]="644|260|d576c1f5398bc3820a0ce2361e2b0b187d5c6263b1cf42c8f121d262309de899"
			add_file["/etc/lmi-p2-d114/weston.ini"]="644|688|b54d838ccf435ee41dbd55f5aab245fd68bb65ab19c784a694375f001a9763a2"
			add_file["/usr/libexec/lmi-p2-d114/config-lifecycle"]="755|8194|b0315472595e56b521345a40350d588402c265c40c0df8be638f5317c9fc3c96"
			add_file["/usr/libexec/lmi-p2-d114/session"]="755|15645|3187f95d801e48efc245511544a21e1528efb2d7bbad4fa5866ddf023ca56ca6"
			add_file["/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"]="755|134456|d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a"
			add_file["/usr/libexec/lmi-p2-d114/weston-terminal-sixrow"]="755|200960|6602f7ac8e0c11892eec1d9db0411397e95f704a1655b94e0885a1220962a8cf"
			add_file["/usr/share/lmi-p2-d114/greetd.confd"]="644|139|5be125043d60ff2d3b98624191769efd06320b81262b5552489d93076e85e6a4"
			add_file["/var/lib/lmi-p2-d114/config-v1"]="600|28|2a480e997834e3a1960bd234c1d69905278a026afacdbb37a13522e6dbafe0f9"
			add_file["/var/lib/lmi-p2-d114/greetd-confd.original"]="600|186|6523d36fa3490b4f518184bb0d5a1dd025f14e93ead2b0f9a80f82d685a953f0"
			add_file["/etc/ssh/sshd_config.d/99-lmi-public-image.conf"]="644|200|a77a68392af734fe7f110041db319673cddae05ac38a6720734a37b1bbc7967b"
			add_parent["/etc/lmi-p2-d114/greetd.toml"]="/etc/lmi-p2-d114"
			add_parent["/etc/lmi-p2-d114/weston.ini"]="/etc/lmi-p2-d114"
			add_parent["/usr/libexec/lmi-p2-d114/config-lifecycle"]="/usr/libexec/lmi-p2-d114"
			add_parent["/usr/libexec/lmi-p2-d114/session"]="/usr/libexec/lmi-p2-d114"
			add_parent["/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"]="/usr/libexec/lmi-p2-d114"
			add_parent["/usr/libexec/lmi-p2-d114/weston-terminal-sixrow"]="/usr/libexec/lmi-p2-d114"
			add_parent["/usr/share/lmi-p2-d114/greetd.confd"]="/usr/share/lmi-p2-d114"
			add_parent["/var/lib/lmi-p2-d114/config-v1"]="/var/lib/lmi-p2-d114"
			add_parent["/var/lib/lmi-p2-d114/greetd-confd.original"]="/var/lib/lmi-p2-d114"
			add_parent["/etc/ssh/sshd_config.d/99-lmi-public-image.conf"]="/etc/ssh/sshd_config.d"

			modified_parent["/etc"]=1
			modified_parent["/usr/libexec"]=1
			modified_parent["/usr/share"]=1
			modified_parent["/var/lib"]=1
			modified_file["/etc/conf.d/greetd"]="greetd"
			modified_file["/etc/resolv.conf"]="empty-215"
			modified_file["/usr/lib/apk/db/installed"]="database"
			modified_file["/usr/lib/apk/db/scripts.tar.gz"]="database"
			modified_file["/var/log/apk.log"]="empty-68657"
			modified_shadow["/etc/shadow-"]=1
			deleted_file["/etc/machine-id"]="644|1|33"
			deleted_file["/var/cache/apk/APKINDEX.066df28d.tar.gz"]="644|1|527944"
			deleted_file["/var/cache/apk/APKINDEX.30e6f5af.tar.gz"]="644|1|748453"
			deleted_file["/var/cache/apk/APKINDEX.b53994b4.tar.gz"]="644|1|2507751"
			deleted_file["/var/cache/apk/APKINDEX.bc99f2f3.tar.gz"]="644|1|110467"
		}
		function valid_sha(value) {
			return length(value) == 64 && value ~ /^[0-9a-f]+$/
		}
		# Full-tree inventory paths follow the snapshot_tree serialization
		# contract.  Linux/ext4 names legitimately contain spaces, @, :, [, and
		# UTF-8, and a complete path may exceed one NAME_MAX-sized component.
		# The exact 29-operation parser below intentionally remains narrower.
		function valid_path(value, components, count, component_index) {
			if (value == "/") return 1
			if (substr(value, 1, 1) != "/" || index(value, "|") != 0) return 0
			count=split(value, components, "/")
			if (count < 2 || components[1] != "") return 0
			for (component_index=2; component_index <= count; component_index++) {
				if (components[component_index] == "" || components[component_index] == "." ||
					components[component_index] == "..") return 0
			}
			return 1
		}
		function valid_stat(value, fields, count) {
			count=split(value, fields, ":")
			return count == 8 && fields[1] ~ /^[0-7]+$/ &&
				fields[2] ~ /^[0-9]+$/ && fields[3] ~ /^[0-9]+$/ &&
				fields[4] ~ /^[0-9]+$/ && fields[5] ~ /^[0-9]+$/ &&
				fields[6] ~ /^[0-9a-f]+$/ && fields[7] ~ /^[0-9a-f]+$/ &&
				fields[8] ~ /^[0-9]+$/
		}
		function stat_part(value, part_index, fields) {
			split(value, fields, ":")
			return fields[part_index]
		}
		function safe_new_flags(value) {
			return value == plain_flags || value == extent_flags
		}
		function valid_record(path, kind, stat_value, payload, xattrs, flags) {
			if (!valid_path(path) || !valid_stat(stat_value) ||
				(path == "/" ? !valid_sha(xattrs) : xattrs != "covered-by-root-xattr-manifest")) return 0
			if (kind == "regular file") return valid_sha(payload) && flags ~ /^[A-Za-z-]{22}$/
			if (kind == "directory") return payload == "-" && flags ~ /^[A-Za-z-]{22}$/
			if (kind == "symbolic link") return payload != "" && flags == "not-applicable"
			return 0
		}
		FILENAME == before_file {
			if (NF != 6 || !valid_record($1, $2, $3, $4, $5, $6) || old_seen[$1]++) bad=1
			old_kind[$1]=$2; old_stat[$1]=$3; old_payload[$1]=$4
			old_xattrs[$1]=$5; old_flags[$1]=$6
			next
		}
		FILENAME == after_file {
			if (NF != 6 || !valid_record($1, $2, $3, $4, $5, $6) || new_seen[$1]++) bad=1
			new_kind[$1]=$2; new_stat[$1]=$3; new_payload[$1]=$4
			new_xattrs[$1]=$5; new_flags[$1]=$6
			next
		}
		END {
			for (path in add_dir) {
				parent=add_parent[path]
				if (old_seen[path] || new_seen[path] != 1 || new_seen[parent] != 1 ||
					new_kind[path] != "directory" || new_payload[path] != "-" ||
					stat_part(new_stat[path], 1) != add_dir[path] ||
					stat_part(new_stat[path], 2) != stat_part(new_stat[parent], 2) ||
					stat_part(new_stat[path], 3) != stat_part(new_stat[parent], 3) ||
					stat_part(new_stat[path], 4) != 2 ||
					stat_part(new_stat[path], 6) != 0 || stat_part(new_stat[path], 7) != 0 ||
					stat_part(new_stat[path], 8) != 0 ||
					new_xattrs[path] != "covered-by-root-xattr-manifest" ||
					!safe_new_flags(new_flags[path])) bad=1
			}
			for (path in add_file) {
				split(add_file[path], expected, "|")
				parent=add_parent[path]
				if (old_seen[path] || new_seen[path] != 1 || new_seen[parent] != 1 ||
					new_kind[path] != "regular file" ||
					stat_part(new_stat[path], 1) != expected[1] ||
					stat_part(new_stat[path], 2) != stat_part(new_stat[parent], 2) ||
					stat_part(new_stat[path], 3) != stat_part(new_stat[parent], 3) ||
					stat_part(new_stat[path], 4) != 1 || stat_part(new_stat[path], 5) != expected[2] ||
					stat_part(new_stat[path], 6) != 0 || stat_part(new_stat[path], 7) != 0 ||
					stat_part(new_stat[path], 8) != 0 || new_payload[path] != expected[3] ||
					new_xattrs[path] != "covered-by-root-xattr-manifest" ||
					!safe_new_flags(new_flags[path])) bad=1
			}
			for (path in modified_parent) {
				if (old_seen[path] != 1 || new_seen[path] != 1 ||
					old_kind[path] != "directory" || new_kind[path] != "directory" ||
					old_payload[path] != "-" || new_payload[path] != "-" ||
					stat_part(old_stat[path], 1) != 755 || stat_part(new_stat[path], 1) != 755 ||
					stat_part(old_stat[path], 2) != stat_part(new_stat[path], 2) ||
					stat_part(old_stat[path], 3) != stat_part(new_stat[path], 3) ||
					stat_part(new_stat[path], 4) != stat_part(old_stat[path], 4) + 1 ||
					stat_part(old_stat[path], 6) != 0 || stat_part(new_stat[path], 6) != 0 ||
					stat_part(old_stat[path], 7) != 0 || stat_part(new_stat[path], 7) != 0 ||
					stat_part(old_stat[path], 8) != 0 || stat_part(new_stat[path], 8) != 0 ||
					old_xattrs[path] != new_xattrs[path] || old_flags[path] != new_flags[path]) bad=1
			}
			for (path in modified_file) {
				if (old_seen[path] != 1 || new_seen[path] != 1 ||
					old_kind[path] != "regular file" || new_kind[path] != "regular file" ||
					stat_part(old_stat[path], 1) != 644 || stat_part(new_stat[path], 1) != 644 ||
					stat_part(old_stat[path], 2) != stat_part(new_stat[path], 2) ||
					stat_part(old_stat[path], 3) != stat_part(new_stat[path], 3) ||
					stat_part(old_stat[path], 4) != 1 || stat_part(new_stat[path], 4) != 1 ||
					stat_part(old_stat[path], 6) != 0 || stat_part(new_stat[path], 6) != 0 ||
					stat_part(old_stat[path], 7) != 0 || stat_part(new_stat[path], 7) != 0 ||
					stat_part(old_stat[path], 8) != 0 || stat_part(new_stat[path], 8) != 0 ||
					old_xattrs[path] != new_xattrs[path] || old_flags[path] != new_flags[path] ||
					!valid_sha(old_payload[path]) || !valid_sha(new_payload[path]) ||
					old_payload[path] == new_payload[path]) bad=1
				if (modified_file[path] == "greetd" &&
					(old_payload[path] != "6523d36fa3490b4f518184bb0d5a1dd025f14e93ead2b0f9a80f82d685a953f0" ||
					 new_payload[path] != "5be125043d60ff2d3b98624191769efd06320b81262b5552489d93076e85e6a4" ||
					 stat_part(old_stat[path], 5) != 186 || stat_part(new_stat[path], 5) != 139)) bad=1
				if (modified_file[path] == "empty-215" &&
					(stat_part(old_stat[path], 5) != 215 || stat_part(new_stat[path], 5) != 0 ||
					 new_payload[path] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) bad=1
				if (modified_file[path] == "empty-68657" &&
					(stat_part(old_stat[path], 5) != 68657 || stat_part(new_stat[path], 5) != 0 ||
					 new_payload[path] != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) bad=1
			}
			for (path in modified_shadow) {
				if (old_seen[path] != 1 || new_seen[path] != 1 ||
					old_seen["/etc/shadow"] != 1 || new_seen["/etc/shadow"] != 1 ||
					old_kind[path] != "regular file" || new_kind[path] != "regular file" ||
					old_kind["/etc/shadow"] != "regular file" || new_kind["/etc/shadow"] != "regular file" ||
					stat_part(old_stat[path], 1) != 640 || stat_part(new_stat[path], 1) != 640 ||
					stat_part(old_stat[path], 2) != stat_part(new_stat[path], 2) ||
					stat_part(old_stat[path], 3) != stat_part(new_stat[path], 3) ||
					stat_part(old_stat[path], 4) != 1 || stat_part(new_stat[path], 4) != 1 ||
					stat_part(old_stat[path], 5) != 730 || stat_part(new_stat[path], 5) != 731 ||
					stat_part(old_stat[path], 6) != 0 || stat_part(new_stat[path], 6) != 0 ||
					stat_part(old_stat[path], 7) != 0 || stat_part(new_stat[path], 7) != 0 ||
					stat_part(old_stat[path], 8) != 0 || stat_part(new_stat[path], 8) != 0 ||
					old_xattrs[path] != new_xattrs[path] || old_flags[path] != new_flags[path] ||
					!valid_sha(old_payload[path]) || !valid_sha(new_payload[path]) ||
					old_payload[path] == new_payload[path] ||
					old_payload["/etc/shadow"] != new_payload["/etc/shadow"] ||
					new_payload[path] != new_payload["/etc/shadow"]) bad=1
			}
			for (path in deleted_file) {
				split(deleted_file[path], expected, "|")
				if (old_seen[path] != 1 || new_seen[path] || old_kind[path] != "regular file" ||
					stat_part(old_stat[path], 1) != expected[1] ||
					stat_part(old_stat[path], 4) != expected[2] || stat_part(old_stat[path], 5) != expected[3] ||
					stat_part(old_stat[path], 6) != 0 || stat_part(old_stat[path], 7) != 0 ||
					stat_part(old_stat[path], 8) != 0 || !valid_sha(old_payload[path]) ||
					old_xattrs[path] != "covered-by-root-xattr-manifest" ||
					!safe_new_flags(old_flags[path])) bad=1
			}
			exit bad != 0
		}
	' "$before" "$after"
}

verify_full_delta() {
	local delta=$1 op_paths=$2 before=$3 after=$4
	local byte_count line_count parse_status awk_status
	[[ -f "$delta" && ! -L "$delta" ]] || fail "filesystem delta inventory is unsafe"
	: >"$op_paths"
	chmod 0600 -- "$op_paths"
	byte_count="$(stat -Lc %s -- "$delta")" || fail "filesystem delta size check failed"
	[[ "$byte_count" =~ ^[0-9]+$ ]] || fail "filesystem delta size is invalid"
	line_count="$(awk 'END { print NR + 0 }' "$delta")" || fail "filesystem delta line count failed"
	[[ "$line_count" =~ ^[0-9]+$ ]] || fail "filesystem delta line count is invalid"
	if (( byte_count > 8192 )); then
		emit_full_delta_diagnostic byte-limit "$line_count" "$byte_count" "$delta" over-bound raw-delta ||
			fail "filesystem delta diagnostic generation failed"
		fail "filesystem delta escaped the exact package/lifecycle allowlist"
	fi
	if (( line_count > 32 )); then
		emit_full_delta_diagnostic line-limit "$line_count" "$byte_count" "$delta" over-bound raw-delta ||
			fail "filesystem delta diagnostic generation failed"
		fail "filesystem delta escaped the exact package/lifecycle allowlist"
	fi
	parse_status=valid
	if awk -F'|' -v diagnostic="$op_paths" '
		BEGIN {
			expected["A|/etc/lmi-p2-d114"]=1
			expected["A|/etc/lmi-p2-d114/greetd.toml"]=1
			expected["A|/etc/lmi-p2-d114/weston.ini"]=1
			expected["A|/usr/libexec/lmi-p2-d114"]=1
			expected["A|/usr/libexec/lmi-p2-d114/config-lifecycle"]=1
			expected["A|/usr/libexec/lmi-p2-d114/session"]=1
			expected["A|/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"]=1
			expected["A|/usr/libexec/lmi-p2-d114/weston-terminal-sixrow"]=1
			expected["A|/usr/share/lmi-p2-d114"]=1
			expected["A|/usr/share/lmi-p2-d114/greetd.confd"]=1
			expected["A|/var/lib/lmi-p2-d114"]=1
			expected["A|/var/lib/lmi-p2-d114/config-v1"]=1
			expected["A|/var/lib/lmi-p2-d114/greetd-confd.original"]=1
			expected["A|/etc/ssh/sshd_config.d/99-lmi-public-image.conf"]=1
			expected["M|/etc"]=1
			expected["M|/etc/conf.d/greetd"]=1
			expected["M|/etc/resolv.conf"]=1
			expected["M|/etc/shadow-"]=1
			expected["D|/etc/machine-id"]=1
			expected["D|/var/cache/apk/APKINDEX.066df28d.tar.gz"]=1
			expected["D|/var/cache/apk/APKINDEX.30e6f5af.tar.gz"]=1
			expected["D|/var/cache/apk/APKINDEX.b53994b4.tar.gz"]=1
			expected["D|/var/cache/apk/APKINDEX.bc99f2f3.tar.gz"]=1
			expected["M|/usr/lib/apk/db/installed"]=1
			expected["M|/usr/lib/apk/db/scripts.tar.gz"]=1
			expected["M|/usr/libexec"]=1
			expected["M|/usr/share"]=1
			expected["M|/var/log/apk.log"]=1
			expected["M|/var/lib"]=1
		}
		function emit(value) { print value >> diagnostic }
		{
			if (NF != 7 || $1 !~ /^[AMD]$/ ||
				$2 !~ /^\/[A-Za-z0-9._+-]+(\/[A-Za-z0-9._+-]+)*$/ ||
				$2 ~ /(^|\/)\.\.?($|\/)/ || length($2) > 256 ||
				$3 == "" || $4 == "" || $5 == "" || $6 == "" || $7 == "") {
				schema_bad=1
				emit("INVALID|line-" NR)
				next
			}
			pair=$1 "|" $2
			emit(pair)
			if (seen_path[$2]++) duplicate=1
			if (++seen_pair[pair] > 1) duplicate=1
			if (!(pair in expected)) mismatch=1
		}
		END {
			for (pair in expected) if (seen_pair[pair] != 1) mismatch=1
			if (NR != 29) mismatch=1
			if (schema_bad) exit 2
			if (duplicate) exit 3
			if (mismatch) exit 4
		}
	' "$delta"; then
		parse_status=valid
	else
		awk_status=$?
		case "$awk_status" in
			2) parse_status=invalid-schema ;;
			3) parse_status=duplicate ;;
			4) parse_status=set-mismatch ;;
			*) parse_status=validator-error ;;
		esac
	fi
	if [[ "$parse_status" != valid ]]; then
		emit_full_delta_diagnostic "$parse_status" "$line_count" "$byte_count" "$op_paths" included normalized-op-path ||
			fail "filesystem delta diagnostic generation failed"
		fail "filesystem delta escaped the exact package/lifecycle allowlist"
	fi
	if ! verify_full_delta_fields "$before" "$after"; then
		emit_full_delta_diagnostic field-mismatch "$line_count" "$byte_count" "$op_paths" included normalized-op-path ||
			fail "filesystem delta diagnostic generation failed"
		fail "filesystem delta escaped the exact package/lifecycle allowlist"
	fi
}

strip_target_records() {
	local database=$1 output=$2
	awk 'BEGIN { RS=""; ORS="" }
		$0 !~ /(^|\n)P:(device-xiaomi-lmi-terminal|lmi-weston-sixrow-clients)(\n|$)/ { print $0 "\n\n" }' "$database" >"$output"
	chmod 0600 -- "$output"
}

verify_p2_record_files() {
	local record=$1 manifest=$2 directory= line relative encoded expected actual
	awk '/^F:/ { directory=substr($0,3); next }
		/^R:/ { file=substr($0,3); next }
		/^Z:/ { print "/" directory "/" file "|" substr($0,3) }' "$record" >"$manifest"
	[[ "$(cut -d'|' -f1 "$manifest")" == $'/etc/lmi-p2-d114/greetd.toml\n/etc/lmi-p2-d114/weston.ini\n/usr/libexec/lmi-p2-d114/config-lifecycle\n/usr/libexec/lmi-p2-d114/session\n/usr/share/lmi-p2-d114/greetd.confd' ]] ||
		fail "target package file inventory mismatch"
	while IFS='|' read -r relative encoded; do
		[[ "$encoded" == Q1* ]] || fail "target package checksum encoding mismatch: $relative"
		expected="$(printf '%s' "${encoded#Q1}" | base64 -d | od -An -tx1 | tr -d ' \n')" ||
			fail "target package checksum decode failed: $relative"
		actual="$(sha1sum -- "$MOUNTPOINT$relative")" || fail "target package SHA1 failed: $relative"
		actual=${actual%% *}
		[[ "$actual" == "$expected" ]] || fail "target package installed checksum mismatch: $relative"
	done <"$manifest"
}

verify_sixrow_record_files() {
	local record=$1 manifest=$2 directory= relative encoded expected actual
	awk '/^F:/ { directory=substr($0,3); next }
		/^R:/ { file=substr($0,3); next }
		/^Z:/ { print "/" directory "/" file "|" substr($0,3) }' "$record" >"$manifest"
	[[ "$(cut -d'|' -f1 "$manifest")" == $'/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow\n/usr/libexec/lmi-p2-d114/weston-terminal-sixrow' ]] ||
		fail "six-row package file inventory mismatch"
	while IFS='|' read -r relative encoded; do
		[[ "$encoded" == Q1* ]] || fail "six-row package checksum encoding mismatch: $relative"
		expected="$(printf '%s' "${encoded#Q1}" | base64 -d | od -An -tx1 | tr -d ' \n')" ||
			fail "six-row package checksum decode failed: $relative"
		actual="$(sha1sum -- "$MOUNTPOINT$relative")" || fail "six-row package SHA1 failed: $relative"
		actual=${actual%% *}
		[[ "$actual" == "$expected" ]] || fail "six-row installed checksum mismatch: $relative"
	done <"$manifest"
}

# This is deliberately the same strict installed-record grammar used by the
# reviewed live installer: every scalar is unique, C is the exact APK checksum,
# the only a: records are the two exact executable attributes, and the F/R/Z/a
# state machine rejects reordered, duplicate, missing, or unknown records.
validate_p2_installed_record() {
	local database=$1 record=$2
	awk -v output="$record" -v package_checksum="$P2_APK_CHECKSUM" '
		BEGIN {
			RS=""; FS="\n"; ORS="\n\n"
			expected_value["P"]="device-xiaomi-lmi-terminal"
			expected_value["V"]="0.1.0-r2"
			expected_value["A"]="noarch"
			expected_value["S"]="8775"
			expected_value["I"]="24926"
			expected_value["T"]="Pinned non-root Weston terminal session for Xiaomi lmi D114"
			expected_value["U"]="https://postmarketos.org"
			expected_value["L"]="MIT"
			expected_value["o"]="device-xiaomi-lmi-terminal"
			expected_value["m"]="lmi P2 maintainers <noreply@example.invalid>"
			expected_value["t"]="1784522705"
			expected_value["c"]="uncommitted-p2-d114-source-lock-v4"
			expected_D="device-xiaomi-lmi=1-r144 greetd=0.10.3-r11 greetd-openrc=0.10.3-r11 greetd-phrog=0.53.0-r0 libseat=0.9.3-r1 libweston=14.0.2-r5 linux-xiaomi-lmi=4.19.325-r15 lmi-weston-sixrow-clients=14.0.2-r2 openrc=0.63.2-r0 seatd=0.9.3-r1 seatd-openrc=0.9.3-r1 weston=14.0.2-r5 weston-backend-drm=14.0.2-r5 weston-shell-desktop=14.0.2-r5 weston-terminal=14.0.2-r5 /bin/sh"
			expected_dep["/bin/sh"]=1
			expected_dep["device-xiaomi-lmi=1-r144"]=1
			expected_dep["greetd=0.10.3-r11"]=1
			expected_dep["greetd-openrc=0.10.3-r11"]=1
			expected_dep["greetd-phrog=0.53.0-r0"]=1
			expected_dep["libseat=0.9.3-r1"]=1
			expected_dep["libweston=14.0.2-r5"]=1
			expected_dep["linux-xiaomi-lmi=4.19.325-r15"]=1
			expected_dep["lmi-weston-sixrow-clients=14.0.2-r2"]=1
			expected_dep["openrc=0.63.2-r0"]=1
			expected_dep["seatd=0.9.3-r1"]=1
			expected_dep["seatd-openrc=0.9.3-r1"]=1
			expected_dep["weston=14.0.2-r5"]=1
			expected_dep["weston-backend-drm=14.0.2-r5"]=1
			expected_dep["weston-shell-desktop=14.0.2-r5"]=1
			expected_dep["weston-terminal=14.0.2-r5"]=1
			expected_file["etc/lmi-p2-d114/greetd.toml"]="Q17aD3D/27DhKiygFdfBjjWQ46v/4="
			expected_file["etc/lmi-p2-d114/weston.ini"]="Q1ACVXZU3ZSa9r/vWT8UkYAfbLRlw="
			expected_file["usr/libexec/lmi-p2-d114/config-lifecycle"]="Q1fz2JibH7B8jAdosh8vogpdSyQZM="
			expected_file["usr/libexec/lmi-p2-d114/session"]="Q1HZ+4EtKUzGLZ9gU4XrAdWTyoAVM="
			expected_file["usr/share/lmi-p2-d114/greetd.confd"]="Q11ujOtYABrGQSohB67SphVfwH5C8="
			expected_attr["usr/libexec/lmi-p2-d114/config-lifecycle"]="0:0:755"
			expected_attr["usr/libexec/lmi-p2-d114/session"]="0:0:755"
			expected_dir["etc"]=1
			expected_dir["etc/lmi-p2-d114"]=1
			expected_dir["usr"]=1
			expected_dir["usr/libexec"]=1
			expected_dir["usr/libexec/lmi-p2-d114"]=1
			expected_dir["usr/share"]=1
			expected_dir["usr/share/lmi-p2-d114"]=1
			allowed["C"]=allowed["P"]=allowed["V"]=allowed["A"]=1
			allowed["S"]=allowed["I"]=allowed["T"]=allowed["U"]=1
			allowed["L"]=allowed["o"]=allowed["m"]=allowed["t"]=1
			allowed["c"]=allowed["D"]=allowed["F"]=allowed["R"]=1
			allowed["Z"]=allowed["a"]=1
		}
		{
			package=""
			for (i=1; i<=NF; i++) if ($i ~ /^P:/) package=substr($i,3)
			if (package != "device-xiaomi-lmi-terminal") next
			seen++
			delete value; delete count; delete actual_dep; delete actual_file
			delete file_checksum; delete file_attr; delete actual_dir
			directory=""; current_file=""
			for (i=1; i<=NF; i++) {
				field=substr($i,1,1); item=substr($i,3)
				if (substr($i,2,1) != ":" || !(field in allowed)) { bad=1; continue }
				count[field]++; value[field]=item
				if (field == "F") {
					if (current_file != "") bad=1
					directory=item; current_file=""; actual_dir[item]++
				}
				if (field == "R") {
					if (current_file != "") bad=1
					current_file=(directory == "" ? item : directory "/" item)
					actual_file[current_file]++
				}
				if (field == "a") {
					if (current_file == "" || (current_file in file_attr)) bad=1
					else file_attr[current_file]=item
				}
				if (field == "Z" && current_file != "") {
					if (current_file in file_checksum) bad=1
					file_checksum[current_file]=item
					current_file=""
				}
				else if (field == "Z") bad=1
			}
			if (current_file != "") bad=1
			for (field in expected_value)
				if (count[field] != 1 || value[field] != expected_value[field]) bad=1
			if (count["C"] != 1 || value["C"] != package_checksum) bad=1
			if (count["D"] != 1 || value["D"] != expected_D) bad=1
			dep_count=split(value["D"], deps, / +/)
			for (i=1; i<=dep_count; i++) actual_dep[deps[i]]++
			for (dep in expected_dep) if (actual_dep[dep] != 1) bad=1
			for (dep in actual_dep) if (!(dep in expected_dep)) bad=1
			for (file in expected_file)
				if (actual_file[file] != 1 || file_checksum[file] != expected_file[file]) bad=1
			for (file in actual_file) if (!(file in expected_file)) bad=1
			for (file in expected_attr) if (file_attr[file] != expected_attr[file]) bad=1
			for (file in file_attr) if (!(file in expected_attr)) bad=1
			for (directory in expected_dir) if (actual_dir[directory] != 1) bad=1
			for (directory in actual_dir) if (!(directory in expected_dir)) bad=1
			if (count["F"] != 7 || count["R"] != 5 || count["Z"] != 5 || count["a"] != 2) bad=1
			print $0 > output
		}
		END { exit !(seen == 1 && bad == 0) }
	' "$database" || {
		rm -f -- "$record"
		fail "P2 package strict record parser rejected checksum, fields, attributes, dependencies, or inventory"
	}
	chmod 0600 -- "$record"
}

validate_sixrow_installed_record() {
	local database=$1 record=$2
	awk -v output="$record" -v package_checksum="$SIXROW_APK_CHECKSUM" '
		BEGIN {
			RS=""; FS="\n"; ORS="\n\n"
			expected_value["P"]="lmi-weston-sixrow-clients"
			expected_value["V"]="14.0.2-r2"
			expected_value["A"]="aarch64"
			expected_value["S"]="121842"
			expected_value["I"]="335416"
			expected_value["T"]="Hash-locked six-row Weston keyboard and text-input terminal for xiaomi-lmi"
			expected_value["U"]="https://gitlab.freedesktop.org/wayland/weston"
			expected_value["L"]="MIT"
			expected_value["o"]="lmi-weston-sixrow-clients"
			expected_value["m"]="Local lmi port work <noreply@example.invalid>"
			expected_value["t"]="1784730238"
			expected_D="so:libc.musl-aarch64.so.1 so:libcairo.so.2 so:libfontconfig.so.1 so:libgobject-2.0.so.0 so:libpango-1.0.so.0 so:libpangocairo-1.0.so.0 so:libpixman-1.so.0 so:libpng16.so.16 so:libwayland-client.so.0 so:libwayland-cursor.so.0 so:libxkbcommon.so.0"
			expected_dep["so:libc.musl-aarch64.so.1"]=1
			expected_dep["so:libcairo.so.2"]=1
			expected_dep["so:libfontconfig.so.1"]=1
			expected_dep["so:libgobject-2.0.so.0"]=1
			expected_dep["so:libpango-1.0.so.0"]=1
			expected_dep["so:libpangocairo-1.0.so.0"]=1
			expected_dep["so:libpixman-1.so.0"]=1
			expected_dep["so:libpng16.so.16"]=1
			expected_dep["so:libwayland-client.so.0"]=1
			expected_dep["so:libwayland-cursor.so.0"]=1
			expected_dep["so:libxkbcommon.so.0"]=1
			expected_file["usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"]="Q1XSUCcmg4Qp6FPO9eNoHsqhU0Rls="
			expected_file["usr/libexec/lmi-p2-d114/weston-terminal-sixrow"]="Q1TfC5e5TmOzP1rew68T4D0bOCiE4="
			expected_attr["usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"]="0:0:755"
			expected_attr["usr/libexec/lmi-p2-d114/weston-terminal-sixrow"]="0:0:755"
			expected_dir["usr"]=1
			expected_dir["usr/libexec"]=1
			expected_dir["usr/libexec/lmi-p2-d114"]=1
			allowed["C"]=allowed["P"]=allowed["V"]=allowed["A"]=1
			allowed["S"]=allowed["I"]=allowed["T"]=allowed["U"]=1
			allowed["L"]=allowed["o"]=allowed["m"]=allowed["t"]=1
			allowed["c"]=allowed["D"]=allowed["F"]=allowed["R"]=1
			allowed["Z"]=allowed["a"]=1
		}
		{
			package=""
			for (i=1; i<=NF; i++) if ($i ~ /^P:/) package=substr($i,3)
			if (package != "lmi-weston-sixrow-clients") next
			seen++
			delete value; delete count; delete actual_dep; delete actual_file
			delete file_checksum; delete file_attr; delete actual_dir
			directory=""; current_file=""
			for (i=1; i<=NF; i++) {
				field=substr($i,1,1); item=substr($i,3)
				if (substr($i,2,1) != ":" || !(field in allowed)) { bad=1; continue }
				count[field]++; value[field]=item
				if (field == "F") {
					if (current_file != "") bad=1
					directory=item; current_file=""; actual_dir[item]++
				}
				if (field == "R") {
					if (current_file != "") bad=1
					current_file=(directory == "" ? item : directory "/" item)
					actual_file[current_file]++
				}
				if (field == "a") {
					if (current_file == "" || (current_file in file_attr)) bad=1
					else file_attr[current_file]=item
				}
				if (field == "Z" && current_file != "") {
					if (current_file in file_checksum) bad=1
					file_checksum[current_file]=item
					current_file=""
				}
				else if (field == "Z") bad=1
			}
			if (current_file != "") bad=1
			for (field in expected_value)
				if (count[field] != 1 || value[field] != expected_value[field]) bad=1
			if (count["C"] != 1 || value["C"] != package_checksum) bad=1
			if (count["D"] != 1 || value["D"] != expected_D) bad=1
			dep_count=split(value["D"], deps, / +/)
			for (i=1; i<=dep_count; i++) actual_dep[deps[i]]++
			for (dep in expected_dep) if (actual_dep[dep] != 1) bad=1
			for (dep in actual_dep) if (!(dep in expected_dep)) bad=1
			for (file in expected_file)
				if (actual_file[file] != 1 || file_checksum[file] != expected_file[file]) bad=1
			for (file in actual_file) if (!(file in expected_file)) bad=1
			for (file in expected_attr) if (file_attr[file] != expected_attr[file]) bad=1
			for (file in file_attr) if (!(file in expected_attr)) bad=1
			for (directory in expected_dir) if (actual_dir[directory] != 1) bad=1
			for (directory in actual_dir) if (!(directory in expected_dir)) bad=1
			if (count["F"] != 3 || count["R"] != 2 || count["Z"] != 2 || count["a"] != 2) bad=1
			print $0 > output
		}
		END { exit !(seen == 1 && bad == 0) }
	' "$database" || {
		rm -f -- "$record"
		fail "six-row package strict record parser rejected checksum, fields, attributes, dependencies, or inventory"
	}
	chmod 0600 -- "$record"
}

verify_scripts_delta() {
	local before=$1 after=$2 work=$3
	local baseline_dir=$work/before final_dir=$work/after target_list=$work/target.list
	mkdir -m 0700 -- "$work" "$baseline_dir" "$final_dir"
	tar -xzf "$before" -C "$baseline_dir" --no-same-owner --no-same-permissions
	tar -xzf "$after" -C "$final_dir" --no-same-owner --no-same-permissions
	find "$final_dir" -xdev -mindepth 1 -maxdepth 1 -type f -name 'device-xiaomi-lmi-terminal-0.1.0-r2.*' -print | sort >"$target_list"
	[[ "$(wc -l <"$target_list")" == 3 ]] || fail "target package script inventory mismatch"
	while IFS= read -r path; do
		case "$path" in
			*.post-install) expected=ccf7bf1a9cf1cbd29b5818f4776d3980953b52c4a341358ba844e0dd82f0c3f2 ;;
			*.post-upgrade) expected=b894337705b202b1eb298a3f4c41295db78ef1a304b2ab37b28e81e973e46f9e ;;
			*.pre-deinstall) expected=6d0ed5ed0ca82532d2721592fafd3ae7068839afe5dfd605fda172a67ac2e537 ;;
			*) fail "unexpected target package script" ;;
		esac
		[[ -f "$path" && ! -L "$path" && "$(sha256_of "$path")" == "$expected" ]] || fail "target package script mismatch"
		rm -f -- "$path"
	done <"$target_list"
	BASE_SCRIPTS_INVENTORY=$work/before.inventory
	FINAL_SCRIPTS_INVENTORY=$work/after.inventory
	snapshot_tree "$baseline_dir" "$BASE_SCRIPTS_INVENTORY"
	snapshot_tree "$final_dir" "$FINAL_SCRIPTS_INVENTORY"
	cmp -s -- "$BASE_SCRIPTS_INVENTORY" "$FINAL_SCRIPTS_INVENTORY" || fail "non-target scripts.tar.gz members changed"
}

verify_installed_records() {
	local database=$1 p2_record=$2 sixrow_record=$3
	validate_p2_installed_record "$database" "$p2_record"
	verify_p2_record_files "$p2_record" "${p2_record}.files"
	validate_sixrow_installed_record "$database" "$sixrow_record"
	verify_sixrow_record_files "$sixrow_record" "${sixrow_record}.files"
}

write_sandbox_entry() {
	local destination=$1
	printf '%s\n' '#!/bin/sh' \
		'set -eu' \
		'set -f' \
		'cap_lines=0' \
		'nonewprivs=0' \
		'while read -r key value rest; do' \
		' case "$key" in CapInh:|CapPrm:|CapEff:|CapBnd:|CapAmb:) [ "$value" = 0000000000000000 ] || exit 120; cap_lines=$((cap_lines + 1));; NoNewPrivs:) [ "$value" = 1 ] || exit 121; nonewprivs=1;; esac' \
		'done </proc/self/status' \
		'[ "$cap_lines" = 5 ] && [ "$nonewprivs" = 1 ] || exit 122' \
		'validate_net_header_one() { [ "$*" = "Inter-| Receive | Transmit" ]; }' \
		'validate_net_header_two() { [ "$*" = "face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed" ]; }' \
		'validate_net_fields() { [ "$#" = 16 ] || return 1; for field do case "$field" in ""|*[!0-9]*) return 1;; esac; done; }' \
		'net_lines=0' \
		'interfaces=0' \
		'while IFS= read -r line; do' \
		' net_lines=$((net_lines + 1))' \
		' case "$net_lines" in' \
		'  1) validate_net_header_one $line || exit 123;;' \
		'  2) validate_net_header_two $line || exit 123;;' \
		'  *) case "$line" in *:*:*) exit 123;; *:*) name=${line%%:*}; fields=${line#*:};; *) exit 123;; esac' \
		'     name=${name#"${name%%[! ]*}"}; name=${name%"${name##*[! ]}"}' \
		'     [ "$name" = lo ] || exit 123' \
		'     validate_net_fields $fields || exit 123' \
		'     interfaces=$((interfaces + 1)); [ "$interfaces" = 1 ] || exit 123;;' \
		' esac' \
		'done </proc/net/dev' \
		'[ "$net_lines" -ge 2 ] || exit 123' \
		'[ "$interfaces" = 1 ] || exit 124' \
		"apk_env=\"export HOME='/root'
export LANG='C'
export LC_ALL='C'
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PWD='/'
export TZ='UTC'\"" \
		"lifecycle_env=\"export HOME='/root'
export LANG='C'
export LC_ALL='C'
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
export PROOT_NO_SECCOMP='1'
export PWD='/'
export TZ='UTC'\"" \
		'actual=$(export -p)' \
		'case "${1-}" in' \
		' apk) [ "$#" = 1 ] || exit 125; [ "$actual" = "$apk_env" ] || exit 128; exec /tools/apk.static --root /image --arch aarch64 --keys-dir /keys --no-logfile --no-network --no-cache --no-scripts --repositories-file /dev/null --force-non-repository add /tools/sixrow.apk /tools/p2.apk;;' \
		' lifecycle) [ "$#" = 1 ] || exit 126; [ "$actual" = "$lifecycle_env" ] || exit 128; exec /runtime/ld-linux-x86-64.so.2 --library-path /runtime /runtime/proot -r /image -q /tools/qemu-aarch64 -w / /usr/libexec/lmi-p2-d114/config-lifecycle install;;' \
		' *) exit 127;;' \
		'esac' >"$destination"
}

main() {
	[[ "$#" == 19 && "$1" == --inside-private-namespace && "$2" == --sealed-script-sha256 &&
		"$4" == --caller-uid && "$6" == --caller-gid && "$8" == --parent-mntns &&
		"${10}" == --parent-netns && "${12}" == --parent-pidns && "${14}" == --parent-ipcns &&
		"${16}" == --parent-utsns && "${18}" == --canonical-source &&
		"${19}" == "$CANONICAL_INJECTOR_SOURCE" ]] ||
		fail "expected only the sealed-launcher namespace contract"
	SEALED_SCRIPT_SHA256=$3
	CALLER_UID=$5
	CALLER_GID=$7
	PARENT_MNTNS=$9
	PARENT_NETNS=${11}
	PARENT_PIDNS=${13}
	PARENT_IPCNS=${15}
	PARENT_UTSNS=${17}
	[[ "$SEALED_SCRIPT_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "invalid sealed script digest"
	[[ "$CALLER_UID" =~ ^[0-9]+$ && "$CALLER_GID" =~ ^[0-9]+$ && "$CALLER_UID" != 0 ]] ||
		fail "invalid unprivileged caller identity"
	[[ "${BASH_SOURCE[0]}" == /run/lmi-p2-d114-inject/inject_rootfs_candidate.*.sh ]] ||
		fail "root entry is not the fixed /run seal"
	[[ -f "${BASH_SOURCE[0]}" && ! -L "${BASH_SOURCE[0]}" ]] || fail "sealed root entry is unsafe"
	[[ "$(stat -Lc %a:%u:%g:%h -- "${BASH_SOURCE[0]}")" == 700:0:0:1 ]] ||
		fail "sealed root entry metadata mismatch"
	[[ "$(sha256_of "${BASH_SOURCE[0]}")" == "$SEALED_SCRIPT_SHA256" ]] || fail "sealed root entry digest mismatch"
	[[ -f "$CANONICAL_INJECTOR_SOURCE" && ! -L "$CANONICAL_INJECTOR_SOURCE" &&
		"$(realpath -e -- "$CANONICAL_INJECTOR_SOURCE")" == "$CANONICAL_INJECTOR_SOURCE" ]] ||
		fail "canonical injector source is unsafe"
	[[ "$(stat -Lc %a:%u:%g:%h -- "$CANONICAL_INJECTOR_SOURCE")" == "755:$CALLER_UID:$CALLER_GID:1" ]] ||
		fail "canonical injector source metadata mismatch"
	[[ "$(sha256_of "$CANONICAL_INJECTOR_SOURCE")" == "$SEALED_SCRIPT_SHA256" ]] ||
		fail "canonical injector source digest mismatch"
	SEALED_SCRIPT_PATH=${BASH_SOURCE[0]}
	SEALED_SCRIPT_ID="$(stat -Lc %d:%i:%a:%u:%g:%h -- "$SEALED_SCRIPT_PATH")"
	for command_name in awk base64 blkid cat chmod chown cmp cp cut dd debugfs dirname dumpe2fs e2fsck e2image env \
		fdisk find findmnt flock grep hostname id ln losetup mkdir mktemp mount mountpoint mv od \
		readlink realpath rm rmdir sha1sum sha256sum sort stat sync tar tr umount uname wc; do
		command -v "$command_name" >/dev/null 2>&1 || fail "missing host tool: $command_name"
	done
	[[ "$(id -ru)" == 0 && "$(id -rg)" == 0 && "$(id -u)" == 0 && "$(id -g)" == 0 ]] ||
		fail "real and effective uid/gid must all be zero"
	verify_private_namespaces
	mount --make-rprivate /
	[[ "$(findmnt -nro PROPAGATION -M /)" != shared* ]] || fail "mount propagation remains shared"

	[[ -d "$REPO" && ! -L "$REPO" ]] || fail "repository root is unsafe"
	REPO_OWNER="$(stat -Lc %u:%g -- "$REPO")"
	[[ "$REPO_OWNER" == "$CALLER_UID:$CALLER_GID" ]] ||
		fail "caller uid/gid does not exactly match repository owner"
	[[ "$INPUT_BUILD_DIR" != "$BUILD_DIR" ]] || fail "input and output directories alias by path"
	open_trusted_directory "$INPUT_BUILD_DIR" INPUT_BUILD_DIR_FD INPUT_BUILD_DIR_ID ||
		fail "read-only input directory is unsafe"
	open_trusted_directory "$BUILD_DIR" BUILD_DIR_FD BUILD_DIR_ID || fail "build directory is unsafe"
	[[ "$INPUT_BUILD_DIR_ID" != "$BUILD_DIR_ID" ]] || fail "input and output directories alias by inode"
	require_repo_ancestors "$INPUT_BUILD_DIR/artifact"
	require_repo_ancestors "$BUILD_DIR/artifact"
	[[ ! -e "$OUTPUT_BUNDLE" && ! -L "$OUTPUT_BUNDLE" ]] || fail "refusing to overwrite: $OUTPUT_BUNDLE"

	open_trusted_file "$RAW" RAW_FD RAW_ID || fail "cannot safely open raw lineage input"
	open_trusted_file "$SPARSE" SPARSE_FD SPARSE_ID || fail "cannot safely open sparse lineage input"
	open_trusted_file "$BASE" BASE_FD BASE_ID || fail "cannot safely open base"
	open_trusted_file "$INPUT" INPUT_FD INPUT_ID || fail "cannot safely open candidate input"
	for spec in "$RAW|raw" "$SPARSE|sparse" "$BASE|base" "$INPUT|candidate-input"; do
		IFS='|' read -r path label <<<"$spec"
		require_private_input "$path" "$label"
	done
	for spec in "$REPAIR_VERIFY_LOG|$REPAIR_VERIFY_LOG_SHA256|repair-verify-log" \
		"$REPAIR_LOG|$REPAIR_LOG_SHA256|repair-log" "$REBUILD_LOCK|$REBUILD_LOCK_SHA256|candidate-rebuild-lock" \
		"$RUNTIME_LOCK|$RUNTIME_LOCK_SHA256|injector-runtime-lock" \
		"$P2_BUILD_ATTESTATION|$P2_BUILD_ATTESTATION_SHA256|P2-build-attestation" \
		"$SIXROW_BUILD_ATTESTATION|$SIXROW_BUILD_ATTESTATION_SHA256|sixrow-build-attestation"; do
		IFS='|' read -r path expected label <<<"$spec"
		open_trusted_file "$path" "${label//-/_}_FD" "${label//-/_}_ID" || fail "cannot safely open $label"
		require_repo_file "$path" 644 "$label"
		descriptor_name="${label//-/_}_FD"
		[[ "$(sha256_of "/proc/self/fd/${!descriptor_name}")" == "$expected" ]] || fail "$label hash mismatch"
	done
	[[ "$(stat -Lc %d:%i -- "/proc/self/fd/$BASE_FD")" != "$(stat -Lc %d:%i -- "/proc/self/fd/$INPUT_FD")" ]] ||
		fail "candidate input aliases base"
	[[ "$(stat -Lc %s -- "/proc/self/fd/$RAW_FD")" == "$RAW_SIZE" ]] || fail "raw lineage size mismatch"
	[[ "$(stat -Lc %s -- "/proc/self/fd/$SPARSE_FD")" == "$SPARSE_SIZE" ]] || fail "sparse lineage size mismatch"
	[[ "$(stat -Lc %s -- "/proc/self/fd/$INPUT_FD")" == "$IMAGE_SIZE" ]] || fail "input size mismatch"
	flock -n -s "$RAW_FD" || fail "raw lineage input is busy"
	flock -n -s "$SPARSE_FD" || fail "sparse lineage input is busy"
	flock -n -s "$BASE_FD" || fail "base is busy"
	flock -n -s "$INPUT_FD" || fail "candidate input is busy"
	[[ "$(sha256_of "/proc/self/fd/$RAW_FD")" == "$RAW_SHA256" ]] || fail "raw lineage hash mismatch"
	[[ "$(sha256_of "/proc/self/fd/$SPARSE_FD")" == "$SPARSE_SHA256" ]] || fail "sparse lineage hash mismatch"
	[[ "$(sha256_of "/proc/self/fd/$BASE_FD")" == "$BASE_SHA256" ]] || fail "base hash mismatch"
	[[ "$(sha256_of "/proc/self/fd/$INPUT_FD")" == "$INPUT_SHA256" ]] || fail "input hash mismatch"
	verify_repair_epoch "/proc/self/fd/$INPUT_FD"
	"$E2FSCK" -fn "/proc/self/fd/$INPUT_FD" || fail "candidate is not clean under pinned e2fsck"
	verify_gpt_geometry "/proc/self/fd/$RAW_FD" || fail "raw 4096-byte GPT geometry mismatch"
	cmp -s -n "$IMAGE_SIZE" -i "$((GPT_SECTOR_SIZE * ROOT_START_SECTOR)):0" -- \
		"/proc/self/fd/$RAW_FD" "/proc/self/fd/$BASE_FD" || fail "raw root partition does not exactly equal base"
	[[ -z "$(findmnt -rn -S "$BASE" || true)" && -z "$(losetup -j "$BASE")" ]] || fail "base is in use"
	[[ -z "$(findmnt -rn -S "$INPUT" || true)" && -z "$(losetup -j "$INPUT")" ]] || fail "input is in use"

	for spec in \
		"$P2_APK|600|P2-APK|$P2_APK_SHA256" \
		"$SIXROW_APK|600|sixrow-APK|$SIXROW_APK_SHA256" \
		"$P2_KEY|644|P2-key|$P2_KEY_SHA256" \
		"$SIXROW_KEY|644|sixrow-key|$SIXROW_KEY_SHA256" \
		"$APK_STATIC|700|apk.static|$APK_STATIC_SHA256" \
		"$PROOT|755|PRoot|$PROOT_SHA256" \
		"$PROOT_TALLOC|644|libtalloc|$PROOT_TALLOC_SHA256" \
		"$QEMU|755|qemu-aarch64|$QEMU_SHA256"; do
		IFS='|' read -r path mode label expected <<<"$spec"
		open_trusted_file "$path" "${label//[^A-Za-z0-9]/_}_FD" "${label//[^A-Za-z0-9]/_}_ID" ||
			fail "cannot safely open $label"
		require_repo_file "$path" "$mode" "$label"
		descriptor_name="${label//[^A-Za-z0-9]/_}_FD"
		descriptor="${!descriptor_name}"
		[[ "$(sha256_of "/proc/self/fd/$descriptor")" == "$expected" ]] || fail "$label hash mismatch"
	done
	[[ "$(stat -Lc %s -- "/proc/self/fd/$P2_APK_FD")" == "$P2_APK_SIZE" ]] || fail "P2 APK size mismatch"
	[[ "$(stat -Lc %s -- "/proc/self/fd/$sixrow_APK_FD")" == "$SIXROW_APK_SIZE" ]] || fail "six-row APK size mismatch"
	for spec in "$HOST_LIBC|755|host-libc|$HOST_LIBC_SHA256" \
		"$HOST_LOADER|755|host-loader|$HOST_LOADER_SHA256" \
		"$BWRAP_LIBSELINUX|644|bwrap-libselinux|$BWRAP_LIBSELINUX_SHA256" \
		"$BWRAP_LIBCAP|644|bwrap-libcap|$BWRAP_LIBCAP_SHA256" \
		"$BWRAP_LIBPCRE|644|bwrap-libpcre|$BWRAP_LIBPCRE_SHA256" \
		"$LSATTR_LIBE2P|644|lsattr-libe2p|$LSATTR_LIBE2P_SHA256" \
		"$LSATTR_LIBCOM_ERR|644|lsattr-libcom-err|$LSATTR_LIBCOM_ERR_SHA256"; do
		IFS='|' read -r path mode label expected <<<"$spec"
		open_trusted_file "$path" "${label//[^A-Za-z0-9]/_}_FD" "${label//[^A-Za-z0-9]/_}_ID" ||
			fail "cannot safely open $label"
		require_system_file "$path" "$mode" "$label"
		descriptor_name="${label//[^A-Za-z0-9]/_}_FD"
		descriptor="${!descriptor_name}"
		[[ "$(sha256_of "/proc/self/fd/$descriptor")" == "$expected" ]] || fail "$label hash mismatch"
	done
	for spec in "$BWRAP|755|bubblewrap|$BWRAP_SHA256" "$SIMG2IMG|755|simg2img|$SIMG2IMG_SHA256" \
		"$E2FSCK|755|e2fsck|$E2FSCK_SHA256" "$E2IMAGE|755|e2image|$E2IMAGE_SHA256" \
		"$DEBUGFS|755|debugfs|$DEBUGFS_SHA256" \
		"$DUMPE2FS|755|dumpe2fs|$DUMPE2FS_SHA256" \
		"$GETFATTR|755|getfattr|$GETFATTR_SHA256" "$LSATTR|755|lsattr|$LSATTR_SHA256" \
		"$BASH|755|bash|$BASH_SHA256"; do
		IFS='|' read -r path mode label expected <<<"$spec"
		open_trusted_file "$path" "${label}_FD" "${label}_ID" || fail "cannot safely open $label"
		require_system_file "$path" "$mode" "$label"
		descriptor_name="${label}_FD"
		[[ "$(sha256_of "/proc/self/fd/${!descriptor_name}")" == "$expected" ]] || fail "$label hash mismatch"
	done
	open_trusted_file "$DASH" dash_FD dash_ID || fail "cannot safely open dash"
	require_system_file "$DASH" 755 dash
	[[ "$(sha256_of "/proc/self/fd/$dash_FD")" == "$DASH_SHA256" ]] || fail "dash hash mismatch"
	[[ -L "$HOST_INTERPRETER" && "$(realpath -e -- "$HOST_INTERPRETER")" == "$HOST_LOADER" ]] ||
		fail "PRoot interpreter link mismatch"

	SCRATCH_DIR="$(mktemp -d "$BUILD_DIR/.inject-rootfs.XXXXXXXX")"
	[[ "$(stat -Lc %a -- "$SCRATCH_DIR")" == 700 && "$(stat -Lc %u:%g -- "$SCRATCH_DIR")" == 0:0 ]] ||
		fail "scratch directory metadata mismatch"
	SCRATCH_ID="$(directory_identity_of "$SCRATCH_DIR")"
	SPARSE_ROUNDTRIP="$SCRATCH_DIR/sparse-roundtrip.raw"
	"$SIMG2IMG" "/proc/self/fd/$SPARSE_FD" "$SPARSE_ROUNDTRIP" || fail "sparse lineage conversion failed"
	[[ "$(stat -Lc %a:%u:%g:%h:%s -- "$SPARSE_ROUNDTRIP")" == 600:0:0:1:$RAW_SIZE ]] ||
		fail "sparse lineage conversion metadata mismatch"
	[[ "$(sha256_of "$SPARSE_ROUNDTRIP")" == "$RAW_SHA256" ]] || fail "sparse-to-raw lineage hash mismatch"
	cmp -s -- "$SPARSE_ROUNDTRIP" "/proc/self/fd/$RAW_FD" || fail "sparse-to-raw lineage is not byte-identical"
	rm -f -- "$SPARSE_ROUNDTRIP"
	SPARSE_ROUNDTRIP=
	SCRATCH_IMAGE="$SCRATCH_DIR/rootfs.ext4"
	copy_fd_to_scratch "$INPUT_FD" "$SCRATCH_IMAGE" || fail "independent scratch copy failed"
	[[ "$(stat -Lc %d:%i -- "$SCRATCH_IMAGE")" != "$(stat -Lc %d:%i -- "/proc/self/fd/$INPUT_FD")" ]] ||
		fail "scratch aliases candidate input"
	[[ "$(sha256_of "$SCRATCH_IMAGE")" == "$INPUT_SHA256" ]] || fail "scratch copy hash mismatch"
	[[ "$(blkid -p -s TYPE -o value -- "$SCRATCH_IMAGE")" == ext4 ]] || fail "scratch is not ext4"
	[[ "$(blkid -p -s UUID -o value -- "$SCRATCH_IMAGE")" == "$IMAGE_UUID" ]] || fail "scratch UUID mismatch"
	"$E2FSCK" -fn "$SCRATCH_IMAGE" || fail "scratch precheck failed"
	GEOMETRY_BEFORE="$(filesystem_geometry "$SCRATCH_IMAGE")"
	[[ -n "$GEOMETRY_BEFORE" ]] || fail "could not record ext4 geometry"
	TOOL_CLOSURE="$SCRATCH_DIR/tools"
	mkdir -m 0700 -- "$TOOL_CLOSURE"
	copy_fd_to_scratch "$P2_APK_FD" "$TOOL_CLOSURE/p2.apk"
	copy_fd_to_scratch "$sixrow_APK_FD" "$TOOL_CLOSURE/sixrow.apk"
	copy_fd_to_scratch "$apk_static_FD" "$TOOL_CLOSURE/apk.static"
	copy_fd_to_scratch "$qemu_aarch64_FD" "$TOOL_CLOSURE/qemu-aarch64"
	chmod 0700 -- "$TOOL_CLOSURE/apk.static" "$TOOL_CLOSURE/qemu-aarch64"
	[[ "$(sha256_of "$TOOL_CLOSURE/p2.apk")" == "$P2_APK_SHA256" ]] || fail "P2 APK closure mismatch"
	[[ "$(sha256_of "$TOOL_CLOSURE/sixrow.apk")" == "$SIXROW_APK_SHA256" ]] || fail "six-row APK closure mismatch"
	[[ "$(sha256_of "$TOOL_CLOSURE/apk.static")" == "$APK_STATIC_SHA256" ]] || fail "apk.static closure mismatch"
	[[ "$(sha256_of "$TOOL_CLOSURE/qemu-aarch64")" == "$QEMU_SHA256" ]] || fail "QEMU closure mismatch"

	RUNTIME_CLOSURE="$SCRATCH_DIR/runtime"
	mkdir -m 0700 -- "$RUNTIME_CLOSURE"
	copy_fd_to_scratch "$bubblewrap_FD" "$RUNTIME_CLOSURE/bwrap"
	copy_fd_to_scratch "$dash_FD" "$RUNTIME_CLOSURE/dash"
	copy_fd_to_scratch "$PRoot_FD" "$RUNTIME_CLOSURE/proot"
	copy_fd_to_scratch "$host_loader_FD" "$RUNTIME_CLOSURE/ld-linux-x86-64.so.2"
	copy_fd_to_scratch "$host_libc_FD" "$RUNTIME_CLOSURE/libc.so.6"
	copy_fd_to_scratch "$bwrap_libselinux_FD" "$RUNTIME_CLOSURE/libselinux.so.1"
	copy_fd_to_scratch "$bwrap_libcap_FD" "$RUNTIME_CLOSURE/libcap.so.2"
	copy_fd_to_scratch "$bwrap_libpcre_FD" "$RUNTIME_CLOSURE/libpcre2-8.so.0"
	copy_fd_to_scratch "$libtalloc_FD" "$RUNTIME_CLOSURE/libtalloc.so.2"
	chmod 0700 -- "$RUNTIME_CLOSURE/bwrap" "$RUNTIME_CLOSURE/dash" "$RUNTIME_CLOSURE/proot" \
		"$RUNTIME_CLOSURE/ld-linux-x86-64.so.2"
	chmod 0644 -- "$RUNTIME_CLOSURE/libc.so.6" "$RUNTIME_CLOSURE/libselinux.so.1" \
		"$RUNTIME_CLOSURE/libcap.so.2" "$RUNTIME_CLOSURE/libpcre2-8.so.0" \
		"$RUNTIME_CLOSURE/libtalloc.so.2"
	verify_runtime_closure "$RUNTIME_CLOSURE" || fail "pinned sandbox runtime closure mismatch before use"

	SANDBOX_ENTRY="$TOOL_CLOSURE/sandbox-entry.sh"
	write_sandbox_entry "$SANDBOX_ENTRY"
	chmod 0700 -- "$SANDBOX_ENTRY"
	SANDBOX_ENTRY_SHA256="$(sha256_of "$SANDBOX_ENTRY")"

	MOUNTPOINT="$(mktemp -d "$SCRATCH_DIR/mount.XXXXXXXX")"
	attach_loop_checked || fail "checked loop allocation/attach failed"
	ATTESTED_LOOP_DEVICE_ID=$LOOP_DEVICE_ID
	ATTESTED_LOOP_BACKING_ID=$LOOP_BACKING_ID
	mount -t ext4 -o rw,nosuid,nodev "$LOOP_DEVICE" "$MOUNTPOINT"
	ROOT_MOUNTED=1
	MOUNT_OPTIONS="$(findmnt -nro FSTYPE,OPTIONS -M "$MOUNTPOINT")"
	[[ "$MOUNT_OPTIONS" == ext4* && "$MOUNT_OPTIONS" == *rw* && "$MOUNT_OPTIONS" == *nosuid* && "$MOUNT_OPTIONS" == *nodev* ]] ||
		fail "rootfs mount closure mismatch"
	verify_image_file /etc/apk/world 644 "$WORLD_SHA256"
	verify_image_file /usr/lib/apk/db/installed 644 "$INSTALLED_DB_PRE_SHA256"
	verify_image_file /usr/lib/apk/db/scripts.tar.gz 644 "$SCRIPTS_DB_PRE_SHA256"
	verify_image_file /usr/lib/apk/db/triggers 644 "$TRIGGERS_DB_SHA256"
	FULL_TREE_BEFORE="$SCRATCH_DIR/filesystem.before"
	FULL_TREE_AFTER="$SCRATCH_DIR/filesystem.after"
	snapshot_tree "$MOUNTPOINT" "$FULL_TREE_BEFORE" || fail "could not inventory candidate before injection"
	INSTALLED_DB_BASELINE="$SCRATCH_DIR/installed.before"
	SCRIPTS_DB_BASELINE="$SCRATCH_DIR/scripts.before.tar.gz"
	TRIGGERS_DB_BASELINE="$SCRATCH_DIR/triggers.before"
	KEY_INVENTORY_BASELINE="$SCRATCH_DIR/keys.before"
	cp --reflink=never -- "$MOUNTPOINT/usr/lib/apk/db/installed" "$INSTALLED_DB_BASELINE"
	cp --reflink=never -- "$MOUNTPOINT/usr/lib/apk/db/scripts.tar.gz" "$SCRIPTS_DB_BASELINE"
	cp --reflink=never -- "$MOUNTPOINT/usr/lib/apk/db/triggers" "$TRIGGERS_DB_BASELINE"
	chmod 0600 -- "$INSTALLED_DB_BASELINE" "$SCRIPTS_DB_BASELINE" "$TRIGGERS_DB_BASELINE"
	snapshot_tree "$MOUNTPOINT/etc/apk/keys" "$KEY_INVENTORY_BASELINE" || fail "could not inventory original image keys"
	WORLD_BASELINE="$SCRATCH_DIR/world.before"
	cp --reflink=never -- "$MOUNTPOINT/etc/apk/world" "$WORLD_BASELINE"
	chmod 0600 -- "$WORLD_BASELINE"
	[[ "$(sha256_of "$WORLD_BASELINE")" == "$WORLD_SHA256" ]] || fail "world baseline copy mismatch"
	[[ -d "$MOUNTPOINT/run" && ! -L "$MOUNTPOINT/run" ]] || fail "image /run is unsafe"

	KEY_CLOSURE="$SCRATCH_DIR/keys"
	mkdir -m 0700 -- "$KEY_CLOSURE"
	cp --reflink=never -- "/proc/self/fd/$P2_key_FD" "$KEY_CLOSURE/${P2_KEY##*/}"
	cp --reflink=never -- "/proc/self/fd/$sixrow_key_FD" "$KEY_CLOSURE/${SIXROW_KEY##*/}"
	chmod 0644 -- "$KEY_CLOSURE/${P2_KEY##*/}" "$KEY_CLOSURE/${SIXROW_KEY##*/}"
	[[ "$(find "$KEY_CLOSURE" -xdev -mindepth 1 -maxdepth 1 -printf '%f\n' | sort)" == 'pmos@local-6a5d38f2.rsa.pub' ]] || fail "key closure inventory mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h -- "$KEY_CLOSURE/${P2_KEY##*/}")" == 644:0:0:1 &&
		"$(sha256_of "$KEY_CLOSURE/${P2_KEY##*/}")" == "$P2_KEY_SHA256" ]] || fail "P2 key closure mismatch"
	[[ "$(stat -Lc %a:%u:%g:%h -- "$KEY_CLOSURE/${SIXROW_KEY##*/}")" == 644:0:0:1 &&
		"$(sha256_of "$KEY_CLOSURE/${SIXROW_KEY##*/}")" == "$SIXROW_KEY_SHA256" ]] || fail "six-row key closure mismatch"
	create_source_bridge /run/lmi-p2-d114-inject "$MOUNTPOINT" "$TOOL_CLOSURE" "$KEY_CLOSURE" "$RUNTIME_CLOSURE" ||
		fail "could not create checked root-owned sandbox source bridge"

	sandbox_status=0
	"$RUNTIME_CLOSURE/ld-linux-x86-64.so.2" --library-path "$RUNTIME_CLOSURE" \
		"$RUNTIME_CLOSURE/bwrap" --unshare-user --unshare-pid --unshare-uts --unshare-ipc --die-with-parent --new-session \
		--uid 0 --gid 0 --cap-drop ALL --clearenv \
		--setenv HOME /root --setenv LANG C --setenv LC_ALL C \
		--setenv PATH /usr/sbin:/usr/bin:/sbin:/bin --setenv PWD / --setenv TZ UTC \
		--proc /proc --dev /dev --tmpfs /tmp \
		--bind "$SOURCE_BRIDGE_IMAGE" /image --ro-bind "$SOURCE_BRIDGE_TOOLS" /tools --ro-bind "$SOURCE_BRIDGE_KEYS" /keys \
		--ro-bind "$SOURCE_BRIDGE_RUNTIME" /runtime --chdir / -- \
		/runtime/ld-linux-x86-64.so.2 --library-path /runtime /runtime/dash /tools/sandbox-entry.sh apk || sandbox_status=$?
	(( sandbox_status == 0 )) || fail "sandbox stage apk failed with status $sandbox_status"
	verify_runtime_closure "$RUNTIME_CLOSURE" || fail "pinned sandbox runtime closure changed after APK use"
	[[ -f "$MOUNTPOINT/etc/apk/world" && ! -L "$MOUNTPOINT/etc/apk/world" ]] || fail "APK replaced world unsafely"
	WORLD_REPLACEMENT="$MOUNTPOINT/etc/apk/.world.lmi-p2-d114-restore"
	[[ ! -e "$WORLD_REPLACEMENT" && ! -L "$WORLD_REPLACEMENT" ]] || fail "world restore staging path occupied"
	cp --reflink=never -- "$WORLD_BASELINE" "$WORLD_REPLACEMENT"
	chown 0:0 -- "$WORLD_REPLACEMENT"
	chmod 0644 -- "$WORLD_REPLACEMENT"
	[[ "$(sha256_of "$WORLD_REPLACEMENT")" == "$WORLD_SHA256" ]] || fail "world restore hash mismatch"
	mv -fT -- "$WORLD_REPLACEMENT" "$MOUNTPOINT/etc/apk/world"
	verify_image_file /etc/apk/world 644 "$WORLD_SHA256"
	verify_image_file /etc/conf.d/greetd 644 6523d36fa3490b4f518184bb0d5a1dd025f14e93ead2b0f9a80f82d685a953f0

	verify_runtime_closure "$RUNTIME_CLOSURE" || fail "pinned sandbox runtime closure mismatch before lifecycle use"
	sandbox_status=0
	"$RUNTIME_CLOSURE/ld-linux-x86-64.so.2" --library-path "$RUNTIME_CLOSURE" \
		"$RUNTIME_CLOSURE/bwrap" --unshare-user --unshare-pid --unshare-uts --unshare-ipc --die-with-parent --new-session \
		--uid 0 --gid 0 --cap-drop ALL --clearenv \
		--setenv HOME /root --setenv LANG C --setenv LC_ALL C \
		--setenv PATH /usr/sbin:/usr/bin:/sbin:/bin --setenv PROOT_NO_SECCOMP 1 --setenv PWD / --setenv TZ UTC \
		--proc /proc --dev /dev --tmpfs /tmp \
		--bind "$SOURCE_BRIDGE_IMAGE" /image --ro-bind "$SOURCE_BRIDGE_TOOLS" /tools \
		--ro-bind "$SOURCE_BRIDGE_RUNTIME" /runtime --chdir / -- \
		/runtime/ld-linux-x86-64.so.2 --library-path /runtime /runtime/dash /tools/sandbox-entry.sh lifecycle || sandbox_status=$?
	(( sandbox_status == 0 )) || fail "sandbox stage lifecycle failed with status $sandbox_status"
	verify_runtime_closure "$RUNTIME_CLOSURE" || fail "pinned sandbox runtime closure changed after lifecycle use"
	cleanup_source_bridge || fail "checked sandbox source bridge cleanup failed"
	sanitize_public_image

	verify_image_file /usr/libexec/lmi-p2-d114/config-lifecycle 755 b0315472595e56b521345a40350d588402c265c40c0df8be638f5317c9fc3c96
	verify_image_file /usr/libexec/lmi-p2-d114/session 755 3187f95d801e48efc245511544a21e1528efb2d7bbad4fa5866ddf023ca56ca6
	verify_image_file /usr/libexec/lmi-p2-d114/weston-keyboard-sixrow 755 d6b9e514d170024ab95bd0539eb84d5ee32fd4f9673a58f7a1dc8d0a4c5e9d2a
	verify_image_file /usr/libexec/lmi-p2-d114/weston-terminal-sixrow 755 6602f7ac8e0c11892eec1d9db0411397e95f704a1655b94e0885a1220962a8cf
	verify_image_file /etc/lmi-p2-d114/weston.ini 644 b54d838ccf435ee41dbd55f5aab245fd68bb65ab19c784a694375f001a9763a2
	verify_image_file /etc/lmi-p2-d114/greetd.toml 644 d576c1f5398bc3820a0ce2361e2b0b187d5c6263b1cf42c8f121d262309de899
	verify_image_file /usr/share/lmi-p2-d114/greetd.confd 644 5be125043d60ff2d3b98624191769efd06320b81262b5552489d93076e85e6a4
	verify_image_file /etc/conf.d/greetd 644 5be125043d60ff2d3b98624191769efd06320b81262b5552489d93076e85e6a4
	verify_image_file /var/lib/lmi-p2-d114/greetd-confd.original 600 6523d36fa3490b4f518184bb0d5a1dd025f14e93ead2b0f9a80f82d685a953f0
	verify_image_file /var/lib/lmi-p2-d114/config-v1 600 2a480e997834e3a1960bd234c1d69905278a026afacdbb37a13522e6dbafe0f9
	[[ -d "$MOUNTPOINT/var/lib/lmi-p2-d114" && ! -L "$MOUNTPOINT/var/lib/lmi-p2-d114" ]] || fail "lifecycle state missing"
	[[ "$(stat -Lc %a:%u:%g -- "$MOUNTPOINT/var/lib/lmi-p2-d114")" == 700:0:0 ]] || fail "lifecycle state metadata mismatch"
	for residue in config-v1.pending config-v1.removing .config-v1.new .config-v1.removing.new; do
		[[ ! -e "$MOUNTPOINT/var/lib/lmi-p2-d114/$residue" && ! -L "$MOUNTPOINT/var/lib/lmi-p2-d114/$residue" ]] ||
			fail "lifecycle residue exists: $residue"
	done
	verify_image_file /etc/apk/world 644 "$WORLD_SHA256"
	P2_PACKAGE_RECORD="$SCRATCH_DIR/device-xiaomi-lmi-terminal.installed-record"
	SIXROW_PACKAGE_RECORD="$SCRATCH_DIR/lmi-weston-sixrow-clients.installed-record"
	verify_installed_records "$MOUNTPOINT/usr/lib/apk/db/installed" "$P2_PACKAGE_RECORD" "$SIXROW_PACKAGE_RECORD"
	NON_TARGET_DB="$SCRATCH_DIR/installed.non-target"
	strip_target_records "$MOUNTPOINT/usr/lib/apk/db/installed" "$NON_TARGET_DB"
	cmp -s -- "$NON_TARGET_DB" "$INSTALLED_DB_BASELINE" || fail "non-target installed database records changed"
	verify_scripts_delta "$SCRIPTS_DB_BASELINE" "$MOUNTPOINT/usr/lib/apk/db/scripts.tar.gz" "$SCRATCH_DIR/scripts-delta"
	cmp -s -- "$TRIGGERS_DB_BASELINE" "$MOUNTPOINT/usr/lib/apk/db/triggers" || fail "APK triggers database changed"
	[[ "$(sha256_of "$MOUNTPOINT/usr/lib/apk/db/triggers")" == "$TRIGGERS_DB_SHA256" ]] || fail "APK triggers digest changed"
	KEY_INVENTORY_FINAL="$SCRATCH_DIR/keys.after"
	snapshot_tree "$MOUNTPOINT/etc/apk/keys" "$KEY_INVENTORY_FINAL" || fail "could not inventory final image keys"
	cmp -s -- "$KEY_INVENTORY_BASELINE" "$KEY_INVENTORY_FINAL" || fail "image APK key inventory changed"
	snapshot_tree "$MOUNTPOINT" "$FULL_TREE_AFTER" || fail "could not inventory candidate after injection"
	FULL_DELTA="$SCRATCH_DIR/filesystem.delta"
	FULL_DELTA_OP_PATHS="$SCRATCH_DIR/filesystem.delta.op-paths"
	compute_tree_delta "$FULL_TREE_BEFORE" "$FULL_TREE_AFTER" "$FULL_DELTA"
	verify_full_delta "$FULL_DELTA" "$FULL_DELTA_OP_PATHS" "$FULL_TREE_BEFORE" "$FULL_TREE_AFTER"
	FULL_DELTA_SHA256="$(sha256_of "$FULL_DELTA")"
	SCRIPTS_DB_FINAL_SHA256="$(sha256_of "$MOUNTPOINT/usr/lib/apk/db/scripts.tar.gz")"
	KEY_INVENTORY_SHA256="$(sha256_of "$KEY_INVENTORY_FINAL")"
	INSTALLED_DB_FINAL_SHA256="$(sha256_of "$MOUNTPOINT/usr/lib/apk/db/installed")"
	P2_PACKAGE_RECORD_SHA256="$(sha256_of "$P2_PACKAGE_RECORD")"
	SIXROW_PACKAGE_RECORD_SHA256="$(sha256_of "$SIXROW_PACKAGE_RECORD")"
	[[ -z "$(find "$MOUNTPOINT" -xdev \( -name '*6a5d38f2*' -o -name '*6a5fb853*' \) -print -quit)" ]] || fail "image contains signing-key residue"
	if find "$MOUNTPOINT" -xdev -type f -size 800c -exec sha256sum -- {} + |
		awk -v p2_key="$P2_KEY_SHA256" -v sixrow_key="$SIXROW_KEY_SHA256" '$1 == p2_key || $1 == sixrow_key { found=1 } END { exit !found }'; then
		fail "image contains signing-key content under another name"
	fi

	sync -f "$MOUNTPOINT"
	umount -- "$MOUNTPOINT"
	ROOT_MOUNTED=0
	DETACHED_LOOP_DEVICE=$LOOP_DEVICE
	detach_loop_checked || fail "checked loop detach failed"
	[[ -z "$LOOP_DEVICE" ]] || fail "loop state was not cleared immediately after detach"
	[[ -z "$(losetup -j "$SCRATCH_IMAGE")" && -z "$(findmnt -rn -S "$DETACHED_LOOP_DEVICE" || true)" ]] || fail "scratch mount residue"
	rmdir -- "$MOUNTPOINT"
	MOUNTPOINT=

	normalize_repair_epoch "$SCRATCH_IMAGE" || fail "output ext4 epoch normalization failed"
	"$E2FSCK" -fn "$SCRATCH_IMAGE" || fail "scratch final check failed"
	NORMALIZED_IMAGE="$SCRATCH_DIR/rootfs.allocated-only.ext4"
	NORMALIZATION_PROOF_IMAGE="$SCRATCH_DIR/rootfs.allocated-only.proof.ext4"
	normalize_allocated_ext4 "$SCRATCH_IMAGE" "$NORMALIZED_IMAGE" "$NORMALIZATION_PROOF_IMAGE" ||
		fail "allocated-only ext4 normalization or zero-free-block proof failed"
	"$E2FSCK" -fn "$SCRATCH_IMAGE" || fail "normalized scratch final check failed"
	MOUNTPOINT="$(mktemp -d "$SCRATCH_DIR/normalized-mount.XXXXXXXX")"
	attach_loop_checked || fail "checked normalized loop allocation/attach failed"
	mount -t ext4 -o ro,noload,nodev,nosuid,noexec "$LOOP_DEVICE" "$MOUNTPOINT"
	ROOT_MOUNTED=1
	NORMALIZATION_MOUNT_OPTIONS="$(findmnt -nro FSTYPE,OPTIONS -M "$MOUNTPOINT")"
	[[ "$NORMALIZATION_MOUNT_OPTIONS" == ext4* && "$NORMALIZATION_MOUNT_OPTIONS" == *ro* &&
		"$NORMALIZATION_MOUNT_OPTIONS" == *nosuid* && "$NORMALIZATION_MOUNT_OPTIONS" == *nodev* &&
		"$NORMALIZATION_MOUNT_OPTIONS" == *noexec* &&
		"$NORMALIZATION_MOUNT_OPTIONS" != *rw* ]] || fail "normalized rootfs read-only mount closure mismatch"
	FULL_TREE_NORMALIZED="$SCRATCH_DIR/filesystem.normalized"
	snapshot_tree "$MOUNTPOINT" "$FULL_TREE_NORMALIZED" || fail "could not inventory normalized candidate"
	cmp -s -- "$FULL_TREE_AFTER" "$FULL_TREE_NORMALIZED" ||
		fail "allocated-only normalization changed the complete filesystem tree"
	NORMALIZATION_TREE_SHA256="$(sha256_of "$FULL_TREE_NORMALIZED")"
	[[ "$NORMALIZATION_TREE_SHA256" == "$(sha256_of "$FULL_TREE_AFTER")" ]] ||
		fail "normalized filesystem tree proof digest mismatch"
	umount -- "$MOUNTPOINT"
	ROOT_MOUNTED=0
	DETACHED_NORMALIZED_LOOP_DEVICE=$LOOP_DEVICE
	detach_loop_checked || fail "checked normalized loop detach failed"
	[[ -z "$LOOP_DEVICE" && -z "$(losetup -j "$SCRATCH_IMAGE")" &&
		-z "$(findmnt -rn -S "$DETACHED_NORMALIZED_LOOP_DEVICE" || true)" ]] || fail "normalized mount residue"
	rmdir -- "$MOUNTPOINT"
	MOUNTPOINT=
	verify_repair_epoch "$SCRATCH_IMAGE"
	[[ "$(stat -Lc %s -- "$SCRATCH_IMAGE")" == "$IMAGE_SIZE" ]] || fail "output size drifted"
	[[ "$(blkid -p -s UUID -o value -- "$SCRATCH_IMAGE")" == "$IMAGE_UUID" ]] || fail "output UUID drifted"
	[[ "$(filesystem_geometry "$SCRATCH_IMAGE")" == "$GEOMETRY_BEFORE" ]] || fail "output geometry drifted"
	GEOMETRY_SHA256_LINE="$(printf '%s\n' "$GEOMETRY_BEFORE" | sha256sum)"
	GEOMETRY_SHA256="${GEOMETRY_SHA256_LINE%% *}"
	FINAL_SHA256="$(sha256_of "$SCRATCH_IMAGE")"
	for spec in "$RAW|$RAW_FD|$RAW_ID|$RAW_SHA256" "$SPARSE|$SPARSE_FD|$SPARSE_ID|$SPARSE_SHA256" \
		"$BASE|$BASE_FD|$BASE_ID|$BASE_SHA256" "$INPUT|$INPUT_FD|$INPUT_ID|$INPUT_SHA256" \
		"$REPAIR_VERIFY_LOG|$repair_verify_log_FD|$repair_verify_log_ID|$REPAIR_VERIFY_LOG_SHA256" \
		"$REPAIR_LOG|$repair_log_FD|$repair_log_ID|$REPAIR_LOG_SHA256" \
		"$REBUILD_LOCK|$candidate_rebuild_lock_FD|$candidate_rebuild_lock_ID|$REBUILD_LOCK_SHA256" \
		"$RUNTIME_LOCK|$injector_runtime_lock_FD|$injector_runtime_lock_ID|$RUNTIME_LOCK_SHA256" \
		"$P2_BUILD_ATTESTATION|$P2_build_attestation_FD|$P2_build_attestation_ID|$P2_BUILD_ATTESTATION_SHA256" \
		"$SIXROW_BUILD_ATTESTATION|$sixrow_build_attestation_FD|$sixrow_build_attestation_ID|$SIXROW_BUILD_ATTESTATION_SHA256"; do
		IFS='|' read -r path descriptor identity expected <<<"$spec"
		verify_open_path_unchanged "$path" "$descriptor" "$identity" || fail "lineage path changed: $path"
		[[ "$(sha256_of "/proc/self/fd/$descriptor")" == "$expected" ]] || fail "lineage content changed: $path"
	done
	verify_open_path_unchanged "$BASE" "$BASE_FD" "$BASE_ID" || fail "base path changed"
	verify_open_path_unchanged "$INPUT" "$INPUT_FD" "$INPUT_ID" || fail "candidate input path changed"
	[[ "$(sha256_of "/proc/self/fd/$BASE_FD")" == "$BASE_SHA256" ]] || fail "base content changed"
	[[ "$(sha256_of "/proc/self/fd/$INPUT_FD")" == "$INPUT_SHA256" ]] || fail "candidate input content changed"
	for spec in "$P2_APK|$P2_APK_FD|$P2_APK_ID|$P2_APK_SHA256" \
		"$SIXROW_APK|$sixrow_APK_FD|$sixrow_APK_ID|$SIXROW_APK_SHA256" \
		"$P2_KEY|$P2_key_FD|$P2_key_ID|$P2_KEY_SHA256" \
		"$SIXROW_KEY|$sixrow_key_FD|$sixrow_key_ID|$SIXROW_KEY_SHA256" \
		"$APK_STATIC|$apk_static_FD|$apk_static_ID|$APK_STATIC_SHA256" \
		"$PROOT|$PRoot_FD|$PRoot_ID|$PROOT_SHA256" "$PROOT_TALLOC|$libtalloc_FD|$libtalloc_ID|$PROOT_TALLOC_SHA256" \
		"$QEMU|$qemu_aarch64_FD|$qemu_aarch64_ID|$QEMU_SHA256"; do
		IFS='|' read -r path descriptor identity expected <<<"$spec"
		verify_open_path_unchanged "$path" "$descriptor" "$identity" || fail "input tool path changed: $path"
		[[ "$(sha256_of "/proc/self/fd/$descriptor")" == "$expected" ]] || fail "input tool content changed: $path"
	done
	for spec in "$HOST_LIBC|$host_libc_FD|$host_libc_ID|$HOST_LIBC_SHA256" \
		"$HOST_LOADER|$host_loader_FD|$host_loader_ID|$HOST_LOADER_SHA256" \
		"$BWRAP_LIBSELINUX|$bwrap_libselinux_FD|$bwrap_libselinux_ID|$BWRAP_LIBSELINUX_SHA256" \
		"$BWRAP_LIBCAP|$bwrap_libcap_FD|$bwrap_libcap_ID|$BWRAP_LIBCAP_SHA256" \
		"$BWRAP_LIBPCRE|$bwrap_libpcre_FD|$bwrap_libpcre_ID|$BWRAP_LIBPCRE_SHA256" \
		"$LSATTR_LIBE2P|$lsattr_libe2p_FD|$lsattr_libe2p_ID|$LSATTR_LIBE2P_SHA256" \
		"$LSATTR_LIBCOM_ERR|$lsattr_libcom_err_FD|$lsattr_libcom_err_ID|$LSATTR_LIBCOM_ERR_SHA256"; do
		IFS='|' read -r path descriptor identity expected <<<"$spec"
		verify_open_path_unchanged "$path" "$descriptor" "$identity" || fail "system runtime path changed: $path"
		[[ "$(sha256_of "/proc/self/fd/$descriptor")" == "$expected" ]] || fail "system runtime content changed: $path"
	done
	for spec in "$BWRAP|$bubblewrap_FD|$bubblewrap_ID|$BWRAP_SHA256" \
		"$SIMG2IMG|$simg2img_FD|$simg2img_ID|$SIMG2IMG_SHA256" \
		"$E2FSCK|$e2fsck_FD|$e2fsck_ID|$E2FSCK_SHA256" \
		"$E2IMAGE|$e2image_FD|$e2image_ID|$E2IMAGE_SHA256" \
		"$DEBUGFS|$debugfs_FD|$debugfs_ID|$DEBUGFS_SHA256" \
		"$DUMPE2FS|$dumpe2fs_FD|$dumpe2fs_ID|$DUMPE2FS_SHA256" \
		"$GETFATTR|$getfattr_FD|$getfattr_ID|$GETFATTR_SHA256" \
		"$LSATTR|$lsattr_FD|$lsattr_ID|$LSATTR_SHA256" \
		"$BASH|$bash_FD|$bash_ID|$BASH_SHA256" "$DASH|$dash_FD|$dash_ID|$DASH_SHA256"; do
		IFS='|' read -r path descriptor identity expected <<<"$spec"
		verify_open_path_unchanged "$path" "$descriptor" "$identity" || fail "critical host tool changed: $path"
		[[ "$(sha256_of "/proc/self/fd/$descriptor")" == "$expected" ]] || fail "critical host tool content changed: $path"
	done
	[[ "$(sha256_of "$HOST_LIBC")" == "$HOST_LIBC_SHA256" && "$(sha256_of "$HOST_LOADER")" == "$HOST_LOADER_SHA256" ]] ||
		fail "host runtime closure changed"

	KERNEL_RELEASE="$(uname -r)"
	[[ "$KERNEL_RELEASE" =~ ^[A-Za-z0-9._+-]+$ ]] || fail "unsafe kernel release for attestation"
	PROC_VERSION_SHA256="$(sha256_of /proc/version)"
	ATTESTATION_TMP="$SCRATCH_DIR/attestation.json"
	printf '%s\n' "{\"claims\":{\"hardware_test_only\":true,\"production\":false,\"release_eligible\":false},\"commands\":{\"apk\":[\"bubblewrap:unshare-user,pid,uts,ipc;outer-private-net\",\"source-bindings:checked-root-owned-run-bridge;outer-private-mountns\",\"cap-drop=ALL;child-verified-no-new-privs-and-zero-capability-sets\",\"env:clear;HOME=/root;LANG=C;LC_ALL=C;PATH=/usr/sbin:/usr/bin:/sbin:/bin;PWD=/;TZ=UTC\",\"--root=/image\",\"--arch=aarch64\",\"--keys-dir=/keys\",\"--no-logfile\",\"--no-network\",\"--no-cache\",\"--no-scripts\",\"--repositories-file=/dev/null\",\"--force-non-repository\",\"add\",\"/tools/sixrow.apk\",\"/tools/p2.apk\"],\"lifecycle\":[\"bubblewrap:unshare-user,pid,uts,ipc;outer-private-net\",\"source-bindings:checked-root-owned-run-bridge;outer-private-mountns\",\"cap-drop=ALL;child-verified-no-new-privs-and-zero-capability-sets\",\"env:clear;HOME=/root;LANG=C;LC_ALL=C;PATH=/usr/sbin:/usr/bin:/sbin:/bin;PROOT_NO_SECCOMP=1;PWD=/;TZ=UTC\",\"loader:--library-path=/runtime\",\"proot:-r=/image,-q=/tools/qemu-aarch64,-w=/\",\"/usr/libexec/lmi-p2-d114/config-lifecycle\",\"install\"]},\"input\":{\"apks\":{\"p2\":{\"build_attestation_sha256\":\"$P2_BUILD_ATTESTATION_SHA256\",\"sandbox_path\":\"/tools/p2.apk\",\"sha256\":\"$P2_APK_SHA256\",\"source_path\":\"private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-build-20260723/run2-device-xiaomi-lmi-terminal-0.1.0-r2.apk\"},\"sixrow\":{\"build_attestation_sha256\":\"$SIXROW_BUILD_ATTESTATION_SHA256\",\"sandbox_path\":\"/tools/sixrow.apk\",\"sha256\":\"$SIXROW_APK_SHA256\",\"source_path\":\"private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-build-20260723/lmi-weston-sixrow-clients-14.0.2-r2.resigned.apk\"}},\"base_sha256\":\"$BASE_SHA256\",\"candidate_rebuild_lock_schema\":\"$REBUILD_LOCK_SCHEMA\",\"candidate_rebuild_lock_sha256\":\"$REBUILD_LOCK_SHA256\",\"candidate_sha256\":\"$INPUT_SHA256\",\"candidate_size\":$IMAGE_SIZE,\"candidate_uuid\":\"$IMAGE_UUID\",\"keys\":{\"p2_sha256\":\"$P2_KEY_SHA256\",\"sixrow_sha256\":\"$SIXROW_KEY_SHA256\"},\"raw_sha256\":\"$RAW_SHA256\",\"repair_epoch\":$REPAIR_EPOCH,\"repair_log_sha256\":\"$REPAIR_LOG_SHA256\",\"sparse_sha256\":\"$SPARSE_SHA256\",\"verify_log_sha256\":\"$REPAIR_VERIFY_LOG_SHA256\"},\"output\":{\"filesystem_delta_sha256\":\"$FULL_DELTA_SHA256\",\"geometry_sha256\":\"$GEOMETRY_SHA256\",\"installed_db_sha256\":\"$INSTALLED_DB_FINAL_SHA256\",\"key_inventory_sha256\":\"$KEY_INVENTORY_SHA256\",\"mode\":\"0640\",\"owner\":\"0:$CALLER_GID\",\"p2_package_record_sha256\":\"$P2_PACKAGE_RECORD_SHA256\",\"packages\":[\"device-xiaomi-lmi-terminal=0.1.0-r2\",\"lmi-weston-sixrow-clients=14.0.2-r2\"],\"path\":\"private/lmi-p1/recovery/d110-d114/p2-d114-r2-most-complete-injected-20260723/lmi-d114-rootfs-p2-r2-most-complete-injected-20260723.bundle/rootfs.ext4\",\"scripts_db_sha256\":\"$SCRIPTS_DB_FINAL_SHA256\",\"sha256\":\"$FINAL_SHA256\",\"sixrow_package_record_sha256\":\"$SIXROW_PACKAGE_RECORD_SHA256\",\"size\":$IMAGE_SIZE,\"triggers_sha256\":\"$TRIGGERS_DB_SHA256\",\"uuid\":\"$IMAGE_UUID\",\"world_sha256\":\"$WORLD_SHA256\"},\"runtime\":{\"injector_runtime_lock_schema\":\"$RUNTIME_LOCK_SCHEMA\",\"injector_runtime_lock_sha256\":\"$RUNTIME_LOCK_SHA256\",\"kernel_release\":\"$KERNEL_RELEASE\",\"mount_loop\":{\"backing_identity\":\"$ATTESTED_LOOP_BACKING_ID\",\"block_identity\":\"$ATTESTED_LOOP_DEVICE_ID\",\"mount_options\":\"$MOUNT_OPTIONS\"},\"namespaces\":{\"ipc\":\"$(readlink /proc/self/ns/ipc)\",\"mnt\":\"$(readlink /proc/self/ns/mnt)\",\"net\":\"$(readlink /proc/self/ns/net)\",\"pid\":\"$(readlink /proc/self/ns/pid)\",\"uts\":\"$(readlink /proc/self/ns/uts)\"},\"proc_version_sha256\":\"$PROC_VERSION_SHA256\",\"sandbox_entry_sha256\":\"$SANDBOX_ENTRY_SHA256\",\"sealed_script_sha256\":\"$SEALED_SCRIPT_SHA256\"},\"sanitization\":{\"apk_cache\":\"exact-four-index-members-removed\",\"apk_log\":\"empty\",\"authorized_keys\":\"absent-in-base\",\"machine_id\":\"removed\",\"resolv_conf\":\"empty\",\"shadow_backup\":\"exact-copy-of-locked-active-shadow\",\"ssh_password_authentication\":\"disabled-by-locked-drop-in\"},\"schema\":\"lmi-p2-d114-rootfs-injection-attestation/v3\",\"tools\":{\"apk_static_sha256\":\"$APK_STATIC_SHA256\",\"bash_sha256\":\"$BASH_SHA256\",\"bubblewrap_sha256\":\"$BWRAP_SHA256\",\"dumpe2fs_sha256\":\"$DUMPE2FS_SHA256\",\"e2fsck_sha256\":\"$E2FSCK_SHA256\",\"getfattr_sha256\":\"$GETFATTR_SHA256\",\"host_libc_sha256\":\"$HOST_LIBC_SHA256\",\"host_loader_sha256\":\"$HOST_LOADER_SHA256\",\"lsattr_libcom_err_sha256\":\"$LSATTR_LIBCOM_ERR_SHA256\",\"lsattr_libe2p_sha256\":\"$LSATTR_LIBE2P_SHA256\",\"lsattr_sha256\":\"$LSATTR_SHA256\",\"proot_libtalloc_sha256\":\"$PROOT_TALLOC_SHA256\",\"proot_sha256\":\"$PROOT_SHA256\",\"qemu_aarch64_sha256\":\"$QEMU_SHA256\",\"simg2img_sha256\":\"$SIMG2IMG_SHA256\"}}" >"$ATTESTATION_TMP"
	ATTESTATION_REWRITE="$SCRATCH_DIR/attestation.normalized.json"
	NORMALIZATION_FRAGMENT="\"normalization\":{\"all_free_blocks_zero\":true,\"allocated_only_command\":[\"e2image\",\"-r\",\"-a\",\"-p\"],\"inactive_journal\":{\"block_count\":$JOURNAL_INACTIVE_BLOCK_COUNT,\"first_block\":$JOURNAL_INACTIVE_FIRST_BLOCK,\"sha256\":\"$JOURNAL_INACTIVE_ZERO_SHA256\"},\"journal_extent\":{\"block_count\":$JOURNAL_BLOCK_COUNT,\"first_block\":$JOURNAL_FIRST_BLOCK},\"pre_normalization_sha256\":\"$PRE_NORMALIZATION_SHA256\",\"proof\":\"second-e2image-byte-identical\",\"proof_sha256\":\"$NORMALIZATION_PROOF_SHA256\",\"reviewed_freed_blocks\":[],\"sparse_st_blocks\":$NORMALIZED_ST_BLOCKS,\"tree_identity_sha256\":\"$NORMALIZATION_TREE_SHA256\"},"
	awk -v normalization="$NORMALIZATION_FRAGMENT" -v debugfs_sha="$DEBUGFS_SHA256" -v e2image_sha="$E2IMAGE_SHA256" '
		{
			if (gsub(/"output":/, normalization "\"output\":" ) != 1) exit 91
			if (gsub(/"dumpe2fs_sha256":/, "\"debugfs_sha256\":\"" debugfs_sha "\",\"dumpe2fs_sha256\":" ) != 1) exit 93
			if (gsub(/"getfattr_sha256":/, "\"e2image_sha256\":\"" e2image_sha "\",\"getfattr_sha256\":" ) != 1) exit 92
			print
		}' "$ATTESTATION_TMP" >"$ATTESTATION_REWRITE" || fail "could not bind ext4 normalization attestation"
	mv -T -- "$ATTESTATION_REWRITE" "$ATTESTATION_TMP"
	chmod 0600 -- "$ATTESTATION_TMP"
	ATTESTATION_SHA256="$(sha256_of "$ATTESTATION_TMP")"
	sync -f "$SCRATCH_IMAGE"
	sync -f "$ATTESTATION_TMP"
	verify_open_directory_unchanged "$INPUT_BUILD_DIR" "$INPUT_BUILD_DIR_FD" "$INPUT_BUILD_DIR_ID" ||
		fail "read-only input directory changed"
	verify_open_directory_unchanged "$BUILD_DIR" "$BUILD_DIR_FD" "$BUILD_DIR_ID" || fail "build directory changed"
	PUBLISH_TMP="$SCRATCH_DIR/publish.bundle"
	mkdir -m 0700 -- "$PUBLISH_TMP"
	mv -T -- "$SCRATCH_IMAGE" "$PUBLISH_TMP/rootfs.ext4"
	mv -T -- "$ATTESTATION_TMP" "$PUBLISH_TMP/attestation.json"
	# The root owner is retained.  Only the caller's exact primary group gets a
	# read-only handoff; the injector never chowns either artifact to a user.
	chown 0:"$CALLER_GID" -- "$PUBLISH_TMP" "$PUBLISH_TMP/rootfs.ext4" "$PUBLISH_TMP/attestation.json"
	chmod 0750 -- "$PUBLISH_TMP"
	chmod 0640 -- "$PUBLISH_TMP/rootfs.ext4" "$PUBLISH_TMP/attestation.json"
	PUBLISHED_BUNDLE_FD_PATH="/proc/self/fd/$BUILD_DIR_FD/${OUTPUT_BUNDLE##*/}"
	publish_bundle "$PUBLISH_TMP" "$PUBLISHED_BUNDLE_FD_PATH" "$FINAL_SHA256" "$ATTESTATION_SHA256" "0:$CALLER_GID" || fail "atomic attested-bundle publication failed"
	sync -f "$BUILD_DIR"
	verify_open_directory_unchanged "$BUILD_DIR" "$BUILD_DIR_FD" "$BUILD_DIR_ID" || fail "build directory changed during publication"
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$OUTPUT_BUNDLE")" == "$PUBLISHED_BUNDLE_ID" ]] || fail "published bundle inode/metadata mismatch"
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$OUTPUT")" == "$PUBLISHED_IMAGE_ID" && "$(sha256_of "$OUTPUT")" == "$FINAL_SHA256" ]] || fail "published image inode/metadata/hash verification failed"
	[[ "$(stat -Lc %d:%i:%a:%u:%g:%h -- "$ATTESTATION")" == "$PUBLISHED_ATTESTATION_ID" && "$(sha256_of "$ATTESTATION")" == "$ATTESTATION_SHA256" ]] || fail "published attestation inode/metadata/hash verification failed"
	SCRATCH_IMAGE=
	ATTESTATION_TMP=
	PUBLISH_TMP=
	cleanup_partials || fail "scratch cleanup failed"
	SCRATCH_DIR=
	SCRATCH_ID=
	COMMITTED=1
	printf 'candidate_sha256=%s  %s\nattestation_sha256=%s  %s\n' \
		"$FINAL_SHA256" "$OUTPUT" "$ATTESTATION_SHA256" "$ATTESTATION"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	trap 'exit 129' HUP
	main "$@"
fi
