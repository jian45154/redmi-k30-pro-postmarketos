#!/usr/bin/env bash
# Non-root, fail-closed launcher for the D114 offline rootfs injector.
set -Eeuo pipefail
IFS=$'\n\t'
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LANG=C LC_ALL=C TZ=UTC
unset BASH_ENV CDPATH ENV LD_AUDIT LD_LIBRARY_PATH LD_PRELOAD

readonly LAUNCHER_SUFFIX=/scripts/lmi_p2_d114/launch_inject_rootfs_candidate.sh
readonly LAUNCHER_SOURCE="${BASH_SOURCE[0]}"
[[ "$LAUNCHER_SOURCE" == /* && -f "$LAUNCHER_SOURCE" && ! -L "$LAUNCHER_SOURCE" ]] || {
	printf 'D114 injector launcher refused: launcher source path is unsafe\n' >&2
	exit 1
}
LAUNCHER_CANONICAL="$(/usr/bin/realpath -e -- "$LAUNCHER_SOURCE")" || exit 1
readonly LAUNCHER_CANONICAL
[[ "$LAUNCHER_CANONICAL" == "$LAUNCHER_SOURCE" && "$LAUNCHER_CANONICAL" == *"$LAUNCHER_SUFFIX" ]] || {
	printf 'D114 injector launcher refused: could not derive canonical repository root\n' >&2
	exit 1
}
readonly REPO="${LAUNCHER_CANONICAL%"$LAUNCHER_SUFFIX"}"
[[ -n "$REPO" && "$REPO" == /* && -d "$REPO" && ! -L "$REPO" ]] || exit 1
readonly BUILD_DIR="$REPO/private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722"
readonly INJECTOR="$REPO/scripts/lmi_p2_d114/inject_rootfs_candidate.sh"
# Updated only after the injector passes its focused tests.
readonly INJECTOR_SHA256=f3f029c533a00747fd8d895d844f217649649edafc3a4a07c566dc962574af15
readonly ROOT_SEAL_DIR=/run/lmi-p2-d114-inject
readonly OUTPUT_BUNDLE="$BUILD_DIR/lmi-d114-rootfs-p2-r1-sixrow-injected-20260722.bundle"
readonly OUTPUT="$OUTPUT_BUNDLE/rootfs.ext4"
readonly ATTESTATION="$OUTPUT_BUNDLE/attestation.json"

STAGE_DIR=
SEALED_ENTRY=
RESULT_LOG=

fail() {
	printf 'D114 injector launcher refused: %s\n' "$*" >&2
	exit 1
}

sha256_of() {
	local line
	line="$(/usr/bin/sha256sum -- "$1")" || return 1
	printf '%s\n' "${line%% *}"
}

close_inherited_fds_and_reject_stdio_sockets() {
	local fd_path fd target kind
	for fd in 0 1 2; do
		kind="$(/usr/bin/stat -Lc %F -- "/proc/self/fd/$fd")" || return 1
		[[ "$kind" != socket ]] || return 1
	done
	for fd_path in /proc/self/fd/*; do
		fd=${fd_path##*/}
		[[ "$fd" =~ ^[0-9]+$ && "$fd" -gt 2 ]] || continue
		target="$(/usr/bin/readlink -- "$fd_path")" || continue
		# Bash keeps the executing script on an internal descriptor.  It is
		# close-on-exec and is the sole temporary exception before exec(sudo).
		if [[ "$target" == "$0" || "$target" == "$(/usr/bin/realpath -e -- "$0")" ]]; then
			continue
		fi
		eval "exec ${fd}>&-"
	done
}

cleanup() {
	local status=$?
	trap - EXIT INT TERM HUP
	set +e
	if [[ -n "$STAGE_DIR" && -d "$STAGE_DIR" && ! -L "$STAGE_DIR" ]]; then
		/usr/bin/find "$STAGE_DIR" -xdev -depth -mindepth 1 -delete || status=1
		/usr/bin/rmdir -- "$STAGE_DIR" || status=1
	fi
	exit "$status"
}

verify_published_bundle() {
	local caller_gid=$1 expected_image_sha=$2 expected_attestation_sha=$3
	local bundle_before image_before attestation_before bundle_after image_after attestation_after
	local image_inode attestation_inode
	[[ -d "$OUTPUT_BUNDLE" && ! -L "$OUTPUT_BUNDLE" && "$(/usr/bin/realpath -e -- "$OUTPUT_BUNDLE")" == "$OUTPUT_BUNDLE" ]] || return 1
	[[ "$(/usr/bin/find "$OUTPUT_BUNDLE" -mindepth 1 -maxdepth 1 -printf '%f\n' | /usr/bin/sort)" == $'attestation.json\nrootfs.ext4' ]] || return 1
	bundle_before="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$OUTPUT_BUNDLE")" || return 1
	image_before="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$OUTPUT")" || return 1
	attestation_before="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$ATTESTATION")" || return 1
	image_inode="$(/usr/bin/stat -Lc %d:%i -- "$OUTPUT")" || return 1
	attestation_inode="$(/usr/bin/stat -Lc %d:%i -- "$ATTESTATION")" || return 1
	[[ "$bundle_before" == *":750:0:$caller_gid:2" ]] || return 1
	[[ "$image_before" == *":640:0:$caller_gid:1" ]] || return 1
	[[ "$attestation_before" == *":640:0:$caller_gid:1" ]] || return 1
	[[ "$image_inode" != "$attestation_inode" ]] || return 1
	[[ "$(sha256_of "$OUTPUT")" == "$expected_image_sha" ]] || return 1
	[[ "$(sha256_of "$ATTESTATION")" == "$expected_attestation_sha" ]] || return 1
	bundle_after="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$OUTPUT_BUNDLE")" || return 1
	image_after="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$OUTPUT")" || return 1
	attestation_after="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$ATTESTATION")" || return 1
	[[ "$bundle_after" == "$bundle_before" && "$image_after" == "$image_before" &&
		"$attestation_after" == "$attestation_before" ]] || return 1
}

main() {
	local launcher uid gid repo_owner source_digest staged status namespace value
	local candidate_line attestation_line candidate_sha attestation_sha
	[[ "$#" == 0 ]] || fail "launcher accepts no arguments"
	[[ "$(/usr/bin/id -ru)" != 0 && "$(/usr/bin/id -ru)" == "$(/usr/bin/id -u)" ]] ||
		fail "launcher must start as one unprivileged real/effective UID"
	[[ "$(/usr/bin/id -rg)" == "$(/usr/bin/id -g)" ]] || fail "launcher real/effective GID mismatch"
	uid="$(/usr/bin/id -u)"
	gid="$(/usr/bin/id -g)"
	repo_owner="$(/usr/bin/stat -Lc %u:%g -- "$REPO")" || fail "cannot read repository owner"
	[[ "$repo_owner" == "$uid:$gid" ]] || fail "caller uid/gid must exactly match repository owner"
	launcher="$(/usr/bin/realpath -e -- "$0")" || fail "cannot canonicalize launcher"
	[[ ! -L "$0" && "$launcher" == "$LAUNCHER_CANONICAL" ]] ||
		fail "launcher is not running from its canonical project path"
	[[ "$(/usr/bin/stat -Lc %a:%u:%g:%h -- "$launcher")" == "755:$uid:$gid:1" ]] ||
		fail "launcher source metadata mismatch"
	[[ -f "$INJECTOR" && ! -L "$INJECTOR" && "$(/usr/bin/realpath -e -- "$INJECTOR")" == "$INJECTOR" ]] ||
		fail "injector source path is unsafe"
	[[ "$(/usr/bin/stat -Lc %a:%u:%g:%h -- "$INJECTOR")" == "755:$uid:$gid:1" ]] ||
		fail "injector source metadata mismatch"
	[[ "$INJECTOR_SHA256" =~ ^[0-9a-f]{64}$ ]] || fail "launcher injector pin is not finalized"
	source_digest="$(sha256_of "$INJECTOR")"
	[[ "$source_digest" == "$INJECTOR_SHA256" ]] || fail "injector source digest differs from launcher pin"
	[[ ! -e "$OUTPUT_BUNDLE" && ! -L "$OUTPUT_BUNDLE" ]] || fail "output bundle already exists"

	STAGE_DIR="$(/usr/bin/mktemp -d "$BUILD_DIR/.inject-launch.XXXXXXXX")"
	[[ "$(/usr/bin/stat -Lc %a:%u:%g -- "$STAGE_DIR")" == "700:$uid:$gid" ]] || fail "launcher staging metadata mismatch"
	staged="$STAGE_DIR/inject_rootfs_candidate.sh"
	/usr/bin/cp --reflink=never -- "$INJECTOR" "$staged"
	/usr/bin/chmod 0600 -- "$staged"
	[[ "$(/usr/bin/stat -Lc %a:%u:%g:%h -- "$staged")" == "600:$uid:$gid:1" ]] || fail "staged injector metadata mismatch"
	[[ "$(sha256_of "$staged")" == "$INJECTOR_SHA256" ]] || fail "staged injector digest mismatch"

	close_inherited_fds_and_reject_stdio_sockets || fail "could not close inherited descriptors or stdio is a socket"
	for namespace in mnt net pid ipc uts; do
		value="$(/usr/bin/readlink -- "/proc/self/ns/$namespace")" || fail "cannot read parent $namespace namespace"
		[[ "$value" =~ ^${namespace}:\[[0-9]+\]$ ]] || fail "invalid parent $namespace namespace identity"
		printf -v "PARENT_${namespace^^}NS" '%s' "$value"
	done

	SEALED_ENTRY="$ROOT_SEAL_DIR/inject_rootfs_candidate.$uid.$$.sh"
	RESULT_LOG="$STAGE_DIR/injector.stdout"
	: >"$RESULT_LOG"
	/usr/bin/chmod 0600 -- "$RESULT_LOG"
	status=0
	/usr/bin/sudo -n -- /usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C LC_ALL=C TZ=UTC \
		/bin/bash --noprofile --norc -c '
			set -Eeuo pipefail
			umask 077
			staged=$1 sealed=$2 expected_sha=$3 caller_uid=$4 caller_gid=$5
				parent_mnt=$6 parent_net=$7 parent_pid=$8 parent_ipc=$9 parent_uts=${10} canonical_source=${11}
			seal_dir=${sealed%/*}
			sealed_created=0
			sealed_identity=
			cleanup_root_seal() {
				local child_status=$? cleanup_failed=0 current_sha
				trap - EXIT INT TERM HUP
				set +e
				if [[ "$sealed_created" == 1 ]]; then
					if [[ -f "$sealed" && ! -L "$sealed" && ( -z "$sealed_identity" || "$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$sealed")" == "$sealed_identity" ) ]]; then
						current_sha="$(/usr/bin/sha256sum -- "$sealed")" || cleanup_failed=1
						current_sha=${current_sha%% *}
						if [[ -z "$sealed_identity" || "$current_sha" == "$expected_sha" ]]; then
							/usr/bin/rm -f -- "$sealed" || cleanup_failed=1
						else
							cleanup_failed=1
						fi
					elif [[ -e "$sealed" || -L "$sealed" ]]; then
						cleanup_failed=1
					fi
				fi
				if [[ -d "$seal_dir" && ! -L "$seal_dir" && "$(/usr/bin/stat -Lc %a:%u:%g -- "$seal_dir")" == 700:0:0 ]]; then
					/usr/bin/rmdir -- "$seal_dir" || cleanup_failed=1
				elif [[ -e "$seal_dir" || -L "$seal_dir" ]]; then
					cleanup_failed=1
				fi
				if (( cleanup_failed != 0 )); then
					printf "D114 injector launcher: privileged sealed-entry cleanup failed: %s\n" "$sealed" >&2
					child_status=1
				fi
				exit "$child_status"
			}
			trap cleanup_root_seal EXIT
			trap "exit 130" INT
			trap "exit 143" TERM
			trap "exit 129" HUP
			[[ -f "$staged" && ! -L "$staged" && "$(/usr/bin/stat -Lc %a:%u:%g:%h -- "$staged")" == "600:$caller_uid:$caller_gid:1" ]] || {
				printf "D114 injector launcher: staged injector metadata changed\n" >&2; exit 1;
			}
			exec {staged_fd}<"$staged"
			[[ "$(/usr/bin/stat -Lc %a:%u:%g:%h -- "/proc/self/fd/$staged_fd")" == "600:$caller_uid:$caller_gid:1" ]] || exit 1
			staged_sha="$(/usr/bin/sha256sum -- "/proc/self/fd/$staged_fd")"; staged_sha=${staged_sha%% *}
			[[ "$staged_sha" == "$expected_sha" ]] || { printf "D114 injector launcher: staged injector digest changed\n" >&2; exit 1; }
			if [[ -e "$seal_dir" || -L "$seal_dir" ]]; then
				[[ -d "$seal_dir" && ! -L "$seal_dir" && "$(/usr/bin/realpath -e -- "$seal_dir")" == "$seal_dir" &&
					"$(/usr/bin/stat -Lc %a:%u:%g -- "$seal_dir")" == 700:0:0 ]] || {
					printf "D114 injector launcher: existing seal directory is unsafe\n" >&2; exit 1;
				}
			fi
			/usr/bin/install -d -o root -g root -m 0700 -- "$seal_dir"
			[[ "$(/usr/bin/stat -Lc %a:%u:%g -- "$seal_dir")" == 700:0:0 ]] || exit 1
			[[ -z "$(/usr/bin/find "$seal_dir" -mindepth 1 -maxdepth 1 -print -quit)" ]] || {
				printf "D114 injector launcher: seal directory is not empty\n" >&2; exit 1;
			}
			# Mark this unique, previously absent destination as ours before install
			# so the same sudo process also removes an interrupted partial copy.
			sealed_created=1
			/usr/bin/install -o root -g root -m 0700 -- "/proc/self/fd/$staged_fd" "$sealed"
			exec {staged_fd}<&-
			sealed_identity="$(/usr/bin/stat -Lc %d:%i:%a:%u:%g:%h -- "$sealed")"
			[[ "$sealed_identity" == *:700:0:0:1 ]] || { printf "D114 injector launcher: root-owned sealed entry metadata mismatch\n" >&2; exit 1; }
			root_digest="$(/usr/bin/sha256sum -- "$sealed")"; root_digest=${root_digest%% *}
			[[ "$root_digest" == "$expected_sha" ]] || { printf "D114 injector launcher: root-owned sealed entry digest mismatch\n" >&2; exit 1; }
			child_status=0
			/usr/bin/unshare --mount --net --pid --fork --ipc --uts --mount-proc=/proc -- \
				/bin/bash --noprofile --norc "$sealed" --inside-private-namespace \
				--sealed-script-sha256 "$expected_sha" --caller-uid "$caller_uid" --caller-gid "$caller_gid" \
					--parent-mntns "$parent_mnt" --parent-netns "$parent_net" --parent-pidns "$parent_pid" \
					--parent-ipcns "$parent_ipc" --parent-utsns "$parent_uts" \
					--canonical-source "$canonical_source" || child_status=$?
			if (( child_status == 0 )) && [[ -e "$sealed" || -L "$sealed" ]]; then
				printf "D114 injector launcher: injector returned without removing its sealed entry\n" >&2
				child_status=1
			fi
			exit "$child_status"
			' lmi-p2-d114-root-wrapper "$staged" "$SEALED_ENTRY" "$INJECTOR_SHA256" "$uid" "$gid" \
			"$PARENT_MNTNS" "$PARENT_NETNS" "$PARENT_PIDNS" "$PARENT_IPCNS" "$PARENT_UTSNS" \
			"$INJECTOR" \
		>"$RESULT_LOG" || status=$?
	if (( status != 0 )); then
		/usr/bin/cat -- "$RESULT_LOG"
		return "$status"
	fi
	candidate_line="$(/usr/bin/grep -E '^candidate_sha256=[0-9a-f]{64}  /' "$RESULT_LOG")" || fail "missing injector image result"
	attestation_line="$(/usr/bin/grep -E '^attestation_sha256=[0-9a-f]{64}  /' "$RESULT_LOG")" || fail "missing injector attestation result"
	[[ "$candidate_line" != *$'\n'* && "$candidate_line" =~ ^candidate_sha256=([0-9a-f]{64})\ \ (.+)$ && "${BASH_REMATCH[2]}" == "$OUTPUT" ]] || fail "ambiguous injector image result"
	candidate_sha=${BASH_REMATCH[1]}
	[[ "$attestation_line" != *$'\n'* && "$attestation_line" =~ ^attestation_sha256=([0-9a-f]{64})\ \ (.+)$ && "${BASH_REMATCH[2]}" == "$ATTESTATION" ]] || fail "ambiguous injector attestation result"
	attestation_sha=${BASH_REMATCH[1]}
	verify_published_bundle "$gid" "$candidate_sha" "$attestation_sha" || fail "published bundle failed caller-side inode/metadata/hash verification"
	/usr/bin/cat -- "$RESULT_LOG"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
main "$@"
