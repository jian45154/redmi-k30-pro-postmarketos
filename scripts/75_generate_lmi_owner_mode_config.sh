#!/usr/bin/env bash
set -euo pipefail

usage() {
	cat <<'EOF'
Usage:
  scripts/75_generate_lmi_owner_mode_config.sh --output <new-or-empty-dir> \
      [--owner-pubkey <ed25519-public-key-file>]

Host-only generator for the explicit lmi OWNER-MODE opt-in documented in
notes/ssh-owner-mode-addendum-2026-07-29.md. It writes staging artifacts:

  etc/ssh/sshd_config.d/40-lmi-owner-mode.conf   include-first sshd drop-in
  etc/ssh/sshd_config.owner-mode                 full merged sshd variant
  etc/sudoers.d/91-lmi-owner-mode                labeled sudoers drop-in
  root-authorized-keys/authorized_keys           owner key or placeholder
  OWNER-MODE-APPLY.md                            manual application steps

The generated profile enables key-only root SSH login (PermitRootLogin
prohibit-password) and blanket passwordless sudo for the lmi user. It never
enables password authentication, keyboard-interactive authentication, or
GatewayPorts; those stay disabled in every emitted file.

This helper never talks to the phone and applies nothing anywhere: it only
writes new files into the staging directory. It refuses to run as root and
refuses output paths inside system configuration roots, so it cannot be
misused to switch the running host — or a mounted device rootfs under a
system root — into owner-mode. Applying the staged files is a separate,
manual owner action on the device.
EOF
}

die() {
	printf 'error: %s\n' "$*" >&2
	exit 2
}

output_dir=
owner_pubkey=
while [ "$#" -gt 0 ]; do
	case $1 in
		-h|--help)
			usage
			exit 0
			;;
		--output)
			[ "$#" -ge 2 ] || die "--output requires a directory argument"
			output_dir=$2
			shift 2
			;;
		--owner-pubkey)
			[ "$#" -ge 2 ] || die "--owner-pubkey requires a file argument"
			owner_pubkey=$2
			shift 2
			;;
		*)
			usage >&2
			die "unknown argument: $1"
			;;
	esac
done

[ -n "$output_dir" ] || { usage >&2; die "--output is required"; }

if [ "$(id -u)" -eq 0 ]; then
	die "refusing to run as root; this generator only stages files"
fi

resolved_output=$(realpath -m -- "$output_dir")
case $resolved_output in
	/|/bin|/bin/*|/boot|/boot/*|/dev|/dev/*|/etc|/etc/*|/lib|/lib/*| \
	/lib64|/lib64/*|/opt|/opt/*|/proc|/proc/*|/root|/root/*|/run|/run/*| \
	/sbin|/sbin/*|/srv|/srv/*|/sys|/sys/*|/usr|/usr/*|/var|/var/*)
		die "refusing system path as staging output: $resolved_output"
		;;
esac
if [ -e "$resolved_output" ]; then
	[ -d "$resolved_output" ] || die "output exists and is not a directory"
	if [ -n "$(ls -A -- "$resolved_output")" ]; then
		die "output directory is not empty: $resolved_output"
	fi
fi

repo_root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
base_sshd=$repo_root/files/lmi-p1/sshd_config
[ -f "$base_sshd" ] || die "hardened base policy missing: $base_sshd"

# The owner-mode variant is derived from the hardened base at run time so it
# can never drift from the shipped default. Fail closed if the base no longer
# carries the exact directives this opt-in amends or retains.
require_base_line() {
	grep -qx -- "$1" "$base_sshd" \
		|| die "hardened base sshd_config lost required directive: $1"
}
require_base_line 'PermitRootLogin no'
require_base_line 'AllowUsers lmi'
require_base_line 'PasswordAuthentication no'
require_base_line 'KbdInteractiveAuthentication no'
require_base_line 'AuthenticationMethods publickey'
require_base_line 'GatewayPorts no'
require_base_line 'X11Forwarding no'
require_base_line 'PermitTunnel no'
require_base_line 'PermitUserEnvironment no'

owner_key_line=
if [ -n "$owner_pubkey" ]; then
	[ -f "$owner_pubkey" ] || die "owner public key file not found: $owner_pubkey"
	[ "$(wc -l < "$owner_pubkey")" -le 1 ] \
		|| die "owner public key file must contain exactly one line"
	owner_key_line=$(head -n 1 -- "$owner_pubkey")
	case $owner_key_line in
		'ssh-ed25519 AAAA'*) ;;
		*) die "owner public key must be a single ssh-ed25519 line" ;;
	esac
fi

mkdir -p -- "$resolved_output/etc/ssh/sshd_config.d" \
	"$resolved_output/etc/sudoers.d" \
	"$resolved_output/root-authorized-keys"

sshd_dropin=$resolved_output/etc/ssh/sshd_config.d/40-lmi-owner-mode.conf
cat > "$sshd_dropin" <<'EOF'
# lmi owner-mode opt-in sshd variant (40-lmi-owner-mode.conf).
# Explicitly labeled owner-mode: never shipped in the public image default.
# OpenSSH uses the first obtained value per keyword, so this file must be
# included BEFORE the hardened directives (Include as the first line of
# /etc/ssh/sshd_config); an Include placed after them has no effect.
# Root login stays key-only; password authentication stays disabled.
PermitRootLogin prohibit-password
AllowUsers lmi root
EOF

full_variant=$resolved_output/etc/ssh/sshd_config.owner-mode
sed \
	-e 's/^PermitRootLogin no$/PermitRootLogin prohibit-password/' \
	-e 's/^AllowUsers lmi$/AllowUsers lmi root/' \
	-- "$base_sshd" > "$full_variant"

# Post-generation invariants: exactly the two intended lines changed, and
# every retained prohibition is still present.
grep -qx 'PermitRootLogin prohibit-password' "$full_variant" \
	|| die "generated variant lost the key-only root login directive"
grep -qx 'AllowUsers lmi root' "$full_variant" \
	|| die "generated variant lost the owner-mode AllowUsers directive"
for retained in \
	'PasswordAuthentication no' \
	'KbdInteractiveAuthentication no' \
	'AuthenticationMethods publickey' \
	'GatewayPorts no' \
	'X11Forwarding no' \
	'PermitTunnel no' \
	'PermitUserEnvironment no'; do
	grep -qx -- "$retained" "$full_variant" \
		|| die "generated variant dropped retained prohibition: $retained"
done
changed_lines=$(diff -- "$base_sshd" "$full_variant" | grep -c '^<' || true)
[ "$changed_lines" -eq 2 ] \
	|| die "generated variant changed $changed_lines base lines instead of 2"

sudoers_dropin=$resolved_output/etc/sudoers.d/91-lmi-owner-mode
cat > "$sudoers_dropin" <<'EOF'
# lmi owner-mode opt-in sudoers variant (91-lmi-owner-mode).
# Explicitly labeled owner-mode: never shipped in the public image default,
# which allows exactly "lmi ALL=(root) NOPASSWD: /usr/sbin/lmi-rootctl".
lmi ALL=(ALL) NOPASSWD: ALL
EOF
if command -v visudo >/dev/null 2>&1; then
	visudo -c -f "$sudoers_dropin" >/dev/null \
		|| die "generated sudoers drop-in failed visudo syntax check"
elif [ -x /usr/sbin/visudo ]; then
	/usr/sbin/visudo -c -f "$sudoers_dropin" >/dev/null \
		|| die "generated sudoers drop-in failed visudo syntax check"
else
	echo "note: visudo not found on this host; syntax check skipped" >&2
fi

authorized_keys=$resolved_output/root-authorized-keys/authorized_keys
if [ -n "$owner_key_line" ]; then
	printf '%s\n' "$owner_key_line" > "$authorized_keys"
else
	cat > "$authorized_keys" <<'EOF'
# lmi owner-mode placeholder: replace this whole file's comment lines with
# exactly one ssh-ed25519 public key line for the owner before installing
# it as /root/.ssh/authorized_keys (root:root, directory 0700, file 0600).
# Owner-mode root login is key-only; no key here means no root login.
EOF
fi

cat > "$resolved_output/OWNER-MODE-APPLY.md" <<'EOF'
# lmi owner-mode staging tree

Generated staging tree — nothing here has been applied to any device or
host. Owner-mode is the explicit opt-in documented in
notes/ssh-owner-mode-addendum-2026-07-29.md; the public image default
remains the hardened r145 contract.

Manual application (owner action, on the device, after review):

1. Verify the sudoers drop-in syntax on a host with visudo:
   `visudo -c -f etc/sudoers.d/91-lmi-owner-mode`.
2. Install it as `/etc/sudoers.d/91-lmi-owner-mode` (`root:root`, mode
   `0440`), keep `/etc/sudoers.d/90-lmi-rootctl` unchanged, then run a
   whole-policy `visudo -c` on the device.
3. Apply the sshd change one of two ways:
   - Replace `/etc/ssh/sshd_config` with `etc/ssh/sshd_config.owner-mode`
     (recommended; it is the hardened base with exactly two lines
     changed), or
   - Install `etc/ssh/sshd_config.d/40-lmi-owner-mode.conf` under
     `/etc/ssh/sshd_config.d/` and add
     `Include /etc/ssh/sshd_config.d/*.conf` as the FIRST line of
     `/etc/ssh/sshd_config`. OpenSSH uses the first obtained value per
     keyword, so an Include after the hardened directives has no effect.
4. Install the owner Ed25519 public key as `/root/.ssh/authorized_keys`
   (`root:root`, directory `0700`, file `0600`). The placeholder file must
   not be installed as-is.
5. Validate with `sshd -t`, then restart sshd through OpenRC.

Still forbidden in owner-mode: SSH password authentication (all users,
including root), keyboard-interactive authentication, GatewayPorts,
X11 forwarding, TUN/TAP tunnels, user-controlled environment injection,
and any reusable console password.
EOF

echo "owner-mode staging artifacts generated under: $resolved_output"
(cd -- "$resolved_output" && find . -type f | sort | while IFS= read -r f; do
	sha256sum -- "$f"
done)
echo "nothing was applied; see OWNER-MODE-APPLY.md for the manual owner steps"
