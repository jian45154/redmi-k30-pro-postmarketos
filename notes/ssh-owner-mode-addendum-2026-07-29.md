# lmi SSH owner-mode addendum — 2026-07-29

Status: **documentation and host-side staging tooling only; no sealed image,
shipped default, or runtime behavior is changed by this work.** No phone,
fastboot command, partition, SSH session, or active bring-up experiment was
touched during this work.

This note amends `notes/ssh-full-function-contract-2026-07-24.md`. That
contract remains the public-image default, unchanged: Ed25519 key-only SSH
for exactly the `lmi` user, `PermitRootLogin no`, no reusable passwords on
any interface, and privileged operations only through the exact
`NOPASSWD: /usr/sbin/lmi-rootctl` sudo rule.

## What owner-mode is

Owner-mode is an explicit, owner-initiated OPT-IN for a phone the owner uses
as a portable development workstation and wants unrestricted root on. It is
a distinct, explicitly labeled configuration variant, not a relaxation of
the default profile. It is applied either at install time through an
installer opt-in flag or post-install by the owner; it is **never the
shipped default**, and the frozen public-image sanitizer and the sealed P1
image gates continue to reject owner-mode artifacts in shipped images.

## Exactly what owner-mode changes

Owner-mode makes exactly two additions on top of the hardened r145 contract:

1. **Root SSH login with keys only.** `PermitRootLogin` moves from `no` to
   `prohibit-password`, `AllowUsers` gains `root`, and the owner installs
   exactly one owner Ed25519 public key in `/root/.ssh/authorized_keys`
   (`root:root`, directory `0700`, file `0600`). Root login is still
   impossible without the owner's private key.
2. **Blanket passwordless sudo for the owner account.** A second,
   explicitly labeled sudoers drop-in `/etc/sudoers.d/91-lmi-owner-mode`
   contains exactly `lmi ALL=(ALL) NOPASSWD: ALL`. The default
   `/etc/sudoers.d/90-lmi-rootctl` drop-in and `lmi-rootctl` audit path
   remain installed and unchanged; owner-mode adds authority next to them
   under a distinct file name so the two profiles are never confused.

## Exactly what owner-mode still forbids

Owner-mode does not reopen any password or transport boundary. On every
interface (USB/RNDIS, Wi-Fi, console-facing SSH), even in owner-mode:

- `PasswordAuthentication no` — SSH password authentication stays disabled
  for every user, including root (`prohibit-password` plus
  `AuthenticationMethods publickey`).
- `KbdInteractiveAuthentication no` — keyboard-interactive/challenge
  authentication stays disabled.
- `GatewayPorts no` — remote-forward listeners stay on the phone's
  loopback interface.
- `X11Forwarding no`, `PermitTunnel no`, and `PermitUserEnvironment no`
  are retained from the base policy.
- The `lmi` and root shadow password fields stay locked; owner-mode grants
  no reusable password anywhere.

## Application boundary

Owner-mode is applied by the owner, never by repository automation:

- `scripts/75_generate_lmi_owner_mode_config.sh` is a host-only generator.
  It writes the owner-mode artifacts (sshd drop-in, full merged
  owner-mode `sshd_config` variant derived from `files/lmi-p1/sshd_config`,
  the `91-lmi-owner-mode` sudoers drop-in, a root `authorized_keys`
  placeholder or owner key, and application instructions) into a private
  staging directory. It refuses system configuration roots, refuses to run
  as root, and never contacts the phone; applying the staged files to a
  device is a separate manual owner action outside this repository's
  tooling.
- An installer opt-in flag is the intended install-time path; it is not
  implemented yet. Until it exists, owner-mode is post-install only.
- Because the shipped `files/lmi-p1/sshd_config` has no `Include`
  directive and OpenSSH uses the first obtained value per keyword, the
  sshd drop-in only works if included before the hardened directives; the
  generated instructions state this, and the full merged variant is the
  simpler application path.

## Default-profile invariants

The host gates that pin the public default are intentionally not extended
to accept owner-mode inside shipped images:

- The P1 builder and artifact semantics still require exactly one sudoers
  drop-in (`90-lmi-rootctl`) and the exact hardened `sshd_config` in any
  sealed image; a rootfs containing `91-lmi-owner-mode` or
  `PermitRootLogin prohibit-password` still fails closed.
- `tests/governance/test_owner_mode_config.py` pins the owner-mode
  artifacts as a distinct labeled variant and simultaneously re-pins the
  hardened default bytes in `files/lmi-p1/`, so the opt-in cannot silently
  leak into the default profile.
