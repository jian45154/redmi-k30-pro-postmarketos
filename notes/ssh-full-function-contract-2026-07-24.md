# lmi full SSH contract — 2026-07-24

Status: **source policy and target OpenSSH parsing are host-verified; no sealed
successor image or runtime behavior is verified yet.** No phone, fastboot
command, partition, or active bring-up experiment was touched during this
work.

## Meaning of “full SSH”

The supported owner workflow is deliberately broad at the `lmi` user boundary:

- Ed25519 public-key login for exactly the provisioned `lmi` owner;
- interactive shell/PTY and non-interactive remote commands;
- the in-process SFTP subsystem and modern SCP-over-SFTP downloads/uploads;
- client-originated local, remote, dynamic, and Unix-socket forwarding;
- outbound `ssh`, `scp`, `sftp`, `ssh-add`, `ssh-agent`, and `ssh-keyscan`
  commands on the phone; and
- audited privileged operations through `sudo /usr/sbin/lmi-rootctl ...`.

“Full” does not mean weakening the trust boundary. Root SSH login, reusable
SSH passwords, keyboard-interactive authentication, X11 forwarding, raw
TUN/TAP forwarding, user-controlled environment injection, and externally
reachable remote-forward listeners remain disabled. `GatewayPorts no` keeps
remote forwards on the phone's loopback interface unless a future separately
reviewed policy changes that boundary.

Key-only SSH also requires key-only privilege. The `lmi` account must have a
locked `/etc/shadow` password field, must not belong to `wheel` or any other
sudo-authorized group, and must have no effective sudo authorization except
the exact passwordless `lmi-rootctl` command rule. Merely disabling SSH
password authentication is insufficient: an SSH key holder could otherwise
use a reusable console password with a broad `%wheel` sudo rule and bypass
`rootctl`.

The SSH service policy is transport-independent. USB/RNDIS and Wi-Fi must
reach the same daemon and owner key; a working Wi-Fi scan or route does not by
itself prove an SSH session traversed WLAN.

## Source implementation

`files/lmi-p1/sshd_config` now explicitly enforces:

```text
PermitRootLogin no
AuthenticationMethods publickey
AllowUsers lmi
DisableForwarding no
PermitTTY yes
AllowAgentForwarding yes
AllowTcpForwarding yes
AllowStreamLocalForwarding yes
PermitOpen any
PermitListen any
GatewayPorts no
X11Forwarding no
PermitTunnel no
PermitUserEnvironment no
Subsystem sftp internal-sftp
```

The P1 builder installs `openssh-client-default`, requires its
`openssh-client-common` dependency, requires both client packages to be
`aarch64` and exactly version-matched with `openssh-server-pam`, and binds
`ssh`, `scp`, `sftp`, `ssh-add`, `ssh-agent`, and `ssh-keyscan` to their
canonical APK owners and file checksums. Final binaries must be root-owned,
single-link, mode-0755 AArch64 ELF files under real root-owned, non-writable
`/usr` and `/usr/bin` directories, with bytes that match the installed APK
database.

The server side is closed over the matching `openssh-keygen`,
`openssh-server-common`, `openssh-server-common-openrc`, and
`openssh-server-pam` split packages. The builder binds `ssh-keygen`, the
OpenRC service and conf.d file, the PAM entry point, both PAM sshd binaries,
the linux-pam vendor policy chain, the required PAM modules, and the `libpam`
payload plus SONAME link to their canonical package records. Local
`/etc/pam.d/base-*` overrides, an SSH OpenRC override, or a missing/tampered
member of that closure are rejected.

Session usability is also an image invariant: `lmi` must be exactly UID/GID
`10000`, home `/home/lmi`, shell `/bin/ash`, with the locked non-expired
shadow tuple `lmi:!::0:99999:7:::`. `/bin/ash` must resolve through the
canonical root-owned BusyBox closure; static `nologin` files are forbidden;
and `/home`, `/home/lmi`, `.ssh`, and `authorized_keys` must have the exact
root/owner and non-writable metadata needed by OpenSSH `StrictModes`.

The candidate device package is now `1-r145`. The P1 pmbootstrap profile uses
the supported `ui=none` selection because `postmarketos-ui-shelli` pulls in
the forbidden second DHCP implementation, `dnsmasq`. NetworkManager is not
left implicit: `networkmanager`, `networkmanager-openrc`,
`networkmanager-cli`, and `networkmanager-wifi` are each pinned directly to
`1.52.2-r0`. The package and finalizer also install the same sole
`90-lmi-rootctl` sudoers path and bytes, so `apk fix` cannot restore a broader
or second rule. Privileged Wi-Fi delay overrides are bounded to 0–120 seconds.
The headless package does not install or enable a Greetd/Phosh/Tinydm session,
and P1 rejects those session package families. Display probes and the
confirmation-gated takeover helper remain available for explicit diagnostics,
but splash release and power-panel helpers are not linked into the default
runlevel.
The final image additionally binds the real `/usr/sbin/NetworkManager`
AArch64 ELF to the canonical `networkmanager` APK record, rejects an OpenRC
override, and permits exactly the intended NetworkManager conf.d file and
system-connection profile inventories.

Artifact semantics independently reject a rootfs that drops any of those
server directives, adds a session-defeating directive, or changes the client
packages, architectures, version matches, command owners, payload metadata,
payload checksums, or internal SFTP subsystem.

## Evidence boundary

Historical hardware evidence proves less than this new contract:

- `D-v27` proves USB/RNDIS, key-authenticated SSH remote-command execution, and
  persistence across reboot.
- `D-v43` proves WLAN interfaces and scan behavior while the control channel
  remained USB SSH; it does not prove SSH over Wi-Fi.
- The public D114 candidate proves RNDIS and TCP/22 reachability, then correctly
  refuses login because sanitation removes `authorized_keys`.

No archived public-safe evidence yet proves PTY, SFTP/SCP, forwarding,
device-originated SSH, or an authenticated WLAN SSH session on the exact new
image. Those remain hardware acceptance items, not inferred successes.

## Host and later hardware acceptance

Host acceptance requires:

1. the P1 build and artifact-semantic suites;
2. OpenSSH `sshd -T`/`-G` parsing of the exact policy with the target OpenSSH
   version; and
3. the repository release static CI.

The second item is now host-verified against the signed-cache
`openssh-server-pam=10.4_p1-r0` aarch64 binary, executed with
`qemu-aarch64` and the extracted aarch64 dependency closure. Both `-T` and
`-G` accepted the exact `files/lmi-p1/sshd_config` and emitted byte-identical
87-line effective configurations. A temporary Ed25519 host key was supplied
with `-h` because this host-side parse did not run inside the target rootfs;
the production `HostKey /etc/ssh/ssh_host_ed25519_key` directive remained in
the parsed configuration. The effective output confirmed public-key-only
`lmi` login, all intended session/forwarding permissions, loopback-only remote
forward listeners, and the retained X11/TUN/user-environment prohibitions.
This is configuration-parser evidence, not a hardware or live-session claim.

The final host-side static closure also passed:

- the SSH/P1/P3 regression suites, including the headless-session package and
  path mutation cases;
- the complete repository `scripts/59_release_static_ci.sh`;
- `scripts/65_lmi_release_safety_lint.sh`; and
- an independent mutation review covering account/StrictModes state,
  `pam_limits.so`, server/PAM package ownership and checksums, NetworkManager
  main/vendor override paths, file metadata, and extra configuration entries.

The `ui=none` dependency closure is expected to leave
`/usr/lib/NetworkManager/conf.d` with exactly the two package-owned
`networkmanager=1.52.2-r0` defaults. A legacy shell-UI rootfs contains
additional `50-*.conf` files through its UI/nftables dependency chain, but
that is not an allowed input to this headless transaction; any such extra
entry fails closed. These results validate source policy and fixtures. They do
not substitute for a newly sealed transaction, final installed-database
inspection, or live SSH behavior.

After an exact image is built and independently authorized through the normal
governance path, run `scripts/74_verify_lmi_ssh_full.sh` once over USB and once
over the phone's WLAN address. The helper requires a caller-owned private key,
a pinned `known_hosts` file, strict batch-mode public-key authentication, and
all protocol checks; it has no skip flags. Its active checks are limited to a
remote command, PTY allocation, a metadata-only SFTP query, an SCP/SFTP download
of `/etc/os-release`, and a loopback-only local TCP forward. It never invokes
fastboot, sudo, a service manager, reboot, or a remote write.

A real run can still update sshd/PAM logs, PTY/login accounting, or access
metadata as an incidental consequence of connecting. “No explicit remote
mutation” is the helper boundary; it is not a claim of zero runtime state.

Upload behavior, remote/Unix listener creation, agent forwarding, outbound SSH,
and `rootctl` are covered statically here but require separately scoped runtime
acceptance because they create remote or privileged transient state.

## Remaining sealed-build and D114 gates

The pinned Alpine aarch64 APKINDEX already contains
`openssh-client-common=10.4_p1-r0` and
`openssh-client-default=10.4_p1-r0`, matching the cached server. The currently
published P1 offline cache contains only the server APKs. A sealed build
therefore intentionally fails closed until those exact two client APKs are
acquired against the pinned index, the acquisition is curated and promoted
twice, and the cache attestation, replay record, source-lock binding, and new
seal are reviewed and repinned. This changes the curated acquisition from 584
to 586 members and each published cache from 588 to 590 members; the old cache,
replay, and seal generation remain immutable evidence.

The repository now has a separate host-only calibration workflow in
`scripts/lmi_p1/offline_cache_calibration.py`. Its prepare phase validates the
old 588-member cache and the 586-member successor, then emits a private,
non-authorizing draft. Its execute phase accepts only a separately installed
canonical authorization, bootstraps a fresh real verifier for each of two
promotions, and writes private candidate production records plus a
hash-bound execution receipt without changing `config/`. The accepted output
must match a descriptor-held acquisition snapshot member for member. Because
the unchanged production promoter still reopens an ordinary pathname, this
proves byte equivalence, not that the promoter consumed the held inode.
Same-UID process-memory modification and post-exit evidence rewriting remain
outside this local receipt's assurance; a distinct-UID, root-owned, signed, or
equivalent immutable boundary would be required to resist that threat.

The original v1 draft, SHA-256
`38b8b57e2ce935141c4877254d806e4fa4ba9388486a780f23b8ba06930a8afc`,
is rejected and stale against the security-reviewed executor bytes. It must
not be installed. The replacement v2 review draft is mode `0600`, single-link,
gitignored, targets bundle `ssh-full-20260724-v2`, and has SHA-256
`2fa6ef38846bad1f720f53ad7351a7a7be86ad8a4c15dab07276911ecb29a482`.
The canonical calibration authorization and its one-shot execution bundle are
still absent pending explicit human review and approval. Therefore no
calibration, production promotion, source-lock repin, seal, or sealed build is
claimed yet.

The r145 owner-test package is also not a release candidate. Its inherited
`lmi-qrtr-ns` ELF is checksum-bound (SHA-256
`979426c3ce01f69c18b44d34d8f3f195967c31200da4eb373c9fb0eb565e56e6`)
but has no locally provable public source revision or build recipe. A local
upstream qrtr 1.2 archive at commit `b51ffaf...` is a plausible source
candidate, not a source-to-binary proof: the static-link command, sysroot, and
toolchain that produced the ELF are absent.

The CNSS path reads executable/runtime bytes from the live `super` partition
and firmware/configuration from live `modem` and `persist`. The observed
Android system was LineageOS `23.2-20260422-NIGHTLY-lmi`; calling all of those
inputs “stock” would therefore overstate the evidence. No authoritative
release digest plus exact partition and archive-member mapping currently binds
the live `cnss-daemon`, runtime APEX/libraries, QCA firmware, configuration,
and calibration bytes to one identified source image. Replacing the
nameserver or vendor chain is a separate Wi-Fi hardware hypothesis; it must
use independently acquired, source-pinned inputs and must not be silently
combined with the SSH acceptance experiment.

The frozen D114 r1 public-image sanitizer remains unchanged: it must not ship
an owner key. It is also **not an acceptable full-SSH base as-is**: read-only
inspection found `lmi` in `wheel`, an active broad `%wheel ALL=(ALL) ALL`
sudo rule, and a reusable `lmi` password hash. Together those paths can bypass
`lmi-rootctl` after key login.

Its successor must:

1. include `openssh-client-default` and apply this same server policy;
2. lock the `lmi` password in both active and backup shadow databases;
3. remove `lmi` from `wheel` and reject every other sudo-authorized group;
4. remove every broad user/group sudo rule and prove that effective
   authorization for `lmi` is exactly
   `NOPASSWD: /usr/sbin/lmi-rootctl`;
5. install exactly one owner Ed25519 key only during private
   personalization; and
6. bind the image, key, passwd/group/shadow databases, main sudoers file, and
   complete sudoers drop-in inventory in never-publish evidence.

These account and sudo gates apply to both public and private successors. A
public artifact remains listening-but-unloginable until its owner performs a
separate personalization step.
