# lmi Port — Domain Glossary

Shared vocabulary for the Redmi K30 Pro (`lmi`) postmarketOS port: two kernel
tracks, hash-pinned build artifacts, and consent-gated device writes. Terms
are defined by how this repository actually uses them; known ambiguities are
called out rather than papered over.

## Language

### Tracks and version labels

**Track**:
One of the two independent version lines: *downstream* (`D-vNN`, LineageOS
4.19 vendor kernel, the working baseline) and *mainline/copydown* (`M-rNN`,
mainline SM8250 path, not boot-verified).
_Avoid_: mixing the two sequences as one version line

**Copydown**:
The mainline-track technique of importing (copying down) mainline package
references into a local overlay to build boot images; `M-rNN` labels cover
both mainline and copydown work.

**D-number (D110, D114)**:
Shorthand for specific downstream artifacts: *D110* is the known-good
downstream v110 boot image used for guarded RAM boots and recovery; *D114*
is the downstream v114 userdata baseline that the P2 deployment campaign
writes and replaces. Distinct from generic `D-vNN` prose labels — D110/D114
name pinned binary baselines, not just versions.

**P-number (P1, P2, P3)**:
The staged build/release families: *P1* is the sealed, source-locked boot
side (kernel/boot filesystem), *P2* is the rootfs/userspace side (the
six-row terminal image), *P3* is the audio-userspace candidate line.
Ambiguity: `README.md`'s "current local P0/P1/P2 status" uses P-numbers as
*hardware-enablement priorities* — an unrelated numbering; read from
context.

### Artifacts and integrity

**Pin**:
Binding a file or tool to an exact identity (SHA-256, size, sometimes
path/URL) inside code or a lock file, so that any byte change is refused
rather than silently accepted. Pins are duplicated by hand across files in
places, which is a known fragility.

**Lock**:
A hash-pinned JSON contract that freezes a set of inputs. Main kinds:
*source-lock* (the exact package/source closure of a build, e.g. the
D110/D114 terminal source lock), *policy-lock* (freezes a deployer's own
policy and helper bytes so the gate cannot drift), and *rebuild-lock*
(`candidate-rebuild-lock`: the base/candidate/raw/sparse image hashes needed
to reproduce a candidate). Note the collision with runtime locking
(`flock`-style execute locks) — "lock file" means the JSON contract unless
talking about concurrency.

**Attestation**:
A recorded, hash-bound statement that a build or assembly step was performed
on specific inputs and produced specific outputs (e.g. the APK
build-attestation, the userdata assembly attestation). Evidence of *what was
done*, where a lock states *what is allowed*.

**Sealed build**:
The P1 discipline where a root-owned, content-addressed seal inventories
every input tree and file a privileged build may consume; the build refuses
anything outside the activated seal. Independent of git.

**Candidate**:
A built image or package that exists and is hash-pinned but is *not yet
approved* for a device write or public release; candidates are reviewed and
pinned before any deployment. "Rejected flash candidates" are never
committed.

**Injector**:
The offline tool (`inject_rootfs_candidate` family) that applies the
six-row-terminal delta onto a base rootfs to produce the P2 candidate image,
under its own policy lock and expected-delta allowlist.

**Transient stage**:
The staged copy of the injector and its runtime closure placed under `/run`
(the "source bridge") for one execution — privileged state that exists only
for the current boot and leaves nothing persistent. More broadly, notes use
"transient state" for any remote or privileged state that a test creates
and must not outlive the session.

**Six-row terminal**:
The P2 user experience: a Weston-based on-screen terminal whose keyboard is
a fixed six-row layout (contract frozen in the r1 readiness record and
enforced by a static verifier). "Six-row" identifies the whole candidate
line (packages, image, release), not just the keyboard widget.

### Governance (bringup engine vocabulary)

**Tier**:
The irreversibility class of an action's *consequences*: `read_only`,
`volatile` (bare reboot), `ram_rw` (RAM-only boot — the command writes no
partition but the booted OS mounts userdata read-write), `persistent`
(partition writes). Tiering follows consequences, not whether the command
itself writes.

**Scope (standing scope)**:
A policy entry through which the owner pre-authorizes a whole tier/operation
pair (only volatile and ram_rw are ever standing); persistent actions are
deliberately never standing.

**Profile**:
A hash-bound file describing one specific persistent write (image identity,
targets, rollback); the owner authorizes a profile, not a command, and the
authorization dies with the profile's hash.

**Claim**:
The atomic act of consuming a one-shot receipt for exactly one device state
change, recorded in the append-only ledger; after a claim, no outcome
permits automatic retry.

**Receipt**:
The short-lived, single-use token issued and consumed around one attempt.
Ambiguity: three lifetimes coexist today — the engine's 900 s receipt, the
D110 executor's internal 30 s attempt ticket, and the D114 120 s one-use
approval (see ADR 0001).

**Experiment**:
The engine's unit of work: one hypothesis, at most one device state change,
one active record (`bringup-active`); absence of an active record is the
safe idle state.

**Ledger**:
The append-only claims log under `notes/bringup-claims/`; never cleaned,
never rewritten.

**Executor**:
The code that actually runs a device-affecting command and owns the device
gates (identity, battery, exact arguments) — deliberately outside the
engine, which never touches the device.

**Forbidden set**:
The hardcoded command words (erase, format, repartition, set_active,
--force, verity-disable, relock) that no data file can un-forbid.

**Session gate (session grant)**:
The D110 executor's interim consent machine: one owner authorization bound
to the current agent thread, helper, policy, image, tool, host boot, and
device, valid up to 12 hours unless revoked or any bound input changes;
every execution still repeats a full read-only preflight. Interim by
declaration — kept "until wired to the engine".

### Deployment

**Transport route**:
Which host stack carries the fastboot transfer for a D114 deploy: the
*Windows-helper route* (Python drives a locked PowerShell helper using
pinned Windows platform-tools) or the *WSL-native route* (the WSL deployer
runs fastboot directly). Same consent model, different platform shims.

**UNKNOWN outcome**:
A deploy result the transcript parser could not positively confirm; treated
conservatively as "an attempt happened, outcome unresolved" — never
auto-retried, and requiring review plus a fresh approval and claim. Known
to be stricter than reality: an UNKNOWN can be a real success.

### Code families (disambiguation)

**`scripts/lmi_p2/` vs `scripts/lmi_p2_d114/`**:
Unrelated code families that share the P2 name: `lmi_p2/` generates and
policy-checks the P2 source overlay/profile; `lmi_p2_d114/` assembles and
deploys the D114 userdata image. Neither imports the other.

**`scripts/lmi_p1/` vs P1-priority**:
`lmi_p1/` is the sealed-build code family (boot side), not the "P1" of the
hardware-priority list.
