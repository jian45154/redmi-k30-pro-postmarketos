# Current State

> Current project organization is tracked in `docs/tracks/README.md`.
> This file preserves earlier state snapshots and should not be treated as the
> sole current handoff after downstream `D-v43`/`D-v46`, local `D-v52`,
> and mainline `M-r7`.

## Update: 2026-07-09 / 2026-07-10

- P0 safety boundary is unchanged: do not write `boot`, `vendor_boot`,
  `init_boot`, `userdata`, `dtbo`, `vbmeta`, `super`, `persist`, modem/EFS, or
  related device-specific partitions without a fresh preflight and exact
  approval.
- `D-v27` remains the rollback/control baseline, not the strongest current
  hardware milestone.
- `D-v46` is the verified downstream Wi-Fi cleanup baseline. Live evidence
  shows SSH reachable, `wlan0` up with a default route, and `p2p0` plus
  `wifi-aware0` present. `D-v43` remains the earlier Wi-Fi baseline.
- Display has moved past pure discovery: DRM/KGSL/DSI are present, direct
  `kmscube -D /dev/dri/card0` exits successfully, and dmesg records
  `dsi_display_set_mode` for `1080x2400@60`. A later passive sample shows
  DPMS/backlight off after the client exits. The latest successful non-atomic
  active snapshot catches `kmscube` alive with CRTC framebuffer binding and
  later in-client sysfs shows connector enabled, DPMS `On`, and `bl_power=0`,
  but brightness remains `0`; the 2026-07-09 17:13:47 UTC active sample repeats
  the same pattern with `during_kmscube_alive=1`, `kmscube_status=0`, CRTC
  `129` using framebuffer `196`, later sysfs `enabled=enabled`, DPMS `On`,
  and `bl_power=0`. The 13:27:05 UTC
  atomic `kmscube -A` sample did not improve the evidence: it exited `255`,
  left CRTC `129` on framebuffer `0`, and stayed DPMS/backlight off.
  The 2026-07-09 18:35:00 UTC active `kmscube` snapshot again recorded
  `during_kmscube_alive=1` and `kmscube_status=0`; during the client, DSI was
  connected/enabled with DPMS `On` and `bl_power=0`, but brightness and
  `actual_brightness` remained `0`; after client exit it returned to
  DPMS/backlight off. The redacted evidence audit classified this as
  `DISPLAY_ACTIVE_KMSCUBE_STATE_SNAPSHOT_RECORDED_NEEDS_OPERATOR_OBSERVATION_TOKEN`
  with no automatic baseline promotion.
  The 2026-07-09 18:38:41 UTC passive display/backlight topology probe recorded
  `panel0-backlight` as a raw backlight with brightness/actual brightness `0`,
  max brightness `2047`, and `bl_power=4` at rest. It also captured Qualcomm
  WLED/KTZ backlight kernel config, MDP/backlight sysfs backlinks, and Xiaomi
  DSI panel DT candidates with DCS backlight control. The local evidence audit
  now marks DRM, backlight, and DT panel topology present, but still classifies
  the display path as requiring operator observation and review.
  Post-client/passive samples reconfirm DPMS/backlight off after client exit.
  Display/backlight topology is now captured for review only: DRM/DSI,
  `panel0-backlight`, and primary display DT/sysfs backlinks are present. A
  physical observation token is still required before changing display labels;
  repeat KMS sampling should not substitute for that observation.
  The 2026-07-09 18:48:05 UTC passive backlight permission probe confirmed the
  current runtime user is `lmi` with `video` group and captured the
  `panel0-backlight` sysfs link/device, but did not capture file modes or
  writability for `brightness`. The 2026-07-09 18:50:07 UTC retry had an
  empty-path quoting failure and only produced `No such file or directory`
  records, so it cannot be used to infer whether non-root brightness writes are
  possible. The 2026-07-09 18:58:19 UTC fixed read-only backlight sysfs
  permission probe then recorded `brightness` as `mode=664 owner=root
  group=video`, `brightness_writable_by_current_user=yes`, and
  `brightness_value=0`; `max_brightness=2047`, `actual_brightness=0`, `type=raw`,
  and `bl_power=4` were also captured. This proves the current `lmi` user can
  write the `brightness` file through its `video` group membership, but it does
  not authorize a brightness write. Any actual brightness test remains a
  hardware/display state change and still requires separate exact approval,
  bounded value/restore handling, and physical observation. Two bounded active
  brightness tests at 2026-07-09 19:03:17 UTC and 19:04:47 UTC correctly skipped
  the write because `kmscube` had exited before DSI/DPMS/backlight power reached
  the active preconditions. The 2026-07-09 19:06:17 UTC short-poll active test
  reached `during_kmscube_alive=1`, `active_precondition_ready=1`, DSI
  enabled/DPMS `On`, and `bl_power=0`, then temporarily wrote `brightness=128`
  and restored the original `brightness=0` with `brightness_restore_status=ok`.
  However, during the hold window `actual_brightness` remained `0` and
  `bl_power` read back as `4`, so this proves only that the `brightness` sysfs
  write path is accepted and restored; it does not prove visible backlight or a
  panel handoff. The route remains
  `BACKLIGHT_BRIGHTNESS_ACTIVE_TEST_RECORDED_REQUIRES_PHYSICAL_OBSERVATION`.
  The combined 2026-07-09 19:13:36 UTC redacted evidence audit records
  `display_backlight_status=DISPLAY_BACKLIGHT_BRIGHTNESS_WRITE_ACCEPTED_NO_ACTUAL_BRIGHTNESS_REQUIRES_REVIEW`
  and keeps `display_status=DISPLAY_ACTIVE_KMSCUBE_STATE_SNAPSHOT_RECORDED_NEEDS_OPERATOR_OBSERVATION_TOKEN`.
  Do not keep repeating brightness writes without a live physical observation
  token; the write path is already proven. The only useful follow-up on this
  route is a bounded, observed, time-series diagnostic that records KMS/DSI,
  `brightness`, `actual_brightness`, `bl_power`, and focused dmesg around the
  same active window. `scripts/downstream_v46_display_observed_timeseries.sh`
  is now the prepared D-v46-only tool for that next step; it requires
  `LMI_DISPLAY_TIMESERIES_CONFIRM=display-observed-timeseries-xiaomi-lmi`,
  starts only bounded `kmscube`, reads KMS/DSI/backlight/dmesg state, and does
  not write brightness, services, rfkill, bootloader transport, or partitions.
  Treat its reports as `validation_scope=D46_RUNTIME_ONLY_NOT_D52_VALIDATION`:
  they can refine the D-v46 display diagnosis, but they do not validate D-v52.
- P2 passive evidence now records no real ALSA card and no proven Bluetooth HCI
  controller. DT/sysfs topology and the focused service-chain snapshot have
  been captured for review only. The service-chain snapshot records
  `dev_subsys_adsp=present`, but `dev_qrtr=missing` and
  `proc_net_qrtr=missing`; it also inventories ADSP firmware symlinks and
  QCA6390/`ttyHS0` topology. The next P2 candidate review is recorded in
  `notes/downstream-p2-next-candidate-review-2026-07-09.md`: QRTR/PDR/service
  foundation first, audio kernel config second, Bluetooth last. Do not use the
  current evidence to change kernel, package, firmware, rfkill, service,
  playback, recording, or sysfs state without that review gate and separate
  approval. The 2026-07-09 17:26:44 UTC service-chain refresh reconfirmed
  `dev_subsys_adsp=present`, `dev_qrtr=missing`, `proc_net_qrtr=missing`,
  `pd-mapper` service missing, no real ALSA card, and no proven Bluetooth HCI.
  The local D-v50 service-foundation source candidate is now applied in
  `device-xiaomi-lmi` source as package `1-r113`; it adds `pd-mapper` and
  `pd-mapper-openrc`, enables the `pd-mapper` default runlevel symlink, and
  tightens OpenRC ordering around `lmi-firmware-mount`, `lmi-qrtr-ns`,
  `pd-mapper`, `rmtfs`, `tqftpserv`, and CNSS without hard-needing
  `pd-mapper`. `scripts/99_audit_downstream_d50_service_foundation_candidate.sh`
  now reports `D50_SERVICE_FOUNDATION_CANDIDATE_STATIC_READY_BUILD_NEXT`.
  `D-v52` has now built this source candidate into a local artifact and the
  rootfs verifier proves `/usr/bin/pd-mapper`, `/etc/init.d/pd-mapper`,
  `/etc/runlevels/default/pd-mapper`, `pd-mapper`, and `pd-mapper-openrc` are
  present with conservative OpenRC ordering. The 2026-07-09 18:44:04 UTC
  passive P2 service-chain refresh on the current D-v46 runtime again recorded
  `dev_subsys_adsp=present`, `dev_qrtr=missing`, `proc_net_qrtr=missing`, and
  missing `pd-mapper` service. The combined redacted evidence audit now records
  P2 service-chain evidence for ADSP visibility, read-only service status,
  audio bindings, Bluetooth transport topology, firmware inventory, and kernel
  blockers, but keeps it review-only with
  `P2_SERVICE_CHAIN_RECORDED_REQUIRES_REVIEW`.
- `D-v52` is the latest built local candidate with target-side rootctl
  confirmation gates for reboot, poweroff, Wi-Fi trigger, active display
  takeover, and service state changes plus the D-v50 service-foundation content.
  It expects and matches `device-xiaomi-lmi` `1-r113`. `D-v52` has not been
  runtime-verified. `D-v51` remains an older target-gate artifact at `1-r112`
  and should not be used to claim D-v52 service-foundation changes on hardware.
  `D-v49` remains an older service-state gate artifact and should not be used
  to claim the newer hardening on hardware. The currently running device is
  `D-v46` and lacks `/usr/sbin/lmi-rootctl`, `/usr/sbin/lmi-display-probe`, and
  the rootctl sudoers drop-in; the host wrapper now reports this mismatch before
  attempting sudo/rootctl. The following D-v51 USB/fastboot records are
  retained as historical evidence only. The D-v51 bootloader-fastboot preflight
  route used
  `DOWNSTREAM_BOOTLOADER_PREFLIGHT_CONFIRM=bootloader-readonly-preflight-xiaomi-lmi`;
  `userdata` rootfs write and temporary RAM boot remain separate exact
  approvals. The 2026-07-09 14:52:18 UTC read-only preflight attempt timed out
  with `WAIT_TIMEOUT_NO_BOOTLOADER_FASTBOOT_DEVICE`; no rootfs write, RAM boot,
  reboot, erase, format, or partition write followed. A second 2026-07-09
  15:11:34 UTC read-only preflight attempt reached the same timeout route, so
  the stop condition remained: device was not visible in bootloader fastboot.
  The 2026-07-09 15:59:29 UTC D-v51 read-only preflight also timed out with
  `WAIT_TIMEOUT_NO_BOOTLOADER_FASTBOOT_DEVICE`; no getvar validation, rootfs
  write, RAM boot, reboot, erase, format, or partition write followed. No
  D-v51 bootloader/RAM-boot/write execute step is eligible from the failed
  fastboot route; read-only RNDIS connectivity checks remained eligible because
  PnP then showed a pmOS/RNDIS candidate. The 2026-07-09 16:12:07 UTC
  D-v51 USB mode read-only classification then reported
  `USB_MODE_NO_ADB_OR_FASTBOOT_DEVICE_VISIBLE`: host-side `adb devices` and
  `fastboot devices` saw no device, with no shell, getvar, reboot, boot, flash,
  erase, format, service change, or partition write. After adding bounded
  per-tool timeouts and a polling window to the same helper, the 2026-07-09
  16:20:53 UTC 20-second read-only observation reported
  `USB_MODE_NO_ADB_OR_FASTBOOT_DEVICE_VISIBLE_AFTER_WAIT` after 10 polls; ADB
  and fastboot command execution worked, but no device was visible.
  The 2026-07-09 16:27:41 UTC Windows PnP read-only check then reported
  `WINDOWS_USB_PNP_PMOS_RNDIS_CANDIDATE_VISIBLE` with two redacted candidates:
  a USB composite device and a Remote NDIS based Internet Sharing Device. This
  does not runtime-verify D-v51 and does not make any D-v51 execute step
  eligible. At that point, it changed the immediate read-only diagnostic route:
  first check
  RNDIS host connectivity to `172.16.42.1` on ICMP/TCP 22/TCP 23, then run the
  remote rootctl preflight only if SSH 22 is reachable. The 2026-07-09 16:41:39
  UTC RNDIS connectivity check reported ICMP reachable, TCP 22 reachable, and
  TCP 23 not reachable, with
  `RNDIS_CONNECTIVITY_SSH22_REACHABLE_REMOTE_PREFLIGHT_ELIGIBLE`. The following
  remote rootctl preflight over SSH reported `sudo=present`, `rootctl=missing`,
  and `REMOTE_ROOTCTL_PREFLIGHT_ROOTCTL_MISSING`, matching the current D-v46
  runtime. The 2026-07-09 17:04:58 UTC D-v51 runtime identity read-only check
  then reported `device_pkg_version=device-xiaomi-lmi-1-r107`,
  `d51_cmdline_uuid_status=differs`, missing rootctl/display-probe/sudoers, and
  `D51_RUNTIME_IDENTITY_D46_ROOTCTL_MISSING`. Do not run rootctl commands until
  D-v52 is actually runtime-verified. The 2026-07-09 18:32:31 UTC selected
  RNDIS read-only check again reported ICMP and TCP 22 reachable, TCP 23 not
  reachable, and `RNDIS_CONNECTIVITY_SSH22_REACHABLE_REMOTE_PREFLIGHT_ELIGIBLE`.
  The following 2026-07-09 18:33:09 UTC D-v52 runtime identity read-only check
  still reported `device_pkg_version=device-xiaomi-lmi-1-r107`,
  `d52_cmdline_uuid_status=differs`, missing rootctl/display-probe/sudoers, and
  `D52_RUNTIME_IDENTITY_D46_ROOTCTL_MISSING`. The 2026-07-09 18:43:34 UTC
  Windows USB/PnP read-only classification again showed a USB composite device
  and Remote NDIS device with `VID_0525&PID_A4A2`, routing to
  `WINDOWS_USB_PNP_POSTMARKETOS_RNDIS_VISIBLE_REVIEW`; the device is not
  currently visible as bootloader fastboot from host-side PnP evidence. The
  2026-07-09 20:57:47 UTC D-v52 RNDIS runtime read-only sequence then reported
  ICMP and TCP 22 reachable, TCP 23 not reachable, and an attempted SSH runtime
  identity check. That identity check still reported
  `device_pkg_version=device-xiaomi-lmi-1-r107`,
  `d52_cmdline_uuid_status=differs`, missing rootctl/display-probe/sudoers, and
  `D52_RUNTIME_IDENTITY_D46_ROOTCTL_MISSING`. The sequence route was
  `D52_RNDIS_RUNTIME_SEQUENCE_CURRENT_RUNTIME_STILL_D46`; its local evidence
  audit reported `runtime_status=D52_RUNTIME_IDENTITY_CURRENT_RUNTIME_STILL_D46`,
  `route_status=HARDWARE_EVIDENCE_AUDIT_RECORDED_NO_AUTOMATIC_BASELINE_PROMOTION`,
  and `failures=0`. Reports:
  `logs/downstream-d52-rndis-runtime-readonly-sequence-20260709-205747.redacted.txt`
  and
  `logs/downstream-d52-rndis-runtime-readonly-sequence-audit-20260709-205747.txt`.
  The 2026-07-09 21:25:56 UTC D-v52 bootloader fastboot read-only preflight
  then waited 120 seconds and timed out with
  `WAIT_TIMEOUT_NO_BOOTLOADER_FASTBOOT_DEVICE`; no fastboot getvar validation,
  rootfs write, RAM boot, reboot, erase, format, or partition write followed.
  Report:
  `logs/downstream-v52-d50-service-foundation-bootloader-preflight-20260709-212556.txt`.
  The 2026-07-10 03:31:44 UTC D-v52 bootloader read-only preflight then passed
  with `product=lmi`, `unlocked=yes`, `is-userspace=no`, visible userdata
  metadata, matching boot/rootfs hashes, and `failures=0`. It ran only the
  staged plan, rootfs dry-run, ramboot dry-run, and readiness audit; no rootfs
  write, RAM boot, reboot, erase, format, or partition write followed. Report:
  `logs/downstream-v52-d50-service-foundation-bootloader-preflight-20260710-033144.txt`.
  After strict D-v52/D-v46/TWRP artifact, recovery, device, capacity, and battery
  gates passed, the 2026-07-10 04:10 UTC D-v52 userdata action sent both sparse
  chunks and fastboot reported `OKAY` for both writes, finishing in 57.067
  seconds. The immediate post-write `getvar` timed out; a delayed raw retry
  reported `FAILED (Write to device failed (no link))` while Windows PnP still
  showed `Android Bootloader Interface`. Treat this as
  `D52_USERDATA_WRITE_COMPLETED_POSTVERIFY_PENDING`: do not repeat the userdata
  write, boot, or reboot. Keep the phone on the fastboot screen, reconnect only
  the USB cable, then rerun the strict read-only post-write gate. Reports:
  `logs/downstream-d52-userdata-write-20260710-0410.txt` and
  `logs/downstream-d52-userdata-postwrite-preflight-20260710-0412.txt`.
  After the USB cable reconnect, the 2026-07-10 04:17:25 UTC strict post-write
  preflight passed with `product=lmi`, `unlocked=yes`, `is-userspace=no`,
  `userdata_type=f2fs`, battery voltage `4153` mV, and
  `route_status=D52_USERDATA_PREFLIGHT_PASSED_NO_WRITE`. This closes the
  post-write bootloader transport check: do not repeat the completed userdata
  write. No RAM boot, reboot, erase, format, or partition write followed.
  Report: `logs/downstream-d52-userdata-postwrite-preflight-latest.txt`.
  The 2026-07-10 04:30:55 UTC strict D-v52 RAM-only wrapper local audit then
  verified boot size `52924416` and SHA-256
  `29a75f5f1d5af2a3999ac11bd9c87293d1c64425f39664f5cc4d05ffb13ce4f3`,
  reporting `D52_RAM_BOOT_LOCAL_AUDIT_PASSED`. It did not invoke fastboot or
  touch the device. Report:
  `logs/downstream-d52-ram-boot-local-audit-latest.txt`.
  The 2026-07-10 04:36:54 UTC RAM-only wrapper read-only preflight then passed
  with `product=lmi`, `unlocked=yes`, `is-userspace=no`, battery voltage `4169`
  mV, `battery-soc-ok=yes`, and
  `route_status=D52_RAM_BOOT_PREFLIGHT_PASSED_NO_BOOT`. No RAM boot or write was
  executed. Report: `logs/downstream-d52-ram-boot-preflight-latest.txt`.
  After fresh exact approval, the 2026-07-10 06:21:38 UTC strict RAM-only
  action reverified the same D-v52 boot size and SHA-256, `product=lmi`,
  `unlocked=yes`, `is-userspace=no`, battery voltage `4284` mV, and
  `battery-soc-ok=yes`. Fastboot reported `OKAY` for both sending and booting
  the fixed image, ending with `result=RAM_BOOT_ACCEPTED` and
  `route_status=D52_RAM_BOOT_ACCEPTED_MANUAL_RUNTIME_VERIFICATION_REQUIRED`.
  No partition was written. Report:
  `logs/downstream-d52-ram-boot-boot-20260710-062138382.txt`.
  The 2026-07-10 06:22:21 UTC host-only PnP check then found the pmOS USB
  composite and Remote NDIS devices with `VID_0525&PID_A4A2`, and the 06:22:50
  UTC host-side connectivity probe found ICMP and TCP 22 reachable while TCP
  23 was closed. The resulting route is
  `RNDIS_CONNECTIVITY_SSH22_REACHABLE_REMOTE_PREFLIGHT_ELIGIBLE`. Reports:
  `logs/downstream-d52-windows-usb-pnp-readonly-post-ramboot-latest.redacted.txt`
  and `logs/downstream-d52-rndis-connectivity-post-ramboot-latest.redacted.txt`.
  The operator reported the physical panel was black after this RAM boot. This
  observation is recorded but is not yet classified as successful display
  takeover, backlight-off, or a display regression.
  A local rootfs-image check found no pre-generated ED25519 host public key;
  preserve the global SSH known_hosts file and use the dedicated pinned-key
  wrapper for the next separately approved read-only runtime identity check.
  A separately approved pinned-key runtime identity invocation did not produce
  a new 06:xx report because the host tool permission review timed out. Do not
  treat that invocation as current runtime evidence. The existing 04:52 D-v52
  identity report predates this 06:21 RAM boot and cannot validate the current
  runtime instance.
  After renewed approval, the 2026-07-10 07:45:36 UTC pinned-key retry
  succeeded against the current RAM-boot instance. It recorded
  `device_pkg_version=device-xiaomi-lmi-1-r113`, a matching D-v52 cmdline UUID,
  executable rootctl/display-probe paths, the rootctl sudoers file, complete
  target gate tokens, and
  `route_status=D52_RUNTIME_IDENTITY_D52_ROOTCTL_READY`. The enclosing sequence
  reported `D52_RNDIS_RUNTIME_SEQUENCE_D52_ROOTCTL_READY_REVIEW`; its local
  redacted evidence audit had `warnings=0`, `failures=0`, and
  `runtime_status=D52_RUNTIME_IDENTITY_READY_REQUIRES_REVIEW`. No sudo/rootctl
  command or state change was executed. Reports:
  `logs/downstream-d52-runtime-identity-readonly-20260710-074533.redacted.txt`,
  `logs/downstream-d52-rndis-runtime-readonly-sequence-20260710-074533.redacted.txt`,
  and
  `logs/downstream-d52-rndis-runtime-readonly-sequence-audit-20260710-074533.txt`.
  After fresh approval, the 2026-07-10 07:49 UTC pinned-key passive display
  batch completed with `DISPLAY_PASSIVE_STATUS_RECORDED` and
  `DISPLAY_BACKLIGHT_TOPOLOGY_RECORDED`. DSI-1 is connected and exposes the
  preferred `1080x2400x60x184345cmd` mode, while sysfs reports
  `enabled=disabled`; modetest reports CRTC 129 with `fb=0`; `/proc/fb` is
  absent; and no active userspace KMS client was observed. The backlight has
  requested `brightness=536` but `actual_brightness=0`; `bl_power=0` records an
  unblank request under the Linux backlight ABI, not proof that the hardware is
  independently powered off.
  Kernel evidence shows the panel bound successfully and continuous splash was
  enabled during probe. Together with the operator's black-screen observation,
  this points to no active userspace scanout with zero actual backlight output,
  rather than a missing DSI panel. No active KMS client or
  state-changing command was run. Reports:
  `logs/downstream-v52-display-passive-status-post-ramboot-latest.redacted.txt`
  and
  `logs/downstream-v52-display-backlight-topology-post-ramboot-latest.redacted.txt`.
  After an exact approval, the hardened direct
  `scripts/95_display_active_kmscube_snapshot.sh` ran at 2026-07-10 10:04 UTC
  through the pinned host key. It opened `card0` and `renderD128`, but Mesa
  selected `llvmpipe`, ZINK could not create a Vulkan instance, and kmscube
  exited `254` with `failed to set mode: No such file or directory`. During the
  client DSI remained disabled, `actual_brightness=0`, and display interrupt
  counters did not advance. The script reaped the client and recorded
  `DISPLAY_ACTIVE_KMSCUBE_CLIENT_FAILED_DURING_STATE_CAPTURE`; it did not write
  sysfs, services, or partitions. Redacted evidence and local audit are
  `logs/downstream-v52-display-active-kmscube-snapshot-post-ramboot-20260710-100401.redacted.txt`
  and `logs/downstream-v52-display-active-kmscube-snapshot-audit-20260710-100401.txt`.
  A local static audit of the same D-v52 userdata image confirms `libdrm` with
  its Freedreno library plus `msm_dri.so` and `kgsl_dri.so`; it does not contain
  `/usr/share/vulkan/icd.d`, and the device package does not directly depend on
  `mesa-vulkan-freedreno`. This makes the Vulkan/ZINK fallback a concrete
  packaging gap, but not a sufficient explanation for KMS modeset `ENOENT`:
  D-v46 also emitted a llvmpipe/ZINK warning while enabling DSI. The rootfs
  verifier now records a concise graphics package and DRI/ICD inventory for
  future candidate images.
  The 2026-07-09 21:35:50 UTC post-timeout Windows USB/PnP host-only check
  still showed a USB composite device and Remote NDIS device with
  `VID_0525&PID_A4A2`, routing to
  `WINDOWS_USB_PNP_POSTMARKETOS_RNDIS_VISIBLE_REVIEW`; it ran only a
  Win32_PnPEntity query and did not run adb, fastboot, shell, getvar, driver
  changes, reboot, service changes, or partition writes. This means the latest
  host-visible state remains pmOS/RNDIS, not bootloader fastboot.
- For manual SSH sessions where the IME candidate window covers the active
  input line, use `scripts/88_lmi_ssh_ime_shell.sh` instead of raw SSH; run
  `scripts/88_lmi_ssh_ime_shell.sh --dry-run --reserved-rows N` first to check
  the local margin plan without opening SSH or sending terminal control
  sequences. The real shell helper only reserves local terminal rows and does
  not run sudo, services, reboot, fastboot, adb, display takeover, Wi-Fi
  trigger, playback, recording, or partition writes. For remote sudo/rootctl
  UX, use `scripts/73_lmi_remote_rootctl.sh --dry-run <command...>` to preview
  the delegated command without SSH, then `scripts/73_lmi_remote_rootctl.sh
  --preflight` before a real rootctl command; the preflight checks SSH
  reachability plus remote `sudo`/`lmi-rootctl` presence without executing
  `sudo -n` or a rootctl subcommand.
- Current source of truth: this file plus `docs/tracks/downstream.md`.
  The execution cadence and experiment-selection rules are in
  `notes/agent-bringup-operating-loop-2026-07-10.md`.
  `D-v52` is runtime-identity verified for the current RAM-boot instance but is
  not yet a Wi-Fi or display working baseline. The D-v52 bootloader read-only
  preflight passed against the intentionally selected bootloader-fastboot
  device. The D-v52 `userdata` rootfs write has
  completed, and the strict post-write fastboot verification passed after the
  USB cable reconnect. Do not repeat the userdata write. The temporary D-v52
  RAM boot has now been accepted, the new pmOS RNDIS runtime exposes SSH on
  TCP 22, and the pinned-key identity check proves the current runtime is the
  expected D-v52 package/rootctl image. D-v52 is runtime-identity verified but
  is not yet a Wi-Fi or display working baseline. For future RNDIS read-only
  identity rechecks, use
  `scripts/downstream_d52_rndis_runtime_readonly_sequence.ps1` with
  `D52_RNDIS_RUNTIME_READONLY_CONFIRM=d52-rndis-runtime-readonly-xiaomi-lmi`;
  the split wrappers remain
  `scripts/downstream_d52_rndis_connectivity_readonly.ps1` and
  `scripts/downstream_d52_runtime_identity_readonly.sh`. Remote rootctl
  preflight remains a wrapper UX presence check, not a D-v52 validation.
  The sequence now runs `scripts/89_audit_downstream_hardware_evidence.sh`
  locally against its own redacted report; review that audit before changing any
  D-v52 baseline label. Treat the sequence exit code as transport/audit
  execution status only; the D-v52 validation result is in `route_status` and
  `evidence_audit_report`.
  D-v52 execution boundaries remain in
  `notes/downstream-d52-service-foundation-hardware-window-runbook-2026-07-10.md`;
  the immediate device-action approval packet is
  `notes/downstream-next-device-action-2026-07-10.md`; its shorter operator
  entry is `scripts/downstream_next_device_action.sh` with per-action exact
  `LMI_NEXT_DEVICE_ACTION_CONFIRM` tokens. P2 candidate order
  remains in `notes/downstream-p2-next-candidate-review-2026-07-09.md`.

## Update: 2026-06-23

- v27 persistent boot is installed and verified.
- `userdata` contains the working postmarketOS image. Rootfs discovery and
  mount are working: `/dev/loop0p2` mounts as `/`, and `/dev/loop0p1` mounts as
  `/boot`.
- USB networking works on Windows as RNDIS (`0525:a4a2 POSTMARKETOS`); SSH is
  reachable at `172.16.42.1:22`.
- Display kernel bring-up is present (`/dev/dri/card0`, DSI panel connected,
  Adreno650v3), but userspace has not taken over the panel, so the screen still
  shows the Redmi logo.
- Audio/mic, Wi-Fi, and Bluetooth are the next main blockers: ALSA exposes no
  soundcard, Wi-Fi exposes no wireless interface, and Bluetooth is rfkill
  soft-blocked.
- Raw logs remain local-only. Use `logs/*.redacted.txt` for published evidence.

签名：codex_ian | 2026-05-28 12:39:41 +10:00 Australia/Sydney

## What Was Extracted

From WSL:

- `/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream/device-xiaomi-lmi`
- `/home/microstar/.local/var/pmbootstrap/cache_git/pmaports/device/downstream/linux-xiaomi-lmi`
- `/home/microstar/.config/pmbootstrap_v3.cfg`
- `/home/microstar/.local/var/pmbootstrap/workdir.cfg`
- `/home/microstar/boot.img`

From Windows downloads:

- `C:\Users\microstar\Downloads\[REC_BOOT]3.7.1_12-RedmiK30Pro-POCOF2Pro_v9.0_A15-lmi-skkk.img`
- `C:\Users\microstar\Downloads\[REC_BOOT]3.6.2_12-RedmiK30Pro-RedmiPOCOF2Pro_v5.6_A12-lmi-skkk_ef1ce3b4.zip`

## WSL2 Check

- WSL default version: 2.
- Default distro: `Ubuntu-22.04`.
- Kernel observed: `6.6.87.2-microsoft-standard-WSL2`.
- Ubuntu observed: `22.04.5 LTS`.
- Disk available under WSL root: about 939 GB free.
- Memory visible to WSL: about 15 GiB RAM, 4 GiB swap.
- pmbootstrap observed: `3.10.1`.

Tools found in WSL:

- `git`
- `python3`
- `pip3`
- `gcc`
- `make`
- `pmbootstrap`

Tools not found in the WSL `PATH` during the check:

- `clang`
- `dtc`
- `mkbootimg`
- `fastboot`
- `adb`
- `repo`
- `unzip`

Windows tools found:

- `adb.exe`: `C:\Program Files\platform-tools\adb.exe`, version `37.0.0-14910828`
- `fastboot.exe`: `C:\Program Files\platform-tools\fastboot.exe`, version `37.0.0-14910828`

## Historical Risk Assessment (2026-06-23)

The project has enough material to start an lmi postmarketOS/downstream port
audit, but not enough to flash a Linux build safely.

Main gaps:

- Need to identify the intended lmi kernel source repository.
- Need to identify the exact kernel commit.
- Need to locate or generate `config-xiaomi-lmi.aarch64`.
- Need to confirm whether `artifacts/images/boot.img` is a bootable Linux image,
  Android boot image, or previous pmbootstrap output.
- Need to collect live phone data through USB.

## Historical Next Confirmation With ian (2026-06-23)

When the phone is connected, run:

```bat
scripts\03_check_phone_usb.bat
```

Then confirm:

- Whether the phone is in Android/LineageOS mode or fastboot mode.
- Whether the phone appears under `adb devices` or `fastboot devices`.
- Whether `logs\phone-adb.txt` and/or `logs\phone-fastboot.txt` were produced.
- Whether `artifacts/images/boot.img` came from pmbootstrap or from another source.

## Update: D71 GUI Bring-Up (2026-07-12)

- The current minimal UI confirms that the screen and touch hardware/input path
  are usable. The remaining limitation is userspace: the on-screen keyboard is
  temporarily unavailable, so text entry is limited to the validated terminal
  and external/input path.

- D71 `userdata` was written with the verified image; the boot image was RAM
  booted only. No protected Android partition was written.
- The D71 rootfs (`device-xiaomi-lmi 1-r131`) includes `lmi-weston` in the
  default OpenRC runlevel after `lmi-seatd`.
- Pinned SSH verification found `lmi-weston`, `openvt`, and Weston alive, with
  Weston owning `tty7`; DSI-1 is connected and the wrapper recorded the
  CRTC 129 / plane 58 splash release.
- The operator physically confirmed that the panel displayed the GUI.
- A second RAM-boot experiment is pending to prove the same automatic takeover
  on an independent D71 start. Local CLI packaging, brightness, touch,
  rotation, suspend/resume, audio, and Bluetooth remain separate work items.
