# Repair Phase 15: Mount-Dispatch Source Probe (do_new_mount / vfs_get_tree)

Operator: Lucien Auregin (ian)
Date: 2026-06-23 Australia/Sydney

## Purpose

v14 proved ext4 is registered (`/proc/filesystems` lists ext4/ext2/ext3;
`CONFIG_EXT4_FS=y`) yet every block-fs `mount(2)` returns `ENOENT` without ever
reaching `mount_bdev`/`legacy_get_tree`/`ext4_fill_super`. Source reading of the
built kernel located the exact return point: `fs/super.c` `vfs_get_tree`

```c
if (fc->fs_type->fs_flags & FS_REQUIRES_DEV && !fc->source)
    return -ENOENT;       /* before fc->ops->get_tree() */
```

ext4/ext2 are `FS_REQUIRES_DEV`, so `fc->source` is empty at this point; tmpfs
(not `FS_REQUIRES_DEV`) and bind mounts are unaffected — exactly the observed
pattern. The open question is **why `fc->source` is empty** when `mount(2)` was
called with a real device path.

v15 reuses the v14 ramdisk byte-for-byte and only changes the kernel: it extends
`lmi-vfs-mount-diagnostic.patch` with three `pr_err` checkpoints in
`fs/namespace.c` `do_new_mount` (entry: fstype/name/data; pre-`vfs_get_tree`:
err + `fc->source`) and `fs/super.c` `vfs_get_tree` (entry: fs_flags + source).

## Kernel package

```text
pkgrel=3   apk=linux-xiaomi-lmi-4.19.325-r3.apk
patch regenerated via `git diff` on the extracted source (correct hunk counts).
A first v15 build failed: shell/heredoc escaping turned the in-string "\n" into a
real newline, breaking the string literal. Fixed by building the insert text with
chr(92)+"n" in a script file; rebuilt clean.
```

## Artifact

```text
file=artifacts/images/pmos-lmi-http-diagnostic-20260622-v15.img
sha256=8d8eeef413a47613f019a150d4a432f54134b7105dc6993900252486dc136bc5
artifact_size=53100544
diagnostic_ramdisk_sha256=2e8191495f3c266708790435dfb1cc8c2d1a8159af64f1ad8ba24255a39f578e  (identical to v13/v14)
reproducible=yes  syntax=ok  inspection=ok
```

## Local inspection (no phone)

```text
android_magic=ANDROID!  header_version=2  total=50.6 MiB (< 128 MiB)
LMI_VFS_DIAG_strings=18  (15 from v14 + 3 new)
new checkpoints present: do_new_mount enter / do_new_mount pre_get_tree / vfs_get_tree enter
```

## Hardware result (RAM boot, 2026-06-23, explicit approval) — ROOT CAUSE FOUND

V15 RAM-booted (OKAY, no partition written); report stable/byte-identical
(`report_size=58017`, `sha256=...`). The new checkpoints are decisive for every
block-fs mount attempt (ext2 loop0p1, ext4 loop0p2, ext4 loop1, ext4
mapper/lmi-root, ext2 loop2, ext2 ram0):

```text
do_new_mount enter      fstype=ext4 name=/dev/loop1 data=noload
do_new_mount pre_get_tree fs=ext4 name=/dev/loop1 err=0 fc_source=(null)
vfs_get_tree enter      fs=ext4 fs_flags=0x1 source=(null) root=(null)
```

Interpretation:
- `name=/dev/loop1` — the device path DOES reach `do_new_mount`.
- after `vfs_parse_fs_string(fc,"source",name,…)` + `parse_monolithic_mount_data`
  the result is `err=0` **but `fc->source` is NULL** — parsing reports success
  yet never populated the source.
- `vfs_get_tree` then hits `if (fs_flags & FS_REQUIRES_DEV && !fc->source)
  return -ENOENT;` (fs_flags=0x1 == FS_REQUIRES_DEV) and returns ENOENT before
  the fs driver. tmpfs (fs_flags without FS_REQUIRES_DEV) is unaffected, which is
  why it mounts; bind has no fc at all.

ROOT CAUSE: this downstream 4.19 fs_context backport drops the device string for
legacy block filesystems mounted via the classic `mount(2)` syscall — `fc->source`
ends up NULL even though `name` is correct and parsing returns 0. The pristine
tarball source for `vfs_parse_fs_string`/`legacy_parse_param`/`vfs_parse_fs_param`
*should* set `fc->source`; the compiled behavior does not, indicating a backport
defect. This affects ALL ext4/ext2 mounts, including the real pmOS init mounting
`pmOS_root` — hence the whole boot is blocked here, not at GPT/UUID/fs content.

## Fix (v16)

Minimal, targets exactly the proven gap — in `fs/namespace.c` `do_new_mount`,
after the parse steps and before `vfs_get_tree`:

```c
if (!err && name && !fc->source)
    fc->source = kstrdup(name, GFP_KERNEL);
```

`fc->source` is freed by `put_fs_context` via `kfree`, so a `kstrdup` allocation
is correct. v16 keeps all LMI_VFS_DIAG logging so the boot report shows the mount
proceeding into `ext4_fill_super` (or reveals the next blocker). Build + RAM boot
under separate approval; success here should allow `pmos_continue_boot` →
`switch_root`.
