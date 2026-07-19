import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from scripts.lmi_p1.common import GateError
from scripts.lmi_p1.pmaports import prepare_pmaports


REPOSITORY = Path(__file__).resolve().parents[2]
PATCH = (
    REPOSITORY
    / "patches/postmarketos-initramfs/0001-lmi-handle-4096-sector-loop-partitions.patch"
)

APKBUILD = """\
# Co-Maintainer: Clayton Craft <clayton@craftyguy.net>
maintainer="Casey Connolly <kcxt@postmarketos.org>"
pkgname=postmarketos-initramfs
pkgver=3.12.0
pkgrel=0
pkgdesc="Base files for the postmarketOS initramfs / initramfs-extra"
url="https://postmarketos.org"
options="!check"  # no tests
sha512sums="
69852928464f01757e2f473bd2c2e7ecb4132ecf3e26bdec95932e928dfe9042f59316e0a509fd38bcda88e24dd94bf33e8a88118b5adbec7023d1c13da12f59  00-initramfs-base.files
6d91270b96ce0c745391174201dde63b43a73ae6456c2e1138046beef3548580588fedbeae7cc914079162e99343b45d82c6e6a7ee1d03829aae7697ae52f575  00-initramfs-extra-base.files
bd72e8b6345a46ec13516c64d78d4fa1a9a18a8db9ab04aac605f9708629453dc65b6fbccd96b58eeb1ea68102ddbcae9dc6b369255c6c6c1fb18ce0bd43ec79  init.sh
1c1518e903a1d08fe6eed85534fe84d12f43bb5fbfbca97de8aed78f30ddf96ebc2391d39eab02d8689549ca1367f422182995a26e5fda284afea024c433b1b9  init_functions.sh
7aa82d5e2907470d667612643d98371dff27b2650051f8c568ab43d1b97677362c3e6fbd442474086d681ea7c0cfbcaf269d3eef2d2dc3ff4ebf17c786b82148  init_2nd.sh
4eca94327274511011967cde1f663b00b1a8182f7dddc3ba19d5c1f0ac094087a154a250c140ca70ac75a2e7c5bb70b03e94fa5eca63a5393efc4a23d025e1c3  init_functions_2nd.sh
675e7d5bee39b2df7d322117f8dcaccc274d61beaf4d50ead19bbf2109446d64b1c0aa0c5b4f9846eb6c1c403418f28f6364eff4537ba41120fbfcbc484b7da7  mdev.conf
"
"""

INIT_FUNCTIONS = """\
setup_dynamic_partitions() {
\tfor partition in fixture; do
\t\t:
\tdone
}

mount_subpartitions() {
\t# skip if ran already (unmerged -extra)
\tif [ -n "$PMOS_ROOT" ] && [ -n "$PMOS_BOOT" ]; then
\t\treturn
\tfi
\ttry_parts="/dev/disk/by-partlabel/userdata /dev/disk/by-partlabel/system* /dev/mapper/system*"
\tandroid_parts=""
\tfor x in $try_parts; do
\t\t[ -e "$x" ] && android_parts="$android_parts $x"
\tdone

\tlocal losetup_args="--show -Pf --direct-io=on"
\tif [ -n "$deviceinfo_rootfs_image_sector_size" ]; then
\t\tlosetup_args="$losetup_args --sector-size $deviceinfo_rootfs_image_sector_size"
\tfi
\tattempt_start=$(get_uptime_seconds)
\twait_seconds=10
\techo "Trying to mount subpartitions for $wait_seconds seconds..."

\t# Subpartition init uses losetup, so make sure the loop module is loaded.
\tmodprobe loop 2>/dev/null || true

\tfind_root_partition
\twhile [ -z "$PMOS_ROOT" ]; do
\t\tpartitions="$android_parts $(grep -v "loop\\|ram" < /proc/diskstats |\\
\t\t\tsed 's/\\(\\s\\+[0-9]\\+\\)\\+\\s\\+//;s/ .*//;s/^/\\/dev\\//')"
\t\tfor partition in $partitions; do
\t\t\t# Subpartitions, if there are any, are counted with fdisk because there doesn't
\t\t\t# seem to be a better way to do this without adding more dependencies to the 1st
\t\t\t# stage initramfs. fdisk's output differs if it's reading a GPT or MBR partition
\t\t\t# table, so this regex needs to account for both, e.g.:
\t\t\t#  GPT:
\t\t\t#   1     2048   499711  243M primary
\t\t\t#  MBR:
\t\t\t# /dev/mmcblk0p62p1 *  4,4,1   979,210,2   2048  499711   97664  243M 83 Linux
\t\t\tlocal part_count
\t\t\tpart_count="$(fdisk -l "$partition" 2>/dev/null | grep -cE '^ +[0-9]|^'"$partition")"
\t\t\t# It's probably the right "disk" if it has 2 partitions on it.
\t\t\tif [ "$part_count" -eq 2 ]; then
\t\t\t\techo "Mount subpartitions of $partition"
\t\t\t\tSUBPARTITION_DEV="$partition"
\t\t\t\t# shellcheck disable=SC2086
\t\t\t\tSUBPARTITION_LOOP="$(losetup $losetup_args "$partition")"
\t\t\t\tif [ -z "$SUBPARTITION_LOOP" ]; then
\t\t\t\t\techo "WARNING: failed to create loop device for $partition"
\t\t\t\t\tSUBPARTITION_DEV=""
\t\t\t\t\tcontinue
\t\t\t\tfi
\t\t\t\t# Ensure that this was the *correct* subpartition
\t\t\t\t# Some devices have mmc partitions that appear to have
\t\t\t\t# subpartitions, but aren't our subpartition.
\t\t\t\tfind_root_partition
\t\t\t\tif [ -n "$PMOS_ROOT" ]; then
\t\t\t\t\tbreak
\t\t\t\tfi
\t\t\t\t[ -n "$SUBPARTITION_LOOP" ] && losetup -d "$SUBPARTITION_LOOP"
\t\t\t\tSUBPARTITION_DEV=""
\t\t\t\tSUBPARTITION_LOOP=""
\t\t\tfi
\t\tdone
\t\treturn
\tdone
}
"""

INIT_2ND = """\
#!/bin/busybox ash
# cleanup after ourselves
# switch_root does a mount --move , keeping stale filesystems like devtmpfs
# with /dev/log in there.
rm /dev/log 2>/dev/null || true

# shellcheck disable=SC2093
exec switch_root /sysroot "$init"

echo "$LOG_PREFIX ERROR: switch_root failed!" > /dev/kmsg
"""


class PmaportsTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.source = self.root / "source"
        self.destination = self.root / "staged"
        self.overlay = self.root / "overlay"
        self.commit = self.make_source()
        self.make_overlay()

    @staticmethod
    def git(repository, *args):
        return subprocess.run(
            ["git", "-C", str(repository), *args],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    @staticmethod
    def worktree_snapshot(root):
        snapshot = {}
        for path in sorted(root.rglob("*")):
            relative = path.relative_to(root)
            if relative.parts[:1] == (".git",):
                continue
            if path.is_symlink():
                snapshot[relative.as_posix()] = ("link", os.readlink(path))
            elif path.is_file():
                snapshot[relative.as_posix()] = ("file", path.read_bytes())
            else:
                snapshot[relative.as_posix()] = ("directory",)
        return snapshot

    def make_source(self, *, collision=False):
        package = self.source / "main/postmarketos-initramfs"
        package.mkdir(parents=True)
        (self.source / "device/downstream").mkdir(parents=True)
        (self.source / "device/downstream/README.md").write_text(
            "fixture\n", encoding="utf-8"
        )
        (self.source / ".gitignore").write_text(
            "ignored-stage.txt\n", encoding="utf-8"
        )
        if collision:
            collision_dir = self.source / "device/downstream/device-xiaomi-lmi"
            collision_dir.mkdir()
            (collision_dir / "APKBUILD").write_text("collision\n", encoding="utf-8")
        (package / "APKBUILD").write_text(APKBUILD, encoding="utf-8")
        (package / "init_functions.sh").write_text(
            INIT_FUNCTIONS, encoding="utf-8"
        )
        (package / "init_2nd.sh").write_text(INIT_2ND, encoding="utf-8")
        subprocess.run(
            ["git", "init", "-q", str(self.source)],
            check=True,
            capture_output=True,
            text=True,
        )
        self.git(self.source, "config", "user.name", "Fixture")
        self.git(self.source, "config", "user.email", "fixture@example.invalid")
        self.git(self.source, "add", ".")
        self.git(self.source, "commit", "-q", "-m", "fixture")
        return self.git(self.source, "rev-parse", "HEAD")

    def make_overlay(self):
        for name, payload in (
            ("device-xiaomi-lmi", "device overlay\n"),
            ("linux-xiaomi-lmi", "kernel overlay\n"),
        ):
            package = self.overlay / name
            package.mkdir(parents=True)
            (package / "APKBUILD").write_text(payload, encoding="utf-8")

    def prepare(self, **overrides):
        arguments = {
            "source": self.source,
            "destination": self.destination,
            "commit": self.commit,
            "overlay": self.overlay,
            "patch": PATCH,
        }
        arguments.update(overrides)
        return prepare_pmaports(**arguments)

    def staged_initramfs_paths(self):
        self.prepare()
        package = self.destination / "main/postmarketos-initramfs"
        return (
            package / "APKBUILD",
            package / "init_functions.sh",
            package / "init_2nd.sh",
        )

    def test_stages_exact_commit_overlay_patch_and_manifest(self):
        manifest = self.prepare()
        package = self.destination / "main/postmarketos-initramfs"
        apkbuild = (package / "APKBUILD").read_text(encoding="utf-8")
        init_functions = (package / "init_functions.sh").read_text(encoding="utf-8")
        init_2nd = (package / "init_2nd.sh").read_text(encoding="utf-8")

        self.assertIn("pkgver=3.12.0\npkgrel=1", apkbuild)
        self.assertIn(
            'fdisk -b "$deviceinfo_rootfs_image_sector_size"', init_functions
        )
        self.assertIn("lmi_populate_block_devs()", init_functions)
        self.assertIn('mknod "/dev/$name" b', init_functions)
        self.assertIn('loop_part="/dev/${loop_name}p2"', init_functions)
        self.assertIn(
            'echo add > "/sys/class/block/${loop_name}p2/uevent"',
            init_functions,
        )
        self.assertIn("transition=switch_root-ready", init_2nd)
        self.assertEqual(manifest["commit"], self.commit)
        self.assertEqual(self.git(self.destination, "rev-parse", "HEAD"), self.commit)
        self.assertEqual(
            self.git(self.destination, "rev-parse", "--abbrev-ref", "HEAD"), "HEAD"
        )

        recorded = json.loads(
            (self.destination / ".lmi-p1-stage.json").read_text(encoding="utf-8")
        )
        self.assertEqual(recorded, manifest)
        expected_files = {
            "device/downstream/device-xiaomi-lmi/APKBUILD",
            "device/downstream/linux-xiaomi-lmi/APKBUILD",
            "main/postmarketos-initramfs/APKBUILD",
            "main/postmarketos-initramfs/init_2nd.sh",
            "main/postmarketos-initramfs/init_functions.sh",
        }
        self.assertEqual(set(manifest) - {"commit"}, expected_files)
        for relative in expected_files:
            self.assertEqual(
                manifest[relative],
                hashlib.sha256((self.destination / relative).read_bytes()).hexdigest(),
            )

    def test_block_population_precedes_partition_candidate_evaluation(self):
        _, init_functions_path, _ = self.staged_initramfs_paths()
        init_functions = init_functions_path.read_text(encoding="utf-8")
        mount = init_functions[init_functions.index("mount_subpartitions() {") :]
        significant = [
            line.strip()
            for line in mount.splitlines()[1:]
            if line.strip() and not line.lstrip().startswith("#")
        ]

        self.assertEqual(
            significant[0], "lmi_populate_block_devs 2>/dev/null || true"
        )
        self.assertLess(
            mount.index("lmi_populate_block_devs 2>/dev/null || true"),
            mount.index('try_parts="/dev/disk/by-partlabel/userdata'),
        )

    def test_fdisk_sector_size_branches_execute_exact_argv(self):
        _, init_functions_path, _ = self.staged_initramfs_paths()
        init_functions = init_functions_path.read_text(encoding="utf-8")
        branch_start = init_functions.index(
            '\t\t\tif [ -n "$deviceinfo_rootfs_image_sector_size" ]; then'
        )
        branch_end = init_functions.index("\n\t\t\tfi", branch_start) + len(
            "\n\t\t\tfi"
        )
        branch = init_functions[branch_start:branch_end]
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fdisk_log = self.root / "fdisk-argv"
        fake_fdisk = fake_bin / "fdisk"
        fake_fdisk.write_text(
            "#!/usr/bin/env bash\n"
            "printf '%s\\n' \"$@\" > \"$FDISK_LOG\"\n"
            "printf ' 1\\n 2\\n'\n",
            encoding="utf-8",
        )
        fake_fdisk.chmod(0o755)
        environment = dict(os.environ)
        environment["PATH"] = f"{fake_bin}:{environment['PATH']}"
        environment["FDISK_LOG"] = str(fdisk_log)

        def run_branch(sector_size):
            result = subprocess.run(
                [
                    "bash",
                    "-eu",
                    "-c",
                    "partition=/dev/fixture\n"
                    f"deviceinfo_rootfs_image_sector_size={sector_size!r}\n"
                    f"{branch}\n"
                    "printf '%s\\n' \"$part_count\"",
                ],
                env=environment,
                capture_output=True,
                text=True,
                check=True,
            )
            self.assertEqual(result.stdout, "2\n")
            return fdisk_log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(run_branch(""), ["-l", "/dev/fixture"])
        self.assertEqual(
            run_branch("4096"), ["-b", "4096", "-l", "/dev/fixture"]
        )

    def test_loop_retry_is_exact_and_cleanup_precedes_continue(self):
        _, init_functions_path, _ = self.staged_initramfs_paths()
        init_functions = init_functions_path.read_text(encoding="utf-8")
        retry_values = re.findall(
            r"for wait_try in ([^;]+); do", init_functions
        )

        self.assertEqual(retry_values, ["1 2 3 4 5"])
        cleanup_start = init_functions.index('if [ ! -b "$loop_part" ]; then')
        cleanup_end = init_functions.index("\n\t\t\t\tfi", cleanup_start)
        cleanup = init_functions[cleanup_start:cleanup_end]
        continue_index = cleanup.index("continue")
        for required in (
            'losetup -d "$SUBPARTITION_LOOP"',
            'SUBPARTITION_DEV=""',
            'SUBPARTITION_LOOP=""',
        ):
            self.assertLess(cleanup.index(required), continue_index)
        self.assertEqual(cleanup.count("continue"), 1)

    def test_transition_write_move_sync_immediately_precedes_switch_root(self):
        _, _, init_2nd_path = self.staged_initramfs_paths()
        init_2nd = init_2nd_path.read_text(encoding="utf-8")
        significant = [
            line.strip()
            for line in init_2nd.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        write_index = significant.index(
            "} > /sysroot/var/lib/lmi-p1/initramfs-transition.new"
        )
        move_index = significant.index(
            "mv /sysroot/var/lib/lmi-p1/initramfs-transition.new " + "\\"
        )
        sync_index = significant.index("sync")
        exec_index = significant.index('exec switch_root /sysroot "$init"')

        self.assertEqual(move_index, write_index + 1)
        self.assertEqual(
            significant[move_index + 1],
            "/sysroot/var/lib/lmi-p1/initramfs-transition",
        )
        self.assertEqual(sync_index, move_index + 2)
        self.assertEqual(exec_index, sync_index + 1)

    def test_applied_initramfs_shell_files_parse_with_bash(self):
        _, init_functions_path, init_2nd_path = self.staged_initramfs_paths()

        subprocess.run(
            ["bash", "-n", str(init_functions_path), str(init_2nd_path)],
            check=True,
            capture_output=True,
            text=True,
        )

    def test_wrong_source_head_fails_closed(self):
        with self.assertRaisesRegex(GateError, "source HEAD"):
            self.prepare(commit="0" * 40)
        self.assertFalse(self.destination.exists())

    def test_tracked_source_modification_fails_closed(self):
        package = self.source / "main/postmarketos-initramfs/APKBUILD"
        package.write_text(APKBUILD + "dirty=true\n", encoding="utf-8")

        with self.assertRaisesRegex(GateError, "tracked modifications"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_non_empty_output_path_fails_closed(self):
        self.destination.mkdir()
        (self.destination / "unrelated").write_text("keep\n", encoding="utf-8")

        with self.assertRaisesRegex(GateError, "not empty"):
            self.prepare()
        self.assertEqual(
            (self.destination / "unrelated").read_text(encoding="utf-8"), "keep\n"
        )

    def test_destination_inside_source_fails_before_mutating_source(self):
        destination = self.source / "generated/stage"
        before = self.worktree_snapshot(self.source)

        with self.assertRaisesRegex(GateError, "path overlap"):
            self.prepare(destination=destination)

        self.assertEqual(self.worktree_snapshot(self.source), before)
        self.assertFalse(destination.parent.exists())

    def test_destination_inside_overlay_fails_before_mutating_overlay(self):
        destination = self.overlay / "generated/stage"
        before = self.worktree_snapshot(self.overlay)

        with self.assertRaisesRegex(GateError, "path overlap"):
            self.prepare(destination=destination)

        self.assertEqual(self.worktree_snapshot(self.overlay), before)
        self.assertFalse(destination.parent.exists())

    def test_equal_and_ancestor_destination_overlaps_fail_closed(self):
        for label, destination in (
            ("equal source", self.source),
            ("equal overlay", self.overlay),
            ("equal package", self.overlay / "device-xiaomi-lmi"),
            ("ancestor", self.root),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(GateError, "path overlap"):
                    self.prepare(destination=destination)

    def test_source_and_overlay_overlap_fails_closed(self):
        nested_overlay = self.source / "local-overlays"
        self.overlay.rename(nested_overlay)
        before = self.worktree_snapshot(self.source)

        with self.assertRaisesRegex(GateError, "path overlap"):
            self.prepare(overlay=nested_overlay)

        self.assertEqual(self.worktree_snapshot(self.source), before)
        self.assertFalse(self.destination.exists())

    def test_source_root_symlink_is_rejected_without_mutation(self):
        source_link = self.root / "source-link"
        os.symlink(self.source, source_link, target_is_directory=True)
        before = self.worktree_snapshot(self.source)

        with self.assertRaisesRegex(GateError, "source root must not be a symlink"):
            self.prepare(source=source_link)

        self.assertEqual(self.worktree_snapshot(self.source), before)
        self.assertFalse(self.destination.exists())

    def test_reusing_populated_destination_fails_closed(self):
        self.prepare()

        with self.assertRaisesRegex(GateError, "not empty"):
            self.prepare()

    def test_overlay_collision_fails_closed(self):
        collision_root = self.root / "collision-source"
        original_source = self.source
        self.source = collision_root
        try:
            collision_commit = self.make_source(collision=True)
        finally:
            self.source = original_source

        with self.assertRaisesRegex(GateError, "overlay destination exists"):
            self.prepare(source=collision_root, commit=collision_commit)

    def test_overlay_symlink_cannot_escape_overlay_tree(self):
        outside = self.root / "outside"
        outside.write_text("secret\n", encoding="utf-8")
        os.symlink(outside, self.overlay / "device-xiaomi-lmi/escape")

        with self.assertRaisesRegex(GateError, "symlink escapes"):
            self.prepare()

    def test_patch_cannot_modify_an_overlaid_file(self):
        unexpected_patch = self.root / "unexpected-overlay-change.patch"
        unexpected_patch.write_text(
            PATCH.read_text(encoding="utf-8")
            + """\
diff --git a/device/downstream/device-xiaomi-lmi/APKBUILD b/device/downstream/device-xiaomi-lmi/APKBUILD
--- a/device/downstream/device-xiaomi-lmi/APKBUILD
+++ b/device/downstream/device-xiaomi-lmi/APKBUILD
@@ -1 +1 @@
-device overlay
+tampered overlay
""",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(GateError, "overlay file changed"):
            self.prepare(patch=unexpected_patch)

    def test_patch_created_ignored_file_is_inventoried_and_rejected(self):
        ignored_patch = self.root / "unexpected-ignored-file.patch"
        ignored_patch.write_text(
            PATCH.read_text(encoding="utf-8")
            + """\
diff --git a/ignored-stage.txt b/ignored-stage.txt
new file mode 100644
--- /dev/null
+++ b/ignored-stage.txt
@@ -0,0 +1 @@
+ignored payload
""",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(GateError, "unexpected untracked file"):
            self.prepare(patch=ignored_patch)

        self.assertFalse((self.destination / ".lmi-p1-stage.json").exists())

    def test_cli_stages_pmaports_with_explicit_inputs(self):
        result = subprocess.run(
            [
                sys.executable,
                str(REPOSITORY / "scripts/lmi_p1_cli.py"),
                "stage-pmaports",
                "--source",
                str(self.source),
                "--destination",
                str(self.destination),
                "--commit",
                self.commit,
                "--overlay",
                str(self.overlay),
                "--patch",
                str(PATCH),
            ],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["commit"], self.commit)


class PmaportsCliTests(unittest.TestCase):
    def test_cli_module_is_import_safe(self):
        result = subprocess.run(
            [sys.executable, "-c", "import scripts.lmi_p1_cli"],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_help_exposes_only_the_staging_command(self):
        result = subprocess.run(
            [sys.executable, str(REPOSITORY / "scripts/lmi_p1_cli.py"), "--help"],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("stage-pmaports", result.stdout)
        self.assertNotIn("build", result.stdout)


if __name__ == "__main__":
    unittest.main()
