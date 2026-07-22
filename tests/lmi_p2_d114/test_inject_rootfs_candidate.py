from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import tarfile
import tempfile
import unittest

from tests.lmi_p2_d114 import host_bound


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts/lmi_p2_d114/inject_rootfs_candidate.sh"
LAUNCHER = REPO / "scripts/lmi_p2_d114/launch_inject_rootfs_candidate.sh"
LOCK = REPO / "config/lmi-p2-d114/candidate-rebuild-lock.json"
RUNTIME_LOCK = REPO / "config/lmi-p2-d114/injector-runtime-lock.json"
INJECTION_POLICY_LOCK = REPO / "config/lmi-p2-d114/injection-policy-lock.json"
BUILD = REPO / "private/lmi-p1/recovery/d110-d114/p2-d114-build-20260720"
SIXROW_APK = (
    REPO
    / "private/lmi-p1/recovery/d110-d114/p2-d114-r1-sixrow-build-20260722"
    / "lmi-weston-sixrow-clients-14.0.2-r1.apk"
)

EXPECTED_DELTA_OP_PATHS = (
    "A|/etc/lmi-p2-d114",
    "A|/etc/lmi-p2-d114/greetd.toml",
    "A|/etc/lmi-p2-d114/weston.ini",
    "A|/usr/libexec/lmi-p2-d114",
    "A|/usr/libexec/lmi-p2-d114/config-lifecycle",
    "A|/usr/libexec/lmi-p2-d114/session",
    "A|/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow",
    "A|/usr/libexec/lmi-p2-d114/weston-terminal-sixrow",
    "A|/usr/share/lmi-p2-d114",
    "A|/usr/share/lmi-p2-d114/greetd.confd",
    "A|/var/lib/lmi-p2-d114",
    "A|/var/lib/lmi-p2-d114/config-v1",
    "A|/var/lib/lmi-p2-d114/greetd-confd.original",
    "A|/etc/ssh/sshd_config.d/99-lmi-public-image.conf",
    "M|/etc",
    "M|/etc/conf.d/greetd",
    "M|/etc/resolv.conf",
    "M|/etc/shadow-",
    "D|/etc/machine-id",
    "D|/home/lmi/.ssh/authorized_keys",
    "D|/var/cache/apk/APKINDEX.066df28d.tar.gz",
    "D|/var/cache/apk/APKINDEX.30e6f5af.tar.gz",
    "D|/var/cache/apk/APKINDEX.b53994b4.tar.gz",
    "D|/var/cache/apk/APKINDEX.bc99f2f3.tar.gz",
    "M|/usr/lib/apk/db/installed",
    "M|/usr/lib/apk/db/scripts.tar.gz",
    "M|/usr/libexec",
    "M|/usr/share",
    "M|/var/log/apk.log",
    "M|/var/lib",
)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


class InjectRootfsCandidateContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.source = SCRIPT.read_text(encoding="utf-8")
        cls.launcher = LAUNCHER.read_text(encoding="utf-8")
        cls.lock_bytes = LOCK.read_bytes()
        cls.lock = json.loads(cls.lock_bytes)
        cls.runtime_lock_bytes = RUNTIME_LOCK.read_bytes()
        cls.runtime_lock = json.loads(cls.runtime_lock_bytes)
        cls.injection_policy_lock = json.loads(INJECTION_POLICY_LOCK.read_bytes())

    @staticmethod
    def valid_p2_installed_record() -> str:
        dependencies = (
            "device-xiaomi-lmi=1-r142 greetd=0.10.3-r11 greetd-openrc=0.10.3-r11 "
            "greetd-phrog=0.53.0-r0 libseat=0.9.3-r0 libweston=14.0.2-r10 "
            "linux-xiaomi-lmi=4.19.325-r9 lmi-weston-sixrow-clients=14.0.2-r1 "
            "openrc=0.63.2-r0 seatd=0.9.3-r0 "
            "seatd-openrc=0.9.3-r0 weston=14.0.2-r10 weston-backend-drm=14.0.2-r10 "
            "weston-shell-desktop=14.0.2-r10 weston-terminal=14.0.2-r10 /bin/sh"
        )
        lines = [
            "C:Q1CgJ9oAvCtPMD0gpMqjIRwUt4gow=",
            "P:device-xiaomi-lmi-terminal",
            "V:0.1.0-r1",
            "A:noarch",
            "S:8768",
            "I:24926",
            "T:Pinned non-root Weston terminal session for Xiaomi lmi D114",
            "U:https://postmarketos.org",
            "L:MIT",
            "o:device-xiaomi-lmi-terminal",
            "m:lmi P2 maintainers <noreply@example.invalid>",
            "t:1784522705",
            "c:uncommitted-p2-d114-source-lock-v3",
            f"D:{dependencies}",
            "F:etc",
            "F:etc/lmi-p2-d114",
            "R:greetd.toml",
            "Z:Q17aD3D/27DhKiygFdfBjjWQ46v/4=",
            "R:weston.ini",
            "Z:Q1ACVXZU3ZSa9r/vWT8UkYAfbLRlw=",
            "F:usr",
            "F:usr/libexec",
            "F:usr/libexec/lmi-p2-d114",
            "R:config-lifecycle",
            "a:0:0:755",
            "Z:Q1fz2JibH7B8jAdosh8vogpdSyQZM=",
            "R:session",
            "a:0:0:755",
            "Z:Q1HZ+4EtKUzGLZ9gU4XrAdWTyoAVM=",
            "F:usr/share",
            "F:usr/share/lmi-p2-d114",
            "R:greetd.confd",
            "Z:Q11ujOtYABrGQSohB67SphVfwH5C8=",
        ]
        return "\n".join(lines) + "\n\n"

    @staticmethod
    def valid_sixrow_installed_record() -> str:
        dependencies = (
            "so:libc.musl-aarch64.so.1 so:libcairo.so.2 so:libfontconfig.so.1 "
            "so:libgobject-2.0.so.0 so:libpango-1.0.so.0 so:libpangocairo-1.0.so.0 "
            "so:libpixman-1.so.0 so:libpng16.so.16 so:libwayland-client.so.0 "
            "so:libwayland-cursor.so.0 so:libxkbcommon.so.0"
        )
        lines = [
            "C:Q1z+kF3cP7AS8SIoqzAnBB/K89PAc=",
            "P:lmi-weston-sixrow-clients",
            "V:14.0.2-r1",
            "A:aarch64",
            "S:120891",
            "I:335416",
            "T:Hash-locked six-row Weston keyboard and text-input terminal for xiaomi-lmi",
            "U:https://gitlab.freedesktop.org/wayland/weston",
            "L:MIT",
            "o:lmi-weston-sixrow-clients",
            "m:Local lmi port work <noreply@example.invalid>",
            "t:1784659116",
            "c:-dirty",
            f"D:{dependencies}",
            "F:usr",
            "F:usr/libexec",
            "F:usr/libexec/lmi-p2-d114",
            "R:weston-keyboard-sixrow",
            "a:0:0:755",
            "Z:Q1azIWyRjIlMC3OdDOa9HLxShf19M=",
            "R:weston-terminal-sixrow",
            "a:0:0:755",
            "Z:Q1TfC5e5TmOzP1rew68T4D0bOCiE4=",
        ]
        return "\n".join(lines) + "\n\n"

    @staticmethod
    def read_apk_member(member: str) -> bytes:
        completed = subprocess.run(
            ["tar", "-xOf", str(SIXROW_APK), member],
            check=False,
            capture_output=True,
            timeout=10,
        )
        if completed.returncode != 0:
            raise AssertionError(completed.stderr.decode("utf-8", errors="replace"))
        return completed.stdout

    def run_helper(
        self,
        body: str,
        *arguments: Path,
        env: dict[str, str] | None = None,
        timeout: int = 20,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["bash", "-c", f'source "$1"\n{body}', "helper-test", str(SCRIPT), *map(str, arguments)],
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )

    @staticmethod
    def write_scripts_archive(path: Path, members: dict[str, bytes]) -> None:
        with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name, payload in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(payload)
                info.mode = 0o755 if name.startswith("device-xiaomi-lmi-terminal-") else 0o644
                info.uid = 0
                info.gid = 0
                info.mtime = 0
                archive.addfile(info, io.BytesIO(payload))

    @staticmethod
    def write_delta(path: Path, op_paths: tuple[str, ...] | list[str], payload: str = "payload") -> None:
        path.write_text(
            "".join(
                f"{op_path}|regular file|644:0:0:1:1:0:0:0|{payload}|"
                f"{hashlib.sha256(b'').hexdigest()}|----------------------\n"
                for op_path in op_paths
            ),
            encoding="utf-8",
        )

    @staticmethod
    def create_delta_baseline(root: Path) -> None:
        for relative in (
            "etc/conf.d",
            "etc/ssh/sshd_config.d",
            "home/lmi/.ssh",
            "usr/bin",
            "usr/lib/apk/db",
            "usr/libexec",
            "usr/share",
            "var/cache/apk",
            "var/lib",
            "var/log",
        ):
            (root / relative).mkdir(parents=True, exist_ok=True)
        (root / "etc/conf.d/greetd").write_text(
            '# Configuration for greetd\n\n'
            '# Path to config file to use.\n'
            'cfgfile="/etc/phrog/greetd-config.toml"\n\n'
            '# Uncomment to use process supervisor when using openrc.\n'
            '# supervisor=supervise-daemon\n',
            encoding="utf-8",
        )
        (root / "etc/unchanged").write_text("unchanged\n", encoding="utf-8")
        (root / "etc/empty").write_bytes(b"")
        (root / "etc/machine-id").write_bytes(b"m" * 33)
        (root / "etc/resolv.conf").write_bytes(b"r" * 211)
        (root / "etc/shadow").write_bytes(b"s" * 731)
        (root / "etc/shadow-").write_bytes(b"b" * 730)
        (root / "etc/shadow").chmod(0o640)
        (root / "etc/shadow-").chmod(0o640)
        (root / "etc/ssh/sshd_config").write_bytes(b"s" * 3542)
        (root / "etc/ssh/sshd_config.d/50-postmarketos-ui-policy.conf").write_bytes(b"p" * 176)
        (root / "etc/ssh/sshd_config.d/50-postmarketos-ui-policy.conf").chmod(0o600)
        (root / "home/lmi/.ssh/authorized_keys").write_bytes(b"k" * 573)
        (root / "home/lmi/.ssh").chmod(0o700)
        (root / "home/lmi/.ssh/authorized_keys").chmod(0o644)
        (root / "usr/lib/apk/db/installed").write_text("baseline-installed\n", encoding="utf-8")
        (root / "usr/lib/apk/db/scripts.tar.gz").write_bytes(b"baseline-scripts")
        for name, size in (
            ("APKINDEX.066df28d.tar.gz", 528174),
            ("APKINDEX.30e6f5af.tar.gz", 750911),
            ("APKINDEX.b53994b4.tar.gz", 2514943),
            ("APKINDEX.bc99f2f3.tar.gz", 116688),
        ):
            (root / "var/cache/apk" / name).write_bytes(b"c" * size)
        (root / "var/log/apk.log").write_bytes(b"l" * 69179)
        # These unchanged names mirror legal paths in the fixed Alpine
        # candidate.  Full-tree validation must not apply the deliberately
        # narrow grammar used for the 20 allowlisted delta operations.
        (root / "usr/bin/[").symlink_to("/bin/busybox")
        exotic_files = {
            "usr/share/ModemManager/fcc-unlock.available.d/03f0:4e1d": b"colon\n",
            "usr/share/alsa/ucm2/conf.d/simple-card/Librem 5.conf": b"space\n",
            "usr/share/ca-certificates/mozilla/NetLock_Arany_=Class_Gold=_F\u0151tan\u00fas\u00edtv\u00e1ny.crt": b"unicode\n",
            "usr/share/espeak-data/voices/!v/f5": b"punctuation\n",
            "usr/share/icons/hicolor/128x128@2/apps/example,name.desktop": b"at-comma\n",
        }
        for relative, payload in exotic_files.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        long_component = "n" * 140
        long_path = root / "usr/share" / long_component / long_component / "unchanged"
        long_path.parent.mkdir(parents=True)
        long_path.write_bytes(b"long-path\n")

    @staticmethod
    def apply_expected_delta(root: Path) -> None:
        payloads = {
            "etc/lmi-p2-d114/greetd.toml": (REPO / "files/lmi-p2-d114/lmi-p2-d114-greetd.toml").read_bytes(),
            "etc/lmi-p2-d114/weston.ini": (REPO / "files/lmi-p2-d114/lmi-p2-d114-weston.ini").read_bytes(),
            "usr/libexec/lmi-p2-d114/config-lifecycle": (
                REPO / "files/lmi-p2-d114/lmi-p2-d114-config-lifecycle"
            ).read_bytes(),
            "usr/libexec/lmi-p2-d114/session": (
                REPO / "files/lmi-p2-d114/lmi-p2-d114-session"
            ).read_bytes(),
            "usr/libexec/lmi-p2-d114/weston-keyboard-sixrow": InjectRootfsCandidateContractTests.read_apk_member(
                "usr/libexec/lmi-p2-d114/weston-keyboard-sixrow"
            ),
            "usr/libexec/lmi-p2-d114/weston-terminal-sixrow": InjectRootfsCandidateContractTests.read_apk_member(
                "usr/libexec/lmi-p2-d114/weston-terminal-sixrow"
            ),
            "usr/share/lmi-p2-d114/greetd.confd": (
                REPO / "files/lmi-p2-d114/lmi-p2-d114-greetd.confd"
            ).read_bytes(),
            "var/lib/lmi-p2-d114/config-v1": b"lmi-p2-d114-greetd-confd/v1\n",
            "var/lib/lmi-p2-d114/greetd-confd.original": (
                root / "etc/conf.d/greetd"
            ).read_bytes(),
            "etc/ssh/sshd_config.d/99-lmi-public-image.conf": (
                b"# D114 public-image SSH policy: local passwords remain available only on the console.\n"
                b"PasswordAuthentication no\n"
                b"KbdInteractiveAuthentication no\n"
                b"PermitEmptyPasswords no\n"
                b"AuthenticationMethods publickey\n"
            ),
        }
        for relative, payload in payloads.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        for relative in (
            "usr/libexec/lmi-p2-d114/config-lifecycle",
            "usr/libexec/lmi-p2-d114/session",
            "usr/libexec/lmi-p2-d114/weston-keyboard-sixrow",
            "usr/libexec/lmi-p2-d114/weston-terminal-sixrow",
        ):
            (root / relative).chmod(0o755)
        for relative in (
            "var/lib/lmi-p2-d114/config-v1",
            "var/lib/lmi-p2-d114/greetd-confd.original",
        ):
            (root / relative).chmod(0o600)
        (root / "var/lib/lmi-p2-d114").chmod(0o700)
        (root / "etc/conf.d/greetd").write_bytes(
            (REPO / "files/lmi-p2-d114/lmi-p2-d114-greetd.confd").read_bytes()
        )
        (root / "usr/lib/apk/db/installed").write_text("installed-with-target\n", encoding="utf-8")
        (root / "usr/lib/apk/db/scripts.tar.gz").write_bytes(b"scripts-with-target")
        (root / "etc/machine-id").unlink()
        (root / "etc/resolv.conf").write_bytes(b"")
        (root / "etc/shadow-").write_bytes((root / "etc/shadow").read_bytes())
        (root / "var/log/apk.log").write_bytes(b"")
        for member in (root / "var/cache/apk").iterdir():
            member.unlink()
        (root / "home/lmi/.ssh/authorized_keys").unlink()

    def test_shell_files_are_syntactically_valid(self) -> None:
        for path in (SCRIPT, LAUNCHER):
            result = subprocess.run(
                ["bash", "-n", str(path)], check=False, capture_output=True, text=True, timeout=10
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_declarations_do_not_expand_variables_declared_by_the_same_command(self) -> None:
        for line_number, line in enumerate(self.source.splitlines(), start=1):
            declaration = line.lstrip()
            if not declaration.startswith("local "):
                continue
            declaration = declaration.removeprefix("local ")
            declared = [token.split("=", 1)[0] for token in declaration.split()]
            for name in declared:
                if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
                    continue
                self.assertNotRegex(
                    declaration,
                    rf"\$(?:{re.escape(name)}\b|\{{{re.escape(name)}(?:\W|\}}))",
                    f"line {line_number} expands {name!r} in the command that declares it",
                )

    def test_scripts_delta_runs_under_nounset_through_final_inventory_comparison(self) -> None:
        target_sources = {
            "device-xiaomi-lmi-terminal-0.1.0-r1.post-install": (
                REPO / "files/lmi-p2-d114/device-xiaomi-lmi-terminal.post-install"
            ).read_bytes(),
            "device-xiaomi-lmi-terminal-0.1.0-r1.post-upgrade": (
                REPO / "files/lmi-p2-d114/device-xiaomi-lmi-terminal.post-upgrade"
            ).read_bytes(),
            "device-xiaomi-lmi-terminal-0.1.0-r1.pre-deinstall": (
                REPO / "files/lmi-p2-d114/device-xiaomi-lmi-terminal.pre-deinstall"
            ).read_bytes(),
        }
        baseline_members = {"unrelated-package-1.0-r0.post-install": b"#!/bin/sh\nexit 0\n"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before, after, work = root / "before.tar.gz", root / "after.tar.gz", root / "work"
            self.write_scripts_archive(before, baseline_members)
            self.write_scripts_archive(after, {**baseline_members, **target_sources})
            result = self.run_helper(
                'verify_scripts_delta "$2" "$3" "$4"\n'
                '[[ "$(wc -l <"$4/target.list")" == 3 ]]\n'
                'cmp -s -- "$4/before.inventory" "$4/after.inventory"\n'
                '[[ -f "$4/after/unrelated-package-1.0-r0.post-install" ]]\n'
                '[[ -z "$(find "$4/after" -maxdepth 1 -name "device-xiaomi-lmi-terminal-*" -print -quit)" ]]\n',
                before,
                after,
                work,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_scripts_delta_failure_is_removed_by_exit_cleanup(self) -> None:
        target_sources = {
            "device-xiaomi-lmi-terminal-0.1.0-r1.post-install": (
                REPO / "files/lmi-p2-d114/device-xiaomi-lmi-terminal.post-install"
            ).read_bytes(),
            "device-xiaomi-lmi-terminal-0.1.0-r1.post-upgrade": (
                REPO / "files/lmi-p2-d114/device-xiaomi-lmi-terminal.post-upgrade"
            ).read_bytes(),
        }
        baseline_members = {"unrelated-package-1.0-r0.post-install": b"#!/bin/sh\nexit 0\n"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            before, after = scratch / "before.tar.gz", scratch / "after.tar.gz"
            self.write_scripts_archive(before, baseline_members)
            self.write_scripts_archive(after, {**baseline_members, **target_sources})
            result = self.run_helper(
                'SCRATCH_DIR=$2\n'
                'SCRATCH_ID="$(directory_identity_of "$SCRATCH_DIR")"\n'
                'trap cleanup EXIT\n'
                'verify_scripts_delta "$3" "$4" "$SCRATCH_DIR/scripts-delta"\n',
                scratch,
                before,
                after,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("target package script inventory mismatch", result.stderr)
            self.assertFalse(scratch.exists())

    def test_full_delta_real_tree_fixture_covers_exact_operations_and_parent_links(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        host_bound.require_tree_snapshot_tools()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before, after = root / "before", root / "after"
            self.create_delta_baseline(before)
            shutil.copytree(before, after, symlinks=True)
            self.apply_expected_delta(after)
            before_inventory = root / "before.inventory"
            after_inventory = root / "after.inventory"
            delta = root / "delta"
            manifest = root / "op-paths"
            result = self.run_helper(
                'snapshot_tree "$2" "$4"\n'
                'snapshot_tree "$3" "$5"\n'
                'cp -- "$5" "$5.normalized"\n'
                'for stable_dir in /home/lmi/.ssh /var/cache/apk /etc/ssh/sshd_config.d; do\n'
                ' before_line="$(awk -F\'|\' -v path="$stable_dir" \'$1 == path { print; exit }\' "$4")"\n'
                ' awk -F\'|\' -v path="$stable_dir" -v replacement="$before_line" \'$1 == path { print replacement; next } { print }\' "$5.normalized" >"$5.next"\n'
                ' mv -T -- "$5.next" "$5.normalized"\n'
                'done\n'
                'mv -T -- "$5.normalized" "$5"\n'
                'compute_tree_delta "$4" "$5" "$6"\n'
                'verify_full_delta "$6" "$7" "$4" "$5"\n',
                before,
                after,
                before_inventory,
                after_inventory,
                delta,
                manifest,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            manifest_op_paths = tuple(manifest.read_text(encoding="utf-8").splitlines())
            self.assertEqual(len(manifest_op_paths), len(EXPECTED_DELTA_OP_PATHS))
            self.assertEqual(set(manifest_op_paths), set(EXPECTED_DELTA_OP_PATHS))
            op_paths = tuple("|".join(line.split("|", 2)[:2]) for line in delta.read_text().splitlines())
            self.assertEqual(len(op_paths), len(EXPECTED_DELTA_OP_PATHS))
            self.assertEqual(set(op_paths), set(EXPECTED_DELTA_OP_PATHS))
            self.assertEqual(sum(item.startswith("A|") for item in op_paths), 14)
            self.assertEqual(sum(item.startswith("M|") for item in op_paths), 10)
            self.assertEqual(sum(item.startswith("D|") for item in op_paths), 6)
            for parent in ("/etc", "/usr/libexec", "/usr/share", "/var/lib"):
                self.assertIn(f"M|{parent}", op_paths)
            before_paths = {
                line.split("|", 1)[0]
                for line in before_inventory.read_text(encoding="utf-8").splitlines()
            }
            self.assertIn("/usr/bin/[", before_paths)
            self.assertIn(
                "/usr/share/ca-certificates/mozilla/NetLock_Arany_=Class_Gold=_F\u0151tan\u00fas\u00edtv\u00e1ny.crt",
                before_paths,
            )
            self.assertGreater(max(map(len, before_paths)), 256)

    def test_public_image_sanitation_is_exact_and_outside_package_lifecycle(self) -> None:
        sanitation = self.source[
            self.source.index("sanitize_public_image() {") : self.source.index(
                "read_ext4_u32() {"
            )
        ]
        for required in (
            "home/lmi/.ssh",
            "authorized_keys",
            "644:10000:10000:1:573",
            "700:10000:10000",
            'rm -- "$authorized_keys"',
            "etc/machine-id",
            "644:0:0:1:33",
            'rm -- "$machine_id"',
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ):
            self.assertIn(required, sanitation)
        lifecycle_call = self.source.index(
            "/usr/libexec/lmi-p2-d114/config-lifecycle install"
        )
        sanitation_call = self.source.index("\tsanitize_public_image\n", lifecycle_call)
        final_snapshot = self.source.index(
            'snapshot_tree "$MOUNTPOINT" "$FULL_TREE_AFTER"', sanitation_call
        )
        self.assertLess(lifecycle_call, sanitation_call)
        self.assertLess(sanitation_call, final_snapshot)
        lifecycle = (REPO / "files/lmi-p2-d114/lmi-p2-d114-config-lifecycle").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("authorized_keys", lifecycle)
        self.assertNotIn("machine-id", lifecycle)

    def test_snapshot_tree_rejects_unserializable_path_delimiters(self) -> None:
        for name in ("contains|pipe", "contains\nnewline"):
            with self.subTest(name=repr(name)), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tree = root / "tree"
                tree.mkdir()
                (tree / name).write_bytes(b"fixture\n")
                inventory = root / "inventory"
                result = self.run_helper(
                    'if snapshot_tree "$2" "$3"; then exit 99; fi\n'
                    '[[ ! -e "$3" && ! -L "$3" ]]\n',
                    tree,
                    inventory,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(inventory.exists())

    def test_snapshot_tree_refuses_traversal_or_sort_failure_without_publishing_inventory(self) -> None:
        cases = {
            "traversal": 'if snapshot_tree "$2/missing" "$3"; then exit 99; fi',
            "sort": 'sort() { return 97; }\nif snapshot_tree "$2" "$3"; then exit 99; fi',
        }
        for name, command in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                tree = root / "tree"
                tree.mkdir()
                (tree / "entry").write_text("fixture\n", encoding="utf-8")
                inventory = root / "inventory"
                result = self.run_helper(
                    f'{command}\n[[ ! -e "$3" && ! -L "$3" ]]\n',
                    tree,
                    inventory,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(inventory.exists())

    def test_full_delta_rejects_metadata_drift_on_unknown_added_and_allowed_paths(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        host_bound.require_tree_snapshot_tools()
        mutations = (
            "root-mode",
            "unknown-xattr",
            "unknown-inode-flags",
            "allowed-file-xattr",
            "allowed-parent-xattr",
            "added-file-xattr",
            "allowed-parent-inode-flags",
            "allowed-file-kind",
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                before, after = root / "before", root / "after"
                self.create_delta_baseline(before)
                shutil.copytree(before, after, symlinks=True)
                self.apply_expected_delta(after)
                if mutation == "root-mode":
                    after.chmod(0o777)
                elif mutation in {
                    "unknown-xattr",
                    "allowed-file-xattr",
                    "allowed-parent-xattr",
                    "added-file-xattr",
                }:
                    xattr_target = {
                        "unknown-xattr": after / "etc/unchanged",
                        "allowed-file-xattr": after / "etc/conf.d/greetd",
                        "allowed-parent-xattr": after / "etc",
                        "added-file-xattr": after / "etc/lmi-p2-d114/greetd.toml",
                    }[mutation]
                    try:
                        os.setxattr(xattr_target, b"user.lmi_probe", b"detected")
                    except (AttributeError, OSError) as error:
                        self.skipTest(f"host filesystem does not support user xattrs: {error}")
                elif mutation in {"unknown-inode-flags", "allowed-parent-inode-flags"}:
                    chattr = shutil.which("chattr")
                    if chattr is None:
                        self.skipTest("chattr is unavailable")
                    flag_target = (
                        after / "etc/unchanged"
                        if mutation == "unknown-inode-flags"
                        else after / "etc"
                    )
                    changed = subprocess.run(
                        [chattr, "+A", str(flag_target)],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    if changed.returncode != 0:
                        self.skipTest(f"host filesystem does not support inode flags: {changed.stderr}")
                else:
                    target = after / "etc/conf.d/greetd"
                    target.unlink()
                    target.symlink_to("../lmi-p2-d114/greetd.toml")
                before_inventory = root / "before.inventory"
                after_inventory = root / "after.inventory"
                delta = root / "delta"
                manifest = root / "op-paths"
                result = self.run_helper(
                    'snapshot_tree "$2" "$4"\n'
                    'snapshot_tree "$3" "$5"\n'
                    'cp -- "$5" "$5.normalized"\n'
                    'for stable_dir in /home/lmi/.ssh /var/cache/apk /etc/ssh/sshd_config.d; do\n'
                    ' before_line="$(awk -F\'|\' -v path="$stable_dir" \'$1 == path { print; exit }\' "$4")"\n'
                    ' awk -F\'|\' -v path="$stable_dir" -v replacement="$before_line" \'$1 == path { print replacement; next } { print }\' "$5.normalized" >"$5.next"\n'
                    ' mv -T -- "$5.next" "$5.normalized"\n'
                    'done\n'
                    'mv -T -- "$5.normalized" "$5"\n'
                    'compute_tree_delta "$4" "$5" "$6"\n'
                    'verify_full_delta "$6" "$7" "$4" "$5"\n',
                    before,
                    after,
                    before_inventory,
                    after_inventory,
                    delta,
                    manifest,
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("filesystem delta escaped the exact package/lifecycle allowlist", result.stderr)
                op_paths = {"|".join(line.split("|", 2)[:2]) for line in delta.read_text().splitlines()}
                expected_path = {
                    "root-mode": "M|/",
                    "unknown-xattr": "M|/",
                    "unknown-inode-flags": "M|/etc/unchanged",
                    "allowed-file-xattr": "M|/",
                    "allowed-parent-xattr": "M|/",
                    "added-file-xattr": "M|/",
                    "allowed-parent-inode-flags": "M|/etc",
                    "allowed-file-kind": "M|/etc/conf.d/greetd",
                }[mutation]
                self.assertIn(expected_path, op_paths)
                if mutation in {"allowed-parent-inode-flags", "allowed-file-kind"}:
                    self.assertIn("parse=field-mismatch", result.stderr)

    def test_snapshot_tree_rejects_special_inodes_without_publishing_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tree = root / "tree"
            tree.mkdir()
            os.mkfifo(tree / "fifo")
            inventory = root / "inventory"
            result = self.run_helper(
                'if snapshot_tree "$2" "$3"; then exit 99; fi\n'
                '[[ ! -e "$3" && ! -L "$3" ]]\n',
                tree,
                inventory,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(inventory.exists())

    def test_metadata_inventory_tools_are_host_pinned_and_attested(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        tools = {
            "getfattr": (Path("/usr/bin/getfattr"), "GETFATTR_SHA256", "getfattr_sha256", "755"),
            "lsattr": (Path("/usr/bin/lsattr"), "LSATTR_SHA256", "lsattr_sha256", "755"),
            "lsattr-libe2p": (
                Path("/usr/lib/x86_64-linux-gnu/libe2p.so.2.3"),
                "LSATTR_LIBE2P_SHA256",
                "lsattr_libe2p_sha256",
                "644",
            ),
            "lsattr-libcom-err": (
                Path("/usr/lib/x86_64-linux-gnu/libcom_err.so.2.1"),
                "LSATTR_LIBCOM_ERR_SHA256",
                "lsattr_libcom_err_sha256",
                "644",
            ),
        }
        for label, (path, constant, policy_field, mode) in tools.items():
            with self.subTest(tool=label):
                expected = digest(path)
                self.assertIn(f"readonly {constant}={expected}", self.source)
                self.assertEqual(self.injection_policy_lock["tools"][policy_field], expected)
                self.assertIn(f'|{mode}|{label}|${constant}', self.source)

    def test_full_delta_exact_set_accepts_reordering_without_losing_operations(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        host_bound.require_tree_snapshot_tools()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before, after = root / "before", root / "after"
            self.create_delta_baseline(before)
            shutil.copytree(before, after, symlinks=True)
            self.apply_expected_delta(after)
            before_inventory = root / "before.inventory"
            after_inventory = root / "after.inventory"
            original_delta = root / "original.delta"
            delta, manifest = root / "delta", root / "op-paths"
            setup = self.run_helper(
                'snapshot_tree "$2" "$4"\n'
                'snapshot_tree "$3" "$5"\n'
                'cp -- "$5" "$5.normalized"\n'
                'for stable_dir in /home/lmi/.ssh /var/cache/apk /etc/ssh/sshd_config.d; do\n'
                ' before_line="$(awk -F\'|\' -v path="$stable_dir" \'$1 == path { print; exit }\' "$4")"\n'
                ' awk -F\'|\' -v path="$stable_dir" -v replacement="$before_line" \'$1 == path { print replacement; next } { print }\' "$5.normalized" >"$5.next"\n'
                ' mv -T -- "$5.next" "$5.normalized"\n'
                'done\n'
                'mv -T -- "$5.normalized" "$5"\n'
                'compute_tree_delta "$4" "$5" "$6"\n',
                before,
                after,
                before_inventory,
                after_inventory,
                original_delta,
            )
            self.assertEqual(setup.returncode, 0, setup.stderr)
            delta.write_text(
                "\n".join(reversed(original_delta.read_text(encoding="utf-8").splitlines())) + "\n",
                encoding="utf-8",
            )
            result = self.run_helper(
                'verify_full_delta "$2" "$3" "$4" "$5"\n',
                delta,
                manifest,
                before_inventory,
                after_inventory,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            reversed_op_paths = tuple(
                "|".join(line.split("|", 2)[:2])
                for line in delta.read_text(encoding="utf-8").splitlines()
            )
            self.assertEqual(
                tuple(manifest.read_text(encoding="utf-8").splitlines()),
                reversed_op_paths,
            )

    def test_full_delta_rejects_wrong_operations_deletes_duplicates_unknown_and_invalid(self) -> None:
        cases = {
            "wrong-operation": ("M" + EXPECTED_DELTA_OP_PATHS[0][1:], *EXPECTED_DELTA_OP_PATHS[1:]),
            "delete": ("D" + EXPECTED_DELTA_OP_PATHS[0][1:], *EXPECTED_DELTA_OP_PATHS[1:]),
            "duplicate": (*EXPECTED_DELTA_OP_PATHS, EXPECTED_DELTA_OP_PATHS[0]),
            "unknown": ("A|/etc/unexpected", *EXPECTED_DELTA_OP_PATHS[1:]),
            "missing": EXPECTED_DELTA_OP_PATHS[1:],
            "invalid-operation": ("X" + EXPECTED_DELTA_OP_PATHS[0][1:], *EXPECTED_DELTA_OP_PATHS[1:]),
            "control-path": ("A|/etc/\x1bunsafe", *EXPECTED_DELTA_OP_PATHS[1:]),
        }
        for name, op_paths in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                delta, manifest = root / "delta", root / "op-paths"
                self.write_delta(delta, list(op_paths))
                result = self.run_helper('verify_full_delta "$2" "$3" "$2" "$2"\n', delta, manifest)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("filesystem delta escaped the exact package/lifecycle allowlist", result.stderr)
                self.assertIn("omitted=no", result.stderr)
                self.assertIn("evidence_scope=normalized-op-path", result.stderr)
                encoded_match = re.search(r"op_path_b64=([A-Za-z0-9+/]*={0,2})", result.stderr)
                digest_match = re.search(r"evidence_sha256=([0-9a-f]{64})", result.stderr)
                self.assertIsNotNone(encoded_match, result.stderr)
                self.assertIsNotNone(digest_match, result.stderr)
                evidence = base64.b64decode(encoded_match.group(1), validate=True)
                self.assertEqual(hashlib.sha256(evidence).hexdigest(), digest_match.group(1))
                self.assertEqual(evidence, manifest.read_bytes())
                self.assertNotIn("\x1b", result.stderr)
                self.assertNotIn("/etc/unexpected", result.stderr)

    def test_full_delta_over_bound_diagnostics_omit_base64_and_bind_raw_delta(self) -> None:
        cases = {
            "line-limit": [f"A|/overflow-{index}" for index in range(33)],
            "byte-limit": ["A|/overflow"],
        }
        for name, op_paths in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                delta, manifest = root / "delta", root / "op-paths"
                payload = "x" * 9000 if name == "byte-limit" else "payload"
                self.write_delta(delta, op_paths, payload=payload)
                result = self.run_helper('verify_full_delta "$2" "$3" "$2" "$2"\n', delta, manifest)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(f"parse={name}", result.stderr)
                self.assertIn("evidence_scope=raw-delta", result.stderr)
                self.assertIn("omitted=over-bound", result.stderr)
                self.assertNotIn("op_path_b64=", result.stderr)
                digest_match = re.search(r"evidence_sha256=([0-9a-f]{64})", result.stderr)
                self.assertIsNotNone(digest_match, result.stderr)
                self.assertEqual(hashlib.sha256(delta.read_bytes()).hexdigest(), digest_match.group(1))

    def test_full_delta_failure_evidence_is_emitted_before_scratch_cleanup(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            scratch = root / "scratch"
            scratch.mkdir(mode=0o700)
            delta = scratch / "delta"
            self.write_delta(delta, ["A|/unexpected"])
            result = self.run_helper(
                'SCRATCH_DIR=$2\n'
                'SCRATCH_ID="$(directory_identity_of "$SCRATCH_DIR")"\n'
                'trap cleanup EXIT\n'
                'verify_full_delta "$3" "$SCRATCH_DIR/op-paths" "$3" "$3"\n',
                scratch,
                delta,
            )
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("op_path_b64=", result.stderr)
            self.assertFalse(scratch.exists())

    def test_fixed_inputs_are_private_canonical_and_candidate_is_never_mutated(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        for name in (
            "xiaomi-lmi-v114-splash-recursion-fix-userdata-20260716.img",
            "xiaomi-lmi-v114-splash-recursion-fix-userdata-20260716.android-sparse.img",
            "lmi-d114-rootfs-base.ext4",
            "lmi-d114-rootfs-p2-candidate-20260720.ext4",
        ):
            path = BUILD / name
            self.assertEqual(path.resolve(strict=True), path)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertNotIn("readonly BASE=/tmp/", self.source)
        self.assertNotIn("readonly INPUT=/tmp/", self.source)
        self.assertIn('[[ "$(dirname -- "$path")" == "$INPUT_BUILD_DIR" ]]', self.source)
        self.assertIn('"$RAW"|"$SPARSE"|"$BASE"|"$INPUT"', self.source)
        self.assertIn('[[ "$INPUT_BUILD_DIR" != "$BUILD_DIR" ]]', self.source)
        self.assertIn('require_private_input "$path" "$label"', self.source)
        self.assertIn('copy_fd_to_scratch "$INPUT_FD" "$SCRATCH_IMAGE"', self.source)
        self.assertIn('LOOP_DEVICE="$(losetup --find)"', self.source)
        self.assertIn('losetup "$LOOP_DEVICE" "$SCRATCH_IMAGE"', self.source)
        self.assertNotIn('losetup --find --show "$SCRATCH_IMAGE"', self.source)
        self.assertNotIn('losetup --find --show "$INPUT"', self.source)

    def test_rebuild_lock_is_exactly_pinned_and_cross_matches_script_constants(self) -> None:
        self.assertEqual(self.lock["schema"], "lmi-p2-d114-candidate-rebuild-lock/v1")
        self.assertEqual(digest(LOCK), "1122fae16487ab77406fe444f1fc96da4848fcfb277fd4ad71dc51d81da01489")
        expected = {
            "61ca69e6c241a92ad86539ffeebc0d4ef296572709445604ce26a78648f27bf6",
            "e8a30dc37cb4b75508d89725a9603bc15a985f4e51af77384e8d43c2928f8d68",
            "76f032775b110855a5984b1ed45b10f9653c59af69b070ceac0e73e7216eb96c",
            "90b9f0ab94198f78eb251cff0d4c521f7b4bb47fb50967a7c661eacc026e0e82",
            "4e23b50bc020fddde6daacf5b5a9a4f5472bcc156e7c58c5c932a8ba4c6ffc4f",
            "9a3b20f3e422ee80cb6615158f1cc8b08fd71dda9a2e49745642404decf60837",
            "2e51f521c676729920eaba694933d9d4048645f1a5789556fd0027e62d11ecc8",
        }
        for value in expected:
            self.assertIn(value, self.source)
        self.assertEqual(self.lock["geometry"]["logical_sector_size"], 4096)
        self.assertEqual(self.lock["geometry"]["partitions"][1]["first_lba"], 124928)
        self.assertEqual(self.lock["geometry"]["partitions"][1]["sector_count"], 690176)
        self.assertEqual(self.lock["candidate"]["normalized_superblock"]["epoch"], 1784551824)
        self.assertIn('verify_open_path_unchanged "$path" "$descriptor" "$identity"', self.source)

    def test_runtime_lock_is_exact_and_matches_the_copied_sandbox_closure(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        self.assertEqual(self.runtime_lock["schema"], "lmi-p2-d114-injector-runtime-lock/v1")
        self.assertEqual(
            digest(RUNTIME_LOCK),
            "11d2cc4e8c327193f2acb23869376cb93838f7d9e775ead24f4755704263ed73",
        )
        by_path = {item["path"]: item for item in self.runtime_lock["artifacts"]}
        self.assertEqual(len(by_path), len(self.runtime_lock["artifacts"]))
        self.assertEqual(
            by_path["/usr/bin/bwrap"]["needed"],
            ["libselinux.so.1", "libcap.so.2", "libc.so.6"],
        )
        self.assertEqual(
            by_path[
                "private/lmi-p1/calibration/acquisition-root/proot-root/usr/bin/proot"
            ]["needed"],
            ["libtalloc.so.2", "libc.so.6"],
        )
        for artifact in self.runtime_lock["artifacts"]:
            self.assertRegex(artifact["sha256"], r"^[0-9a-f]{64}$")
            self.assertIn(artifact["sha256"], self.source)
        self.assertIn('verify_runtime_closure "$RUNTIME_CLOSURE"', self.source)
        self.assertGreaterEqual(self.source.count('verify_runtime_closure "$RUNTIME_CLOSURE"'), 4)
        self.assertNotRegex(self.source, r"\bsetpriv\b")
        self.assertIn(
            "864e1d7b445e7b5bfc831da78330dbcafc590fa82b89ea9de60b7527f989954f",
            self.source,
        )
        version = subprocess.run(
            ["/usr/bin/bwrap", "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(version.returncode, 0, version.stderr)
        self.assertEqual(version.stdout.strip(), "bubblewrap 0.11.1")

    def test_candidate_primary_superblock_has_reviewed_little_endian_epoch(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        candidate = BUILD / "lmi-d114-rootfs-p2-candidate-20260720.ext4"
        with candidate.open("rb") as source:
            source.seek(1072)
            wtime = int.from_bytes(source.read(4), "little")
            source.seek(1088)
            lastcheck = int.from_bytes(source.read(4), "little")
        self.assertEqual((wtime, lastcheck), (1784551824, 1784551824))
        self.assertIn("normalize_repair_epoch", self.source)
        self.assertIn('"$E2FSCK" -fn "$SCRATCH_IMAGE"', self.source)

    def test_lineage_replays_sparse_and_checks_raw_root_slice_and_gpt(self) -> None:
        for fragment in (
            '"$SIMG2IMG" "/proc/self/fd/$SPARSE_FD" "$SPARSE_ROUNDTRIP"',
            'cmp -s -- "$SPARSE_ROUNDTRIP" "/proc/self/fd/$RAW_FD"',
            'verify_gpt_geometry "/proc/self/fd/$RAW_FD"',
            'cmp -s -n "$IMAGE_SIZE" -i "$((GPT_SECTOR_SIZE * ROOT_START_SECTOR)):0"',
            "Sector size (logical/physical): 4096 bytes / 4096 bytes",
            "candidate is not clean under pinned e2fsck",
        ):
            self.assertIn(fragment, self.source)

    def test_timeout_dependency_is_completely_removed(self) -> None:
        self.assertNotRegex(self.source, r"\btimeout\b")
        self.assertNotRegex(self.launcher, r"\btimeout\b")

    def test_launcher_prehashes_copies_and_root_seals_before_namespace_execution(self) -> None:
        injector_hash = digest(SCRIPT)
        self.assertIn(f"readonly INJECTOR_SHA256={injector_hash}", self.launcher)
        copy_at = self.launcher.index('/usr/bin/cp --reflink=never -- "$INJECTOR" "$staged"')
        staged_hash_at = self.launcher.index('"$(sha256_of "$staged")" == "$INJECTOR_SHA256"')
        first_transport_at = self.launcher.index('"${root_transport[@]}" /usr/bin/env -i')
        root_install_at = self.launcher.index('/usr/bin/install -o root -g root -m 0700 -- "/proc/self/fd/$staged_fd" "$sealed"')
        unshare_at = self.launcher.index("/usr/bin/unshare --mount --net --pid --fork --ipc --uts --mount-proc=/proc")
        self.assertLess(copy_at, staged_hash_at)
        self.assertLess(staged_hash_at, first_transport_at)
        self.assertLess(root_install_at, unshare_at)
        for fragment in (
            "root-owned sealed entry digest mismatch",
            "close_inherited_fds_and_reject_stdio_sockets",
            "/usr/bin/env -i",
            "/bin/bash --noprofile --norc",
            "launcher accepts no arguments or exactly one --wsl-root argument",
            "caller uid/gid must exactly match repository owner",
            "injector returned without removing its sealed entry",
            "published bundle failed caller-side inode/metadata/hash verification",
        ):
            self.assertIn(fragment, self.launcher)
        self.assertEqual(self.launcher.count("/usr/bin/sudo -n --"), 1)
        cleanup = self.launcher[self.launcher.index("cleanup() {") : self.launcher.index("verify_published_bundle()")]
        self.assertNotIn("sudo", cleanup)

    def test_launcher_root_transport_modes_are_strict_and_share_one_root_block(self) -> None:
        self.assertEqual(self.launcher.count("/usr/bin/sudo -n --"), 1)
        self.assertIn("sudo) root_transport=(/usr/bin/sudo -n --) ;;", self.launcher)
        self.assertIn(
            'root_transport=("$WSL_ROOT_TRANSPORT" -d "$WSL_ROOT_DISTRO" -u root --exec)',
            self.launcher,
        )
        self.assertNotIn(" -u root -- ", self.launcher)
        self.assertEqual(self.launcher.count('"${root_transport[@]}" /usr/bin/env -i'), 1)
        root_block = self.launcher[
            self.launcher.index('"${root_transport[@]}" /usr/bin/env -i') :
            self.launcher.index(' lmi-p2-d114-root-wrapper', self.launcher.index('"${root_transport[@]}" /usr/bin/env -i'))
        ]
        self.assertIn('"$(/usr/bin/id -ru)" == 0', root_block)
        self.assertIn('"$(/usr/bin/id -rg)" == 0', root_block)
        self.assertIn("/usr/bin/install -o root -g root -m 0700", root_block)
        self.assertIn("/usr/bin/unshare --mount --net --pid --fork --ipc --uts", root_block)

    def test_wsl_root_transport_is_fixed_pinned_nonwritable_and_drvfs_identified(self) -> None:
        for fragment in (
            "readonly WSL_ROOT_WINDOWS_DIR=/mnt/c/WINDOWS",
            "readonly WSL_ROOT_SYSTEM32_DIR=/mnt/c/WINDOWS/system32",
            "readonly WSL_ROOT_TRANSPORT=/mnt/c/WINDOWS/system32/wsl.exe",
            "readonly WSL_ROOT_TRANSPORT_SHA256=e27cbfcbd61c44796e2cfdd031663245bda8d6e4a43c1451b1fc505333908126",
            "readonly WSL_ROOT_TRANSPORT_SIZE=278528",
            "readonly WSL_ROOT_DISTRO=Ubuntu",
            "readonly WSL_ROOT_KERNEL=6.6.87.2-microsoft-standard-WSL2",
            '[[ "$fstype" == 9p ]]',
            "for required_option in aname=drvfs 'path=C:\\' access=client",
            '! -w "$WSL_ROOT_TRANSPORT"',
            "%d:%i:%a:%s:%Y:%Z",
            '[[ "$transport_digest" == "$WSL_ROOT_TRANSPORT_SHA256" ]]',
            '[[ "$transport_after" == "$transport_before" ]]',
        ):
            self.assertIn(fragment, self.launcher)
        self.assertNotRegex(self.launcher, r"(?:^|[,;])(?:rfd|wfd|fd)=")

    def test_wsl_transport_ancestors_are_canonical_nonwritable_and_identity_locked(self) -> None:
        ancestor_gate = self.launcher[
            self.launcher.index('for ancestor in "$WSL_ROOT_WINDOWS_DIR" "$WSL_ROOT_SYSTEM32_DIR"') :
            self.launcher.index('[[ -f "$WSL_ROOT_TRANSPORT"', self.launcher.index("verify_wsl_root_transport()"))
        ]
        for fragment in (
            '[[ -d "$ancestor" && ! -L "$ancestor" && ! -w "$ancestor" ]]',
            'ancestor_canonical="$(/usr/bin/realpath -e -- "$ancestor")"',
            '[[ "$ancestor_canonical" == "$ancestor" ]]',
            '[[ "$(/usr/bin/stat -c %F -- "$ancestor")" == directory ]]',
            'ancestor_identity="$(/usr/bin/stat -c %d:%i:%a:%s:%Y:%Z -- "$ancestor")"',
            '[[ "$ancestor_identity" == *:555:* ]]',
            "WSL_ROOT_WINDOWS_IDENTITY=$ancestor_identity",
            "WSL_ROOT_SYSTEM32_IDENTITY=$ancestor_identity",
        ):
            self.assertIn(fragment, ancestor_gate)
        self.assertIn(
            "WSL_ROOT_TRANSPORT_TREE_IDENTITY=$WSL_ROOT_TRANSPORT_IDENTITY$'\\n'$WSL_ROOT_WINDOWS_IDENTITY$'\\n'$WSL_ROOT_SYSTEM32_IDENTITY",
            self.launcher,
        )

    def test_wsl_transport_is_rehashed_immediately_before_common_execution(self) -> None:
        preexec_at = self.launcher.index('if [[ "$root_mode" == wsl-root ]]')
        second_identity_at = self.launcher.index(
            'transport_current="$(wsl_root_transport_tree_identity)"',
            preexec_at,
        )
        second_digest_at = self.launcher.index(
            'transport_current="$(sha256_of "$WSL_ROOT_TRANSPORT")"',
            second_identity_at,
        )
        final_identity_at = self.launcher.index(
            'transport_current="$(wsl_root_transport_tree_identity)"',
            second_digest_at,
        )
        common_execution_at = self.launcher.index('"${root_transport[@]}" /usr/bin/env -i')
        self.assertLess(second_identity_at, second_digest_at)
        self.assertLess(second_digest_at, final_identity_at)
        self.assertLess(final_identity_at, common_execution_at)
        between_final_stat_and_exec = self.launcher[final_identity_at:common_execution_at]
        self.assertNotIn("sha256_of", between_final_stat_and_exec)
        self.assertNotIn("findmnt", between_final_stat_and_exec)

    def test_root_block_requires_transport_namespace_equality_before_sealing(self) -> None:
        root_block_at = self.launcher.index('"${root_transport[@]}" /usr/bin/env -i')
        equality_at = self.launcher.index('[[ "$current_value" == "$parent_value" ]]', root_block_at)
        seal_at = self.launcher.index('/usr/bin/install -d -o root -g root -m 0700 -- "$seal_dir"', root_block_at)
        unshare_at = self.launcher.index("/usr/bin/unshare --mount --net --pid --fork --ipc --uts", root_block_at)
        self.assertLess(equality_at, seal_at)
        self.assertLess(seal_at, unshare_at)
        self.assertIn("for namespace in mnt net pid ipc uts", self.launcher[root_block_at:seal_at])

    def test_launcher_rejects_every_non_contract_argument_before_transport(self) -> None:
        for arguments in (("--not-wsl-root",), ("--wsl-root", "extra"), ("extra", "--wsl-root")):
            result = subprocess.run(
                [str(LAUNCHER), *arguments],
                cwd=REPO,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "launcher accepts no arguments or exactly one --wsl-root argument",
                result.stderr,
            )
            self.assertNotIn("sudo:", result.stderr)

    def test_private_input_gate_accepts_only_the_four_exact_old_build_inputs(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        allowed = self.run_helper(
            'REPO_OWNER="$(stat -Lc %u:%g -- "$REPO")"\n'
            'for spec in "$RAW|raw" "$SPARSE|sparse" "$BASE|base" "$INPUT|candidate-input"; do\n'
            " IFS='|' read -r path label <<<\"$spec\"\n"
            ' require_private_input "$path" "$label"\n'
            "done\n"
            "printf 'EXACT_INPUT_GATE_OK\\n'\n"
        )
        self.assertEqual(allowed.returncode, 0, allowed.stderr)
        self.assertEqual(allowed.stdout, "EXACT_INPUT_GATE_OK\n")

        same_directory_extra = self.run_helper(
            'REPO_OWNER="$(stat -Lc %u:%g -- "$REPO")"\n'
            'require_private_input "$REPAIR_LOG" repair-log\n'
        )
        self.assertEqual(same_directory_extra.returncode, 1)
        self.assertIn("repair-log is not an exact allowlisted read-only input", same_directory_extra.stderr)

        output_directory_apk = self.run_helper(
            'REPO_OWNER="$(stat -Lc %u:%g -- "$REPO")"\n'
            'require_private_input "$P2_APK" P2-APK\n'
        )
        self.assertEqual(output_directory_apk.returncode, 1)
        self.assertIn("P2-APK is not an exact allowlisted read-only input", output_directory_apk.stderr)

        prefix_sibling = self.run_helper(
            'REPO_OWNER="$(stat -Lc %u:%g -- "$REPO")"\n'
            'require_private_input "$RAW.evil" prefix-sibling\n'
        )
        self.assertEqual(prefix_sibling.returncode, 1)
        self.assertIn(
            "prefix-sibling is not an exact allowlisted read-only input",
            prefix_sibling.stderr,
        )

    def test_namespace_contract_uses_pid1_and_parent_identity_not_nspid_depth(self) -> None:
        self.assertIn('"$BASHPID" == 1', self.source)
        self.assertIn('"$(awk \'/^NSpid:/ { print $NF }\' /proc/1/status)" == 1', self.source)
        self.assertIn('[[ "$self_namespace" != "$parent_value" ]]', self.source)
        self.assertNotIn("print NF", self.source)
        self.assertIn("--parent-pidns", self.launcher)

    def test_namespace_contract_parses_positional_parameters_above_nine(self) -> None:
        arguments = [
            "--inside-private-namespace",
            "--sealed-script-sha256",
            "0" * 64,
            "--caller-uid",
            "1000",
            "--caller-gid",
            "1000",
            "--parent-mntns",
            "mnt:[1]",
            "--parent-netns",
            "net:[2]",
            "--parent-pidns",
            "pid:[3]",
            "--parent-ipcns",
            "ipc:[4]",
            "--parent-utsns",
            "uts:[5]",
            "--canonical-source",
            str(SCRIPT),
        ]
        result = subprocess.run(
            ["bash", str(SCRIPT), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("expected only the sealed-launcher namespace contract", result.stderr)
        self.assertIn("root entry is not the fixed /run seal", result.stderr)
        self.assertIn('"${10}" == --parent-netns', self.source)
        self.assertIn("PARENT_UTSNS=${17}", self.source)
        self.assertIn('"${18}" == --canonical-source', self.source)

    def test_repository_root_is_canonically_derived_without_host_identity_leakage(self) -> None:
        self.assertNotIn("/home/microstar-lnx", self.source)
        self.assertNotIn("/home/microstar-lnx", self.launcher)
        self.assertIn("derive_repo_root", self.source)
        self.assertIn("LAUNCHER_CANONICAL", self.launcher)
        self.assertIn('--canonical-source "$canonical_source"', self.launcher)
        derived = self.run_helper('printf "%s\\n" "$REPO"\n')
        self.assertEqual(derived.returncode, 0, derived.stderr)
        self.assertEqual(derived.stdout, f"{REPO}\n")

    def test_launcher_accepts_relative_canonical_invocation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            scripts = repository / "scripts/lmi_p2_d114"
            scripts.mkdir(parents=True)
            launcher = scripts / LAUNCHER.name
            injector = scripts / SCRIPT.name
            shutil.copy2(LAUNCHER, launcher)
            shutil.copy2(SCRIPT, injector)
            launcher.chmod(0o755)
            injector.chmod(0o755)
            result = subprocess.run(
                [f"./scripts/lmi_p2_d114/{LAUNCHER.name}"],
                cwd=repository,
                check=False,
                capture_output=True,
                text=True,
                timeout=10,
            )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("launcher source path is unsafe", result.stderr)
        self.assertNotIn("could not derive canonical repository root", result.stderr)
        self.assertNotIn("launcher is not running from its canonical project path", result.stderr)

    def test_ext4_normalization_is_allocated_only_zero_proven_and_tree_identical(self) -> None:
        host_bound.require_path(host_bound.REPO / "private/lmi-p1/recovery/d110-d114")
        host_bound.require_tree_snapshot_tools()
        normalization = self.injection_policy_lock["normalization"]
        self.assertEqual(
            normalization["fixed"]["allocated_only_command"],
            ["e2image", "-r", "-a", "-p"],
        )
        for fragment in (
            '"$E2IMAGE" -r -a -p "$image" "$normalized"',
            '"$E2IMAGE" -r -a -p "$normalized" "$proof"',
            'cmp -s -- "$normalized" "$proof"',
            '"$DEBUGFS" -R "testb $block"',
            "Block $block not in use",
            'mount -t ext4 -o ro,noload,nodev,nosuid,noexec',
            'cmp -s -- "$FULL_TREE_AFTER" "$FULL_TREE_NORMALIZED"',
            "JOURNAL_INACTIVE_FIRST_BLOCK=327681",
            "JOURNAL_INACTIVE_BLOCK_COUNT=16383",
            "REVIEWED_FREED_BLOCK_ONE=586227",
            "REVIEWED_FREED_BLOCK_TWO=661606",
            "all_free_blocks_zero",
            "tree_identity_sha256",
        ):
            self.assertIn(fragment, self.source)
        result = self.run_helper('verify_journal_extent "$INPUT"\n')
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_disposable_namespace_contract_when_kernel_allows_it(self) -> None:
        parent = {
            name: os.readlink(f"/proc/self/ns/{name}") for name in ("mnt", "net", "pid", "ipc", "uts")
        }
        body = (
            'source "$1"\n'
            + "\n".join(f"PARENT_{name.upper()}NS='{value}'" for name, value in parent.items())
            + "\nverify_private_namespaces\n"
        )
        result = subprocess.run(
            [
                "/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--net", "--pid", "--fork",
                "--ipc", "--uts", "--mount-proc=/proc", "--", "/bin/bash", "--noprofile", "--norc",
                "-c", body, "namespace-test", str(SCRIPT),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if result.returncode and re.search(r"Operation not permitted|Permission denied|unshare failed", result.stderr):
            self.skipTest(f"kernel/outer sandbox forbids disposable namespaces: {result.stderr.strip()}")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_child_userns_root_cannot_traverse_an_unmapped_0700_ancestor(self) -> None:
        restricted = Path("/root")
        metadata = restricted.stat()
        if (
            not restricted.is_dir()
            or metadata.st_uid == os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            self.skipTest("host has no suitable unmapped mode-0700 ancestor fixture")
        with tempfile.TemporaryDirectory() as temporary:
            bridge = Path(temporary) / "mapped-root-bridge"
            bridge.mkdir(mode=0o700)
            (bridge / "sentinel").write_text("reachable\n", encoding="utf-8")
            body = (
                '[[ "$(id -u)" == 0 ]]\n'
                'if cd -- "$1" 2>/dev/null; then exit 90; fi\n'
                '[[ "$(cat -- "$2/sentinel")" == reachable ]]\n'
            )
            result = subprocess.run(
                [
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--fork",
                    "--",
                    "/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    body,
                    "path-walk-test",
                    str(restricted),
                    str(bridge),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        if result.returncode and re.search(
            r"Operation not permitted|Permission denied|unshare failed", result.stderr
        ):
            self.skipTest(f"kernel/outer sandbox forbids disposable user namespaces: {result.stderr.strip()}")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_root_owned_bind_bridge_is_identity_checked_and_leaves_no_residue(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            bridge_parent = root / "seal"
            sources = [root / name for name in ("image", "tools", "keys", "runtime")]
            bridge_parent.mkdir(mode=0o700)
            for source in sources:
                source.mkdir(mode=0o700)
            body = (
                'source "$1"\n'
                'mount --make-rprivate /\n'
                'MOUNTPOINT=$3\nTOOL_CLOSURE=$4\nKEY_CLOSURE=$5\nRUNTIME_CLOSURE=$6\n'
                'create_source_bridge "$2" "$MOUNTPOINT" "$TOOL_CLOSURE" "$KEY_CLOSURE" "$RUNTIME_CLOSURE"\n'
                'bridge_dir=$SOURCE_BRIDGE_DIR\n'
                'verify_source_bridge_mount "$MOUNTPOINT" "$SOURCE_BRIDGE_IMAGE" "$SOURCE_BRIDGE_IMAGE_SOURCE_ID" "$SOURCE_BRIDGE_IMAGE_MOUNT_ID"\n'
                'verify_source_bridge_mount "$TOOL_CLOSURE" "$SOURCE_BRIDGE_TOOLS" "$SOURCE_BRIDGE_TOOLS_SOURCE_ID" "$SOURCE_BRIDGE_TOOLS_MOUNT_ID"\n'
                'verify_source_bridge_mount "$KEY_CLOSURE" "$SOURCE_BRIDGE_KEYS" "$SOURCE_BRIDGE_KEYS_SOURCE_ID" "$SOURCE_BRIDGE_KEYS_MOUNT_ID"\n'
                'verify_source_bridge_mount "$RUNTIME_CLOSURE" "$SOURCE_BRIDGE_RUNTIME" "$SOURCE_BRIDGE_RUNTIME_SOURCE_ID" "$SOURCE_BRIDGE_RUNTIME_MOUNT_ID"\n'
                '# Model a signal after mount(2) but before its mount ID assignment.\n'
                'SOURCE_BRIDGE_RUNTIME_MOUNT_ID=\n'
                'normal_unmounts=0\n'
                'umount() { normal_unmounts=$((normal_unmounts + 1)); /usr/bin/umount "$@"; }\n'
                'cleanup_source_bridge\n'
                '[[ "$normal_unmounts" == 4 ]]\n'
                '[[ -z "$SOURCE_BRIDGE_DIR$SOURCE_BRIDGE_IMAGE$SOURCE_BRIDGE_TOOLS$SOURCE_BRIDGE_KEYS$SOURCE_BRIDGE_RUNTIME" ]]\n'
                '[[ ! -e "$bridge_dir" && -z "$(find "$2" -mindepth 1 -maxdepth 1 -print -quit)" ]]\n'
            )
            result = subprocess.run(
                [
                    "/usr/bin/unshare",
                    "--user",
                    "--map-root-user",
                    "--mount",
                    "--fork",
                    "--",
                    "/bin/bash",
                    "--noprofile",
                    "--norc",
                    "-c",
                    body,
                    "bridge-test",
                    str(SCRIPT),
                    str(bridge_parent),
                    *map(str, sources),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        if result.returncode and re.search(
            r"Operation not permitted|Permission denied|unshare failed", result.stderr
        ):
            self.skipTest(f"kernel/outer sandbox forbids disposable mount namespaces: {result.stderr.strip()}")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_bwrap_uses_only_run_bridge_sources_and_cleanup_precedes_rootfs_unmount(self) -> None:
        for fragment in (
            'create_source_bridge /run/lmi-p2-d114-inject "$MOUNTPOINT" "$TOOL_CLOSURE" "$KEY_CLOSURE" "$RUNTIME_CLOSURE"',
            '--bind "$SOURCE_BRIDGE_IMAGE" /image',
            '--ro-bind "$SOURCE_BRIDGE_TOOLS" /tools',
            '--ro-bind "$SOURCE_BRIDGE_KEYS" /keys',
            '--ro-bind "$SOURCE_BRIDGE_RUNTIME" /runtime',
            "source-bindings:checked-root-owned-run-bridge;outer-private-mountns",
            'current_mount_id="$(source_bridge_mount_id_of "$target")"',
            '[[ "$(directory_identity_of "$target")" == "$expected_source_id" ]]',
        ):
            self.assertIn(fragment, self.source)
        self.assertNotRegex(
            self.source,
            r'--(?:ro-)?bind "\$(?:MOUNTPOINT|TOOL_CLOSURE|KEY_CLOSURE|RUNTIME_CLOSURE)"',
        )
        cleanup = self.source[
            self.source.index("cleanup() {") : self.source.index("verify_runtime_closure()")
        ]
        self.assertLess(
            cleanup.index('cleanup_source_bridge || cleanup_failed=1'),
            cleanup.index('umount -- "$MOUNTPOINT"'),
        )
        bridge_cleanup = self.source[
            self.source.index("cleanup_source_bridge() {") : self.source.index("create_source_bridge()")
        ]
        single_mount_cleanup = self.source[
            self.source.index("cleanup_source_bridge_mount() {") : self.source.index(
                "clear_source_bridge_state()"
            )
        ]
        self.assertEqual(single_mount_cleanup.count('umount -- "$target" || return 1'), 1)
        order = [
            bridge_cleanup.index('"$SOURCE_BRIDGE_RUNTIME"'),
            bridge_cleanup.index('"$SOURCE_BRIDGE_KEYS"'),
            bridge_cleanup.index('"$SOURCE_BRIDGE_TOOLS"'),
            bridge_cleanup.index('"$SOURCE_BRIDGE_IMAGE"'),
        ]
        self.assertEqual(order, sorted(order))
        self.assertNotIn("umount -l", self.source)
        self.assertNotIn("--lazy", self.source)

    def test_loop_detach_is_inode_checked_and_state_is_immediately_cleared(self) -> None:
        for fragment in (
            "verify_loop_backing_identity || return 1",
            'losetup --detach "$LOOP_DEVICE" || return 1\n\tLOOP_DEVICE=',
            'if [[ -n "$LOOP_DEVICE" ]]; then\n\t\tdetach_loop_checked',
            'LOOP_BACKING_ID="$(stat -Lc %d:%i -- "$SCRATCH_IMAGE")"',
        ):
            self.assertIn(fragment, self.source)
        result = self.run_helper(
            "verify_loop_device_identity() { return 0; }\n"
            "loop_backing_path_or_empty() { printf '/scratch\\n'; }\n"
            "verify_loop_backing_identity() { return 0; }\n"
            "losetup() { [[ \"$1\" == --detach && \"$2\" == /dev/loop-test ]]; }\n"
            "LOOP_DEVICE=/dev/loop-test\nLOOP_DEVICE_ID=x\nLOOP_BACKING_ID=y\n"
            "detach_loop_checked\n[[ -z \"$LOOP_DEVICE$LOOP_DEVICE_ID$LOOP_BACKING_ID\" ]]\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_loop_attach_records_cleanup_identity_before_attach_and_never_detaches_foreign_backing(self) -> None:
        backing_at = self.source.index('LOOP_BACKING_ID="$(stat -Lc %d:%i -- "$SCRATCH_IMAGE")"')
        candidate_at = self.source.index('LOOP_DEVICE="$(losetup --find)"', backing_at)
        device_id_at = self.source.index('LOOP_DEVICE_ID="$(stat -Lc %t:%T:%r -- "$LOOP_DEVICE")"', candidate_at)
        attach_at = self.source.index('losetup "$LOOP_DEVICE" "$SCRATCH_IMAGE"', device_id_at)
        self.assertLess(backing_at, candidate_at)
        self.assertLess(candidate_at, device_id_at)
        self.assertLess(device_id_at, attach_at)
        result = self.run_helper(
            "verify_loop_device_identity() { return 0; }\n"
            "loop_backing_path_or_empty() { printf '/foreign\\n'; }\n"
            "verify_loop_backing_identity() { return 1; }\n"
            "losetup() { return 91; }\n"
            "LOOP_DEVICE=/dev/loop-test\nLOOP_DEVICE_ID=x\nLOOP_BACKING_ID=y\n"
            "if detach_loop_checked; then exit 90; fi\n"
            "[[ \"$LOOP_DEVICE:$LOOP_DEVICE_ID:$LOOP_BACKING_ID\" == /dev/loop-test:x:y ]]\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_apk_runs_in_bwrap_with_child_verified_nnp_caps_and_private_outer_net(self) -> None:
        for fragment in (
            '"$RUNTIME_CLOSURE/bwrap" --unshare-user --unshare-pid --unshare-uts --unshare-ipc',
            "--cap-drop ALL",
            "NoNewPrivs:",
            "CapInh:|CapPrm:|CapEff:|CapBnd:|CapAmb:",
            "0000000000000000",
            "</proc/net/dev",
            "--no-logfile --no-network --no-cache --no-scripts --repositories-file /dev/null",
        ):
            self.assertIn(fragment, self.source)
        self.assertNotIn('"$TOOL_CLOSURE/apk.static" \\\n\t\t--root "$MOUNTPOINT"', self.source)
        self.assertEqual(
            self.source.count(
                '"$RUNTIME_CLOSURE/bwrap" --unshare-user --unshare-pid --unshare-uts --unshare-ipc'
            ),
            2,
        )
        self.assertIn(
            "proot -r /image -q /tools/qemu-aarch64 -w / /usr/libexec/lmi-p2-d114/config-lifecycle install",
            self.source,
        )

    def test_apk_transaction_logging_is_disabled_and_existing_log_is_sanitized(self) -> None:
        apk_command = self.injection_policy_lock["commands"]["apk"]
        self.assertEqual(apk_command.count("--no-logfile"), 1)
        self.assertLess(apk_command.index("--no-logfile"), apk_command.index("add"))
        self.assertEqual(self.source.count("--no-logfile"), 2)
        self.assertIn('local apk_log=$MOUNTPOINT/var/log/apk.log', self.source)
        self.assertEqual(self.injection_policy_lock["sanitization"]["apk_log"], "empty")

    def test_bwrap_environment_is_cleared_exact_and_lifecycle_only_gets_proot_switch(self) -> None:
        apk_bwrap_env = (
            "--clearenv \\\n"
            "\t\t--setenv HOME /root --setenv LANG C --setenv LC_ALL C \\\n"
            "\t\t--setenv PATH /usr/sbin:/usr/bin:/sbin:/bin --setenv PWD / --setenv TZ UTC"
        )
        lifecycle_bwrap_env = apk_bwrap_env.replace(
            "--setenv PWD /", "--setenv PROOT_NO_SECCOMP 1 --setenv PWD /"
        )
        self.assertEqual(self.source.count(apk_bwrap_env), 1)
        self.assertEqual(self.source.count(lifecycle_bwrap_env), 1)
        self.assertEqual(self.source.count("--setenv PWD /"), 2)
        self.assertEqual(self.source.count("--setenv PROOT_NO_SECCOMP 1"), 1)
        self.assertNotIn("--setenv PROOT_NO_SECCOMP 1", self.source[: self.source.index("sandbox-entry.sh apk")])
        self.assertIn("sandbox stage apk failed with status $sandbox_status", self.source)
        self.assertIn("sandbox stage lifecycle failed with status $sandbox_status", self.source)

        apk_env = "env:clear;HOME=/root;LANG=C;LC_ALL=C;PATH=/usr/sbin:/usr/bin:/sbin:/bin;PWD=/;TZ=UTC"
        lifecycle_env = apk_env.replace(";PWD=/", ";PROOT_NO_SECCOMP=1;PWD=/")
        self.assertEqual(self.injection_policy_lock["commands"]["apk"][3], apk_env)
        self.assertEqual(self.injection_policy_lock["commands"]["lifecycle"][3], lifecycle_env)
        self.assertIn(apk_env, self.source)
        self.assertIn(lifecycle_env, self.source)

    def test_generated_sandbox_network_parser_is_strict_and_capability_gates_run_first(self) -> None:
        valid_status = "\n".join(
            [
                "CapInh:\t0000000000000000",
                "CapPrm:\t0000000000000000",
                "CapEff:\t0000000000000000",
                "CapBnd:\t0000000000000000",
                "CapAmb:\t0000000000000000",
                "NoNewPrivs:\t1",
            ]
        ) + "\n"
        header_one = "Inter-|   Receive                                                |  Transmit\n"
        header_two = (
            " face |bytes    packets errs drop fifo frame compressed multicast|"
            "bytes    packets errs drop fifo colls carrier compressed\n"
        )
        lo = "    lo: 120 2 0 0 0 0 0 0 120 2 0 0 0 0 0 0\n"
        eth0 = "  eth0: 240 3 0 0 0 0 0 0 240 3 0 0 0 0 0 0\n"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            entry = root / "sandbox-entry.sh"
            status_fixture = root / "status"
            net_fixture = root / "net-dev"
            harness = root / "sandbox-entry-fixture.sh"
            result = self.run_helper('write_sandbox_entry "$2"\n', entry)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                digest(entry),
                self.injection_policy_lock["runtime"]["fixed"]["sandbox_entry_sha256"],
            )
            self.assertEqual(
                digest(SCRIPT),
                self.injection_policy_lock["runtime"]["sealed_injector_script_sha256"],
            )
            entry_source = entry.read_text(encoding="utf-8")
            self.assertEqual(entry_source.count("/proc/self/status"), 1)
            self.assertEqual(entry_source.count("/proc/net/dev"), 1)
            self.assertLess(
                entry_source.index('[ "$cap_lines" = 5 ]'),
                entry_source.index("net_lines=0"),
            )
            apk_exports = "\n".join(
                (
                    "export HOME='/root'",
                    "export LANG='C'",
                    "export LC_ALL='C'",
                    "export PATH='/usr/sbin:/usr/bin:/sbin:/bin'",
                    "export PWD='/'",
                    "export TZ='UTC'",
                )
            )
            lifecycle_exports = apk_exports.replace(
                "export PWD='/'", "export PROOT_NO_SECCOMP='1'\nexport PWD='/'"
            )
            self.assertIn(f'apk_env="{apk_exports}"', entry_source)
            self.assertIn(f'lifecycle_env="{lifecycle_exports}"', entry_source)
            self.assertEqual(entry_source.count("actual=$(export -p)"), 1)
            self.assertNotRegex(entry_source, r"\b(?:eval|source)\b")

            apk_exec = "exec /tools/apk.static --root /image --arch aarch64 --keys-dir /keys --no-logfile --no-network --no-cache --no-scripts --repositories-file /dev/null --force-non-repository add /tools/sixrow.apk /tools/p2.apk"
            lifecycle_exec = "exec /runtime/ld-linux-x86-64.so.2 --library-path /runtime /runtime/proot -r /image -q /tools/qemu-aarch64 -w / /usr/libexec/lmi-p2-d114/config-lifecycle install"
            self.assertEqual(entry_source.count(apk_exec), 1)
            self.assertEqual(entry_source.count(lifecycle_exec), 1)
            harness_source = entry_source.replace(apk_exec, "exit 0").replace(
                lifecycle_exec, "exit 0"
            )

            def run_entry(
                net_dev: str,
                status: str = valid_status,
                *,
                arguments: tuple[str, ...] = ("probe",),
                env: dict[str, str] | None = None,
                cwd: Path = Path("/"),
            ) -> subprocess.CompletedProcess[str]:
                status_fixture.write_text(status, encoding="utf-8")
                net_fixture.write_text(net_dev, encoding="utf-8")
                harness.write_text(
                    harness_source.replace("/proc/self/status", str(status_fixture)).replace(
                        "/proc/net/dev", str(net_fixture)
                    ),
                    encoding="utf-8",
                )
                return subprocess.run(
                    ["/usr/bin/dash", str(harness), *arguments],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=env,
                    cwd=cwd,
                )

            network_cases = {
                "headers-and-one-lo": (header_one + header_two + lo, 127),
                "foreign-interface": (header_one + header_two + eth0, 123),
                "lo-then-foreign": (header_one + header_two + lo + eth0, 123),
                "duplicate-lo": (header_one + header_two + lo + lo, 123),
                "missing-lo": (header_one + header_two, 124),
                "malformed-first-header": (
                    header_one.replace("Receive", "RX") + header_two + lo,
                    123,
                ),
                "malformed-second-header": (
                    header_one + header_two.replace("carrier", "carriers") + lo,
                    123,
                ),
                "missing-interface-colon": (
                    header_one + header_two + lo.replace(":", "", 1),
                    123,
                ),
                "malformed-interface-fields": (
                    header_one + header_two + "    lo: 1 2 3\n",
                    123,
                ),
                "nonnumeric-interface-field": (
                    header_one + header_two + lo.replace("120 2", "x 2", 1),
                    123,
                ),
            }
            for name, (net_dev, expected_status) in network_cases.items():
                with self.subTest(name=name):
                    completed = run_entry(net_dev)
                    self.assertEqual(completed.returncode, expected_status, completed.stderr)

            precedence_cases = {
                "nonzero-capability": (
                    valid_status.replace(
                        "CapInh:\t0000000000000000", "CapInh:\t0000000000000001"
                    ),
                    120,
                ),
                "no-new-privs-disabled": (
                    valid_status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0"),
                    121,
                ),
                "missing-capability-line": (
                    valid_status.replace("CapAmb:\t0000000000000000\n", ""),
                    122,
                ),
            }
            for name, (status, expected_status) in precedence_cases.items():
                with self.subTest(name=name):
                    completed = run_entry(header_one + header_two + eth0, status)
                    self.assertEqual(completed.returncode, expected_status, completed.stderr)

            fixed_env = {
                "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                "HOME": "/root",
                "LANG": "C",
                "LC_ALL": "C",
                "PWD": "/",
                "TZ": "UTC",
            }
            completed = run_entry(header_one + header_two + lo, arguments=("apk",), env=fixed_env)
            self.assertEqual(completed.returncode, 0, completed.stderr)
            for name, mutated in {
                "wrong-path": {**fixed_env, "PATH": "/bin"},
                "missing-home": {key: value for key, value in fixed_env.items() if key != "HOME"},
                "unexpected-proot-switch": {**fixed_env, "PROOT_NO_SECCOMP": "1"},
                "injected": {**fixed_env, "INJECTED": "bad"},
            }.items():
                with self.subTest(environment=name):
                    completed = run_entry(
                        header_one + header_two + lo, arguments=("apk",), env=mutated
                    )
                    self.assertEqual(completed.returncode, 128, completed.stderr)

            for name, mutated in {
                "missing-pwd": {key: value for key, value in fixed_env.items() if key != "PWD"},
                "wrong-pwd": {**fixed_env, "PWD": "/wrong"},
            }.items():
                with self.subTest(environment=name):
                    completed = run_entry(
                        header_one + header_two + lo,
                        arguments=("apk",),
                        env=mutated,
                        cwd=root,
                    )
                    self.assertEqual(completed.returncode, 128, completed.stderr)

            lifecycle_env = {**fixed_env, "PROOT_NO_SECCOMP": "1"}
            completed = run_entry(
                header_one + header_two + lo, arguments=("lifecycle",), env=lifecycle_env
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            completed = run_entry(
                header_one + header_two + lo, arguments=("lifecycle",), env=fixed_env
            )
            self.assertEqual(completed.returncode, 128, completed.stderr)

    def test_pinned_host_only_proot_recursive_exec_when_namespaces_are_available(self) -> None:
        acquisition = REPO / "private/lmi-p1/calibration/acquisition-root"
        rootfs = acquisition / "work-proot-chroot2/chroot_rootfs_xiaomi-lmi"
        proot = acquisition / "proot-root/usr/bin/proot"
        talloc = acquisition / "proot-root/usr/lib/x86_64-linux-gnu/libtalloc.so.2.4.3"
        qemu = (
            acquisition
            / "work-proot-chroot2/chroot_native-pre-rootfs-calibration/usr/bin/qemu-aarch64"
        )
        loader = Path("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
        libc = Path("/usr/lib/x86_64-linux-gnu/libc.so.6")
        dash = Path("/usr/bin/dash")
        bwrap = Path("/usr/bin/bwrap")
        expected = {
            bwrap: "0abea81db798ebf6b4742ac0664802d97521547a353c2a0dbdc21d76cbbfd2c0",
            dash: "c626229526bb58ec2d0f585f3c3ae1412e6f973b4353385042d11c38d8426917",
            loader: "223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb",
            libc: "d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0",
            proot: "e95e0da51b8948c38743704a0e751276faf95b176e11dc4f1f99bca7157fb2ab",
            talloc: "261d4fd32e2341567eeafba6d4d75684c8eeaedb9bcda04f1fd69792e6197634",
            qemu: "4a2fd0e1fb9c1ba3f63f81113ead9e96e0cdb513c64c83bb2ecfc94e1df05e4c",
            rootfs / "bin/busybox": "a8d8e2b9898537c8b9fb4fcb3d9c95c2e09fecc76c9adfb19ac75965e1a4f19b",
            rootfs / "etc/alpine-release": "bd55fa8916c0153c4cca02f5149f15fd22cc7049e7a4101c72bb5e5a5a2b0365",
        }
        unavailable = [str(path) for path, sha256 in expected.items() if not path.is_file() or digest(path) != sha256]
        if unavailable or not rootfs.is_dir():
            self.skipTest("exact host-only PRoot calibration closure is unavailable")

        gate_and_probe = (
            "cap_lines=0; nonewprivs=0; "
            "while read -r key value rest; do "
            'case "$key" in '
            'CapInh:|CapPrm:|CapEff:|CapBnd:|CapAmb:) [ "$value" = 0000000000000000 ] || exit 120; cap_lines=$((cap_lines + 1));; '
            'NoNewPrivs:) [ "$value" = 1 ] || exit 121; nonewprivs=1;; esac; '
            "done </proc/self/status; "
            '[ "$cap_lines" = 5 ] && [ "$nonewprivs" = 1 ] || exit 122; '
            "exec /runtime/ld-linux-x86-64.so.2 --library-path /runtime /runtime/proot "
            "-r /image -q /tools/qemu-aarch64 -w / /bin/sh -c "
            "'printf \"recursive-ok\\n\"; id -u; stat -c %a:%u:%g /etc/alpine-release; "
            "cat /etc/alpine-release; /bin/true'"
        )
        command = [
            str(bwrap),
            "--unshare-user", "--unshare-pid", "--unshare-uts", "--unshare-ipc", "--unshare-net",
            "--die-with-parent", "--new-session", "--uid", "0", "--gid", "0", "--cap-drop", "ALL",
            "--clearenv",
            "--setenv", "HOME", "/root",
            "--setenv", "LANG", "C",
            "--setenv", "LC_ALL", "C",
            "--setenv", "PATH", "/usr/sbin:/usr/bin:/sbin:/bin",
            "--setenv", "PROOT_NO_SECCOMP", "1",
            "--setenv", "PWD", "/",
            "--setenv", "TZ", "UTC",
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp",
            "--ro-bind", str(rootfs), "/image",
            "--dir", "/tools", "--ro-bind", str(qemu), "/tools/qemu-aarch64",
            "--dir", "/runtime",
            "--ro-bind", str(proot), "/runtime/proot",
            "--ro-bind", str(talloc), "/runtime/libtalloc.so.2",
            "--ro-bind", str(libc), "/runtime/libc.so.6",
            "--ro-bind", str(loader), "/runtime/ld-linux-x86-64.so.2",
            "--ro-bind", str(dash), "/runtime/dash",
            "--chdir", "/", "--",
            "/runtime/ld-linux-x86-64.so.2", "--library-path", "/runtime", "/runtime/dash",
            "-c", gate_and_probe,
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=20,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"},
        )
        if completed.returncode and re.search(
            r"Operation not permitted|Permission denied|No permissions to create new namespace",
            completed.stderr,
        ):
            self.skipTest(f"kernel/outer sandbox forbids disposable PRoot probe: {completed.stderr.strip()}")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "recursive-ok\n0\n644:0:0\n3.24.0\n")

    def test_strict_installed_record_parsers_accept_only_exact_c_and_a_records(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            database, record = root / "installed", root / "record"
            records = (
                (
                    "validate_p2_installed_record",
                    self.valid_p2_installed_record(),
                    "C:Q1CgJ9oAvCtPMD0gpMqjIRwUt4gow=",
                    "V:0.1.0-r1",
                ),
                (
                    "validate_sixrow_installed_record",
                    self.valid_sixrow_installed_record(),
                    "C:Q1z+kF3cP7AS8SIoqzAnBB/K89PAc=",
                    "V:14.0.2-r1",
                ),
            )
            for parser, baseline, checksum, version in records:
                with self.subTest(parser=parser):
                    database.write_text(baseline, encoding="utf-8")
                    result = self.run_helper(f'{parser} "$2" "$3"\n', database, record)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(record.read_text(encoding="utf-8"), baseline)
                mutations = {
                    "wrong-c": baseline.replace(checksum, "C:Q1" + "A" * 28 + "="),
                    "missing-a": baseline.replace("a:0:0:755\n", "", 1),
                    "wrong-a": baseline.replace("a:0:0:755", "a:0:0:775", 1),
                    "duplicate-a": baseline.replace("a:0:0:755\n", "a:0:0:755\na:0:0:755\n", 1),
                    "unknown": baseline.replace(f"{version}\n", f"{version}\nX:unexpected\n"),
                    "duplicate-scalar": baseline.replace(f"{version}\n", f"{version}\n{version}\n"),
                }
                for name, mutated in mutations.items():
                    with self.subTest(parser=parser, mutation=name):
                        database.write_text(mutated, encoding="utf-8")
                        record.unlink(missing_ok=True)
                        result = self.run_helper(f'{parser} "$2" "$3"\n', database, record)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertFalse(record.exists())

    def test_package_verification_covers_exact_deps_files_db_scripts_triggers_keys_and_delta(self) -> None:
        for fragment in (
            "P2 package strict record parser rejected checksum, fields, attributes, dependencies, or inventory",
            "six-row package strict record parser rejected checksum, fields, attributes, dependencies, or inventory",
            'expected_attr["usr/libexec/lmi-p2-d114/config-lifecycle"]="0:0:755"',
            'count["C"] != 1 || value["C"] != package_checksum',
            "target package file inventory mismatch",
            "target package installed checksum mismatch",
            "non-target installed database records changed",
            "non-target scripts.tar.gz members changed",
            "APK triggers database changed",
            "image APK key inventory changed",
            "filesystem delta escaped the exact package/lifecycle allowlist",
            "FULL_DELTA_SHA256",
        ):
            self.assertIn(fragment, self.source)

    def test_atomic_bundle_publication_never_exposes_a_bare_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.bundle"
            output = root / "final.bundle"
            source.mkdir(mode=0o700)
            image = source / "rootfs.ext4"
            attestation = source / "attestation.json"
            image.write_bytes(b"image")
            attestation.write_bytes(b"attestation")
            source.chmod(0o750)
            image.chmod(0o640)
            attestation.chmod(0o640)
            owner = f"{os.getuid()}:{os.getgid()}"
            result = self.run_helper(
                'publish_bundle "$2" "$3" "$(sha256_of "$2/rootfs.ext4")" "$(sha256_of "$2/attestation.json")" "$4"\n',
                source,
                output,
                Path(owner),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(source.exists())
            self.assertEqual({path.name for path in output.iterdir()}, {"rootfs.ext4", "attestation.json"})
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o750)
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)
                self.assertEqual(path.stat().st_nlink, 1)

    def test_bundle_publication_refuses_overwrite_or_digest_mismatch(self) -> None:
        for occupied in (False, True):
            with self.subTest(occupied=occupied), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                source, output = root / "source.bundle", root / "final.bundle"
                source.mkdir(mode=0o750)
                (source / "rootfs.ext4").write_bytes(b"image")
                (source / "attestation.json").write_bytes(b"attestation")
                for path in source.iterdir():
                    path.chmod(0o640)
                if occupied:
                    output.mkdir()
                result = self.run_helper(
                    'if publish_bundle "$2" "$3" bad bad "$4"; then exit 90; fi\n',
                    source,
                    output,
                    Path(f"{os.getuid()}:{os.getgid()}"),
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(source.exists())

    def test_attestation_v3_binds_lineage_geometry_packages_sanitation_runtime_and_tools(self) -> None:
        self.assertIn("lmi-p2-d114-rootfs-injection-attestation/v3", self.source)
        for field in (
            "candidate_rebuild_lock_schema", "raw_sha256", "sparse_sha256", "repair_epoch",
            "filesystem_delta_sha256", "geometry_sha256", "scripts_db_sha256", "triggers_sha256",
            "key_inventory_sha256", "mount_loop", "namespaces", "proc_version_sha256",
            "sealed_script_sha256", "bubblewrap_sha256", "e2fsck_sha256", "getfattr_sha256",
            "lsattr_libe2p_sha256", "lsattr_libcom_err_sha256", "lsattr_sha256", "simg2img_sha256",
            "injector_runtime_lock_schema", "injector_runtime_lock_sha256", "sandbox_entry_sha256",
            '\\"owner\\":\\"0:$CALLER_GID\\"', '\\"mode\\":\\"0640\\"',
            '\\"sandbox_path\\":\\"/tools/p2.apk\\"',
            '\\"sandbox_path\\":\\"/tools/sixrow.apk\\"',
            "hardware_test_only", "release_eligible", "shadow_backup",
        ):
            self.assertIn(field, self.source)
        self.assertNotIn("setpriv", self.source)
        self.assertIn("debugfs_sha256", self.source)
        self.assertIn("e2image_sha256", self.source)
        self.assertIn('chown 0:"$CALLER_GID"', self.source)
        self.assertIn('chmod 0750 -- "$PUBLISH_TMP"', self.source)
        self.assertIn('chmod 0640 -- "$PUBLISH_TMP/rootfs.ext4" "$PUBLISH_TMP/attestation.json"', self.source)
        self.assertIn("publish_bundle", self.source)
        self.assertNotIn("publish_pair", self.source)

    def test_complete_producer_payload_is_exact_canonical_json(self) -> None:
        policy = self.injection_policy_lock

        def fixture_sha(label: str) -> str:
            return hashlib.sha256(label.encode("ascii")).hexdigest()

        output_hashes = {
            field: fixture_sha(field) for field in policy["output"]["sha256_fields"]
        }
        output = copy.deepcopy(policy["output"]["fixed"])
        output.update(output_hashes)
        output["owner"] = f"0:{os.getgid()}"

        normalization = copy.deepcopy(policy["normalization"]["fixed"])
        normalization.update(
            {
                "pre_normalization_sha256": fixture_sha("pre-normalization"),
                "proof_sha256": output["sha256"],
                "sparse_st_blocks": 1234,
                "tree_identity_sha256": fixture_sha("tree-identity"),
            }
        )
        namespaces = {
            name: os.readlink(f"/proc/self/ns/{name}")
            for name in policy["runtime"]["namespace_fields"]
        }
        runtime = copy.deepcopy(policy["runtime"]["fixed"])
        runtime.update(
            {
                "kernel_release": "6.6.87.2-fixture",
                "mount_loop": {
                    "backing_identity": "123:456",
                    "block_identity": "7:0:1792",
                    "mount_options": "ext4 rw,nosuid,nodev,relatime",
                },
                "namespaces": namespaces,
                "proc_version_sha256": fixture_sha("proc-version"),
                "sealed_script_sha256": digest(SCRIPT),
            }
        )
        expected = {
            "claims": copy.deepcopy(policy["claims"]),
            "commands": copy.deepcopy(policy["commands"]),
            "input": copy.deepcopy(policy["input"]),
            "normalization": normalization,
            "output": output,
            "runtime": runtime,
            "sanitization": copy.deepcopy(policy["sanitization"]),
            "schema": policy["attestation_schema"],
            "tools": copy.deepcopy(policy["tools"]),
        }
        canonical = (
            json.dumps(expected, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii")

        shell_values = {
            "ATTESTED_LOOP_BACKING_ID": runtime["mount_loop"]["backing_identity"],
            "ATTESTED_LOOP_DEVICE_ID": runtime["mount_loop"]["block_identity"],
            "CALLER_GID": os.getgid(),
            "FINAL_SHA256": output["sha256"],
            "FULL_DELTA_SHA256": output["filesystem_delta_sha256"],
            "GEOMETRY_SHA256": output["geometry_sha256"],
            "INSTALLED_DB_FINAL_SHA256": output["installed_db_sha256"],
            "KEY_INVENTORY_SHA256": output["key_inventory_sha256"],
            "KERNEL_RELEASE": runtime["kernel_release"],
            "MOUNT_OPTIONS": runtime["mount_loop"]["mount_options"],
            "NORMALIZATION_PROOF_SHA256": normalization["proof_sha256"],
            "NORMALIZATION_TREE_SHA256": normalization["tree_identity_sha256"],
            "NORMALIZED_ST_BLOCKS": normalization["sparse_st_blocks"],
            "P2_PACKAGE_RECORD_SHA256": output["p2_package_record_sha256"],
            "PRE_NORMALIZATION_SHA256": normalization["pre_normalization_sha256"],
            "PROC_VERSION_SHA256": runtime["proc_version_sha256"],
            "SANDBOX_ENTRY_SHA256": runtime["sandbox_entry_sha256"],
            "SCRIPTS_DB_FINAL_SHA256": output["scripts_db_sha256"],
            "SEALED_SCRIPT_SHA256": runtime["sealed_script_sha256"],
            "SIXROW_PACKAGE_RECORD_SHA256": output[
                "sixrow_package_record_sha256"
            ],
        }
        assignments = ["SCRATCH_DIR=$2"]
        assignments.extend(
            f"{name}={shlex.quote(str(value))}"
            for name, value in shell_values.items()
        )
        producer_start = self.source.index(
            '\tATTESTATION_TMP="$SCRATCH_DIR/attestation.json"'
        )
        producer_end = self.source.index(
            '\tATTESTATION_SHA256="$(sha256_of "$ATTESTATION_TMP")"',
            producer_start,
        )
        producer = self.source[producer_start:producer_end]

        with tempfile.TemporaryDirectory() as temporary:
            result = self.run_helper(
                "\n".join(assignments)
                + "\n"
                + producer
                + '\ncat -- "$ATTESTATION_TMP"\n',
                Path(temporary),
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = result.stdout.encode("ascii")
        self.assertEqual(json.loads(payload), expected)
        self.assertEqual(payload, canonical)

    def test_attestation_tool_fields_are_emitted_in_canonical_json_order(self) -> None:
        attestation_writer = self.source.split(
            'ATTESTATION_TMP="$SCRATCH_DIR/attestation.json"', 1
        )[1].split('chmod 0600 -- "$ATTESTATION_TMP"', 1)[0]
        fields = list(self.injection_policy_lock["tools"])
        self.assertEqual(fields, sorted(fields))
        for field in fields:
            self.assertIn(f'\\"{field}\\":', attestation_writer)
        self.assertIn(
            'gsub(/"dumpe2fs_sha256":/, "\\"debugfs_sha256\\":',
            attestation_writer,
        )
        self.assertIn(
            'gsub(/"getfattr_sha256":/, "\\"e2image_sha256\\":',
            attestation_writer,
        )

    def test_scratch_copy_is_independent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, scratch = root / "input.ext4", root / "scratch.ext4"
            original = b"fixture-input" * 1024
            source.write_bytes(original)
            result = self.run_helper(
                'exec {fixture_fd}<"$2"\ncopy_fd_to_scratch "$fixture_fd" "$3"\nprintf mutation >>"$3"\n',
                source,
                scratch,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(source.read_bytes(), original)
            self.assertEqual(stat.S_IMODE(scratch.stat().st_mode), 0o600)
            self.assertNotEqual((source.stat().st_dev, source.stat().st_ino), (scratch.stat().st_dev, scratch.stat().st_ino))


if __name__ == "__main__":
    unittest.main()
