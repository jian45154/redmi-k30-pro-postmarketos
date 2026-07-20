from __future__ import annotations

import os
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-p2"
HELPER = FILES / "lmi-account-lifecycle"


FAKE_ALPINE_TOOL = r'''#!/usr/bin/env python3
from __future__ import annotations

import os
from pathlib import Path
import sys


root = Path(os.environ["FAKE_ROOT"])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
passwd_path = root / "etc/passwd"
group_path = root / "etc/group"
shadow_path = root / "etc/shadow"
audit_path = Path(os.environ["FAKE_AUDIT"])


def records(path: Path) -> list[list[str]]:
    result = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line:
            result.append(line.split(":"))
    return result


def store(path: Path, entries: list[list[str]]) -> None:
    path.write_text(
        "".join(":".join(entry) + "\n" for entry in entries),
        encoding="utf-8",
    )


def mutate(label: str) -> None:
    with audit_path.open("a", encoding="utf-8") as stream:
        stream.write(label + "\n")


def injected_failure() -> None:
    if os.environ.get("FAKE_FAIL_ON") == command:
        print(f"injected {command} failure", file=sys.stderr)
        raise SystemExit(70)


def find(entries: list[list[str]], key: str, numeric_index: int) -> list[str] | None:
    for entry in entries:
        if entry[0] == key or entry[numeric_index] == key:
            return entry
    return None


if command == "getent":
    if len(args) not in (1, 2) or args[0] not in {"passwd", "group", "shadow"}:
        raise SystemExit(2)
    database = {
        "passwd": passwd_path,
        "group": group_path,
        "shadow": shadow_path,
    }[args[0]]
    entries = records(database)
    if len(args) == 1:
        for entry in entries:
            print(":".join(entry))
        raise SystemExit(0)
    numeric_index = 2 if args[0] != "passwd" else 2
    entry = find(entries, args[1], numeric_index)
    if entry is None:
        raise SystemExit(2)
    print(":".join(entry))
    raise SystemExit(0)

if command == "id":
    passwd_entries = records(passwd_path)
    group_entries = records(group_path)
    if len(args) == 1:
        name = args[0]
        entry = find(passwd_entries, name, 2)
        if entry is None:
            raise SystemExit(1)
        print(f"uid={entry[2]}({entry[0]}) gid={entry[3]}")
        raise SystemExit(0)
    if len(args) == 2 and args[0] in {"-g", "-nG"}:
        entry = find(passwd_entries, args[1], 2)
        if entry is None:
            raise SystemExit(1)
        if args[0] == "-g":
            print(entry[3])
            raise SystemExit(0)
        primary = find(group_entries, entry[3], 2)
        if primary is None:
            raise SystemExit(1)
        names = [primary[0]]
        for group in group_entries:
            members = [item for item in group[3].split(",") if item]
            if entry[0] in members and group[0] not in names:
                names.append(group[0])
        print(" ".join(names))
        raise SystemExit(0)
    raise SystemExit(2)

injected_failure()

if command == "addgroup":
    groups = records(group_path)
    if len(args) == 2 and args[0] == "-S":
        name = args[1]
        if find(groups, name, 2) is not None:
            raise SystemExit(1)
        next_gid = max(int(entry[2]) for entry in groups) + 1
        groups.append([name, "x", str(next_gid), ""])
        mutate(f"addgroup:{name}")
        store(group_path, groups)
        raise SystemExit(0)
    if len(args) == 2:
        user, group_name = args
        if find(records(passwd_path), user, 2) is None:
            raise SystemExit(1)
        group = find(groups, group_name, 2)
        if group is None:
            raise SystemExit(1)
        members = [item for item in group[3].split(",") if item]
        if user not in members:
            members.append(user)
            group[3] = ",".join(members)
            mutate(f"add-member:{user}:{group_name}")
            store(group_path, groups)
        raise SystemExit(0)
    raise SystemExit(2)

if command == "adduser":
    values: dict[str, str] = {}
    index = 0
    while index < len(args) - 1:
        option = args[index]
        if option in {"-h", "-s", "-G"}:
            values[option] = args[index + 1]
            index += 2
        elif option in {"-S", "-D", "-H"}:
            index += 1
        else:
            raise SystemExit(2)
    name = args[-1]
    passwd_entries = records(passwd_path)
    groups = records(group_path)
    primary = find(groups, values["-G"], 2)
    if primary is None or find(passwd_entries, name, 2) is not None:
        raise SystemExit(1)
    next_uid = max(int(entry[2]) for entry in passwd_entries) + 1
    passwd_entries.append(
        [name, "x", str(next_uid), primary[2], "", values["-h"], values["-s"]]
    )
    shadow_entries = records(shadow_path)
    shadow_entries.append([name, "x", "0", "0", "99999", "7", "", "", ""])
    mutate(f"adduser:{name}")
    store(passwd_path, passwd_entries)
    store(shadow_path, shadow_entries)
    raise SystemExit(0)

if command == "passwd":
    if len(args) != 2 or args[0] != "-l":
        raise SystemExit(2)
    shadow_entries = records(shadow_path)
    entry = find(shadow_entries, args[1], 2)
    if entry is None:
        raise SystemExit(1)
    if not entry[1].startswith(("!", "*")):
        entry[1] = "!" + entry[1]
    mutate(f"lock:{args[1]}")
    store(shadow_path, shadow_entries)
    raise SystemExit(0)

if command == "deluser":
    if len(args) != 1:
        raise SystemExit(2)
    name = args[0]
    passwd_entries = records(passwd_path)
    if find(passwd_entries, name, 2) is None:
        raise SystemExit(1)
    passwd_entries = [entry for entry in passwd_entries if entry[0] != name]
    shadow_entries = [entry for entry in records(shadow_path) if entry[0] != name]
    groups = records(group_path)
    for group in groups:
        group[3] = ",".join(
            member for member in group[3].split(",") if member and member != name
        )
    mutate(f"deluser:{name}")
    store(passwd_path, passwd_entries)
    store(shadow_path, shadow_entries)
    store(group_path, groups)
    raise SystemExit(0)

if command == "delgroup":
    groups = records(group_path)
    if len(args) == 2:
        user, group_name = args
        group = find(groups, group_name, 2)
        if group is None:
            raise SystemExit(1)
        members = [member for member in group[3].split(",") if member]
        if user not in members:
            raise SystemExit(1)
        group[3] = ",".join(member for member in members if member != user)
        mutate(f"del-member:{user}:{group_name}")
        store(group_path, groups)
        raise SystemExit(0)
    if len(args) == 1:
        group = find(groups, args[0], 2)
        if group is None or group[3]:
            raise SystemExit(1)
        if any(entry[3] == group[2] for entry in records(passwd_path)):
            raise SystemExit(1)
        groups = [entry for entry in groups if entry[0] != args[0]]
        mutate(f"delgroup:{args[0]}")
        store(group_path, groups)
        raise SystemExit(0)
    raise SystemExit(2)

if command == "rc-service":
    # The fixture models a stopped service.  Tests still exercise that the
    # helper calls status before attempting a stop.
    if args == ["lmi-display", "status"]:
        raise SystemExit(3)
    if args == ["lmi-display", "stop"]:
        mutate("rc-service:stop")
        raise SystemExit(0)
    raise SystemExit(2)

raise SystemExit(127)
'''


@unittest.skipIf(os.getuid() == 0, "test redirection is intentionally non-root-only")
class AccountLifecycleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        temporary = Path(self.temporary.name)
        self.root = (temporary / "root").resolve()
        self.fake_bin = temporary / "fake-bin"
        self.audit = temporary / "mutations.log"
        for directory in (
            self.root / "etc",
            self.root / "bin",
            self.root / "var/lib",
            self.root / "var/log",
            self.root / "run/user",
            self.root / "proc",
            self.fake_bin,
        ):
            directory.mkdir(parents=True, exist_ok=True)
        false_shell = self.root / "bin/false"
        false_shell.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
        false_shell.chmod(0o755)

        (self.root / "etc/passwd").write_text(
            textwrap.dedent(
                """\
                root:x:0:0:root:/root:/bin/ash
                lmi:x:1500:1500:recovery:/home/lmi:/bin/ash
                admin:x:1600:1600:administrator:/home/admin:/bin/ash
                """
            ),
            encoding="utf-8",
        )
        (self.root / "etc/group").write_text(
            textwrap.dedent(
                """\
                root:x:0:
                seat:x:100:lmi
                lmi:x:1500:
                admin:x:1600:
                """
            ),
            encoding="utf-8",
        )
        (self.root / "etc/shadow").write_text(
            "root:!:0:0:99999:7:::\n"
            "lmi:!:0:0:99999:7:::\n"
            "admin:!:0:0:99999:7:::\n",
            encoding="utf-8",
        )
        fake_tool = temporary / "fake-alpine-tool"
        fake_tool.write_text(FAKE_ALPINE_TOOL, encoding="utf-8")
        fake_tool.chmod(0o755)
        for name in (
            "getent",
            "id",
            "addgroup",
            "adduser",
            "passwd",
            "deluser",
            "delgroup",
            "rc-service",
        ):
            (self.fake_bin / name).symlink_to(fake_tool)

        self.environment = os.environ.copy()
        self.environment.update(
            {
                "LMI_P2_TEST_ROOT": str(self.root),
                "FAKE_ROOT": str(self.root),
                "FAKE_AUDIT": str(self.audit),
                "PATH": f"{self.fake_bin}:{self.environment['PATH']}",
            }
        )

    def run_helper(
        self, operation: str, *, fail_on: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        environment = self.environment.copy()
        if fail_on is not None:
            environment["FAKE_FAIL_ON"] = fail_on
        return subprocess.run(
            ["sh", str(HELPER), operation],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=5,
        )

    def entries(self, database: str) -> dict[str, list[str]]:
        return {
            fields[0]: fields
            for fields in (
                line.split(":")
                for line in (self.root / f"etc/{database}")
                .read_text(encoding="utf-8")
                .splitlines()
            )
        }

    def replace_entry(self, database: str, name: str, fields: list[str]) -> None:
        entries = self.entries(database)
        self.assertIn(name, entries)
        entries[name] = fields
        (self.root / f"etc/{database}").write_text(
            "".join(":".join(entry) + "\n" for entry in entries.values()),
            encoding="utf-8",
        )

    def file_snapshot(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.root).as_posix(): path.read_bytes()
            for path in sorted(self.root.rglob("*"))
            if path.is_file()
        }

    def install(self) -> None:
        result = self.run_helper("install")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_first_install_and_upgrade_are_idempotent_and_revoke_legacy_seat(self) -> None:
        self.install()
        passwd_entries = self.entries("passwd")
        group_entries = self.entries("group")
        shadow_entries = self.entries("shadow")
        account = passwd_entries["lmi-p2-gui"]
        primary = group_entries["lmi-p2-gui"]
        self.assertNotEqual(account[2], "0")
        self.assertEqual(account[3], primary[2])
        self.assertEqual(account[5:], ["/var/lib/lmi-p2/home", "/bin/false"])
        self.assertEqual(primary[3], "")
        self.assertTrue(shadow_entries["lmi-p2-gui"][1].startswith("!"))
        self.assertEqual(group_entries["seat"][3], "lmi-p2-gui")
        self.assertEqual(
            (self.root / "var/lib/lmi-p2/account-v1").read_text(encoding="utf-8"),
            "lmi-p2-gui/v1\n",
        )
        self.assertTrue((self.root / "var/lib/lmi-p2/home").is_dir())
        installed_snapshot = self.file_snapshot()

        seat = self.entries("group")["seat"]
        seat[3] = "lmi,lmi-p2-gui"
        self.replace_entry("group", "seat", seat)
        upgraded = self.run_helper("upgrade")
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        self.assertEqual(self.entries("group")["seat"][3], "lmi-p2-gui")
        self.assertEqual(self.file_snapshot(), installed_snapshot)

        repeated = self.run_helper("upgrade")
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(self.file_snapshot(), installed_snapshot)

    def test_install_failure_rolls_back_marker_account_and_group(self) -> None:
        result = self.run_helper("install", fail_on="passwd")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("injected passwd failure", result.stderr)
        self.assertNotIn("lmi-p2-gui", self.entries("passwd"))
        self.assertNotIn("lmi-p2-gui", self.entries("group"))
        self.assertFalse((self.root / "var/lib/lmi-p2").exists())
        # Security revocation precedes creation and is intentionally not undone.
        self.assertEqual(self.entries("group")["seat"][3], "")

    def test_uninstall_removes_owned_identity_and_runtime_state(self) -> None:
        self.install()
        uid = self.entries("passwd")["lmi-p2-gui"][2]
        (self.root / f"run/user/{uid}").mkdir()
        (self.root / f"run/user/{uid}/wayland-lmi-p2").write_text(
            "socket fixture", encoding="utf-8"
        )
        (self.root / "run/lmi-p2").mkdir()
        (self.root / "run/lmi-p2/ready").write_text("ready\n", encoding="utf-8")
        (self.root / "var/log/lmi-p2-display.log").write_text(
            "fixture\n", encoding="utf-8"
        )

        result = self.run_helper("remove")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("lmi-p2-gui", self.entries("passwd"))
        self.assertNotIn("lmi-p2-gui", self.entries("group"))
        self.assertNotIn("lmi-p2-gui", self.entries("shadow"))
        self.assertNotIn("lmi-p2-gui", self.entries("group")["seat"][3])
        self.assertFalse((self.root / "var/lib/lmi-p2").exists())
        self.assertFalse((self.root / f"run/user/{uid}").exists())
        self.assertFalse((self.root / "run/lmi-p2").exists())
        self.assertFalse((self.root / "var/log/lmi-p2-display.log").exists())

    def test_uninstall_refuses_supplementary_group_members_before_mutation(self) -> None:
        self.install()
        primary = self.entries("group")["lmi-p2-gui"]
        primary[3] = "admin"
        self.replace_entry("group", "lmi-p2-gui", primary)
        before = self.file_snapshot()
        self.audit.write_text("", encoding="utf-8")

        result = self.run_helper("remove")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("supplementary members", result.stderr)
        self.assertEqual(self.file_snapshot(), before)
        self.assertEqual(self.audit.read_text(encoding="utf-8"), "")

    def test_uninstall_refuses_other_primary_gid_reference_before_mutation(self) -> None:
        self.install()
        gid = self.entries("group")["lmi-p2-gui"][2]
        with (self.root / "etc/passwd").open("a", encoding="utf-8") as stream:
            stream.write(f"borrower:x:1700:{gid}:borrower:/home/borrower:/bin/ash\n")
        with (self.root / "etc/shadow").open("a", encoding="utf-8") as stream:
            stream.write("borrower:!:0:0:99999:7:::\n")
        before = self.file_snapshot()
        self.audit.write_text("", encoding="utf-8")

        result = self.run_helper("remove")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("another account's primary group", result.stderr)
        self.assertEqual(self.file_snapshot(), before)
        self.assertEqual(self.audit.read_text(encoding="utf-8"), "")

    def test_apk_hooks_delegate_all_lifecycle_phases(self) -> None:
        expected = {
            "device-xiaomi-lmi-gui.post-install": "install",
            "device-xiaomi-lmi-gui.post-upgrade": "upgrade",
            "device-xiaomi-lmi-gui.pre-deinstall": "remove",
        }
        for name, operation in expected.items():
            with self.subTest(name=name):
                source = (FILES / name).read_text(encoding="utf-8")
                self.assertIn(
                    f"exec /usr/libexec/lmi-p2/lmi-account-lifecycle {operation}",
                    source,
                )
                subprocess.run(
                    ["sh", "-n", str(FILES / name)],
                    check=True,
                    capture_output=True,
                    text=True,
                )


if __name__ == "__main__":
    unittest.main()
