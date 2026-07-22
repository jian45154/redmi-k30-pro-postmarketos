from __future__ import annotations

from pathlib import Path
import re
import subprocess
import unittest


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-p2-d114"


class RuntimePolicyTests(unittest.TestCase):
    def test_all_shell_sources_have_valid_posix_syntax(self) -> None:
        for path in sorted(FILES.iterdir()):
            if path.name.endswith((".toml", ".ini", ".confd")):
                continue
            with self.subTest(path=path.name):
                result = subprocess.run(
                    ["/bin/sh", "-n", str(path)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_session_is_pinned_nonroot_sixrow_weston_chain(self) -> None:
        session = (FILES / "lmi-p2-d114-session").read_text(encoding="utf-8")
        for required in (
            'export HOME=/home/lmi',
            'export XDG_RUNTIME_DIR=/run/user/10000',
            'export WAYLAND_DISPLAY=wayland-lmi-p2-d114',
            'export LIBSEAT_BACKEND=seatd',
            '"$(id -u)" = 10000',
            '"$(id -g)" = 10000',
            'stat -c %a /run/seatd.sock)" = 770',
            '/usr/bin/weston',
            '--backend=drm-backend.so',
            '--drm-device=card0',
            '--renderer=pixman',
            '--shell=desktop-shell.so',
            '/usr/libexec/lmi-p2-d114/weston-terminal-sixrow --maximized --font-size=18',
            '/sys/class/drm/card0-DSI-1/status',
            '/sys/class/drm/card0-DSI-1/enabled',
            'takeover_lock=/run/lmi-display-takeover.lock',
            'session_lock=$XDG_RUNTIME_DIR/lmi-p2-d114-session.lock',
            'fail "weston-terminal exited $check_context',
            'find_keyboard_child',
            'keyboard_identity_full "$keyboard_pid" "$keyboard_starttime"',
            'readlink "/proc/$keyboard_check_pid/exe"',
            '[ "$keyboard_exe" = /usr/libexec/lmi-p2-d114/weston-keyboard-sixrow ]',
            'process_starttime()',
            'process_identity_full()',
            'core_child_valid "$stop_pid" "$stop_exe" "$stop_starttime"',
            'keyboard_restart_count',
            'weston-keyboard exceeded its bounded restart budget',
            'sleep 5',
        ):
            self.assertIn(required, session)
        for forbidden in (
            "lmi-p2-gui",
            "/dev/input/",
            "/dev/uinput",
            "sudo",
            "doas",
            "openvt",
            "--tty=7",
            "renderer=gl",
            "wayland-0",
        ):
            self.assertNotIn(forbidden, session)
        self.assertIn("weston|phoc|phosh|kmscube|modetest", session)
        self.assertNotIn("/usr/bin/phoc", session)
        self.assertNotIn("/usr/bin/phosh", session)
        self.assertLess(
            session.index('wait_for_keyboard 150 "before keyboard readiness"'),
            session.index(
                '/usr/libexec/lmi-p2-d114/weston-terminal-sixrow --maximized --font-size=18'
            ),
        )
        self.assertNotRegex(session, r"\b(?:sh|bash)\s+-c\b")
        self.assertNotRegex(session, r"\beval\b")
        stop_child = session[
            session.index("stop_child() {") : session.index("release_session_lock() {")
        ]
        self.assertLess(
            stop_child.index("process_identity_full"),
            stop_child.index('kill -TERM "$stop_pid"'),
        )
        self.assertLess(
            stop_child.rindex("process_identity_full"),
            stop_child.index('kill -KILL "$stop_pid"'),
        )

    def test_configuration_uses_sixrow_clients_and_pinned_greetd(self) -> None:
        weston = (FILES / "lmi-p2-d114-weston.ini").read_text(encoding="utf-8")
        greetd = (FILES / "lmi-p2-d114-greetd.toml").read_text(encoding="utf-8")
        confd = (FILES / "lmi-p2-d114-greetd.confd").read_text(encoding="utf-8")
        for required in (
            "backend=drm-backend.so",
            "renderer=pixman",
            "shell=desktop-shell.so",
            "path=/usr/libexec/lmi-p2-d114/weston-keyboard-sixrow",
            "name=DSI-1",
            "mode=current",
            "scale=2",
            "overlay-keyboard=false",
            "path=/usr/libexec/lmi-p2-d114/weston-terminal-sixrow",
        ):
            self.assertIn(required, weston)
        self.assertNotIn("path=/usr/libexec/weston-keyboard\n", weston)
        self.assertNotIn("path=/usr/bin/weston-terminal\n", weston)
        self.assertEqual(greetd.count('command = "/usr/libexec/lmi-p2-d114/session"'), 2)
        self.assertEqual(greetd.count('user = "lmi"'), 2)
        self.assertIn("[default_session]", greetd)
        self.assertIn("[initial_session]", greetd)
        self.assertIn("[general]", greetd)
        self.assertIn("source_profile = false", greetd)
        self.assertIn('runfile = "/run/greetd-lmi-p2-d114.run"', greetd)
        self.assertIn("vt = 7", greetd)
        self.assertIn("switch = true", greetd)
        self.assertIn('cfgfile="/etc/lmi-p2-d114/greetd.toml"', confd)
        self.assertIn('rc_need="lmi-seatd"', confd)

    def test_lifecycle_changes_only_greetd_confd_and_is_reversible(self) -> None:
        lifecycle = (FILES / "lmi-p2-d114-config-lifecycle").read_text(
            encoding="utf-8"
        )
        for required in (
            "target_parent=$root/etc/conf.d",
            "target=$target_parent/greetd",
            "packaged=$root/usr/share/lmi-p2-d114/greetd.confd",
            "greetd-confd.original",
            "config-v1.pending",
            "config-v1.removing",
            "original_sha256=6523d36f",
            'mv -f "$replacement" "$target"',
            'write_removing_marker',
            'restore_original',
        ):
            self.assertIn(required, lifecycle)
        for forbidden in (
            "/etc/phrog",
            "/etc/runlevels",
            "rc-service",
            "rc-update",
            "sudo",
            "doas",
            "eval",
            "sh -c",
        ):
            self.assertNotIn(forbidden, lifecycle)

    def test_no_windows_paths_or_device_mutation_commands(self) -> None:
        text = "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(FILES.iterdir())
            if path.is_file()
        ).lower()
        for forbidden in (
            "/mnt/c/",
            "c:\\users",
            "fastboot",
            "reboot",
            "flash userdata",
            "telnetd",
            "rootctl",
            "nopasswd",
        ):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
