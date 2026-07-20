from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-p2"
PROFILE = REPO / "config/lmi-p2/source-profile.json"


class RuntimePolicyTests(unittest.TestCase):
    def source_text(self) -> str:
        return "\n".join(
            path.read_text(encoding="utf-8")
            for path in sorted(FILES.iterdir())
            if path.is_file()
        )

    def test_root_handoff_is_argument_free_bounded_and_drops_privileges(self) -> None:
        handoff = (FILES / "lmi-display-handoff.c").read_text(encoding="utf-8")
        initd = (FILES / "lmi-display.initd").read_text(encoding="utf-8")
        dropper = (FILES / "lmi-session-launcher.c").read_text(encoding="utf-8")
        user_session = (FILES / "lmi-weston-user-session").read_text(
            encoding="utf-8"
        )
        self.assertIn("argc != 1", handoff)
        self.assertIn("getresuid", handoff)
        self.assertIn("READY_WAIT_ATTEMPTS = 150", handoff)
        self.assertIn("STOP_WAIT_ATTEMPTS = 50", handoff)
        self.assertIn('"/usr/bin/openvt"', handoff)
        self.assertIn('"-e", "-c", "7"', handoff)
        self.assertEqual(
            re.findall(r'^command="([^"]+)"$', initd, flags=re.MULTILINE),
            ["/usr/sbin/lmi-display-handoff"],
        )
        self.assertNotIn("command_args", initd)
        self.assertRegex(initd, r"(?m)^\s*need seatd$")
        self.assertIn("setgroups(1, &seat_group)", dropper)
        self.assertIn('#define LMI_ACCOUNT "lmi-p2-gui"', dropper)
        self.assertIn('#define LMI_ACCOUNT_SHELL "/bin/false"', dropper)
        self.assertIn('#define LMI_ACCOUNT_HOME "/var/lib/lmi-p2/home"', dropper)
        self.assertNotIn('#define LMI_ACCOUNT "lmi"', dropper)
        self.assertIn(
            "setresgid(primary_group, primary_group, primary_group)", dropper
        )
        self.assertIn("setresuid(user_id, user_id, user_id)", dropper)
        self.assertIn("PR_SET_NO_NEW_PRIVS", dropper)
        self.assertIn("PR_CAP_AMBIENT_CLEAR_ALL", dropper)
        self.assertIn("SYS_capset", dropper)
        self.assertIn("SYS_capget", dropper)
        self.assertNotIn("initgroups", dropper)
        self.assertIn(
            "lmi-weston-user-session did not drop to lmi-p2-gui", user_session
        )
        self.assertIn(
            "requires exactly the seat supplementary group", user_session
        )
        self.assertIn("LIBSEAT_BACKEND=seatd", user_session)
        self.assertIn('retry="TERM/5/KILL/5"', initd)

    def test_seatd_access_uses_only_the_seat_group(self) -> None:
        post_install = (FILES / "device-xiaomi-lmi-gui.post-install").read_text(
            encoding="utf-8"
        )
        post_upgrade = (FILES / "device-xiaomi-lmi-gui.post-upgrade").read_text(
            encoding="utf-8"
        )
        pre_deinstall = (
            FILES / "device-xiaomi-lmi-gui.pre-deinstall"
        ).read_text(encoding="utf-8")
        lifecycle = (FILES / "lmi-account-lifecycle").read_text(encoding="utf-8")
        self.assertIn("account=lmi-p2-gui", lifecycle)
        self.assertIn("account_shell=/bin/false", lifecycle)
        self.assertIn('addgroup "$account" seat', lifecycle)
        self.assertIn("delgroup lmi seat", lifecycle)
        self.assertNotIn("addgroup lmi seat", lifecycle)
        self.assertNotRegex(lifecycle, r"addgroup (?:lmi|\"\$account\") (?:input|video)")
        self.assertIn("lmi-account-lifecycle install", post_install)
        self.assertIn("lmi-account-lifecycle upgrade", post_upgrade)
        self.assertIn("lmi-account-lifecycle remove", pre_deinstall)
        for cleanup in (
            'delgroup "$account" seat',
            'deluser "$account"',
            'rm -rf -- "$state_dir"',
            'rm -rf -- "$service_runtime"',
            "lmi-p2-display.log",
        ):
            self.assertIn(cleanup, lifecycle)
        self.assertIn("refusing to remove an unmarked GUI identity", lifecycle)
        self.assertIn("GUI primary group has supplementary members", lifecycle)
        self.assertIn("another account's primary group", lifecycle)

    def test_no_broad_sudo_or_fixed_input_framebuffer_drm_node(self) -> None:
        text = self.source_text()
        forbidden = {
            "sudo": r"\bsudo\b",
            "sudoers": r"sudoers",
            "input event node": r"/dev/input/event[0-9]+",
            "framebuffer zero": r"/dev/fb0\b",
            "DRM card zero": r"/dev/dri/card0\b",
            "shell eval": r"\beval\b",
            "shell command string": r"\b(?:sh|bash)\s+-c\b",
        }
        for label, pattern in forbidden.items():
            with self.subTest(label=label):
                self.assertIsNone(re.search(pattern, text))

    def test_weston_configuration_is_exact_and_user_owned(self) -> None:
        config = (FILES / "weston.ini").read_text(encoding="utf-8")
        session = (FILES / "lmi-weston-user-session").read_text(encoding="utf-8")
        for item in (
            "backend=drm-backend.so",
            "renderer=pixman",
            "shell=desktop-shell.so",
            "name=DSI-1",
            "mode=current",
            "scale=2",
            "path=/usr/libexec/lmi-p2/lmi-weston-osk",
            "path=/usr/libexec/lmi-p2/lmi-terminal",
            "path=/usr/libexec/lmi-p2/lmi-editor",
        ):
            self.assertIn(item, config)
        self.assertIn('XDG_RUNTIME_DIR="/run/user/$gui_uid"', session)
        self.assertIn("--socket=wayland-lmi-p2", session)
        self.assertIn('"$HOME/.local/state/lmi-p2/weston.log"', session)
        self.assertNotIn("/root", session)
        self.assertNotIn("/usr/libexec/lmi-p2/lmi-terminal &", session)

    def test_osk_uses_complete_protocol_listeners_and_exact_output(self) -> None:
        osk = (FILES / "lmi-weston-osk.c").read_text(encoding="utf-8")
        for symbol in (
            "zwp_input_method_v1",
            "zwp_input_method_context_v1_commit_string",
            "zwp_input_method_context_v1_keysym",
            "zwp_input_method_context_v1_modifiers_map",
            "zwp_input_panel_surface_v1_set_toplevel",
            "wl_touch_add_listener",
            "pointer_axis_source",
            "pointer_axis_stop",
            "pointer_axis_discrete",
            "LMI_OUTPUT_CONNECTOR",
            "wl_output_listener",
        ):
            self.assertIn(symbol, osk)
        self.assertIn("layer_state.displayed", osk)
        self.assertIn("layer_state.requested", osk)
        self.assertIn("wl_pointer_release", osk)
        self.assertIn("wl_touch_release", osk)
        self.assertNotIn("/dev/uinput", osk)
        self.assertNotIn("/dev/input/", osk)
        self.assertNotIn("zwp_text_input_v1", osk)

    def test_unverifiable_terminal_touch_route_is_fail_closed(self) -> None:
        osk = (FILES / "lmi-weston-osk.c").read_text(encoding="utf-8")
        state = (FILES / "lmi-input-state.c").read_text(encoding="utf-8")
        bridge = (FILES / "lmi-terminal-bridge.c").read_text(encoding="utf-8")
        profile = json.loads(PROFILE.read_text(encoding="utf-8"))
        for forbidden in (
            "getrandom",
            "zwp_text_input_v1",
            "LMI_TERMINAL_FOCUS",
            "LMI_TERMINAL_CHALLENGE",
            "LMI_TERMINAL_ACK",
            "LMI_TERMINAL_KEY",
            "SOCK_SEQPACKET",
            "lmi-p2-osk-focus.sock",
            "reactivation",
        ):
            self.assertNotIn(forbidden, osk + state + bridge)
        self.assertNotIn("LMI_INPUT_TERMINAL", state)
        self.assertIn("LMI_INPUT_EDITOR", state)
        self.assertIn(
            "stock-weston-terminal-native-focus-integration-unavailable",
            profile["release"]["blockers"],
        )

    def test_terminal_bridge_and_outer_handoff_have_stable_child_ownership(self) -> None:
        bridge = (FILES / "lmi-terminal-bridge.c").read_text(encoding="utf-8")
        terminal = (FILES / "lmi-terminal").read_text(encoding="utf-8")
        handoff = (FILES / "lmi-display-handoff.c").read_text(encoding="utf-8")
        supervisor = (FILES / "lmi-child-supervisor.c").read_text(encoding="utf-8")
        self.assertIn("getuid() == 0 || geteuid() == 0", bridge)
        self.assertIn("IO_DEADLINE_MS = 2000", bridge)
        self.assertNotIn("poll(&output, 1, -1)", bridge)
        self.assertIn('#define LMI_TERMINAL_SHELL "/bin/ash"', bridge)
        self.assertIn('execl(LMI_TERMINAL_SHELL, "ash", "-l"', bridge)
        self.assertIn(
            "--shell=/usr/libexec/lmi-p2/lmi-terminal-bridge", terminal
        )
        self.assertIn("setsid()", bridge)
        self.assertNotIn("SECCOMP", bridge)
        self.assertNotIn("waitpid", bridge)
        self.assertNotIn("waitpid", handoff)
        self.assertNotIn("kill(-", bridge + handoff)
        self.assertIn("PR_SET_CHILD_SUBREAPER", supervisor)
        self.assertIn("/proc/self/task/%ld/children", supervisor)
        self.assertIn("WNOWAIT", supervisor)
        self.assertIn("snapshot.count != 1", supervisor)
        self.assertIn("lmi_child_reap_anchor", bridge)
        self.assertIn("lmi_child_reap_anchor", handoff)
        self.assertNotIn("/dev/uinput", bridge)

    def test_profile_covers_every_acceptance_key(self) -> None:
        value = json.loads(PROFILE.read_text(encoding="utf-8"))
        keys = [
            key
            for layer in value["keyboard"]["layers"]
            for row in layer["rows"]
            for key in row
        ]
        text_values = {key["value"] for key in keys if key["action"] == "text"}
        keysyms = {key["value"] for key in keys if key["action"] == "keysym"}
        modifiers = {
            key["value"] for key in keys if key["action"] == "modifier"
        }
        self.assertTrue(set("abcdefghijklmnopqrstuvwxyz") <= text_values)
        self.assertTrue(set("ABCDEFGHIJKLMNOPQRSTUVWXYZ") <= text_values)
        self.assertTrue(
            set("0123456789-_/\\|<>=+*?.,:;'\"()[]{}$#@!%&~^` ") <= text_values
        )
        self.assertTrue(
            {
                "Escape",
                "Tab",
                "Left",
                "Right",
                "Up",
                "Down",
                "Home",
                "End",
                "Prior",
                "Next",
                "Delete",
                "BackSpace",
                "Return",
            }
            <= keysyms
        )
        self.assertEqual(modifiers, {"shift", "control", "alt"})

    def test_p1_services_and_d80_are_not_replayed(self) -> None:
        text = self.source_text().lower()
        for forbidden in ("sshd", "networkmanager", "rootctl", "d80", "r139"):
            self.assertNotIn(forbidden, text)


if __name__ == "__main__":
    unittest.main()
