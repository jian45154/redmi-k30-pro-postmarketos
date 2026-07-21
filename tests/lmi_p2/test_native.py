from __future__ import annotations

import os
from pathlib import Path
import pty
import select
import shutil
import subprocess
import tempfile
import time
import unittest

from scripts.lmi_p2.generate import generate_overlay


REPO = Path(__file__).resolve().parents[2]
FILES = REPO / "files/lmi-p2"
PROFILE = REPO / "config/lmi-p2/source-profile.json"
class NativeRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            raise unittest.SkipTest("a native C compiler is unavailable")
        cls.compiler = compiler
        cls.build_directory = tempfile.TemporaryDirectory()
        cls.build = Path(cls.build_directory.name)
        cls.binaries: dict[str, Path] = {}
        for source in (
            "lmi-display-handoff.c",
            "lmi-session-launcher.c",
            "lmi-terminal-bridge.c",
        ):
            output = cls.build / source.removesuffix(".c")
            command = [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(FILES),
            ]
            if source == "lmi-terminal-bridge.c":
                command.append('-DLMI_TERMINAL_SHELL="/bin/sh"')
            command.append(str(FILES / source))
            if source in {"lmi-display-handoff.c", "lmi-terminal-bridge.c"}:
                command.append(str(FILES / "lmi-child-supervisor.c"))
            command.extend(["-o", str(output)])
            subprocess.run(command, check=True, capture_output=True, text=True)
            cls.binaries[source] = output
        harness = cls.build / "native-terminal-bridge-harness"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(FILES),
                str(REPO / "tests/lmi_p2/native_terminal_bridge_harness.c"),
                str(FILES / "lmi-child-supervisor.c"),
                "-o",
                str(harness),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.binaries["native_terminal_bridge_harness.c"] = harness
        state_harness = cls.build / "native-osk-state-harness"
        subprocess.run(
            [
                compiler,
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(FILES),
                str(REPO / "tests/lmi_p2/native_osk_state_harness.c"),
                str(FILES / "lmi-input-state.c"),
                str(FILES / "lmi-layer-state.c"),
                "-o",
                str(state_harness),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        cls.binaries["native_osk_state_harness.c"] = state_harness

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "build_directory"):
            cls.build_directory.cleanup()

    def test_privileged_boundaries_reject_an_unprivileged_caller(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the host test process is root")
        for source in ("lmi-display-handoff.c", "lmi-session-launcher.c"):
            with self.subTest(source=source):
                result = subprocess.run(
                    [str(self.binaries[source])],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=2,
                )
                self.assertEqual(result.returncode, 77)

    def test_terminal_bridge_carries_inherited_terminal_input(self) -> None:
        if os.geteuid() == 0:
            self.skipTest("the terminal bridge deliberately rejects root")
        master, slave = pty.openpty()
        process = subprocess.Popen(
            [str(self.binaries["lmi-terminal-bridge.c"])],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            close_fds=True,
        )
        os.close(slave)
        try:
            time.sleep(0.1)
            os.write(master, b"printf 'LMI_BRIDGE_OK\\n'; exit\n")
            os.set_blocking(master, False)
            output = bytearray()
            deadline = time.monotonic() + 6
            while time.monotonic() < deadline and b"LMI_BRIDGE_OK" not in output:
                readable, _, _ = select.select([master], [], [], 0.2)
                if not readable:
                    continue
                try:
                    output.extend(os.read(master, 4096))
                except BlockingIOError:
                    pass
            self.assertIn(b"LMI_BRIDGE_OK", output)
            self.assertEqual(process.wait(timeout=4), 0)
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=2)
            os.close(master)

    def test_stable_child_ownership_and_failure_modes(self) -> None:
        result = subprocess.run(
            [str(self.binaries["native_terminal_bridge_harness.c"])],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_editor_only_input_and_layer_state_machines(self) -> None:
        result = subprocess.run(
            [str(self.binaries["native_osk_state_harness.c"])],
            check=False,
            capture_output=True,
            text=True,
            timeout=3,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_shell_sources_parse(self) -> None:
        sources = [
            FILES / "device-xiaomi-lmi-gui.post-install",
            FILES / "device-xiaomi-lmi-gui.post-upgrade",
            FILES / "device-xiaomi-lmi-gui.pre-deinstall",
            FILES / "lmi-account-lifecycle",
            FILES / "lmi-display.initd",
            FILES / "lmi-editor",
            FILES / "lmi-terminal",
            FILES / "lmi-weston-user-session",
        ]
        with tempfile.TemporaryDirectory() as directory:
            package = generate_overlay(PROFILE, Path(directory) / "overlay")
            subprocess.run(
                ["sh", "-n", *map(str, sources), str(package / "APKBUILD")],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_osk_compiles_against_the_weston14_protocol_surface(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            package = generate_overlay(PROFILE, Path(directory) / "overlay")
            subprocess.run(
                [
                    self.compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsyntax-only",
                    "-I",
                    str(REPO / "tests/lmi_p2/stubs"),
                    "-I",
                    str(package),
                    str(package / "lmi-weston-osk.c"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

    def test_osk_compiles_when_native_wayland_development_files_exist(self) -> None:
        scanner = shutil.which("wayland-scanner")
        pkg_config = shutil.which("pkg-config")
        packages = ["wayland-client", "pangocairo", "xkbcommon"]
        if pkg_config is None:
            self.skipTest("pkg-config is unavailable")
        probe = subprocess.run(
            [pkg_config, "--exists", *packages],
            check=False,
            capture_output=True,
        )
        protocol_root = Path("/usr/share/wayland-protocols/unstable")
        input_method = protocol_root / "input-method/input-method-unstable-v1.xml"
        if scanner is None or probe.returncode != 0 or not input_method.is_file():
            self.skipTest("native Wayland/Pango/XKB development files are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            package = generate_overlay(PROFILE, Path(directory) / "overlay")
            generated = Path(directory) / "protocols"
            generated.mkdir()
            for xml, stem in ((input_method, "input-method-unstable-v1"),):
                subprocess.run(
                    [scanner, "client-header", str(xml), str(generated / f"{stem}-client-protocol.h")],
                    check=True,
                    capture_output=True,
                )
            flags = subprocess.run(
                [pkg_config, "--cflags", *packages],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.split()
            subprocess.run(
                [
                    self.compiler,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsyntax-only",
                    "-I",
                    str(package),
                    "-I",
                    str(generated),
                    *flags,
                    str(package / "lmi-weston-osk.c"),
                ],
                check=True,
                capture_output=True,
                text=True,
            )


if __name__ == "__main__":
    unittest.main()
