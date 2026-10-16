"""Launch the dev-sidecar Linux binary on an isolated X/DBus session.

Run via xvfb-run -a python .../native_smoke.py EVIDENCE_DIR.
No real deployment configuration, system proxy or TUN is enabled.
"""

import os
from pathlib import Path
import signal
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from PIL import ImageGrab


def main():
    root = Path(__file__).resolve().parents[2]
    evidence = Path(sys.argv[1]).resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pw-") as directory:
        isolated = Path(directory)
        env = dict(os.environ)
        for name in (
            "XDG_DATA_HOME",
            "XDG_CONFIG_HOME",
            "XDG_CACHE_HOME",
            "XDG_RUNTIME_DIR",
        ):
            target = isolated / name.lower()
            target.mkdir(mode=0o700)
            env[name] = str(target)
        env["PILGRIM_WORKSPACE_CONFIG"] = str(isolated / "not-configured.json")
        env["PILGRIM_WORKSPACE_AGENT"] = str(
            root / "companion/.venv/bin/pilgrim-workspace-agent"
        )
        env["CODEX_HOME"] = str(isolated / "codex")
        env["GDK_BACKEND"] = "x11"
        env["WEBKIT_DISABLE_COMPOSITING_MODE"] = "1"
        app_data = Path(env["XDG_DATA_HOME"]) / "com.pilgrimss.workspace.dev"
        app_data.mkdir(mode=0o700)
        for name in ("Country.mmdb", "ASN.mmdb", "geoip.dat", "geosite.dat"):
            shutil.copyfile(root / "src-tauri/resources" / name, app_data / name)
        with (evidence / "native.log").open("w") as log:
            bus = subprocess.Popen(
                ["dbus-daemon", "--session", "--nofork", "--print-address=1"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=log,
                text=True,
                start_new_session=True,
            )
            env["DBUS_SESSION_BUS_ADDRESS"] = bus.stdout.readline().strip()
            if not env["DBUS_SESSION_BUS_ADDRESS"]:
                bus.wait(timeout=5)
                raise RuntimeError("Isolated DBus session failed")
            process = subprocess.Popen(
                [str(root / "target/debug/pilgrim-workspace")],
                cwd=root,
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                found = False
                for _ in range(90):
                    if process.poll() is not None:
                        raise RuntimeError(
                            "Native application exited; inspect native.log"
                        )
                    windows = subprocess.check_output(
                        ["xwininfo", "-root", "-tree"], text=True
                    )
                    if '"Pilgrim Workspace"' in windows:
                        found = True
                        break
                    time.sleep(0.5)
                if not found:
                    raise RuntimeError("Workspace window was not created")
                core_socket = app_data / "pilgrim-mihomo.sock"
                core_ready = False
                for _ in range(60):
                    try:
                        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as core:
                            core.settimeout(1)
                            core.connect(str(core_socket))
                            core.sendall(
                                b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                            )
                            status = core.recv(1024).split(b"\r\n")[0]
                            core_ready = b"200" in status or b"401" in status
                    except OSError:
                        pass
                    if core_ready:
                        break
                    time.sleep(0.5)
                if not core_ready:
                    raise RuntimeError(
                        "Native mihomo API did not respond; inspect native.log"
                    )
                time.sleep(2)
                ImageGrab.grab(xdisplay=os.environ["DISPLAY"]).save(
                    evidence / "native-workspace.png"
                )
                print(
                    "Native window opened and mihomo Unix API responded; inspect native-workspace.png for rendered state. No tenant or system-network acceptance claimed."
                )
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                if bus.poll() is None:
                    os.killpg(bus.pid, signal.SIGTERM)
                    bus.wait(timeout=5)


if __name__ == "__main__":
    main()
