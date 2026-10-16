"""Run the real workbench UI against the real companion and a local OIDC fixture.

The native Tauri transport, OS keyring and OS proxy are NOT exercised here.
"""

import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import urllib.request
import sys

from playwright.sync_api import sync_playwright
from test_smoke import MemoryStore, Provider
from workspace_agent import Agent


def main():
    root = Path(__file__).resolve().parents[2]
    screenshot_dir = Path(
        sys.argv[1]
        if len(sys.argv) > 1
        else tempfile.mkdtemp(prefix="workspace-evidence-")
    )
    screenshot_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="workspace-smoke-") as directory:
        temporary = Path(directory)
        provider = Provider()
        config = temporary / "deployment.json"
        config.write_text(
            json.dumps(
                {
                    "version": 2,
                    "providers": {
                        name: {
                            "issuer": provider.issuer,
                            "client_id": "workspace-smoke",
                            "redirect_port": 0,
                            "policy_endpoint": provider.base + "/policy",
                            "credential_endpoint": provider.base + "/credential",
                        }
                        for name in ("feishu", "authentik")
                    },
                }
            )
        )
        os.environ["CODEX_HOME"] = str(temporary / "codex")
        agent = Agent(
            config,
            store=MemoryStore(),
            browser=provider.browser,
            helper="/test/pilgrim-workspace-agent",
        )
        capability = secrets.token_urlsafe(32)
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        origin = f"http://127.0.0.1:{port}"

        class RPC(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def send_cors_headers(self, status):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header(
                    "Access-Control-Allow-Headers", "Authorization, Content-Type"
                )
                self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
                self.end_headers()

            def do_OPTIONS(self):
                self.send_cors_headers(204)

            def do_POST(self):
                if self.headers.get("Authorization") != "Bearer " + capability:
                    self.send_error(403)
                    return
                action = json.loads(
                    self.rfile.read(int(self.headers["Content-Length"]))
                )["action"]
                action = action.replace("_", "-")
                if action not in (
                    "status",
                    "login-authentik",
                    "login-feishu",
                    "configure",
                    "logout",
                ):
                    self.send_error(400)
                    return
                try:
                    value = agent.run(action)
                    value["network_enabled"] = False
                    self.respond(200, value)
                except Exception:
                    self.respond(500, {"error": "SMOKE_OPERATION_FAILED"})

            def respond(self, status, value):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", origin)
                self.end_headers()
                self.wfile.write(json.dumps(value).encode())

        rpc = ThreadingHTTPServer(("127.0.0.1", 0), RPC)
        thread = threading.Thread(target=rpc.serve_forever, daemon=True)
        thread.start()
        with (temporary / "vite.log").open("w") as log:
            vite = subprocess.Popen(
                [
                    "pnpm",
                    "exec",
                    "vite",
                    "--config",
                    "scripts/smoke/vite.config.mts",
                    "--port",
                    str(port),
                ],
                cwd=root,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                url = origin + "/scripts/smoke/workspace.html"
                for _ in range(120):
                    if vite.poll() is not None:
                        raise RuntimeError((temporary / "vite.log").read_text())
                    try:
                        urllib.request.urlopen(url, timeout=1).close()
                        break
                    except Exception:
                        time.sleep(0.25)
                with sync_playwright() as playwright:
                    browser = playwright.chromium.launch(
                        executable_path="/usr/bin/chromium", args=["--no-sandbox"]
                    )
                    page = browser.new_page(viewport={"width": 1100, "height": 820})
                    page.add_init_script(
                        "window.__WORKSPACE_SMOKE__ = "
                        + json.dumps(
                            {
                                "endpoint": f"http://127.0.0.1:{rpc.server_port}",
                                "capability": capability,
                            }
                        )
                    )
                    errors = []
                    page.on("pageerror", lambda error: errors.append(str(error)))
                    page.goto(url)
                    page.get_by_role("button", name="企业 SSO 登录", exact=True).click()
                    page.get_by_role("heading", name="Smoke User").wait_for()
                    page.get_by_role("button", name="同步 Codex 配置").click()
                    page.get_by_text("Codex 已配置", exact=True).wait_for()
                    page.screenshot(
                        path=str(screenshot_dir / "workbench-desktop.png"),
                        full_page=True,
                    )
                    page.set_viewport_size({"width": 390, "height": 844})
                    page.screenshot(
                        path=str(screenshot_dir / "workbench-mobile.png"),
                        full_page=True,
                    )
                    assert page.evaluate(
                        "document.documentElement.scrollWidth <= innerWidth"
                    )
                    assert page.get_by_text("节点", exact=True).count() == 0
                    assert page.get_by_text("订阅", exact=True).count() == 0
                    assert page.evaluate(
                        "Array.from(document.querySelectorAll('button')).every(e => parseFloat(getComputedStyle(e).fontSize) >= 14 && e.getBoundingClientRect().height >= 44)"
                    )
                    provider.fail_policy = True
                    page.get_by_role("button", name="同步 Codex 配置").click()
                    page.get_by_role("alert").wait_for()
                    page.get_by_role("button", name="退出登录并断开").click()
                    page.get_by_role(
                        "button", name="企业 SSO 登录", exact=True
                    ).wait_for()
                    assert agent.store.get() is None
                    provider.fail_policy = False
                    page.get_by_role("button", name="飞书登录", exact=True).click()
                    page.get_by_role("heading", name="Smoke User").wait_for()
                    assert agent.store.get()["provider"] == "feishu"
                    page.get_by_role("button", name="同步 Codex 配置").click()
                    page.get_by_text("Codex 已配置", exact=True).wait_for()
                    page.get_by_role("button", name="退出登录并断开").click()
                    page.get_by_role("button", name="飞书登录", exact=True).wait_for()
                    assert agent.store.get() is None
                    assert page.locator(".workspace-identity-text").bounding_box()["width"] >= 200
                    page.screenshot(
                        path=str(screenshot_dir / "login-providers.png"), full_page=True
                    )
                    assert not errors, errors
                    browser.close()
                print(
                    json.dumps(
                        {
                            "result": "passed",
                            "flows": [
                                "Authentik and Feishu OIDC login",
                                "Codex configuration",
                                "policy failure",
                                "logout",
                                "390px layout",
                            ],
                            "screenshots": str(screenshot_dir),
                            "excluded": [
                                "native IPC",
                                "OS keyring",
                                "OS proxy",
                                "real Authentik tenant",
                            ],
                        }
                    )
                )
            finally:
                import signal

                os.killpg(vite.pid, signal.SIGTERM)
                vite.wait(timeout=10)
                rpc.shutdown()
                rpc.server_close()
                provider.close()


if __name__ == "__main__":
    main()
