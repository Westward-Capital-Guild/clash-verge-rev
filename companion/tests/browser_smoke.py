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
                payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                action = payload["action"]
                action = action.replace("_", "-")
                if action.startswith("remote-"):
                    value = agent.remote(action.removeprefix("remote-"), payload.get("hostId"), payload.get("workspaceId"))
                    self.respond(200, value)
                    return
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
                        executable_path=os.environ.get(
                            "WORKSPACE_SMOKE_BROWSER",
                            "/usr/bin/chromium" if sys.platform == "linux" else None,
                        ),
                        args=["--no-sandbox"],
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
                    page.get_by_role("button", name="配置本机模型").click()
                    page.get_by_text("本机模型已配置", exact=True).wait_for()
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
                    page.get_by_role("button", name="配置本机模型").click()
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
                    page.get_by_role("button", name="配置本机模型").click()
                    page.get_by_text("本机模型已配置", exact=True).wait_for()
                    page.get_by_role("button", name="退出登录并断开").click()
                    page.get_by_role("button", name="飞书登录", exact=True).wait_for()
                    assert agent.store.get() is None
                    assert page.locator(".workspace-identity-text").bounding_box()["width"] >= 200
                    page.screenshot(
                        path=str(screenshot_dir / "login-providers.png"), full_page=True
                    )
                    provider.cancel = True
                    page.get_by_role("button", name="飞书登录", exact=True).click()
                    page.get_by_role("alert").wait_for()
                    assert agent.store.get() is None
                    page.screenshot(
                        path=str(screenshot_dir / "login-cancelled.png"), full_page=True
                    )
                    provider.cancel = False
                    page.get_by_role("button", name="飞书登录", exact=True).click()
                    page.get_by_role("heading", name="Smoke User").wait_for()
                    agent.store.value["token"]["expires_at"] = 1
                    page.get_by_role("button", name="检查状态", exact=True).click()
                    page.get_by_text("登录已过期", exact=False).wait_for()
                    assert page.get_by_role("button", name="配置本机模型").is_disabled()
                    page.screenshot(
                        path=str(screenshot_dir / "session-expired.png"), full_page=True
                    )
                    page.get_by_role("button", name="退出登录并断开").click()
                    page.get_by_role("button", name="飞书登录", exact=True).wait_for()
                    assert agent.store.get() is None
                    page.get_by_role("button", name="飞书登录", exact=True).click()
                    page.get_by_role("heading", name="Smoke User").wait_for()
                    agent.remote_authority = lambda _: [{
                        "id": "synthetic-host", "display_name": "Synthetic development host",
                        "connection": {"network_requirement": "direct"},
                        "workspaces": [{"id": "synthetic-project", "display_name": "Synthetic project", "path": "/workspace/synthetic"}],
                    }]
                    class SyntheticSSH:
                        def check(self, record, workspace_id):
                            return {"state": "ssh_ready", "alias": "pilgrim-synthetic", "path": "/workspace/synthetic"}
                    agent.remote_ssh = SyntheticSSH()
                    page.get_by_role("button", name="刷新开发机").click()
                    page.get_by_role("heading", name="Synthetic development host").wait_for()
                    page.get_by_role("button", name="检查连接").click()
                    page.get_by_text("尚未添加 Codex Desktop 项目", exact=False).wait_for()
                    page.get_by_text("在 Codex Desktop 设置", exact=False).wait_for()
                    page.screenshot(path=str(screenshot_dir / "remote-synthetic.png"), full_page=True)
                    page.get_by_role("button", name="退出登录并断开").click()
                    page.get_by_role("button", name="飞书登录", exact=True).wait_for()
                    assert page.get_by_role("heading", name="Synthetic development host").count() == 0
                    agent.remote_authority = None
                    agent.config = None
                    agent.providers = {}
                    page.get_by_role("button", name="检查状态", exact=True).click()
                    page.get_by_text("无需手动填写配置", exact=False).wait_for()
                    assert page.get_by_role("button", name="飞书登录", exact=True).is_disabled()
                    assert page.get_by_role("button", name="企业 SSO 登录", exact=True).count() == 0
                    page.screenshot(
                        path=str(screenshot_dir / "unconfigured.png"), full_page=True
                    )
                    import pytest
                    from test_workspace_access import service
                    with pytest.MonkeyPatch.context() as patch:
                        fixture_run = service.__wrapped__(temporary / "company", patch)
                        fixture, agent = next(fixture_run)
                        try:
                            page.get_by_role("button", name="检查状态", exact=True).click()
                            page.get_by_role("heading", name="Fixture A", exact=True).wait_for()
                            page.get_by_role("heading", name="Synthetic host", exact=True).wait_for()
                            assert page.get_by_role("button", name="配置本机模型", exact=True).count() == 0
                            page.get_by_role("button", name="准备 SSH", exact=True).click()
                            page.get_by_text("SSH 配置已准备，尚未验证连接。", exact=True).wait_for()
                            assert "PRIVATE KEY" not in page.locator("body").inner_text()
                            page.screenshot(path=str(screenshot_dir / "company-managed-key-synthetic.png"), full_page=True)
                            fixture["network"] = "not_granted"
                            page.get_by_role("button", name="检查状态", exact=True).click()
                            page.get_by_role("button", name="连接公司网络", exact=True).wait_for()
                            page.wait_for_function("document.querySelectorAll('button').length > 0 && Array.from(document.querySelectorAll('button')).some(b => b.textContent === '连接公司网络' && b.disabled)")
                            assert page.get_by_role("heading", name="Synthetic host", exact=True).count() == 1
                            agent.store.clear()
                            page.get_by_role("button", name="检查状态", exact=True).click()
                            page.get_by_role("button", name="飞书登录", exact=True).wait_for()
                            assert page.get_by_role("button", name="企业 SSO 登录", exact=True).count() == 0
                        finally:
                            fixture_run.close()
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
                                "login cancellation",
                                "expired session",
                                "logout",
                                "390px layout",
                                "unconfigured company integration",
                                "synthetic remote UI distinguishes SSH from Desktop project acceptance",
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
