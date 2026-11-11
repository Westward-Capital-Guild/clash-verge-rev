"""Focused coverage for the rc.7 configuration delivery contract."""

import json
from concurrent.futures import ThreadPoolExecutor
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time
from types import SimpleNamespace
import pytest
from test_smoke import MemoryStore
from workspace_access import AccessError, WorkspaceAccess
from workspace_agent import Agent


@pytest.fixture
def reporting_agent(tmp_path):
    store = MemoryStore()
    store.set({"provider": "feishu", "identity": {"sub": "member-a"}})
    agent = Agent(tmp_path / "unused.json", store=store)
    agent.providers = {"feishu": {"issuer": "https://passport.example", "client_id": "workspace-desktop"}}
    agent.access = SimpleNamespace(
        bootstrap={"installations_endpoint": "https://passport.example/workspace/installations"},
        register_installation=lambda *_: None,
    )
    return agent


def test_report_retry_preserves_payload_and_new_revision_gets_new_identity(reporting_agent):
    agent = reporting_agent
    sent = []

    def send(*args):
        sent.append(args[2:])
        if len(sent) == 1:
            raise AccessError("WORKSPACE_UNAVAILABLE")

    agent.access.report = send
    assert not agent._report("token", {"id": "network", "revision": "r1"}, "received")
    assert agent._report("token", {"id": "network", "revision": "r1"}, "received")
    assert sent[0] == sent[1]
    assert agent._report("token", {"id": "network", "revision": "r2"}, "received")
    assert sent[2][0] != sent[1][0]
    assert sent[2][1] == {"configuration_id": "network", "revision": "r2", "sequence": 2, "stage": "received", "error_code": None}
    assert agent._report("token", {"id": "network", "revision": "r2"}, "received")
    assert len(sent) == 3


def test_concurrent_reports_share_one_installation_and_preserve_both_resources(reporting_agent):
    agent = reporting_agent
    first_registration, duplicate_registration, release = threading.Event(), threading.Event(), threading.Event()
    registered = []

    def register(*args):
        registered.append(args[1])
        if len(registered) > 1:
            duplicate_registration.set()
        first_registration.set()
        assert release.wait(5)

    agent.access.register_installation = register
    agent.access.report = lambda *_: None
    with ThreadPoolExecutor() as pool:
        first = pool.submit(agent._report, "token", {"id": "network", "revision": "r1"}, "received")
        assert first_registration.wait(5)
        second = pool.submit(agent._report, "token", {"id": "ssh-host", "revision": "r2"}, "received")
        try:
            assert not duplicate_registration.wait(0.2)
        finally:
            release.set()
        assert first.result() and second.result()
    assert len(registered) == 1
    assert set(agent._delivery_state()["reports"]) == {"network", "ssh-host"}


def test_ssh_report_refers_to_delivered_revision_when_catalogue_changes(reporting_agent):
    agent = reporting_agent
    configuration = {"id": "ssh-host", "revision": "r1", "kind": "ssh", "binding_id": "member-a"}
    catalogue = [configuration]
    agent.access.bootstrap["configurations_endpoint"] = "https://passport.example/workspace/configurations"
    agent.access.policy = lambda _: {"capabilities": {"development_hosts": "granted"}}
    agent.access.configurations = lambda _: catalogue
    agent.access_token = lambda: "token"
    agent._configuration_delivery = lambda *_: (configuration, {"configuration": {
        "connection": {}, "workspaces": [{"id": "repo"}], "ssh_access_mode": "registered-public-key",
    }})

    def check(*_):
        catalogue[:] = [{**configuration, "revision": "r2"}]
        return {"state": "ssh_ready"}

    agent.remote_ssh = SimpleNamespace(check=check)
    reported = []
    agent._report = lambda *args: reported.append(args[1:])
    assert agent.remote("check", "host", "repo")["state"] == "ssh_ready"
    assert reported == [(configuration, "verified")]
    assert reported[0][0]["revision"] == "r1"


def test_ssh_delivery_does_not_duplicate_source_host_key_algorithm(reporting_agent):
    agent = reporting_agent
    configuration = {"id": "ssh-host", "revision": "r1", "kind": "ssh", "binding_id": "member-a"}
    agent.access.bootstrap["configurations_endpoint"] = "https://passport.example/workspace/configurations"
    agent.access.policy = lambda _: {"capabilities": {"development_hosts": "granted"}}
    agent.access.configurations = lambda _: [configuration]
    agent.access_token = lambda: "token"
    delivered = {"configuration": {
        "connection": {
            "transport": "ssh", "network_requirement": "direct", "hostname": "host.example",
            "port": 22, "username": "dev",
            "host_keys": [{"algorithm": "ssh-ed25519", "public_key": "ssh-ed25519 AAAA-source comment"}],
        },
        "workspaces": [{"id": "repo"}], "ssh_access_mode": "registered-public-key",
        "user_key_fingerprints": ["SHA256:key"],
    }}
    agent._configuration_delivery = lambda *_: (configuration, delivered)
    seen = []
    agent.remote_ssh = SimpleNamespace(check=lambda record, workspace: seen.append(record) or {"state": "ssh_ready"})
    agent._report = lambda *_: None
    assert agent.remote("check", "host", "repo")["state"] == "ssh_ready"
    assert seen[0]["connection"]["host_keys"] == ["ssh-ed25519 AAAA-source comment"]


def test_codex_synchronization_reads_config_after_acquiring_lock(reporting_agent, tmp_path, monkeypatch):
    import workspace_agent
    import tomlkit

    agent = reporting_agent
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    target = agent.codex_path()
    target.parent.mkdir()
    target.write_text('model_provider = "original"\n')
    original_lock = workspace_agent.FileLock

    def lock_after_user_edit(path, **kwargs):
        if path.endswith(".workspace.lock"):
            target.write_text('model_provider = "updated"\n[model_providers.updated]\nname = "Existing provider"\n')
        return original_lock(path, **kwargs)

    monkeypatch.setattr(workspace_agent, "FileLock", lock_after_user_edit)
    agent.status = lambda: {}
    agent.configure()
    document = tomlkit.parse(target.read_text())
    assert document["model_provider"] == "updated"
    assert document["model_providers"]["updated"] == {"name": "Existing provider"}
    assert document["profiles"]["pilgrim_workspace"] == {"model_provider": "updated"}


def test_configuration_catalogue_rejects_wrong_kind_id(monkeypatch):
    access = WorkspaceAccess("https://passport.example/workspace/bootstrap")
    access.bootstrap = {
        "configurations_endpoint": "https://passport.example/workspace/configurations",
    }
    monkeypatch.setattr(
        access,
        "request",
        lambda *_args, **_kwargs: {
            "version": 1,
            "binding_id": "member-a",
            "configurations": [{
                "id": "ssh-host-a",
                "kind": "mihomo",
                "revision": "r1",
                "preparation": "prepared",
                "observation": None,
            }],
        },
    )
    with pytest.raises(AccessError, match="INVALID_RESPONSE"):
        access.configurations("token")


def test_configuration_catalogue_accepts_people_observation_shape(monkeypatch):
    access = WorkspaceAccess("https://passport.example/workspace/bootstrap")
    access.bootstrap = {
        "configurations_endpoint": "https://passport.example/workspace/configurations",
    }
    monkeypatch.setattr(
        access,
        "request",
        lambda *_args, **_kwargs: {
            "version": 1,
            "binding_id": "member-a",
            "configurations": [{
                "id": "network",
                "kind": "mihomo",
                "revision": "r1",
                "preparation": "prepared",
                "observation": {
                    "executor": "people",
                    "observed_at": "2026-11-11T00:00:00Z",
                    "source": "mihomo",
                    "status": "verified",
                    "valid_for_seconds": 300,
                    "work_order_id": "work-1",
                },
            }],
        },
    )
    result = access.configurations("token")
    assert result[0]["observation"] == {
        "principal_id": "member-a",
        "configuration_id": "network",
        "revision": "r1",
        "status": "verified",
        "reason": None,
    }


def test_delivery_rejects_private_key_for_registered_public_key(monkeypatch):
    access = WorkspaceAccess("https://passport.example/workspace/bootstrap")
    access.bootstrap = {
        "configurations_endpoint": "https://passport.example/workspace/configurations",
    }
    monkeypatch.setattr(
        access,
        "request",
        lambda *_args, **_kwargs: {
            "version": 1,
            "binding_id": "member-a",
            "id": "ssh-host-a",
            "kind": "ssh",
            "revision": "r1",
            "configuration": {
                "connection": {
                    "transport": "ssh",
                    "network_requirement": "direct",
                    "hostname": "host.example",
                    "port": 22,
                    "username": "dev",
                    "host_keys": [{"algorithm": "ssh-ed25519", "public_key": "AAAA"}],
                },
                "workspaces": [{"id": "repo", "display_name": "Repo", "path": "/srv/repo"}],
                "ssh_access_mode": "registered-public-key",
                "user_key_fingerprints": ["SHA256:key"],
                "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
            },
        },
    )
    configuration = {
        "id": "ssh-host-a",
        "kind": "ssh",
        "revision": "r1",
        "binding_id": "member-a",
    }
    with pytest.raises(AccessError, match="INVALID_HOST"):
        access.delivery("token", configuration)


def test_report_conflict_rotates_installation(tmp_path):
    store = MemoryStore()
    store.set({"provider": "feishu", "identity": {"sub": "member-a"}})
    agent = Agent(tmp_path / "unused.json", store=store)
    registered = []

    class ConflictAccess:
        bootstrap = {"installations_endpoint": "https://passport.example/workspace/installations"}

        def register_installation(self, *_args):
            registered.append(True)

        def report(self, *_args):
            raise AccessError("REPORT_CONFLICT")

    agent.access = ConflictAccess()
    agent.providers = {"feishu": {"issuer": "https://passport.example", "client_id": "workspace-desktop"}}
    first = agent._delivery_state()["installation_id"]
    assert agent._report("token", {"id": "network", "revision": "r1"}, "received") is False
    second = agent._delivery_state()["installation_id"]
    assert registered and first != second


def test_rc7_delivery_registers_once_reports_idempotently(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    calls = []
    reports = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, value, status=200):
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(value).encode())

        def do_GET(self):
            calls.append(("GET", self.path))
            if self.path == "/workspace/bootstrap":
                self.reply({
                    "version": 1,
                    "providers": {"feishu": {
                        "issuer": base, "client_id": "workspace-desktop",
                        "scope": "openid profile", "redirect_port": 47831,
                        "redirect_uri": "http://127.0.0.1:47831/callback",
                    }},
                    "policy_endpoint": base + "/workspace/policy",
                    "network_profile_endpoint": base + "/workspace/network-profile",
                    "development_hosts_endpoint": base + "/workspace/development-hosts",
                    "configurations_endpoint": base + "/workspace/configurations",
                    "installations_endpoint": base + "/workspace/installations",
                })
            elif self.path == "/workspace/policy":
                self.reply({
                    "version": 2, "binding_id": "member-a", "revision": "policy-1",
                    "capabilities": {"network": "granted", "development_hosts": "not_granted", "local_model": "not_granted"},
                    "network": {"profile_endpoint": base + "/workspace/network-profile"},
                })
            elif self.path == "/workspace/configurations":
                self.reply({
                    "version": 1, "binding_id": "member-a", "configurations": [{
                        "id": "network", "kind": "mihomo", "revision": "network-1",
                        "preparation": "prepared", "observation": None,
                    }],
                })
            else:
                self.reply({"error": {"code": "RESOURCE_NOT_FOUND"}}, 404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            calls.append(("POST", self.path, body))
            if self.path == "/workspace/installations":
                self.reply({"version": 1, "id": body["id"], "binding_id": "member-a"})
            elif self.path == "/workspace/configurations/network/delivery":
                self.reply({
                    "version": 1, "binding_id": "member-a", "id": "network",
                    "kind": "mihomo", "revision": "network-1",
                    "configuration": {"yaml": "proxies: []\nrules: [MATCH,DIRECT]\n"},
                })
            else:
                self.reply({"error": {"code": "RESOURCE_NOT_FOUND"}}, 404)

        def do_PUT(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length) or b"{}")
            calls.append(("PUT", self.path, body))
            reports.append((self.path, body))
            self.reply({"version": 1, "report_id": self.path.rsplit("/", 1)[-1], "source": "client_self_report"})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    store = MemoryStore()
    store.set({"provider": "feishu", "session_id": "login-a", "identity": {"sub": "a", "name": "A"}, "client": [base, "workspace-desktop"], "token": {"access_token": "token", "expires_at": time.time() + 300}})
    agent = Agent(tmp_path / "unused.json", store=store, bootstrap_url=base + "/workspace/bootstrap", allow_loopback=True, helper="/test/helper")
    try:
        target = agent.codex_path()
        target.parent.mkdir(parents=True)
        target.write_text('model_provider = "customer"\n[model_providers.customer]\nname = "Existing"\n')
        assert agent.run("configure")["codex"]
        assert "model_provider = \"customer\"" in target.read_text()
        assert "pilgrim_workspace" in target.read_text()
        assert "name = \"Existing\"" in target.read_text()
        first = agent.run("network-profile")
        second = agent.run("network-profile")
        assert "MATCH,DIRECT" in first["yaml"] and second["revision"] == "network-1"
        assert len([call for call in calls if call[0] == "POST" and call[1] == "/workspace/installations"]) == 1
        assert len(reports) == 1
        assert agent.delivery_state_path.exists()
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
