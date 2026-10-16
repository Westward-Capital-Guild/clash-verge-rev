"""Passport contract regressions with synthetic keys and isolated local state."""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from remote_ssh import RemoteSSH, key_fingerprint
from test_smoke import MemoryStore
from workspace_access import AccessError, WorkspaceAccess
from workspace_agent import Agent, AgentError


@pytest.fixture
def service(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    fingerprint = key_fingerprint(public)
    fixture = {"calls": [], "network": "granted", "development_hosts": "granted", "error": None, "revision": "revision-1", "private": private}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, value, status=200, media="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", media)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(json.dumps(value).encode() if media == "application/json" else value.encode())

        def do_GET(self):
            fixture["calls"].append(self.path)
            if self.path == "/workspace/bootstrap":
                self.reply(fixture["bootstrap"])
                return
            if self.headers.get("Authorization") != "Bearer synthetic-a":
                self.reply({"error": {"code": "INVALID_SESSION", "retryable": False}}, 401)
                return
            if fixture["error"]:
                status, code = fixture["error"]
                self.reply({"error": {"code": code, "retryable": status == 503}}, status)
            elif self.path == "/workspace/policy":
                policy = {"version": 2, "binding_id": "member-a", "revision": fixture["revision"], "capabilities": {
                    "network": fixture["network"], "development_hosts": fixture["development_hosts"], "local_model": "not_granted"}}
                if fixture["network"] == "granted":
                    policy["network"] = {"profile_endpoint": base + "/workspace/network-profile"}
                if fixture["development_hosts"] == "granted":
                    policy["development_hosts"] = {"endpoint": base + "/workspace/development-hosts"}
                self.reply(policy)
            elif self.path == "/workspace/network-profile":
                if fixture.get("redirect"):
                    self.send_response(302)
                    self.send_header("Location", "https://forbidden.example.invalid/profile")
                    self.end_headers()
                else:
                    self.reply(fixture.get("profile", "proxies: []\nrules: [MATCH,DIRECT]\n"), media="application/yaml")
            elif self.path == "/workspace/development-hosts":
                self.reply({"version": 1, "binding_id": "member-a", "revision": fixture["revision"], "capability": "granted", "hosts": [fixture["host"]]})
            else:
                self.reply("private upstream error", 503, "text/html")

        def do_POST(self):
            fixture["calls"].append(self.path)
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            if self.headers.get("Authorization") != "Bearer synthetic-a":
                self.reply({"error": {"code": "INVALID_SESSION"}}, 401)
            elif body != {"version": 1, "revision": fixture["revision"]}:
                self.reply({"error": {"code": "BINDING_CHANGED"}}, 409)
            else:
                self.reply({"version": 1, "binding_id": fixture.get("key_binding", "member-a"), "revision": fixture["revision"],
                            "host_id": "host-a", "format": "openssh", "private_key": fixture["private"], "fingerprint_sha256": fingerprint})

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    base = f"http://127.0.0.1:{server.server_port}"
    fixture["bootstrap"] = {"version": 1, "company_name": "Fixture company", "providers": {"feishu": {
        "issuer": base, "client_id": "fixture-client", "scope": "openid profile", "redirect_port": 47831,
        "redirect_uri": "http://127.0.0.1:47831/callback"}}, "policy_endpoint": base + "/workspace/policy",
        "network_profile_endpoint": base + "/workspace/network-profile", "development_hosts_endpoint": base + "/workspace/development-hosts"}
    fixture["host"] = {"id": "host-a", "display_name": "Synthetic host", "connection": {"hostname": "127.0.0.1", "port": 2222,
        "username": "fixture", "transport": "ssh", "network_requirement": "direct",
        "host_keys": [{"algorithm": "ssh-ed25519", "public_key": public.split()[1]}]},
        "workspaces": [{"id": "project", "display_name": "Synthetic project", "path": "/workspace/a folder's project"}],
        "ssh_access_mode": "managed-keypair", "user_key_fingerprints": [fingerprint], "managed_key_fingerprint": fingerprint,
        "ssh_credential_endpoint": base + "/workspace/development-hosts/host-a/ssh-credential"}
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    store = MemoryStore()
    store.set({"provider": "feishu", "session_id": "login-a", "identity": {"sub": "a", "name": "Fixture A"},
               "client": [base, "fixture-client"], "token": {"access_token": "synthetic-a", "expires_at": time.time() + 300}})
    agent = Agent(tmp_path / "unused.json", store=store, bootstrap_url=base + "/workspace/bootstrap", allow_loopback=True,
                  remote_ssh=RemoteSSH(tmp_path / "home"))
    try:
        yield fixture, agent
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


@pytest.mark.parametrize("network,hosts", [("granted", "not_granted"), ("not_granted", "granted"), ("granted", "granted")])
def test_independent_capabilities_and_no_model_dependency(service, network, hosts):
    fixture, agent = service
    fixture.update(network=network, development_hosts=hosts)
    assert agent.status()["capabilities"]["network"] == network
    assert agent.status()["providers"] == ["feishu"]
    if network == "granted":
        assert "yaml" in agent.run("network-profile")
    else:
        with pytest.raises(AgentError, match="NETWORK_NOT_GRANTED"):
            agent.run("network-profile")
    assert agent.remote("hosts")["state"] == ("available" if hosts == "granted" else "not_authorized")
    with pytest.raises(AgentError, match="LOCAL_MODEL_NOT_GRANTED"):
        agent.run("configure")
    assert not agent.codex_path().exists()
    assert not any("credential" in call for call in fixture["calls"])


def test_managed_key_installed_privately_idempotently_and_not_returned(service):
    fixture, agent = service
    assert agent.remote("hosts")["state"] == "available"
    assert not any("credential" in call for call in fixture["calls"])
    first = agent.remote("prepare", "host-a", "project")
    assert first["state"] == "ssh_prepared", first
    key = agent.remote_ssh.managed / (first["alias"] + ".key")
    assert key.stat().st_mode & 0o777 == 0o600
    assert key.read_text() == fixture["private"]
    assert "PRIVATE KEY" not in json.dumps(first)
    assert agent.remote("prepare", "host-a", "project") == first
    key.write_text("unrelated local key")
    assert agent.remote("prepare", "host-a", "project")["state"] == "config_conflict"
    assert key.read_text() == "unrelated local key"


def test_binding_revision_key_and_member_isolation(service):
    fixture, agent = service
    policy = agent.policy()
    host = agent.access.hosts(agent.access_token(), policy)[0]
    fixture["revision"] = "revision-2"
    with pytest.raises(AccessError, match="BINDING_CHANGED"):
        agent.access.credential(agent.access_token(), host)
    fixture["key_binding"] = "member-b"
    assert agent.remote("prepare", "host-a", "project")["state"] == "binding_changed"
    fixture["key_binding"] = "member-a"
    wrong = Ed25519PrivateKey.generate()
    fixture["private"] = wrong.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH, serialization.NoEncryption()).decode()
    assert agent.remote("prepare", "host-a", "project")["state"] == "key_mismatch"
    assert not agent.remote_ssh.managed.exists()
    agent.store.value["token"]["access_token"] = "synthetic-b"
    assert agent.remote("hosts")["code"] == "INVALID_SESSION"


@pytest.mark.parametrize("status,code,state", [(403, "MEMBER_BINDING_MISMATCH", "not_authorized"), (503, "WORKSPACE_UNAVAILABLE", "unavailable"), (409, "BINDING_CHANGED", "binding_changed")])
def test_error_codes_preserved_without_disclosing_bodies(service, status, code, state):
    fixture, agent = service
    fixture["error"] = status, code
    result = agent.remote("hosts")
    assert result == {"state": state, "code": code, "hosts": []}
    fixture["error"] = None
    with pytest.raises(AccessError, match="WORKSPACE_UNAVAILABLE"):
        agent.access.request(agent.access.origin[0] + "://127.0.0.1:" + str(agent.access.origin[2]) + "/upstream", agent.access_token())


def test_bootstrap_origin_https_and_version_fail_closed(service):
    fixture, agent = service
    with pytest.raises(AccessError, match="HTTPS_REQUIRED"):
        WorkspaceAccess(agent.access.bootstrap_url)
    for endpoint in ("https://@example.invalid", "https://example.invalid:0", "https://example.invalid:invalid"):
        with pytest.raises(AccessError, match="INVALID_ENDPOINT"):
            WorkspaceAccess(endpoint)
    fixture["bootstrap"]["providers"]["feishu"]["issuer"] = "https://other.example.invalid"
    with pytest.raises(AccessError, match="ENDPOINT_ORIGIN_MISMATCH"):
        agent.access.load()
    fixture["bootstrap"]["version"] = 8
    with pytest.raises(AccessError, match="UNSUPPORTED_VERSION"):
        agent.access.load()


def test_registered_key_never_requests_private_key(service):
    fixture, agent = service
    host = fixture["host"]
    host["ssh_access_mode"] = "registered-public-key"
    ssh = agent.remote_ssh.ssh
    ssh.mkdir(parents=True, mode=0o700)
    identity = ssh / "id_ed25519"
    identity.write_text(fixture["private"])
    identity.chmod(0o600)
    identity.with_suffix(".pub").write_text("ssh-ed25519 " + host["connection"]["host_keys"][0]["public_key"])
    assert agent.remote("prepare", "host-a", "project")["state"] == "ssh_prepared"
    assert not any("credential" in call for call in fixture["calls"])


def test_redirect_and_oversized_profile_are_rejected(service):
    fixture, agent = service
    fixture["redirect"] = True
    with pytest.raises(AccessError, match="REDIRECT_FORBIDDEN"):
        agent.run("network-profile")
    fixture["redirect"] = False
    fixture["profile"] = "x" * 2_000_001
    with pytest.raises(AccessError, match="PROFILE_TOO_LARGE"):
        agent.run("network-profile")
