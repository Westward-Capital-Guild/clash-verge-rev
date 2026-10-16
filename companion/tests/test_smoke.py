"""HTTP smoke uses signed OIDC tokens and PKCE, never a company tenant."""

import base64
import hashlib
import json
import platform
from pathlib import Path
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlsplit

from authlib.jose import JsonWebKey, JsonWebToken
import pytest
import keyring
from keyring.backends.null import Keyring as NullKeyring
import requests
import tomlkit

from workspace_agent import Agent, AgentError


class MemoryStore:
    def __init__(self):
        self.value = None

    def get(self):
        return self.value

    def set(self, value):
        self.value = value

    def clear(self):
        self.value = None


class Provider:
    def __init__(self, *, refresh=True):
        self.refresh = refresh
        self.last_scope = None
        self.key = JsonWebKey.generate_key(
            "RSA", 2048, is_private=True, options={"kid": "smoke"}
        )
        self.codes = {}
        self.revoked = []
        self.refresh_count = 0
        self.claim_overrides = {}
        self.cancel = False
        self.fail_policy = False
        self.fail_revoke = False
        self.foreign_profile = False
        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def reply(self, value, status=200, content_type="application/json"):
                body = (
                    json.dumps(value).encode()
                    if content_type == "application/json"
                    else value.encode()
                )
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.end_headers()
                self.wfile.write(body)

            def authenticated(self):
                return self.headers.get("Authorization") == "Bearer smoke-access"

            def do_GET(self):
                path = urlsplit(self.path)
                if path.path.endswith("/.well-known/openid-configuration"):
                    self.reply(
                        {
                            "issuer": provider.issuer,
                            "authorization_endpoint": provider.base + "/authorize",
                            "token_endpoint": provider.base + "/token",
                            "jwks_uri": provider.base + "/jwks",
                            "revocation_endpoint": provider.base + "/revoke",
                            "code_challenge_methods_supported": ["S256"],
                        }
                    )
                elif path.path == "/jwks":
                    self.reply({"keys": [provider.key.as_dict(is_private=False)]})
                elif path.path == "/authorize":
                    query = parse_qs(path.query)
                    provider.last_scope = query["scope"][0]
                    assert query["code_challenge_method"] == ["S256"]
                    code = str(len(provider.codes) + 1)
                    provider.codes[code] = query
                    result = (
                        {"state": query["state"][0], "error": "access_denied"}
                        if provider.cancel
                        else {"state": query["state"][0], "code": code}
                    )
                    self.send_response(302)
                    self.send_header(
                        "Location", query["redirect_uri"][0] + "?" + urlencode(result)
                    )
                    self.end_headers()
                elif path.path == "/policy" and self.authenticated():
                    if provider.fail_policy:
                        self.reply({"error": "denied"}, 403)
                    else:
                        self.reply(
                            {
                                "version": 1,
                                "codex": {
                                    "base_url": provider.base + "/v1",
                                    "model": "smoke-model",
                                },
                                "network": {
                                    "profile_endpoint": "https://other.invalid/profile"
                                    if provider.foreign_profile
                                    else provider.base + "/profile"
                                },
                            }
                        )
                elif path.path == "/profile" and self.authenticated():
                    self.reply(
                        "mode: rule\nproxies: []\nrules:\n  - MATCH,DIRECT\n",
                        content_type="text/yaml",
                    )
                else:
                    self.reply({"error": "unauthorized"}, 401)

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                if self.path == "/token":
                    form = parse_qs(body.decode())
                    if form.get("grant_type") == ["refresh_token"]:
                        provider.refresh_count += 1
                        self.reply(
                            {
                                "access_token": "smoke-access",
                                "token_type": "Bearer",
                                "expires_in": 300,
                                "refresh_token": "smoke-refresh-rotated",
                            }
                        )
                        return
                    auth = provider.codes.pop(form["code"][0])
                    challenge = (
                        base64.urlsafe_b64encode(
                            hashlib.sha256(form["code_verifier"][0].encode()).digest()
                        )
                        .rstrip(b"=")
                        .decode()
                    )
                    assert auth["code_challenge"] == [challenge]
                    assert auth["redirect_uri"] == form["redirect_uri"]
                    claims = {
                        "iss": provider.issuer,
                        "sub": "smoke-user",
                        "aud": "workspace-smoke",
                        "iat": int(time.time()),
                        "exp": int(time.time()) + 300,
                        "nonce": auth["nonce"][0],
                        "name": "Smoke User",
                        **provider.claim_overrides,
                    }
                    token = (
                        JsonWebToken(["RS256"])
                        .encode({"alg": "RS256", "kid": "smoke"}, claims, provider.key)
                        .decode()
                    )
                    self.reply(
                        {
                            "access_token": "smoke-access",
                            "token_type": "Bearer",
                            "expires_in": 300,
                            **(
                                {"refresh_token": "smoke-refresh"}
                                if provider.refresh
                                else {}
                            ),
                            "id_token": token,
                        }
                    )
                elif self.path == "/credential" and self.authenticated():
                    assert json.loads(body) == {"audience": "codex"}
                    self.reply(
                        {"access_token": "smoke-model-credential", "expires_in": 300}
                    )
                elif self.path == "/revoke":
                    provider.revoked.append(parse_qs(body.decode())["token"][0])
                    self.reply({}, status=503 if provider.fail_revoke else 200)
                elif (
                    self.path == "/v1/responses"
                    and self.headers.get("Authorization")
                    == "Bearer smoke-model-credential"
                ):
                    self.reply(
                        'data: {"type":"response.completed","response":{"status":"completed"}}\n\n',
                        content_type="text/event-stream",
                    )
                else:
                    self.reply({"error": "unauthorized"}, 401)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = f"http://127.0.0.1:{self.server.server_port}"
        self.issuer = self.base + "/application/o/workspace/"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def browser(self, url):
        threading.Thread(
            target=lambda: requests.get(url, timeout=10), daemon=True
        ).start()
        return True


@pytest.fixture
def environment(tmp_path, monkeypatch):
    provider = Provider()
    config = tmp_path / "deployment.json"
    config.write_text(
        json.dumps(
            {
                "version": 1,
                "issuer": provider.issuer,
                "client_id": "workspace-smoke",
                "redirect_port": 0,
                "policy_endpoint": provider.base + "/policy",
                "credential_endpoint": provider.base + "/credential",
            }
        )
    )
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    store = MemoryStore()
    agent = Agent(
        config,
        store=store,
        browser=provider.browser,
        helper="/test/pilgrim-workspace-agent",
    )
    yield agent, provider, store
    provider.close()


def test_sign_in_configure_refresh_model_and_logout(environment):
    agent, provider, store = environment
    assert agent.run("status")["state"] == "signed_out"
    assert agent.run("login")["name"] == "Smoke User"
    target = agent.codex_path()
    target.parent.mkdir()
    original = '# Personal settings\nmodel = "personal-model"\n[projects."/work"]\ntrust_level = "trusted"\n'
    target.write_text(original)
    assert agent.run("configure")["codex"]
    configured = target.read_text()
    parsed = tomlkit.parse(configured)
    assert "# Personal settings" in configured
    assert parsed["model"] == "personal-model"
    assert parsed["projects"]["/work"]["trust_level"] == "trusted"
    assert "profiles" not in parsed
    assert not target.with_name("pilgrim.config.toml").exists()
    assert "smoke-access" not in configured and "smoke-refresh" not in configured
    assert target.with_name("config.before-workspace.toml").read_text() == original
    agent.run("configure")
    assert target.read_text() == configured
    assert "MATCH,DIRECT" in agent.run("network-profile")["yaml"]
    store.value["token"]["expires_at"] = 1
    assert agent.run("status")["state"] == "expired"
    credential = agent.run("token")
    assert provider.refresh_count == 1
    assert store.value["token"]["refresh_token"] == "smoke-refresh-rotated"
    response = requests.post(
        provider.base + "/v1/responses",
        headers={"Authorization": "Bearer " + credential},
        json={"model": "smoke-model", "input": "smoke", "stream": True},
        stream=True,
        timeout=5,
    )
    assert response.status_code == 200
    assert any(
        '"type":"response.completed"' in line.decode()
        for line in response.iter_lines()
        if line
    )
    assert agent.run("logout")["remote_revoked"]
    assert "smoke-refresh-rotated" in provider.revoked
    assert store.get() is None
    with pytest.raises(AgentError, match="SIGN_IN_REQUIRED"):
        agent.run("token")


def test_configure_preserves_existing_profiles(environment):
    agent, _, _ = environment
    agent.run("login")
    target = agent.codex_path()
    target.parent.mkdir()
    original = '[profiles.pilgrim]\nmodel_provider = "personal"\nmodel = "personal-model"\n'
    target.write_text(original)
    profile_path = target.with_name("pilgrim.config.toml")
    profile_original = '# User profile\nmodel = "another-personal-model"\n'
    profile_path.write_text(profile_original)
    assert agent.run("configure")["codex"]
    assert tomlkit.parse(target.read_text())["profiles"]["pilgrim"]["model_provider"] == "personal"
    assert profile_path.read_text() == profile_original


@pytest.mark.parametrize(
    "claim,value",
    [
        ("aud", "other-client"),
        ("iss", "https://other.invalid"),
        ("nonce", "wrong"),
        ("exp", 1),
    ],
)
def test_invalid_identity_never_persists_credentials(environment, claim, value):
    agent, provider, store = environment
    provider.claim_overrides = {claim: value}
    with pytest.raises(Exception):
        agent.run("login")
    assert store.get() is None


def test_cancellation_and_wrong_state(environment):
    agent, provider, store = environment

    def browser(url):
        query = parse_qs(urlsplit(url).query)

        def finish():
            invalid = requests.get(
                query["redirect_uri"][0],
                params={"state": "wrong", "code": "malicious"},
                timeout=5,
            )
            assert invalid.status_code == 400
            requests.get(url, timeout=5)

        threading.Thread(target=finish, daemon=True).start()
        return True

    agent.browser = browser
    provider.cancel = True
    with pytest.raises(AgentError, match="SIGN_IN_CANCELLED"):
        agent.run("login")
    assert store.get() is None


def test_failed_policy_preserves_config_and_failed_revocation_clears_session(
    environment,
):
    agent, provider, store = environment
    agent.run("login")
    target = agent.codex_path()
    target.parent.mkdir()
    target.write_text('model = "personal"\n')
    provider.fail_policy = True
    with pytest.raises(requests.HTTPError):
        agent.run("configure")
    assert target.read_text() == 'model = "personal"\n'
    provider.fail_revoke = True
    assert agent.run("logout")["remote_revoked"] is False
    assert store.get() is None


def test_foreign_network_origin_and_existing_provider_are_rejected(environment):
    agent, provider, _ = environment
    agent.run("login")
    provider.foreign_profile = True
    with pytest.raises(AgentError, match="PROFILE_ORIGIN_MISMATCH"):
        agent.run("network-profile")
    target = agent.codex_path()
    target.parent.mkdir()
    target.write_text('[model_providers.pilgrim]\nname = "My provider"\n')
    with pytest.raises(AgentError, match="CODEX_PROVIDER_CONFLICT"):
        agent.run("configure")
    assert "My provider" in target.read_text()


def test_missing_config_has_no_keyring_dependency(tmp_path):
    assert Agent(tmp_path / "missing.json").run("status")["state"] == "unconfigured"


def test_unavailable_os_keyring_has_no_plaintext_fallback(environment, monkeypatch):
    agent, _, _ = environment
    monkeypatch.setattr(keyring, "get_keyring", lambda: NullKeyring())
    production_agent = Agent(agent.path, helper=agent.helper)
    with pytest.raises(AgentError, match="OS_KEYRING_UNAVAILABLE"):
        production_agent.run("login")


def test_insecure_remote_issuer_rejected(tmp_path):
    config = tmp_path / "bad.json"
    config.write_text(json.dumps({"version": 1, "issuer": "http://insecure.invalid"}))
    with pytest.raises(AgentError, match="HTTPS_REQUIRED"):
        Agent(config)


def test_provisioned_profile_forwards_through_real_mihomo(environment, tmp_path):
    agent, provider, _ = environment
    host = {
        ("Linux", "x86_64"): "x86_64-unknown-linux-gnu",
        ("Darwin", "x86_64"): "x86_64-apple-darwin",
        ("Darwin", "arm64"): "aarch64-apple-darwin",
    }.get((platform.system(), platform.machine()))
    if host is None:
        pytest.skip("Real core smoke is unavailable for this host")
    binary = (
        Path(__file__).resolve().parents[2]
        / f"src-tauri/sidecar/verge-mihomo-{host}"
    )
    if not binary.exists():
        pytest.skip("Run pnpm prebuild for the real core smoke")
    agent.run("login")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    profile = tmp_path / "network.yaml"
    profile.write_text(
        agent.run("network-profile")["yaml"]
        + f"mixed-port: {port}\nallow-lan: false\nbind-address: 127.0.0.1\n"
    )
    subprocess.run(
        [str(binary), "-t", "-d", str(tmp_path / "core"), "-f", str(profile)],
        check=True,
        capture_output=True,
        timeout=15,
    )
    with (tmp_path / "core.log").open("w") as output:
        process = subprocess.Popen(
            [str(binary), "-d", str(tmp_path / "core"), "-f", str(profile)],
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            for _ in range(100):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.1)
            with requests.Session() as client:
                client.trust_env = False
                # The core binds its listener before initializing its proxy providers.
                for _ in range(50):
                    response = client.get(
                        provider.issuer + ".well-known/openid-configuration",
                        proxies={"http": f"http://127.0.0.1:{port}"},
                        timeout=10,
                    )
                    if response.status_code == 200:
                        break
                    time.sleep(0.1)
            assert response.status_code == 200
            assert response.json()["issuer"] == provider.issuer
        finally:
            process.terminate()
            process.wait(timeout=10)


def test_two_providers_keep_sessions_and_gateways_separate(tmp_path, monkeypatch):
    feishu, authentik = Provider(refresh=False), Provider()
    try:
        config = tmp_path / "deployment.json"
        providers = {
            name: {
                "issuer": server.issuer,
                "client_id": "workspace-smoke",
                "redirect_port": 0,
                "policy_endpoint": server.base + "/policy",
                "credential_endpoint": server.base + "/credential",
            }
            for name, server in (("feishu", feishu), ("authentik", authentik))
        }
        config.write_text(json.dumps({"version": 2, "providers": providers}))
        monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
        store = MemoryStore()
        agent = Agent(
            config, store=store, browser=feishu.browser, helper="/test/helper"
        )
        assert agent.status()["providers"] == ["feishu", "authentik"]
        with pytest.raises(AgentError, match="PROVIDER_REQUIRED"):
            agent.run("login")
        assert agent.run("login-feishu")["provider"] == "feishu"
        assert feishu.last_scope == "openid profile"
        assert authentik.last_scope is None
        assert agent.policy()["codex"]["base_url"] == feishu.base + "/v1"
        assert agent.run("configure")["codex"]
        assert agent.run("token-feishu") == "smoke-model-credential"
        assert "MATCH,DIRECT" in agent.run("network-profile")["yaml"]
        # A fresh CLI invocation must recover the selected provider from Keychain.
        agent = Agent(
            config, store=store, browser=authentik.browser, helper="/test/helper"
        )
        with pytest.raises(AgentError, match="SIGN_OUT_FIRST"):
            agent.run("login-authentik")
        store.value["token"]["expires_at"] = 1
        store.value["token"]["refresh_token"] = "unexpected-feishu-refresh"
        with pytest.raises(AgentError, match="SESSION_EXPIRED"):
            agent.run("token-feishu")
        store.value["token"].pop("refresh_token")
        assert feishu.refresh_count == 0
        assert agent.run("logout")["remote_revoked"]
        assert len(feishu.revoked) == 1 and not authentik.revoked
        assert agent.run("login-authentik")["provider"] == "authentik"
        assert not agent.status()["codex"]
        with pytest.raises(AgentError, match="PROVIDER_MISMATCH"):
            agent.run("token-feishu")
        with pytest.raises(AgentError, match="PROVIDER_REQUIRED"):
            agent.run("token")
        assert authentik.last_scope == "openid profile offline_access"
        assert agent.policy()["codex"]["base_url"] == authentik.base + "/v1"
        assert agent.run("configure")["codex"]
        store.value["token"]["expires_at"] = 1
        assert agent.run("token-authentik") == "smoke-model-credential"
        assert authentik.refresh_count == 1
        assert agent.run("logout")["remote_revoked"]
        assert len(authentik.revoked) == 2
        assert store.get() is None
    finally:
        feishu.close()
        authentik.close()


def test_unconfigured_provider_is_rejected_before_browser(environment):
    agent, provider, store = environment
    with pytest.raises(AgentError, match="PROVIDER_NOT_CONFIGURED"):
        agent.run("login-feishu")
    assert provider.last_scope is None and store.get() is None
