"""Generic public companion. Deployment configuration is supplied locally."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
import webbrowser

from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import JsonWebToken
from authlib.oidc.core import CodeIDToken
from filelock import FileLock
import keyring
import requests
import tomlkit


class AgentError(Exception):
    pass


def secure_url(value):
    url = urlsplit(value)
    if url.username or url.password or url.fragment:
        raise AgentError("INVALID_ENDPOINT")
    if url.scheme != "https" and not (
        url.scheme == "http" and url.hostname in ("127.0.0.1", "::1")
    ):
        raise AgentError("HTTPS_REQUIRED")
    if not url.hostname:
        raise AgentError("INVALID_ENDPOINT")
    return value


def atomic_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink():
        raise AgentError("SYMLINK_NOT_SUPPORTED")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".workspace-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


class CredentialStore:
    def __init__(self, account):
        self.account = account

    def backend(self):
        backend = keyring.get_keyring()
        if type(backend).__module__ not in (
            "keyring.backends.SecretService",
            "keyring.backends.macOS",
            "keyring.backends.Windows",
            "keyring.backends.libsecret",
        ):
            raise AgentError("OS_KEYRING_UNAVAILABLE")
        return backend

    def get(self):
        raw = self.backend().get_password("Pilgrim Workspace", self.account)
        return json.loads(raw) if raw else None

    def set(self, value):
        self.backend().set_password(
            "Pilgrim Workspace", self.account, json.dumps(value)
        )

    def clear(self):
        if self.get() is not None:
            self.backend().delete_password("Pilgrim Workspace", self.account)


class Agent:
    def __init__(
        self, config_path, *, store=None, browser=webbrowser.open, helper=None
    ):
        self.path = Path(config_path).expanduser().resolve()
        self.config = json.loads(self.path.read_text()) if self.path.exists() else None
        self.browser = browser
        self.helper = str(Path(helper or sys.argv[0]).resolve())
        self.metadata = None
        if self.config:
            if self.config.get("version") != 1:
                raise AgentError("UNSUPPORTED_CONFIG_VERSION")
            for field in ("issuer", "policy_endpoint", "credential_endpoint"):
                secure_url(self.config[field])
            if not self.config.get("client_id"):
                raise AgentError("CLIENT_ID_REQUIRED")
        account = hashlib.sha256(
            (str(self.path) + json.dumps(self.config, sort_keys=True)).encode()
        ).hexdigest()
        self.store = store or CredentialStore(account)

    def discover(self):
        if self.metadata is None:
            issuer = self.config["issuer"]
            response = requests.get(
                issuer.rstrip("/") + "/.well-known/openid-configuration",
                timeout=15,
                allow_redirects=False,
            )
            response.raise_for_status()
            self.metadata = response.json()
            if self.metadata.get("issuer") != issuer:
                raise AgentError("ISSUER_MISMATCH")
            for field in ("authorization_endpoint", "token_endpoint", "jwks_uri"):
                secure_url(self.metadata[field])
            if "S256" not in self.metadata.get("code_challenge_methods_supported", []):
                raise AgentError("PKCE_NOT_SUPPORTED")
        return self.metadata

    def validate_identity(self, token, *, nonce=None, subject=None):
        meta = self.discover()
        response = requests.get(meta["jwks_uri"], timeout=15, allow_redirects=False)
        response.raise_for_status()
        claims = JsonWebToken(["RS256", "ES256"]).decode(
            token["id_token"],
            response.json(),
            claims_cls=CodeIDToken,
            claims_options={
                "iss": {"essential": True, "value": self.config["issuer"]},
                "aud": {"essential": True, "value": self.config["client_id"]},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "sub": {"essential": True},
            },
            claims_params={
                "nonce": nonce,
                "client_id": self.config["client_id"],
                "access_token": token["access_token"],
            },
        )
        claims.validate(leeway=30)
        if subject is not None and claims["sub"] != subject:
            raise AgentError("SUBJECT_MISMATCH")
        return {
            "sub": claims["sub"],
            "name": claims.get("name")
            or claims.get("preferred_username")
            or claims["sub"],
        }

    def client(self, **kwargs):
        return OAuth2Session(
            self.config["client_id"], token_endpoint_auth_method="none", **kwargs
        )

    def login(self):
        if self.store.get():
            raise AgentError("SIGN_OUT_FIRST")
        meta = self.discover()
        nonce, state, verifier = (secrets.token_urlsafe(32) for _ in range(3))
        callback = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                parsed = urlsplit(handler.path)
                values = parse_qs(parsed.query)
                valid = parsed.path == "/callback" and values.get("state") == [state]
                if not valid:
                    handler.send_error(400, "Invalid sign-in callback")
                    return
                callback.append(handler.path)
                handler.send_response(200)
                handler.send_header("Content-Type", "text/plain; charset=utf-8")
                handler.send_header("Cache-Control", "no-store")
                handler.send_header("Referrer-Policy", "no-referrer")
                handler.end_headers()
                handler.wfile.write(
                    b"Return to Pilgrim Workspace to finish signing in."
                )

            def log_message(self, *_):
                pass

        port = self.config.get("redirect_port", 47831)

        class CallbackServer(HTTPServer):
            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(2)
                return connection, address

        with CallbackServer(("127.0.0.1", port), Handler) as server:
            server.timeout = 0.5
            redirect = f"http://127.0.0.1:{server.server_port}/callback"
            with self.client(
                redirect_uri=redirect,
                scope="openid profile offline_access",
                code_challenge_method="S256",
            ) as client:
                url, _ = client.create_authorization_url(
                    meta["authorization_endpoint"],
                    state=state,
                    nonce=nonce,
                    code_verifier=verifier,
                )
                if not self.browser(url):
                    raise AgentError("BROWSER_OPEN_FAILED")
                deadline = time.monotonic() + 120
                while not callback and time.monotonic() < deadline:
                    server.handle_request()
                if not callback:
                    raise AgentError("SIGN_IN_TIMED_OUT")
                values = parse_qs(urlsplit(callback[0]).query)
                if "error" in values:
                    raise AgentError("SIGN_IN_CANCELLED")
                if len(values.get("code", [])) != 1:
                    raise AgentError("INVALID_CALLBACK")
                token = client.fetch_token(
                    meta["token_endpoint"],
                    code=values["code"][0],
                    code_verifier=verifier,
                    timeout=15,
                    allow_redirects=False,
                )
        identity = self.validate_identity(token, nonce=nonce)
        self.store.set({"token": dict(token), "identity": identity})
        return self.status()

    def access_token(self):
        session = self.store.get()
        if not session:
            raise AgentError("SIGN_IN_REQUIRED")
        token = session["token"]
        if token.get("expires_at", 0) <= time.time() + 30:
            if not token.get("refresh_token"):
                raise AgentError("SESSION_EXPIRED")
            with self.client(token=token) as client:
                refreshed = dict(
                    client.refresh_token(
                        self.discover()["token_endpoint"],
                        refresh_token=token["refresh_token"],
                        timeout=15,
                        allow_redirects=False,
                    )
                )
            if "id_token" in refreshed:
                self.validate_identity(refreshed, subject=session["identity"]["sub"])
            refreshed.setdefault("refresh_token", token["refresh_token"])
            session["token"] = refreshed
            self.store.set(session)
            token = refreshed
        return token["access_token"]

    def status(self):
        if not self.config:
            return {"state": "unconfigured", "name": None, "codex": False}
        session = self.store.get()
        state = "signed_out" if not session else "signed_in"
        if session and session["token"].get("expires_at", 0) <= time.time():
            state = "expired"
        config = self.codex_path()
        configured = False
        if config.exists():
            document = tomlkit.parse(config.read_text())
            auth = (
                document.get("model_providers", {}).get("pilgrim", {}).get("auth", {})
            )
            profile = document.get("profiles", {}).get("pilgrim", {})
            configured = (
                auth.get("command") == self.helper
                and auth.get("args") == ["--config", str(self.path), "token"]
                and profile.get("model_provider") == "pilgrim"
                and bool(profile.get("model"))
            )
        return {
            "state": state,
            "name": session["identity"]["name"] if session else None,
            "codex": configured,
        }

    def policy(self):
        response = requests.get(
            self.config["policy_endpoint"],
            headers={"Authorization": "Bearer " + self.access_token()},
            timeout=15,
            allow_redirects=False,
        )
        response.raise_for_status()
        value = response.json()
        if value.get("version") != 1:
            raise AgentError("UNSUPPORTED_POLICY_VERSION")
        secure_url(value["codex"]["base_url"])
        if (
            not isinstance(value["codex"].get("model"), str)
            or not value["codex"]["model"]
        ):
            raise AgentError("MODEL_REQUIRED")
        return value

    def codex_path(self):
        return (
            Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
            / "config.toml"
        )

    def configure(self):
        policy = self.policy()
        target = self.codex_path()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with FileLock(str(target) + ".workspace.lock", timeout=10):
            original = target.read_text() if target.exists() else ""
            doc = tomlkit.parse(original)
            providers = doc.setdefault("model_providers", tomlkit.table())
            profiles = doc.setdefault("profiles", tomlkit.table())
            existing = providers.get("pilgrim")
            expected_args = ["--config", str(self.path), "token"]
            if existing and (
                existing.get("auth", {}).get("command") != self.helper
                or existing.get("auth", {}).get("args") != expected_args
            ):
                raise AgentError("CODEX_PROVIDER_CONFLICT")
            if (
                "pilgrim" in profiles
                and profiles["pilgrim"].get("model_provider") != "pilgrim"
            ):
                raise AgentError("CODEX_PROFILE_CONFLICT")
            desired = {
                "name": "Company gateway",
                "base_url": policy["codex"]["base_url"],
                "wire_api": "responses",
                "auth": {
                    "command": self.helper,
                    "args": expected_args,
                    "timeout_ms": 60000,
                    "refresh_interval_ms": 60000,
                },
            }
            if existing != desired:
                providers["pilgrim"] = desired
            profile = profiles.setdefault("pilgrim", tomlkit.table())
            profile["model_provider"] = "pilgrim"
            profile["model"] = policy["codex"]["model"]
            rendered = tomlkit.dumps(doc)
            if rendered == original:
                return self.status()
            if (
                original
                and not target.with_name("config.before-workspace.toml").exists()
            ):
                atomic_write(target.with_name("config.before-workspace.toml"), original)
            atomic_write(target, rendered)
        return self.status()

    def token(self):
        response = requests.post(
            self.config["credential_endpoint"],
            json={"audience": "codex"},
            headers={"Authorization": "Bearer " + self.access_token()},
            timeout=15,
            allow_redirects=False,
        )
        response.raise_for_status()
        result = response.json()
        value = result.get("access_token")
        if (
            not isinstance(value, str)
            or not value
            or any(c.isspace() for c in value)
            or result.get("expires_in", 0) < 90
        ):
            raise AgentError("INVALID_GATEWAY_CREDENTIAL")
        return value

    def network_profile(self):
        policy = self.policy()
        url = secure_url(policy["network"]["profile_endpoint"])
        # Do not forward an identity credential to an arbitrary policy URL.
        if (urlsplit(url).scheme, urlsplit(url).netloc) != (
            urlsplit(self.config["policy_endpoint"]).scheme,
            urlsplit(self.config["policy_endpoint"]).netloc,
        ):
            raise AgentError("PROFILE_ORIGIN_MISMATCH")
        response = requests.get(
            url,
            headers={"Authorization": "Bearer " + self.access_token()},
            timeout=15,
            allow_redirects=False,
        )
        response.raise_for_status()
        if len(response.content) > 2_000_000:
            raise AgentError("PROFILE_TOO_LARGE")
        return {"yaml": response.text}

    def logout(self):
        session = self.store.get()
        revoked = True
        try:
            if session:
                endpoint = self.discover().get("revocation_endpoint")
                if not endpoint:
                    revoked = False
                else:
                    secure_url(endpoint)
                    for kind in ("refresh_token", "access_token"):
                        if session["token"].get(kind):
                            response = requests.post(
                                endpoint,
                                data={
                                    "token": session["token"][kind],
                                    "token_type_hint": kind,
                                    "client_id": self.config["client_id"],
                                },
                                timeout=15,
                                allow_redirects=False,
                            )
                            response.raise_for_status()
                            if not 200 <= response.status_code < 300:
                                raise AgentError("REVOCATION_FAILED")
        except Exception:
            revoked = False
        finally:
            self.store.clear()
        return {**self.status(), "remote_revoked": revoked}

    def run(self, action):
        if action == "status":
            return self.status()
        if not self.config:
            raise AgentError("NOT_CONFIGURED")
        with FileLock(str(self.path) + ".lock", timeout=1):
            return getattr(self, action.replace("-", "_"))()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--config",
        default=os.environ.get(
            "PILGRIM_WORKSPACE_CONFIG",
            str(Path.home() / ".config/pilgrim-workspace/config.json"),
        ),
    )
    parser.add_argument(
        "action",
        choices=["status", "login", "logout", "configure", "token", "network-profile"],
    )
    args = parser.parse_args()
    try:
        value = Agent(args.config).run(args.action)
        print(value if args.action == "token" else json.dumps(value))
    except Exception as error:
        # Library errors may contain callback URLs or tokens; never emit them.
        code = (
            str(error)
            if isinstance(error, AgentError)
            else "WORKSPACE_OPERATION_FAILED"
        )
        print(json.dumps({"error": code}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
