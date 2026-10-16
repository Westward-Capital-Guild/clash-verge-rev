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


from remote_ssh import RemoteError, RemoteSSH, public_hosts
from workspace_access import AccessError, WorkspaceAccess


class AgentError(Exception):
    pass


def secure_url(value):
    url = urlsplit(value)
    if url.username is not None or url.password is not None or url.fragment:
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
        self, config_path, *, store=None, browser=webbrowser.open, helper=None,
        remote_authority=None, remote_ssh=None, bootstrap_url=None, allow_loopback=False
    ):
        self.remote_authority = remote_authority
        proxy_port = os.environ.get("PILGRIM_WORKSPACE_SOCKS_PORT", "")
        self.remote_ssh = remote_ssh or RemoteSSH(proxy_port=int(proxy_port) if proxy_port.isdigit() else None)
        self.path = Path(config_path).expanduser().resolve()
        self.access = None
        self.bootstrap_error = None
        if bootstrap_url:
            self.path = Path(os.environ.get("XDG_STATE_HOME", str(Path.home() / ".local/state"))) / "pilgrim-workspace/session"
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self.access = WorkspaceAccess(bootstrap_url, allow_loopback=allow_loopback)
            try:
                self.config = self.access.load()
            except AccessError as error:
                self.config = None
                self.bootstrap_error = str(error)
        else:
            self.config = json.loads(self.path.read_text()) if self.path.exists() else None
        self.browser = browser
        self.helper = str(Path(helper or sys.argv[0]).resolve())
        self.metadata = None
        self.selected = None
        self.providers = {}
        if self.config:
            version = self.config.get("version")
            if version == 1:
                self.providers = {"authentik": self.config}
            elif version == 2:
                self.providers = self.config.get("providers", {})
            else:
                raise AgentError("UNSUPPORTED_CONFIG_VERSION")
            if not self.providers or set(self.providers) - {"feishu", "authentik"}:
                raise AgentError("INVALID_PROVIDERS")
            for provider in self.providers.values():
                for field in (("issuer", "policy_endpoint") if self.access else ("issuer", "policy_endpoint", "credential_endpoint")):
                    secure_url(provider[field])
                if not provider.get("client_id"):
                    raise AgentError("CLIENT_ID_REQUIRED")
        account = hashlib.sha256(
            (bootstrap_url if self.access else str(self.path) + json.dumps(self.config, sort_keys=True)).encode()
        ).hexdigest()
        self.store = store or CredentialStore(account)

    def provider(self):
        session = self.store.get()
        name = self.selected or (
            session.get("provider", "authentik") if session else None
        )
        if name not in self.providers:
            raise AgentError("SIGN_IN_REQUIRED")
        return self.providers[name]

    def discover(self):
        if self.metadata is None:
            issuer = self.provider()["issuer"]
            response = requests.get(
                issuer.rstrip("/") + "/.well-known/openid-configuration",
                timeout=15,
                allow_redirects=False,
            )
            if not 200 <= response.status_code < 300:
                raise AgentError("DISCOVERY_UNAVAILABLE")
            self.metadata = response.json()
            if self.metadata.get("issuer") != issuer:
                raise AgentError("ISSUER_MISMATCH")
            for field in ("authorization_endpoint", "token_endpoint", "jwks_uri", "revocation_endpoint"):
                if field not in self.metadata and field == "revocation_endpoint" and not self.access:
                    continue
                if self.access:
                    self.access.url(self.metadata[field])
                else:
                    secure_url(self.metadata[field])
            if self.access and "none" not in self.metadata.get("token_endpoint_auth_methods_supported", []):
                raise AgentError("PUBLIC_CLIENT_REQUIRED")
            if "S256" not in self.metadata.get("code_challenge_methods_supported", []):
                raise AgentError("PKCE_NOT_SUPPORTED")
        return self.metadata

    def validate_identity(self, token, *, nonce=None, subject=None):
        meta = self.discover()
        response = requests.get(meta["jwks_uri"], timeout=15, allow_redirects=False)
        if not 200 <= response.status_code < 300:
            raise AgentError("JWKS_UNAVAILABLE")
        claims = JsonWebToken(["RS256", "ES256"]).decode(
            token["id_token"],
            response.json(),
            claims_cls=CodeIDToken,
            claims_options={
                "iss": {"essential": True, "value": self.provider()["issuer"]},
                "aud": {"essential": True, "value": self.provider()["client_id"]},
                "exp": {"essential": True},
                "iat": {"essential": True},
                "sub": {"essential": True},
            },
            claims_params={
                "nonce": nonce,
                "client_id": self.provider()["client_id"],
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
            self.provider()["client_id"], token_endpoint_auth_method="none", **kwargs
        )

    def login(self, provider=None):
        if self.store.get():
            raise AgentError("SIGN_OUT_FIRST")
        if provider is None:
            if len(self.providers) != 1:
                raise AgentError("PROVIDER_REQUIRED")
            provider = next(iter(self.providers))
        if provider not in self.providers:
            raise AgentError("PROVIDER_NOT_CONFIGURED")
        self.selected = provider
        self.metadata = None
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

        port = self.provider().get("redirect_port", 47831)

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
                scope="openid profile"
                if provider == "feishu"
                else "openid profile offline_access",
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
        self.store.set(
            {"provider": provider, "session_id": nonce, "token": dict(token), "identity": identity,
             "client": [self.provider()["issuer"], self.provider()["client_id"]]}
        )
        return self.status()

    def access_token(self):
        session = self.store.get()
        if not session:
            raise AgentError("SIGN_IN_REQUIRED")
        if self.access and session.get("client") != [self.provider()["issuer"], self.provider()["client_id"]]:
            raise AgentError("INVALID_SESSION")
        token = session["token"]
        if token.get("expires_at", 0) <= time.time() + 30:
            if session.get("provider") == "feishu" or not token.get("refresh_token"):
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

    def token_args(self, provider):
        return ["--config", str(self.path), "token-" + provider]

    def status(self):
        if not self.config:
            return {
                "state": "unconfigured",
                "name": None,
                "codex": False,
                "providers": [],
                "provider": None,
                "company": self.access is not None,
                "code": self.bootstrap_error,
            }
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
            configured = (
                auth.get("command") == self.helper
                and session is not None
                and auth.get("args")
                == self.token_args(session.get("provider", "authentik"))
            )
        extra = {"company": self.access is not None}
        if self.access and state == "signed_in":
            try:
                extra["capabilities"] = self.policy()["capabilities"]
            except (AgentError, AccessError) as error:
                extra["code"] = str(error)
        return {
            **extra,
            "providers": list(self.providers),
            "provider": session.get("provider", "authentik") if session else None,
            "state": state,
            "name": session["identity"]["name"] if session else None,
            "codex": configured,
        }

    def policy(self):
        if self.access:
            return self.access.policy(self.access_token())
        response = requests.get(
            self.provider()["policy_endpoint"],
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
        if self.access:
            raise AgentError("LOCAL_MODEL_NOT_GRANTED")
        policy = self.policy()
        target = self.codex_path()
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with FileLock(str(target) + ".workspace.lock", timeout=10):
            original = target.read_text() if target.exists() else ""
            doc = tomlkit.parse(original)
            providers = doc.setdefault("model_providers", tomlkit.table())
            existing = providers.get("pilgrim")
            expected_args = self.token_args(
                self.store.get().get("provider", "authentik")
            )
            owned_args = [self.token_args(name) for name in self.providers]
            owned_args.append(["--config", str(self.path), "token"])
            if existing and (
                existing.get("auth", {}).get("command") != self.helper
                or existing.get("auth", {}).get("args") not in owned_args
            ):
                raise AgentError("CODEX_PROVIDER_CONFLICT")
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
        if self.access:
            raise AgentError("LOCAL_MODEL_NOT_GRANTED")
        response = requests.post(
            self.provider()["credential_endpoint"],
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
        if self.access:
            if policy["capabilities"]["network"] != "granted":
                raise AgentError("NETWORK_NOT_GRANTED")
            return {"yaml": self.access.request(policy["network"]["profile_endpoint"], self.access_token(), yaml=True),
                    "binding_id": policy["binding_id"], "revision": policy["revision"]}
        url = secure_url(policy["network"]["profile_endpoint"])
        # Do not forward an identity credential to an arbitrary policy URL.
        if (urlsplit(url).scheme, urlsplit(url).netloc) != (
            urlsplit(self.provider()["policy_endpoint"]).scheme,
            urlsplit(self.provider()["policy_endpoint"]).netloc,
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
                                    "client_id": self.provider()["client_id"],
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
            self.selected = None
            self.metadata = None
        return {**self.status(), "remote_revoked": revoked}

    def session_binding(self):
        session = self.store.get()
        if not session:
            return None
        identity = session.get("identity", {})
        return (session.get("provider"), identity.get("sub"), session.get("session_id"))

    def remote(self, action, host_id=None, workspace_id=None):
        # Bootstrap/access-service delivery owns this adapter; no employee JSON wiring.
        if self.remote_authority is None and self.access is None:
            return {"state": "unconfigured", "hosts": []}
        try:
            with FileLock(str(self.path) + ".lock", timeout=1):
                if not self.store.get():
                    return {"state": "signed_out", "hosts": []}
                token = self.access_token()
                session = self.session_binding()
            if self.access:
                policy = self.access.policy(token)
                records = self.access.hosts(token, policy)
            else:
                records = self.remote_authority(token)
            if self.session_binding() != session:
                return {"state": "not_authorized", "hosts": []}
            if action == "hosts":
                return {"state": "available" if records else "unassigned", "hosts": public_hosts(records)}
            record = next((item for item in records if item["id"] == host_id), None)
            if record is None or not any(w["id"] == workspace_id for w in record["workspaces"]):
                return {"state": "not_authorized", "hosts": []}
            operation = self.remote_ssh.prepare if action == "prepare" else self.remote_ssh.check
            if self.access and record["ssh_access_mode"] == "managed-keypair":
                # Only an explicit preparation/check fetches the approved key.
                credential = self.access.credential(token, record)
                if self.session_binding() != session:
                    return {"state": "not_authorized", "hosts": []}
                result = operation(record, workspace_id, credential=credential)
            else:
                result = operation(record, workspace_id)
            if self.session_binding() != session:
                return {"state": "not_authorized", "hosts": []}
            return {**result, "hosts": []}
        except (AccessError, AgentError) as error:
            code = str(error)
            state = {
                "INVALID_SESSION": "signed_out", "SIGN_IN_REQUIRED": "signed_out",
                "SESSION_EXPIRED": "signed_out", "BINDING_CHANGED": "binding_changed",
                "MEMBER_NOT_REGISTERED": "not_authorized", "MEMBER_BINDING_MISMATCH": "not_authorized",
                "RESOURCE_NOT_FOUND": "not_authorized", "LOCAL_KEY_REQUIRED": "missing_key",
                "KEY_MISMATCH": "key_mismatch", "INVALID_HOST": "invalid_host",
            }.get(code, "unavailable")
            return {"state": state, "code": code, "hosts": []}
        except RemoteError as error:
            return {"state": str(error), "hosts": []}
        except Exception:
            return {"state": "unavailable", "hosts": []}

    def run(self, action):
        if action == "status":
            return self.status()
        if action == "logout" and self.access and not self.config:
            self.store.clear()
            return {**self.status(), "remote_revoked": False}
        if not self.config:
            raise AgentError(self.bootstrap_error or "NOT_CONFIGURED")
        with FileLock(str(self.path) + ".lock", timeout=1):
            if action in ("token-feishu", "token-authentik"):
                session = self.store.get()
                if not session:
                    raise AgentError("SIGN_IN_REQUIRED")
                if session.get("provider", "authentik") != action.removeprefix(
                    "token-"
                ):
                    raise AgentError("PROVIDER_MISMATCH")
                return self.token()
            if action == "token" and self.config["version"] == 2:
                raise AgentError("PROVIDER_REQUIRED")
            if action in ("login-feishu", "login-authentik"):
                return self.login(action.removeprefix("login-"))
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
        choices=[
            "status",
            "login",
            "login-feishu",
            "login-authentik",
            "logout",
            "configure",
            "token",
            "token-feishu",
            "token-authentik",
            "network-profile",
            "remote-hosts",
            "remote-prepare",
            "remote-check",
        ],
    )
    parser.add_argument("--host-id")
    parser.add_argument("--workspace-id")
    args = parser.parse_args()
    try:
        agent = Agent(args.config, bootstrap_url=os.environ.get("PILGRIM_WORKSPACE_BOOTSTRAP_URL"))
        value = (
            agent.remote(args.action.removeprefix("remote-"), args.host_id, args.workspace_id)
            if args.action.startswith("remote-") else agent.run(args.action)
        )
        print(
            value
            if args.action == "token" or args.action.startswith("token-")
            else json.dumps(value)
        )
    except Exception as error:
        # Library errors may contain callback URLs or tokens; never emit them.
        code = (
            str(error)
            if isinstance(error, (AgentError, AccessError))
            else "WORKSPACE_OPERATION_FAILED"
        )
        print(json.dumps({"error": code}), file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
