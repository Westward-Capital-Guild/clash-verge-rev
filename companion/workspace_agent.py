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
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
import webbrowser

from authlib.integrations.requests_client import OAuth2Session
from authlib.jose import JsonWebToken
from authlib.oidc.core import CodeIDToken
from filelock import FileLock
import requests
import tomlkit


from remote_ssh import RemoteError, RemoteSSH, public_hosts, ssh_proxy
from workspace_access import AccessError, WorkspaceAccess, host_key_line


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
    """Persist the OIDC session in the app state directory.

    The companion deliberately does not use an OS keychain.  The session file
    is private to the current user (0600) and the containing directory is 0700,
    so desktop startup and token refresh never require a credential prompt.
    """

    def __init__(self, account, path=None):
        self.account = account
        default = Path.home() / ".local/state/pilgrim-workspace/credentials.json"
        self.path = Path(path).expanduser() if path is not None else default
        self.lock_path = self.path.with_suffix(self.path.suffix + ".lock")

    def _lock(self):
        folder = self.path.parent
        if folder.is_symlink() or self.path.is_symlink() or self.lock_path.is_symlink():
            raise AgentError("INVALID_SESSION")
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        folder.chmod(0o700)
        return FileLock(self.lock_path, timeout=10)

    def _check_private(self):
        owner = getattr(os, "getuid", lambda: None)()
        if self.path.exists() and (
            self.path.is_symlink()
            or owner is not None and self.path.stat().st_uid != owner
            or self.path.stat().st_mode & 0o077
        ):
            raise AgentError("INVALID_SESSION")

    def get(self):
        with self._lock():
            if not self.path.exists():
                return None
            self._check_private()
            try:
                return json.loads(self.path.read_text(encoding="utf-8"))
            except (OSError, ValueError, UnicodeError):
                raise AgentError("INVALID_SESSION") from None

    def set(self, value):
        with self._lock():
            atomic_write(self.path, json.dumps(value, sort_keys=True))
            self.path.chmod(0o600)

    def clear(self):
        with self._lock():
            if self.path.is_symlink():
                raise AgentError("INVALID_SESSION")
            self.path.unlink(missing_ok=True)


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
        self.delivery_state_path = self.path.with_name("delivery.json")
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
        self.store = store or CredentialStore(account, path=self.path.with_name("credentials.json"))

    def _delivery_state(self):
        if not self.delivery_state_path.exists():
            return {"installation_id": str(uuid.uuid4()), "subject": None, "issuer": None, "client_id": None, "reports": {}}
        try:
            value = json.loads(self.delivery_state_path.read_text())
            if (
                not isinstance(value, dict)
                or not isinstance(value.get("installation_id"), str)
                or not isinstance(value.get("reports", {}), dict)
                or not isinstance(value.get("registered", False), bool)
            ):
                raise ValueError()
            uuid.UUID(value["installation_id"])
            for configuration_id, report in value.get("reports", {}).items():
                if (
                    not isinstance(configuration_id, str)
                    or not isinstance(report, dict)
                    or not isinstance(report.get("report_id"), str)
                    or report.get("revision") is not None and not isinstance(report["revision"], str)
                    or not isinstance(report.get("sequence"), int)
                    or report["sequence"] <= 0
                    or report["sequence"] > 9_007_199_254_740_991
                    or report.get("stage") not in ("received", "applied", "verified", "failed")
                    or report.get("error_code") not in (None, "permission_required", "connection_failed", "invalid_configuration", "unsupported_platform", "cancelled")
                    or (report.get("stage") == "failed") != (report.get("error_code") is not None)
                    or not isinstance(report.get("acknowledged", False), bool)
                ):
                    raise ValueError()
            return value
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            raise AgentError("INVALID_DELIVERY_STATE") from None

    def _save_delivery_state(self, value):
        atomic_write(self.delivery_state_path, json.dumps(value, sort_keys=True))

    def _new_installation(self, state):
        return {
            "installation_id": str(uuid.uuid4()),
            "subject": state.get("subject"),
            "issuer": state.get("issuer"),
            "client_id": state.get("client_id"),
            "reports": {},
        }

    @staticmethod
    def _platform():
        if sys.platform == "darwin":
            return "macos"
        if sys.platform.startswith("win"):
            return "windows"
        return "linux"

    def _ensure_installation(self, token):
        if not self.access or not self.access.bootstrap.get("installations_endpoint"):
            return None
        with FileLock(str(self.delivery_state_path) + ".lock", timeout=10):
            session = self.store.get() or {}
            subject = session.get("identity", {}).get("sub")
            provider = self.provider()
            issuer = provider.get("issuer")
            client_id = provider.get("client_id")
            state = self._delivery_state()
            if (
                state.get("subject") != subject
                or state.get("issuer") != issuer
                or state.get("client_id") != client_id
            ):
                state = self._new_installation({"subject": subject, "issuer": issuer, "client_id": client_id})
            if not state.get("registered"):
                try:
                    self.access.register_installation(
                        token, state["installation_id"], self._platform(),
                        os.environ.get("PILGRIM_WORKSPACE_CLIENT_VERSION", "workspace-client"),
                    )
                except AccessError as error:
                    if str(error) != "INSTALLATION_CONFLICT":
                        raise
                    state = self._new_installation(state)
                    self.access.register_installation(
                        token, state["installation_id"], self._platform(),
                        os.environ.get("PILGRIM_WORKSPACE_CLIENT_VERSION", "workspace-client"),
                    )
                state["registered"] = True
            self._save_delivery_state(state)
            return state

    def _report(self, token, configuration, stage, error_code=None):
        if not self.access or not self.access.bootstrap.get("installations_endpoint"):
            return False
        state = self._ensure_installation(token)
        if state is None:
            return False
        key = configuration["id"]
        with FileLock(str(self.delivery_state_path) + ".lock", timeout=10):
            state = self._delivery_state()
            current = state["reports"].get(key)
            same_report = current and current.get("revision") == configuration["revision"] and current["stage"] == stage and current.get("error_code") == error_code
            if same_report and current.get("acknowledged"):
                return True
            if same_report:
                report_id = current["report_id"]
                sequence = current["sequence"]
            else:
                sequence = int(current.get("sequence", 0) if current else 0) + 1
                if sequence > 9_007_199_254_740_991:
                    raise AgentError("INVALID_DELIVERY_STATE")
                report_id = str(uuid.uuid4())
                current = {
                    "report_id": report_id, "sequence": sequence, "revision": configuration["revision"],
                    "stage": stage, "error_code": error_code,
                }
                state["reports"][key] = current
            current["acknowledged"] = False
            self._save_delivery_state(state)
            payload = {
                "sequence": sequence, "configuration_id": configuration["id"],
                "revision": configuration["revision"], "stage": stage,
                "error_code": error_code,
            }
            try:
                self.access.report(token, state["installation_id"], report_id, payload)
            except AccessError as error:
                if str(error) in ("REPORT_CONFLICT", "REPORT_OUT_OF_ORDER", "BINDING_CHANGED"):
                    self._save_delivery_state(self._new_installation(state))
                return False
            except AgentError:
                return False
            current["acknowledged"] = True
            self._save_delivery_state(state)
            return True

    def _configuration_delivery(self, token, configuration_id, kind):
        policy = self.policy()
        if kind == "mihomo" and policy["capabilities"]["network"] != "granted":
            raise AgentError("NETWORK_NOT_GRANTED")
        if kind == "ssh" and policy["capabilities"]["development_hosts"] != "granted":
            raise AccessError("RESOURCE_NOT_FOUND")
        configurations = self.access.configurations(token)
        configuration = next(
            (item for item in configurations if item["id"] == configuration_id and item["kind"] == kind),
            None,
        )
        if configuration is None:
            raise AccessError("RESOURCE_NOT_FOUND")
        if configuration["preparation"] == "not_ready":
            raise AccessError("RESOURCE_NOT_READY")
        self._ensure_installation(token)
        delivery = self.access.delivery(token, configuration)
        self._report(token, configuration, "received")
        return configuration, delivery

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
            if self.metadata.get("userinfo_endpoint"):
                if self.access:
                    self.access.url(self.metadata["userinfo_endpoint"])
                else:
                    secure_url(self.metadata["userinfo_endpoint"])
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
        subject = claims["sub"]
        name = self._identity_name_from_claims(claims, subject) or self._userinfo_name(token, subject)
        return {
            "sub": subject,
            "name": name or subject,
        }

    @staticmethod
    def _identity_name_from_claims(claims, subject):
        for field in ("name", "display_name", "nickname", "preferred_username", "email"):
            value = claims.get(field)
            if not isinstance(value, str):
                continue
            value = value.strip()
            if value and value != subject and not value.startswith("ou_"):
                return value
        return None

    def _userinfo_name(self, token, subject):
        endpoint = self.discover().get("userinfo_endpoint")
        if not endpoint:
            return None
        try:
            response = requests.get(
                endpoint,
                headers={"Authorization": "Bearer " + token["access_token"]},
                timeout=15,
                allow_redirects=False,
            )
            if not 200 <= response.status_code < 300:
                return None
            value = response.json()
        except (KeyError, requests.RequestException, ValueError, TypeError):
            return None
        if not isinstance(value, dict) or value.get("sub") != subject:
            raise AgentError("SUBJECT_MISMATCH")
        return self._identity_name_from_claims(value, subject)

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
                session["identity"] = self.validate_identity(
                    refreshed, subject=session["identity"]["sub"]
                )
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
        if session and state == "signed_in":
            identity = session.get("identity", {})
            subject = identity.get("sub")
            if (
                isinstance(subject, str)
                and self._identity_name_from_claims(identity, subject) is None
            ):
                try:
                    name = self._userinfo_name(session["token"], subject)
                except (AgentError, AccessError):
                    name = None
                if name:
                    session["identity"] = {"sub": subject, "name": name}
                    self.store.set(session)
        config = self.codex_path()
        configured = False
        managed = self.codex_managed_path()
        if self.access:
            if managed.exists() and session is not None:
                try:
                    document = tomlkit.parse(managed.read_text())
                    managed_configured = (
                        document.get("workspace", {}).get("command") == self.helper
                        and document.get("workspace", {}).get("args")
                        == self.token_args(session.get("provider", "feishu"))
                    )
                    if managed_configured and config.exists():
                        codex = tomlkit.parse(config.read_text())
                        profile = codex.get("profiles", {}).get("pilgrim_workspace", {})
                        configured = profile.get("model_provider") == document.get("workspace", {}).get("provider")
                except (OSError, AttributeError, TypeError, tomlkit.exceptions.ParseError):
                    configured = False
        elif config.exists():
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
                token = self.access_token()
                policy = self.access.policy(token)
                extra["capabilities"] = policy["capabilities"]
                if self.access.bootstrap.get("configurations_endpoint"):
                    try:
                        extra["configurations"] = self.access.configurations(token)
                    except AccessError as error:
                        extra["catalogue_code"] = str(error)
                    state_file = self._delivery_state()
                    extra["installation_id"] = state_file["installation_id"]
                    try:
                        installations = self.access.installations(token)
                    except AccessError as error:
                        extra["installation_code"] = str(error)
                    else:
                        current = next(
                            (item for item in installations if item.get("id") == state_file["installation_id"]),
                            None,
                        )
                        if isinstance(current, dict):
                            reports = current.get("reports")
                            if isinstance(reports, list):
                                revisions = {
                                    item["id"]: item["revision"]
                                    for item in extra.get("configurations", [])
                                }
                                public_reports = []
                                for report in reports:
                                    if (
                                        not isinstance(report, dict)
                                        or revisions.get(report.get("configuration_id")) != report.get("revision")
                                        or not isinstance(report.get("configuration_id"), str)
                                        or not isinstance(report.get("revision"), str)
                                        or not isinstance(report.get("sequence"), int)
                                        or isinstance(report.get("sequence"), bool)
                                        or not isinstance(report.get("stage"), str)
                                    ):
                                        continue
                                    public = {
                                        key: report[key]
                                        for key in ("configuration_id", "revision", "sequence", "stage", "error_code", "source", "received_at")
                                        if key in report
                                        and (key == "error_code" and report[key] is None or isinstance(report[key], (str, int)))
                                    }
                                    public_reports.append(public)
                                extra["installation_reports"] = public_reports
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

    def codex_managed_path(self):
        return self.codex_path().with_name("pilgrim-workspace.toml")

    def configure(self):
        if self.access:
            session = self.store.get()
            if not session:
                raise AgentError("SIGN_IN_REQUIRED")
            target = self.codex_managed_path()
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            config = self.codex_path()
            with FileLock(str(config) + ".workspace.lock", timeout=10), FileLock(str(target) + ".lock", timeout=10):
                if config.is_symlink() or target.is_symlink():
                    raise AgentError("CODEX_CONFIG_CONFLICT")
                if not config.exists():
                    raise AgentError("LOCAL_MODEL_NOT_GRANTED")
                try:
                    original_config = config.read_text()
                    document = tomlkit.parse(original_config)
                    provider = document.get("model_provider")
                    if provider is not None and not isinstance(provider, str):
                        raise ValueError()
                    if not provider:
                        raise AgentError("CODEX_PROVIDER_REQUIRED")
                except (OSError, tomlkit.exceptions.ParseError, ValueError):
                    raise AgentError("CODEX_CONFIG_INVALID") from None
                profiles = document.setdefault("profiles", tomlkit.table())
                if not hasattr(profiles, "get") or not hasattr(profiles, "__setitem__"):
                    raise AgentError("CODEX_CONFIG_INVALID")
                existing_profile = profiles.get("pilgrim_workspace")
                desired_profile = {"model_provider": provider}
                if existing_profile and (
                    not hasattr(existing_profile, "items")
                    or dict(existing_profile) != desired_profile
                ):
                    raise AgentError("CODEX_CONFIG_CONFLICT")
                profiles["pilgrim_workspace"] = desired_profile
                config_rendered = tomlkit.dumps(document)
                desired = tomlkit.document()
                workspace = tomlkit.table()
                workspace.add("version", 1)
                workspace.add("provider", provider)
                workspace.add("command", self.helper)
                workspace.add("args", self.token_args(session.get("provider", "feishu")))
                workspace.add("provider_immutable", True)
                desired.add("workspace", workspace)
                rendered = tomlkit.dumps(desired)
                original_managed = target.read_text() if target.exists() else ""
                if original_managed and original_managed != rendered:
                    try:
                        existing = tomlkit.parse(original_managed)
                    except tomlkit.exceptions.ParseError:
                        raise AgentError("CODEX_CONFIG_CONFLICT") from None
                    if existing.get("workspace", {}).get("provider_immutable") is not True:
                        raise AgentError("CODEX_CONFIG_CONFLICT")
                if config.read_text() != original_config or (target.read_text() if target.exists() else "") != original_managed:
                    raise AgentError("CODEX_CONFIG_CONFLICT")
                if config_rendered != original_config:
                    if not config.with_name("config.before-workspace.toml").exists():
                        atomic_write(config.with_name("config.before-workspace.toml"), original_config)
                    atomic_write(config, config_rendered)
                if rendered != original_managed:
                    if original_managed and not target.with_name("pilgrim-workspace.before-workspace.toml").exists():
                        atomic_write(target.with_name("pilgrim-workspace.before-workspace.toml"), original_managed)
                    atomic_write(target, rendered)
            return self.status()
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
            policy = self.policy()
            if policy["capabilities"].get("local_model") != "granted":
                raise AgentError("LOCAL_MODEL_NOT_GRANTED")
            credential = self.access.model_credential(self.access_token(), name="codex")
            local_model = policy.get("local_model")
            expected_url = local_model.get("base_url") if isinstance(local_model, dict) else None
            if expected_url and credential["url"].rstrip("/") != expected_url.rstrip("/"):
                raise AgentError("CREDENTIAL_ORIGIN_MISMATCH")
            return credential["key"]
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
            if self.access.bootstrap.get("configurations_endpoint"):
                configuration, delivery = self._configuration_delivery(self.access_token(), "network", "mihomo")
                yaml = delivery.get("configuration", {}).get("yaml")
                if not isinstance(yaml, str) or not yaml:
                    raise AccessError("INVALID_PROFILE")
                return {
                    "yaml": yaml, "binding_id": configuration["binding_id"],
                    "revision": configuration["revision"],
                    "configuration_id": configuration["id"],
                    "installation_id": self._delivery_state().get("installation_id"),
                }
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
        revoked = True
        try:
            session = self.store.get()
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

    def report_stage(self, configuration_id, revision, stage, error_code=None):
        if not self.access:
            return {"synced": False}
        if not isinstance(configuration_id, str) or not configuration_id or not isinstance(revision, str) or not revision:
            raise AgentError("INVALID_REPORT")
        if stage not in ("received", "applied", "verified", "failed"):
            raise AgentError("INVALID_REPORT")
        if stage == "failed" and error_code not in (
            "permission_required", "connection_failed", "invalid_configuration",
            "unsupported_platform", "cancelled",
        ):
            raise AgentError("INVALID_REPORT")
        if stage != "failed" and error_code is not None:
            raise AgentError("INVALID_REPORT")
        token = self.access_token()
        configuration = {"id": configuration_id, "revision": revision}
        return {"synced": self._report(token, configuration, stage, error_code)}

    def session_binding(self):
        session = self.store.get()
        if not session:
            return None
        identity = session.get("identity", {})
        return (session.get("provider"), identity.get("sub"), session.get("session_id"))

    def remote(self, action, host_id=None, workspace_id=None, identity_path=None, export_path=None):
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
                if self.access.bootstrap.get("configurations_endpoint"):
                    if policy["capabilities"]["development_hosts"] == "not_granted":
                        records = []
                    else:
                        configurations = self.access.configurations(token)
                        if action == "hosts":
                            # The catalogue is intentionally metadata-only. Use the
                            # legacy host listing when available so the UI can show
                            # verified workspaces without fetching a private key.
                            try:
                                records = self.access.hosts(token, policy)
                            except AccessError as error:
                                if str(error) not in ("RESOURCE_NOT_FOUND", "UNSUPPORTED_VERSION"):
                                    raise
                                records = [{
                                    "id": item["id"].removeprefix("ssh-"),
                                    "display_name": item["id"],
                                    "connection": {"network_requirement": "direct"},
                                    "workspaces": [],
                                } for item in configurations if item["kind"] == "ssh"]
                        else:
                            configuration, delivery = self._configuration_delivery(
                                token, "ssh-" + str(host_id), "ssh"
                            )
                            payload = delivery.get("configuration", {})
                            if not isinstance(payload, dict):
                                raise AccessError("INVALID_RESPONSE")
                            connection = dict(payload.get("connection", {}))
                            if isinstance(connection.get("host_keys"), list):
                                connection["host_keys"] = [
                                    key if isinstance(key, str) else host_key_line(key)
                                    for key in connection["host_keys"]
                                ]
                            record = {
                                **payload,
                                "connection": connection,
                                "id": str(host_id),
                                "binding_id": configuration["binding_id"],
                                "revision": configuration["revision"],
                            }
                            records = [record]
                else:
                    if action == "hosts" and policy["capabilities"]["development_hosts"] == "not_granted":
                        records = []
                    else:
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
            if action == "export":
                operation = self.remote_ssh.export
            if self.access and record["ssh_access_mode"] == "managed-keypair":
                # Only an explicit preparation/check fetches the approved key.
                credential = record.pop("private_key", None) if self.access.bootstrap.get("configurations_endpoint") else self.access.credential(token, record)
                if not credential:
                    raise AccessError("LOCAL_KEY_REQUIRED")
                if self.session_binding() != session:
                    return {"state": "not_authorized", "hosts": []}
                if action == "export":
                    if not export_path:
                        raise AgentError("EXPORT_PATH_REQUIRED")
                    result = operation(record, workspace_id, export_path, credential=credential)
                else:
                    result = operation(record, workspace_id, credential=credential)
            else:
                if action == "export":
                    raise AgentError("EXPORT_NOT_SUPPORTED")
                if identity_path:
                    result = operation(record, workspace_id, identity_path=identity_path)
                else:
                    result = operation(record, workspace_id)
            if self.session_binding() != session:
                return {"state": "not_authorized", "hosts": []}
            if self.access and self.access.bootstrap.get("configurations_endpoint"):
                if result.get("state") in ("ssh_prepared", "ssh_ready"):
                    self._report(token, configuration, "verified" if result["state"] == "ssh_ready" else "applied")
                else:
                    code = {
                        "network_required": "connection_failed",
                        "unreachable": "connection_failed",
                        "permission_denied": "permission_required",
                        "codex_unavailable": "connection_failed",
                    }.get(result.get("state"), "connection_failed")
                    self._report(token, configuration, "failed", code)
            return {**result, "key_mode": record.get("ssh_access_mode"), "hosts": []}
        except (AccessError, AgentError) as error:
            code = str(error)
            state = {
                "INVALID_SESSION": "signed_out", "SIGN_IN_REQUIRED": "signed_out",
                "SESSION_EXPIRED": "signed_out", "BINDING_CHANGED": "binding_changed",
                "MEMBER_NOT_REGISTERED": "unassigned", "MEMBER_BINDING_MISMATCH": "not_authorized",
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
            "remote-export",
            "report",
            "ssh-proxy",
        ],
    )
    parser.add_argument("--host-id")
    parser.add_argument("--workspace-id")
    parser.add_argument("--configuration-id")
    parser.add_argument("--revision")
    parser.add_argument("--stage")
    parser.add_argument("--error-code")
    parser.add_argument("--proxy-port", type=int)
    parser.add_argument("--target-host")
    parser.add_argument("--target-port", type=int)
    parser.add_argument("--identity-path")
    parser.add_argument("--export-path")
    args = parser.parse_args()
    try:
        if args.action == "ssh-proxy":
            ssh_proxy(args.proxy_port, args.target_host, args.target_port)
            return
        agent = Agent(args.config, bootstrap_url=os.environ.get("PILGRIM_WORKSPACE_BOOTSTRAP_URL"))
        if args.action == "report":
            value = agent.report_stage(args.configuration_id, args.revision, args.stage, args.error_code)
        else:
            value = (
                agent.remote(args.action.removeprefix("remote-"), args.host_id, args.workspace_id, args.identity_path, args.export_path)
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
