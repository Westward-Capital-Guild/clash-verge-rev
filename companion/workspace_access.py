"""Native Passport workspace protocol; never expose secret responses to the UI."""

import json
from urllib.parse import quote, urlsplit

import requests


ERROR_CODES = {
    "INVALID_SESSION", "MEMBER_NOT_REGISTERED", "MEMBER_BINDING_MISMATCH",
    "NETWORK_NOT_GRANTED", "LOCAL_KEY_REQUIRED", "RESOURCE_NOT_FOUND",
    "BINDING_CHANGED", "INVALID_REQUEST", "UNSUPPORTED_VERSION",
    "RESOURCE_NOT_READY", "WORKSPACE_UNAVAILABLE",
}


class AccessError(Exception):
    def __init__(self, code, retryable=False):
        super().__init__(code)
        self.retryable = retryable


class WorkspaceAccess:
    def __init__(self, bootstrap_url, *, allow_loopback=False):
        self.allow_loopback = allow_loopback
        self.origin = None
        self.url(bootstrap_url)
        self.origin = self.url_origin(bootstrap_url)
        self.bootstrap_url = bootstrap_url
        self.bootstrap = None

    @staticmethod
    def url_origin(value):
        url = urlsplit(value)
        return url.scheme, url.hostname, url.port or (443 if url.scheme == "https" else 80)

    def url(self, value):
        try:
            url = urlsplit(value)
            if (not url.hostname or url.username is not None or url.password is not None or url.fragment
                    or any(c.isspace() for c in value) or "\\" in value):
                raise ValueError()
            if url.port is not None and not 1 <= url.port <= 65535:
                raise ValueError()
            if url.scheme != "https" and not (
                self.allow_loopback and url.scheme == "http" and url.hostname == "127.0.0.1"
            ):
                raise AccessError("HTTPS_REQUIRED")
            if self.origin and self.url_origin(value) != self.origin:
                raise AccessError("ENDPOINT_ORIGIN_MISMATCH")
        except (TypeError, ValueError):
            raise AccessError("INVALID_ENDPOINT") from None
        return value

    def request(self, endpoint, token=None, *, body=None, yaml=False):
        self.url(endpoint)
        headers = {"Accept": "application/yaml" if yaml else "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        limit = 2_000_000 if yaml else 256_000
        try:
            with requests.request(
                "POST" if body is not None else "GET", endpoint,
                headers=headers, json=body, timeout=(10, 20),
                allow_redirects=False, stream=True,
            ) as response:
                if 300 <= response.status_code < 400:
                    raise AccessError("REDIRECT_FORBIDDEN")
                content = bytearray()
                for chunk in response.iter_content(16384):
                    content.extend(chunk)
                    if len(content) > limit:
                        raise AccessError("PROFILE_TOO_LARGE" if yaml else "INVALID_RESPONSE")
                if not 200 <= response.status_code < 300:
                    code = "INVALID_SESSION" if response.status_code == 401 else "PROFILE_TOO_LARGE" if response.status_code == 413 and yaml else "WORKSPACE_UNAVAILABLE"
                    try:
                        error = json.loads(content).get("error", {})
                        if error.get("code") in ERROR_CODES:
                            code = error["code"]
                    except (ValueError, AttributeError, TypeError):
                        pass
                    raise AccessError(code, response.status_code >= 500)
                media = response.headers.get("Content-Type", "").split(";")[0].lower().strip()
                if yaml:
                    if media != "application/yaml":
                        raise AccessError("INVALID_PROFILE")
                    return content.decode("utf-8")
                if media != "application/json":
                    raise AccessError("INVALID_RESPONSE")
                result = json.loads(content)
                if not isinstance(result, dict):
                    raise AccessError("INVALID_RESPONSE")
                return result
        except requests.RequestException:
            raise AccessError("WORKSPACE_UNAVAILABLE", True) from None
        except (ValueError, UnicodeError):
            raise AccessError("INVALID_RESPONSE") from None

    def load(self):
        value = self.request(self.bootstrap_url)
        if type(value.get("version")) is not int or value["version"] != 1:
            raise AccessError("UNSUPPORTED_VERSION")
        try:
            if set(value["providers"]) != {"feishu"}:
                raise ValueError()
            provider = value["providers"]["feishu"]
            self.url(provider["issuer"])
            if (not isinstance(provider["client_id"], str) or not provider["client_id"]
                    or provider["redirect_port"] != 47831
                    or provider["redirect_uri"] != "http://127.0.0.1:47831/callback"
                    or provider["scope"] != "openid profile"):
                raise ValueError()
            for name in ("policy_endpoint", "network_profile_endpoint", "development_hosts_endpoint"):
                self.url(value[name])
        except (KeyError, TypeError, ValueError):
            raise AccessError("INVALID_BOOTSTRAP") from None
        self.bootstrap = value
        return {"version": 2, "providers": {"feishu": {
            **provider, "policy_endpoint": value["policy_endpoint"],
        }}}

    def policy(self, token):
        value = self.request(self.bootstrap["policy_endpoint"], token)
        if type(value.get("version")) is not int or value["version"] != 2:
            raise AccessError("UNSUPPORTED_VERSION")
        try:
            for name in ("binding_id", "revision"):
                if not isinstance(value[name], str) or not value[name]:
                    raise ValueError()
            capabilities = value["capabilities"]
            for capability, section, field, bootstrap_field in (
                ("network", "network", "profile_endpoint", "network_profile_endpoint"),
                ("development_hosts", "development_hosts", "endpoint", "development_hosts_endpoint"),
            ):
                if capabilities[capability] not in ("granted", "not_granted"):
                    raise ValueError()
                if capabilities[capability] == "granted":
                    endpoint = self.url(value[section][field])
                    if endpoint != self.bootstrap[bootstrap_field]:
                        raise ValueError()
                elif section in value:
                    raise ValueError()
            if capabilities.get("local_model") != "not_granted":
                raise AccessError("UNSUPPORTED_VERSION")
        except (KeyError, TypeError, ValueError):
            raise AccessError("INVALID_POLICY") from None
        return value

    def hosts(self, token, policy):
        if policy["capabilities"]["development_hosts"] != "granted":
            raise AccessError("RESOURCE_NOT_FOUND")
        value = self.request(policy["development_hosts"]["endpoint"], token)
        if type(value.get("version")) is not int or value["version"] != 1:
            raise AccessError("UNSUPPORTED_VERSION")
        if any(value.get(k) != policy[k] for k in ("binding_id", "revision")):
            raise AccessError("BINDING_CHANGED")
        if value.get("capability") != "granted" or not isinstance(value.get("hosts"), list):
            raise AccessError("INVALID_RESPONSE")
        records = []
        try:
            for host in value["hosts"]:
                if not isinstance(host["id"], str) or not host["id"] or host["id"] in (".", "..") or any(ord(c) < 32 for c in host["id"]):
                    raise ValueError()
                connection = dict(host["connection"])
                if connection["network_requirement"] not in ("direct", "tailscale", "company_proxy"):
                    raise ValueError()
                connection["host_keys"] = [key["algorithm"] + " " + key["public_key"] for key in connection["host_keys"]]
                if host["ssh_access_mode"] not in ("managed-keypair", "registered-public-key"):
                    raise ValueError()
                if host["ssh_access_mode"] == "managed-keypair":
                    self.url(host["ssh_credential_endpoint"])
                    if host["ssh_credential_endpoint"] != self.bootstrap["development_hosts_endpoint"].rstrip("/") + "/" + quote(host["id"], safe="") + "/ssh-credential":
                        raise ValueError()
                    if host["managed_key_fingerprint"] not in host["user_key_fingerprints"]:
                        raise ValueError()
                records.append({**host, "connection": connection,
                                "binding_id": policy["binding_id"], "revision": policy["revision"]})
        except (KeyError, TypeError, ValueError):
            raise AccessError("INVALID_HOST") from None
        return records

    def credential(self, token, host):
        value = self.request(host["ssh_credential_endpoint"], token,
                             body={"version": 1, "revision": host["revision"]})
        if type(value.get("version")) is not int or value["version"] != 1:
            raise AccessError("UNSUPPORTED_VERSION")
        if (any(value.get(k) != host[k] for k in ("binding_id", "revision"))
                or value.get("host_id") != host["id"]):
            raise AccessError("BINDING_CHANGED")
        if (value.get("format") != "openssh"
                or value.get("fingerprint_sha256") != host["managed_key_fingerprint"]
                or not isinstance(value.get("private_key"), str)):
            raise AccessError("KEY_MISMATCH")
        return value["private_key"]
