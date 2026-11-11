"""Native Passport workspace protocol; never expose secret responses to the UI."""

import json
from urllib.parse import quote, urlsplit

import requests


ERROR_CODES = {
    "INVALID_SESSION", "MEMBER_NOT_REGISTERED", "MEMBER_BINDING_MISMATCH",
    "NETWORK_NOT_GRANTED", "LOCAL_KEY_REQUIRED", "RESOURCE_NOT_FOUND",
    "BINDING_CHANGED", "INVALID_REQUEST", "UNSUPPORTED_VERSION",
    "RESOURCE_NOT_READY", "WORKSPACE_UNAVAILABLE",
    "CATALOG_NOT_READY", "ARTIFACT_CHANGED", "INVALID_INSTALLATION",
    "INSTALLATION_CONFLICT", "INVALID_REPORT", "REPORT_OUT_OF_ORDER",
    "REPORT_CONFLICT",
}


class AccessError(Exception):
    def __init__(self, code, retryable=False):
        super().__init__(code)
        self.retryable = retryable


def host_key_line(key):
    """Return one OpenSSH public-key line without duplicating its algorithm."""
    if not isinstance(key, dict):
        raise ValueError()
    algorithm = key.get("algorithm")
    public_key = key.get("public_key")
    if not isinstance(algorithm, str) or not isinstance(public_key, str):
        raise ValueError()
    fields = public_key.split()
    if fields and fields[0] == algorithm:
        return public_key
    return algorithm + " " + public_key


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

    def request(self, endpoint, token=None, *, body=None, yaml=False, method=None, max_bytes=256_000):
        self.url(endpoint)
        headers = {"Accept": "application/yaml" if yaml else "application/json"}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        limit = 2_000_000 if yaml else max_bytes
        try:
            with requests.request(
                method or ("POST" if body is not None else "GET"), endpoint,
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
            if (
                not isinstance(provider["client_id"], str)
                or not provider["client_id"]
                or type(provider["redirect_port"]) is not int
                or not 1 <= provider["redirect_port"] <= 65535
                or provider["redirect_uri"] != f"http://127.0.0.1:{provider['redirect_port']}/callback"
                or provider["scope"] != "openid profile"
            ):
                raise ValueError()
            for name in ("policy_endpoint", "network_profile_endpoint", "development_hosts_endpoint"):
                self.url(value[name])
            has_catalogue = value.get("configurations_endpoint") is not None
            has_installations = value.get("installations_endpoint") is not None
            if has_catalogue != has_installations:
                raise ValueError()
            for name in ("configurations_endpoint", "installations_endpoint", "credential_endpoint", "personal_center_url"):
                if value.get(name) is not None:
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
            local_model = capabilities.get("local_model")
            if local_model not in ("granted", "not_granted"):
                raise ValueError()
            if local_model == "granted":
                credential_endpoint = self.bootstrap.get("credential_endpoint")
                if not credential_endpoint:
                    raise ValueError()
                if self.url(credential_endpoint) != credential_endpoint:
                    raise ValueError()
                if "local_model" in value and not isinstance(value["local_model"], dict):
                    raise ValueError()
            elif "local_model" in value:
                raise ValueError()
        except (KeyError, TypeError, ValueError):
            raise AccessError("INVALID_POLICY") from None
        return value

    def model_credential(self, token, *, name="codex"):
        endpoint = self.bootstrap.get("credential_endpoint") if self.bootstrap else None
        if not endpoint:
            raise AccessError("LOCAL_MODEL_NOT_GRANTED")
        value = self.request(endpoint, token, body={"name": name})
        if (
            not isinstance(value.get("url"), str)
            or not value["url"]
            or not isinstance(value.get("key"), str)
            or not value["key"]
            or any(char.isspace() for char in value["key"])
        ):
            raise AccessError("INVALID_GATEWAY_CREDENTIAL")
        return value

    def configurations(self, token):
        endpoint = self.bootstrap.get("configurations_endpoint") if self.bootstrap else None
        if not endpoint:
            raise AccessError("UNSUPPORTED_VERSION")
        value = self.request(endpoint, token)
        if type(value.get("version")) is not int or value["version"] != 1:
            raise AccessError("UNSUPPORTED_VERSION")
        if not isinstance(value.get("binding_id"), str) or not value["binding_id"]:
            raise AccessError("INVALID_RESPONSE")
        configurations = value.get("configurations")
        if not isinstance(configurations, list):
            raise AccessError("INVALID_RESPONSE")
        records = []
        seen = set()
        try:
            for item in configurations:
                if (
                    not isinstance(item["id"], str)
                    or not item["id"]
                    or any(ord(c) < 32 for c in item["id"])
                    or item["kind"] not in ("mihomo", "ssh")
                    or (item["kind"] == "mihomo" and item["id"] != "network")
                    or (item["kind"] == "ssh" and not item["id"].startswith("ssh-"))
                    or not isinstance(item["revision"], str)
                    or not item["revision"]
                    or item["preparation"] not in ("prepared", "not_ready")
                    or item["id"] in seen
                ):
                    raise ValueError()
                seen.add(item["id"])
                observation = item.get("observation")
                if observation is not None and not isinstance(observation, dict):
                    raise ValueError()
                if observation is not None:
                    old_shape = {"principal_id", "configuration_id", "revision", "status", "reason"}
                    people_shape = {"executor", "observed_at", "source", "status", "valid_for_seconds", "work_order_id"}
                    if set(observation) <= old_shape:
                        if (
                            not isinstance(observation.get("principal_id"), str)
                            or not observation.get("principal_id")
                            or observation.get("configuration_id") != item["id"]
                            or observation.get("revision") != item["revision"]
                            or observation.get("status") not in ("pending", "running", "verified", "blocked", "failed")
                            or observation.get("reason") is not None
                            and observation.get("reason") not in (
                                "awaiting_member", "awaiting_administrator",
                                "dependency_unavailable", "verification_failed",
                            )
                            or observation.get("status") == "verified"
                            and observation.get("reason") is not None
                            or observation.get("status") in ("blocked", "failed")
                            and observation.get("reason") is None
                        ):
                            raise ValueError()
                    elif set(observation) == people_shape:
                        if (
                            not all(isinstance(observation.get(field), str) and observation.get(field) for field in ("executor", "observed_at", "source", "status", "work_order_id"))
                            or type(observation.get("valid_for_seconds")) is not int
                            or observation.get("valid_for_seconds") < 0
                            or observation.get("status") not in ("pending", "running", "verified", "blocked", "failed")
                        ):
                            raise ValueError()
                        observation = {
                            "principal_id": value["binding_id"],
                            "configuration_id": item["id"],
                            "revision": item["revision"],
                            "status": observation["status"],
                            "reason": None,
                        }
                    else:
                        raise ValueError()
                records.append({
                    "id": item["id"], "kind": item["kind"],
                    "revision": item["revision"],
                    "preparation": item["preparation"],
                    "observation": observation,
                    "binding_id": value["binding_id"],
                })
        except (KeyError, TypeError, ValueError):
            raise AccessError("INVALID_RESPONSE") from None
        return records

    def delivery(self, token, configuration):
        endpoint = self.bootstrap.get("configurations_endpoint") if self.bootstrap else None
        if not endpoint:
            raise AccessError("UNSUPPORTED_VERSION")
        endpoint = endpoint.rstrip("/") + "/" + quote(configuration["id"], safe="") + "/delivery"
        # JSON escaping can expand each byte of the 2 MB YAML payload sixfold.
        value = self.request(endpoint, token, body={"revision": configuration["revision"]},
                             max_bytes=12_256_000 if configuration["kind"] == "mihomo" else 256_000)
        if type(value.get("version")) is not int or value["version"] != 1:
            raise AccessError("UNSUPPORTED_VERSION")
        payload = value.get("configuration")
        if (
            value.get("binding_id") != configuration["binding_id"]
            or value.get("id") != configuration["id"]
            or value.get("revision") != configuration["revision"]
            or value.get("kind") != configuration["kind"]
            or not isinstance(payload, dict)
        ):
            raise AccessError("BINDING_CHANGED")
        if configuration["kind"] == "mihomo":
            if set(payload) != {"yaml"} or not isinstance(payload.get("yaml"), str) or not payload["yaml"] or len(payload["yaml"].encode()) > 2_000_000:
                raise AccessError("INVALID_PROFILE")
        else:
            self._validate_ssh_delivery(payload)
        return {**value, "configuration": payload}

    @staticmethod
    def _validate_ssh_delivery(payload):
        required = {"connection", "workspaces", "ssh_access_mode", "user_key_fingerprints"}
        if not required.issubset(payload) or not isinstance(payload["connection"], dict) or not isinstance(payload["workspaces"], list):
            raise AccessError("INVALID_RESPONSE")
        connection = payload["connection"]
        if (
            connection.get("transport") != "ssh"
            or connection.get("network_requirement") not in ("direct", "tailscale", "company_proxy")
            or not isinstance(connection.get("hostname"), str)
            or type(connection.get("port")) is not int
            or not 1 <= connection["port"] <= 65535
            or not isinstance(connection.get("username"), str)
            or not isinstance(connection.get("host_keys"), list)
            or not connection["host_keys"]
        ):
            raise AccessError("INVALID_HOST")
        if payload["ssh_access_mode"] not in ("managed-keypair", "registered-public-key"):
            raise AccessError("INVALID_HOST")
        if (
            not isinstance(payload["user_key_fingerprints"], list)
            or not payload["user_key_fingerprints"]
            or not all(isinstance(value, str) for value in payload["user_key_fingerprints"])
        ):
            raise AccessError("INVALID_HOST")
        for key in connection["host_keys"]:
            if not isinstance(key, dict) or not isinstance(key.get("algorithm"), str) or not isinstance(key.get("public_key"), str):
                raise AccessError("INVALID_HOST")
        for workspace in payload["workspaces"]:
            if (
                not isinstance(workspace, dict)
                or not isinstance(workspace.get("id"), str)
                or not isinstance(workspace.get("display_name"), str)
                or not isinstance(workspace.get("path"), str)
                or not workspace["path"].startswith("/")
                or any(ord(char) < 32 for char in workspace["path"])
            ):
                raise AccessError("INVALID_HOST")
        private_key = payload.get("private_key")
        if payload["ssh_access_mode"] == "registered-public-key":
            if private_key is not None or payload.get("managed_key_fingerprint") is not None:
                raise AccessError("INVALID_HOST")
        else:
            if (
                not isinstance(payload.get("managed_key_fingerprint"), str)
                or payload["managed_key_fingerprint"] not in payload["user_key_fingerprints"]
                or private_key is not None
                and (not isinstance(private_key, str) or not private_key.startswith("-----BEGIN"))
            ):
                raise AccessError("KEY_MISMATCH")

    def register_installation(self, token, installation_id, platform, client_version):
        endpoint = self.bootstrap.get("installations_endpoint") if self.bootstrap else None
        if not endpoint:
            raise AccessError("UNSUPPORTED_VERSION")
        value = self.request(endpoint, token, body={
            "id": installation_id, "platform": platform,
            "client_version": client_version,
        })
        if (
            type(value.get("version")) is not int or value["version"] != 1
            or value.get("id") != installation_id
            or not isinstance(value.get("binding_id"), str)
        ):
            raise AccessError("INVALID_RESPONSE")
        return value

    def installations(self, token):
        endpoint = self.bootstrap.get("installations_endpoint") if self.bootstrap else None
        if not endpoint:
            raise AccessError("UNSUPPORTED_VERSION")
        value = self.request(endpoint, token)
        if type(value.get("version")) is not int or value["version"] != 1:
            raise AccessError("UNSUPPORTED_VERSION")
        installations = value.get("installations")
        if not isinstance(installations, list):
            raise AccessError("INVALID_RESPONSE")
        try:
            for installation in installations:
                if (
                    not isinstance(installation, dict)
                    or not isinstance(installation.get("id"), str)
                    or not installation["id"]
                    or installation.get("reports") is not None
                    and not isinstance(installation["reports"], list)
                ):
                    raise ValueError()
        except (TypeError, ValueError):
            raise AccessError("INVALID_RESPONSE") from None
        return installations

    def report(self, token, endpoint, report_id, payload):
        url = self.bootstrap.get("installations_endpoint") if self.bootstrap else None
        if not url:
            raise AccessError("UNSUPPORTED_VERSION")
        url = url.rstrip("/") + "/" + quote(endpoint, safe="") + "/reports/" + quote(report_id, safe="")
        value = self.request(url, token, body=payload, method="PUT")
        if type(value.get("version")) is not int or value["version"] != 1 or value.get("report_id") != report_id:
            raise AccessError("INVALID_RESPONSE")
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
                connection["host_keys"] = [host_key_line(key) for key in connection["host_keys"]]
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
