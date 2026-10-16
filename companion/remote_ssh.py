"""Local SSH preparation for identity-authorized development hosts.

The access-service adapter supplies records; the WebView supplies only IDs.
Managed keys are verified and installed natively; remote model settings are untouched.
"""

import base64
import hashlib
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import stat

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from filelock import FileLock


class RemoteError(Exception):
    pass


def key_fingerprint(line):
    fields = line.split()
    if len(fields) < 2 or fields[0] not in (
        "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    ):
        raise RemoteError("unverified_host")
    try:
        blob = base64.b64decode(fields[1], validate=True)
        length = int.from_bytes(blob[:4], "big")
        if blob[4:4 + length].decode() != fields[0] or len(blob) < length + 8:
            raise ValueError()
        serialization.load_ssh_public_key((fields[0] + " " + fields[1]).encode())
    except (ValueError, UnicodeError):
        raise RemoteError("unverified_host") from None
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def checked_record(record, workspace_id):
    try:
        connection = record["connection"]
        workspace = next(w for w in record["workspaces"] if w["id"] == workspace_id)
        if connection["transport"] != "ssh":
            raise ValueError()
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9.:-]{0,252}", connection["hostname"]):
            raise ValueError()
        if not re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_.-]{0,63}", connection["username"]):
            raise ValueError()
        if type(connection["port"]) is not int or not 1 <= connection["port"] <= 65535:
            raise ValueError()
        if not workspace["path"].startswith("/") or any(ord(c) < 32 for c in workspace["path"]):
            raise ValueError()
        keys = connection.get("host_keys", [])
        if not keys:
            raise RemoteError("unverified_host")
        for key in keys:
            if "\n" in key.strip() or "\r" in key.strip():
                raise ValueError()
            key_fingerprint(key)
        if not record.get("user_key_fingerprints"):
            raise RemoteError("missing_key")
        return connection, workspace
    except (KeyError, TypeError, ValueError, StopIteration):
        raise RemoteError("invalid_host") from None


def write_private(path, content):
    fd, name = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(content.encode() if isinstance(content, str) else content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class RemoteSSH:
    def __init__(self, home=None, runner=subprocess.run, proxy_port=None):
        self.ssh = Path(home or Path.home()) / ".ssh"
        self.managed = self.ssh / "pilgrim-workspace"
        self.runner = runner
        self.proxy_port = proxy_port

    def public_identity(self, allowed):
        for path in sorted(self.ssh.glob("*.pub")):
            if path.is_symlink() or not path.is_file():
                continue
            try:
                if key_fingerprint(path.read_text()) in allowed:
                    private_path = path.with_suffix("")
                    if private_path.is_file():
                        return private_path
            except (OSError, RemoteError):
                continue
        result = self.runner(["ssh-add", "-L"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                try:
                    if key_fingerprint(line) in allowed:
                        return line
                except RemoteError:
                    continue
        raise RemoteError("missing_key")

    def alias(self, record):
        return "pilgrim-" + hashlib.sha256((record.get("binding_id", "") + record["id"]).encode()).hexdigest()[:20]

    def managed_identity(self, record, credential):
        try:
            key = serialization.load_ssh_private_key(credential.encode(), password=None)
            if not isinstance(key, Ed25519PrivateKey):
                raise ValueError()
            public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
            if key_fingerprint(public) != record["managed_key_fingerprint"]:
                raise ValueError()
        except (TypeError, ValueError, RemoteError):
            raise RemoteError("key_mismatch") from None
        return self.managed / (self.alias(record) + ".key")

    def prepare(self, record, workspace_id, *, credential=None):
        connection, workspace = checked_record(record, workspace_id)
        if connection.get("network_requirement") == "company_proxy" and not self.proxy_port:
            raise RemoteError("network_required")
        identity = self.managed_identity(record, credential) if record.get("ssh_access_mode") == "managed-keypair" else self.public_identity(record["user_key_fingerprints"])
        alias = self.alias(record)
        if self.ssh.is_symlink() or self.managed.is_symlink():
            raise RemoteError("config_conflict")
        self.ssh.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.ssh.stat().st_uid != os.getuid() or stat.S_IMODE(self.ssh.stat().st_mode) & 0o022:
            raise RemoteError("config_conflict")
        self.managed.mkdir(mode=0o700, exist_ok=True)
        if self.managed.stat().st_uid != os.getuid() or stat.S_IMODE(self.managed.stat().st_mode) != 0o700:
            raise RemoteError("config_conflict")
        config = self.ssh / "config"
        fragment = self.managed / f"{alias}.conf"
        known = self.managed / f"{alias}.known_hosts"
        agent_public = self.managed / f"{alias}.pub"
        lock = self.managed / "update.lock"
        if any(p.is_symlink() for p in (config, fragment, known, agent_public, lock)):
            raise RemoteError("config_conflict")
        with FileLock(lock, timeout=1):
            public_content = identity + "\n" if isinstance(identity, str) else None
            if public_content is not None:
                identity = agent_public
            quote = lambda value: '"' + str(value).replace('\\', '\\\\').replace('"', '\\"') + '"'
            if any(c in str(identity) for c in ("%", "\n", "\r")):
                raise RemoteError("config_conflict")
            pin = "".join(f"{alias} {' '.join(key.split()[:2])}\n" for key in connection["host_keys"])
            settings = {
                "HostName": connection["hostname"], "Port": connection["port"],
                "User": connection["username"], "IdentityFile": quote(identity),
                "IdentitiesOnly": "yes", "BatchMode": "yes", "StrictHostKeyChecking": "yes",
                "HostKeyAlias": alias, "UserKnownHostsFile": quote(known),
                "GlobalKnownHostsFile": "/dev/null", "UpdateHostKeys": "no",
                "ProxyCommand": "none", "ProxyJump": "none", "LocalCommand": "none",
                "PermitLocalCommand": "no", "ForwardAgent": "no", "ForwardX11": "no",
                "ClearAllForwardings": "yes", "RequestTTY": "no", "ControlMaster": "no",
                "ControlPath": "none", "RemoteCommand": "none", "ConnectTimeout": "8", "ConnectionAttempts": "1",
            }
            if connection.get("network_requirement") == "company_proxy":
                if type(self.proxy_port) is not int or not 1 <= self.proxy_port <= 65535:
                    raise RemoteError("network_required")
                settings["ProxyCommand"] = f"/usr/bin/nc -X 5 -x 127.0.0.1:{self.proxy_port} %h %p"
            contents = f"Host {alias}\n" + "".join(f"  {key} {value}\n" for key, value in settings.items()) + "Host *\n"
            expected_files = [(fragment, contents), (known, pin)]
            if credential is not None:
                if identity.is_symlink():
                    raise RemoteError("config_conflict")
                expected_files.append((identity, credential))
            if public_content is not None:
                expected_files.append((agent_public, public_content))
            for path, value in expected_files:
                if path.exists():
                    if (path.read_bytes() != value.encode() or path.stat().st_uid != os.getuid()
                            or stat.S_IMODE(path.stat().st_mode) & 0o077):
                        raise RemoteError("config_conflict")
            include = ('Include ' + quote(self.managed / '*.conf') + '\n').encode()
            original = config.read_bytes() if config.exists() else b""
            if b"pilgrim-workspace/" in original and not original.startswith(include):
                raise RemoteError("config_conflict")
            if not original.startswith(include):
                backup = self.managed / "config.before-workspace"
                if backup.is_symlink():
                    raise RemoteError("config_conflict")
                if config.exists() and not backup.exists():
                    write_private(backup, original)
            for path, content in expected_files:
                if not path.exists():
                    fd, temporary = tempfile.mkstemp(dir=self.managed)
                    try:
                        with os.fdopen(fd, "wb") as stream:
                            stream.write(content.encode())
                            stream.flush()
                            os.fsync(stream.fileno())
                        # A concurrent writer cannot replace a pre-existing key or pin.
                        os.link(temporary, path)
                    except FileExistsError:
                        raise RemoteError("config_conflict") from None
                    finally:
                        os.unlink(temporary)
            if not original.startswith(include):
                write_private(config, include + original)
        resolved = self.runner(["ssh", "-G", "-F", str(config), alias], capture_output=True, text=True, timeout=5)
        actual = {}
        for line in resolved.stdout.splitlines():
            name, _, value = line.partition(" ")
            actual.setdefault(name, value)
        if (resolved.returncode or actual.get("hostname") != connection["hostname"]
                or actual.get("user") != connection["username"] or actual.get("port") != str(connection["port"])
                or actual.get("stricthostkeychecking") not in ("true", "yes")
                or actual.get("identityfile", "").strip('"') != str(identity)):
            return {"state": "desktop_config_conflict", "alias": alias, "path": workspace["path"]}
        return {"state": "ssh_prepared", "alias": alias, "path": workspace["path"]}

    def check(self, record, workspace_id, *, credential=None):
        prepared = self.prepare(record, workspace_id, credential=credential)
        if prepared["state"] != "ssh_prepared":
            return prepared
        connection, workspace = checked_record(record, workspace_id)
        fragment = self.managed / f"{prepared['alias']}.conf"
        # Use only the managed fragment during the probe; personal config may run commands.
        script = "cd -- " + shlex.quote(workspace["path"]) + " && id -un && pwd -P && (command -v codex || printf 'CODEX_UNAVAILABLE\\n')"
        command = 'exec "$SHELL" -lc ' + shlex.quote(script)
        try:
            result = self.runner(
                ["ssh", "-F", str(fragment), prepared["alias"], command],
                capture_output=True, text=True, timeout=15,
            )
        except subprocess.TimeoutExpired:
            return {**prepared, "state": "unreachable"}
        lines = result.stdout.strip().splitlines()
        if result.returncode and ("REMOTE HOST IDENTIFICATION HAS CHANGED" in result.stderr or "Host key verification failed" in result.stderr):
            return {**prepared, "state": "host_key_conflict"}
        if result.returncode and "Permission denied" in result.stderr:
            return {**prepared, "state": "permission_denied"}
        if result.returncode or len(lines) != 3 or lines[:2] != [connection["username"], workspace["path"]]:
            return {**prepared, "state": "unreachable"}
        if not lines[2].startswith("/"):
            return {**prepared, "state": "codex_unavailable"}
        return {**prepared, "state": "ssh_ready"}


def public_hosts(records):
    return [{
        "id": host["id"], "display_name": host["display_name"],
        "network_requirement": host["connection"].get("network_requirement", "direct"),
        "workspaces": [{"id": w["id"], "display_name": w["display_name"], "path": w["path"]} for w in host["workspaces"]],
    } for host in records]
