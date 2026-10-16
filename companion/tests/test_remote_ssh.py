"""Regressions for preserving personal SSH config and pinning authorized hosts."""

import copy
import getpass
from pathlib import Path
import socket
import subprocess
import time

import pytest

from remote_ssh import RemoteError, RemoteSSH, key_fingerprint
from workspace_agent import Agent


@pytest.fixture
def remote(tmp_path):
    ssh = tmp_path / "home/.ssh"
    ssh.mkdir(parents=True)
    identity = ssh / "id_ed25519"
    server = tmp_path / "server_key"
    for key in (identity, server):
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    record = {
        "id": "fixture-host", "display_name": "Fixture development host",
        "connection": {"hostname": "127.0.0.1", "port": 2222, "username": getpass.getuser(),
                       "transport": "ssh", "host_keys": [server.with_suffix(".pub").read_text()]},
        "user_key_fingerprints": [key_fingerprint(identity.with_suffix(".pub").read_text())],
        "workspaces": [{"id": "project", "display_name": "Fixture project", "path": str(tmp_path)}],
    }
    return RemoteSSH(tmp_path / "home"), record, identity, server


def test_preserves_config_and_rejects_changed_pin(remote):
    manager, record, identity, server = remote
    manager.public_identity = lambda _: identity.with_suffix(".pub").read_text()
    config = manager.ssh / "config"
    original = b"# Personal settings\r\nHost personal\r\n  HostName personal.invalid\r\n"
    config.write_bytes(original)
    first = manager.prepare(record, "project")
    content = config.read_bytes()
    assert content.endswith(original)
    assert manager.prepare(record, "project") == first
    assert config.read_bytes() == content
    assert (manager.managed / "config.before-workspace").read_bytes() == original
    result = subprocess.run(["ssh", "-G", "-F", str(config), first["alias"]], capture_output=True, text=True, check=True)
    for expected in ("stricthostkeychecking true", "forwardagent no", "clearallforwardings yes", "batchmode yes"):
        assert expected in result.stdout
    public_path = manager.managed / f"{first['alias']}.pub"
    previous_public = public_path.read_bytes()
    manager.public_identity = lambda _: server.with_suffix(".pub").read_text()
    changed = copy.deepcopy(record)
    changed["connection"]["host_keys"] = [Path(remote[2]).with_suffix(".pub").read_text()]
    with pytest.raises(RemoteError, match="config_conflict"):
        manager.prepare(changed, "project")
    assert config.read_bytes() == content
    assert public_path.read_bytes() == previous_public


def test_rejects_unverified_or_injected_targets(remote):
    manager, record, _, _ = remote
    for field, value in (("hostname", "-oProxyCommand=anything"), ("username", "user\nLocalCommand anything"), ("port", 0)):
        invalid = copy.deepcopy(record)
        invalid["connection"][field] = value
        with pytest.raises(RemoteError, match="invalid_host"):
            manager.prepare(invalid, "project")
    record["connection"]["host_keys"] = []
    with pytest.raises(RemoteError, match="unverified_host"):
        manager.prepare(record, "project")
    assert not manager.managed.exists()


def test_remote_authority_refetched_and_failure_is_not_unassigned(remote, tmp_path):
    manager, record, _, _ = remote
    class Store:
        def get(self):
            return {"provider": "feishu"}
    records = [record]
    agent = Agent(tmp_path / "unconfigured.json", store=Store(), remote_authority=lambda _: records, remote_ssh=manager)
    agent.access_token = lambda: "synthetic-access"
    assert agent.remote("hosts")["state"] == "available"
    records.clear()
    assert agent.remote("prepare", record["id"], "project")["state"] == "not_authorized"
    assert not manager.managed.exists()
    assert agent.remote("hosts")["state"] == "unassigned"
    def outage(_):
        raise ConnectionError()
    agent.remote_authority = outage
    assert agent.remote("hosts")["state"] == "unavailable"
    assert Agent(tmp_path / "unconfigured.json").remote("hosts")["state"] == "unconfigured"


def test_real_loopback_ssh_checks_user_directory_and_codex(remote, tmp_path):
    manager, record, identity, server = remote
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    record["connection"]["port"] = port
    config = tmp_path / "sshd_config"
    config.write_text(
        f"Port {port}\nListenAddress 127.0.0.1\nHostKey {server}\n"
        f"PidFile {tmp_path / 'sshd.pid'}\nAuthorizedKeysFile {identity.with_suffix('.pub')}\n"
        "StrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nUsePAM no\n"
    )
    with (tmp_path / "sshd.log").open("w+") as log:
        daemon = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", str(config)], stderr=log)
        try:
            for _ in range(30):
                if daemon.poll() is not None:
                    log.seek(0)
                    pytest.fail("Loopback sshd could not start: " + log.read())
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            result = manager.check(record, "project")
            assert result["state"] in ("ssh_ready", "codex_unavailable"), result
            wrong_pin = copy.deepcopy(record)
            wrong_pin["connection"]["host_keys"] = [identity.with_suffix(".pub").read_text()]
            wrong_manager = RemoteSSH(tmp_path / "wrong-pin-home")
            wrong_manager.public_identity = lambda _: identity
            assert wrong_manager.check(wrong_pin, "project")["state"] == "host_key_conflict"
            wrong_identity = RemoteSSH(tmp_path / "wrong-identity-home")
            wrong_identity.public_identity = lambda _: server
            assert wrong_identity.check(record, "project")["state"] == "permission_denied"
            record["workspaces"][0]["path"] = str(tmp_path / "missing")
            assert manager.check(record, "project")["state"] == "unreachable"
        finally:
            daemon.terminate()
            daemon.wait(timeout=5)


def test_ssh_check_does_not_block_model_helper_and_rejects_signed_out_result(remote, tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    import threading
    manager, record, _, _ = remote
    started, finish = threading.Event(), threading.Event()
    class Store:
        value = {"provider": "feishu"}
        def get(self):
            return self.value
    store = Store()
    class SlowSSH:
        def check(self, *_):
            started.set()
            assert finish.wait(5)
            return {"state": "ssh_ready"}
    agent = Agent(tmp_path / "unconfigured.json", store=store, remote_authority=lambda _: [record], remote_ssh=SlowSSH())
    agent.config = {"version": 2}
    agent.access_token = lambda: "synthetic-access"
    agent.token = lambda: "synthetic-model"
    with ThreadPoolExecutor() as executor:
        operation = executor.submit(agent.remote, "check", record["id"], "project")
        assert started.wait(3)
        try:
            assert agent.run("token-feishu") == "synthetic-model"
            store.value["token"] = {"access_token": "rotated-synthetic-access"}
        finally:
            finish.set()
        assert operation.result()["state"] == "ssh_ready"
        for replacement in (None, {"provider": "feishu", "session_id": "new-login"}):
            store.value = {"provider": "feishu", "session_id": "original-login"}
            started.clear()
            finish.clear()
            operation = executor.submit(agent.remote, "check", record["id"], "project")
            assert started.wait(3)
            store.value = replacement
            finish.set()
            assert operation.result()["state"] == "not_authorized"
