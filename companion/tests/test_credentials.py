"""The desktop session uses a private app-state file, never an OS keychain."""

import json
import os
import stat

import pytest

from workspace_agent import AgentError, CredentialStore


def test_session_file_is_private_and_round_trips(tmp_path):
    path = tmp_path / "credentials.json"
    store = CredentialStore("synthetic-account", path=path)
    session = {"provider": "feishu", "token": {"access_token": "synthetic"}}

    store.set(session)

    assert store.get() == session
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert json.loads(path.read_text()) == session


def test_session_file_rejects_symlink(tmp_path):
    target = tmp_path / "target.json"
    target.write_text("{}")
    path = tmp_path / "credentials.json"
    path.symlink_to(target)
    store = CredentialStore("synthetic-account", path=path)

    with pytest.raises(AgentError, match="INVALID_SESSION"):
        store.get()


def test_session_file_rejects_group_or_other_access(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(json.dumps({"provider": "feishu"}))
    path.chmod(0o644)
    store = CredentialStore("synthetic-account", path=path)

    with pytest.raises(AgentError, match="INVALID_SESSION"):
        store.get()


def test_clear_removes_session_file(tmp_path):
    store = CredentialStore("synthetic-account", path=tmp_path / "credentials.json")
    store.set({"provider": "feishu"})
    store.clear()
    assert store.get() is None
