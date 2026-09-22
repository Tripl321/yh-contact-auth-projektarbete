"""Tester för OS-valvet. Rör aldrig riktigt Keychain — subprocess
och plattform fakes."""

import pytest

from shallot_cli import admin_vault


class _Proc:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _mac(monkeypatch, run):
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("shutil.which", lambda name: "/usr/bin/security")
    monkeypatch.setattr("subprocess.run", run)


def test_no_backend_fails_closed(monkeypatch):
    monkeypatch.setattr("sys.platform", "haiku")
    monkeypatch.setattr("shutil.which", lambda name: None)
    with pytest.raises(RuntimeError, match="OS-säkert"):
        admin_vault.backend_name()
    with pytest.raises(RuntimeError, match="OS-säkert"):
        admin_vault.store_hash({"hash": "x"})


def test_macos_keychain_roundtrip(monkeypatch):
    calls = []
    box = {}

    def fake_run(argv, **kwargs):
        calls.append(argv)
        if argv[1] == "add-generic-password":
            box["blob"] = argv[argv.index("-w") + 1]
            return _Proc(0)
        if argv[1] == "find-generic-password":
            return _Proc(0, stdout=box["blob"])
        return _Proc(0)

    _mac(monkeypatch, fake_run)
    assert admin_vault.backend_name() == "macos-keychain"
    admin_vault.store_hash({"salt": "ab", "hash": "cd", "iterations": 1})
    assert admin_vault.load_hash() == {"salt": "ab", "hash": "cd", "iterations": 1}
    assert calls[0][0] == "security" and calls[0][1] == "add-generic-password"
    assert all(cmd[0] == "security" and cmd[1:2] != ["sh"] for cmd in calls)


def test_macos_missing_hash_returns_none(monkeypatch):
    _mac(monkeypatch, lambda argv, **kw: _Proc(44, stderr="not found"))
    assert admin_vault.load_hash() is None


def test_secret_tool_store_uses_stdin(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["stdin"] = kwargs.get("input")
        if argv[1] == "lookup":
            return _Proc(0, stdout='{"salt": "ab"}')
        return _Proc(0)

    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which",
                        lambda name: "/usr/bin/secret-tool" if name == "secret-tool" else None)
    monkeypatch.setattr("subprocess.run", fake_run)
    assert admin_vault.backend_name() == "secret-tool"
    admin_vault.store_hash({"salt": "ab"})
    assert seen["stdin"] == '{"salt": "ab"}'
    assert admin_vault.load_hash() == {"salt": "ab"}
