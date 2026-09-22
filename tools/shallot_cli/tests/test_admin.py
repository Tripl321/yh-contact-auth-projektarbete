"""Tester för Admin-upplevelsen. Hermetisk lagring via conftest; valv
och getpass fakes — rör aldrig riktigt Keychain eller terminal."""

import json

import pytest

from shallot_cli import admin, admin_vault, cli, fido2
from shallot_cli import fido2_store as store


class FakeVault:
    def __init__(self):
        self.record = None

    def store_hash(self, record):
        self.record = dict(record)

    def load_hash(self):
        return dict(self.record) if self.record is not None else None

    def delete_hash(self):
        self.record = None


@pytest.fixture
def vault(monkeypatch):
    return FakeVault()


def _enroll(vault, code="123456"):
    vault.store_hash(admin.hash_code(code))
    return code


def _register_admin(user="admin-01"):
    return fido2.register_user(user)


def _code(monkeypatch, code):
    monkeypatch.setattr("getpass.getpass", lambda prompt="": code)


def test_login_success_creates_sliding_session(vault, monkeypatch, capsys):
    _register_admin()
    _enroll(vault)
    _code(monkeypatch, "123456")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    out = capsys.readouterr().out
    assert "OK" in out and "Inloggad som admin-01" in out
    sess = admin.require_session("test")
    assert sess["user"] == "admin-01"
    # Glidande: användning rör last_activity framåt.
    assert admin.run_status() == 0
    assert "giltig" in capsys.readouterr().out


def test_five_wrong_codes_lock_until_fresh_fido2(vault, monkeypatch):
    _register_admin()
    _enroll(vault)
    _code(monkeypatch, "000000")
    for _ in range(5):
        assert admin.run_login("admin-01", mock=True, vault=vault) == 1
    assert admin._load_state()["code_locked"] is True
    # Låst: nästa inloggnings färska FIDO2 låser upp, men koden nekas
    # den rundan — sjunde inloggningen lyckas.
    _code(monkeypatch, "123456")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 1
    assert admin._load_state()["code_locked"] is False
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0


def test_session_expires_after_inactivity(vault, monkeypatch):
    _register_admin()
    _enroll(vault)
    _code(monkeypatch, "123456")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    state = admin._load_state()
    state["session"]["last_activity"] -= admin.SESSION_TIMEOUT_S + 1
    admin._save_state(state)
    assert admin.run_status() == 1
    with pytest.raises(admin.AdminDenied):
        admin.require_session("test")
    # Utgången session rensas + nekas journalförs (utan hemligheter).
    assert admin._load_state()["session"] is None


def test_logout_clears_session(vault, monkeypatch, capsys):
    _register_admin()
    _enroll(vault)
    _code(monkeypatch, "123456")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    assert admin.run_logout() == 0
    assert "Utloggad" in capsys.readouterr().out
    assert admin.run_status() == 1


def test_login_without_enrolled_code_points_to_reset(vault, monkeypatch, capsys):
    _register_admin()
    _code(monkeypatch, "123456")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 1
    assert "reset-code" in capsys.readouterr().out


def test_reset_code_requires_confirm_and_session(vault, monkeypatch, capsys):
    _register_admin()
    _enroll(vault)
    assert admin.run_reset_code(confirm=False, vault=vault) == 2
    assert admin.run_reset_code(confirm=True, vault=vault) == 1
    assert "session" in capsys.readouterr().out.lower()


def test_reset_code_full_flow_with_physical_assertion(vault, monkeypatch, capsys):
    _register_admin()
    _enroll(vault, "111111")
    _code(monkeypatch, "111111")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    monkeypatch.setattr(admin, "_hardware_assertion_ok",
                        lambda user: (True, "ok"))
    monkeypatch.setattr(admin.secrets, "randbelow", lambda n: 654321)
    _code(monkeypatch, "654321")
    capsys.readouterr()
    assert admin.run_reset_code(confirm=True, vault=vault) == 0
    out = capsys.readouterr().out
    assert "654321" in out  # visad EN gång vid skapande
    # Nya koden gäller, gamla är död.
    _code(monkeypatch, "111111")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 1
    _code(monkeypatch, "654321")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    # Koden förekommer aldrig i loggar eller tillstånd.
    audit_blob = admin._audit_path().read_text(encoding="utf-8")
    state_blob = admin._state_path().read_text(encoding="utf-8")
    assert "654321" not in audit_blob and "654321" not in state_blob
    assert "111111" not in audit_blob


def test_reset_code_mismatch_stores_nothing(vault, monkeypatch):
    _register_admin()
    _enroll(vault, "111111")
    _code(monkeypatch, "111111")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    monkeypatch.setattr(admin, "_hardware_assertion_ok",
                        lambda user: (True, "ok"))
    monkeypatch.setattr(admin.secrets, "randbelow", lambda n: 654321)
    _code(monkeypatch, "000000")
    assert admin.run_reset_code(confirm=True, vault=vault) == 1
    assert admin.verify_code("111111", vault.load_hash()) is True


def test_reset_code_bootstrap_without_session(vault, monkeypatch):
    _register_admin()
    monkeypatch.setattr(admin, "_hardware_assertion_ok",
                        lambda user: (True, "ok"))
    monkeypatch.setattr(admin.secrets, "randbelow", lambda n: 222222)
    monkeypatch.setattr("builtins.input", lambda *a: "admin-01")
    _code(monkeypatch, "222222")
    assert admin.run_reset_code(confirm=True, vault=vault) == 0
    assert admin.verify_code("222222", vault.load_hash()) is True


def test_reset_code_requires_physical_assertion(vault, monkeypatch):
    _register_admin()
    _enroll(vault, "111111")
    _code(monkeypatch, "111111")
    assert admin.run_login("admin-01", mock=True, vault=vault) == 0
    monkeypatch.setattr(admin, "_hardware_assertion_ok",
                        lambda user: (False, "device-error"))
    assert admin.run_reset_code(confirm=True, vault=vault) == 1


def test_hash_verify_and_corrupt_record():
    rec = admin.hash_code("123456")
    assert admin.verify_code("123456", rec) is True
    assert admin.verify_code("123455", rec) is False
    assert admin.verify_code("123456", {}) is False
    assert admin.verify_code("123456", {"hash": "zz", "salt": "zz"}) is False
    assert set(rec) == {"salt", "hash", "iterations"}


def test_admin_login_defaults_to_hardware(vault, monkeypatch, capsys):
    from shallot_cli import fido2_backend
    _register_admin()
    _enroll(vault)
    monkeypatch.setattr(fido2_backend.CtapHidBackend, "describe_devices",
                        lambda self: [])
    assert admin.run_login("admin-01", vault=vault) == 1
    assert "--mock" in capsys.readouterr().out


def test_check_confirm_and_require_session_gates():
    with pytest.raises(ValueError):
        admin.check_confirm(False, "reset-code")
    admin.check_confirm(True, "reset-code")
    with pytest.raises(admin.AdminDenied):
        admin.require_session("flash")


def test_cli_wiring_admin_status_and_reset_confirm(capsys):
    assert cli.main(["admin", "status"]) == 1
    assert cli.main(["admin", "reset-code"]) == 2
    assert "--confirm" in capsys.readouterr().err


def test_audit_log_has_no_secrets(vault, monkeypatch):
    _register_admin()
    _enroll(vault)
    _code(monkeypatch, "000000")
    admin.run_login("admin-01", mock=True, vault=vault)
    blob = admin._audit_path().read_text(encoding="utf-8")
    assert "000000" not in blob and "123456" not in blob
    for line in blob.strip().splitlines():
        entry = json.loads(line)
        assert set(entry) == {"ts", "action", "details"}
