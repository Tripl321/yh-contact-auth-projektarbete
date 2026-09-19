"""Tester för FIDO2-lagring. Använder tmp_path — rör aldrig riktig lagring."""

import json

import pytest

from shallot_cli import fido2_store as store


def _meta(cid="cred-1", user="admin-01"):
    return {"credential_id": cid, "user_id": user, "created": "2026-01-01T00:00:00Z",
            "status": store.STATUS_ACTIVE, "policy": {"user_presence": True}}


def test_save_and_load_roundtrip(tmp_path):
    store.save_credential(_meta(), root=tmp_path)
    creds = store.load_credentials(root=tmp_path)
    assert creds["cred-1"]["user_id"] == "admin-01"
    assert creds["cred-1"]["status"] == "active"


def test_load_empty_store_returns_empty_dict(tmp_path):
    assert store.load_credentials(root=tmp_path) == {}


def test_forbidden_fields_rejected(tmp_path):
    for field in store.FORBIDDEN_FIELDS:
        bad = _meta()
        bad[field] = "hemlighet"
        with pytest.raises(ValueError, match="förbjudet fält"):
            store.save_credential(bad, root=tmp_path)
    assert store.load_credentials(root=tmp_path) == {}


def test_missing_required_field_rejected(tmp_path):
    bad = _meta()
    del bad["policy"]
    with pytest.raises(ValueError, match="policy"):
        store.save_credential(bad, root=tmp_path)


def test_duplicate_credential_rejected(tmp_path):
    store.save_credential(_meta(), root=tmp_path)
    with pytest.raises(ValueError, match="finns redan"):
        store.save_credential(_meta(), root=tmp_path)


def test_set_status_lifecycle(tmp_path):
    store.save_credential(_meta(), root=tmp_path)
    updated = store.set_status("cred-1", store.STATUS_REVOKED, root=tmp_path)
    assert updated["status"] == "revoked"
    assert store.load_credentials(root=tmp_path)["cred-1"]["status"] == "revoked"


def test_set_status_unknown_credential_and_status(tmp_path):
    with pytest.raises(KeyError):
        store.set_status("finns-inte", store.STATUS_REVOKED, root=tmp_path)
    store.save_credential(_meta(), root=tmp_path)
    with pytest.raises(ValueError):
        store.set_status("cred-1", "borttappad", root=tmp_path)


def test_update_policy_merges_and_rejects(tmp_path):
    store.save_credential(_meta(), root=tmp_path)
    updated = store.update_policy("cred-1", {"user_verification": "required"},
                                  root=tmp_path)
    assert updated["policy"]["user_verification"] == "required"
    assert store.load_credentials(root=tmp_path)["cred-1"]["policy"]["user_verification"] == "required"
    with pytest.raises(KeyError):
        store.update_policy("finns-inte", {"user_verification": "required"}, root=tmp_path)
    with pytest.raises(ValueError):
        store.update_policy("cred-1", {}, root=tmp_path)


def test_audit_append_and_read(tmp_path):
    store.audit("register", {"credential_id": "cred-1"}, root=tmp_path)
    store.audit("revoke", {"credential_id": "cred-1"}, root=tmp_path)
    entries = store.read_audit(root=tmp_path)
    assert [e["action"] for e in entries] == ["register", "revoke"]
    assert all("ts" in e for e in entries)


def test_audit_rejects_secrets(tmp_path):
    with pytest.raises(ValueError, match="förbjudet fält"):
        store.audit("register", {"private_key": "x"}, root=tmp_path)


def test_audit_read_empty_and_skips_corrupt(tmp_path):
    assert store.read_audit(root=tmp_path) == []
    (tmp_path / store.AUDIT_FILE).write_text('{"ts":"t","action":"ok"}\nKORRUPT\n',
                                             encoding="utf-8")
    assert store.read_audit(root=tmp_path) == [{"ts": "t", "action": "ok"}]


def test_store_root_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv(store.STORE_ENV, str(tmp_path / "prod-like"))
    assert store.store_root() == tmp_path / "prod-like"


def test_stored_file_contains_no_secrets(tmp_path):
    store.save_credential(_meta(), root=tmp_path)
    blob = (tmp_path / store.CREDENTIALS_FILE).read_text(encoding="utf-8")
    assert "private" not in blob.lower() and "secret" not in blob.lower()
    assert json.loads(blob)["cred-1"]["user_id"] == "admin-01"


def test_suite_store_is_hermetic(tmp_path):
    import os
    assert os.environ.get(store.STORE_ENV) == str(tmp_path / "fido2-store")
    assert store.store_root() == tmp_path / "fido2-store"
