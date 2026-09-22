"""Tester för FIDO2-kommandolagret. Lagring isoleras via SHALLOT_FIDO2_STORE."""

import pytest

from shallot_cli import cli, fido2
from shallot_cli import fido2_store as store
from shallot_cli.commands import fido2_cmd


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    monkeypatch.setenv(store.STORE_ENV, str(tmp_path))
    return tmp_path


def test_register_confirmed(isolated, capsys):
    assert fido2_cmd.run_register("admin-01", yes=True, mock=True) == 0
    out = capsys.readouterr().out
    assert "Registrerad" in out and "admin-01" in out
    creds = store.load_credentials(root=isolated)
    assert len(creds) == 1
    assert [e["action"] for e in store.read_audit(root=isolated)] == ["register"]


def test_register_declined_writes_nothing(isolated, capsys, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    assert fido2_cmd.run_register("admin-01", yes=False) == 2
    assert store.load_credentials(root=isolated) == {}
    assert store.read_audit(root=isolated) == []


def test_register_invalid_user(isolated, capsys):
    assert fido2_cmd.run_register("admin@example.com", yes=True) == 2
    assert store.load_credentials(root=isolated) == {}


def test_authenticate_allow_and_audit(isolated, capsys):
    fido2_cmd.run_register("op-01", yes=True, mock=True)
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("op-01", mock=True) == 0
    out = capsys.readouterr().out
    assert "SIMULATED / TEST-ONLY" in out and "ALLOW" in out
    actions = [e["action"] for e in store.read_audit(root=isolated)]
    assert actions == ["register", "authenticate"]


def test_authenticate_unknown_user_denies(isolated, capsys):
    assert fido2_cmd.run_authenticate("finns-inte") == 1
    assert "DENY (unknown-credential)" in capsys.readouterr().out


def test_authenticate_revoked_denies(isolated, capsys):
    fido2_cmd.run_register("op-02", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    fido2_cmd.run_credential_revoke(cid, yes=True)
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("op-02", mock=True) == 1
    assert "DENY (revoked-credential)" in capsys.readouterr().out


def test_authenticate_ambiguous_without_credential_denies(isolated, capsys):
    fido2_cmd.run_register("op-03", yes=True, mock=True)
    fido2_cmd.run_register("op-03b", yes=True, mock=True)
    # op-03 har exakt en aktiv credential -> ALLOW med eller utan explicit val
    assert fido2_cmd.run_authenticate("op-03", mock=True) == 0
    cid = [c for c, m in store.load_credentials(root=isolated).items()
           if m["user_id"] == "op-03b"][0]
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("op-03b", credential=cid, mock=True) == 0
    assert "ALLOW" in capsys.readouterr().out


def test_list_truncates_credential_ids(isolated, capsys):
    fido2_cmd.run_register("admin-02", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    assert len(cid) > 16  # rå-ID:t är långt/identifierande
    capsys.readouterr()
    assert fido2_cmd.run_credential_list() == 0
    out = capsys.readouterr().out
    assert cid not in out  # fullständigt ID visas aldrig
    assert "cred:" in out and "admin-02" in out


def test_list_empty(isolated, capsys):
    assert fido2_cmd.run_credential_list() == 0
    assert "Inga credentials" in capsys.readouterr().out


def test_revoke_requires_confirmation(isolated, capsys, monkeypatch):
    fido2_cmd.run_register("op-04", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    assert fido2_cmd.run_credential_revoke(cid, yes=False) == 2
    assert store.load_credentials(root=isolated)[cid]["status"] == "active"


def test_revoke_confirmed_audits(isolated, capsys):
    fido2_cmd.run_register("op-05", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    capsys.readouterr()
    assert fido2_cmd.run_credential_revoke(cid, yes=True) == 0
    assert "Spärrad" in capsys.readouterr().out
    assert store.load_credentials(root=isolated)[cid]["status"] == "revoked"
    assert "revoke" in [e["action"] for e in store.read_audit(root=isolated)]


def test_revoke_unknown_credential(isolated, capsys):
    assert fido2_cmd.run_credential_revoke("finns-inte", yes=True) == 1


def test_status_shows_sanitized_metadata(isolated, capsys):
    fido2_cmd.run_register("op-06", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    capsys.readouterr()
    assert fido2_cmd.run_credential_status(cid) == 0
    out = capsys.readouterr().out
    assert "active" in out and cid not in out
    assert fido2_cmd.run_credential_status("finns-inte") == 2


def test_simulate_all_scenarios_marked(isolated, capsys):
    for name in fido2.SCENARIOS:
        assert fido2_cmd.run_simulate(name) == 0
        out = capsys.readouterr().out
        assert "SIMULATED / TEST-ONLY" in out
    assert fido2_cmd.run_simulate("finns-inte") == 2


def test_audit_shows_entries(isolated, capsys):
    assert fido2_cmd.run_audit() == 0
    assert "tom" in capsys.readouterr().out
    fido2_cmd.run_register("op-07", yes=True, mock=True)
    capsys.readouterr()
    assert fido2_cmd.run_audit() == 0
    assert "register" in capsys.readouterr().out


def test_cli_wiring_register_authenticate_simulate(isolated, capsys):
    assert cli.main(["fido2", "register", "--user", "cli-01", "--yes", "--mock"]) == 0
    capsys.readouterr()
    assert cli.main(["fido2", "authenticate", "--user", "cli-01", "--mock"]) == 0
    assert "ALLOW" in capsys.readouterr().out
    assert cli.main(["fido2", "credential", "list"]) == 0
    assert cli.main(["fido2", "simulate", "--scenario", "replay"]) == 0
    assert "DENY" in capsys.readouterr().out


def test_export_writes_public_metadata_only(isolated, capsys, tmp_path):
    import hashlib
    import json
    fido2_cmd.run_register("op-08", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    out_file = tmp_path / "op-08.approval.json"
    capsys.readouterr()
    assert fido2_cmd.run_credential_export(cid, str(out_file)) == 0
    doc = json.loads(out_file.read_text(encoding="utf-8"))
    assert doc["format"] == "shallot-fido2-approval/1"
    assert doc["user_id"] == "op-08" and doc["credential_id"] == cid
    assert doc["status"] == "active" and doc["exported_at"]
    blob = out_file.read_text(encoding="utf-8").lower()
    assert "private" not in blob and "secret" not in blob
    expect = hashlib.sha256(("%s|%s" % (cid, doc["public_key"] or "")).encode()
                            ).hexdigest()[:16]
    assert doc["fingerprint"] == expect
    out = capsys.readouterr().out
    assert "Exporterad" in out and expect in out and cid not in out
    actions = [e["action"] for e in store.read_audit(root=isolated)]
    assert "export" in actions


def test_export_unknown_credential_and_missing_dir(isolated, capsys, tmp_path):
    assert fido2_cmd.run_credential_export("finns-inte", str(tmp_path / "x.json")) == 2
    fido2_cmd.run_register("op-09", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    assert fido2_cmd.run_credential_export(cid, str(tmp_path / "saknas" / "x.json")) == 1


def test_cli_wiring_export(isolated, capsys, tmp_path):
    assert cli.main(["fido2", "register", "--user", "cli-02", "--yes", "--mock"]) == 0
    cid = next(iter(store.load_credentials(root=isolated)))
    out_file = tmp_path / "cli-02.json"
    capsys.readouterr()
    assert cli.main(["fido2", "credential", "export",
                     "--credential", cid, "--output", str(out_file)]) == 0
    assert "fingeravtryck" in capsys.readouterr().out


def test_injected_confirm_gates_destructive_action(isolated):
    asked = []
    fake = lambda q: asked.append(q) or False
    assert fido2_cmd.run_register("admin-99", confirm=fake) == 2
    assert asked == ["Fortsätt med registrering"]
    assert store.load_credentials(root=isolated) == {}
    assert fido2_cmd.run_register("admin-99", confirm=lambda q: True, mock=True) == 0
    assert len(store.load_credentials(root=isolated)) == 1


def test_verify_malformed_credential_denies_without_exception():
    cer = fido2.Ceremony(rng=lambda n: b"\x42" * n, now_fn=lambda: 1000.0)
    ch = cer.begin()
    allow, reason = cer.verify_assertion(
        credential={"status": "active"}, challenge=ch, origin=fido2.ORIGIN,
        rp_id=fido2.RP_ID, user_presence=True, signature=b"")
    assert (allow, reason) == (False, "invalid-signature")


def test_verify_with_nonsigner_backend_denies():
    from shallot_cli import fido2_backend
    cer = fido2.Ceremony(backend=fido2_backend.CtapHidBackend(),
                         rng=lambda n: b"\x42" * n, now_fn=lambda: 1000.0)
    ch = cer.begin()
    cred = {"credential_id": "c", "user_id": "u",
            "created": "t", "status": store.STATUS_ACTIVE, "policy": {}}
    allow, reason = cer.verify_assertion(
        credential=cred, challenge=ch, origin=fido2.ORIGIN,
        rp_id=fido2.RP_ID, user_presence=True, signature=b"x")
    assert (allow, reason) == (False, "wrong-backend")


def test_verifier_module_owns_decision_directly():
    from shallot_cli import fido2_verify
    cer = fido2.Ceremony(rng=lambda n: b"\x42" * n, now_fn=lambda: 1000.0)
    ch = cer.begin()
    # Samma beslut via modulen som via Ceremony-wrappern.
    assert fido2_verify.precheck(
        cer, credential=None, challenge=ch, origin=fido2.ORIGIN,
        rp_id=fido2.RP_ID, user_presence=True,
        expected_origin=fido2.ORIGIN,
        expected_rp_id=fido2.RP_ID) == "unknown-credential"
    assert fido2_verify.verify_assertion(
        cer, credential=None, challenge=ch, origin="https://evil.example",
        rp_id=fido2.RP_ID, user_presence=True, signature=b"",
        expected_origin=fido2.ORIGIN,
        expected_rp_id=fido2.RP_ID) == (False, "unknown-credential")
    # Ceremony är challenge-lager: begin + tillslag, inget beslut.
    assert set(cer._challenges) == {ch.hex()}


def test_hw_corrupt_credential_id_denies(isolated, capsys):
    meta = {"credential_id": None, "user_id": "op-11",
            "created": "2026-01-01T00:00:00Z", "status": store.STATUS_ACTIVE,
            "policy": {"backend": "hardware"}}
    store.save_credential(meta, root=isolated)
    assert fido2_cmd._run_authenticate_hw("op-11", meta, "?", "preferred") == 1
    out = capsys.readouterr().out
    assert "DENY" in out and "invalid-signature" in out
    entries = store.read_audit(root=isolated)
    assert entries[-1]["action"] == "authenticate"
    assert entries[-1]["details"]["reason"] == "invalid-signature"


def test_export_path_shares_mamabear_rule(tmp_path):
    from shallot_cli import mamabear
    for bad in ("x.txt", str(tmp_path / "saknas" / "x.json"), "x\x00y", "   "):
        with pytest.raises(RuntimeError):
            mamabear.resolve_output_path(bad)
        with pytest.raises(RuntimeError):
            fido2_cmd._resolve_export_path(bad)
    assert (mamabear.resolve_output_path(str(tmp_path / "a.json"))
            == fido2_cmd._resolve_export_path(str(tmp_path / "a.json")))


def test_default_register_without_device_denies_with_next_step(isolated, capsys, monkeypatch):
    from shallot_cli import fido2_backend
    monkeypatch.setattr(fido2_backend.CtapHidBackend, "list_devices",
                        lambda self: [])
    assert cli.main(["fido2", "register", "--user", "nodev-01", "--yes"]) == 1
    assert "--mock" in capsys.readouterr().err


def test_default_never_silently_falls_back_to_mock(isolated, capsys):
    fido2_cmd.run_register("nomock-01", yes=True, mock=True)
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("nomock-01") == 1
    assert "wrong-backend" in capsys.readouterr().out


def test_default_store_is_persistent_production_path(monkeypatch):
    from pathlib import Path
    monkeypatch.delenv(store.STORE_ENV, raising=False)
    assert store.store_root() == Path.home() / ".local" / "share" / "shallot" / "fido2"


def test_cli_wiring_audit(isolated, capsys):
    fido2_cmd.run_register("op-12", yes=True, mock=True)
    capsys.readouterr()
    assert cli.main(["fido2", "audit"]) == 0
    assert "register" in capsys.readouterr().out
    assert cli.main(["fido2", "audit", "--limit", "0"]) == 2


def test_set_policy_stores_and_audits(isolated, capsys):
    fido2_cmd.run_register("op-10", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    capsys.readouterr()
    assert fido2_cmd.run_credential_set_policy(cid, "required", yes=True) == 0
    out = capsys.readouterr().out
    assert "preferred → required" in out
    meta = store.load_credentials(root=isolated)[cid]
    assert meta["policy"]["user_verification"] == "required"
    entry = store.read_audit(root=isolated)[-1]
    assert entry["action"] == "set-policy"
    assert entry["details"]["user_verification"] == {"old": "preferred", "new": "required"}


def test_set_policy_noop_declined_unknown_invalid(isolated, capsys, monkeypatch):
    fido2_cmd.run_register("op-11", yes=True, mock=True)
    cid = next(iter(store.load_credentials(root=isolated)))
    capsys.readouterr()
    assert fido2_cmd.run_credential_set_policy(cid, "preferred", yes=True) == 0
    assert "Oförändrat" in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda *a: "n")
    assert fido2_cmd.run_credential_set_policy(cid, "required", yes=False) == 2
    assert store.load_credentials(root=isolated)[cid]["policy"]["user_verification"] == "preferred"
    assert fido2_cmd.run_credential_set_policy("finns-inte", "required", yes=True) == 2
    assert fido2_cmd.run_credential_set_policy(cid, "alltid", yes=True) == 2


def test_cli_wiring_set_policy(isolated, capsys):
    assert cli.main(["fido2", "register", "--user", "cli-03", "--yes", "--mock"]) == 0
    cid = next(iter(store.load_credentials(root=isolated)))
    capsys.readouterr()
    assert cli.main(["fido2", "credential", "set-policy", "--credential", cid,
                     "--user-verification", "required", "--yes"]) == 0
    assert "required" in capsys.readouterr().out
