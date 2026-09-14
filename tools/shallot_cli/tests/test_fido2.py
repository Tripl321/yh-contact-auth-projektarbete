"""Tester för FIDO2-ceremonier: varje scenario, regel och fail-closed-beslut."""

import pytest

from shallot_cli import fido2
from shallot_cli import fido2_store as store


def test_all_scenarios_known():
    assert set(fido2.SCENARIOS) == {"success", "unknown-credential", "revoked-credential",
                                    "wrong-origin", "replay", "timeout", "invalid-signature"}


def test_success_allows_rest_deny():
    for name in fido2.SCENARIOS:
        res = fido2.run_scenario(name)
        if name == "success":
            assert res["result"] == "ALLOW" and res["reason"] == "ok"
            assert res["decision"] == "allow"
        else:
            assert res["result"] == "DENY", name
            assert res["reason"] == name, name
            assert res["decision"] == "deny (fail closed)", name


def test_unknown_scenario_rejected():
    with pytest.raises(ValueError):
        fido2.run_scenario("lock-pick")


def test_render_always_marked_and_sanitized():
    for name in fido2.SCENARIOS:
        text = fido2.render(fido2.run_scenario(name))
        assert "SIMULATED / TEST-ONLY" in text
        assert "PAW–DEN" in text  # relationsbeskrivning till UART/HMAC


def test_user_validation_rejects_pii_and_junk():
    assert fido2.validate_user("admin-01") == "admin-01"
    for bad in ["admin@example.com", "", "a b", "../x", "x" * 65, "användare"]:
        with pytest.raises(ValueError):
            fido2.validate_user(bad)


def test_wrong_rp_id_denied():
    cer = fido2.Ceremony(rng=lambda n: b"\x07" * n, now_fn=lambda: 500.0)
    cred = {"credential_id": "abc", "status": store.STATUS_ACTIVE}
    ch = cer.begin()
    sig = cer.backend.sign(credential_id=b"abc",
                           signed_data=fido2.signed_data(ch, fido2.ORIGIN, "evil.example", True))
    allow, reason = cer.verify_assertion(credential=cred, challenge=ch, origin=fido2.ORIGIN,
                                         rp_id="evil.example", user_presence=True, signature=sig)
    assert (allow, reason) == (False, "wrong-rp-id")


def test_missing_user_presence_denied():
    cer = fido2.Ceremony(rng=lambda n: b"\x07" * n, now_fn=lambda: 500.0)
    cred = {"credential_id": "abc", "status": store.STATUS_ACTIVE}
    ch = cer.begin()
    sig = cer.backend.sign(credential_id=b"abc",
                           signed_data=fido2.signed_data(ch, fido2.ORIGIN, fido2.RP_ID, False))
    allow, reason = cer.verify_assertion(credential=cred, challenge=ch, origin=fido2.ORIGIN,
                                         rp_id=fido2.RP_ID, user_presence=False, signature=sig)
    assert (allow, reason) == (False, "no-user-presence")


def test_unknown_challenge_is_replay_deny():
    cer = fido2.Ceremony(now_fn=lambda: 500.0)
    cred = {"credential_id": "abc", "status": store.STATUS_ACTIVE}
    allow, reason = cer.verify_assertion(credential=cred, challenge=b"\x00" * 32,
                                         origin=fido2.ORIGIN, rp_id=fido2.RP_ID,
                                         user_presence=True, signature=b"\x00" * 32)
    assert (allow, reason) == (False, "replay")


def test_register_stores_metadata_only(tmp_path):
    meta = fido2.register_user("admin-01", rng=lambda n: b"\x09" * n, root=tmp_path)
    assert meta["user_id"] == "admin-01" and meta["status"] == "active"
    assert meta["policy"]["mode"] == "simulated-test"
    assert "private_key" not in meta and "secret" not in str(meta).lower()
    assert store.load_credentials(root=tmp_path)[meta["credential_id"]]["user_id"] == "admin-01"
    actions = [e["action"] for e in store.read_audit(root=tmp_path)]
    assert "register" in actions


def test_register_rejects_bad_user_and_duplicates(tmp_path):
    with pytest.raises(ValueError):
        fido2.register_user("admin@example.com", root=tmp_path)
    fido2.register_user("admin-01", rng=lambda n: b"\x09" * n, root=tmp_path)
    with pytest.raises(ValueError, match="finns redan"):
        fido2.register_user("admin-01", rng=lambda n: b"\x09" * n, root=tmp_path)


def test_registered_credential_authenticates():
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        meta = fido2.register_user("op-02", rng=lambda n: b"\x0b" * n, root=root)
        creds = store.load_credentials(root=root)
        cer = fido2.Ceremony(rng=lambda n: b"\x0c" * n, now_fn=lambda: 900.0)
        ch = cer.begin()
        sig = cer.backend.sign(
            credential_id=meta["credential_id"].encode(),
            signed_data=fido2.signed_data(ch, fido2.ORIGIN, fido2.RP_ID, True))
        allow, reason = cer.verify_assertion(
            credential=creds[meta["credential_id"]], challenge=ch,
            origin=fido2.ORIGIN, rp_id=fido2.RP_ID, user_presence=True, signature=sig)
        assert (allow, reason) == (True, "ok")


def test_approval_fingerprint_stable_and_scoped():
    fp1 = fido2.approval_fingerprint("cid-1", "cHViLWtleQ")
    assert len(fp1) == 16 and all(c in "0123456789abcdef" for c in fp1)
    assert fido2.approval_fingerprint("cid-1", "cHViLWtleQ") == fp1
    assert fido2.approval_fingerprint("cid-2", "cHViLWtleQ") != fp1
    assert fido2.approval_fingerprint("cid-1", None) != fp1
