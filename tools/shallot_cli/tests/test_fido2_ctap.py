"""Tester för HW-läget (CTAP2). Ingen fysisk enhet — CTAP-lagret mockas,
RP-verifieringen körs mot riktiga lib-byggda testvektorer."""

import base64
import hashlib
import json

import pytest

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from shallot_cli import fido2, fido2_backend, fido2_store
from shallot_cli.commands import fido2_cmd

RP_ID = fido2.RP_ID
ORIGIN = fido2.ORIGIN


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def _keypair():
    from fido2.cose import ES256
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, ES256.from_cryptography_key(priv.public_key())


def _client_data_json(kind: str, challenge: bytes, origin: str = ORIGIN) -> bytes:
    return json.dumps({"type": kind, "challenge": b64url(challenge),
                       "origin": origin}).encode()


def _attestation(priv, cose, challenge: bytes, rp_id: str = RP_ID,
                 origin: str = ORIGIN, fmt: str = "packed", counter: int = 0,
                 up: bool = True, cred_id: bytes = b"hw-cred-id-1234",
                 tamper_sig: bool = False, x5c: bool = False) -> tuple:
    from fido2.webauthn import (AttestationObject, AttestedCredentialData,
                                AuthenticatorData)
    flags = 0
    if up:
        flags |= AuthenticatorData.FLAG.UP
    flags |= AuthenticatorData.FLAG.AT
    auth_data = AuthenticatorData.create(
        hashlib.sha256(rp_id.encode()).digest(), flags, counter,
        credential_data=bytes(AttestedCredentialData.create(
            b"\x00" * 16, cred_id, cose)))
    client_data = _client_data_json("webauthn.create", challenge, origin)
    if fmt == "none":
        stmt = {}
    else:
        sig = priv.sign(bytes(auth_data) + hashlib.sha256(client_data).digest(),
                        ec.ECDSA(hashes.SHA256()))
        if tamper_sig:
            sig = bytearray(sig)
            sig[0] ^= 0xFF
            sig = bytes(sig)
        stmt = {"alg": -7, "sig": sig}
        if x5c:
            stmt["x5c"] = [b"junk-inte-ett-cert"]
    return bytes(AttestationObject.create(fmt, auth_data, stmt)), client_data


def make_hw_credential(challenge: bytes = b"\x11" * 32, counter: int = 7):
    """Registrera på riktigt mot en testvektor. Returnerar (priv, metadata)."""
    priv, cose = _keypair()
    att_obj, client_data = _attestation(priv, cose, challenge, counter=counter)
    cred = fido2.verify_hw_registration(
        attestation_object=att_obj, client_data_json=client_data,
        challenge=challenge, rp_id=RP_ID, origin=ORIGIN)
    meta = {"credential_id": cred["credential_id"], "user_id": "hw-admin",
            "created": fido2_store.utcnow(), "status": fido2_store.STATUS_ACTIVE,
            "policy": {"user_presence": True, "rp_id": RP_ID, "origin": ORIGIN,
                       "backend": "hardware", "mode": "hardware-ctap",
                       "attestation": cred["attestation_fmt"]},
            "public_key": cred["public_key_cose"],
            "sign_count": cred["sign_count"]}
    return priv, meta


def _assertion(priv, challenge: bytes, rp_id: str = RP_ID,
               origin: str = ORIGIN, counter: int = 8, uv: bool = False) -> tuple:
    flags = _auth_flags(uv)
    auth_data = _auth_data_full(rp_id, counter, flags)
    client_data = _client_data_json("webauthn.get", challenge, origin)
    sig = priv.sign(bytes(auth_data) + hashlib.sha256(client_data).digest(),
                    ec.ECDSA(hashes.SHA256()))
    return bytes(auth_data), client_data, sig


def _auth_flags(uv: bool):
    from fido2.webauthn import AuthenticatorData
    return AuthenticatorData.FLAG.UP | (AuthenticatorData.FLAG.UV if uv else 0)


def _auth_data_full(rp_id: str, counter: int, flags) -> bytes:
    from fido2.webauthn import AuthenticatorData
    return bytes(AuthenticatorData.create(hashlib.sha256(rp_id.encode()).digest(),
                                          flags, counter))


# --- RP-verifiering: registrering -------------------------------------------

def test_hw_registration_packed_self_ok():
    priv, cose = _keypair()
    ch = b"\x11" * 32
    att_obj, client_data = _attestation(priv, cose, ch, counter=7)
    cred = fido2.verify_hw_registration(
        attestation_object=att_obj, client_data_json=client_data,
        challenge=ch, rp_id=RP_ID, origin=ORIGIN)
    assert cred["attestation_fmt"] == "packed-self"
    assert cred["sign_count"] == 7
    assert cred["credential_id"] == b64url(b"hw-cred-id-1234")


def test_hw_registration_none_ok():
    priv, cose = _keypair()
    ch = b"\x11" * 32
    att_obj, client_data = _attestation(priv, cose, ch, fmt="none")
    cred = fido2.verify_hw_registration(
        attestation_object=att_obj, client_data_json=client_data,
        challenge=ch, rp_id=RP_ID, origin=ORIGIN)
    assert cred["attestation_fmt"] == "none"


def test_hw_registration_rejects_untrusted():
    priv, cose = _keypair()
    ch = b"\x11" * 32
    cases = []
    att, cd = _attestation(priv, cose, ch, x5c=True)
    cases.append((att, cd, ch))  # packed med x5c, inga trust anchors
    att, cd = _attestation(priv, cose, ch, tamper_sig=True)
    cases.append((att, cd, ch))  # manipulerad attesteringssignatur
    att, cd = _attestation(priv, cose, ch)
    cases.append((att, cd, b"\x99" * 32))  # fel challenge
    att, cd = _attestation(priv, cose, ch, rp_id="evil.example")
    cases.append((att, cd, ch))  # fel rp
    att, cd = _attestation(priv, cose, ch, origin="https://evil.example")
    cases.append((att, cd, ch))  # fel origin
    att, cd = _attestation(priv, cose, ch, up=False)
    cases.append((att, cd, ch))  # ingen user presence
    for att_obj, client_data, challenge in cases:
        with pytest.raises(ValueError, match="untrusted-attestation|no-user-presence"):
            fido2.verify_hw_registration(
                attestation_object=att_obj, client_data_json=client_data,
                challenge=challenge, rp_id=RP_ID, origin=ORIGIN)


def test_hw_registration_rejects_unknown_fmt():
    from fido2.webauthn import (AttestationObject, AttestedCredentialData,
                                AuthenticatorData)
    priv, cose = _keypair()
    ch = b"\x11" * 32
    auth_data = AuthenticatorData.create(
        hashlib.sha256(RP_ID.encode()).digest(),
        AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, 0,
        credential_data=bytes(AttestedCredentialData.create(
            b"\x00" * 16, b"cid", cose)))
    client_data = _client_data_json("webauthn.create", ch)
    att_obj = bytes(AttestationObject.create("android-key", auth_data, {}))
    with pytest.raises(ValueError, match="untrusted-attestation"):
        fido2.verify_hw_registration(
            attestation_object=att_obj, client_data_json=client_data,
            challenge=ch, rp_id=RP_ID, origin=ORIGIN)


# --- RP-verifiering: assertion ----------------------------------------------

def _ceremony():
    return fido2.Ceremony(rng=lambda n: b"\x22" * n, now_fn=lambda: 500.0)


def test_hw_assertion_success_and_counter():
    priv, meta = make_hw_credential(counter=7)
    cer = _ceremony()
    ch = cer.begin()
    auth_data, client_data, sig = _assertion(priv, ch, counter=9)
    allow, reason, new_count = fido2.verify_hw_assertion(
        credential=meta, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data, client_data_json=client_data,
        signature=sig, ceremony=cer)
    assert (allow, reason, new_count) == (True, "ok", 9)


def test_hw_assertion_clone_detected():
    priv, meta = make_hw_credential(counter=7)
    meta["sign_count"] = 10
    cer = _ceremony()
    ch = cer.begin()
    auth_data, client_data, sig = _assertion(priv, ch, counter=9)
    allow, reason, new_count = fido2.verify_hw_assertion(
        credential=meta, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data, client_data_json=client_data,
        signature=sig, ceremony=cer)
    assert (allow, reason, new_count) == (False, "clone-detected", None)


def test_hw_assertion_zero_counter_accepted_without_clone_detection():
    priv, meta = make_hw_credential(counter=0)
    meta["sign_count"] = 0
    cer = _ceremony()
    ch = cer.begin()
    auth_data, client_data, sig = _assertion(priv, ch, counter=0)
    allow, reason, new_count = fido2.verify_hw_assertion(
        credential=meta, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data, client_data_json=client_data,
        signature=sig, ceremony=cer)
    assert (allow, reason, new_count) == (True, "ok", 0)


def test_hw_assertion_rejects_bad_signature_and_rp():
    priv, meta = make_hw_credential()
    other, _ = _keypair()
    cer = _ceremony()
    ch = cer.begin()
    auth_data, client_data, _ = _assertion(other, ch)
    allow, reason, _ = fido2.verify_hw_assertion(
        credential=meta, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data, client_data_json=client_data,
        signature=b"\x00" * 64, ceremony=cer)
    assert (allow, reason) == (False, "invalid-signature")
    # Authenticator-data från annat RP avvisas
    cer2 = _ceremony()
    ch2 = cer2.begin()
    auth_data2, client_data2, sig2 = _assertion(priv, ch2, rp_id="evil.example")
    allow, reason, _ = fido2.verify_hw_assertion(
        credential=meta, challenge=ch2, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data2, client_data_json=client_data2,
        signature=sig2, ceremony=cer2)
    assert (allow, reason) == (False, "invalid-signature")


def test_hw_assertion_replay_and_revoked():
    priv, meta = make_hw_credential()
    cer = _ceremony()
    ch = cer.begin()
    auth_data, client_data, sig = _assertion(priv, ch)
    kw = dict(credential=meta, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
              authenticator_data=auth_data, client_data_json=client_data,
              signature=sig, ceremony=cer)
    assert fido2.verify_hw_assertion(**kw)[0] is True
    assert fido2.verify_hw_assertion(**kw)[1] == "replay"
    meta_revoked = dict(meta, status=fido2_store.STATUS_REVOKED)
    cer2 = _ceremony()
    ch2 = cer2.begin()
    auth_data2, client_data2, sig2 = _assertion(priv, ch2)
    allow, reason, _ = fido2.verify_hw_assertion(
        credential=meta_revoked, challenge=ch2, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data2, client_data_json=client_data2,
        signature=sig2, ceremony=cer2)
    assert (allow, reason) == (False, "revoked-credential")


# --- Backend: ingen USB i konstruktor, tydliga fel --------------------------

def test_ctap_backend_touches_no_usb_on_construct():
    be = fido2_backend.CtapHidBackend()
    assert be.name == "hardware"
    assert not hasattr(be, "sign") and not hasattr(be, "verify")


def test_ctap_backend_no_device_fails_closed():
    be = fido2_backend.CtapHidBackend(device_finder=lambda: None)
    with pytest.raises(fido2_backend.DeviceNotFound):
        be.register(origin=ORIGIN, rp_id=RP_ID, rp_name="T",
                    user_id="u", challenge=b"\x00" * 32)
    with pytest.raises(fido2_backend.DeviceNotFound):
        be.authenticate(origin=ORIGIN, rp_id=RP_ID, challenge=b"\x00" * 32,
                        credential_id=b"cid")


def test_ctap_backend_maps_pin_and_timeout_errors():
    from fido2.client import ClientError
    from fido2.ctap import CtapError

    def client_error(ctap_code):
        return ClientError(ClientError.ERR.BAD_REQUEST,
                           CtapError(ctap_code))

    seen = {}

    class FakeClient:
        def make_credential(self, options):
            seen["options"] = options
            raise client_error(CtapError.ERR.PIN_BLOCKED)

        def get_assertion(self, options):
            raise client_error(CtapError.ERR.ACTION_TIMEOUT)

    be = fido2_backend.CtapHidBackend(
        device_finder=lambda: object(),
        client_factory=lambda dev: FakeClient())
    with pytest.raises(fido2_backend.DeviceError, match="spärrad"):
        be.register(origin=ORIGIN, rp_id=RP_ID, rp_name="T",
                    user_id="u", challenge=b"\x00" * 32)
    with pytest.raises(fido2_backend.DeviceError, match="i tid"):
        be.authenticate(origin=ORIGIN, rp_id=RP_ID, challenge=b"\x00" * 32,
                        credential_id=b"cid")


def test_ctap_backend_missing_package_gives_install_hint(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "fido2.hid", None)
    be = fido2_backend.CtapHidBackend()
    with pytest.raises(RuntimeError, match="pip install"):
        be.list_devices()


def test_ctap_backend_unwraps_lib_response_objects():
    """Regressionstest: libbens svarsaccessor (attribut, inte dict-index)."""
    from types import SimpleNamespace
    att_obj = b"fake-attestation-object"
    client_data = b'{"type":"webauthn.create"}'
    auth_data = b"fake-authenticator-data"
    sig = b"fake-signature"

    class FakeClient:
        def make_credential(self, options):
            return SimpleNamespace(response=SimpleNamespace(
                attestation_object=att_obj, client_data=client_data))

        def get_assertion(self, options):
            inner = SimpleNamespace(
                authenticator_data=auth_data, client_data=client_data,
                signature=sig)
            selection = SimpleNamespace(
                get_response=lambda index: SimpleNamespace(response=inner))
            return selection

    be = fido2_backend.CtapHidBackend(
        device_finder=lambda: object(),
        client_factory=lambda dev: FakeClient())
    reg = be.register(origin=ORIGIN, rp_id=RP_ID, rp_name="T",
                      user_id="u", challenge=b"\x00" * 32)
    assert reg == {"attestation_object": att_obj, "client_data_json": client_data}
    auth = be.authenticate(origin=ORIGIN, rp_id=RP_ID, challenge=b"\x00" * 32,
                           credential_id=b"cid")
    assert auth == {"authenticator_data": auth_data, "client_data_json": client_data,
                    "signature": sig}


def test_factory_hardware_returns_ctap():
    assert isinstance(fido2_backend.get_backend("hardware"), fido2_backend.CtapHidBackend)


# --- Kommandolager: fysisk default, explicit --mock ---------------------------

class FakeCtap:
    """Fejkad enhet: svarar med riktiga testvektorer, rör aldrig USB."""

    def __init__(self, priv, cose, counter=7, error=None):
        self.priv = priv
        self.cose = cose
        self.counter = counter
        self.error = error
        self.calls = []

    def register(self, **kw):
        self.calls.append(("register", kw))
        if self.error:
            raise self.error
        ch = kw["challenge"]
        att_obj, client_data = _attestation(
            self.priv, self.cose, ch, counter=self.counter)
        return {"attestation_object": att_obj, "client_data_json": client_data}

    def authenticate(self, **kw):
        self.calls.append(("authenticate", kw))
        if self.error:
            raise self.error
        ch = kw["challenge"]
        auth_data, client_data, sig = _assertion(self.priv, ch, counter=self.counter + 1)
        return {"authenticator_data": auth_data, "client_data_json": client_data,
                "signature": sig}


@pytest.fixture
def hw_isolated(tmp_path, monkeypatch):
    import shallot_cli.fido2_store as store
    monkeypatch.setenv(store.STORE_ENV, str(tmp_path))
    return tmp_path


def test_register_hw_stores_pubkey_and_counter(hw_isolated, capsys, monkeypatch):
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose, counter=7)
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    assert fido2_cmd.run_register("hw-01", yes=True) == 0
    out = capsys.readouterr().out
    assert "HARDWARE" in out and "SIMULATED" not in out
    import shallot_cli.fido2_store as store
    creds = store.load_credentials(root=hw_isolated)
    assert len(creds) == 1
    meta = next(iter(creds.values()))
    assert meta["policy"]["backend"] == "hardware"
    assert meta["sign_count"] == 7 and meta["public_key"]
    assert any(e["action"] == "register" and e["details"].get("backend") == "hardware"
               for e in store.read_audit(root=hw_isolated))


def test_authenticate_hw_allow_updates_counter(hw_isolated, capsys, monkeypatch):
    import shallot_cli.fido2_store as store
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose, counter=7)
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    assert fido2_cmd.run_register("hw-02", yes=True) == 0
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("hw-02") == 0
    out = capsys.readouterr().out
    assert "ALLOW" in out and "sign_count=8" in out
    meta = next(iter(store.load_credentials(root=hw_isolated).values()))
    assert meta["sign_count"] == 8


def test_stored_uv_policy_enforced_on_hw(hw_isolated, capsys, monkeypatch):
    import shallot_cli.fido2_store as store
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose, counter=7)  # UP-only, ingen UV-flagg
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    assert fido2_cmd.run_register("hw-uv", yes=True) == 0
    cid = next(iter(store.load_credentials(root=hw_isolated)))
    assert fido2_cmd.run_credential_set_policy(cid, "required", yes=True) == 0
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("hw-uv") == 1
    assert "no-user-verification" in capsys.readouterr().out


def test_authenticate_hw_no_device_denies(hw_isolated, capsys, monkeypatch):
    import shallot_cli.fido2_store as store
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose)
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    fido2_cmd.run_register("hw-03", yes=True)
    capsys.readouterr()
    gone = FakeCtap(priv, cose, error=fido2_backend.DeviceNotFound("borta"))
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: gone)
    assert fido2_cmd.run_authenticate("hw-03") == 1
    assert "DENY (device-error)" in capsys.readouterr().out


def test_wrong_backend_denies_both_directions(hw_isolated, capsys, monkeypatch):
    import shallot_cli.fido2_store as store
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose)
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    fido2_cmd.run_register("hw-04", yes=True)
    fido2_cmd.run_register("mock-04", yes=True, mock=True)
    capsys.readouterr()
    assert fido2_cmd.run_authenticate("hw-04", mock=True) == 1
    assert "wrong-backend" in capsys.readouterr().out
    assert fido2_cmd.run_authenticate("mock-04") == 1
    assert "wrong-backend" in capsys.readouterr().out
    reasons = [e["details"].get("reason") for e in store.read_audit(root=hw_isolated)
               if e["action"] == "authenticate"]
    assert reasons.count("wrong-backend") == 2
    assert not any(call[0] == "authenticate" for call in fake.calls)


def test_wrong_backend_denies_before_ctap_access(hw_isolated, capsys, monkeypatch):
    fido2_cmd.run_register("mock-05", yes=True, mock=True)
    capsys.readouterr()

    class ForbiddenCtap:
        def __init__(self):
            raise AssertionError("CTAP must not be opened for a mock credential")

    monkeypatch.setattr(fido2_backend, "CtapHidBackend", ForbiddenCtap)
    assert fido2_cmd.run_authenticate("mock-05") == 1
    assert "wrong-backend" in capsys.readouterr().out


def test_cli_hardware_is_default_and_mock_is_explicit(hw_isolated, capsys, monkeypatch):
    from shallot_cli import cli
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose)
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    # Fysisk är default — ingen flagga behövs.
    assert cli.main(["fido2", "register", "--user", "hw-cli", "--yes"]) == 0
    capsys.readouterr()
    assert cli.main(["fido2", "authenticate", "--user", "hw-cli"]) == 0
    out = capsys.readouterr().out
    assert "ALLOW" in out and "SIMULATED" not in out


def test_cli_mock_flag_wiring(hw_isolated, capsys):
    from shallot_cli import cli
    assert cli.main(["fido2", "register", "--user", "mock-cli",
                     "--yes", "--mock"]) == 0
    out = capsys.readouterr().out
    assert "SIMULATED / TEST-ONLY" in out
    assert cli.main(["fido2", "authenticate", "--user", "mock-cli",
                     "--mock"]) == 0
    assert "ALLOW" in capsys.readouterr().out


def test_device_list_shows_and_empty(capsys, monkeypatch):
    from shallot_cli import cli

    class FakeBackend:
        def __init__(self, infos):
            self._infos = infos

        def describe_devices(self):
            return self._infos

    monkeypatch.setattr(fido2_backend, "CtapHidBackend",
                        lambda: FakeBackend([{"product": "Pico Fido",
                                              "serial": "ABC123", "version": "2.3"}]))
    assert cli.main(["fido2", "device", "list"]) == 0
    out = capsys.readouterr().out
    assert "Pico Fido" in out and "ABC123" in out
    monkeypatch.setattr(fido2_backend, "CtapHidBackend",
                        lambda: FakeBackend([]))
    assert cli.main(["fido2", "device", "list"]) == 0
    assert "Inga FIDO2-authenticators" in capsys.readouterr().out


def test_device_list_backend_error_exits_1(capsys, monkeypatch):
    from shallot_cli import cli

    class FakeBackend:
        def describe_devices(self):
            raise fido2_backend.DeviceError("trasig USB")

    monkeypatch.setattr(fido2_backend, "CtapHidBackend", FakeBackend)
    assert cli.main(["fido2", "device", "list"]) == 1
    assert "trasig USB" in capsys.readouterr().err


# --- UV-krav (user verification) --------------------------------------------

def test_hw_assertion_uv_required_enforced():
    priv, meta = make_hw_credential()
    # Utan UV-flagg + krav → DENY
    cer = _ceremony()
    ch = cer.begin()
    auth_data, client_data, sig = _assertion(priv, ch, uv=False)
    allow, reason, _ = fido2.verify_hw_assertion(
        credential=meta, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data, client_data_json=client_data,
        signature=sig, ceremony=cer, require_uv=True)
    assert (allow, reason) == (False, "no-user-verification")
    # Med UV-flagg + krav → ALLOW
    cer2 = _ceremony()
    ch2 = cer2.begin()
    auth_data2, client_data2, sig2 = _assertion(priv, ch2, uv=True)
    allow, reason, _ = fido2.verify_hw_assertion(
        credential=meta, challenge=ch2, origin=ORIGIN, rp_id=RP_ID,
        authenticator_data=auth_data2, client_data_json=client_data2,
        signature=sig2, ceremony=cer2, require_uv=True)
    assert (allow, reason) == (True, "ok")


def test_stored_uv_policy_enforced_without_flag(hw_isolated, capsys, monkeypatch):
    import shallot_cli.fido2_store as store
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose)  # UP-only assertions, ingen UV-flagg
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    assert fido2_cmd.run_register("hw-uv", yes=True,
                                  require_uv=True) == 0
    meta = next(iter(store.load_credentials(root=hw_isolated).values()))
    assert meta["policy"]["user_verification"] == "required"
    capsys.readouterr()
    # Lagrad policy slår igenom även utan flagga
    assert fido2_cmd.run_authenticate("hw-uv") == 1
    assert "no-user-verification" in capsys.readouterr().out


def test_mock_uv_requirement_and_invalid_policy(hw_isolated):
    cer = fido2.Ceremony(rng=lambda n: b"\x22" * n, now_fn=lambda: 500.0)
    cred = {"credential_id": "abc", "status": fido2_store.STATUS_ACTIVE}
    ch = cer.begin()
    sig = cer.backend.sign(credential_id=b"abc",
                           signed_data=fido2.signed_data(ch, ORIGIN, RP_ID, True))
    allow, reason = cer.verify_assertion(
        credential=cred, challenge=ch, origin=ORIGIN, rp_id=RP_ID,
        user_presence=True, signature=sig,
        user_verified=False, require_uv=True)
    assert (allow, reason) == (False, "no-user-verification")
    with pytest.raises(ValueError, match="UV-policy"):
        fido2.register_user("x", rng=lambda n: b"\x01" * n,
                            root=hw_isolated, user_verification="alltid")


def test_cli_require_uv_flag_stores_policy(hw_isolated, capsys, monkeypatch):
    from shallot_cli import cli
    import shallot_cli.fido2_store as store
    priv, cose = _keypair()
    fake = FakeCtap(priv, cose)
    monkeypatch.setattr(fido2_backend, "CtapHidBackend", lambda: fake)
    assert cli.main(["fido2", "register", "--user", "uv-cli",
                     "--yes", "--require-uv"]) == 0
    meta = next(iter(store.load_credentials(root=hw_isolated).values()))
    assert meta["policy"]["user_verification"] == "required"
    capsys.readouterr()
    # Fake-enheten är UP-only: lagrad required-policy nekar utan UV-flagg.
    assert cli.main(["fido2", "authenticate", "--user", "uv-cli"]) == 1
    assert "no-user-verification" in capsys.readouterr().out


def test_prompt_pin_hint_and_cancel(monkeypatch, capsys):
    import getpass
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: "1234")
    assert fido2_backend._prompt_pin("shallot.local") == "1234"
    out = capsys.readouterr().out
    assert "ingen PIN" in out and "spärra" in out
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: "")
    assert fido2_backend._prompt_pin("shallot.local") is None
    monkeypatch.setattr(getpass, "getpass", lambda *a, **k: (_ for _ in ()).throw(EOFError))
    assert fido2_backend._prompt_pin("shallot.local") is None
