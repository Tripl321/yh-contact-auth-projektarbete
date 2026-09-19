"""Tester för FIDO2-adapterlagret. Mocken är HMAC-baserad; ingen HW rörs."""

import pytest

from shallot_cli import fido2_backend as be


def test_mock_sign_verify_roundtrip():
    b = be.MockBackend()
    sig = b.sign(credential_id=b"cred-1", signed_data=b"challenge|origin")
    assert b.verify(credential_id=b"cred-1", signed_data=b"challenge|origin", signature=sig)


def test_mock_is_deterministic():
    b = be.MockBackend()
    assert (b.sign(credential_id=b"c", signed_data=b"d")
            == b.sign(credential_id=b"c", signed_data=b"d"))


def test_mock_rejects_tampered_signature():
    b = be.MockBackend()
    sig = bytearray(b.sign(credential_id=b"c", signed_data=b"d"))
    sig[0] ^= 0xFF
    assert not b.verify(credential_id=b"c", signed_data=b"d", signature=bytes(sig))


def test_mock_rejects_wrong_credential_and_data():
    b = be.MockBackend()
    sig = b.sign(credential_id=b"c1", signed_data=b"d")
    assert not b.verify(credential_id=b"c2", signed_data=b"d", signature=sig)
    assert not b.verify(credential_id=b"c1", signed_data=b"other", signature=sig)


def test_mock_rejects_empty_inputs():
    b = be.MockBackend()
    with pytest.raises(ValueError):
        b.sign(credential_id=b"", signed_data=b"d")
    assert not b.verify(credential_id=b"c", signed_data=b"d", signature=b"")


def test_mock_uses_constant_time_compare():
    import hmac as hmac_mod
    orig = hmac_mod.compare_digest
    calls = {"n": 0}

    def spy(a, b):
        calls["n"] += 1
        return orig(a, b)

    b = be.MockBackend()
    sig = b.sign(credential_id=b"c", signed_data=b"d")
    hmac_mod.compare_digest = spy
    try:
        assert b.verify(credential_id=b"c", signed_data=b"d", signature=sig)
    finally:
        hmac_mod.compare_digest = orig
    assert calls["n"] == 1


def test_hw_stub_refuses_server_side_signing():
    assert not hasattr(be, "HwBackend")  # död stub borttagen (steg 2)
    b = be.CtapHidBackend()
    with pytest.raises(be.DeviceError):
        b.sign(credential_id=b"c", signed_data=b"d")
    with pytest.raises(be.DeviceError):
        b.verify(credential_id=b"c", signed_data=b"d", signature=b"s")


def test_backend_implementations_are_exactly_two():
    subs = be.AuthenticatorBackend.__subclasses__()
    assert {c.__name__ for c in subs} == {"MockBackend", "CtapHidBackend"}


def test_factory_defaults_to_mock_and_rejects_unknown():
    assert isinstance(be.get_backend(), be.MockBackend)
    assert isinstance(be.get_backend("mock"), be.MockBackend)
    assert isinstance(be.get_backend("hardware"), be.CtapHidBackend)
    with pytest.raises(ValueError):
        be.get_backend("ctap")
