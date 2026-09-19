"""Tester för FIDO2-sanering: varje regel + att benign text bevaras."""

from shallot_cli import fido2_sanitize as san


def test_masks_long_credential_id():
    cid = "dGhpcyBpcyBhIHRlc3QgY3JlZGVudGlhbCBpZA123456"
    assert san.sanitize("credential %s registrerad" % cid) == \
        "credential [REDACTED-CRED] registrerad"


def test_masks_labeled_keys_and_tokens():
    dirty = 'api_key=SECRET123 token: "abc" password=hunter2 bearer TOKEN123'
    clean = san.sanitize(dirty)
    for secret in ["SECRET123", "abc", "hunter2", "TOKEN123"]:
        assert secret not in clean, secret
    assert "api_key=[REDACTED]" in clean and "bearer [REDACTED]" in clean


def test_masks_cbor_hex_payloads():
    assert san.sanitize("authData h'deadbeefcafebabe'") == "authData h'[REDACTED-HEX]'"
    assert "[REDACTED-HEX]" in san.sanitize("blob 00112233445566778899aabbccddeeff00")


def test_masks_private_addresses():
    for ip in ["10.1.2.3", "172.20.5.4", "192.168.0.10", "100.64.1.5", "127.0.0.1"]:
        assert san.sanitize("nås via " + ip) == "nås via [REDACTED-IP]", ip
    assert "[REDACTED-IP]" in san.sanitize("ll fe80::1 och loopback ::1")


def test_masks_email_but_keeps_user_ids():
    assert san.sanitize("kontakt admin@example.com") == "kontakt [REDACTED-EMAIL]"
    assert san.sanitize("användare admin-01 status active") == \
        "användare admin-01 status active"


def test_short_credential_truncates_only_long_ids():
    assert san.short_credential("kort-id") == "kort-id"
    long_id = "dGhpcyBpcyBhIHRlc3QgY3JlZGVudGlhbCBpZA123456"
    short = san.short_credential(long_id)
    assert short.startswith("cred:dGhpcyBp") and short.endswith("3456")
    assert long_id not in short


def test_benign_ceremony_output_preserved():
    benign = ("ALLOW användare admin-01 credential kort-id "
              "user_presence=True rp_id=shallot.local")
    assert san.sanitize(benign) == benign


def test_masks_mamabear_fingerprint_and_mac():
    assert "fingerprint=[REDACTED-FINGERPRINT]" in \
        san.sanitize("fingerprint=deadbeef1234")
    assert san.sanitize("mac AA:BB:CC:DD:EE:FF up") == "mac [REDACTED-MAC] up"


def test_mamabear_delegates_to_single_owner():
    import shallot_cli.mamabear as mamabear
    assert not hasattr(mamabear, "REDACTIONS")
    samples = [
        "fingerprint=deadbeef1234",
        "mac AA:BB:CC:DD:EE:FF up",
        "token=supersecretvalue12345678901234567890",
        "nås via 100.64.9.9",
        "MAMABEAR_SELFTEST_OK",
    ]
    for sample in samples:
        assert mamabear.sanitize(sample) == san.sanitize(sample), sample
