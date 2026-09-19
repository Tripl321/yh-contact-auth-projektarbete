"""
PRO-98 DEN enforcement: active PAW blocklist with fail-closed deny.

Focused session tests for the revocation gate in den_on_response
(HMAC ok -> blocklist gate -> grant/deny). Mirrors firmware order:
deny on blocked fingerprint, deny on unknown revocation status
(missing/invalid list), grant only for unlisted fingerprint under a
valid list (deny-list semantics; the "unknown" in the requirement is
the status, not the fingerprint — see docs/17).

Crypto acceptance itself (Ed25519 sign/verify, format, manipulated,
rollback) is pinned in tests/test_pro88_den.py; here those vectors
drive the session gate end to end. All key material below is TEST-ONLY.
"""
import hashlib
import hmac as hmac_module

import sys
sys.path.insert(0, '.')
from tests.test_pro88_den import (
    MockDenSession, K_MAC, hmac16,
    REASON_OK, REASON_HMAC_MISMATCH, REASON_BLOCKLISTED,
    BLOCKLIST_VERSION, BLOCKLIST_ISSUER, BLOCKLIST_MAX_ENTRIES,
    KEY_HASH_SIZE, BLOCKLIST_SIGNATURE_SIZE,
    TEST_ED25519_PRIVATE_KEY, TEST_ED25519_PUBLIC_KEY, TEST_BLOCKLIST_V1,
    ed25519_sign, ed25519_verify,
)
from tests.test_pro84_paw import MockPawResponder
from tests.test_pro87_uart import encode, T_CHALLENGE, T_ACK

BLOCKED_MASTER = bytes(range(16))  # test-only master; fp goes on the list
CLEAN_MASTER = bytes(range(1, 17))  # test-only master; fp stays unlisted
OTHER_ED25519_PRIVATE = bytes.fromhex(
    "9d61b19f0854a2d6457cb4c1480b9e326f8c8f7ef2869fd8f7c8f8f8f8f8f8f8"
)


def fp_of(master):
    """Mirror of SHA-256(denDevKey)[:4] (non-secret fingerprint)."""
    return hashlib.sha256(bytes(master)).digest()[:4]


def build_list(entries, priv=TEST_ED25519_PRIVATE_KEY,
               version=BLOCKLIST_VERSION, issuer=BLOCKLIST_ISSUER):
    """Build a signed raw list (mirrors UNO Q sign_blocklist layout)."""
    data = bytes([version]) + bytes(issuer) + bytes([len(entries)]) + b"".join(entries)
    return data + ed25519_sign(data, priv)


def try_install(s, raw, pubkey=TEST_ED25519_PUBLIC_KEY):
    """Mirror of process_blocklist_message acceptance: only a fully valid
    list mutates state (failures keep the previous list, like firmware)."""
    raw = bytes(raw)
    if len(raw) < 82:
        return False
    if raw[0] < BLOCKLIST_VERSION:
        return False
    if raw[1:17] != bytes(BLOCKLIST_ISSUER):
        return False
    count = raw[17]
    if count > BLOCKLIST_MAX_ENTRIES:
        return False
    need = 18 + count * KEY_HASH_SIZE + BLOCKLIST_SIGNATURE_SIZE
    if len(raw) < need:
        return False
    data = raw[:18 + count * KEY_HASH_SIZE]
    sig = raw[18 + count * KEY_HASH_SIZE:need]
    if not ed25519_verify(data, sig, pubkey):
        return False
    s.install_blocklist([data[18 + i * KEY_HASH_SIZE:22 + i * KEY_HASH_SIZE]
                         for i in range(count)])
    return True


def grant_session(master, entries):
    """Full happy-path drive: provision key + valid list, challenge, answer."""
    s = MockDenSession(master)
    assert try_install(s, build_list(entries))
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    return s, s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)


# ============================================================================
# Valid / blocked / unknown / invalid / missing
# ============================================================================

def test_pro98_valid_list_unlisted_fp_grants():
    """Giltig lista + ospärrad fingerprint -> grant (deny-list semantics)."""
    s, done = grant_session(CLEAN_MASTER, [fp_of(BLOCKED_MASTER)])
    assert done == (True, 0x01, REASON_OK)
    assert s.state == "AUTHENTICATED"
    assert s.nonce is None  # wiped after decision


def test_pro98_empty_valid_list_grants():
    """Giltig tom lista (0 poster) -> okänd fingerprint beviljas."""
    s, done = grant_session(CLEAN_MASTER, [])
    assert done == (True, 0x01, REASON_OK)


def test_pro98_blocked_fp_denied_before_grant():
    """Spärrad fingerprint -> DENIED + BLOCKLISTED, aldrig AUTHENTICATED."""
    s = MockDenSession(BLOCKED_MASTER)
    assert try_install(s, build_list([fp_of(BLOCKED_MASTER)]))
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    done = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert done == (False, 0x00, REASON_BLOCKLISTED)
    assert s.state == "DENIED"
    assert s.state != "AUTHENTICATED"
    assert s.nonce is None  # wiped like every other deny path
    assert s.log == ["FAILED:%d" % REASON_BLOCKLISTED]


def test_pro98_missing_list_denies_unknown_status():
    """Ingen distribuerad lista -> spärrstatus okänd -> deny (fail closed)."""
    s = MockDenSession(CLEAN_MASTER)
    assert s.blocklist_valid is False
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    done = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert done == (False, 0x00, REASON_BLOCKLISTED)
    assert s.state == "DENIED"


def test_pro98_invalid_signature_keeps_missing():
    """Manipulerad signatur aktiverar aldrig listan -> fortsatt deny."""
    s = MockDenSession(CLEAN_MASTER)
    bad = bytearray(TEST_BLOCKLIST_V1)
    bad[-1] ^= 0x01
    assert try_install(s, bytes(bad)) is False
    assert s.blocklist_valid is False
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    assert s.on_frame(0x02, hmac16(K_MAC, nonce), 10100) == (
        False, 0x00, REASON_BLOCKLISTED)


def test_pro98_rollback_version_rejected():
    """Version < 1 avvisas (rollback) -> fortsatt deny."""
    s = MockDenSession(CLEAN_MASTER)
    raw = build_list([], version=0)
    assert try_install(s, raw) is False
    assert s.blocklist_valid is False


def test_pro98_truncated_list_rejected():
    """Trunkerad lista aktiveras aldrig -> fortsatt deny."""
    s = MockDenSession(CLEAN_MASTER)
    assert try_install(s, TEST_BLOCKLIST_V1[:40]) is False
    assert s.blocklist_valid is False
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    assert s.on_frame(0x02, hmac16(K_MAC, nonce), 10100) == (
        False, 0x00, REASON_BLOCKLISTED)


def test_pro98_oversize_entry_count_rejected():
    """entry_count > 16 avvisas innan fler byte tolkas."""
    s = MockDenSession(CLEAN_MASTER)
    raw = build_list([b"\x00" * KEY_HASH_SIZE])
    bad = bytearray(raw)
    bad[17] = BLOCKLIST_MAX_ENTRIES + 1
    assert try_install(s, bytes(bad)) is False
    assert s.blocklist_valid is False


def test_pro98_wrong_trust_root_rejected():
    """Lista signerad under annan nyckel verifierar ej mot trust root.

    Modellerar placeholder/fel trust root: ingen lista blir giltig,
    alla sessioner nekas fail-closed."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    other_pub = Ed25519PrivateKey.from_private_bytes(
        OTHER_ED25519_PRIVATE).public_key().public_bytes_raw()
    raw = build_list([fp_of(BLOCKED_MASTER)], priv=OTHER_ED25519_PRIVATE)
    s = MockDenSession(CLEAN_MASTER)
    assert try_install(s, raw, pubkey=TEST_ED25519_PUBLIC_KEY) is False
    assert try_install(s, raw, pubkey=other_pub) is True  # ...men under sin egen rot
    assert s.blocklist_valid is True


def test_pro98_issuer_mismatch_rejected():
    """Giltig signatur under fel issuer avvisas (inte vår lista)."""
    other_issuer = b"EVIL-AUTH\x00\x00\x00\x00\x00\x00\x00"
    assert len(other_issuer) == 16
    raw = build_list([], issuer=other_issuer)
    s = MockDenSession(CLEAN_MASTER)
    assert try_install(s, raw) is False
    assert s.blocklist_valid is False


def test_pro98_precomputed_vector_installs():
    """Repo-vektorn TEST_BLOCKLIST_V1 installerar med posten deadbeef."""
    s = MockDenSession(CLEAN_MASTER)
    assert try_install(s, TEST_BLOCKLIST_V1) is True
    assert s.blocklist_valid is True
    assert s.blocklist_entries == [bytes.fromhex("deadbeef")]


def test_pro98_keeps_last_valid_on_error():
    """Misslyckad uppdatering behåller föregående giltiga lista."""
    s = MockDenSession(CLEAN_MASTER)
    assert try_install(s, build_list([])) is True
    bad = bytearray(build_list([fp_of(CLEAN_MASTER)]))
    bad[-1] ^= 0x01
    assert try_install(s, bytes(bad)) is False
    assert s.blocklist_valid is True  # last valid kept
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    assert s.on_frame(0x02, hmac16(K_MAC, nonce), 10100) == (True, 0x01, REASON_OK)
    s.clear_blocklist()  # listan tappas (t.ex. aldrig distribuerad) -> deny
    s.advance_gap(10100 + 1000 + 1)
    s.send_challenge(nonce, 20000)
    assert s.on_frame(0x02, hmac16(K_MAC, nonce), 20100) == (False, 0x00, REASON_BLOCKLISTED)


def test_pro98_bad_hmac_never_reaches_gate():
    """Fel HMAC med spärrad fingerprint ger HMAC_MISMATCH (grinden körs
    aldrig på oautentiserad input)."""
    s = MockDenSession(BLOCKED_MASTER)
    assert try_install(s, build_list([fp_of(BLOCKED_MASTER)]))
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    bad = bytearray(hmac16(K_MAC, nonce))
    bad[0] ^= 0x01
    assert s.on_frame(0x02, bytes(bad), 10100) == (False, 0x00, REASON_HMAC_MISMATCH)


def test_pro98_deny_chain_never_shows_authenticated():
    """Nekad (spärrad) session: DEN ACK 0x00 -> PAW-display FAILED, aldrig grant."""
    s = MockDenSession(BLOCKED_MASTER)
    assert try_install(s, build_list([fp_of(BLOCKED_MASTER)]))
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    done = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert done == (False, 0x00, REASON_BLOCKLISTED)
    paw = MockPawResponder(key_stored=True)
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == "authenticating"
    paw.feed(encode(T_ACK, b"\x00"), now=1100)
    assert paw.display_status == "failed"
    assert paw.display_status != "authenticated"


# ============================================================================
# Source guards: gate placement, reason code, placeholder scope
# ============================================================================

def _den_src():
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent /
            "plc/den-main/den-main.ino").read_text()


def test_pro98_source_reason_code_stable():
    """DEN_REASON_BLOCKLISTED pins kod 8 (samma som testkonstanten)."""
    src = _den_src()
    assert "DEN_REASON_BLOCKLISTED" in src
    assert REASON_BLOCKLISTED == 8
    assert 'label = "blocked"' in src


def test_pro98_source_deny_before_grant():
    """Revocation-grinden ligger efter HMAC-kontroll men före varje
    grant-artefakt (ACK 0x01-kodning, LED-tändning, AUTHENTICATED)."""
    src = _den_src()
    body = src[src.index("static void den_on_response"):]
    gate = body.index("if (!blocklist_valid)")
    for artifact in ["uint8_t ackBody[1] = {0x01}",
                     "digitalWrite(LED_BUILTIN, HIGH)",
                     "denState = DEN_ST_AUTHENTICATED",
                     'Serial.println("[DEN] AUTHENTICATED']:
        assert gate < body.index(artifact), artifact
    assert "DEN_REASON_BLOCKLISTED" in body


def test_pro98_source_fingerprint_from_master_and_wiped():
    """Fingerprint beräknas från lagrad master och rensas efter bruk."""
    src = _den_src()
    body = src[src.index("static void den_on_response"):]
    assert "shalot_sha256(denDevKey, AES_KEY_SIZE, kh)" in body
    assert "memset(kh, 0, sizeof(kh))" in body
    assert "memset(fp, 0, sizeof(fp))" in body


def test_pro98_source_issuer_checked():
    """Issuer binds mot SHALLOT-AUTH i process_blocklist_message."""
    src = _den_src()
    body = src[src.index("static uint8_t process_blocklist_message"):]
    assert "kExpectedIssuer" in body
    assert "issuerOk" in body


def test_pro98_source_trust_root_placeholder_scoped():
    """Placeholder-roten är explicit avgränsad: nollor + fail-closed-
    konsekvens dokumenterad i källan (aktivering kräver pinnad nyckel)."""
    src = _den_src()
    assert "PLACEHOLDER TRUST ROOT" in src
    assert "TEST-ONLY trust root" in src
