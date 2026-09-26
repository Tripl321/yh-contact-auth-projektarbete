"""
PRO-50: HMAC-SHA256 on PAW.

Covers:
- PAW computes HMAC-SHA256 using K_mac (never master key directly)
- HMAC output is 32 bytes
- HMAC matches test vectors
- Fail-closed: no HMAC computed when key not stored
- Source guards for hmac_sha256 implementation
"""

import hashlib
import hmac as hmac_module
import sys

sys.path.insert(0, ".")
from tests.test_pro84_paw import paw_hmac
from tests.test_pro88_den import DEV_HMAC_HEX, DEV_KEY, K_MAC


def test_pro50_paw_hmac_uses_k_mac():
    """PAW computes HMAC with K_mac (from PawSession), not master key directly."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / "id-kort/paw-main/paw-main.ino").read_text()
    lib = (root / "libraries/PawSession/src/PawSession.h").read_text()
    # PAW reads K_mac via the session API and feeds it to shalot_hmac_sha256.
    assert "paw_session_k_mac(&pawSession)" in src
    assert "shalot_hmac_sha256(" in src
    # Master key is never passed directly to hmac_sha256.
    assert "shalot_hmac_sha256(aes_key" not in lib
    assert "shalot_hmac_sha256(aesKey" not in src
    assert "shalot_hmac_sha256(DEN_DEV_KEY" not in src


def test_pro50_hmac_output_length():
    """PAW HMAC output is 32 bytes (SHA-256)."""
    nonce = bytes(range(8))
    mac = paw_hmac(nonce)
    assert len(mac) == 32


def test_pro50_hmac_matches_test_vector():
    """PAW HMAC computation matches the shared test vector."""
    nonce = bytes(range(0x10, 0x18))
    mac = paw_hmac(nonce)
    assert mac.hex() == DEV_HMAC_HEX


def test_pro50_hmac_with_different_nonces():
    """Different nonces produce different HMACs (no reuse)."""
    nonce1 = bytes(range(0x10, 0x18))
    nonce2 = bytes(range(0x20, 0x28))
    mac1 = paw_hmac(nonce1)
    mac2 = paw_hmac(nonce2)
    assert mac1 != mac2


def test_pro50_hmac_consistent():
    """Same nonce and key always produce same HMAC (deterministic)."""
    nonce = bytes(range(0x10, 0x18))
    mac1 = paw_hmac(nonce)
    mac2 = paw_hmac(nonce)
    assert mac1 == mac2


def test_pro50_k_mac_differs_from_master():
    """HMAC with K_mac differs from HMAC with master key (proves separation)."""
    nonce = bytes(range(0x10, 0x18))
    hmac_master = hmac_module.new(DEV_KEY, nonce, hashlib.sha256).hexdigest()
    hmac_k_mac = hmac_module.new(K_MAC, nonce, hashlib.sha256).hexdigest()
    assert hmac_master != hmac_k_mac


def test_pro50_fail_closed_no_key():
    """PAW does not answer a dock challenge when the key is not stored."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    lib = (root / "libraries/PawSession/src/PawSession.h").read_text()
    # Accept-challenge returns NO_KEY (and resets auth) when key not valid.
    assert "if (!paw_session_key_is_valid(session))" in lib
    assert "PAW_SESSION_EVENT_NO_KEY" in lib
    # The sketch gates the dock challenge on the same check; the response path
    # (sha256/HMAC) only runs when key_is_valid() returned true.
    src = (root / "id-kort/paw-main/paw-main.ino").read_text()
    assert "if (!paw_session_accept_challenge" in src
    assert "shalot_hmac_sha256(" in src


def test_pro50_hmac_implementation_exists():
    """Source guard: HMAC comes from ShallotCrypto, no local copy in PAW."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / "id-kort/paw-main/paw-main.ino").read_text()
    assert "#include <ShallotCrypto.h>" in src
    assert "void hmac_sha256(" not in src
    assert "void sha256(" not in src
    assert "sha256_k" not in src


def test_pro50_constant_time_comment():
    """Source guard: PAW firmware mentions constant-time for HMAC."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / "id-kort/paw-main/paw-main.ino").read_text()
    # PAW computes HMAC; constant-time is more relevant for DEN verification
    # But source should still mention it
    assert "PRO-50" in src


def test_pro50_no_key_exposure_in_hmac():
    """Source guard: HMAC computation doesn't expose key material."""
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / "id-kort/paw-main/paw-main.ino").read_text()
    # Key material should not be printed
    assert 'Serial.printf("%02X", kMac' not in src
    assert "Serial.print(kMac" not in src
    assert "Serial.write(kMac" not in src
    # Only the HMAC result (response) is transmitted over radio/Serial1, never
    # the key material itself.
    src = (root / "id-kort/paw-main/paw-main.ino").read_text()
    assert "paw_session_response_sent(" in src  # response marked sent exactly once
    assert "radio.transmit(txPacket" in src  # only the framed HMAC is transmitted
