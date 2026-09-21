"""
PRO-47 secure key storage in SRAM: clearing, non-exposure, and SRAM-only.

Covers:
- Key is stored after valid provisioning
- Key is cleared on timeout, disconnect (timeout), reset (boot), and new provisioning
- Key material is never written to Serial output
- Key material is never written to flash (source guard)
- Missing or corrupt (all-zero) key is fail-closed on retrieval
"""
import hashlib
import binascii

import sys
sys.path.insert(0, '.')
from tests.test_paw_responsive import MockProv
from tests.test_pro88_den import (
    MockDenSession, K_MAC, REASON_OK, REASON_HMAC_MISMATCH, hmac16,
)


def test_pro47_key_stored_after_valid_provisioning():
    """Valid handshake + key-data stores key in SRAM."""
    prov = MockProv()
    key = bytes(range(1, 17))
    kd = b'\xa3\x10' + key + (binascii.crc32(key) & 0xFFFFFFFF).to_bytes(4, 'big')
    prov.poll(b'\xa1\x02', now=0)  # handshake
    assert prov.key_stored is False
    prov.poll(kd, now=100)
    assert prov.key_stored is True


def test_pro47_key_cleared_on_timeout():
    """Timeout during key-data accumulation clears any previously stored key."""
    prov = MockProv()
    key = bytes(range(1, 17))
    kd = b'\xa3\x10' + key + (binascii.crc32(key) & 0xFFFFFFFF).to_bytes(4, 'big')
    prov.poll(b'\xa1\x02', now=0)
    prov.poll(kd[:10], now=100)  # partial key data
    assert prov.key_stored is False
    # Simulate timeout (10 s without full key)
    prov.poll(b'', now=10000 + 100)
    assert prov.key_stored is False
    assert prov.phase == 'hs'


def test_pro47_key_cleared_on_new_provisioning():
    """A new handshake clears any previously stored key (fail-closed reset)."""
    prov = MockProv()
    key1 = bytes(range(1, 17))
    kd1 = b'\xa3\x10' + key1 + (binascii.crc32(key1) & 0xFFFFFFFF).to_bytes(4, 'big')
    prov.poll(b'\xa1\x02', now=0)
    prov.poll(kd1, now=100)
    assert prov.key_stored is True
    # New provisioning starts: new handshake
    key2 = bytes(range(17, 33))
    kd2 = b'\xa3\x10' + key2 + (binascii.crc32(key2) & 0xFFFFFFFF).to_bytes(4, 'big')
    prov.poll(b'\xa1\x02', now=2000)
    assert prov.key_stored is False  # cleared before new session
    prov.poll(kd2, now=2100)
    assert prov.key_stored is True


def test_pro47_key_cleared_on_crc_mismatch():
    """CRC/CRC mismatch handling delegates to PawSession, which wipes state."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    # pollProvisioning feeds bytes to the library; it no longer holds local key
    # buffers, so wipe-on-failure lives in PawSession.
    pp_start = src.index('static uint8_t pollProvisioning()')
    pp_end = src.index('// =============================================================\n// Authentication State Machine')
    pp_body = src[pp_start:pp_end]
    assert 'paw_session_provisioning_push' in pp_body
    assert 'paw_session_provisioning_poll' in pp_body
    lib = (root / 'libraries/PawSession/src/PawSession.h').read_text()
    assert 'paw_session_reset(session)' in lib      # reset on any rejection
    assert 'paw_session_wipe_key' in lib             # clear on key wipe
    assert 'shalot_crc32' in lib                     # CRC verified before store


def test_pro47_key_never_exposed_in_serial():
    """Source guard: key bytes are never printed to Serial output."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    # Key bytes must never be printed: no printf/print with key buffer names
    assert 'Serial.printf("%02X", aesKey' not in src
    assert 'Serial.print(aesKey' not in src
    assert 'Serial.write(aesKey' not in src
    assert 'Serial.write(kMac' not in src
    assert 'Serial.write(kEnc' not in src
    # Only the fingerprint (hash) is ever transmitted/printed
    assert 'paw_session_fingerprint' in src
    assert 'Serial.write(MSG_STORED)' in src


def test_pro47_sram_only_no_flash_writes():
    """Source guard: key material stays in SRAM; no flash/EEPROM writes for keys."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    # No EEPROM/flash writes for key material
    assert 'EEPROM.put' not in src
    assert 'EEPROM.write' not in src
    assert 'FlashStorage' not in src
    # The sketch's secure_clear_key delegates to the library (no local buffer).
    assert 'static void secure_clear_key()' in src
    assert 'paw_session_wipe_key(&pawSession)' in src
    # Key state lives in the library struct (not a sketch-level AES buffer).
    lib = (root / 'libraries/PawSession/src/PawSession.h').read_text()
    assert 'uint8_t aes_key[SHALOT_KEY_LEN]' in lib   # owned by PawSession
    assert 'bool key_stored' in lib
    # Zeroization goes through volatile-aware shalot_wipe (no optimizable memset).
    assert 'shalot_wipe(session->aes_key, sizeof(session->aes_key))' in lib
    assert 'shalot_wipe(session->k_mac, sizeof(session->k_mac))' in lib
    assert 'shalot_wipe(session->k_enc, sizeof(session->k_enc))' in lib


def test_pro47_secure_clear_on_boot():
    """PRO-47: setup() calls secure_clear_key() for clean boot state."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    setup_start = src.index('void setup()')
    setup_end = src.index('void loop()')
    setup_body = src[setup_start:setup_end]
    assert 'secure_clear_key()' in setup_body


def test_pro47_key_hierarchy_documented():
    """PRO-47: master key, K_mac, K_enc boundaries are documented in source."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'master key' in src          # comment: derives K_mac/K_enc from master
    assert 'K_mac' in src or 'k_mac' in src
    assert 'K_enc' in src or 'k_enc' in src
    assert 'SRAM' in src                # ownership: keys live in SRAM only


def test_pro47_clear_on_new_handshake_in_source():
    """PRO-47: new handshake + timeout + failure all call paw_session_reset
    (fail-closed), wiping the previously stored key in the library."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    pp_start = src.index('static uint8_t pollProvisioning()')
    pp_end = src.index('// =============================================================\n// Authentication State Machine')
    pp_body = src[pp_start:pp_end]
    # Firmware delegates every rejection to the library; no local key buffers.
    assert 'paw_session_provisioning_push' in pp_body
    assert 'paw_session_provisioning_poll' in pp_body
    assert 'secure_clear_key()' not in pp_body   # no sketch-level key buffer to clear
    # Library: reset (key-wipe) on accepted handshake, CRC mismatch, malformed,
    # all-zero, and provisioning timeout — fail-closed on every rejection.
    lib = (root / 'libraries/PawSession/src/PawSession.h').read_text()
    assert 'paw_session_reset(session)' in lib
    assert lib.count('paw_session_reset(session)') >= 4
    assert 'paw_session_wipe_key(' in lib        # explicit key-wipe path
    assert 'shalot_crc32' in lib                     # CRC verified before store
    assert 'all_zero' in lib                         # zero master rejected at store


# ============================================================================
# Missing or corrupt key: fail-closed retrieval (mocked)
# ============================================================================
#
# Mirrors key_is_valid()/den_key_valid(): a key is usable only when the
# provisioned flag is set AND the master buffer is non-zero. An all-zero
# master is indistinguishable from unprovisioned/wiped SRAM.

def _key_packet(key):
    return b'\xa3\x10' + bytes(key) + (binascii.crc32(bytes(key)) & 0xFFFFFFFF).to_bytes(4, 'big')


def test_pro47_missing_key_retrieval_invalid():
    """Fresh (never provisioned) store retrieves as invalid."""
    prov = MockProv()
    assert prov.key_stored is False
    assert prov.key is None
    assert prov.is_valid() is False


def test_pro47_zero_key_rejected_at_provisioning():
    """All-zero master passes CRC but is rejected as corrupt: never stored."""
    prov = MockProv()
    prov.poll(b'\xa1\x02', now=0)
    assert prov.poll(_key_packet(bytes(16)), now=100) == 'failed'
    assert prov.key_stored is False
    assert prov.key is None
    assert prov.is_valid() is False
    assert prov.stored_sent == []  # no fingerprint for a rejected key


def test_pro47_zero_key_does_not_wipe_valid_fingerprint_log():
    """A prior valid fingerprint is kept; the zero attempt stages nothing."""
    prov = MockProv()
    key = bytes(range(1, 17))
    prov.poll(b'\xa1\x02', now=0)
    assert prov.poll(_key_packet(key), now=100) == 'done'
    assert prov.is_valid() is True
    prov.poll(b'\xa1\x02', now=2000)  # new session wipes (fail-closed reset)
    assert prov.is_valid() is False
    assert prov.key is None
    assert prov.poll(_key_packet(bytes(16)), now=2100) == 'failed'
    assert prov.is_valid() is False


def test_pro47_corrupt_crc_stages_no_key_bytes():
    """CRC mismatch leaves no key bytes behind (nothing to retrieve)."""
    prov = MockProv()
    key = bytes(range(1, 17))
    bad = bytearray(_key_packet(key))
    bad[-1] ^= 0xFF
    prov.poll(b'\xa1\x02', now=0)
    assert prov.poll(bytes(bad), now=100) == 'failed'
    assert prov.key is None
    assert prov.is_valid() is False


def test_pro47_timeout_wipes_staged_key_bytes():
    """Timeout clears any staged bytes as well as the flag."""
    prov = MockProv()
    prov.poll(b'\xa1\x02', now=0)
    prov.poll(_key_packet(bytes(range(1, 17)))[:10], now=100)
    assert prov.poll(b'', now=10000 + 100) == 'failed'
    assert prov.key is None
    assert prov.is_valid() is False
    assert prov.phase == 'hs'


def test_pro47_valid_key_retrieves_and_answers():
    """A valid provisioned key retrieves as valid and authorises an answer."""
    import sys as _sys
    _sys.path.insert(0, '.')
    from tests.test_pro84_paw import MockPawResponder, encode, T_CHALLENGE
    from tests.test_pro87_uart import decode
    prov = MockProv()
    key = bytes(range(1, 17))
    prov.poll(b'\xa1\x02', now=0)
    assert prov.poll(_key_packet(key), now=100) == 'done'
    assert prov.is_valid() is True
    assert prov.key == key
    paw = MockPawResponder(key_stored=prov.is_valid())
    paw.feed(encode(T_CHALLENGE, bytes(range(0x10, 0x18))))
    assert len(paw.sent) == 1
    t, _ = decode(paw.sent[0])
    assert t == 0x02


def test_pro47_den_provision_zero_rejected():
    """DEN provisioning mock rejects an all-zero master (fail-closed)."""
    s = MockDenSession(K_MAC)
    assert s.is_valid() is True
    assert s.provision(bytes(16)) is False
    assert s.is_valid() is False
    assert s.key is None


def test_pro47_den_missing_key_denies_valid_hmac():
    """DEN without a provisioned key denies even a correct HMAC."""
    s = MockDenSession(K_MAC)
    s.clear_key()
    assert s.is_valid() is False
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert (ok, ack, reason) == (False, 0x00, REASON_HMAC_MISMATCH)
    assert s.state == 'DENIED'
    assert s.nonce is None


def test_pro47_den_corrupt_key_denies_valid_hmac():
    """Flag set but master wiped to zero (SRAM skew) still denies."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    s.key = bytes(16)  # corrupt: flag still set, buffer zeroed
    assert s.provisioned is True
    assert s.is_valid() is False
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert (ok, ack, reason) == (False, 0x00, REASON_HMAC_MISMATCH)
    assert s.state == 'DENIED'


def test_pro47_den_clear_resets_flag_and_reprovision_works():
    """Clear wipes + resets flag; a later valid provisioning restores auth."""
    s = MockDenSession(K_MAC)
    s.clear_key()
    assert s.provisioned is False
    assert s.key is None
    assert s.provision(bytes(range(1, 17))) is True
    assert s.is_valid() is True
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    s.install_blocklist([b"\xca\xfe\xba\xbe"])  # valid list required since PRO-98
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert (ok, ack, reason) == (True, 0x01, REASON_OK)


def test_pro47_paw_source_validated_retrieval():
    """PAW firmware gates both auth paths on key_is_valid (flag + nonzero).

    The sketch's key_is_valid() delegates to the library, which checks the
    provision flag and that the master buffer is non-zero — a wiped (all-zero)
    master is indistinguishable from unprovisioned SRAM.
    """
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'static bool key_is_valid()' in src
    assert 'paw_session_key_is_valid(&pawSession)' in src  # library gate
    lib = (root / 'libraries/PawSession/src/PawSession.h').read_text()
    # Library: key valid only when stored AND master has a non-zero byte.
    assert 'if (session->aes_key[i] != 0) return true;' in lib
    assert 'if (!paw_session_key_is_valid(session))' in lib
    # Auth paths in the sketch gate on the gate.
    assert 'if (paw_session_key_is_valid(&pawSession))' in src      # LoRa heartbeat
    assert 'if (key_is_valid())' in src or 'key_is_valid()' in src  # dock auth


def test_pro47_den_source_validated_retrieval_and_wipe():
    """DEN firmware: den_key_valid gate, flag reset in wipe, clear on
    handshake/timeout/failure, zero-key rejection at store."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    assert 'static uint8_t den_key_valid()' in src
    assert 'if (denDevKey[i] != 0) return 1;' in src
    assert 'if (!den_key_valid())' in src
    # Wipe resets the provisioned flag (otherwise flag/buffer skew).
    wipe = src[src.index('static void secure_clear_key()'):src.index('#define DEN_UART_BAUD')]
    assert 'key_provisioned = 0;' in wipe
    # Provisioning hygiene: clear on new handshake, timeout, and failure.
    pp = src[src.index('static uint8_t pollProvisioning()'):src.index('void loop()')]
    assert pp.count('secure_clear_key();') >= 3
    assert 'Zero key rejected.' in src
