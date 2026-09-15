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
    """CRC mismatch path in firmware clears key via secure_clear_key()."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    # Find pollProvisioning and verify secure_clear_key is called for
    # any failure outcome (including CRC mismatch).
    pp_start = src.index('static uint8_t pollProvisioning()')
    pp_end = src.index('// =============================================================\n// Authentication State Machine')
    pp_body = src[pp_start:pp_end]
    # The secure_clear_key is called after the do-while block for failures
    assert 'if (outcome != PROV_DONE)' in pp_body
    assert 'secure_clear_key()' in pp_body
    # Verify it appears after the do-while block (not just inside one branch)
    do_while_end = pp_body.index('return outcome;')
    clear_before_return = pp_body[:do_while_end].count('secure_clear_key()')
    assert clear_before_return >= 1


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
    # Only the hash (fingerprint) is ever transmitted/printed
    assert 'Serial.write(keyHash' in src
    assert 'Serial.write(MSG_STORED)' in src


def test_pro47_sram_only_no_flash_writes():
    """Source guard: key material stays in SRAM; no flash writes for keys."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    # No EEPROM/flash writes for key material
    assert 'EEPROM.put' not in src
    assert 'EEPROM.write' not in src
    assert 'FlashStorage' not in src
    # Key buffer is a plain static array (SRAM)
    assert 'static uint8_t aesKey[AES_KEY_SIZE]' in src
    # secure_clear_key exists and uses volatile to prevent optimization
    assert 'static void secure_clear_key()' in src
    assert 'volatile uint8_t* k = (volatile uint8_t*)aesKey' in src


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
    assert 'master key' in src
    assert 'K_mac' in src or 'kMac' in src
    assert 'K_enc' in src or 'kEnc' in src
    assert 'SRAM-only' in src


def test_pro47_clear_on_new_handshake_in_source():
    """PRO-47: new handshake triggers secure_clear_key() in pollProvisioning."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    # Find pollProvisioning and check that secure_clear_key is called
    # on new handshake and on timeout
    pp_start = src.index('static uint8_t pollProvisioning()')
    pp_end = src.index('// =============================================================\n// Authentication State Machine')
    pp_body = src[pp_start:pp_end]
    assert 'secure_clear_key()' in pp_body
    # Count calls: should be at least 3 (new handshake, timeout, failure)
    assert pp_body.count('secure_clear_key()') >= 3


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
    """PAW firmware gates both auth paths on key_is_valid (flag + nonzero)."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'static bool key_is_valid()' in src
    assert 'if (aesKey[i] != 0) return true;' in src
    lines = src.splitlines()
    start = next(i for i, l in enumerate(lines) if 'void handleDockAuth()' in l)
    depth, begun = 0, False
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if '{' in lines[i]:
            begun = True
        if begun and depth == 0:
            dock_end = i
            break
    else:
        raise AssertionError('unbalanced: handleDockAuth')
    assert 'if (!key_is_valid())' in '\n'.join(lines[start:dock_end + 1])
    assert 'if (key_is_valid())' in src  # LoRa response path
    assert 'Zero key rejected.' in src  # store-time corrupt rejection


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
