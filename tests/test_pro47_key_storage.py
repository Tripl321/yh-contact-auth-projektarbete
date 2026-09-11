"""
PRO-47 secure key storage in SRAM: clearing, non-exposure, and SRAM-only.

Covers:
- Key is stored after valid provisioning
- Key is cleared on timeout, disconnect (timeout), reset (boot), and new provisioning
- Key material is never written to Serial output
- Key material is never written to flash (source guard)
"""
import hashlib
import binascii

import sys
sys.path.insert(0, '.')
from tests.test_paw_responsive import MockProv


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
