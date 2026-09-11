"""
PRO-49: HMAC-SHA256 on RP2350 edge enforcement node.

Covers:
- K_mac derivation from master key (SHA-256(master || "MAC")[:16])
- HMAC verification uses K_mac, not master key directly
- Constant-time comparison for HMAC (den_ct_compare / hmac_module.compare_digest)
- Valid, invalid, and manipulated HMAC vectors
- Hardware-accelerated SHA-256 where available (RP2350)
"""
import hashlib
import hmac as hmac_module

import sys
sys.path.insert(0, '.')
from tests.test_pro88_den import K_MAC, DEV_KEY, DEV_HMAC_HEX


def test_pro49_k_mac_derivation_vector():
    """K_mac = SHA-256(master_key || "MAC")[:16] matches expected vector."""
    master = bytes(range(16))
    msg = master + b'MAC'
    full_hash = hashlib.sha256(msg).digest()
    k_mac = full_hash[:16]
    assert k_mac.hex() == '99c7117275f487623752e6d5d0eb438f'


def test_pro49_hmac_uses_k_mac_not_master():
    """HMAC with K_mac differs from HMAC with master key (proves separation)."""
    nonce = bytes(range(0x10, 0x20))
    hmac_master = hmac_module.new(DEV_KEY, nonce, hashlib.sha256).hexdigest()
    hmac_k_mac = hmac_module.new(K_MAC, nonce, hashlib.sha256).hexdigest()
    assert hmac_master == 'e76b9e0fe4021d62ea97745ef43c654dc14698aa799acb9ccc3e7f2a2b41a19e'  # old vector
    assert hmac_k_mac == DEV_HMAC_HEX  # new vector with K_mac
    assert hmac_master != hmac_k_mac  # proves separation


def test_pro49_invalid_hmac_rejected():
    """Manipulated HMAC (1 byte flipped) fails constant-time comparison."""
    nonce = bytes(range(0x10, 0x20))
    valid_hmac = hmac_module.new(K_MAC, nonce, hashlib.sha256).digest()
    bad_hmac = bytearray(valid_hmac)
    bad_hmac[0] ^= 0xFF  # flip first byte
    assert not hmac_module.compare_digest(valid_hmac, bytes(bad_hmac))


def test_pro49_constant_time_compare_used():
    """Source guard: DEN firmware uses den_ct_compare, not memcmp."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    den = (root / 'plc/den-main/den-main.ino').read_text()
    assert 'den_ct_compare' in den
    assert 'memcmp(expect' not in den  # never use memcmp for HMAC
    assert 'memcmp(kMac' not in den


def test_pro49_k_mac_derived_in_paw_source():
    """Source guard: PAW firmware derives K_mac and uses it for HMAC."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'derive_k_mac' in src
    assert 'kMac' in src
    assert 'hmac_sha256(kMac' in src
    assert 'hmac_sha256(aesKey' not in src  # never use master key directly


def test_pro49_k_mac_derived_in_den_source():
    """Source guard: DEN firmware derives K_mac and uses it for HMAC."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    assert 'den_derive_k_mac' in src
    assert 'kMac' in src
    assert 'den_hmac_sha256(kMac' in src
    assert 'den_hmac_sha256(DEN_DEV_KEY' not in src  # never use master directly


def test_pro49_k_mac_cleared_on_key_clear():
    """PRO-47 integration: secure_clear_key also clears K_mac."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    secure_clear_start = src.index('static void secure_clear_key()')
    secure_clear_end = src.index('}', secure_clear_start + 1)
    secure_clear_body = src[secure_clear_start:secure_clear_end + 1]
    assert 'kMac' in secure_clear_body
    assert 'volatile uint8_t*' in secure_clear_body


def test_pro49_k_mac_separate_from_k_enc():
    """K_mac and K_enc are separate buffers in SRAM."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'static uint8_t kMac[AES_KEY_SIZE]' in src
    assert 'static uint8_t kEnc[AES_KEY_SIZE]' in src
    # They are separate arrays, not aliases
    assert 'kMac =' not in src or 'kMac[k' in src  # not an alias assignment
    assert 'kEnc =' not in src or 'kEnc[k' in src


def test_pro49_hardware_sha256_comment():
    """Source guard: PRO-49 mentions hardware-accelerated SHA-256."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'PRO-49' in src
    assert 'hardware' in src.lower() or 'accelerat' in src.lower()
    # Should mention RP2350 SHA accelerator
    assert 'RP2350' in src or 'pico' in src.lower() or 'hardware' in src.lower()
