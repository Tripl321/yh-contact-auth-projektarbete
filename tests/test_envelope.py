"""
Phase 1 envelope vectors + negatives (docs/12-envelope-protocol.md).

All crypto runs through the REAL vendored C (tests/_envelope_lib.py builds
envelope.so from libraries/EnvelopeCrypto). Pinned digests below were each
independently verified on silicon (see VETTING-NOTE.md); if one fails, the C
or the pin changed — investigate, do not "fix" the pin.
"""
import pytest

from _envelope_lib import (
    DOMAIN, E1_TAG, E2_TAG, EnvelopeError, PawSession, build_aad,
    encode_e1, gcm_open, gcm_seal, hkdf, hkdf_kek, is_all_zero, mcu_wrap,
    parse_e2, verify_value, x25519_dh, x25519_pub,
)

RFC7748_ALICE_SEC = bytes.fromhex(
    '77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
RFC7748_ALICE_PUB = ('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')

GCM_EMPTY_TAG = '58e2fccefa7e3061367f1d57a4e7455a'
GCM_CT2 = '0388dace60b6a392f328c2b971b2fe78'
GCM_TAG2 = 'ab6e47d42cec13bdf53a67b21257bddf'

HKDF_IKM = bytes.fromhex('0b' * 22)
HKDF_SALT = bytes.fromhex('000102030405060708090a0b0c')
HKDF_INFO = bytes.fromhex('f0f1f2f3f4f5f6f7f8f9')
HKDF_OKM42 = ('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf'
              '34007208d5b887185865')

# Golden envelope: consistency anchor for Phase 2 firmware (generated with the
# vetted C; firmware must reproduce these exact E2 bytes from the same inputs).
G_SEC_P = bytes(range(1, 33))
G_NONCE_P = bytes(range(0xA0, 0xA8))
G_SEC_M = bytes(range(0x40, 0x60))
G_NONCE_M = bytes(range(0x10, 0x1C))
G_OP = bytes(range(0xD0, 0xE0))
G_DEV = b'PAW\x01'
G_PUB_P = '07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c'
G_KEK = 'fcfd978a5b64727fb656af797df54b47'
G_E2 = ('b20000000179a631eede1bf9c98f12032cdeadd0e7a079398fc786b88cc846ec89af'
        '85a51a101112131415161718191a1b723bfcc60ebbd126fd49250bc7e36dba6794d'
        'cb421e94f0414235b76e0c9bdc0')
G_VERIFY = '3b4bd122b0fc6f9f'


def test_rfc7748_x25519_pub():
    assert x25519_pub(RFC7748_ALICE_SEC).hex() == RFC7748_ALICE_PUB


def test_x25519_dh_symmetry_and_sensitivity():
    sec_b = bytes(range(0x80, 0xA0))
    pub_b = x25519_pub(sec_b)
    pub_a = x25519_pub(RFC7748_ALICE_SEC)
    assert x25519_dh(RFC7748_ALICE_SEC, pub_b) == x25519_dh(sec_b, pub_a)
    tampered = bytearray(pub_b)
    tampered[0] ^= 0x01
    assert x25519_dh(RFC7748_ALICE_SEC, bytes(tampered)) != \
        x25519_dh(RFC7748_ALICE_SEC, pub_b)


def test_nist_gcm_empty():
    _, tag = gcm_seal(bytes(16), bytes(12), b'', b'')
    assert tag.hex() == GCM_EMPTY_TAG


def test_nist_gcm_case2():
    ct, tag = gcm_seal(bytes(16), bytes(12), b'', bytes(16))
    assert ct.hex() == GCM_CT2
    assert tag.hex() == GCM_TAG2
    assert gcm_open(bytes(16), bytes(12), b'', ct, tag) == bytes(16)


def test_gcm_tamper_reject():
    ct, tag = gcm_seal(bytes(16), bytes(12), b'ad', b'0123456789abcdef')
    bad_ct = bytearray(ct)
    bad_ct[3] ^= 0x04
    assert gcm_open(bytes(16), bytes(12), b'ad', bytes(bad_ct), tag) is None
    bad_tag = bytearray(tag)
    bad_tag[15] ^= 0x80
    assert gcm_open(bytes(16), bytes(12), b'ad', ct, bytes(bad_tag)) is None
    assert gcm_open(bytes(16), bytes(12), b'AD', ct, tag) is None


def test_hkdf_rfc5869_case1():
    assert hkdf(HKDF_SALT, HKDF_IKM, HKDF_INFO, 42).hex() == HKDF_OKM42


def test_kek_deterministic_and_sensitive():
    k1 = hkdf_kek(bytes(32))
    assert len(k1) == 16 and k1 == hkdf_kek(bytes(32))
    assert hkdf_kek(bytes([1] + [0] * 31)) != k1


def test_all_zero_check():
    assert is_all_zero(bytes(32))
    assert not is_all_zero(bytes([0] * 31 + [1]))


def _fresh_pair(epoch=1):
    paw = PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P)
    e2, ver = mcu_wrap(0x01, G_DEV, epoch, G_OP, paw.pub_p, G_NONCE_P,
                       G_SEC_M, G_NONCE_M)
    return paw, e2, ver


def test_golden_envelope_bytes():
    paw = PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P)
    assert paw.pub_p.hex() == G_PUB_P
    assert paw.e1() == bytes([E1_TAG]) + paw.pub_p + G_NONCE_P
    assert len(paw.e1()) == 41
    e2, ver = mcu_wrap(0x01, G_DEV, 1, G_OP, paw.pub_p, G_NONCE_P,
                       G_SEC_M, G_NONCE_M)
    assert e2.hex() == G_E2
    assert len(e2) == 81
    assert ver == G_VERIFY and len(ver) == 16
    int(ver, 16)  # hex, 64 bits
    f = parse_e2(e2)
    assert set(f) == {'epoch', 'pub_m', 'nonce_m', 'ct', 'tag'}
    assert len(build_aad(0x01, G_DEV, 1, paw.pub_p, f['pub_m'],
                         G_NONCE_P, G_NONCE_M)) == 106


def test_envelope_roundtrip():
    paw, e2, ver = _fresh_pair()
    pt, ver2 = paw.open(e2)
    assert pt == G_OP and ver2 == ver


def test_tamper_ct_tag_rejected():
    paw, e2, _ = _fresh_pair()
    f = parse_e2(e2)
    for field, idx in (('ct', 2), ('tag', 0)):
        bad = bytearray(e2)
        bad[e2.index(f[field]) + idx] ^= 0x01
        with pytest.raises(EnvelopeError):
            PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P).open(bytes(bad))


def test_tampered_pubkey_nonce_rejected():
    paw, e2, _ = _fresh_pair()
    f = parse_e2(e2)
    for field in ('pub_m', 'nonce_m'):
        bad = bytearray(e2)
        bad[e2.index(f[field])] ^= 0x02
        with pytest.raises(EnvelopeError):
            PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P).open(bytes(bad))


def test_wrong_device_epoch_rejected():
    paw = PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P)
    e2, _ = mcu_wrap(0x01, b'PAW\x02', 1, G_OP, paw.pub_p, G_NONCE_P,
                     G_SEC_M, G_NONCE_M)
    with pytest.raises(EnvelopeError):
        paw.open(e2)
    paw2 = PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P)
    e2b, _ = mcu_wrap(0x01, G_DEV, 9, G_OP, paw2.pub_p, G_NONCE_P,
                      G_SEC_M, G_NONCE_M)
    forged = e2b[:1] + b'\x00\x00\x00\x02' + e2b[5:]
    with pytest.raises(EnvelopeError):
        paw2.open(forged)


def test_replay_into_new_session_rejected():
    paw_old, e2_old, _ = _fresh_pair()
    paw_old.open(e2_old)
    paw_new = PawSession(0x01, G_DEV, G_SEC_P, bytes(range(0xB0, 0xB8)))
    with pytest.raises(EnvelopeError):
        paw_new.open(e2_old)


def test_epoch_monotonic():
    paw, e2, _ = _fresh_pair(epoch=1)
    paw.open(e2)
    with pytest.raises(EnvelopeError):
        paw.open(e2)  # same epoch replay
    paw2 = PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P)
    e2b, _ = mcu_wrap(0x01, G_DEV, 5, G_OP, paw2.pub_p, G_NONCE_P,
                      G_SEC_M, G_NONCE_M)
    paw2.open(e2b)
    e2c, _ = mcu_wrap(0x01, G_DEV, 3, G_OP, paw2.pub_p, G_NONCE_P,
                      G_SEC_M, G_NONCE_M)
    with pytest.raises(EnvelopeError):
        paw2.open(e2c)


def test_degenerate_peer_aborts():
    paw = PawSession(0x01, G_DEV, G_SEC_P, G_NONCE_P)
    with pytest.raises(EnvelopeError):
        mcu_wrap(0x01, G_DEV, 1, G_OP, bytes(32), G_NONCE_P,
                 G_SEC_M, G_NONCE_M)
    e2, _ = mcu_wrap(0x01, G_DEV, 1, G_OP, paw.pub_p, G_NONCE_P,
                     G_SEC_M, G_NONCE_M)
    f = parse_e2(e2)
    zero_pub = bytes([E2_TAG]) + e2[1:5] + bytes(32) + e2[37:]
    assert len(zero_pub) == 81
    with pytest.raises(EnvelopeError):
        paw.open(zero_pub)
    assert f['epoch'] == 1  # sanity: frame layout as assumed
