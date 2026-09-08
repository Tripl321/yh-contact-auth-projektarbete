"""
PRO-52 protocol mirror tests (draft-PR #2 review).

Python mirror of shared/shallot_protocol.h packet codec, key derivation,
truncated-HMAC construction and replay whitelist. The RP2350 hardware
SHA-256 peripheral has no host equivalent, so hashlib (independent,
standard SHA-256) acts as oracle: any bench KAT of derive_keys /
hmac_sha256_truncated MUST equal these values, otherwise the peripheral
adapter (padding/endianness) is wrong.
"""
import hashlib
import hmac as hmac_module
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent

VERSION = 0x01
HMAC_LEN = 8
SENDERID_LEN = 8
SEQNUM_LEN = 4
NONCE_LEN = 8
KEY_LEN = 16
MAX_PAYLOAD = 64
HEADER_LEN = 1 + SENDERID_LEN + SEQNUM_LEN + NONCE_LEN
MIN_PACKET = HEADER_LEN + HMAC_LEN


def kdf(master, label):
    """Mirror of derive_keys: SHA-256(master || label)[:16]."""
    return hashlib.sha256(bytes(master) + label).digest()[:KEY_LEN]


def hmac_trunc(k_mac, msg):
    """Mirror of hmac_sha256_truncated: HMAC-SHA256, first 8 bytes."""
    return hmac_module.new(bytes(k_mac), bytes(msg), hashlib.sha256).digest()[:HMAC_LEN]


def build_packet(version, msg_type, sender_id, seq, nonce, payload):
    out = bytearray()
    out.append(((version << 4) | (msg_type & 0x0F)) & 0xFF)
    out += bytes(sender_id)
    out += seq.to_bytes(4, 'big')
    out += bytes(nonce)
    out += bytes(payload)
    return bytes(out)


def parse_packet(data):
    """Mirror of parse_packet. Returns dict or None when rejected."""
    if len(data) < MIN_PACKET:
        return None
    vm = data[0]
    if (vm >> 4) != VERSION:
        return None
    p = 1
    sender_id = data[p:p + SENDERID_LEN]
    p += SENDERID_LEN
    seq = int.from_bytes(data[p:p + 4], 'big')
    p += SEQNUM_LEN
    nonce = data[p:p + NONCE_LEN]
    p += NONCE_LEN
    payload_len = len(data) - p - HMAC_LEN
    if payload_len < 0 or payload_len > MAX_PAYLOAD:
        return None
    return {'msg_type': vm & 0x0F, 'sender_id': sender_id, 'seq': seq,
            'nonce': nonce, 'payload': data[p:p + payload_len],
            'hmac': data[-HMAC_LEN:]}


class SeqWhitelist:
    """Mirror of SeqWhitelist (WINDOW_SIZE=10)."""

    WINDOW = 10

    def __init__(self):
        self.last = None
        self.mask = 0

    def check_and_add(self, seq):
        if self.last is None:
            self.last = seq
            self.mask = 1 << (self.WINDOW - 1)
            return True
        if seq > self.last:
            adv = seq - self.last
            if adv >= self.WINDOW:
                self.mask = 1 << (self.WINDOW - 1)
            else:
                self.mask = ((self.mask << adv) & ((1 << self.WINDOW) - 1)) | \
                    (1 << (self.WINDOW - 1))
            self.last = seq
            return True
        if seq == self.last:
            return False
        diff = self.last - seq
        if diff >= self.WINDOW:
            return False
        slot = self.WINDOW - 1 - diff
        if self.mask & (1 << slot):
            return False
        self.mask |= (1 << slot)
        return True


MASTER = bytes(range(16))


def test_kdf_vectors():
    """KDF oracle: bench HW-SHA output must equal these digests."""
    assert kdf(MASTER, b'ENC').hex() == hashlib.sha256(MASTER + b'ENC').hexdigest()[:32]
    assert kdf(MASTER, b'MAC').hex() == hashlib.sha256(MASTER + b'MAC').hexdigest()[:32]
    assert kdf(MASTER, b'ENC') != kdf(MASTER, b'MAC')
    assert len(kdf(MASTER, b'MAC')) == KEY_LEN


def test_hmac_truncated_vector():
    k_mac = kdf(MASTER, b'MAC')
    msg = build_packet(VERSION, 0x01, bytes([1] + [0] * 7), 7,
                       bytes(range(8)), b'')
    mac = hmac_trunc(k_mac, msg)
    assert len(mac) == HMAC_LEN
    assert mac == hmac_module.new(k_mac, msg, hashlib.sha256).digest()[:8]
    bad = bytearray(mac)
    bad[0] ^= 0x01
    assert not hmac_module.compare_digest(mac, bytes(bad))


def test_packet_roundtrip():
    sender, nonce, payload = bytes([2] + [0] * 7), os.urandom(8), os.urandom(8)
    body = build_packet(VERSION, 0x02, sender, 42, nonce, payload)
    k_mac = kdf(MASTER, b'MAC')
    wire = body + hmac_trunc(k_mac, body)
    pkt = parse_packet(wire)
    assert pkt is not None
    assert (pkt['msg_type'], pkt['seq']) == (0x02, 42)
    assert pkt['sender_id'] == sender and pkt['nonce'] == nonce
    assert pkt['payload'] == payload
    assert pkt['hmac'] == hmac_trunc(k_mac, body)


def test_packet_malformed_rejected():
    assert parse_packet(b'\x10\x01\x02') is None  # short
    good = build_packet(VERSION, 0x01, bytes(8), 1, bytes(8), b'') + bytes(8)
    bad_ver = bytearray(good)
    bad_ver[0] = 0x20
    assert parse_packet(bytes(bad_ver)) is None  # wrong version
    huge = build_packet(VERSION, 0x01, bytes(8), 1, bytes(8), bytes(65)) + bytes(8)
    assert parse_packet(huge) is None  # oversize payload


def test_whitelist_replay():
    w = SeqWhitelist()
    assert w.check_and_add(100)
    assert not w.check_and_add(100)  # duplicate
    assert w.check_and_add(101)
    assert w.check_and_add(99)  # in-window late arrival
    assert not w.check_and_add(99)  # now seen
    assert not w.check_and_add(50)  # outside window
    assert w.check_and_add(200)  # jump re-anchors


def test_challenge_response_math():
    """Full edge->PAW->edge HMAC chain with the shared construction."""
    k_mac = kdf(MASTER, b'MAC')
    chal_body = build_packet(VERSION, 0x01, bytes([1] + [0] * 7), 5,
                             os.urandom(8), b'')
    chal = chal_body + hmac_trunc(k_mac, chal_body)
    rx = parse_packet(chal)
    assert rx is not None
    assert hmac_module.compare_digest(hmac_trunc(k_mac, chal_body), rx['hmac'])
    resp_body = build_packet(VERSION, 0x02, bytes([2] + [0] * 7), 9,
                             os.urandom(8), rx['nonce'])
    resp = resp_body + hmac_trunc(k_mac, resp_body)
    rx2 = parse_packet(resp)
    assert rx2 is not None and rx2['payload'] == rx['nonce']
    assert hmac_module.compare_digest(hmac_trunc(k_mac, resp_body), rx2['hmac'])


def test_pr2_source_guards():
    """Review guards: real SDK SHA API with padding, single-block AES,
    dedicated CTR counter bytes, correct RadioLib call order."""
    hdr = (ROOT / 'shared/shallot_protocol.h').read_text()
    # Streaming adapter implements hw_sha256_* on the real SDK peripheral
    # API (the SDK has no hw_sha256_* / update-with-padding of its own).
    assert 'static inline void hw_sha256_start(void)' in hdr
    assert 'static inline void hw_sha256_finish' in hdr
    assert 'sha256_start()' in hdr
    assert 'sha256_get_result(&res, SHA256_BIG_ENDIAN)' in hdr
    assert 'sha256_put_word' in hdr  # full 64B blocks, never partial
    assert '#include <AESLib.h>' not in hdr  # CBC envelope API unusable here
    assert '#include <AES.h>' in hdr  # bundled single-block API
    assert 'aes.set_key(key, 128)' in hdr
    assert 'aes.clean()' in hdr
    assert 'counter[0] = (uint8_t)(blockCtr >> 8)' in hdr  # dedicated bytes
    assert 'counter[14]' not in hdr  # never overlaps nonce tail
    for rel, miso in [('plc/edge-challenge-response/edge-challenge-response.ino', '12'),
                      ('id-kort/paw-challenge-response/paw-challenge-response.ino', '24')]:
        src = (ROOT / rel).read_text()
        assert 'new Module(LORA_CS, LORA_DIO1, LORA_RST, LORA_BUSY' in src
        assert 'radio.begin(LORA_FREQ, LORA_BW, LORA_SF, LORA_CR,' in src
        assert 'RadioLibModule' not in src
        assert 'static SPIClass spi1(spi1)' not in src
    paw = (ROOT / 'id-kort/paw-challenge-response/paw-challenge-response.ino').read_text()
    assert '#define LORA_MISO  24' in paw
