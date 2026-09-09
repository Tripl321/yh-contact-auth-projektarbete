"""
PRO-84 PAW responder tests: valid challenge/response, bad CRC, invalid
nonce length, unexpected type, split frames, parser recovery, and
never-initiates. Cross-checks the DEN DEV vector (e76b9e0f...): PAW's
answer to DEN's challenge MUST equal what DEN expects (C-level interop
additionally proven by host-extracted KAT of both hmac implementations).
"""
import hashlib
import hmac as hmac_module

import sys
sys.path.insert(0, '.')
from tests.test_pro87_uart import (encode, decode, DenError, Scanner,
                                   T_CHALLENGE, T_RESPONSE, T_HEARTBEAT,
                                   T_ALARM, T_ACK, MAX_PAYLOAD)

DEV_KEY = bytes(range(16))  # must equal DEN_DEV_KEY (guarded below)
DEV_HMAC_HEX = 'e76b9e0fe4021d62ea97745ef43c654dc14698aa799acb9ccc3e7f2a2b41a19e'


def paw_hmac(nonce):
    assert len(nonce) == 16
    return hmac_module.new(DEV_KEY, nonce, hashlib.sha256).digest()


class MockPawResponder:
    """Mirror of handleDockUart: responder-only, CHALLENGE-only."""

    def __init__(self):
        self.sc = Scanner()
        self.sent = []  # frames PAW transmitted
        self.log = []

    def feed(self, data, now=1000):
        for b in bytes(data):
            try:
                r = self.sc.push(b, now)
            except DenError as e:
                self.log.append('rejected: ' + str(e))
                continue
            if r is None:
                continue
            ptype, payload = r
            if ptype != T_CHALLENGE:
                self.log.append('ignored type 0x%02x' % ptype)
                continue
            self.sent.append(encode(T_RESPONSE, paw_hmac(payload)))
            self.log.append('answered')


def test_pro84_valid_challenge_response():
    """PAW answer matches DEN's expected MAC (interop vector)."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x20))
    paw.feed(encode(T_CHALLENGE, nonce))
    assert len(paw.sent) == 1
    t, mac = decode(paw.sent[0])
    assert t == T_RESPONSE and len(mac) == 32
    assert mac.hex() == DEV_HMAC_HEX
    assert paw.log == ['answered']


def test_pro84_bad_crc_ignored():
    paw = MockPawResponder()
    bad = bytearray(encode(T_CHALLENGE, bytes(16)))
    bad[-1] ^= 0x01
    paw.feed(bytes(bad))
    assert paw.sent == []
    assert any('rejected: crc' in line for line in paw.log)


def test_pro84_invalid_nonce_length_ignored():
    """LEN != 16 for CHALLENGE: rejected at decode, never answered."""
    import struct
    import binascii
    for ln in (0, 8, 15, 17, 33):
        body = struct.pack('<H', ln) + bytes([T_CHALLENGE]) + bytes(ln)
        frame = bytes([0xAA]) + body + struct.pack(
            '<I', binascii.crc32(body) & 0xFFFFFFFF)
        paw = MockPawResponder()
        paw.feed(frame)
        assert paw.sent == [], ln
        assert paw.log and 'answered' not in paw.log


def test_pro84_unexpected_type_ignored():
    """HEARTBEAT/ACK/ALARM/RESPONSE inbound: parsed but never answered."""
    paw = MockPawResponder()
    paw.feed(encode(T_HEARTBEAT, b''))
    paw.feed(encode(T_ACK, b'\x01'))
    paw.feed(encode(T_ALARM, b'\x02'))
    paw.feed(encode(T_RESPONSE, bytes(32)))
    assert paw.sent == []
    assert sum('ignored type' in line for line in paw.log) == 4


def test_pro84_split_frames_assemble():
    paw = MockPawResponder()
    frame = encode(T_CHALLENGE, bytes(range(16)))
    paw.feed(frame[:5])
    assert paw.sent == []
    paw.feed(frame[5:11])
    assert paw.sent == []
    paw.feed(frame[11:])
    assert len(paw.sent) == 1


def test_pro84_garbage_recovery():
    """Garbage then corrupt then valid: only the valid one answered."""
    paw = MockPawResponder()
    paw.feed(bytes([0x00, 0xFF, 0x55, 0xA1, 0x02]))
    bad = bytearray(encode(T_CHALLENGE, bytes(16)))
    bad[10] ^= 0xFF
    paw.feed(bytes(bad))
    assert paw.sent == []
    paw.feed(encode(T_CHALLENGE, bytes(range(16))))
    assert len(paw.sent) == 1


def test_pro84_never_initiates():
    """Driving every failure mode produces zero transmissions."""
    paw = MockPawResponder()
    paw.feed(b'')
    paw.feed(bytes([0xAA]))  # lone SYNC, nothing follows
    paw.feed(encode(T_HEARTBEAT, b''))
    assert paw.sent == []


def test_pro84_source_guards():
    """PAW reuses framing/CRC (no dup), answers only RESPONSE, keeps
    Serial1 115200 defaults, marks the dev key, preserves e-paper/LoRa."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert '#include <DenUartProtocol.h>' in src
    assert 'den_scanner_push' in src and 'den_encode(DEN_TYPE_RESPONSE' in src
    assert 'den_encode(DEN_TYPE_CHALLENGE' not in src  # never initiates
    assert 'Serial1.begin(115200)' in src
    assert 'setTX(' not in src and 'setRX(' not in src
    assert '#warning' in src and 'DEVELOPMENT-ONLY' in src
    assert 'hmac_sha256(DEN_DEV_KEY' in src  # existing HMAC reused
    assert 'epd.showStatus(EPD_STATUS_AUTHENTICATING)' in src  # e-paper kept
    assert '#include <RadioLib.h>' in src and 'radio.transmit' in src  # LoRa kept
    assert 'handleDockUart();' in src
    den = (root / 'plc/den-main/den-main.ino').read_text()
    assert '0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07' in den
    assert '0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07' in src  # same dev key
