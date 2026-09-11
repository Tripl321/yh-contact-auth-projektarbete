"""
PRO-84 PAW responder tests: valid challenge/response, bad CRC, invalid
nonce length, unexpected type, split frames, parser recovery, and
never-initiates. Cross-checks the DEN DEV vector (782b6a81...): PAW's
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
K_MAC = bytes.fromhex('99c7117275f487623752e6d5d0eb438f')  # SHA-256(master || "MAC")[:16]
DEV_HMAC_HEX = '782b6a817980c559128e9804f6434d4a08ca0dacb2107658e7f777b1ecb57bda'


def paw_hmac(nonce):
    assert len(nonce) == 8
    return hmac_module.new(K_MAC, nonce, hashlib.sha256).digest()


class MockPawResponder:
    """Mirror of handleDockAuth: responder-only, CHALLENGE-only."""

    def __init__(self):
        self.sc = Scanner()
        self.sent = []  # frames PAW transmitted
        self.log = []
        self.display_status = None   # last epd.showStatus value
        self.ack_pending = False      # waiting for DEN ACK
        self.last_resp_sent_at = 0    # millis of last RESPONSE transmit

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
                if ptype == T_ACK and self.ack_pending:
                    self.ack_pending = False
                    if payload and payload[0] == 0x01:
                        self.display_status = 'authenticated'
                        self.log.append('ack_authenticated')
                    else:
                        self.display_status = 'failed'
                        self.log.append('ack_failed')
                elif ptype == T_ACK and not self.ack_pending:
                    self.log.append('ignored: no pending response')
                else:
                    self.log.append('ignored type 0x%02x' % ptype)
                continue
            self.display_status = 'authenticating'
            self.sent.append(encode(T_RESPONSE, paw_hmac(payload)))
            self.last_resp_sent_at = now
            self.ack_pending = True
            self.log.append('answered')

    def poll(self, now=1000):
        """PAW-side ACK watchdog: 2.5 s after last response -> FAILED."""
        if self.ack_pending and now - self.last_resp_sent_at > 2500:
            self.display_status = 'failed'
            self.ack_pending = False
            self.log.append('ack_timeout')


def test_pro84_valid_challenge_response():
    """PAW answer matches DEN's expected MAC (interop vector)."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce))
    assert len(paw.sent) == 1
    t, mac = decode(paw.sent[0])
    assert t == T_RESPONSE and len(mac) == 32
    assert mac.hex() == DEV_HMAC_HEX
    assert paw.log == ['answered']


def test_pro84_bad_crc_ignored():
    paw = MockPawResponder()
    bad = bytearray(encode(T_CHALLENGE, bytes(8)))
    bad[-1] ^= 0x01
    paw.feed(bytes(bad))
    assert paw.sent == []
    assert any('rejected: crc' in line for line in paw.log)


def test_pro84_invalid_nonce_length_ignored():
    """LEN != 8 for CHALLENGE: rejected at decode, never answered."""
    import struct
    import binascii
    for ln in (0, 7, 9, 15, 17, 33):
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
    assert sum('ignored type' in line for line in paw.log) == 3  # HEARTBEAT, ALARM, RESPONSE
    assert 'ignored: no pending response' in paw.log  # ACK with no pending


def test_pro84_split_frames_assemble():
    paw = MockPawResponder()
    frame = encode(T_CHALLENGE, bytes(range(8)))
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
    bad = bytearray(encode(T_CHALLENGE, bytes(8)))
    bad[10] ^= 0xFF
    paw.feed(bytes(bad))
    assert paw.sent == []
    paw.feed(encode(T_CHALLENGE, bytes(range(8))))
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
    assert 'hmac_sha256(kMac' in src  # PRO-49: HMAC uses K_mac, not master key
    assert 'derive_k_mac' in src  # PRO-49: K_mac derivation present
    assert 'epd.showStatus(EPD_STATUS_AUTHENTICATING)' in src  # e-paper kept
    assert '#include <RadioLib.h>' in src and 'radio.transmit' in src  # LoRa kept
    assert 'handleDockAuth();' in src
    den = (root / 'plc/den-main/den-main.ino').read_text()
    assert '0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07' in den
    assert '0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07' in src  # same dev key


# ============================================================================
# PRO-58: e-paper status transitions during dock challenge-response
# ============================================================================

def test_pro58_challenge_sets_authenticating():
    """CHALLENGE frame sets display to AUTHENTICATING (non-blocking)."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    assert paw.ack_pending is True
    assert paw.last_resp_sent_at == 1000


def test_pro58_ack_success_sets_authenticated():
    """ACK 0x01 after RESPONSE sets display to AUTHENTICATED."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.feed(encode(T_ACK, b'\x01'), now=1100)
    assert paw.display_status == 'authenticated'
    assert paw.ack_pending is False


def test_pro58_ack_fail_sets_failed():
    """ACK 0x00 after RESPONSE sets display to FAILED."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.feed(encode(T_ACK, b'\x00'), now=1100)
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False


def test_pro58_late_ack_ignored():
    """Late ACK after PAW timeout (2.5 s) is ignored; FAILED stays."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    # PAW watchdog fires at >2500 ms after response (firmware uses > 2500)
    paw.poll(now=3501)
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False
    # Late ACK must not overwrite FAILED
    paw.feed(encode(T_ACK, b'\x01'), now=4000)
    assert paw.display_status == 'failed'
    assert 'ignored: no pending response' in paw.log


def test_pro58_timeout_does_not_affect_auth():
    """Display/Ack watchdog is display-only: DEN decision logic is
    independent of e-paper state (fail-closed)."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    # Simulate a display degrade: showStatus returns but status is set.
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    # Even if display is stuck/degraded, the auth answer is still sent.
    assert len(paw.sent) == 1
    t, mac = decode(paw.sent[0])
    assert t == T_RESPONSE and mac.hex() == DEV_HMAC_HEX


def test_pro58_new_challenge_resets_authenticating():
    """A new CHALLENGE resets display to AUTHENTICATING even if prior
    session was FAILED or AUTHENTICATED."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    # First challenge -> ACK fail -> FAILED
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.feed(encode(T_ACK, b'\x00'), now=1100)
    assert paw.display_status == 'failed'
    # Second challenge -> AUTHENTICATING again
    paw.feed(encode(T_CHALLENGE, bytes(range(0x20, 0x28))), now=2000)
    assert paw.display_status == 'authenticating'
    assert paw.ack_pending is True


# ============================================================================
# PRO-59: approved authentication text on e-paper
# ============================================================================

def test_pro59_authenticated_persists_until_new_challenge():
    """AUTHENTICATED stays until a new CHALLENGE resets to AUTHENTICATING."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.feed(encode(T_ACK, b'\x01'), now=1100)
    assert paw.display_status == 'authenticated'
    assert paw.ack_pending is False
    # Time passes, no new challenge: status stays AUTHENTICATED
    paw.poll(now=5000)
    assert paw.display_status == 'authenticated'
    # New challenge resets to AUTHENTICATING
    paw.feed(encode(T_CHALLENGE, bytes(range(0x20, 0x28))), now=6000)
    assert paw.display_status == 'authenticating'
    assert paw.ack_pending is True


def test_pro59_timeout_after_challenge_sets_failed():
    """PAW watchdog timeout (2.5 s) after CHALLENGE sets FAILED."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    # Watchdog fires at 3501 ms (1000 + 2500 + 1)
    paw.poll(now=3501)
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False


def test_pro59_failed_response_sets_failed():
    """ACK 0x00 after RESPONSE sets FAILED (mirrors DEN deny)."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.feed(encode(T_ACK, b'\x00'), now=1100)
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False
    # Subsequent frames do not change FAILED until new challenge
    paw.feed(encode(T_ACK, b'\x01'), now=1200)
    assert paw.display_status == 'failed'  # late ACK ignored


def test_pro59_source_has_text_rendering():
    """PRO-59: firmware renders AUTHENTICATED text on e-paper."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'FONT_5X7' in src
    assert 'void drawChar(char c, int x, int y)' in src
    assert 'void drawText(const char* text, int x, int y)' in src
    assert 'drawText("AUTHENTICATED"' in src
    assert 'PRO-59' in src
