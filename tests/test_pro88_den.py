"""
PRO-88 DEN session tests: deterministic vectors + state-machine mirror.

Mirror of plc/den-main/den-main.ino session logic (GAP -> WAIT ->
AUTHENTICATED/FAILED + ACK). HMAC oracle is hashlib; the firmware C
SHA/HMAC was separately KAT-verified by host extraction (empty, 'abc',
56/64-byte edges, HMAC-16/16 — all match). DEV key below equals the
firmware DEN_DEV_KEY stub (bring-up only, #warning-marked there).
"""
import hashlib
import hmac as hmac_module

DEV_KEY = bytes(range(16))
DEADLINE_MS = 2000

# HMAC-SHA256(DEV_KEY, nonce 0x10..0x1F) — pins firmware behavior.
DEV_HMAC_HEX = 'e76b9e0fe4021d62ea97745ef43c654dc14698aa799acb9ccc3e7f2a2b41a19e'


def hmac16(key, nonce):
    assert len(key) == 16 and len(nonce) == 16
    return hmac_module.new(key, nonce, hashlib.sha256).digest()


class MockDenSession:
    """Mirror of the DEN firmware session (single attempt)."""

    def __init__(self, key):
        self.key = key
        self.nonce = None
        self.sent_at = None
        self.done = None  # (verdict, ack_byte)
        self.log = []

    def send_challenge(self, nonce, now):
        assert len(nonce) == 16
        self.nonce = bytes(nonce)
        self.sent_at = now
        self.done = None
        return self.nonce

    def on_frame(self, ptype, payload, now, crc_ok=True, size_ok=True):
        if self.done is not None or self.nonce is None:
            return
        if now - self.sent_at > DEADLINE_MS:
            return self._finish(False, 'timeout')
        if not crc_ok:
            return self._finish(False, 'parse error')
        if ptype != 0x02:
            return self._finish(False, 'unexpected type')
        if not size_ok or len(payload) != 32:
            return self._finish(False, 'invalid size')
        expect = hmac16(self.key, self.nonce)
        if not hmac_module.compare_digest(expect, bytes(payload)):
            return self._finish(False, 'hmac mismatch')
        return self._finish(True, 'ok')

    def poll_timeout(self, now):
        if self.done is None and self.nonce is not None \
                and now - self.sent_at > DEADLINE_MS:
            self._finish(False, 'timeout')

    def _finish(self, ok, reason):
        self.done = (ok, 0x01 if ok else 0x00)
        self.log.append(('AUTHENTICATED' if ok else 'FAILED: ' + reason))
        self.nonce = None  # wiped like firmware
        return self.done


def test_pro88_hmac_vector():
    """DEV-key vector pins the exact MAC the firmware must compute."""
    assert hmac16(DEV_KEY, bytes(range(0x10, 0x20))).hex() == DEV_HMAC_HEX


def test_pro88_happy_path():
    s = MockDenSession(DEV_KEY)
    nonce = bytes(range(0x10, 0x20))
    s.send_challenge(nonce, 10000)
    ok, ack = s.on_frame(0x02, hmac16(DEV_KEY, nonce), 10100)
    assert ok and ack == 0x01
    assert s.log == ['AUTHENTICATED']


def test_pro88_timeout():
    s = MockDenSession(DEV_KEY)
    s.send_challenge(bytes(16), 10000)
    s.poll_timeout(10000 + DEADLINE_MS + 1)
    assert s.done == (False, 0x00)
    assert s.log == ['FAILED: timeout']
    assert s.nonce is None  # wiped on failure


def test_pro88_late_response_denied():
    """Answer arriving after the deadline must not grant (fail closed)."""
    s = MockDenSession(DEV_KEY)
    nonce = bytes(range(0x10, 0x20))
    s.send_challenge(nonce, 10000)
    ok, ack = s.on_frame(0x02, hmac16(DEV_KEY, nonce), 10000 + DEADLINE_MS + 1)
    assert (ok, ack) == (False, 0x00)


def test_pro88_malformed_crc_denied():
    s = MockDenSession(DEV_KEY)
    s.send_challenge(bytes(16), 10000)
    assert s.on_frame(0x02, bytes(32), 10100, crc_ok=False) == (False, 0x00)


def test_pro88_unexpected_type_denied():
    """Loopback-style: own CHALLENGE (or HEARTBEAT) as answer -> deny."""
    s = MockDenSession(DEV_KEY)
    s.send_challenge(bytes(16), 10000)
    assert s.on_frame(0x01, bytes(16), 10100) == (False, 0x00)
    s2 = MockDenSession(DEV_KEY)
    s2.send_challenge(bytes(16), 10000)
    assert s2.on_frame(0x03, b'', 10100) == (False, 0x00)


def test_pro88_invalid_size_denied():
    s = MockDenSession(DEV_KEY)
    s.send_challenge(bytes(16), 10000)
    assert s.on_frame(0x02, bytes(16), 10100, size_ok=False) == (False, 0x00)


def test_pro88_hmac_mismatch_denied():
    s = MockDenSession(DEV_KEY)
    nonce = bytes(range(0x10, 0x20))
    s.send_challenge(nonce, 10000)
    bad = bytearray(hmac16(DEV_KEY, nonce))
    bad[0] ^= 0x01
    assert s.on_frame(0x02, bytes(bad), 10100) == (False, 0x00)
    assert s.log == ['FAILED: hmac mismatch']


def test_pro88_source_guards():
    """DEN owns the session; framing/CRC/parser/compare are reused from
    the shared module (no duplication); UART fixed at 115200/TX0/RX1;
    dev key explicitly marked; no radio/display code."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    assert 'Serial1.begin(DEN_UART_BAUD)' in src or 'Serial1.begin(115200)' in src
    assert 'setTX(' not in src and 'setRX(' not in src  # UART0 defaults 0/1
    for token in ['den_encode', 'den_scanner_push', 'den_ct_compare',
                  'DEN_RESPONSE_DEADLINE_MS', 'DEN_TYPE_CHALLENGE',
                  'DEN_TYPE_RESPONSE', 'DEN_TYPE_ACK']:
        assert token in src, f'missing shared-module use: {token}'
    assert '#warning' in src and 'DEVELOPMENT-ONLY' in src  # dev key marked
    for banned in ['RadioLib', 'GxEPD', 'ShallotEpd', 'memcmp', 'SPI.']:
        assert banned not in src, f'out of scope in DEN firmware: {banned}'
