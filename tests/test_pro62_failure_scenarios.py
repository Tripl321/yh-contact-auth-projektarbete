"""
PRO-62: failure scenario testing for authentication flow.

Covers:
- Invalid HMAC: DEN rejects and remains fail-closed
- Timeout: missing/late response denied without retaining prior auth
- Packet loss / retry: DEN returns to DENIED after failure, sends new
  challenge after session gap (protocol-level retry)
- Multiple consecutive failures: DEN stays fail-closed
- CRC errors, wrong frame type, invalid frame length
- PAW display status transitions correctly on rejection/timeout
- End-to-end failure flows

Reuses existing helpers: MockDenSession, MockPawResponder,
test vectors from test_pro88_den, test_pro84_paw, test_pro87_uart.
"""
import hashlib
import hmac as hmac_module

import sys
sys.path.insert(0, '.')
from tests.test_pro88_den import (
    MockDenSession, K_MAC, DEV_KEY, DEV_HMAC_HEX,
    REASON_OK, REASON_TIMEOUT, REASON_UNEXPECTED_TYPE,
    REASON_INVALID_SIZE, REASON_PARSE_ERROR, REASON_HMAC_MISMATCH,
    REASON_DISCONNECT, REASON_STALE_RESPONSE
)
from tests.test_pro84_paw import MockPawResponder, encode, T_CHALLENGE, T_ACK, T_HEARTBEAT, T_ALARM, T_RESPONSE, paw_hmac
from tests.test_pro87_uart import decode


def hmac16(key, nonce):
    assert len(key) == 16 and len(nonce) == 8
    return hmac_module.new(key, nonce, hashlib.sha256).digest()


# ============================================================================
# DEN-side failure scenarios
# ============================================================================

def test_pro62_invalid_hmac_denied():
    """Invalid HMAC: DEN rejects and remains fail-closed."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    bad_hmac = bytearray(hmac16(K_MAC, nonce))
    bad_hmac[0] ^= 0xFF  # flip entire first byte
    ok, ack, reason = s.on_frame(0x02, bytes(bad_hmac), 10100)
    assert ok is False
    assert ack == 0x00
    assert reason == REASON_HMAC_MISMATCH
    assert s.state == 'DENIED'
    assert s.nonce is None  # wiped


def test_pro62_timeout_missing_response():
    """Timeout with no response: DENIED (DISCONNECT), no auth retained."""
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    # denBytesRx == 0 means DISCONNECT (no bytes received)
    s.poll_timeout(10000 + 2000 + 1)  # just past deadline
    assert s.done == (False, 0x00, REASON_DISCONNECT)
    assert s.state == 'DENIED'
    assert s.nonce is None


def test_pro62_timeout_partial_response():
    """Timeout with partial bytes: DENIED (TIMEOUT)."""
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    # Simulate some bytes received but no complete frame
    s.denBytesRx = 5  # partial data received
    s.poll_timeout(10000 + 2000 + 1)
    assert s.done == (False, 0x00, REASON_TIMEOUT)
    assert s.state == 'DENIED'


def test_pro62_multiple_consecutive_failures():
    """Multiple consecutive failures: DEN stays fail-closed."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))

    # First attempt: invalid HMAC
    s.send_challenge(nonce, 10000)
    bad_hmac = bytearray(hmac16(K_MAC, nonce))
    bad_hmac[0] ^= 0x01
    s.on_frame(0x02, bytes(bad_hmac), 10100)
    assert s.state == 'DENIED'
    assert s.done[0] is False

    # Second attempt: timeout
    s.send_challenge(bytes(8), 20000)
    s.poll_timeout(20000 + 2000 + 1)
    assert s.state == 'DENIED'
    assert s.done[0] is False

    # Third attempt: wrong type
    s.send_challenge(bytes(8), 30000)
    s.on_frame(0x01, bytes(8), 30100)
    assert s.state == 'DENIED'
    assert s.done[0] is False

    # All three attempts failed
    assert len([l for l in s.log if l.startswith('FAILED')]) == 3


def test_pro62_packet_loss_retry_behavior():
    """Packet loss: DEN retries after session gap (protocol-level retry)."""
    s = MockDenSession(K_MAC)
    nonce1 = bytes(range(0x10, 0x18))
    nonce2 = bytes(range(0x20, 0x28))

    # First attempt: PAW never responds (packet loss)
    s.send_challenge(nonce1, 10000)
    s.poll_timeout(10000 + 2000 + 1)
    assert s.state == 'DENIED'
    assert s.done == (False, 0x00, REASON_DISCONNECT)  # zero bytes = disconnect

    # After session gap, DEN sends new challenge (retry)
    s.advance_gap(10000 + 2000 + 1 + 1000 + 1)
    assert s.state == 'DENIED'
    # New challenge can be sent
    s.send_challenge(nonce2, 10000 + 2000 + 1 + 1000 + 1 + 1000)
    assert s.state == 'CHALLENGE_SENT'
    assert s.nonce == nonce2


def test_pro62_retry_after_hmac_mismatch():
    """After HMAC mismatch, DEN retries with new challenge after gap."""
    s = MockDenSession(K_MAC)
    nonce1 = bytes(range(0x10, 0x18))
    nonce2 = bytes(range(0x20, 0x28))

    # First attempt: HMAC mismatch
    s.send_challenge(nonce1, 10000)
    bad_hmac = bytearray(hmac16(K_MAC, nonce1))
    bad_hmac[0] ^= 0x01
    s.on_frame(0x02, bytes(bad_hmac), 10100)
    assert s.state == 'DENIED'

    # After gap, new challenge (retry)
    s.advance_gap(10100 + 1000 + 1)
    s.send_challenge(nonce2, 10100 + 1000 + 1 + 1000)
    assert s.state == 'CHALLENGE_SENT'
    assert s.nonce == nonce2


def test_pro62_max_retries_not_defined():
    """Protocol does not define max retries; DEN keeps retrying.
    This test documents that behavior."""
    s = MockDenSession(K_MAC)
    # Protocol has no max retry limit; DEN keeps sending challenges
    # after each failure (with session gap).
    for i in range(5):
        nonce = bytes([i] * 8)
        s.send_challenge(nonce, 10000 + i * 5000)
        s.poll_timeout(10000 + i * 5000 + 2000 + 1)
        assert s.state == 'DENIED'
        s.advance_gap(10000 + i * 5000 + 2000 + 1 + 1000 + 1)


# ============================================================================
# PAW-side failure scenarios
# ============================================================================

def test_pro62_paw_ack_failed_sets_display_failed():
    """ACK 0x00 sets PAW display to FAILED."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.feed(encode(T_ACK, b'\x00'), now=1100)
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False


def test_pro62_paw_timeout_sets_display_failed():
    """PAW watchdog timeout (2.5s) sets display to FAILED."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    paw.poll(now=3501)  # > 2500ms after response
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False


def test_pro62_paw_late_ack_ignored():
    """Late ACK after PAW timeout is ignored; FAILED stays."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    paw.poll(now=3501)  # timeout
    assert paw.display_status == 'failed'
    # Late ACK should not change status
    paw.feed(encode(T_ACK, b'\x01'), now=4000)
    assert paw.display_status == 'failed'
    assert 'ignored: no pending response' in paw.log


def test_pro62_paw_new_challenge_after_timeout():
    """New CHALLENGE resets display to AUTHENTICATING after timeout."""
    paw = MockPawResponder()
    nonce1 = bytes(range(0x10, 0x18))
    nonce2 = bytes(range(0x20, 0x28))

    # First challenge -> timeout -> FAILED
    paw.feed(encode(T_CHALLENGE, nonce1), now=1000)
    paw.poll(now=3501)
    assert paw.display_status == 'failed'

    # New challenge -> AUTHENTICATING again
    paw.feed(encode(T_CHALLENGE, nonce2), now=4000)
    assert paw.display_status == 'authenticating'
    assert paw.ack_pending is True


# ============================================================================
# Protocol-level error handling
# ============================================================================

def test_pro62_crc_error_denied():
    """CRC error: frame rejected, never answered."""
    paw = MockPawResponder()
    bad = bytearray(encode(T_CHALLENGE, bytes(8)))
    bad[-1] ^= 0xFF  # corrupt CRC
    paw.feed(bytes(bad))
    assert paw.sent == []
    assert any('rejected: crc' in line for line in paw.log)


def test_pro62_wrong_frame_type_ignored():
    """Wrong frame type: parsed but never answered."""
    paw = MockPawResponder()
    # HEARTBEAT has no payload
    paw.feed(encode(T_HEARTBEAT, b''))
    assert paw.sent == []
    assert any('ignored type' in line for line in paw.log)


def test_pro62_invalid_payload_length():
    """Invalid payload length: rejected at decode."""
    paw = MockPawResponder()
    # Create a CHALLENGE frame with wrong length (e.g., 7 bytes instead of 8)
    import struct
    import binascii
    body = struct.pack('<H', 7) + bytes([T_CHALLENGE]) + bytes(7)
    frame = bytes([0xAA]) + body + struct.pack(
        '<I', binascii.crc32(body) & 0xFFFFFFFF)
    paw.feed(frame)
    assert paw.sent == []
    assert any('rejected' in line or 'ignored' in line for line in paw.log)


def test_pro62_paw_never_answers_non_challenge():
    """PAW never answers HEARTBEAT, ACK, ALARM, RESPONSE."""
    paw = MockPawResponder()
    paw.feed(encode(T_HEARTBEAT, b''))
    paw.feed(encode(T_ACK, b'\x01'))
    paw.feed(encode(T_ALARM, b'\x02'))
    paw.feed(encode(T_RESPONSE, bytes(32)))
    assert paw.sent == []
    assert sum('ignored type' in line for line in paw.log) == 3  # HEARTBEAT, ALARM, RESPONSE
    assert 'ignored: no pending response' in paw.log  # ACK with no pending


# ============================================================================
# End-to-end failure flow
# ============================================================================

def test_pro62_end_to_end_failure_then_retry():
    """End-to-end: challenge -> failure -> gap -> new challenge -> success."""
    s = MockDenSession(K_MAC)
    nonce1 = bytes(range(0x10, 0x18))
    nonce2 = bytes(range(0x20, 0x28))

    # First session: invalid HMAC -> FAILED
    s.send_challenge(nonce1, 10000)
    bad_hmac = bytearray(hmac16(K_MAC, nonce1))
    bad_hmac[1] ^= 0x01
    ok, ack, reason = s.on_frame(0x02, bytes(bad_hmac), 10100)
    assert ok is False
    assert s.state == 'DENIED'
    assert s.nonce is None

    # After session gap, new challenge
    s.advance_gap(10100 + 1000 + 1)
    s.send_challenge(nonce2, 10100 + 1000 + 1 + 1000)
    assert s.state == 'CHALLENGE_SENT'
    assert s.nonce == nonce2

    # Second session: valid HMAC -> AUTHENTICATED
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce2), 10100 + 1000 + 1 + 1000 + 100)
    assert ok is True
    assert ack == 0x01
    assert reason == REASON_OK
    assert s.state == 'AUTHENTICATED'


def test_pro62_paw_display_fails_on_rejection():
    """PAW display shows FAILED when DEN sends ACK 0x00."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    paw.feed(encode(T_ACK, b'\x00'), now=1100)
    assert paw.display_status == 'failed'
    assert paw.ack_pending is False


def test_pro62_paw_display_fails_on_timeout():
    """PAW display shows FAILED on watchdog timeout."""
    paw = MockPawResponder()
    nonce = bytes(range(0x10, 0x18))
    paw.feed(encode(T_CHALLENGE, nonce), now=1000)
    assert paw.display_status == 'authenticating'
    paw.poll(now=3501)  # > 2500ms
    assert paw.display_status == 'failed'


# ============================================================================
# Source guards for PRO-62 failure handling
# ============================================================================

def test_pro62_source_has_failure_handling():
    """PRO-62: DEN firmware has explicit failure handling for all error types."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    # Verify all error reasons are handled
    assert 'DEN_REASON_TIMEOUT' in src
    assert 'DEN_REASON_DISCONNECT' in src
    assert 'DEN_REASON_HMAC_MISMATCH' in src
    assert 'DEN_REASON_UNEXPECTED_TYPE' in src
    assert 'DEN_REASON_INVALID_SIZE' in src
    assert 'DEN_REASON_PARSE_ERROR' in src
    assert 'DEN_REASON_STALE_RESPONSE' in src


def test_pro62_paw_source_has_failure_display():
    """PRO-62: PAW firmware shows FAILED on auth failure."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    assert 'EPD_STATUS_FAILED' in src
    assert 'ack_failed' in src or 'ACK 0x00' in src


def test_pro62_constant_time_compare_used():
    """PRO-62: DEN uses constant-time compare for HMAC."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    assert 'den_ct_compare' in src
    # DEN firmware uses den_ct_compare, not memcmp
    assert 'memcmp(expect' not in src

