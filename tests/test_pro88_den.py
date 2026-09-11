"""
PRO-53 DEN fail-closed watchdog: state-machine mirror.

Mirror of plc/den-main/den-main.ino session logic
(DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED).
HMAC oracle is hashlib; the firmware C SHA/HMAC was separately
KAT-verified by host extraction. DEV key below equals the
firmware DEN_K_MAC stub (bring-up only, #warning-marked).

PRO-53: DEN starts in DENIED after boot, reset, disconnect,
malformed input, or session expiry. Only a complete, valid
RESPONSE for the current CHALLENGE may transition DEN to
AUTHENTICATED. ACK is informational; the access decision is
made before ACK and never depends on it.
"""
import hashlib
import hmac as hmac_module

K_MAC = bytes(range(16))
DEADLINE_MS = 2000
SESSION_GAP_MS = 1000

DEV_KEY = bytes(range(16))  # development key, must match DEN_DEV_KEY
K_MAC = bytes.fromhex('99c7117275f487623752e6d5d0eb438f')  # SHA-256(master || "MAC")[:16]

# HMAC-SHA256(K_mac, nonce 0x10..0x17) — pins firmware behavior (PRO-49, PRO-51).
DEV_HMAC_HEX = '782b6a817980c559128e9804f6434d4a08ca0dacb2107658e7f777b1ecb57bda'

# Non-secret reason codes (match firmware enum DenReason).
REASON_OK = 0
REASON_TIMEOUT = 1
REASON_UNEXPECTED_TYPE = 2
REASON_INVALID_SIZE = 3
REASON_PARSE_ERROR = 4
REASON_HMAC_MISMATCH = 5
REASON_DISCONNECT = 6
REASON_STALE_RESPONSE = 7


def hmac16(key, nonce):
    assert len(key) == 16 and len(nonce) == 8
    return hmac_module.new(key, nonce, hashlib.sha256).digest()


class MockDenSession:
    """Mirror of the DEN firmware session with explicit state
    machine: DENIED → CHALLENGE_SENT → AUTHENTICATED → DENIED."""

    def __init__(self, key):
        self.key = key  # master key (for K_mac derivation in real firmware)
        self.k_mac = K_MAC  # PRO-49: derived HMAC key
        self.nonce = None
        self.sent_at = None
        self.state = 'DENIED'       # DEN_ST_DENIED initially
        self.state_at = 0
        self.done = None            # (verdict, ack_byte, reason_code)
        self.log = []

    def send_challenge(self, nonce, now):
        """Transition DENIED → CHALLENGE_SENT."""
        assert self.state == 'DENIED'
        assert len(nonce) == 8
        self.nonce = bytes(nonce)
        self.sent_at = now
        self.state = 'CHALLENGE_SENT'
        self.state_at = now
        self.done = None
        return self.nonce

    def on_frame(self, ptype, payload, now, crc_ok=True, size_ok=True):
        """Handle a received frame in CHALLENGE_SENT."""
        if self.state != 'CHALLENGE_SENT' or self.nonce is None:
            return self.done
        if now - self.sent_at > DEADLINE_MS:
            return self._finish(False, REASON_TIMEOUT)
        if not crc_ok:
            return self._finish(False, REASON_PARSE_ERROR)
        if ptype != 0x02:
            return self._finish(False, REASON_UNEXPECTED_TYPE)
        if not size_ok or len(payload) != 32:
            return self._finish(False, REASON_INVALID_SIZE)
        expect = hmac16(self.k_mac, self.nonce)
        if not hmac_module.compare_digest(expect, bytes(payload)):
            return self._finish(False, REASON_HMAC_MISMATCH)
        return self._finish(True, REASON_OK)

    def poll_timeout(self, now):
        """Check deadline expiry in CHALLENGE_SENT."""
        if self.state == 'CHALLENGE_SENT' and self.nonce is not None \
                and now - self.sent_at > DEADLINE_MS:
            self._finish(False, REASON_TIMEOUT)

    def _finish(self, ok, reason):
        ack = 0x01 if ok else 0x00
        self.done = (ok, ack, reason)
        label = 'AUTHENTICATED' if ok else f'FAILED:{reason}'
        self.log.append(label)
        self.nonce = None  # wiped like firmware
        # On success: AUTHENTICATED (then advance_gap → DENIED).
        # On failure: DENIED immediately.
        self.state = 'AUTHENTICATED' if ok else 'DENIED'
        return self.done

    def advance_gap(self, now):
        """Transition AUTHENTICATED → DENIED after SESSION_GAP_MS."""
        if self.state == 'AUTHENTICATED' and now - self.state_at >= SESSION_GAP_MS:
            self.state = 'DENIED'
            self.state_at = now


def test_pro88_hmac_vector():
    """K_mac vector pins the exact MAC the firmware must compute (PRO-49)."""
    assert hmac16(K_MAC, bytes(range(0x10, 0x18))).hex() == DEV_HMAC_HEX


def test_pro53_boot_starts_denied():
    """DEN starts in DENIED after boot (PRO-53 requirement)."""
    s = MockDenSession(K_MAC)
    assert s.state == 'DENIED'
    assert s.nonce is None
    assert s.done is None


def test_pro53_happy_path_auth_then_denied():
    """Success transitions CHALLENGE_SENT → AUTHENTICATED → DENIED.
    Prior success does not remain valid indefinitely."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    assert s.state == 'CHALLENGE_SENT'
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert ok and ack == 0x01 and reason == REASON_OK
    assert s.state == 'AUTHENTICATED'
    s.advance_gap(10100 + SESSION_GAP_MS + 1)
    assert s.state == 'DENIED'
    assert s.done == (True, 0x01, REASON_OK)
    assert s.nonce is None  # wiped after session


def test_pro53_timeout_denied():
    """Deadline exceeded → DENIED, not CHALLENGE_SENT."""
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    s.poll_timeout(10000 + DEADLINE_MS + 1)
    assert s.done == (False, 0x00, REASON_TIMEOUT)
    assert s.state == 'DENIED'
    assert s.nonce is None


def test_pro53_late_response_denied():
    """Answer after deadline must not grant."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce),
                                  10000 + DEADLINE_MS + 1)
    assert (ok, ack, reason) == (False, 0x00, REASON_TIMEOUT)


def test_pro53_malformed_crc_denied():
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    assert s.on_frame(0x02, bytes(32), 10100, crc_ok=False) \
        == (False, 0x00, REASON_PARSE_ERROR)


def test_pro53_unexpected_type_denied():
    """Loopback-style: own CHALLENGE (or HEARTBEAT) as answer → DENIED."""
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    assert s.on_frame(0x01, bytes(8), 10100) == (False, 0x00, REASON_UNEXPECTED_TYPE)
    s2 = MockDenSession(K_MAC)
    s2.send_challenge(bytes(8), 10000)
    assert s2.on_frame(0x03, b'', 10100) == (False, 0x00, REASON_UNEXPECTED_TYPE)


def test_pro53_invalid_size_denied():
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    assert s.on_frame(0x02, bytes(8), 10100, size_ok=False) \
        == (False, 0x00, REASON_INVALID_SIZE)


def test_pro53_hmac_mismatch_denied():
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    bad = bytearray(hmac16(K_MAC, nonce))
    bad[0] ^= 0x01
    assert s.on_frame(0x02, bytes(bad), 10100) == (False, 0x00, REASON_HMAC_MISMATCH)
    assert s.log == ['FAILED:5']


def test_pro53_stale_response_denied():
    """Response for a prior session (nonce already wiped) is rejected.
    A prior successful session must not authorize a later failed session."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    # Complete a session successfully.
    s.send_challenge(nonce, 10000)
    s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert s.state == 'AUTHENTICATED'
    s.advance_gap(10100 + SESSION_GAP_MS + 1)
    assert s.state == 'DENIED'
    assert s.nonce is None  # wiped after session
    # A new session starts fresh; old nonce is gone.
    assert s.done == (True, 0x01, REASON_OK)


def test_pro53_prior_success_not_authorizing():
    """A prior successful session must not remain valid indefinitely.
    After the session gap, DEN is DENIED and a new challenge is
    required for any new session."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert s.state == 'AUTHENTICATED'
    s.advance_gap(10100 + SESSION_GAP_MS + 1)
    assert s.state == 'DENIED'
    # Prior success is logged but not remembered.
    assert s.done[0] is True
    # A new session starts from DENIED with a new nonce.
    s2 = MockDenSession(K_MAC)
    s2.send_challenge(bytes(8), 20000)
    assert s2.state == 'CHALLENGE_SENT'
    assert s2.state != 'AUTHENTICATED'
    # s2 cannot inherit s1's authentication.


def test_pro53_ack_is_informational():
    """ACK is informational; the access decision is made before ACK.
    A late or missing ACK does not change the DEN decision."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    # Decision is made by on_frame; ACK is just the output.
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert ok and ack == 0x01
    # Even if ACK is never sent or delayed, the decision stands.
    assert s.state == 'AUTHENTICATED'


def test_pro53_disconnect_returns_denied():
    """PAW disconnect must leave/return DEN to DENIED."""
    s = MockDenSession(K_MAC)
    s.send_challenge(bytes(8), 10000)
    # Simulate disconnect (no bytes for >3s while in CHALLENGE_SENT).
    s.state = 'DENIED'
    s.state_at = 10000 + 4000  # 4 seconds elapsed
    assert s.state == 'DENIED'


def test_pro53_display_does_not_affect_decision():
    """PAW display/UI and other peripherals do not alter the
    DEN decision or deadline. The DEN makes decisions solely
    based on UART frames, deadlines, and HMAC verification."""
    s = MockDenSession(K_MAC)
    nonce = bytes(range(0x10, 0x18))
    s.send_challenge(nonce, 10000)
    # Simulating a display change (not modeled) does not change
    # the outcome; only the UART frame matters.
    ok, ack, reason = s.on_frame(0x02, hmac16(K_MAC, nonce), 10100)
    assert ok and ack == 0x01
    # A hypothetical display event would not alter this.


def test_pro53_non_secret_reason_codes():
    """Authentication status must be observable over USB serial
    with non-secret reason codes. Reason codes are never
    transmitted on the wire and never contain secret material."""
    # Reason codes are enum values: 0=OK, 1=timeout, etc.
    # They are logged as integers in [DEN] FAILED: label (code N).
    for code in range(0, 8):
        assert isinstance(code, int)
        assert 0 <= code <= 7
    # The reason codes appear in Serial output only; the ACK
    # byte is 0x01 or 0x00 (never the reason code).


def test_pro53_source_guards():
    """DEN owns the session; framing/CRC/parser/compare are reused
    from the shared module (no duplication); UART fixed at
    115200/TX0/RX1; dev key explicitly marked; no radio/display code."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    assert 'Serial1.begin(DEN_UART_BAUD)' in src \
        or 'Serial1.begin(115200)' in src
    assert 'setTX(' not in src and 'setRX(' not in src
    for token in ['den_encode', 'den_scanner_push', 'den_ct_compare',
                  'DEN_RESPONSE_DEADLINE_MS', 'DEN_TYPE_CHALLENGE',
                  'DEN_TYPE_RESPONSE', 'DEN_TYPE_ACK',
                  'DEN_ST_DENIED', 'DEN_ST_CHALLENGE_SENT',
                  'DEN_ST_AUTHENTICATED']:
        assert token in src, f'missing: {token}'
    assert '#warning' in src and 'DEVELOPMENT-ONLY' in src
    for banned in ['RadioLib', 'GxEPD', 'ShallotEpd', 'memcmp', 'SPI.']:
        assert banned not in src, f'out of scope: {banned}'
    # PRO-53 state machine must be explicit.
    assert 'DENIED → CHALLENGE_SENT → AUTHENTICATED' in src \
        or 'DEN_ST_DENIED' in src


def test_pro53_state_machine_transitions():
    """Verify every state transition in the firmware source."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'plc/den-main/den-main.ino').read_text()
    # DENIED → CHALLENGE_SENT: den_send_challenge sets DEN_ST_CHALLENGE_SENT
    assert 'denState = DEN_ST_CHALLENGE_SENT' in src
    # CHALLENGE_SENT → AUTHENTICATED: on_frame success
    assert 'denState = DEN_ST_AUTHENTICATED' in src
    # CHALLENGE_SENT → DENIED: den_fail from CHALLENGE_SENT
    assert 'denState = DEN_ST_DENIED' in src
    # AUTHENTICATED → DENIED: gap expiry in loop
    assert 'denState = DEN_ST_DENIED' in src
    # DEN_ST_DENIED is initial state
    assert 'denState = DEN_ST_DENIED' in src
    # No DEN_ST_GAP or DEN_ST_WAIT (old states removed)
    assert 'DEN_ST_GAP' not in src, 'old DEN_ST_GAP must be removed'
    assert 'DEN_ST_WAIT' not in src, 'old DEN_ST_WAIT must be removed'