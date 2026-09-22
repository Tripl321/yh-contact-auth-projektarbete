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

DEV_KEY = bytes(range(16))  # test-only master; PRO-93 forbids it in firmware
K_MAC = bytes.fromhex('99c7117275f487623752e6d5d0eb438f')  # SHA-256(master || "MAC")[:16]
DEV_HMAC_HEX = '782b6a817980c559128e9804f6434d4a08ca0dacb2107658e7f777b1ecb57bda'


def paw_hmac(nonce):
    assert len(nonce) == 8
    return hmac_module.new(K_MAC, nonce, hashlib.sha256).digest()


class MockPawResponder:
    """Mirror of handleDockAuth: responder-only, CHALLENGE-only."""

    def __init__(self, key_stored=True):
        self.sc = Scanner()
        self.sent = []  # frames PAW transmitted
        self.log = []
        self.display_status = None   # last epd.showStatus value
        self.ack_pending = False      # waiting for DEN ACK
        self.last_resp_sent_at = 0    # millis of last RESPONSE transmit
        self.key_stored = key_stored  # PRO-94: no key -> never answer

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
            if not self.key_stored:
                # PRO-59 fail-closed: unprovisioned PAW never answers and
                # never shows AUTHENTICATED; the stale grant (if any) is
                # cleared to FAILED (mirrors LoRa NO_KEY -> FAILED).
                self.display_status = 'failed'
                self.log.append('ignored: no key')
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


def test_pro84_unprovisioned_ignores_challenge():
    """PRO-94 fail-closed: no key -> CHALLENGE ignored, zero transmissions,
    display FAILED (never AUTHENTICATED; mirrors handleDockAuth NO_KEY)."""
    paw = MockPawResponder(key_stored=False)
    paw.feed(encode(T_CHALLENGE, bytes(range(0x10, 0x18))))
    assert paw.sent == []
    assert paw.display_status == 'failed'
    assert paw.display_status != 'authenticated'
    assert paw.ack_pending is False
    assert paw.log == ['ignored: no key']


def test_pro84_unprovisioned_ignores_everything():
    """Unprovisioned PAW transmits nothing for any inbound traffic."""
    paw = MockPawResponder(key_stored=False)
    paw.feed(encode(T_CHALLENGE, bytes(8)))
    paw.feed(encode(T_HEARTBEAT, b''))
    paw.feed(encode(T_ACK, b'\x01'))
    paw.feed(encode(T_ALARM, b'\x02'))
    paw.feed(encode(T_RESPONSE, bytes(32)))
    assert paw.sent == []
    assert paw.display_status == 'failed'
    assert paw.display_status != 'authenticated'
    assert paw.ack_pending is False


def test_pro84_provisioned_still_answers():
    """The keyStored gate only affects unprovisioned units."""
    paw = MockPawResponder(key_stored=True)
    paw.feed(encode(T_CHALLENGE, bytes(range(0x10, 0x18))))
    assert len(paw.sent) == 1
    assert paw.display_status == 'authenticating'


def _paw_dock_handler_body():
    """Extract handleDockAuth() body for source-guard assertions."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    lines = src.splitlines()
    start = next(i for i, l in enumerate(lines) if 'void handleDockAuth()' in l)
    depth, begun = 0, False
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if '{' in lines[i]:
            begun = True
        if begun and depth == 0:
            return '\n'.join(lines[start:i + 1])
    raise AssertionError('unbalanced: handleDockAuth')


def test_pro84_dock_checks_key_stored():
    """PRO-94: handleDockAuth gates CHALLENGE on the library key-is-valid check
    (fail-closed); RESPONSE is encoded at exactly one site."""
    body = _paw_dock_handler_body()
    assert 'paw_session_accept_challenge(' in body   # accepts challenge only if key valid
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    lib = (pathlib.Path(__file__).resolve().parent.parent /
           'libraries/PawSession/src/PawSession.h').read_text()
    # Library denies challenge when key not valid -> fail-closed.
    assert 'if (!paw_session_key_is_valid(session))' in lib
    assert 'PAW_SESSION_EVENT_NO_KEY' in lib
    assert src.count('den_encode(DEN_TYPE_RESPONSE') == 1


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
    # PRO-93: no hardcoded development keys or warnings
    assert '#warning' not in src, "PRO-93: #warning must be removed"
    assert 'DEVELOPMENT-ONLY' not in src, "PRO-93: dev key stub must be removed"
    assert 'DEN_DEV_KEY' not in src, "PRO-93: DEN_DEV_KEY must be removed"
    lib = (root / 'libraries/PawSession/src/PawSession.h').read_text()
    assert 'shalot_hmac_sha256(' in src                      # PRO-49: HMAC present
    assert 'paw_session_k_mac(&pawSession)' in src          # PRO-49: from K_mac, not master
    assert 'shalot_derive_k_mac' in lib    # PRO-49: K_mac derivation present
    assert 'void sha256(' not in src  # no local copy (ShallotCrypto)
    assert 'epd.showStatus(EPD_STATUS_AUTHENTICATING)' in src  # e-paper kept
    assert '#include <RadioLib.h>' in src and 'radio.transmit' in src  # LoRa kept
    assert 'handleDockAuth();' in src
    den = (root / 'plc/den-main/den-main.ino').read_text()
    assert '0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07' not in den
    assert '0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07' not in src


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


# ============================================================================
# PRO-59b: AUTHENTICATED shown only on grant (ongoing/denied never shows it)
# ============================================================================
#
# Render contract mirrors ShallotEPD::showStatus/drawIcon: only the granted
# state renders checkmark + text. Both grant paths are gated on a pending
# response (dock: paw_ack_pending, LoRa: STATE_WAITING_FOR_RESULT), so an
# unsolicited ACK/RESULT can never light AUTHENTICATED.

def render_epd(status):
    """Content contract mirror of showStatus+drawIcon (icon, text)."""
    if status == 'authenticating':
        return ('dots-in-circle', None)
    if status == 'authenticated':
        return ('checkmark-in-circle', 'AUTHENTICATED')
    if status == 'failed':
        return ('x-in-circle', None)
    raise AssertionError('unknown status: %r' % (status,))


class MockLoRaResult:
    """Mirror of the LoRa MSG_RESULT branch: grant-gated display."""

    W_KEY, W_CHAL, COMPUTING, W_RES = 'key', 'challenge', 'computing', 'wait_result'

    def __init__(self):
        self.state = self.W_KEY
        self.display = None
        self.log = []

    def provision(self):
        self.state = self.W_CHAL

    def challenge(self):
        self.display = 'authenticating'
        self.state = self.COMPUTING
        self.log.append('challenge')

    def respond(self):
        assert self.state == self.COMPUTING
        self.state = self.W_RES

    def on_result(self, ok):
        if self.state != self.W_RES:
            self.log.append('ignored: no pending response')
            return
        self.state = self.W_CHAL
        if ok:
            self.display = 'authenticated'
            self.log.append('result_authenticated')
        else:
            self.display = 'failed'
            self.log.append('result_failed')


def test_pro59b_ongoing_never_shows_authenticated():
    """AUTHENTICATING render carries no checkmark and no grant text."""
    icon, text = render_epd('authenticating')
    assert icon != 'checkmark-in-circle'
    assert text is None


def test_pro59b_denied_never_shows_authenticated():
    """FAILED render carries no checkmark and no grant text."""
    icon, text = render_epd('failed')
    assert icon != 'checkmark-in-circle'
    assert text is None


def test_pro59b_granted_shows_checkmark_and_text():
    """AUTHENTICATED render is checkmark + grant text (no green: the 1.54
    panel is monochrome-driven, see paw-main README)."""
    assert render_epd('authenticated') == ('checkmark-in-circle', 'AUTHENTICATED')


def test_pro59b_lora_unsolicited_result_ignored():
    """RESULT 0x01 with no pending response changes nothing (all states)."""
    cases = [
        (lambda m: None, ['ignored: no pending response'], None),
        (lambda m: m.provision(), ['ignored: no pending response'], None),
        (lambda m: (m.provision(), m.challenge()),
         ['challenge', 'ignored: no pending response'], 'authenticating'),
    ]
    for setup, want_log, want_display in cases:
        m = MockLoRaResult()
        setup(m)
        m.on_result(True)
        assert m.display == want_display
        assert m.display != 'authenticated'
        assert m.log == want_log


def test_pro59b_lora_result_grant_and_deny():
    """Pending RESULT 0x01 -> authenticated, 0x00 -> failed."""
    m = MockLoRaResult()
    m.provision()
    m.challenge()
    m.respond()
    m.on_result(True)
    assert m.display == 'authenticated'
    assert render_epd(m.display)[1] == 'AUTHENTICATED'
    m2 = MockLoRaResult()
    m2.provision()
    m2.challenge()
    m2.respond()
    m2.on_result(False)
    assert m2.display == 'failed'
    assert render_epd(m2.display) == ('x-in-circle', None)


def test_pro59b_lora_duplicate_result_after_grant_ignored():
    """Second RESULT for the same session cannot re-light authenticated."""
    m = MockLoRaResult()
    m.provision()
    m.challenge()
    m.respond()
    m.on_result(False)
    assert m.display == 'failed'
    m.on_result(True)  # late/duplicate: no pending response anymore
    assert m.display == 'failed'
    assert m.log[-1] == 'ignored: no pending response'


def test_pro59b_new_challenge_resets_grant():
    """A new challenge returns the display to AUTHENTICATING (grant is
    per-session, never sticky)."""
    m = MockLoRaResult()
    m.provision()
    m.challenge()
    m.respond()
    m.on_result(True)
    assert m.display == 'authenticated'
    m.challenge()
    assert m.display == 'authenticating'
    assert render_epd(m.display)[1] is None


def test_pro59b_source_grant_sites_are_exactly_two():
    """Only the two grant paths may request AUTHENTICATED (dock ACK 0x01
    with pending response, LoRa RESULT 0x01 while waiting)."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    assert src.count('showStatus(EPD_STATUS_AUTHENTICATED)') == 2


def test_pro59b_source_lora_result_gated_on_pending():
    """RESULT with no pending WAITING_FOR_RESULT session is ignored (fail-closed),
    before any display change — mirrors the dock paw_ack_pending gate."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parent.parent
    src = (root / 'id-kort/paw-main/paw-main.ino').read_text()
    lib = (root / 'libraries/PawSession/src/PawSession.h').read_text()
    # Library: on_result only applies when state == WAITING_FOR_RESULT.
    assert 'session->auth_state != PAW_AUTH_WAITING_FOR_RESULT' in lib
    # Sketch: the LoRa MSG_RESULT branch feeds the library (which gate-keeps),
    # and only lights AUTHENTICATED when the library returns success.
    assert 'msgType == MSG_RESULT' in src
    assert 'paw_session_on_result(' in src
    assert 'PAW_SESSION_EVENT_AUTH_SUCCESS' in src
    result_idx = src.index('paw_session_on_result(')
    auth_idx = src.index('PAW_SESSION_EVENT_AUTH_SUCCESS')
    assert result_idx < auth_idx  # result check precedes AUTHENTICATED status


def test_pro59b_source_grant_text_gated_on_status():
    """The AUTHENTICATED text renders only inside the authenticated branch."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    assert src.count('drawText("AUTHENTICATED"') == 1
    idx = src.index('drawText("AUTHENTICATED"')
    gate = src[max(0, idx - 300):idx]
    assert 'status == EPD_STATUS_AUTHENTICATED' in gate


def test_pro59b_source_setup_never_grants_or_denies():
    """Boot shows AUTHENTICATING only; AUTHENTICATED/FAILED are unreachable
    before the first grant/deny."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    setup = src[src.index('void setup()'):src.index('void loop()')]
    assert 'EPD_STATUS_AUTHENTICATING' in setup
    assert 'EPD_STATUS_AUTHENTICATED' not in setup
    assert 'EPD_STATUS_FAILED' not in setup


# ============================================================================
# PRO-59 fixes: missing key, strict RESULT length, stale-grant clear
# ============================================================================

def test_pro59_dock_no_key_shows_failed_never_authenticated():
    """Saknad nyckel (dock): CHALLENGE utan nyckel -> FAILED, aldrig grant."""
    paw = MockPawResponder(key_stored=False)
    paw.feed(encode(T_CHALLENGE, bytes(range(0x10, 0x18))), now=1000)
    assert paw.sent == []
    assert paw.display_status == 'failed'
    assert paw.display_status != 'authenticated'
    assert paw.ack_pending is False
    # En obeställd ACK 0x01 efteråt kan inte tända AUTHENTICATED.
    paw.feed(encode(T_ACK, b'\x01'), now=1100)
    assert paw.display_status == 'failed'


def test_pro59_source_dock_no_key_clears_to_failed():
    """Firmware: dock NO_KEY-grenen visar FAILED (samma som LoRa)."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    body = _paw_dock_handler_body()
    assert 'PAW_SESSION_EVENT_NO_KEY' in body
    no_key_idx = body.index('PAW_SESSION_EVENT_NO_KEY')
    window = body[no_key_idx:no_key_idx + 500]
    assert 'EPD_STATUS_FAILED' in window


def test_pro59_source_lora_result_requires_exact_length():
    """Firmware: LoRa RESULT kräver exakt 2 byte (typ + 1 statusbyte);
    längre ramar är malformed och kan aldrig bevilja."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    assert 'msgType == MSG_RESULT && rxLen == 2' in src
    assert 'msgType == MSG_RESULT && rxLen >= 2' not in src


def test_pro59_source_key_loss_clears_stale_grant():
    """Firmware: valid -> invalid nyckelkant återställer display till låst
    läge så bistabil AUTHENTICATED aldrig fastnar efter nyckelbortfall."""
    import pathlib
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    loop = src[src.index('void loop()'):]
    assert 'lastKeyValid' in loop
    assert 'key_is_valid()' in loop
    edge_idx = loop.index('lastKeyValid && !curKeyValid')
    assert 'EPD_STATUS_AUTHENTICATING' in loop[edge_idx:edge_idx + 300]
    # Grant-platserna är fortfarande exakt två (ingen ny grant-väg).
    assert src.count('showStatus(EPD_STATUS_AUTHENTICATED)') == 2
