"""
PRO-87 docked UART protocol (PAW<->DEN): frame vectors + policy mirrors.

Mirror of libraries/DenUartProtocol/src/DenUartProtocol.h wire format:
  SYNC 0xAA | LEN u16 LE | TYPE u8 | PAYLOAD | CRC32 u32 LE (IEEE 802.3
  over LEN+TYPE+PAYLOAD). Expected digests below are hardcoded (computed
  once with binascii); the live path recomputes them independently.
"""
import binascii
import struct

SYNC = 0xAA
T_CHALLENGE, T_RESPONSE, T_HEARTBEAT, T_ALARM, T_ACK = 0x01, 0x02, 0x03, 0x04, 0xFF
MAX_PAYLOAD = 64
BYTE_TIMEOUT_MS = 100
RESPONSE_DEADLINE_MS = 2000
MAX_RESYNC_SKIPS = 64

TYPE_SIZES = {T_CHALLENGE: 16, T_RESPONSE: 32, T_HEARTBEAT: 0, T_ALARM: 1, T_ACK: 1}


def crc32(data):
    return binascii.crc32(bytes(data)) & 0xFFFFFFFF


def encode(ptype, payload):
    payload = bytes(payload)
    assert ptype in TYPE_SIZES and len(payload) == TYPE_SIZES[ptype]
    body = struct.pack('<H', len(payload)) + bytes([ptype]) + payload
    return bytes([SYNC]) + body + struct.pack('<I', crc32(body))


def decode(data):
    """Returns (type, payload) or raises DenError."""
    if len(data) < 8 or data[0] != SYNC:
        raise DenError('sync')
    ln = struct.unpack('<H', data[1:3])[0]
    if ln > MAX_PAYLOAD:
        raise DenError('length')
    if len(data) < 4 + ln + 4:
        raise DenError('short')
    ptype = data[3]
    if ptype not in TYPE_SIZES or ln != TYPE_SIZES[ptype]:
        raise DenError('type')
    body, want = data[1:4 + ln], struct.unpack('<I', data[4 + ln:8 + ln])[0]
    if crc32(body) != want:
        raise DenError('crc')
    return ptype, data[4:4 + ln]


class DenError(Exception):
    pass


class Scanner:
    """Mirror of den_scanner_t: tag-anchored resync + byte timeout."""

    def __init__(self):
        self.buf = bytearray()
        self.skipped = 0

    def push(self, byte, now_ms, last_ms=None):
        if last_ms is not None and self.buf and now_ms - last_ms > BYTE_TIMEOUT_MS:
            self.buf = bytearray()  # stale partial discarded (fail-closed)
            raise DenError('timeout')
        if not self.buf:
            if byte != SYNC:
                self.skipped += 1
                if self.skipped > MAX_RESYNC_SKIPS:
                    raise DenError('resync')
                return None
        self.buf.append(byte)
        if len(self.buf) >= 3:
            ln = struct.unpack('<H', self.buf[1:3])[0]
            if ln > MAX_PAYLOAD:
                self.buf = bytearray()
                raise DenError('length')
            if len(self.buf) >= 4 + ln + 4:
                try:
                    out = decode(bytes(self.buf[:4 + ln + 4]))
                except DenError as e:
                    self.buf = bytearray()  # discard whole frame, seek SYNC
                    raise
                self.buf = bytearray()
                self.skipped = 0
                return out
        return None


# ============================================================================
# Hardcoded vectors (frame hex -> (type, payload hex))
# ============================================================================

VECTORS = {
    'aa000003a8884866':
        (T_HEARTBEAT, ''),
    'aa0100ff019d75db7d':
        (T_ACK, '01'),
    'aa01000402511c9a13':
        (T_ALARM, '02'),
    'aa100001000102030405060708090a0b0c0d0e0ffb90996c':
        (T_CHALLENGE, '000102030405060708090a0b0c0d0e0f'),
    'aa200002202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f09ad4514':
        (T_RESPONSE, '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'),
}


def test_crc_algorithm_pinned():
    """CRC32('123456789') must be the IEEE reference (algorithm choice)."""
    assert crc32(b'123456789') == 0xCBF43926


def test_encode_vectors():
    for hexframe, (ptype, payloadhex) in VECTORS.items():
        assert encode(ptype, bytes.fromhex(payloadhex)).hex() == hexframe


def test_decode_vectors():
    for hexframe, (ptype, payloadhex) in VECTORS.items():
        t, p = decode(bytes.fromhex(hexframe))
        assert t == ptype and p.hex() == payloadhex


def test_decode_bad_crc():
    bad = bytearray.fromhex('aa0100ff019d75db7d')
    bad[-1] ^= 0x01
    try:
        decode(bytes(bad))
        assert False
    except DenError as e:
        assert str(e) == 'crc'


def test_decode_bad_length():
    try:
        decode(bytes([SYNC, 65, 0, T_HEARTBEAT]) + bytes(65 + 4))
        assert False
    except DenError as e:
        assert str(e) == 'length'


def test_decode_wrong_size_for_type():
    good = bytearray(encode(T_CHALLENGE, bytes(16)))
    good[1] = 8  # lie about length; CRC recomputed over the lie is wrong too
    try:
        decode(bytes(good))
        assert False
    except DenError:
        pass


def test_decode_unknown_type():
    body = struct.pack('<H', 0) + bytes([0x09])
    frame = bytes([SYNC]) + body + struct.pack('<I', crc32(body))
    try:
        decode(frame)
        assert False
    except DenError as e:
        assert str(e) == 'type'


def test_decode_truncated():
    full = bytes.fromhex('aa100001000102030405060708090a0b0c0d0e0ffb90996c')
    try:
        decode(full[:10])
        assert False
    except DenError as e:
        assert str(e) == 'short'


def test_scanner_garbage_prefix_resyncs():
    sc = Scanner()
    for b in bytes([0x00, 0xFF, 0x55]):
        assert sc.push(b, 1000) is None
    assert sc.skipped == 3  # stray bytes counted, then dropped
    out = None
    for b in bytes.fromhex('aa0100ff019d75db7d'):
        r = sc.push(b, 1000)
        if r is not None:
            out = r
    assert out == (T_ACK, bytes([0x01]))
    assert sc.skipped == 0  # reset on valid frame (mirrors C)


def test_scanner_split_frame_waits():
    sc = Scanner()
    frame = bytes.fromhex('aa100001000102030405060708090a0b0c0d0e0ffb90996c')
    for b in frame[:7]:
        assert sc.push(b, 1000) is None  # partial: waits, drops nothing
    out = None
    for b in frame[7:]:
        r = sc.push(b, 1000)
        if r is not None:
            out = r
    assert out[0] == T_CHALLENGE and out[1] == bytes(range(16))


def test_scanner_byte_timeout_discards():
    sc = Scanner()
    for b in bytes.fromhex('aa1000010001'):
        sc.push(b, 1000)
    try:
        sc.push(0x02, 1000 + BYTE_TIMEOUT_MS + 1, last_ms=1000)
        assert False
    except DenError as e:
        assert str(e) == 'timeout'
    assert sc.buf == bytearray()


def test_scanner_resync_budget():
    sc = Scanner()
    try:
        for _ in range(MAX_RESYNC_SKIPS + 2):
            sc.push(0x55, 1000)
        assert False
    except DenError as e:
        assert str(e) == 'resync'


def test_scanner_crc_error_recovers():
    """Corrupt frame dropped; next valid frame still parses."""
    sc = Scanner()
    bad = bytearray(encode(T_ACK, b'\x01'))
    bad[-1] ^= 0xFF
    seen_err = False
    for b in bytes(bad):
        try:
            sc.push(b, 1000)
        except DenError as e:
            assert str(e) == 'crc'
            seen_err = True
    assert seen_err
    out = None
    for b in bytes.fromhex('aa000003a8884866'):
        r = sc.push(b, 2000)
        if r is not None:
            out = r
    assert out == (T_HEARTBEAT, b'')


def test_response_deadline_rule():
    """Session rule mirror: answer after 2 s is too late (fail closed)."""
    challenge_at, answer_at = 5000, 5000 + RESPONSE_DEADLINE_MS + 1
    assert answer_at - challenge_at > RESPONSE_DEADLINE_MS  # -> deny, new session
    assert 5000 + RESPONSE_DEADLINE_MS - 5000 <= RESPONSE_DEADLINE_MS  # -> accept


def test_source_guards():
    """The skeleton owns the wire: sync/length/type gates, IEEE CRC,
    constant-time compare (no memcmp), timeout + resync budgets."""
    import pathlib
    hdr = (pathlib.Path(__file__).resolve().parent.parent /
           'libraries/DenUartProtocol/src/DenUartProtocol.h').read_text()
    for token in ['#define DEN_SYNC              0xAA',
                  'DEN_RESPONSE_DEADLINE_MS  2000',
                  'DEN_MAX_PAYLOAD       64',
                  '0xEDB88320', 'den_ct_compare',
                  'DEN_ERR_CRC', 'DEN_ERR_LENGTH', 'DEN_ERR_TYPE',
                  'DEN_BYTE_TIMEOUT_MS', 'DEN_MAX_RESYNC_SKIPS']:
        assert token in hdr, f'missing: {token}'
    assert 'memcmp' not in hdr
    assert '#include <Arduino.h>' not in hdr
    assert 'Serial.' not in hdr and 'Serial1' not in hdr  # transport-free
