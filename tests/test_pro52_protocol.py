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


# ============================================================================
# PRO-52 review fixes: reboot resync + verdict binding.
#
# Cipher note: the RP2350 / firmware AES-CTR has no host equivalent, so the
# mirrors below drive AES-128-ECB through the openssl CLI (FIPS-197
# verified) with the DOCUMENTED counter layout (blkCtr_be2 || 00 00 ||
# seq_be4 || nonce). This pins the layout fix: any firmware/mirror layout
# drift breaks these vectors. HW-SHA truth remains bench KAT.
# ============================================================================

import shutil
import subprocess

HAS_OPENSSL = shutil.which('openssl') is not None


def aes_ecb_enc(key, block16):
    assert HAS_OPENSSL, 'openssl CLI required for AES-CTR mirror'
    p = subprocess.run(['openssl', 'enc', '-aes-128-ecb', '-K', bytes(key).hex(),
                        '-nopad'], input=bytes(block16), capture_output=True)
    assert p.returncode == 0, 'openssl AES-ECB failed'
    assert len(p.stdout) == 16
    return p.stdout


def aes_ctr(key, seq, nonce, data):
    """Mirror of firmware aes_ctr_crypt (fixed layout)."""
    out = bytearray(data)
    blk, off = 0, 0
    while off < len(out):
        ctr = blk.to_bytes(2, 'big') + b'\x00\x00' + \
            seq.to_bytes(4, 'big') + bytes(nonce)
        ks = aes_ecb_enc(key, ctr)
        n = min(16, len(out) - off)
        for i in range(n):
            out[off + i] ^= ks[i]
        off += n
        blk += 1
    return bytes(out)


def test_ctr_old_layout_twotimepad():
    """Documents the fixed bug: the old layout XORed the block counter
    over nonce[6..7], so a nonce ending 00 01 reused block-0 keystream
    for block 1. The fixed layout never collides (counter in bytes 0..1,
    nonce intact in bytes 8..15)."""
    key = bytes(range(16))
    nonce_bad = bytes([0] * 6 + [0x00, 0x01])
    data = bytes(32)
    # Old layout keystream blocks:
    ks0_old = aes_ecb_enc(key, b'\x00' * 4 + (7).to_bytes(4, 'big') + nonce_bad)
    ctr1_old = b'\x00' * 4 + (7).to_bytes(4, 'big') + nonce_bad[:6] + b'\x00\x01'
    ks1_old = aes_ecb_enc(key, ctr1_old)
    assert ks0_old == ks1_old  # BUG: identical keystream, two-time pad
    # Fixed layout: block counter can never equal a nonce tail slice.
    ks0_new = aes_ecb_enc(key, b'\x00\x00\x00\x00' + (7).to_bytes(4, 'big') + nonce_bad)
    ks1_new = aes_ecb_enc(key, b'\x00\x01\x00\x00' + (7).to_bytes(4, 'big') + nonce_bad)
    assert ks0_new != ks1_new
    # Mirror roundtrips (encrypt == decrypt).
    assert aes_ctr(key, 7, nonce_bad, aes_ctr(key, 7, nonce_bad, data)) == data


class EdgeAccept:
    """Mirror of the edge RESPONSE accept path: HMAC -> echo-bind to the
    live challenge nonce -> whitelist, resync-anchoring on miss."""

    def __init__(self, k_mac, k_enc):
        self.k_mac, self.k_enc = k_mac, k_enc
        self.wl = SeqWhitelist()
        self.resyncs = 0

    def on_response(self, live_nonce, seq, resp_nonce, enc_echo, mac, wire):
        if not hmac_module.compare_digest(hmac_trunc(self.k_mac, wire), mac):
            return False, 'hmac'
        echo = aes_ctr(self.k_enc, seq, resp_nonce, enc_echo)
        if not hmac_module.compare_digest(echo, bytes(live_nonce)):
            return False, 'bind'
        if not self.wl.check_and_add(seq):
            self.wl.last = seq  # mirror of resync()
            self.wl.mask = 1 << (self.wl.WINDOW - 1)
            self.wl.initialized = True
            self.resyncs += 1
        return True, 'ok'


def _resp_vec(k_mac, k_enc, resp_seq, chal_nonce, paw_nonce=None):
    """Build a genuine PAW response wire + fields for a live challenge."""
    paw_nonce = paw_nonce or os.urandom(8)
    enc = aes_ctr(k_enc, resp_seq, paw_nonce, chal_nonce)
    body = build_packet(VERSION, 0x02, bytes([2] + [0] * 7), resp_seq,
                       paw_nonce, enc)
    return body + hmac_trunc(k_mac, body), paw_nonce, enc


def test_resync_reboot_paw_recovers():
    """Edge remembers seq ~120; rebooted PAW answers the live challenge
    from seq 0 -> accepted via resync, then proceeds normally."""
    k_mac, k_enc = kdf(MASTER, b'MAC'), kdf(MASTER, b'ENC')
    edge = EdgeAccept(k_mac, k_enc)
    for s in range(111, 121):
        assert edge.wl.check_and_add(s)
    live = os.urandom(8)
    wire, paw_nonce, enc = _resp_vec(k_mac, k_enc, 0, live)
    ok, reason = edge.on_response(live, 0, paw_nonce, enc, wire[-8:], wire[:-8])
    assert ok, reason
    assert edge.resyncs == 1  # exactly one re-anchor
    wire2, paw_nonce2, enc2 = _resp_vec(k_mac, k_enc, 1, os.urandom(8))
    live2 = aes_ctr(k_enc, 1, paw_nonce2, enc2)  # PAW's next live challenge echo
    ok, _ = edge.on_response(live2, 1, paw_nonce2, enc2, wire2[-8:], wire2[:-8])
    assert ok
    assert edge.resyncs == 1  # no further churn


def test_replay_during_resync_rejected():
    """Attacker replays an old HMAC-valid response (stale echo) against a
    live challenge: rejected on binding, window NOT re-anchored, and the
    genuine rebooted response still resyncs exactly once afterwards."""
    k_mac, k_enc = kdf(MASTER, b'MAC'), kdf(MASTER, b'ENC')
    edge = EdgeAccept(k_mac, k_enc)
    for s in range(111, 121):
        assert edge.wl.check_and_add(s)
    old_nonce = os.urandom(8)
    old_wire, old_paw_nonce, old_enc = _resp_vec(k_mac, k_enc, 5, old_nonce)
    live = os.urandom(8)  # different live challenge
    ok, reason = edge.on_response(live, 5, old_paw_nonce, old_enc,
                                  old_wire[-8:], old_wire[:-8])
    assert not ok and reason == 'bind'
    assert edge.resyncs == 0  # replay must not move the window
    assert edge.wl.last == 120
    wire, paw_nonce, enc = _resp_vec(k_mac, k_enc, 0, live)
    ok, _ = edge.on_response(live, 0, paw_nonce, enc, wire[-8:], wire[:-8])
    assert ok and edge.resyncs == 1


def test_resync_requires_hmac():
    """Garbage-HMAC packet with a reset seq: rejected, no re-anchor."""
    k_mac, k_enc = kdf(MASTER, b'MAC'), kdf(MASTER, b'ENC')
    edge = EdgeAccept(k_mac, k_enc)
    for s in range(111, 121):
        assert edge.wl.check_and_add(s)
    live = os.urandom(8)
    ok, reason = edge.on_response(live, 0, os.urandom(8), os.urandom(8),
                                  os.urandom(8), os.urandom(29))
    assert not ok and reason == 'hmac'
    assert edge.resyncs == 0


class PawVerdict:
    """Mirror of the PAW verdict wait: type gate -> HMAC -> echo-bind to
    the outstanding challenge nonce. No match -> no state change."""

    def __init__(self, k_mac, k_enc):
        self.k_mac, self.k_enc = k_mac, k_enc
        self.outstanding = None
        self.display = None

    def on_response_sent(self, challenge_nonce):
        self.outstanding = bytes(challenge_nonce)

    def on_packet(self, msg_type, seq, pkt_nonce, payload, mac, wire):
        if msg_type not in (0x03, 0x04):
            return False, 'not-verdict'  # never a verdict, ignored silently
        if not hmac_module.compare_digest(hmac_trunc(self.k_mac, wire), mac):
            return False, 'hmac'
        if self.outstanding is None or len(payload) != NONCE_LEN:
            return False, 'bind'
        echo = aes_ctr(self.k_enc, seq, pkt_nonce, payload)
        if not hmac_module.compare_digest(echo, self.outstanding):
            return False, 'bind'
        self.outstanding = None
        self.display = 'granted' if msg_type == 0x03 else 'denied'
        return True, 'ok'


def _verdict_vec(k_mac, k_enc, msg_type, vseq, vnonce, chal_nonce):
    enc = aes_ctr(k_enc, vseq, vnonce, chal_nonce)
    body = build_packet(VERSION, msg_type, bytes([1] + [0] * 7), vseq,
                       vnonce, enc)
    return body + hmac_trunc(k_mac, body), enc


def test_verdict_challenge_as_verdict_ignored():
    """A fresh CHALLENGE arriving during the verdict wait is never a
    verdict: ignored with zero state change (the bench-observed 0x1 bug)."""
    paw = PawVerdict(kdf(MASTER, b'MAC'), kdf(MASTER, b'ENC'))
    outstanding = os.urandom(8)
    paw.on_response_sent(outstanding)
    chal_body = build_packet(VERSION, 0x01, bytes([1] + [0] * 7), 200,
                             os.urandom(8), b'')
    chal = chal_body + hmac_trunc(paw.k_mac, chal_body)
    rx = parse_packet(chal)
    ok, reason = paw.on_packet(rx['msg_type'], rx['seq'], rx['nonce'],
                               rx['payload'], rx['hmac'], chal_body)
    assert not ok and reason == 'not-verdict'
    assert paw.display is None and paw.outstanding == outstanding


def test_verdict_wrong_nonce_ignored():
    """SUCCESS echoing another cycle's nonce: ignored, outstanding kept,
    and the real verdict still accepted afterwards."""
    k_mac, k_enc = kdf(MASTER, b'MAC'), kdf(MASTER, b'ENC')
    paw = PawVerdict(k_mac, k_enc)
    outstanding = os.urandom(8)
    paw.on_response_sent(outstanding)
    vnonce = os.urandom(8)
    wire, _ = _verdict_vec(k_mac, k_enc, 0x03, 50, vnonce, os.urandom(8))
    rx = parse_packet(wire)
    ok, reason = paw.on_packet(rx['msg_type'], rx['seq'], rx['nonce'],
                               rx['payload'], rx['hmac'], wire[:-8])
    assert not ok and reason == 'bind'
    assert paw.display is None and paw.outstanding == outstanding
    wire2, _ = _verdict_vec(k_mac, k_enc, 0x03, 51, os.urandom(8), outstanding)
    rx2 = parse_packet(wire2)
    ok, _ = paw.on_packet(rx2['msg_type'], rx2['seq'], rx2['nonce'],
                          rx2['payload'], rx2['hmac'], wire2[:-8])
    assert ok and paw.display == 'granted' and paw.outstanding is None


def test_verdict_failure_bound():
    """FAILURE for the outstanding cycle denies; a replayed verdict for a
    consumed cycle is ignored (outstanding cleared)."""
    k_mac, k_enc = kdf(MASTER, b'MAC'), kdf(MASTER, b'ENC')
    paw = PawVerdict(k_mac, k_enc)
    outstanding = os.urandom(8)
    paw.on_response_sent(outstanding)
    wire, _ = _verdict_vec(k_mac, k_enc, 0x04, 51, os.urandom(8), outstanding)
    rx = parse_packet(wire)
    ok, _ = paw.on_packet(rx['msg_type'], rx['seq'], rx['nonce'],
                          rx['payload'], rx['hmac'], wire[:-8])
    assert ok and paw.display == 'denied'
    ok, reason = paw.on_packet(rx['msg_type'], rx['seq'], rx['nonce'],
                               rx['payload'], rx['hmac'], wire[:-8])
    assert not ok  # consumed cycle: no double-act


def test_resync_source_guards():
    """Review guards: resync exists and is gated by freshness binding;
    verdicts carry encrypted echo; PAW tracks the outstanding cycle and
    type-gates before treating anything as a verdict."""
    hdr = (ROOT / 'shared/shallot_protocol.h').read_text()
    assert 'void resync(uint32_t seqNum)' in hdr
    assert 'verify_echo_binding' in hdr
    edge = (ROOT / 'plc/edge-challenge-response/edge-challenge-response.ino').read_text()
    assert 'verify_echo_binding(keys, response.payload' in edge
    assert 'seqWhitelist.resync(response.seqNum)' in edge
    assert 'aes_ctr_crypt(keys.k_enc, pkt.seqNum, pkt.nonce, pkt.payload' in edge
    paw = (ROOT / 'id-kort/paw-challenge-response/paw-challenge-response.ino').read_text()
    assert 'seqWhitelist.resync(challenge.seqNum)' in paw
    assert 'awaitingVerdict' in paw and 'outstandingNonce' in paw
    assert 'verdict.msgType != MSG_SUCCESS && verdict.msgType != MSG_FAILURE' in paw
    assert 'verify_echo_binding(keys, verdict.payload' in paw
