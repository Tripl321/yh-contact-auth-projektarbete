"""
Phase 1 envelope mirror (docs/12-envelope-protocol.md).

Builds envelope.so from libraries/EnvelopeCrypto + tests/envelope_wrap.c and
exposes the REAL C primitives (X25519 / AES-GCM / HKDF) via ctypes. The
protocol logic (AAD assembly, epoch rule, all-zero check) mirrors the spec so
Phase 2 firmware has a byte-exact reference; the golden vector in
test_envelope.py pins the wire bytes.
"""
import ctypes
import hashlib
import os
import struct
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CRYPTO = os.path.join(REPO, 'libraries', 'EnvelopeCrypto')
WRAP_SRC = os.path.join(REPO, 'tests', 'envelope_wrap.c')
BUILD_DIR = os.path.join(REPO, 'tests', 'build')
SO_PATH = os.path.join(BUILD_DIR, 'envelope.so')

# Proven link set (identical to the vetted host .so; aes_ct_cbcenc.c is not
# part of the GCM path and is excluded here, as in vetting).
_C_SOURCES = [
    'aes_ct.c', 'aes_ct_ctr.c', 'aes_ct_enc.c', 'gcm.c', 'ghash_ctmul.c',
    'sha2small.c', 'hmac.c', 'hkdf.c', 'dec32be.c', 'enc32be.c', 'ccopy.c',
    'ec_c25519_i15.c',
    'i15_add.c', 'i15_bitlen.c', 'i15_decmod.c', 'i15_decode.c',
    'i15_decred.c', 'i15_encode.c', 'i15_fmont.c', 'i15_iszero.c',
    'i15_moddiv.c', 'i15_modpow.c', 'i15_modpow2.c', 'i15_montmul.c',
    'i15_mulacc.c', 'i15_muladd.c', 'i15_ninv15.c', 'i15_reduce.c',
    'i15_rshift.c', 'i15_sub.c', 'i15_tmont.c',
]

DOMAIN = b'SHALLOT-ENV1'
VER = 0x01
KEK_INFO_V2 = b'SHALLOT-ENV1/KEK-v2'
# v0.1 label retained only to prove domain separation (old KEKs never collide).
KEK_INFO_V1 = b'SHALLOT-ENV1/KEK'
E1_TAG, E2_TAG = 0xB1, 0xB2
E1_LEN, E2_LEN, AAD_LEN = 45, 81, 106


class EnvelopeError(Exception):
    pass


def _build_so():
    srcs = [os.path.join(CRYPTO, 'src', s) for s in _C_SOURCES] + [WRAP_SRC]
    missing = [s for s in srcs if not os.path.exists(s)]
    if missing:
        raise EnvelopeError('missing C sources: %s' % missing)
    rebuild = (not os.path.exists(SO_PATH) or
               any(os.path.getmtime(s) > os.path.getmtime(SO_PATH) for s in srcs))
    if rebuild:
        os.makedirs(BUILD_DIR, exist_ok=True)
        cc = os.environ.get('CC', 'cc')
        cmd = ([cc, '-std=c99', '-fPIC', '-shared', '-O2',
                '-I', os.path.join(CRYPTO, 'inc'),
                '-I', os.path.join(CRYPTO, 'src'),
                '-o', SO_PATH] + srcs)
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise EnvelopeError('C build failed:\n%s' % r.stderr)
    return ctypes.CDLL(SO_PATH)


_lib = _build_so()

_lib.env_x25519_pub.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.env_x25519_pub.restype = ctypes.c_uint32
_lib.env_x25519_dh.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p]
_lib.env_x25519_dh.restype = ctypes.c_uint32
_lib.env_gcm_seal.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_size_t, ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_size_t, ctypes.c_char_p]
_lib.env_gcm_seal.restype = ctypes.c_int
_lib.env_gcm_open.argtypes = _lib.env_gcm_seal.argtypes
_lib.env_gcm_open.restype = ctypes.c_int
_lib.env_hkdf.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p,
                          ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t,
                          ctypes.c_char_p, ctypes.c_size_t]
_lib.env_hkdf.restype = None
_lib.env_hkdf_kek.argtypes = [ctypes.c_char_p, ctypes.c_char_p,
                              ctypes.c_char_p, ctypes.c_size_t,
                              ctypes.c_char_p, ctypes.c_size_t]
_lib.env_hkdf_kek.restype = None


def x25519_pub(sec):
    out = ctypes.create_string_buffer(32)
    if _lib.env_x25519_pub(out, bytes(sec)) != 1:
        raise EnvelopeError('x25519_pub failed')
    return out.raw


def x25519_dh(sec, peer):
    out = ctypes.create_string_buffer(32)
    if _lib.env_x25519_dh(out, bytes(sec), bytes(peer)) != 1:
        raise EnvelopeError('x25519_dh failed')
    return out.raw


def gcm_seal(key, iv, aad, pt):
    ct = ctypes.create_string_buffer(len(pt))
    tag = ctypes.create_string_buffer(16)
    _lib.env_gcm_seal(bytes(key), bytes(iv), bytes(aad), len(aad),
                      bytes(pt), ct, len(pt), tag)
    return ct.raw, tag.raw


def gcm_open(key, iv, aad, ct, tag):
    pt = ctypes.create_string_buffer(len(ct))
    ok = _lib.env_gcm_open(bytes(key), bytes(iv), bytes(aad), len(aad),
                           bytes(ct), pt, len(ct), bytes(tag))
    return pt.raw if ok == 1 else None


def hkdf(salt, ikm, info, out_len):
    out = ctypes.create_string_buffer(out_len)
    _lib.env_hkdf(out, out_len, bytes(salt), len(salt),
                  bytes(ikm), len(ikm), bytes(info), len(info))
    return out.raw


def kek_salt(aad):
    """Spec v0.2: salt is SHA256 of the session AAD (transcript hash)."""
    return hashlib.sha256(bytes(aad)).digest()


def hkdf_kek(shared, salt, info=KEK_INFO_V2):
    out = ctypes.create_string_buffer(16)
    _lib.env_hkdf_kek(out, bytes(shared), bytes(salt), len(bytes(salt)),
                      bytes(info), len(bytes(info)))
    return out.raw


def is_all_zero(buf):
    """Mirror of the firmware data-independent all-zero check."""
    acc = 0
    for b in bytes(buf):
        acc |= b
    return acc == 0


def build_aad(target_id, device_id, epoch, pub_p, pub_m, nonce_p, nonce_m):
    aad = (DOMAIN + bytes([VER, target_id]) + bytes(device_id) +
           struct.pack('>I', epoch) + bytes(pub_p) + bytes(pub_m) +
           bytes(nonce_p) + bytes(nonce_m))
    assert len(aad) == 106
    return aad


def verify_value(pub_p, pub_m):
    return hashlib.sha256(bytes([E1_TAG]) + bytes(pub_p) + bytes(pub_m)).hexdigest()[:16]


def encode_e1(device_id, pub_p, nonce_p):
    assert len(bytes(device_id)) == 4
    assert len(pub_p) == 32 and len(nonce_p) == 8
    return (bytes([E1_TAG]) + bytes(device_id) + bytes(pub_p) +
            bytes(nonce_p))


def parse_e1(frame):
    """Strict 45 B E1 parse (spec §4)."""
    frame = bytes(frame)
    if len(frame) != 45 or frame[0] != E1_TAG:
        raise EnvelopeError('bad E1 frame')
    return {'device_id': frame[1:5], 'pub_p': frame[5:37],
            'nonce_p': frame[37:45]}


def frame_line(prefix, blob):
    """USB hex-line framing (spec §4): 'E1:<hex>\\n' etc."""
    return f'{prefix}:{bytes(blob).hex()}\n'


def parse_line(line, prefix, blob_len):
    """Strict USB hex-line parse; raises on any deviation."""
    line = str(line).strip()
    if not line.startswith(prefix + ':'):
        raise EnvelopeError('bad line prefix')
    body = line[len(prefix) + 1:]
    if len(body) != 2 * blob_len:
        raise EnvelopeError('bad line length')
    try:
        return bytes.fromhex(body)
    except ValueError:
        raise EnvelopeError('bad line hex')


def parse_e2(frame):
    """MPU relay view: public fields only, fixed 81 B."""
    frame = bytes(frame)
    if len(frame) != 81 or frame[0] != E2_TAG:
        raise EnvelopeError('bad E2 frame')
    return {'epoch': struct.unpack('>I', frame[1:5])[0],
            'pub_m': frame[5:37], 'nonce_m': frame[37:49],
            'ct': frame[49:65], 'tag': frame[65:81]}


def mcu_wrap(target_id, e1, epoch, op_key, sec_m, nonce_m):
    """MCU side mirror of envelopeWrap: parses E1, then DH + zero-check +
    KEK + seal. Returns E2 bytes + VERIFY."""
    f1 = parse_e1(e1)
    shared = x25519_dh(sec_m, f1['pub_p'])
    if is_all_zero(shared):
        raise EnvelopeError('degenerate shared secret (MCU)')
    pub_m = x25519_pub(sec_m)
    aad = build_aad(target_id, f1['device_id'], epoch,
                    f1['pub_p'], pub_m, f1['nonce_p'], nonce_m)
    ct, tag = gcm_seal(hkdf_kek(shared, kek_salt(aad)), nonce_m, aad, op_key)
    e2 = (bytes([E2_TAG]) + struct.pack('>I', epoch) + pub_m +
          bytes(nonce_m) + ct + tag)
    return e2, verify_value(f1['pub_p'], pub_m)


class PawSession:
    """PAW side mirror with SRAM epoch state."""

    def __init__(self, target_id, device_id, sec_p, nonce_p):
        self.target_id = target_id
        self.device_id = bytes(device_id)
        self.sec_p = bytes(sec_p)
        self.nonce_p = bytes(nonce_p)
        self.pub_p = x25519_pub(sec_p)
        self.last_epoch = None

    def e1(self):
        return encode_e1(self.device_id, self.pub_p, self.nonce_p)

    def open(self, e2):
        f = parse_e2(e2)
        if self.last_epoch is not None and f['epoch'] <= self.last_epoch:
            raise EnvelopeError('epoch rule violated')
        shared = x25519_dh(self.sec_p, f['pub_m'])
        if is_all_zero(shared):
            raise EnvelopeError('degenerate shared secret (PAW)')
        aad = build_aad(self.target_id, self.device_id, f['epoch'],
                        self.pub_p, f['pub_m'], self.nonce_p, f['nonce_m'])
        pt = gcm_open(hkdf_kek(shared, kek_salt(aad)), f['nonce_m'], aad,
                      f['ct'], f['tag'])
        if pt is None:
            raise EnvelopeError('tag verify failed')
        self.last_epoch = f['epoch']
        return pt, verify_value(self.pub_p, f['pub_m'])
