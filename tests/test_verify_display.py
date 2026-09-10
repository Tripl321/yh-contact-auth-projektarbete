"""
VERIFY glass ceremony (docs/12-envelope-protocol.md v0.2 + fixture display).

Proves, through the REAL vendored C plus source guards on the firmware:
- the full 16-hex VERIFY reaches the display callsite only for a valid
  active session (same buffer as the serial line, never truncated);
- no key material is nameable from the display path;
- timeout / tamper / cancel / degraded paths fail closed with the right
  glass state and never commit or emit E3.

Firmware logic is mirrored (repo precedent: test_paw_uart_split.py) in
EnvGlassMirror; firmware↔mirror constants are cross-checked so the mirror
cannot drift silently.
"""
import pathlib
import re

import pytest

from _envelope_lib import (
    E1_LEN, E2_LEN, EnvelopeError, PawSession, frame_line, mcu_wrap,
    parse_e2, parse_line,
)

ROOT = pathlib.Path(__file__).resolve().parent.parent
PAW = (ROOT / 'id-kort/paw-main/paw-main.ino').read_text()
MPU = (ROOT / 'key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py').read_text()
FONT_H = (ROOT / 'libraries/EpdText/src/EpdText.h').read_text()

T_SEC_P = bytes(range(1, 33))
T_NONCE_P = bytes(range(0xA0, 0xA8))
T_SEC_M = bytes(range(0x40, 0x60))
T_NONCE_M = bytes(range(0x10, 0x1C))
T_OP = bytes(range(0xD0, 0xE0))
T_DEV = b'PAW\x01'


def _function_range(src, signature):
    lines = src.splitlines()
    start = next(i for i, l in enumerate(lines) if signature in l)
    depth, begun = 0, False
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if '{' in lines[i]:
            begun = True
        if begun and depth == 0:
            return start, i
    raise AssertionError('unbalanced: ' + signature)


def _body(src, signature):
    start, end = _function_range(src, signature)
    return '\n'.join(src.splitlines()[start:end + 1])


# ---------------------------------------------------------------- guards

def test_verify_reaches_glass_whole_and_once():
    """Single call site, full 16-char buffer shared with the serial line."""
    assert PAW.count('showVerifyText(envVer17)') == 1
    body = _body(PAW, 'static void showVerify(')
    assert 'Serial.print("VERIFY:")' in body
    assert 'memcpy(envVer17, ver17' in body
    assert 'showVerifyText(envVer17)' in body
    # Definition order: value computed from the live session pubs only
    # after a successful open, then shown.
    assert PAW.index('if (!env_open(kek') < PAW.index('showVerify(ver17)')
    assert PAW.index('env_verify_hex(envPubP, pubM, ver17)') < \
        PAW.index('showVerify(ver17)')


def test_verify_layout_covers_all_16():
    """EPDT_VERIFY_COLS * ROWS == 16: nothing truncated, icons never a
    substitute (both rows always drawn from the same buffer)."""
    defs = dict(re.findall(r'#define\s+(EPDT_\w+)\s+(\d+)', FONT_H))
    assert int(defs['EPDT_VERIFY_COLS']) == 8
    assert int(defs['EPDT_VERIFY_ROWS']) == 2
    assert 8 * 2 == 16
    w = 8 * (5 * 3 + 3) - 3
    assert w == int(defs['EPDT_VERIFY_W']) == 141 <= 200
    assert 'memcpy(row, ver17 + EPDT_VERIFY_COLS' in PAW


def test_display_path_names_no_secrets():
    """Source guard: the glass path cannot name key material."""
    for sig in ('bool ShallotEPD::showVerifyText',
                'void ShallotEPD::showEnvWord',
                'void ShallotEPD::drawChar5x7',
                'void ShallotEPD::drawText5x7',
                'static void showVerify('):
        body = re.sub(r'//.*', '', _body(PAW, sig))
        for word in ('aesKey', 'envStage', 'kek', 'shared', 'envSecP',
                     'envPubP', 'envNonceP', 'secM', 'pubM', 'ct', 'tag'):
            assert not re.search(r'\b%s\b' % word, body), f'{sig}: {word}'
        assert not re.search(r'\bpt\b', body), f'{sig}: pt'


def test_lifecycle_tokens_present():
    for token in ('ENV_PH_DISP', 'ENV_DISP_TIMEOUT_MS', 'DISP:OK',
                  'DISP:FAIL', '"CANCEL"', '"RESULT:', 'envCommitted',
                  'envHaveStage', 'EPDT_WORD_VERIFIED', 'EPDT_WORD_REJECTED',
                  'EPDT_WORD_TIMEDOUT', 'EPDT_WORD_CANCELLED',
                  'EPDT_WORD_SESSION', '#include <EpdText.h>'):
        assert token in PAW, f'missing: {token}'
    # E3 is emitted only after the render completes (commit), never before.
    disp_block = PAW[PAW.index('if (epd.updateDone()) {'):]
    disp_block = disp_block[:disp_block.index('return ENV_DONE')]
    assert 'envHexEmit("E3:"' in disp_block


def test_mpu_display_plumbing():
    assert 'timeout_s=30' in MPU
    assert '_envelope_wait_e3' in MPU
    assert 'RESULT:OK' in MPU and 'RESULT:FAIL' in MPU
    assert 'envelope_display_fail' in MPU
    code = re.sub(r'#.*', '', MPU)
    for word in ('sec_M', 'sec_P', 'op_key', 'x25519', 'X25519', 'hkdf',
                 'HKDF', 'gcm_seal', 'gcm_open', 'KEK', 'aesKey'):
        assert word not in code, f'MPU names key material: {word}'


# ---------------------------------------------------------------- mirror

class EnvGlassMirror:
    """Glass/session lifecycle mirror of pollEnvelope (firmware behavior).

    Crypto core is real (_envelope_lib); glass + session state machine
    mirrors the firmware phases. Glass log holds ("VERIFY", hex16) or
    ("WORD", state); serial log holds emitted lines; events holds E3 /
    DISP outcomes for MPU-side assertions.
    """

    E2_TIMEOUT = 10.0
    DISP_TIMEOUT = 25.0

    def __init__(self):
        assert self.E2_TIMEOUT * 1000 == self._fw_ms('ENV_E2_TIMEOUT_MS')
        assert self.DISP_TIMEOUT * 1000 == self._fw_ms('ENV_DISP_TIMEOUT_MS')
        self.phase = 'IDLE'
        self.t = 0.0
        self.t0 = 0.0
        self.fixture = False
        self.paw = None
        self.e1 = None
        self.staged = None
        self.pending_verify = None
        self.committed = False
        self.key = None
        self.last_epoch = None
        self.glass = []
        self.serial = []
        self.events = []

    @staticmethod
    def _fw_ms(name):
        m = re.search(r'#define\s+%s\s+(\d+)' % name, PAW)
        assert m, name
        return int(m.group(1))

    def command(self, line):
        if line == 'FIXTURE':
            self.fixture = True
            return
        if line == 'CANCEL':
            if self.phase != 'IDLE' or self.staged is not None:
                self._wipe()
                self.phase = 'IDLE'
                self.glass.append(('WORD', 'CANCELLED'))
            return
        if line.startswith('RESULT:'):
            if self.committed:
                if line == 'RESULT:OK':
                    self.glass.append(('WORD', 'VERIFIED'))
                else:
                    self.key = None
                    self.committed = False
                    self.glass.append(('WORD', 'REJECTED'))
            return
        if self.phase != 'IDLE':
            return
        if line == 'ENVELOPE_START':
            assert self.fixture
            self.committed = False
            self.paw = PawSession(0x02, T_DEV, T_SEC_P, T_NONCE_P)
            self.e1 = self.paw.e1()
            self.phase = 'E2'
            self.t0 = self.t
            self.glass.append(('WORD', 'SESSION'))

    def deliver_e2(self, e2):
        assert self.phase == 'E2'
        try:
            pt, ver = self.paw.open(e2)
        except EnvelopeError:
            self._wipe()
            self.phase = 'IDLE'
            self.glass.append(('WORD', 'REJECTED'))
            return
        self.staged = pt
        # Value staged for the glass but NOT shown: the operator sees it
        # only when the render completes (render_done True).
        self.pending_verify = ver
        self.serial.append(f'VERIFY:{ver}')
        self.phase = 'DISP'
        self.t0 = self.t

    def render_done(self, ok):
        assert self.phase == 'DISP'
        if not ok:
            self._wipe()
            self.pending_verify = None
            self.phase = 'IDLE'
            self.events.append('DISP:FAIL')
            return
        self.glass.append(('VERIFY', self.pending_verify))
        self.pending_verify = None
        self.key = self.staged
        self.committed = True
        self.events.append('E3')
        self.events.append('DISP:OK')
        self.phase = 'IDLE'

    def tick(self, dt):
        self.t += dt
        if self.phase == 'E2' and self.t - self.t0 > self.E2_TIMEOUT:
            self._wipe()
            self.phase = 'IDLE'
            self.glass.append(('WORD', 'TIMED OUT'))
        elif self.phase == 'DISP' and self.t - self.t0 > self.DISP_TIMEOUT:
            self._wipe()
            self.phase = 'IDLE'
            self.events.append('DISP:FAIL')
            self.glass.append(('WORD', 'TIMED OUT'))

    def _wipe(self):
        self.staged = None
        self.pending_verify = None
        self.paw = None
        self.e1 = None


def _wrap_for(mirror, epoch=1, mutate=None):
    e2, ver = mcu_wrap(0x02, mirror.e1, epoch, T_OP, T_SEC_M, T_NONCE_M)
    if mutate:
        e2 = mutate(bytearray(e2))
    return bytes(e2), ver


def test_mirror_happy_path():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, ver = _wrap_for(m)
    m.deliver_e2(e2)
    assert m.serial == [f'VERIFY:{ver}'] and len(ver) == 16
    assert m.glass == [('WORD', 'SESSION')]  # staged, not yet shown
    assert m.events == []
    m.render_done(True)
    assert m.glass[-1] == ('VERIFY', ver)  # full value on glass
    assert m.events == ['E3', 'DISP:OK']
    assert m.key == T_OP and m.committed
    m.command('RESULT:OK')
    assert m.glass[-1] == ('WORD', 'VERIFIED')


def test_mirror_tamper_never_shows_value():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, _ = _wrap_for(m, mutate=lambda b: (b.__setitem__(55, b[55] ^ 1), b)[1])
    m.deliver_e2(e2)
    assert m.glass[-1] == ('WORD', 'REJECTED')
    assert m.events == [] and m.key is None and not m.committed
    shown = [v for k, v in m.glass if k == 'VERIFY']
    assert shown == [], 'tampered session must never reach the glass'
    assert m.serial == []


def test_mirror_timeout_and_cancel():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    m.tick(11.0)
    assert m.glass[-1] == ('WORD', 'TIMED OUT')
    assert m.events == [] and m.key is None

    m.command('ENVELOPE_START')
    m.command('CANCEL')
    assert m.glass[-1] == ('WORD', 'CANCELLED')
    assert m.key is None and m.events == []

    m.command('ENVELOPE_START')
    e2, _ = _wrap_for(m)
    m.deliver_e2(e2)
    m.command('CANCEL')  # preempt during DISP
    assert m.glass[-1] == ('WORD', 'CANCELLED')
    assert m.key is None and 'E3' not in m.events


def test_mirror_degraded_render():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, ver = _wrap_for(m)
    m.deliver_e2(e2)
    assert m.serial == [f'VERIFY:{ver}']  # serial still emitted
    m.render_done(False)  # panel dead: render never completes
    assert m.events == ['DISP:FAIL']
    assert m.key is None and not m.committed
    assert m.glass == [('WORD', 'SESSION')]  # value never reached glass
    assert all(v != ver for k, v in m.glass if k == 'VERIFY')


def test_mirror_disp_timeout_overwrites_stale():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, _ = _wrap_for(m)
    m.deliver_e2(e2)
    m.tick(26.0)
    assert 'DISP:FAIL' in m.events
    assert m.glass[-1] == ('WORD', 'TIMED OUT')  # no stale VERIFY persists
    assert m.key is None


def test_mirror_operator_reject_wipes():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, _ = _wrap_for(m)
    m.deliver_e2(e2)
    m.render_done(True)
    assert m.committed and m.key == T_OP
    m.command('RESULT:FAIL')
    assert m.key is None and not m.committed
    assert m.glass[-1] == ('WORD', 'REJECTED')


def test_mirror_result_without_commit_ignored():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('RESULT:OK')
    assert m.glass == [] and not m.committed


# ---------------------------------------------------------------- font

def _font_rows():
    rows = re.findall(r'\{0x[0-9A-Fa-f]{2}(?:,0x[0-9A-Fa-f]{2}){4}\}', FONT_H)
    assert len(rows) == 96, f'expected 96 glyphs, got {len(rows)}'
    return [[int(b, 16) for b in r.strip('{}').split(',')] for r in rows]


def test_font_covers_ceremony_alphabet():
    rows = _font_rows()
    assert not any(rows[0x20 - 0x20]), 'space must be blank advance'
    need = set('0123456789abcdefVERIFIEDJCTMOUSPALN') - {' '}
    for ch in need:
        glyph = rows[ord(ch) - 0x20]
        assert any(glyph), f'blank glyph for {ch!r}'


def test_font_hex_glyphs_distinct():
    rows = _font_rows()
    patterns = [tuple(rows[ord(c) - 0x20]) for c in '0123456789abcdef']
    assert len(set(patterns)) == 16, 'duplicate hex glyphs would mislead'
