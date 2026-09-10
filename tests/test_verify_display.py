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
                  '#include <EpdText.h>'):
        assert token in PAW, f'missing: {token}'
    # E3 is emitted only after the render completes (commit), never before.
    disp_block = PAW[PAW.index('if (epd.updateDone()) {'):]
    disp_block = disp_block[:disp_block.index('return ENV_DONE')]
    assert 'envHexEmit("E3:"' in disp_block


def test_mpu_display_plumbing():
    assert 'timeout_s=75' in MPU  # cold-panel double render budget
    assert '_envelope_wait_e3' in MPU
    assert 'RESULT:OK' in MPU and 'RESULT:FAIL' in MPU
    assert 'envelope_display_fail' in MPU
    assert 'operator_confirm' in MPU
    code = re.sub(r'#.*', '', MPU)
    for word in ('sec_M', 'sec_P', 'op_key', 'x25519', 'X25519', 'hkdf',
                 'HKDF', 'gcm_seal', 'gcm_open', 'KEK', 'aesKey'):
        assert word not in code, f'MPU names key material: {word}'


def _mpu_function(name):
    """Load a pure helper out of the MPU script (which is not importable
    on host: it needs arduino.app_utils). Fails if the helper gains
    module-level dependencies, keeping it testable by construction."""
    import ast
    tree = ast.parse((ROOT / 'key-authority/uno-q-key-authority-mpu' /
                      'uno-q-key-authority-mpu.py').read_text())
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == name:
            ns = {}
            exec(compile(ast.Module(body=[node], type_ignores=[]),
                         '<mpu>', 'exec'), ns)
            return ns[name]
    raise AssertionError(f'MPU helper missing: {name}')


def test_operator_confirm_proof_of_reading():
    oc = _mpu_function('operator_confirm')
    calls = []

    def reader_ok(prompt):
        calls.append(prompt)
        return 'ca01'

    assert oc('3b4bd122b0fcca01', reader_ok) is True
    assert len(calls) == 1  # first try, no retries needed

    answers = iter(['0000', ' ca01 '])
    assert oc('3b4bd122b0fcca01', lambda p: next(answers)) is True

    assert oc('3b4bd122b0fcca01', lambda p: '') is False  # abort

    def reader_eof(prompt):
        raise EOFError

    assert oc('3b4bd122b0fcca01', reader_eof) is False
    assert oc('3b4bd122b0fcca01', lambda p: 'zzzz') is False  # 3 strikes


def test_operator_confirm_gates_confirmation():
    """The human gate sits between auto-match and env_confirm: no
    proof-of-reading, no confirmation, no RESULT:OK."""
    idx_match = MPU.index('if paw_verify != verify:')
    idx_gate = MPU.index('if not operator_confirm(paw_verify):')
    idx_confirm = MPU.index('Bridge.call("env_confirm"')
    assert idx_match < idx_gate < idx_confirm
    gate_block = MPU[idx_gate:MPU.index('confirmed = Bridge.call')]
    assert 'RESULT:FAIL' in gate_block
    assert 'envelope_operator_abort' in gate_block


# ---------------------------------------------------------------- mirror

class EnvGlassMirror:
    """Glass/session lifecycle mirror of pollEnvelope (firmware behavior).

    Crypto core is real (_envelope_lib); glass + session state machine
    mirrors the firmware phases. Glass log holds ("VERIFY", hex16) or
    ("WORD", state); serial log holds emitted lines; events holds E3 /
    DISP outcomes for MPU-side assertions.
    """

    E2_TIMEOUT = 10.0
    # Measurement bound; tune down together with the firmware define.
    DISP_TIMEOUT = 60.0

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
        # Render pipeline mirror (firmware one-slot queue): a frame is
        # in_flight while the panel is busy; a second request waits.
        self.in_flight = None
        self.queued = []
        self.degraded = False

    @staticmethod
    def _fw_ms(name):
        m = re.search(r'#define\s+%s\s+(\d+)' % name, PAW)
        assert m, name
        return int(m.group(1))

    def _show_word(self, word):
        """Glass word via the render pipeline: immediate when the panel is
        idle, queued behind the in-flight frame otherwise (firmware
        showEnvWord behaves exactly so)."""
        if self.in_flight is None and not self.degraded:
            self.glass.append(('WORD', word))
        else:
            self.queued.append(('WORD', word))

    def command(self, line):
        if line == 'FIXTURE':
            self.fixture = True
            return
        if line == 'CANCEL':
            if self.phase != 'IDLE' or self.staged is not None:
                if self.in_flight == 'VERIFY' and self.pending_verify:
                    # The VERIFY frame was already on the panel/in flight:
                    # visible transiently, then overwritten below.
                    self.glass.append(('VERIFY', self.pending_verify))
                self._wipe()
                self.phase = 'IDLE'
                self._show_word('CANCELLED')
            return
        if line.startswith('RESULT:'):
            if self.committed:
                if line == 'RESULT:OK':
                    self._show_word('VERIFIED')
                else:
                    self.key = None
                    self.committed = False
                    self._show_word('REJECTED')
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
            # No glass render at START by firmware design (speed): the
            # glass keeps the previous result word until VERIFY.

    def _complete_flight(self, ok):
        """Finish the in-flight frame; start the queued one if any."""
        tag = self.in_flight
        self.in_flight = None
        if not ok:
            self.degraded = True
            self.queued = []
            return None
        if isinstance(tag, tuple):
            self.glass.append(tag)
        if self.queued:
            nxt = self.queued.pop(0)
            self.in_flight = nxt
            return nxt
        return None

    def deliver_e2(self, e2):
        assert self.phase == 'E2'
        try:
            pt, ver = self.paw.open(e2)
        except EnvelopeError:
            self._wipe()
            self.phase = 'IDLE'
            self._show_word('REJECTED')
            return
        self.staged = pt
        # Value staged for the glass but NOT shown: the operator sees it
        # only when its render completes. Serial goes out immediately.
        self.pending_verify = ver
        self.serial.append(f'VERIFY:{ver}')
        if self.degraded:
            # Panel already dead: firmware fails at render start.
            self._wipe()
            self.pending_verify = None
            self.phase = 'IDLE'
            self.events.append('DISP:FAIL')
            return
        if self.in_flight is None:
            self.in_flight = 'VERIFY'
        else:
            # SESSION render still running: VERIFY waits its turn.
            self.queued.append('VERIFY')
        self.phase = 'DISP'
        self.t0 = self.t

    def render_done(self, ok):
        assert self.in_flight is not None
        self._complete_flight(ok)
        if self.degraded:
            if self.phase == 'DISP':
                self._wipe()
                self.pending_verify = None
                self.phase = 'IDLE'
                self.events.append('DISP:FAIL')
            return
        if self.phase == 'DISP' and self.in_flight is None \
                and self.pending_verify is not None:
            # The VERIFY render just completed: commit.
            self.glass.append(('VERIFY', self.pending_verify))
            self.pending_verify = None
            self.key = self.staged
            self.committed = True
            self.events.append('E3')
            self.events.append('DISP:OK')
            self.phase = 'IDLE'
        # Otherwise the completed frame was SESSION's (glass updated inside
        # _complete_flight) and VERIFY is now rendering.

    def tick(self, dt):
        self.t += dt
        if self.phase == 'E2' and self.t - self.t0 > self.E2_TIMEOUT:
            self._wipe()
            self.phase = 'IDLE'
            self._show_word('TIMED OUT')
        elif self.phase == 'DISP' and self.t - self.t0 > self.DISP_TIMEOUT:
            self._wipe()
            self.phase = 'IDLE'
            self.events.append('DISP:FAIL')
            self._show_word('TIMED OUT')

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
    assert m.glass == []  # staged, not yet shown
    assert m.events == []
    m.render_done(True)  # VERIFY completes: commit
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
    assert m.events == [] and m.key is None and not m.committed
    assert m.serial == []
    assert m.glass == [('WORD', 'REJECTED')]
    shown = [v for k, v in m.glass if k == 'VERIFY']
    assert shown == [], 'tampered session must never reach the glass'
    assert m.glass[-1] == ('WORD', 'REJECTED')


def test_mirror_timeout_and_cancel():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    m.tick(11.0)
    assert m.glass == [('WORD', 'TIMED OUT')]
    assert m.events == [] and m.key is None

    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    m.command('CANCEL')
    assert m.glass == [('WORD', 'CANCELLED')]
    assert m.key is None and m.events == []

    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, ver = _wrap_for(m)
    m.deliver_e2(e2)
    m.command('CANCEL')  # preempt during DISP
    assert m.key is None and 'E3' not in m.events
    m.render_done(True)  # in-flight VERIFY finishes...
    m.render_done(True)  # ...then CANCELLED overwrites it
    assert m.glass[-1] == ('WORD', 'CANCELLED')
    assert ('VERIFY', ver) in m.glass, \
        'cancelled-after-open flashes the value but must overwrite it'


def test_mirror_degraded_render():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, ver = _wrap_for(m)
    m.deliver_e2(e2)
    assert m.serial == [f'VERIFY:{ver}']  # serial still emitted
    m.render_done(False)  # VERIFY render dies
    assert m.events == ['DISP:FAIL']
    assert m.key is None and not m.committed
    assert all(v != ver for k, v in m.glass if k == 'VERIFY')

    # Panel already dead when E2 arrives (begin-failure modelled by preset
    # degraded flag): fail at render start.
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    m.degraded = True
    e2, _ = _wrap_for(m)
    m.deliver_e2(e2)
    assert m.events == ['DISP:FAIL']
    assert m.key is None and not m.committed


def test_mirror_disp_timeout_overwrites_stale():
    m = EnvGlassMirror()
    m.command('FIXTURE')
    m.command('ENVELOPE_START')
    e2, _ = _wrap_for(m)
    m.deliver_e2(e2)
    m.tick(m.DISP_TIMEOUT + 1.0)
    assert 'DISP:FAIL' in m.events
    m.render_done(True)  # wedged VERIFY finishes...
    m.render_done(True)  # ...then TIMED OUT overwrites it
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


def _hamming(a, b):
    return sum(bin(x ^ y).count('1') for x, y in zip(a, b))


def test_font_hex_glyphs_not_confusable():
    """Glyph accuracy is ceremony security: the operator distinguishes all
    16 hex chars by eye on e-paper (3x scale, ghosting). Minimum pairwise
    distance is a/e at 4 bits (top-bar vs descender-tail position), i.e. at
    least 4x9=36 physical pixels differ between any two chars. A font edit
    that closes this gap fails here and must be re-justified, not just
    re-pinned: below 4 bits two values become operator-confusable and a
    substituted envelope could pass comparison."""
    rows = _font_rows()
    glyphs = {c: rows[ord(c) - 0x20] for c in '0123456789abcdef'}
    worst = min(
        (_hamming(glyphs[a], glyphs[b]), a, b)
        for i, a in enumerate('0123456789abcdef')
        for b in '0123456789abcdef'[i + 1:]
    )
    assert worst[0] >= 4, f'confusable pair {worst[1]}/{worst[2]}: {worst[0]} bits'
    assert (worst[1], worst[2]) == ('a', 'e'), f'changed worst pair: {worst}'
