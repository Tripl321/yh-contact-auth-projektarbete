"""
PAW Serial1 ownership: mutually exclusive provisioning/operational modes.

Mirror of the mode dispatch in paw-main.ino: exactly one parser consumes
Serial1 per loop pass — handleProvisioning() without a stored key,
handleDockAuth() with one. The inactive handler never runs, so it can
neither inspect nor consume UART bytes. Boot always starts provisioning
(SRAM holds no key); success switches to operational (logged).
"""
import re

MODE_BOOT = 'PROVISIONING'
MODE_OPS = 'OPERATIONAL'


class MockPawModes:
    """Mirror of loop() dispatch + both handlers' Serial1 accounting."""

    def __init__(self):
        self.key_stored = False  # hasValidStoredKey()
        self.reads = []  # ('prov'|'dock', n_bytes) per loop pass
        self.log = ['Boot mode: PROVISIONING (no stored key)']
        self.mode = MODE_BOOT
        self.dock_answers = 0

    def loop_pass(self, uart_bytes=b'', provision_ok=False,
                  dock_frame_valid=False):
        prov_reads = dock_reads = 0
        if not self.key_stored:
            # handleProvisioning(): sole reader.
            prov_reads = len(uart_bytes)
            if provision_ok and uart_bytes:
                self.key_stored = True
                self.mode = MODE_OPS
                self.log.append('Mode: OPERATIONAL (key stored, dock responder owns Serial1)')
            # Invalid/incomplete/malformed: key untouched, mode unchanged.
        else:
            # handleDockAuth(): sole reader.
            dock_reads = len(uart_bytes)
            if dock_frame_valid and uart_bytes:
                self.dock_answers += 1
        self.reads.append((prov_reads, dock_reads))

    def assert_single_reader(self):
        for prov, dock in self.reads:
            assert (prov > 0) != (dock > 0) or (prov == dock == 0), \
                'both parsers consumed Serial1 in one pass'


def test_modes_boot_is_provisioning():
    m = MockPawModes()
    assert m.mode == MODE_BOOT
    assert m.log[0].startswith('Boot mode: PROVISIONING')


def test_modes_exclusive_readers():
    m = MockPawModes()
    m.loop_pass(uart_bytes=b'\xaa\x10')  # provisioning reads
    m.loop_pass(uart_bytes=b'')  # idle: neither reads
    m.key_stored = True  # (driven by test; transition covered below)
    m.mode = MODE_OPS
    m.loop_pass(uart_bytes=b'\xaa\x10', dock_frame_valid=True)  # dock reads
    m.assert_single_reader()
    kinds = [('prov' if p else 'dock' if d else 'none') for p, d in m.reads]
    assert kinds == ['prov', 'none', 'dock']


def test_modes_invalid_provisioning_keeps_mode():
    """Garbage during provisioning: no key, no transition, dock silent."""
    m = MockPawModes()
    m.loop_pass(uart_bytes=b'\x00\xffgarbage', provision_ok=False)
    assert not m.key_stored and m.mode == MODE_BOOT
    assert m.dock_answers == 0
    m.assert_single_reader()


def test_modes_transition_on_success():
    m = MockPawModes()
    m.loop_pass(uart_bytes=b'\xa1\x02...', provision_ok=True)
    assert m.key_stored and m.mode == MODE_OPS
    assert m.log[-1].startswith('Mode: OPERATIONAL')
    # Next pass the dock parser owns Serial1 (provisioning parked).
    m.loop_pass(uart_bytes=b'\xaa\x10\x00\x01', dock_frame_valid=True)
    assert m.dock_answers == 1
    m.assert_single_reader()


def _function_range(src, signature):
    """(start, end) line indexes of a function body via brace matching."""
    lines = src.splitlines()
    start = next(i for i, l in enumerate(lines) if signature in l)
    depth = 0
    begun = False
    for i in range(start, len(lines)):
        depth += lines[i].count('{') - lines[i].count('}')
        if '{' in lines[i]:
            begun = True
        if begun and depth == 0:
            return start, i
    raise AssertionError('unbalanced: ' + signature)


def _paw_src():
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent /
            'id-kort/paw-main/paw-main.ino').read_text()


def test_modes_dispatch_shape():
    """Source guard: loop dispatches exactly one handler per pass."""
    src = _paw_src()
    code = re.sub(r'//.*', '', src)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    norm = re.sub(r'\s+', ' ', code)
    assert re.search(r'if\s*\(!hasValidStoredKey\(\)\)\s*\{\s*'
                     r'handleProvisioning\(\);\s*\}\s*else\s*\{\s*'
                     r'handleDockAuth\(\);\s*\}', norm), 'dispatch shape changed'
    assert 'static inline bool hasValidStoredKey()' in src
    assert code.count('handleProvisioning();') == 1  # dispatch only
    assert code.count('handleDockAuth();') == 1  # dispatch only
    assert code.count('if (receiveKeyFromUNOQ())') == 2  # setup + handleProvisioning


def test_modes_single_reader_by_scope():
    """Source guard: Serial1 read/availability APIs appear ONLY inside the
    two owner functions (provisioning + dock-auth)."""
    src = _paw_src()
    lines = src.splitlines()
    prov = _function_range(src, 'bool receiveKeyFromUNOQ()')
    dock = _function_range(src, 'static void handleDockAuth()')
    apis = ('Serial1.available()', 'Serial1.read(', 'Serial1.readBytes', 'Serial1.peek()')
    for i, line in enumerate(lines):
        if any(a in line for a in apis):
            inside = (prov[0] <= i <= prov[1]) or (dock[0] <= i <= dock[1])
            assert inside, f'Serial1 read outside owners at line {i + 1}: {line.strip()}'


def test_modes_logging():
    """Source guard: mode logged at boot and on change."""
    src = _paw_src()
    assert 'Boot mode: PROVISIONING' in src
    assert src.count('Mode: OPERATIONAL (key stored, dock responder owns Serial1)') == 2
