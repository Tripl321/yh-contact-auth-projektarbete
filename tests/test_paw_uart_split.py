"""
PAW transport split: Mama Bear provisioning on USB Serial, DEN dock
exclusively on Serial1 (GPIO0/1). No parser may touch the other
transport. Mirrors the steady-state behavior (provisioning parser on
USB bytes, dock parser on UART bytes) plus source guards pinning the
split in paw-main.ino.
"""
import re


class MockTransportSplit:
    """Two independent byte streams; each parser sees only its own."""

    def __init__(self):
        self.usb_in = bytearray()   # Mama Bear -> PAW (provisioning)
        self.uart_in = bytearray()  # DEN -> PAW (dock)
        self.usb_out = bytearray()
        self.uart_out = bytearray()
        self.key_stored = False
        self.dock_answers = 0

    def provisioning_poll(self):
        """Mirror of receiveKeyFromUNOQ: reads USB Serial only."""
        if len(self.usb_in) >= 2 and self.usb_in[:1] == b'\xa1':
            self.usb_in = self.usb_in[2:]
            self.key_stored = True  # valid handshake+key assumed staged
            self.usb_out += b'\xa2'
            return True
        return False

    def dock_poll(self, valid_challenge=False):
        """Mirror of handleDockAuth: reads Serial1 only."""
        if self.uart_in[:1] == b'\xaa' and valid_challenge:
            self.uart_in = self.uart_in[1:]
            self.uart_out += b'\x02'  # RESPONSE tag
            self.dock_answers += 1
            return True
        return False


def test_split_streams_independent():
    m = MockTransportSplit()
    m.usb_in += b'\xa1\x02'
    m.uart_in += b'\xaa\x10\x00\x01'
    assert m.provisioning_poll()
    assert m.key_stored
    assert m.usb_out == b'\xa2' and m.uart_out == b''
    assert m.dock_poll(valid_challenge=True)
    assert m.dock_answers == 1 and m.uart_out == b'\x02'


def test_split_dock_ignores_usb_noise():
    """USB provisioning bytes never reach the dock parser and vice versa."""
    m = MockTransportSplit()
    m.usb_in += b'\xa1\x02'
    assert not m.dock_poll(valid_challenge=False)
    assert m.dock_answers == 0
    assert m.uart_in == b'' and m.uart_out == b''


def _paw_src():
    import pathlib
    return (pathlib.Path(__file__).resolve().parent.parent /
            'id-kort/paw-main/paw-main.ino').read_text()


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


def test_split_provisioning_on_usb_only():
    """Source guard: provisioning touches USB Serial, never Serial1."""
    src = _paw_src()
    start, end = _function_range(src, 'bool receiveKeyFromUNOQ()')
    body = re.sub(r'//.*', '', '\n'.join(src.splitlines()[start:end + 1]))
    assert 'Serial1.' not in body
    for api in ('Serial.available()', 'Serial.read(', 'Serial.readBytes',
                'Serial.write(', 'Serial.flush()'):
        assert api in body, f'provisioning lost USB Serial use: {api}'


def test_split_dock_on_serial1_only():
    """Source guard: dock handler touches Serial1, never USB reads."""
    src = _paw_src()
    start, end = _function_range(src, 'static void handleDockAuth()')
    body = '\n'.join(src.splitlines()[start:end + 1])
    assert 'Serial1.available()' in body and 'Serial1.read(' in body
    for api in ('Serial.available()', 'Serial.read(', 'Serial.readBytes',
                'Serial.peek()'):
        assert api not in body, f'dock handler touches USB: {api}'


def test_split_no_debug_simulator():
    """Source guard: the legacy USB-Serial debug simulator (which ate
    arbitrary USB bytes) is gone — USB reads belong to provisioning."""
    src = _paw_src()
    assert 'Debug Serial' not in src
    assert 'Serial fallback' not in src


def test_split_single_serial1_begin():
    """Source guard: Serial1 init once at 115200 with UART0 defaults."""
    src = _paw_src()
    code = re.sub(r'//.*', '', src)
    assert code.count('Serial1.begin(') == 1
    assert 'Serial1.begin(115200)' in src
    assert 'setTX(' not in src and 'setRX(' not in src


def test_epd_busy_wait_bounded():
    """Source guard (integration defect PRO-52): BUSY may only be polled
    inside the bounded wait — a stuck panel must degrade, never hang
    UART/LoRa. Exactly one BUSY poll site, guarded by a timeout."""
    src = _paw_src()
    assert 'EPD_BUSY_TIMEOUT_MS' in src
    assert 'bool waitUntilIdle(uint32_t timeoutMs' in src
    assert src.count('digitalRead(EPD_BUSY_PIN) == HIGH') == 1
    assert 'millis() - t0 > timeoutMs' in src
