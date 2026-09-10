"""
PRO-46 USB-C provisioning tests: MPU UsbCdcDistributor against a scripted
PAW USB receiver, plus source guards for the single-sender rule.

Wire frames (byte-identical to the legacy UART protocol, now USB-CDC):
  MPU -> PAW: 0xA1 + target | PAW -> MPU: 0xA2 + devid[4]
  MPU -> PAW: 0xA3 + len + key[16] + crc32-BE | PAW -> MPU: 0xA4 + hash[4]
"""
import binascii
import hashlib
import hmac as hmac_module
import importlib.util
import struct
import sys
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Import the MPU script with stubbed UNO Q App Lab modules (absent off-board)
# --------------------------------------------------------------------------

def _load_mpu():
    arduino_pkg = types.ModuleType('arduino')
    app_utils = types.ModuleType('arduino.app_utils')

    class FakeBridge:
        calls = []
        confirmed = []
        key_hex = ''
        fingerprint = ''
        state = 4

        @classmethod
        def reset(cls, key_hex='', fingerprint=''):
            cls.calls = []
            cls.confirmed = []
            cls.key_hex = key_hex
            cls.fingerprint = fingerprint

        @classmethod
        def call(cls, name, *args):
            cls.calls.append((name, args))
            if name == 'request_key_distribution':
                return True
            if name == 'export_staged_key':
                return cls.key_hex  # test arms this ('' until button)
            if name == 'confirm_distribution':
                cls.confirmed.append(args)
                return True
            if name == 'get_key_fingerprint':
                return cls.fingerprint
            if name == 'get_key_state':
                return cls.state
            return None

        @classmethod
        def provide(cls, *a):
            pass

        @classmethod
        def notify(cls, *a):
            pass

    class FakeApp:
        @staticmethod
        def run(user_loop=None):
            pass

    app_utils.Bridge = FakeBridge
    app_utils.App = FakeApp
    arduino_pkg.app_utils = app_utils
    sys.modules['arduino'] = arduino_pkg
    sys.modules['arduino.app_utils'] = app_utils
    path = ROOT / 'key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py'
    spec = importlib.util.spec_from_file_location('mpu_mod', str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.FakeBridge = FakeBridge
    return mod


mpu = _load_mpu()


# --------------------------------------------------------------------------
# Fakes: serial endpoint pair + scripted PAW USB receiver (mirror)
# --------------------------------------------------------------------------

class MockPawUsb:
    """Mirror of PAW receiveKeyFromUNOQ over USB Serial (fail-closed)."""

    def __init__(self, target=0x02, faults=None):
        self.target = target
        self.faults = faults or {}
        self.inbuf = bytearray()
        self.out = bytearray()
        self.stored = None

    def on_write(self, data):
        if self.faults.get('silent'):
            return
        self.inbuf += data
        while True:
            if len(self.inbuf) < 2:
                return
            if self.inbuf[0] == 0xA1 and len(self.inbuf) >= 2:
                t = self.inbuf[1]
                del self.inbuf[:2]
                if t != self.target:
                    continue
                self.out += b'\xa2' + b'PAW\x01'
                continue
            if len(self.inbuf) < 22:
                return
            frame = bytes(self.inbuf[:22])
            del self.inbuf[:22]
            if frame[0] != 0xA3 or frame[1] != 16:
                continue  # wrong tag/len: ignore, store nothing
            key, crc = frame[2:18], struct.unpack('>I', frame[18:22])[0]
            if binascii.crc32(key) & 0xFFFFFFFF != crc:
                self.out += b'\xa5'  # ERROR like the firmware
                continue  # nothing stored (fail-closed)
            self.stored = bytes(key)
            self.out += b'\xa4' + hashlib.sha256(key).digest()[:4]


class MockSerial:
    """Fake pyserial Serial bound to a MockPawUsb (or failure modes)."""

    fail_open = False
    fail_after = None  # raise IOError after N total read bytes

    def __init__(self, device):
        if MockSerial.fail_open:
            raise OSError('no such device')
        self.dev = device
        self.written = bytearray()
        self.read_total = 0
        self.closed = False

    def write(self, data):
        self.written += data
        self.dev.on_write(bytes(data))
        return len(data)

    def flush(self):
        pass

    def read(self, n=1):
        if MockSerial.fail_after is not None and self.read_total >= MockSerial.fail_after:
            raise IOError('device gone')
        out = self.dev.out[:n]
        del self.dev.out[:n]
        self.read_total += len(out)
        return bytes(out)

    def reset_input_buffer(self):
        self.dev.out = bytearray()

    def close(self):
        self.closed = True


class MockSerialModule:
    @staticmethod
    def Serial(port, baudrate=None, timeout=None):
        return MockSerial(_current_device[0])


_current_device = [None]


def _patch_serial(monkeypatch_device):
    _current_device[0] = monkeypatch_device
    mpu.serial = MockSerialModule()
    mpu.HAS_PYSERIAL = True
    MockSerial.fail_open = False
    MockSerial.fail_after = None


KEY = bytes(range(1, 17))
FP_HEX = hashlib.sha256(KEY).digest()[:4].hex()


def _distribute(dev, key=KEY, fp=FP_HEX, target=0x02, port='/dev/ttyACM9'):
    _patch_serial(dev)
    d = mpu.UsbCdcDistributor(port=port)
    return d, d.distribute(target, bytearray(key), fp)


def test_usb_happy_path():
    dev = MockPawUsb()
    d, (ok, reason) = _distribute(dev)
    assert ok, reason
    assert dev.stored == KEY  # device stored exactly the sent key
    assert reason == 'ok'


def test_usb_bad_crc_fails_closed():
    """Corrupted key byte in transit: device rejects, stores nothing."""
    dev = MockPawUsb()

    orig_write = MockSerial.write

    def tampering_write(self, data):
        data = bytearray(data)
        if len(data) == 22 and data[0] == 0xA3:
            data[5] ^= 0xFF  # flip one key byte on the wire
        return orig_write(self, bytes(data))

    MockSerial.write = tampering_write
    try:
        d, (ok, reason) = _distribute(dev)
    finally:
        MockSerial.write = orig_write
    assert not ok
    assert dev.stored is None  # fail-closed device side


def test_usb_timeout():
    dev = MockPawUsb(faults={'silent': True})

    class SlowDist(mpu.UsbCdcDistributor):
        def __init__(self):
            super().__init__(port='/dev/ttyACM9', step_timeout=0.05)

    _patch_serial(dev)
    ok, reason = SlowDist().distribute(0x02, bytearray(KEY), FP_HEX)
    assert not ok
    assert reason == 'timeout'
    assert dev.stored is None


def test_usb_disconnect_open():
    dev = MockPawUsb()
    _patch_serial(dev)
    MockSerial.fail_open = True
    d = mpu.UsbCdcDistributor(port='/dev/ttyACM9')
    ok, reason = d.distribute(0x02, bytearray(KEY), FP_HEX)
    MockSerial.fail_open = False
    assert not ok and reason == 'open-failed'


def test_usb_disconnect_mid_transfer():
    dev = MockPawUsb()
    _patch_serial(dev)
    MockSerial.fail_after = 0  # die on the very first READY read
    d = mpu.UsbCdcDistributor(port='/dev/ttyACM9')
    ok, reason = d.distribute(0x02, bytearray(KEY), FP_HEX)
    MockSerial.fail_after = None
    assert not ok
    assert dev.stored is None  # interrupted transfer stores nothing


def test_usb_fingerprint_mismatch():
    dev = MockPawUsb()
    d, (ok, reason) = _distribute(dev, fp='deadbeef')
    assert not ok and reason == 'fingerprint-mismatch'


class LoggyPawUsb(MockPawUsb):
    """PAW that multiplexes human-readable log lines with binary frames
    on the same USB CDC port (like the real firmware)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.out += b'[PRO-48] Waiting for key distribution...\r\n'

    def on_write(self, data):
        super().on_write(data)
        # Log output interleaved with the binary reply.
        self.out += b'[PRO-48] note: multiplexed log line\r\n'


def test_usb_log_interleaving_succeeds():
    """Log lines multiplexed with frames must not break the transfer."""
    dev = LoggyPawUsb()
    d, (ok, reason) = _distribute(dev)
    assert ok, reason
    assert dev.stored == KEY


def test_usb_stale_bytes_flushed():
    """Leftover bytes from an earlier run are flushed, not misparsed."""
    dev = MockPawUsb()
    dev.out += b'GARBAGE\xa2\x00leftover'
    d, (ok, reason) = _distribute(dev)
    assert ok, reason
    assert dev.stored == KEY


def test_usb_no_key_material_logged_or_audited(tmp_path, capsys):
    """Sentinel key must appear nowhere in stdout or the audit file."""
    sentinel = bytes([0xDE, 0xAD, 0xBE, 0xEF] * 4)
    sentinel_hex = sentinel.hex()
    fp = hashlib.sha256(sentinel).digest()[:4].hex()
    dev = MockPawUsb()
    _patch_serial(dev)
    mpu.AUDIT_LOG_PATH = str(tmp_path / 'audit.jsonl')
    mpu.AUDIT_DIR = str(tmp_path)
    mpu.FakeBridge.reset(key_hex=sentinel_hex, fingerprint=fp)
    real_sleep = mpu.time.sleep
    mpu.time.sleep = lambda s: None
    try:
        assert mpu.request_key_distribution(0x02, port='/dev/ttyACM9') is True
    finally:
        mpu.time.sleep = real_sleep
    assert dev.stored == sentinel  # transport itself worked
    out = capsys.readouterr().out
    audit = (tmp_path / 'audit.jsonl').read_text()
    assert sentinel_hex not in out and sentinel_hex not in audit
    assert fp in audit  # fingerprint only
    # confirm reported back with success
    assert mpu.FakeBridge.confirmed and mpu.FakeBridge.confirmed[-1] == (0x02, True)


def test_usb_full_flow_event_order():
    """Arm -> export -> USB exchange -> confirm(success)."""
    dev = MockPawUsb()
    _patch_serial(dev)
    mpu.FakeBridge.reset(key_hex=KEY.hex(), fingerprint=FP_HEX)
    real_sleep = mpu.time.sleep
    mpu.time.sleep = lambda s: None
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        mpu.AUDIT_LOG_PATH = td + '/a.jsonl'
        mpu.AUDIT_DIR = td
        try:
            assert mpu.request_key_distribution(0x02, port='/dev/ttyACM9') is True
        finally:
            mpu.time.sleep = real_sleep
    names = [c[0] for c in mpu.FakeBridge.calls]
    assert names[0] == 'request_key_distribution'
    assert 'export_staged_key' in names
    assert 'get_key_fingerprint' in names
    assert 'confirm_distribution' in names


def test_mcu_single_sender_guards():
    """Source guard: no Serial1 sender remains; one-shot export +
    confirm RPCs exist; no key bytes in MCU Serial logs."""
    import re
    mcu = (ROOT / 'key-authority/uno-q-key-authority-mcu/uno-q-key-authority-mcu.ino').read_text()
    code = re.sub(r'//.*', '', mcu)
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    assert 'Serial1.' not in code  # sender fully removed (comments may mention it)
    assert 'distributeKey(' not in code
    for token in ['export_staged_key', 'confirm_distribution', 'exportConsumed',
                  'BUTTON_FRESH_MS', 'lastButtonLowMs',
                  'keyAvailableForDistribution']:
        assert token in mcu, f'missing: {token}'
    for i, line in enumerate(mcu.splitlines(), 1):
        if 'Serial.print' in line and ('aesKey' in line or 'pendingKey' in line):
            raise AssertionError(f'key material in MCU log line {i}')


def test_mpu_distributor_guards():
    """Source guard: pyserial optional, distributor wipes + never logs keys."""
    import pathlib
    mpu_src = (pathlib.Path(__file__).resolve().parent.parent /
               'key-authority/uno-q-key-authority-mpu/uno-q-key-authority-mpu.py').read_text()
    assert 'HAS_PYSERIAL' in mpu_src
    assert 'key[i] = 0' in mpu_src  # buffer wipe
    assert 'confirm_distribution' in mpu_src
    # Timeout must be a keyword: 3rd positional Serial() arg is bytesize.
    assert 'serial.Serial(port, self.baud, timeout=' in mpu_src
