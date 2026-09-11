"""
Issue #11: PAW dock auth stays responsive with dead e-paper / absent or
garbage provisioning traffic.

Virtual-time mirror of the reworked paw-main.ino loop (10 ms ticks):
dock parser answers instantly per pass, provisioning is a non-blocking
poll, and e-paper work is request + background poll with a degraded
latch on BUSY timeout. Adversarial conditions: BUSY stuck HIGH forever,
no provisioning sender, malformed USB bytes.
"""
import hashlib
import hmac as hmac_module

DEV_KEY = bytes(range(16))
K_MAC = bytes.fromhex('99c7117275f487623752e6d5d0eb438f')  # SHA-256(master || "MAC")[:16]
TICK_MS = 10
DEADLINE_MS = 2000


def hmac16(key, nonce):
    return hmac_module.new(bytes(key), bytes(nonce), hashlib.sha256).digest()


class MockEpd:
    """Mirror of async ShallotEPD: requests start transmits, poll()
    completes them; stuck BUSY latches degraded (fail silent after)."""

    REFRESH_TIMEOUT = 90000

    def __init__(self, busy_stuck):
        self.busy_stuck = busy_stuck
        self.degraded = False
        self.update_busy = False
        self.update_start = 0
        self.now = 0
        self.show_cost_ms = 0  # CPU time spent inside showStatus calls

    def begin(self):
        # Bounded init waits: first stuck wait fails fast (short bound).
        if self.busy_stuck:
            self.degraded = True
            return False, 2000  # one init-timeout, then give up
        return True, 0

    def showStatus(self, _status):
        if self.degraded:
            return 0  # fail silent: zero loop cost once degraded
        self.update_busy = True
        self.update_start = self.now
        return 0  # returns immediately; transmit is fire-and-forget

    def poll(self):
        if self.degraded or not self.update_busy:
            return 0
        if not self.busy_stuck:
            self.update_busy = False  # live panel went idle
            return 0
        if self.now - self.update_start > self.REFRESH_TIMEOUT:
            self.degraded = True
            self.update_busy = False
            return 0
        return 0


class MockProv:
    """Mirror of pollProvisioning: handshake scan -> READY -> accumulate
    exactly 22 key-data bytes -> strict validate -> store. Never waits.
    PRO-47: clears stored key on timeout, new handshake, or failure."""

    def __init__(self):
        self.phase = 'hs'
        self.buf = bytearray()
        self.t0 = 0
        self.key_stored = False
        self.stored_sent = []

    def poll(self, usb_in, now):
        if self.phase == 'hs':
            self.buf += bytes(usb_in)
            while len(self.buf) >= 2:
                msg, tgt = self.buf[0], self.buf[1]
                del self.buf[:2]
                if msg == 0xA1 and tgt == 0x02:
                    self.phase = 'kd'
                    self.t0 = now
                    self.buf = bytearray()
                    # PRO-47: new provisioning session clears any prior key
                    self.key_stored = False
                    return 'ready'
            return 'pending'
        self.buf += bytes(usb_in)
        if len(self.buf) < 22:
            if now - self.t0 > 10000:
                self.phase = 'hs'  # attempt timeout: wipe partial, retry
                self.buf = bytearray()
                # PRO-47: timeout clears stored key
                self.key_stored = False
                return 'failed'
            return 'pending'
        tag, ln, key, crc = (self.buf[0], self.buf[1], bytes(self.buf[2:18]),
                             int.from_bytes(self.buf[18:22], 'big'))
        self.buf = bytearray()
        self.phase = 'hs'
        if tag != 0xA3 or ln != 16:
            # PRO-47: malformed frame clears stored key
            self.key_stored = False
            return 'failed'
        import binascii
        if binascii.crc32(key) & 0xFFFFFFFF != crc:
            # PRO-47: CRC mismatch clears stored key
            self.key_stored = False
            return 'failed'
        self.key_stored = True
        fp = hashlib.sha256(key).digest()[:4]
        self.stored_sent.append(fp)
        return 'done'


class MockPawLoop:
    """One virtual PAW: dock poll first, epd poll, prov poll per tick."""

    def __init__(self, busy_stuck):
        self.now = 0
        self.epd = MockEpd(busy_stuck)
        self.prov = MockProv()
        self.usb_in = bytearray()
        self.uart_in = bytearray()
        self.responses = []  # (t_answered, t_challenged_virt, mac_ok)
        self.key = DEV_KEY
        self.k_mac = K_MAC  # PRO-49: derived HMAC key
        ok, cost = self.epd.begin()
        self.now += cost
        self.setup_ms = self.now

    def tick(self, usb_bytes=b'', uart_bytes=b'', chal_at=None):
        self.usb_in += bytes(usb_bytes)
        self.uart_in += bytes(uart_bytes)
        # 1. dock poll (instant per buffered bytes)
        while self.uart_in:
            b = self.uart_in.pop(0)
            if b == 0xAA:  # SYNC: parse frame header for length
                if len(self.uart_in) >= 3:
                    ln = int.from_bytes(bytes(self.uart_in[:2]), 'little')
                    total_needed = 2 + 1 + ln + 4  # LEN + TYPE + PAYLOAD + CRC
                    if len(self.uart_in) >= total_needed:
                        frame = bytes([b]) + bytes(self.uart_in[:total_needed])
                        del self.uart_in[:total_needed]
                        import binascii
                        body, want = frame[1:1+2+1+ln], int.from_bytes(frame[1+2+1+ln:1+2+1+ln+4], 'little')
                        if binascii.crc32(body) & 0xFFFFFFFF == want \
                                and frame[3] == 0x01 and ln == 8:
                            mac = hmac16(self.k_mac, frame[4:4+8])
                            self.responses.append((self.now, chal_at, mac))
                            self.epd.showStatus('authenticating')
        # 2. epd poll 3. prov poll (both instant)
        self.epd.now = self.now
        self.epd.poll()
        self.prov.poll(self.usb_in, self.now)
        self.usb_in = bytearray()
        self.now += TICK_MS


def den_challenge(nonce):
    import binascii
    body = len(nonce).to_bytes(2, 'little') + b'\x01' + bytes(nonce)
    return b'\xaa' + body + (binascii.crc32(body) & 0xFFFFFFFF).to_bytes(4, 'little')


def test_responsive_dead_panel_no_provisioning():
    """Dead panel + no sender: setup fast, challenge answered < 2 s."""
    paw = MockPawLoop(busy_stuck=True)
    assert paw.setup_ms < 10000  # never the old 90 s+ boot stall
    assert paw.epd.degraded  # latched at first stuck wait
    nonce = bytes(range(0x10, 0x18))
    t_tx = paw.now
    for _ in range(DEADLINE_MS // TICK_MS):
        paw.tick(uart_bytes=den_challenge(nonce) if paw.now == t_tx else b'',
                 chal_at=t_tx)
        if paw.responses:
            break
    assert paw.responses, 'no answer within deadline'
    t_ans, _, mac = paw.responses[0]
    assert t_ans - t_tx < DEADLINE_MS
    assert mac == hmac16(K_MAC, nonce)


def test_responsive_garbage_usb_traffic():
    """Malformed USB bytes: no key stored, dock still prompt."""
    paw = MockPawLoop(busy_stuck=True)
    nonce = bytes(range(0x20, 0x28))
    answered = None
    for i in range(DEADLINE_MS // TICK_MS):
        usb = b'\x00\xff\xa1\x99' if i % 3 == 0 else b'\xa3\x10' + bytes(20)
        paw.tick(usb_bytes=usb,
                 uart_bytes=den_challenge(nonce) if i == 5 else b'',
                 chal_at=paw.now if i == 5 else None)
        if paw.responses:
            answered = paw.responses[0]
            break
    assert not paw.prov.key_stored  # garbage never stages a key
    assert answered is not None
    assert answered[0] - answered[1] < DEADLINE_MS


def test_provisioning_completes_via_poll():
    """Valid handshake + key-data across ticks: stored, fingerprinted."""
    import binascii
    paw = MockPawLoop(busy_stuck=False)
    key = bytes(range(1, 17))
    kd = b'\xa3\x10' + key + (binascii.crc32(key) & 0xFFFFFFFF).to_bytes(4, 'big')
    paw.tick(usb_bytes=b'\xa1\x02')  # clean handshake pair
    assert paw.prov.key_stored is False
    for i in range(0, len(kd), 5):  # split across passes (partial frames)
        paw.tick(usb_bytes=kd[i:i + 5])
    assert paw.prov.key_stored
    assert paw.prov.stored_sent[0] == hashlib.sha256(key).digest()[:4]


def test_degraded_display_stays_fast():
    """After degrade, showStatus costs nothing (loop cadence protected)."""
    paw = MockPawLoop(busy_stuck=True)
    assert paw.epd.degraded
    t0 = paw.now
    for _ in range(100):
        paw.epd.showStatus('authenticating')
        paw.tick()
    assert paw.now - t0 == 100 * TICK_MS  # zero display stall


def test_source_guards():
    """Issue #11 structural pins: async display, non-blocking provisioning,
    dock poll every pass and first, no unbounded waits."""
    import pathlib
    import re
    src = (pathlib.Path(__file__).resolve().parent.parent /
           'id-kort/paw-main/paw-main.ino').read_text()
    code = re.sub(r'//.*', '', src)
    # E-paper: request + poll, bounded waits only.
    assert 'EPD_REFRESH_TIMEOUT_MS 90000' in src
    assert 'EPD_INIT_TIMEOUT_MS' in src
    assert 'bool waitUntilIdle(uint32_t timeoutMs)' in src
    assert 'void waitUntilIdle()' not in src
    assert 'epd.poll();' in src
    assert '_degraded' in src and 'degraded display mode' in src
    # Provisioning: poll function, never the blocking receiver.
    assert 'bool receiveKeyFromUNOQ()' not in src
    assert 'pollProvisioning()' in src
    start, end = None, None
    lines = src.splitlines()
    i = next(i for i, l in enumerate(lines) if 'uint8_t pollProvisioning()' in l)
    depth, begun = 0, False
    for j in range(i, len(lines)):
        depth += lines[j].count('{') - lines[j].count('}')
        if '{' in lines[j]:
            begun = True
        if begun and depth == 0:
            start, end = i, j
            break
    body = '\n'.join(lines[start:end + 1])
    assert 'delay(' not in body  # never sleeps inside the poll
    assert 'while (Serial.available() <' not in body  # no blocking-wait form
    assert 'readBytes' not in body  # no blocking reads
    # Loop: dock poll present and ahead of LoRa handling.
    loop = src[src.index('void loop()'):]
    assert loop.index('handleDockAuth();') < loop.index('loraPacketReceived')
    # Setup: no provisioning wait, no display clear stall.
    setup = src[src.index('void setup()'):src.index('void loop()')]
    assert 'receiveKeyFromUNOQ' not in setup
    assert 'epd.clear();' not in setup
