"""USB-nyckelsändare för bänken (PRO-48 PAW / PRO-46 DEN).

Skickar en fast testnyckel över USB-seriell: HANDSHAKE [0xA1, target]
-> READY [0xA2, id×4] -> KEY_DATA (22 byte) -> STORED [0xA4, sha256[:4]]
eller ERROR [0xA5]. All avvikelse (timeout, fel typ/längd, CRC-fel på
STORED-svar, fel fingeravtryck) nekar fail-closed via ProvisionError.

USB-serien bär inledd loggtext på samma tråd (firmwarens Serial skriver
både loggar och binärsvar); läsaren synkar därför fram ramarnas
typsbyte (0xA2/0xA4/0xA5, aldrig ASCII-text) istället för att ta råa
byte. UNO Q:s egen distribution går över ren Serial1-UART och behöver
ingen synk.

Aldrig riktiga hemligheter: fast testvektor, aldrig i loggar eller
auditposter (auditposter returneras — anroparen journalför).
Transporten är ett objekt med write(bytes) + read(n, timeout)->bytes;
hårdvara öppnas via serial_adapters.open_provision.
"""

from __future__ import annotations

import hashlib
import time
import zlib

MSG_HANDSHAKE = 0xA1
MSG_READY = 0xA2
MSG_KEY_DATA = 0xA3
MSG_STORED = 0xA4
MSG_ERROR = 0xA5

TARGETS = {"den": 0x01, "paw": 0x02}

#: Fast testvektor för bänken (samma som tests/vectors/provisioning.json).
#: Aldrig produktion — enheter med denna nyckel är per definition test.
TEST_KEY = bytes(range(16))

KEY_DATA_LEN = 22
READY_LEN = 5
STORED_LEN = 5


class ProvisionError(RuntimeError):
    """Nekad/felaktig provisionering (fail closed)."""


class SerialTransport:
    """Adapter pyserial -> provision-kontraktet (write + read(n, timeout)).

    pyserials ``read()`` tar ingen timeout-parameter; adaptern sätter
    portens timeout tillfälligt per anrop och återställer alltid.
    Äger ingen policy — bara signaturanpassning.
    """

    def __init__(self, ser):
        self._ser = ser

    def write(self, data: bytes) -> int:
        return self._ser.write(data)

    def read(self, n: int, timeout: float = 1.0) -> bytes:
        old = self._ser.timeout
        self._ser.timeout = max(0.0, timeout)
        try:
            return self._ser.read(n)
        finally:
            self._ser.timeout = old


def build_handshake(target: str) -> bytes:
    """2 byte HANDSHAKE för mål ('den' eller 'paw')."""
    try:
        code = TARGETS[target]
    except KeyError:
        raise ValueError("okänt mål %r (välj: den|paw)" % (target,)) from None
    return bytes([MSG_HANDSHAKE, code])


def build_key_data(key: bytes) -> bytes:
    """22 byte KEY_DATA. Avvisar all-noll (firmware gör detsamma)."""
    if len(bytes(key)) != 16:
        raise ValueError("nyckeln måste vara 16 byte.")
    if not any(key):
        raise ValueError("all-noll nyckel avvisas (oskrivbar SRAM-markör).")
    return (bytes([MSG_KEY_DATA, 16]) + bytes(key)
            + zlib.crc32(bytes(key)).to_bytes(4, "big"))


def parse_ready(data: bytes) -> bytes | None:
    """READY-svar -> 4 byte device-ID, eller None vid fel form."""
    if len(data) == READY_LEN and data[0] == MSG_READY:
        return bytes(data[1:5])
    return None


def expected_fingerprint(key: bytes) -> bytes:
    """STORED-förväntning: SHA-256(master)[:4], båda firmwares regel."""
    return hashlib.sha256(bytes(key)).digest()[:4]


def parse_stored(data: bytes, key: bytes) -> bool:
    """Validera STORED-svar mot nyckeln. ERROR/fel form höjer."""
    if data[:1] == bytes([MSG_ERROR]):
        raise ProvisionError("enheten svarade ERROR (nyckel avvisad).")
    if len(data) != STORED_LEN or data[0] != MSG_STORED:
        raise ProvisionError("ogiltigt STORED-svar (%d byte)." % len(data))
    return bytes(data[1:5]) == expected_fingerprint(key)


def _read_exact(transport, n: int, deadline: float) -> bytes:
    out = bytearray()
    while len(out) < n:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProvisionError("timeout: enheten svarade inte.")
        chunk = transport.read(n - len(out), timeout=remaining)
        if not chunk:
            raise ProvisionError("timeout: enheten svarade inte.")
        out += chunk
    return bytes(out)


def settle(ser, delay: float = 2.5) -> None:
    """Låt enheten boota klart efter portöppning och töm bufferten.

    USB CDC-öppning resettar enheten (DTR); utan väntan försvinner
    handskaket i omstarten och svaret uteblir. Anropas av
    provisioneringsvägarna mellan open och provision_device.
    """
    if delay > 0:
        time.sleep(delay)
    reset = getattr(ser, "reset_input_buffer", None)
    if callable(reset):
        reset()


def _sync_frame(transport, want: tuple[int, ...], deadline: float) -> int:
    """Skanna fram nästa ram-typsbyte, släng inledd loggtext.

    Returnerar typsbyten. Timeout nekar fail-closed. Typsbyten
    (0xA2/0xA4/0xA5) förekommer aldrig i firmwarens ASCII-loggar.
    """
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ProvisionError("timeout: enheten svarade inte.")
        chunk = transport.read(1, timeout=remaining)
        if not chunk:
            raise ProvisionError("timeout: enheten svarade inte.")
        if chunk[0] in want:
            return chunk[0]


def provision_device(transport, target: str, key: bytes = TEST_KEY,
                     timeout: float = 10.0,
                     audit: list | None = None) -> dict:
    """Kör hela kedjan mot en enhet. Returnerar fakta + auditposter.

    audit är en lista av {action, details} utan nyckelmaterial, ägd av
    anroparen: poster läggs till löpande och finns kvar även när DENY
    höjer — anroparen journalför (t.ex. admin.audit_admin). Utelämnas
    den skapas en intern lista som returneras i svaret.
    """
    key = bytes(key)
    entries: list[dict] = audit if audit is not None else []

    def deny(reason: str, message: str) -> None:
        entries.append({"action": "provision",
                        "details": {"target": target, "result": "DENY",
                                    "reason": reason}})
        raise ProvisionError(message)

    deadline = time.monotonic() + timeout
    try:
        transport.write(build_handshake(target))
        sync = _sync_frame(transport, (MSG_READY,), deadline)
        ready = parse_ready(bytes([sync])
                            + _read_exact(transport, READY_LEN - 1, deadline))
        if ready is None:
            deny("bad-ready", "ogiltigt READY-svar.")
        transport.write(build_key_data(key))
        # ERROR är 1 byte, STORED är 5 — synka fram typbyten först.
        first = _sync_frame(transport, (MSG_STORED, MSG_ERROR), deadline)
        if first == MSG_ERROR:
            deny("device-error", "enheten svarade ERROR (nyckel avvisad).")
        rest = _read_exact(transport, STORED_LEN - 1, deadline)
        if not parse_stored(bytes([first]) + rest, key):
            deny("fingerprint-mismatch",
                 "STORED-fingeravtryck matchar inte nyckeln.")
    except ProvisionError:
        if not entries:
            # Tidsöverskridning: exakt en post.
            entries.append({"action": "provision",
                            "details": {"target": target, "result": "DENY",
                                        "reason": "timeout"}})
        raise
    entries.append({"action": "provision",
                    "details": {"target": target, "result": "granted",
                                "fingerprint": expected_fingerprint(key).hex()}})
    return {"result": "granted", "target": target, "device_id": ready,
            "fingerprint": expected_fingerprint(key), "audit": entries}
