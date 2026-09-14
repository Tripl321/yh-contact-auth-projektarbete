"""SHALLOT — dockat UART-ramformat (DEN↔PAW).

Egen produktionsmodul för CLI:t. Äger samma trådformat som firmwarens
delade modul ``libraries/DenUartProtocol/src/DenUartProtocol.h``:

    [SYNC 1B = 0xAA] [LEN u16 LE] [TYPE u8] [PAYLOAD 0–64B] [CRC32 u32 LE]

- ``LEN`` = antal PAYLOAD-byte (inte header/CRC).
- CRC32 = IEEE 802.3 över ``LEN + TYPE + PAYLOAD``
  (allt utom SYNC och CRC-fältet).
- Max payload 64 byte. Allt ogiltigt avvisas fail-closed.

Modulen importerar aldrig testfiler; testvektorerna i CLI:ts egna
tester är hårdkodade ramar (samma princip som firmwarens KAT).
"""

from __future__ import annotations

import binascii
import struct

SYNC = 0xAA
MAX_PAYLOAD = 64

T_CHALLENGE = 0x01
T_RESPONSE = 0x02
T_HEARTBEAT = 0x03
T_ALARM = 0x04
T_ACK = 0xFF

BYTE_TIMEOUT_MS = 100
RESPONSE_DEADLINE_MS = 2000
MAX_RESYNC_SKIPS = 64

#: Exakt payload-storlek per känd ramtyp.
TYPE_SIZES = {
    T_CHALLENGE: 8,
    T_RESPONSE: 32,
    T_HEARTBEAT: 0,
    T_ALARM: 1,
    T_ACK: 1,
}

TYPE_NAMES = {
    T_CHALLENGE: "challenge",
    T_RESPONSE: "response",
    T_HEARTBEAT: "heartbeat",
    T_ALARM: "alarm",
    T_ACK: "ack",
}


class UartError(Exception):
    """Fail-closed ramfel. ``code`` är maskinläsbar, str() är mänsklig."""

    CODES = ("sync", "length", "short", "type", "crc", "timeout", "resync")

    MESSAGES = {
        "sync": "ogiltig SYNC (ramen måste börja med 0xAA)",
        "length": "ogiltig längd (LEN > 64 eller matchar inte ramtypen)",
        "short": " trunkerad ram (färre byte än LEN + header + CRC anger)",
        "type": "okänd ramtyp eller fel payload-storlek för känd typ",
        "crc": "CRC32-fel (ramen är korrupt eller manipulerad)",
        "timeout": "byte-timeout mitt i ram (>100 ms utan byte)",
        "resync": "resynk-budget slut (>64 skräpbyte före SYNC)",
    }

    def __init__(self, code: str):
        if code not in self.CODES:
            raise ValueError("okänd felkod: %r" % (code,))
        self.code = code
        super().__init__(self.MESSAGES[code])


def crc32(data: bytes) -> int:
    """IEEE 802.3 CRC32. Referens: CRC32("123456789") = 0xCBF43926."""
    return binascii.crc32(bytes(data)) & 0xFFFFFFFF


def type_name(ptype: int) -> str:
    return TYPE_NAMES.get(ptype, "unknown(0x%02x)" % ptype)


def parse_type(text: str) -> int:
    """Tolka ramtyp från namn (challenge/...) eller nummer (0x01/1)."""
    t = text.strip().lower()
    for value, name in TYPE_NAMES.items():
        if t == name:
            return value
    try:
        value = int(t, 0)
    except ValueError:
        raise UartError("type")
    if value not in TYPE_SIZES:
        raise UartError("type")
    return value


def parse_hex(text: str, what: str) -> bytes:
    try:
        return bytes.fromhex(text.strip().replace(" ", ""))
    except ValueError:
        raise ValueError("ogiltig hex för %s: %r" % (what, text)) from None


def encode(ptype: int, payload: bytes) -> bytes:
    """Koda en ram. Kastar UartError vid okänd typ eller fel storlek."""
    payload = bytes(payload)
    if ptype not in TYPE_SIZES or len(payload) != TYPE_SIZES[ptype]:
        raise UartError("type" if ptype not in TYPE_SIZES else "length")
    body = struct.pack("<H", len(payload)) + bytes([ptype]) + payload
    return bytes([SYNC]) + body + struct.pack("<I", crc32(body))


def decode(data: bytes) -> tuple[int, bytes]:
    """Avkoda en komplett ram. Returnerar (typ, payload).

    Kastar UartError('short') för trunkerade ramar så att anroparen
    kan skilja "vänta på fler byte" från "kassera ramen".
    """
    data = bytes(data)
    if len(data) < 8 or data[0] != SYNC:
        if len(data) >= 1 and data[0] != SYNC:
            raise UartError("sync")
        raise UartError("short")
    length = struct.unpack("<H", data[1:3])[0]
    if length > MAX_PAYLOAD:
        raise UartError("length")
    if len(data) < 4 + length + 4:
        raise UartError("short")
    ptype = data[3]
    if ptype not in TYPE_SIZES or length != TYPE_SIZES[ptype]:
        raise UartError("type")
    body = data[1 : 4 + length]
    want = struct.unpack("<I", data[4 + length : 8 + length])[0]
    if crc32(body) != want:
        raise UartError("crc")
    return ptype, data[4 : 4 + length]


class Scanner:
    """Byte-ström → ramar med resynk + byte-timeout (jfr DenScanner)."""

    def __init__(self) -> None:
        self.buf = bytearray()
        self.skipped = 0

    def push(self, byte: int, now_ms: int, last_ms: int | None = None):
        """Mata en byte. Returnerar (typ, payload) vid komplett giltig
        ram, None medan ramen samlas. Kastar UartError vid fel (fail-closed:
        påbörjad ram kasseras, skannern söker ny SYNC)."""
        if last_ms is not None and self.buf and now_ms - last_ms > BYTE_TIMEOUT_MS:
            self.buf = bytearray()
            raise UartError("timeout")
        if not self.buf:
            if byte != SYNC:
                self.skipped += 1
                if self.skipped > MAX_RESYNC_SKIPS:
                    raise UartError("resync")
                return None
        self.buf.append(byte)
        if len(self.buf) >= 3:
            length = struct.unpack("<H", self.buf[1:3])[0]
            if length > MAX_PAYLOAD:
                self.buf = bytearray()
                raise UartError("length")
            if len(self.buf) >= 4 + length + 4:
                try:
                    out = decode(bytes(self.buf[: 4 + length + 4]))
                except UartError:
                    self.buf = bytearray()
                    raise
                self.buf = bytearray()
                self.skipped = 0
                return out
        return None
