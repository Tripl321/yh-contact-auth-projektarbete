"""Tester för shallot_cli.uart — hårdkodade ramvektorer (ingen import av repoets tester)."""

import pytest

from shallot_cli import uart

VECTORS = {
    "aa000003a8884866": (uart.T_HEARTBEAT, ""),
    "aa0100ff019d75db7d": (uart.T_ACK, "01"),
    "aa01000402511c9a13": (uart.T_ALARM, "02"),
    "aa08000100010203040506071cf3b72b": (uart.T_CHALLENGE, "0001020304050607"),
    "aa200002202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f09ad4514": (
        uart.T_RESPONSE,
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"),
}


def test_crc_pinned():
    assert uart.crc32(b"123456789") == 0xCBF43926


def test_encode_vectors():
    for hexframe, (ptype, payloadhex) in VECTORS.items():
        assert uart.encode(ptype, bytes.fromhex(payloadhex)).hex() == hexframe


def test_decode_vectors():
    for hexframe, (ptype, payloadhex) in VECTORS.items():
        t, p = uart.decode(bytes.fromhex(hexframe))
        assert t == ptype and p.hex() == payloadhex


def test_decode_bad_crc():
    bad = bytearray.fromhex("aa0100ff019d75db7d")
    bad[-1] ^= 0x01
    with pytest.raises(uart.UartError) as e:
        uart.decode(bytes(bad))
    assert e.value.code == "crc"


def test_decode_bad_length():
    with pytest.raises(uart.UartError) as e:
        uart.decode(bytes([uart.SYNC, 65, 0, uart.T_HEARTBEAT]) + bytes(65 + 4))
    assert e.value.code == "length"


def test_decode_unknown_type():
    import struct
    body = struct.pack("<H", 0) + bytes([0x09])
    frame = bytes([uart.SYNC]) + body + struct.pack("<I", uart.crc32(body))
    with pytest.raises(uart.UartError) as e:
        uart.decode(frame)
    assert e.value.code == "type"


def test_decode_truncated_is_short():
    with pytest.raises(uart.UartError) as e:
        uart.decode(bytes.fromhex("aa08000100010203"))
    assert e.value.code == "short"


def test_decode_bad_sync():
    with pytest.raises(uart.UartError) as e:
        uart.decode(bytes.fromhex("ab0100ff019d75db7d"))
    assert e.value.code == "sync"


def test_encode_rejects_wrong_size():
    with pytest.raises(uart.UartError):
        uart.encode(uart.T_CHALLENGE, bytes(7))


def test_encode_rejects_unknown_type():
    with pytest.raises(uart.UartError):
        uart.encode(0x09, b"")


def test_parse_type_names_and_numbers():
    assert uart.parse_type("challenge") == uart.T_CHALLENGE
    assert uart.parse_type("ACK") == uart.T_ACK
    assert uart.parse_type("0x02") == uart.T_RESPONSE
    assert uart.parse_type("3") == uart.T_HEARTBEAT
    with pytest.raises(uart.UartError):
        uart.parse_type("unlock")


def test_scanner_split_and_resync():
    sc = uart.Scanner()
    frame = bytes.fromhex("aa08000100010203040506071cf3b72b")
    for b in bytes([0x00, 0xFF]):
        assert sc.push(b, 1000) is None
    out = None
    for b in frame:
        r = sc.push(b, 1000)
        if r is not None:
            out = r
    assert out == (uart.T_CHALLENGE, bytes(range(8)))


def test_scanner_timeout_discards():
    sc = uart.Scanner()
    for b in bytes.fromhex("aa08000100"):
        sc.push(b, 1000)
    with pytest.raises(uart.UartError) as e:
        sc.push(0x02, 1000 + uart.BYTE_TIMEOUT_MS + 1, last_ms=1000)
    assert e.value.code == "timeout"
    assert sc.buf == bytearray()


def test_scanner_resync_budget():
    sc = uart.Scanner()
    with pytest.raises(uart.UartError) as e:
        for _ in range(uart.MAX_RESYNC_SKIPS + 2):
            sc.push(0x55, 1000)
    assert e.value.code == "resync"
