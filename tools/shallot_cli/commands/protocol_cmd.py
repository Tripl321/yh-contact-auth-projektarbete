"""`shallot protocol encode|decode` — UART-ramformatet utan hårdvara.

Ram: AA | len u16 LE | type | payload | CRC32 LE (CRC över len+type+payload).
"""

from __future__ import annotations

import sys

from shallot_cli import uart


def run_encode(type_text: str, payload_hex: str) -> int:
    try:
        ptype = uart.parse_type(type_text)
    except uart.UartError:
        print("error: okänd ramtyp %r (kända: %s)" % (
            type_text, ", ".join(sorted(uart.TYPE_NAMES.values()))), file=sys.stderr)
        return 2
    try:
        payload = uart.parse_hex(payload_hex, "payload")
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    try:
        frame = uart.encode(ptype, payload)
    except uart.UartError:
        print("error: fel payload-storlek för %s: fick %d byte, väntas %d." % (
            uart.type_name(ptype), len(payload), uart.TYPE_SIZES[ptype]), file=sys.stderr)
        return 2
    print(frame.hex())
    return 0


def run_decode(frame_hex: str) -> int:
    try:
        raw = uart.parse_hex(frame_hex, "ram")
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    try:
        ptype, payload = uart.decode(raw)
    except uart.UartError as e:
        print("error: ogiltig ram (%s): %s" % (e.code, e), file=sys.stderr)
        return 1
    print("typ     : %s (0x%02x)" % (uart.type_name(ptype), ptype))
    print("payload : %s (%d byte)" % (payload.hex() or "(tom)", len(payload)))
    print("längd   : OK (LEN=%d)" % len(payload))
    print("crc     : OK (IEEE 802.3 över LEN+TYPE+PAYLOAD)")
    return 0
