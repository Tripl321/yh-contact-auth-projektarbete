"""`shallot monitor` — skrivskyddad visning av serial-loggar.

Öppnar porten för läsning och skriver aldrig till enheten
(ingen kommandostyrning finns i denna CLI).
"""

from __future__ import annotations

import sys

from shallot_cli import serial_adapters

DEVICES = ("den", "paw", "mamabear")


def run(device: str, port: str, baud: int = 115200) -> int:
    if device not in DEVICES:
        print("error: okänd enhet %r (välj: %s)" % (device, "|".join(DEVICES)), file=sys.stderr)
        return 2
    if not port:
        print("error: --port krävs.", file=sys.stderr)
        return 2
    try:
        ser = serial_adapters.open_read_only(port, baud=baud)
    except RuntimeError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    except Exception as e:
        print("error: kunde inte öppna %s: %s" % (port, e), file=sys.stderr)
        return 1
    print("Läser %s (%s) @ %d baud — skrivskyddad visning, Ctrl-C avbryter." % (port, device, baud))
    try:
        with ser:
            while True:
                raw = ser.readline()
                if not raw:
                    continue
                sys.stdout.write(raw.decode("utf-8", errors="replace"))
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nAvbrutet av användaren.")
        return 0
    except Exception as e:
        print("error: läsfel på %s: %s" % (port, e), file=sys.stderr)
        return 1
