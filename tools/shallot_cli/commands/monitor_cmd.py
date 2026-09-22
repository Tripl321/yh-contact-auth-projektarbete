"""`shallot monitor` — skrivskyddad visning av serial-loggar.

Öppnar porten för läsning och skriver aldrig till enheten
(ingen kommandostyrning finns i denna CLI).
"""

from __future__ import annotations

import sys
import time

from shallot_cli import fido2_sanitize, serial_adapters

DEVICES = ("den", "paw", "mamabear")


def _validate_port(port: str) -> str:
    """Porten väljs av operatören (jfr --output): avvisa tom/NUL, inget mer.

    Sökvägen normaliseras inte mot CWD — serieportar bor utanför trädet
    (t.ex. /dev/ttyACM0). Felet fångas fail-closed vid öppning.
    """
    if not isinstance(port, str) or "\x00" in port or not port.strip():
        raise ValueError("ogiltig --port.")
    return port


def read_until(port: str, baud: int, needles: list[str],
               timeout: float = 60.0) -> tuple[str | None, str | None]:
    """Läs seriell logg tills en nål matchar eller timeout. Returnerar
    (träffad nål, rad) eller (None, None). Raden returneras osanerad
    (matchning); anroparen sanerar före visning."""
    try:
        port = _validate_port(port)
    except ValueError:
        return None, None
    if not isinstance(baud, int) or baud <= 0:
        return None, None
    try:
        ser = serial_adapters.open_read_only(port, baud=baud, timeout=1.0)
    except Exception:
        return None, None
    deadline = time.monotonic() + timeout
    buf = ""
    try:
        with ser:
            while time.monotonic() < deadline:
                raw = ser.readline()
                if not raw:
                    continue
                buf += raw.decode("utf-8", errors="replace")
                while "\n" in buf:
                    line, buf = buf.split("\n", 1)
                    for needle in needles:
                        if needle in line:
                            return needle, line
    except Exception:
        return None, None
    return None, None


def run(device: str, port: str, baud: int = 115200) -> int:
    if device not in DEVICES:
        print("error: okänd enhet %r (välj: %s)" % (device, "|".join(DEVICES)), file=sys.stderr)
        return 2
    try:
        port = _validate_port(port)
    except ValueError as e:
        print("error: %s" % e, file=sys.stderr)
        return 2
    if not isinstance(baud, int) or baud <= 0:
        print("error: ogiltig --baud %r." % (baud,), file=sys.stderr)
        return 2
    try:
        ser = serial_adapters.open_read_only(port, baud=baud)
    except RuntimeError as e:
        print("error: %s" % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    except Exception as e:
        print("error: kunde inte öppna port: %s"
              % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    print("Läser %s (%s) @ %d baud — skrivskyddad visning, Ctrl-C avbryter." % (port, device, baud))
    try:
        with ser:
            while True:
                raw = ser.readline()
                if not raw:
                    continue
                sys.stdout.write(fido2_sanitize.sanitize(
                    raw.decode("utf-8", errors="replace")))
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\nAvbrutet av användaren.")
        return 0
    except Exception as e:
        print("error: läsfel på port: %s"
              % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
