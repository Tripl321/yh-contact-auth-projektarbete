"""Serieportsadaptrar — ett sanktionerat skrivundantag: provisionering.

All hårdvarukontakt i CLI:t går via denna modul så att skrivning kan
granskas på ett ställe:

- :func:`list_ports` enumererar portar (ingen I/O mot enheten).
- :func:`open_read_only` öppnar en port för läsning. Returnerar ett
  öppet serieobjekt; anropare får aldrig anropa ``write()`` på det —
  ``monitor``-kommandot läser endast.
- :func:`open_provision` öppnar en port för nyckelsändning (enda
  skrivvägen; testnycklar via :mod:`shallot_cli.provision`).
- :func:`open_console` öppnar en port för läsning + skrivning mot en
  bänkkonsol (t.ex. UNO Q:s ``g``/``1``/``2``/``s``-kommandon).
  Får endast användas av bänkceremoni-flödet med explicit
  operatörsbekräftelse per tillståndsändrande kommando; sänder aldrig
  hemligheter.
"""

from __future__ import annotations


def list_ports() -> list[dict]:
    """Lista serieportar utan att skriva till dem.

    Returnerar en lista av dictar med nycklarna ``device``,
    ``description`` och ``hwid``. Fungerar även utan pyserial
    (fallback: glob av /dev-noder, då utan beskrivning).
    """
    try:
        from serial.tools import list_ports as lp
    except ImportError:
        return _fallback_ports()
    found = []
    for p in lp.comports():
        found.append(
            {
                "device": p.device,
                "description": p.description or "okänd enhet",
                "hwid": p.hwid or "okänt hwid",
            }
        )
    return found


def _fallback_ports() -> list[dict]:
    import glob

    devices = sorted(
        set(
            glob.glob("/dev/ttyACM*")
            + glob.glob("/dev/ttyUSB*")
            + glob.glob("/dev/cu.usb*")
            + glob.glob("/dev/tty.usb*")
        )
    )
    return [
        {
            "device": d,
            "description": "okänd enhet (pyserial saknas)",
            "hwid": "okänt hwid",
        }
        for d in devices
    ]


def open_read_only(port: str, baud: int = 115200, timeout: float = 1.0):
    """Öppna en serieport för läsning. Kastar RuntimeError om pyserial
    saknas, annars serial.SerialException vid fel. Gör ingen skrivning."""
    try:
        import serial
    except ImportError:
        raise RuntimeError(
            "pyserial saknas — installera med: pip install 'shallot[test]' "
            "eller pip install pyserial"
        ) from None
    return serial.Serial(port=port, baudrate=baud, timeout=timeout)


def open_provision(port: str, baud: int = 115200, timeout: float = 1.0):
    """Öppna en serieport för nyckelsändning (enda skrivvägen).

    Får endast användas av provision-sändaren med testnycklar.
    Samma felkontrakt som open_read_only.
    """
    if not isinstance(port, str) or "\x00" in port or not port.strip():
        raise RuntimeError("ogiltig serieport.")
    try:
        import serial
    except ImportError:
        raise RuntimeError(
            "pyserial saknas — installera med: pip install 'shallot[test]' "
            "eller pip install pyserial"
        ) from None
    return serial.Serial(
        port=port, baudrate=baud, timeout=timeout, write_timeout=timeout
    )


def open_console(port: str, baud: int = 115200, timeout: float = 1.0):
    """Öppna en seriekonsol för läsning + skrivning (bänkceremoni).

    Används endast av ``bench unoq`` för UNO Q-konsolens enbokstavs-
    kommandon (``s`` status, ``g`` generera, ``1``/``2`` distribuera).
    Anroparen ansvarar för operatörsbekräftelse före tillståndsändrande
    kommandon; inga hemligheter skickas eller loggas någonsin här.
    Samma felkontrakt som open_read_only.
    """
    if not isinstance(port, str) or "\x00" in port or not port.strip():
        raise RuntimeError("ogiltig serieport.")
    try:
        import serial
    except ImportError:
        raise RuntimeError(
            "pyserial saknas — installera med: pip install 'shallot[test]' "
            "eller pip install pyserial"
        ) from None
    return serial.Serial(
        port=port, baudrate=baud, timeout=timeout, write_timeout=timeout
    )
