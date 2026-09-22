"""`shallot device list` — skrivfri uppräkning av serieportar."""

from __future__ import annotations

import sys

from shallot_cli import fido2_sanitize, serial_adapters


def run_list() -> int:
    try:
        ports = serial_adapters.list_ports()
    except Exception as e:
        print("error: kunde inte lista serieportar: %s"
              % fido2_sanitize.sanitize(str(e)), file=sys.stderr)
        return 1
    if not ports:
        print("Inga serieportar hittades.")
        return 0
    print("%-18s %-28s %s" % ("PORT", "BESKRIVNING", "HWID"))
    for p in ports:
        print("%-18s %-28s %s" % (
            fido2_sanitize.sanitize(str(p["device"])),
            fido2_sanitize.sanitize(str(p["description"]))[:28],
            fido2_sanitize.sanitize(str(p["hwid"]))))
    print("Identifiering osäker (gissning utifrån namn/Vid:Pid) — ingen skrivning utförd.")
    return 0
